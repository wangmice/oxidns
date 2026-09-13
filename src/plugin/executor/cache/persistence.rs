// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cache persistence helpers.

use std::cmp::Ordering as CmpOrdering;
use std::collections::{BinaryHeap, HashSet};
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};
use wincode::{SchemaRead, SchemaWrite};

use super::key::{
    CacheKey, EcsLookupIndex, canonical_ecs_key_digest, normalize_cache_key_domain, persisted_ecs_key_matches_response,
};
use super::{
    CacheItem, CacheLoadPolicy, CacheMap, clamp_persisted_cache_ttl, is_cache_disposition_valid,
    response_disposition_for_cache,
};
use crate::infra::cache::ttl::TtlCacheHandle;
use crate::infra::clock::AppClock;
use crate::infra::error::{DnsError, Result};
use crate::infra::system::file_len_if_exists;
use crate::proto::{DNSClass, Message, RecordType};

// Little-endian bytes spell "DSCACHE1". The magic lets us distinguish the
// versioned format from the old unversioned Vec<PersistedCacheEntry> format.
const CACHE_DUMP_MAGIC: u64 = 0x3145_4843_4143_5344;
const LEGACY_CACHE_DUMP_VERSION: u32 = 1;
const PREVIOUS_CACHE_DUMP_VERSION: u32 = 2;
const CACHE_DUMP_VERSION: u32 = 3;
/// Maximum cache dump size accepted/written by file persistence.
///
/// The API has its own smaller request-body limit. Disk persistence is allowed
/// to be larger, but must remain bounded so a corrupt or malicious dump file
/// cannot cause an unbounded allocation during startup.
pub(super) const MAX_PERSISTED_CACHE_DUMP_BYTES: usize = 64 * 1024 * 1024;

/// Build the cache-persistence wincode configuration with an explicit
/// deserialization preallocation budget. This keeps the existing wire format
/// (little-endian, fixed-width integers and bincode-compatible lengths) while
/// replacing wincode's default 4 MiB sequence-allocation limit with the
/// caller's already-enforced dump-size budget.
#[inline]
fn cache_wincode_config<const PREALLOCATION_LIMIT: usize>() -> impl wincode::config::Config {
    wincode::config::Configuration::default().with_preallocation_size_limit::<PREALLOCATION_LIMIT>()
}

#[derive(Debug)]
pub(super) enum CacheDumpOutcome {
    Complete(Vec<u8>),
    TooLarge { limit: usize, minimum_size: usize },
}

static DUMP_TMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, SchemaRead, SchemaWrite)]
struct PersistedCacheDump {
    magic: u64,
    version: u32,
    dumped_at_unix_ms: u64,
    entries: Vec<PersistedCacheEntry>,
}

#[derive(Debug, SchemaRead, SchemaWrite)]
struct PersistedCacheDumpPrefix {
    magic: u64,
    version: u32,
}

#[derive(Debug, SchemaRead, SchemaWrite)]
struct PersistedCacheDumpV3Header {
    magic: u64,
    version: u32,
    dumped_at_unix_ms: u64,
    entry_count: u64,
}

#[derive(Debug, Clone, SchemaRead, SchemaWrite)]
struct PersistedCacheEntry {
    domain: String,
    record_type: u16,
    dns_class: u16,
    do_bit: bool,
    cd_bit: bool,
    ecs_family: Option<u16>,
    ecs_source_prefix: Option<u8>,
    ecs_scope_prefix: Option<u8>,
    ecs_network: Option<Vec<u8>>,
    resp_bytes: Vec<u8>,
    cache_age_ms: u64,
    last_access_age_ms: u64,
    ttl: u32,
    remaining_ttl_ms: u64,
}

struct PreparedCacheEntry {
    key: CacheKey,
    value: CacheItem,
    cache_time_ms: u64,
    expire_at_ms: u64,
    last_access_ms: u64,
    restore_cache_age_ms: u64,
    restore_last_access_age_ms: u64,
}

fn invalid_dump(message: impl Into<String>) -> DnsError {
    DnsError::Runtime(format!("invalid cache dump: {}", message.into()))
}

#[cfg(unix)]
async fn sync_parent_directory(path: &str) -> Result<()> {
    let path = Path::new(path);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent).await?;
    directory.sync_all().await?;
    Ok(())
}

#[cfg(not(unix))]
async fn sync_parent_directory(_path: &str) -> Result<()> {
    // Directory fsync is not portable. The temporary file is already synced
    // before rename; platforms without a supported directory handle must not
    // report a successful dump as failed solely because this optional
    // durability step is unavailable.
    Ok(())
}

pub(super) async fn dump_cache_to_file(cache_map: &CacheMap, dump_path: &str) -> Result<()> {
    let cache_map = cache_map.clone();
    let encoded = tokio::task::spawn_blocking(move || dump_cache_to_bytes(&cache_map))
        .await
        .map_err(|err| DnsError::Runtime(format!("cache dump worker failed: {err}")))??;

    if encoded.len() > MAX_PERSISTED_CACHE_DUMP_BYTES {
        return Err(DnsError::Runtime(format!(
            "cache dump too large: {} bytes exceeds persistence limit of {} bytes",
            encoded.len(),
            MAX_PERSISTED_CACHE_DUMP_BYTES,
        )));
    }
    // Use a unique temporary file so concurrent dumps cannot truncate each
    // other's staging file. fsync both the file and the parent directory so
    // the rename is durable on filesystems that support directory fsync.
    let sequence = DUMP_TMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let tmp_path = format!("{dump_path}.tmp.{}.{}", std::process::id(), sequence);

    let write_result: Result<()> = async {
        let mut file = File::create(&tmp_path).await?;
        file.write_all(&encoded).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&tmp_path, dump_path).await?;
        sync_parent_directory(dump_path).await?;
        Ok(())
    }
    .await;

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp_path).await;
    }

    write_result
}

fn serialized_size_to_usize(size: u64) -> Result<usize> {
    usize::try_from(size).map_err(|_| DnsError::Runtime("cache dump serialized size exceeds usize".to_string()))
}

fn persisted_entry_serialized_size<const PREALLOCATION_LIMIT: usize>(entry: &PersistedCacheEntry) -> Result<usize> {
    serialized_size_to_usize(wincode::config::serialized_size(
        entry,
        cache_wincode_config::<PREALLOCATION_LIMIT>(),
    )?)
}

fn v3_header_serialized_size<const PREALLOCATION_LIMIT: usize>() -> Result<usize> {
    let header = PersistedCacheDumpV3Header {
        magic: CACHE_DUMP_MAGIC,
        version: CACHE_DUMP_VERSION,
        dumped_at_unix_ms: 0,
        entry_count: 0,
    };
    serialized_size_to_usize(wincode::config::serialized_size(
        &header,
        cache_wincode_config::<PREALLOCATION_LIMIT>(),
    )?)
}

fn frame_len_serialized_size<const PREALLOCATION_LIMIT: usize>() -> Result<usize> {
    serialized_size_to_usize(wincode::config::serialized_size(
        &0u64,
        cache_wincode_config::<PREALLOCATION_LIMIT>(),
    )?)
}

fn prepare_persisted_entry(
    key: &CacheKey,
    item: &TtlCacheHandle<CacheItem>,
    now_elapsed_ms: u64,
) -> Option<PersistedCacheEntry> {
    let value = item.value();

    if item.expire_at_ms() <= now_elapsed_ms {
        return None;
    }

    let remaining_ttl_ms = item.expire_at_ms().saturating_sub(now_elapsed_ms);
    if remaining_ttl_ms == 0 {
        return None;
    }

    if !value.is_validated() {
        let disposition = response_disposition_for_cache(&value.resp, key);
        if !is_cache_disposition_valid(disposition) {
            return None;
        }
    }

    let resp_bytes = match value.resp.to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!("Failed to encode cached DNS message for {}: {}", key.domain, err);
            return None;
        }
    };

    let (ecs_family, ecs_source_prefix, ecs_scope_prefix, ecs_network) = match &key.ecs_scope {
        Some(ecs) => {
            let network_len = usize::from(ecs.network_len);
            if network_len > ecs.network.len()
                || canonical_ecs_key_digest(
                    ecs.family,
                    ecs.source_prefix,
                    ecs.scope_prefix,
                    &ecs.network[..network_len],
                )
                .is_none()
            {
                warn!(
                    "Skip cache entry with invalid ECS metadata while dumping: {}",
                    key.domain
                );
                return None;
            }
            (
                Some(ecs.family),
                Some(ecs.source_prefix),
                Some(ecs.scope_prefix),
                Some(ecs.network[..network_len].to_vec()),
            )
        }
        None => (None, None, None, None),
    };

    // Persist the true accumulated cache age, not freshness-derived age.
    // Once an entry becomes stale, fresh_until_ms no longer advances, so using
    // it to reconstruct age would pin every stale entry at exactly its fresh
    // TTL and could incorrectly revive it under a shorter lazy-retention
    // policy.
    let cache_age_ms = value.total_cache_age_ms(item.cache_time_ms(), now_elapsed_ms);

    Some(PersistedCacheEntry {
        domain: key.domain.to_string(),
        record_type: u16::from(key.record_type),
        dns_class: u16::from(key.dns_class),
        do_bit: key.do_bit,
        cd_bit: key.cd_bit,
        ecs_family,
        ecs_source_prefix,
        ecs_scope_prefix,
        ecs_network,
        resp_bytes,
        cache_age_ms,
        last_access_age_ms: now_elapsed_ms.saturating_sub(item.last_access_ms()),
        ttl: value.ttl,
        remaining_ttl_ms,
    })
}

/// Serialize a cache dump under both a wire-size limit and the wincode
/// preallocation budget that the corresponding reader will use. Keeping the
/// writer and reader on the same `PREALLOCATION_LIMIT` prevents the API from
/// emitting a dump that its own bounded loader would reject.
pub(super) fn dump_cache_to_bytes_with_limit<const PREALLOCATION_LIMIT: usize>(
    cache_map: &CacheMap,
    max_bytes: usize,
) -> Result<CacheDumpOutcome> {
    let now_elapsed_ms = AppClock::elapsed_millis();
    let dumped_at_unix_ms = AppClock::now_timestamp();
    let header_size = v3_header_serialized_size::<PREALLOCATION_LIMIT>()?;
    let frame_len_size = frame_len_serialized_size::<PREALLOCATION_LIMIT>()?;
    let mut encoded_size = header_size;

    if encoded_size > max_bytes {
        return Ok(CacheDumpOutcome::TooLarge {
            limit: max_bytes,
            minimum_size: encoded_size,
        });
    }

    // Keep dump construction bounded by the configured wire-size cap. Version
    // 3 frames each entry independently so the reader can deserialize one
    // entry at a time without first allocating Vec<PersistedCacheEntry>.
    let mut entries: Vec<(PersistedCacheEntry, usize)> = Vec::with_capacity(cache_map.entry_count().min(4096));
    let mut build_error: Option<DnsError> = None;
    let mut too_large: Option<usize> = None;

    cache_map.visit_handles_cloned_by_shard(|batch| {
        for (key, item) in batch {
            let Some(entry) = prepare_persisted_entry(&key, &item, now_elapsed_ms) else {
                continue;
            };

            let entry_size = match persisted_entry_serialized_size::<PREALLOCATION_LIMIT>(&entry) {
                Ok(size) => size,
                Err(err) => {
                    build_error = Some(err);
                    return false;
                }
            };

            let minimum_size = encoded_size.saturating_add(frame_len_size).saturating_add(entry_size);
            if minimum_size > max_bytes {
                too_large = Some(minimum_size);
                return false;
            }

            encoded_size = minimum_size;
            entries.push((entry, entry_size));
        }
        true
    });

    if let Some(err) = build_error {
        return Err(err);
    }
    if let Some(minimum_size) = too_large {
        return Ok(CacheDumpOutcome::TooLarge {
            limit: max_bytes,
            minimum_size,
        });
    }

    let entry_count = u64::try_from(entries.len())
        .map_err(|_| DnsError::Runtime("cache dump entry count exceeds u64".to_string()))?;
    let header = PersistedCacheDumpV3Header {
        magic: CACHE_DUMP_MAGIC,
        version: CACHE_DUMP_VERSION,
        dumped_at_unix_ms,
        entry_count,
    };

    let mut encoded = Vec::with_capacity(encoded_size);
    encoded.extend_from_slice(&wincode::config::serialize(
        &header,
        cache_wincode_config::<PREALLOCATION_LIMIT>(),
    )?);

    for (entry, entry_size) in entries {
        let entry_len = u64::try_from(entry_size)
            .map_err(|_| DnsError::Runtime("cache dump entry frame exceeds u64".to_string()))?;
        encoded.extend_from_slice(&wincode::config::serialize(
            &entry_len,
            cache_wincode_config::<PREALLOCATION_LIMIT>(),
        )?);
        let frame = wincode::config::serialize(&entry, cache_wincode_config::<PREALLOCATION_LIMIT>())?;
        debug_assert_eq!(frame.len(), entry_size);
        encoded.extend_from_slice(&frame);
    }

    debug_assert_eq!(encoded.len(), encoded_size);
    Ok(CacheDumpOutcome::Complete(encoded))
}

pub(super) fn dump_cache_to_bytes(cache_map: &CacheMap) -> Result<Vec<u8>> {
    match dump_cache_to_bytes_with_limit::<MAX_PERSISTED_CACHE_DUMP_BYTES>(cache_map, MAX_PERSISTED_CACHE_DUMP_BYTES)? {
        CacheDumpOutcome::Complete(bytes) => Ok(bytes),
        CacheDumpOutcome::TooLarge { limit, minimum_size } => Err(DnsError::Runtime(format!(
            "cache dump too large: requires at least {minimum_size} bytes, limit is {limit} bytes"
        ))),
    }
}

fn persisted_dump_prefix_size<const PREALLOCATION_LIMIT: usize>() -> Result<usize> {
    let prefix = PersistedCacheDumpPrefix {
        magic: CACHE_DUMP_MAGIC,
        version: CACHE_DUMP_VERSION,
    };
    serialized_size_to_usize(wincode::config::serialized_size(
        &prefix,
        cache_wincode_config::<PREALLOCATION_LIMIT>(),
    )?)
}

fn parse_dump_prefix<const PREALLOCATION_LIMIT: usize>(data: &[u8]) -> Result<PersistedCacheDumpPrefix> {
    let prefix_size = persisted_dump_prefix_size::<PREALLOCATION_LIMIT>()?;
    if data.len() < prefix_size {
        return Err(invalid_dump("truncated header"));
    }
    let prefix = wincode::config::deserialize_exact::<PersistedCacheDumpPrefix, _>(
        &data[..prefix_size],
        cache_wincode_config::<PREALLOCATION_LIMIT>(),
    )
    .map_err(|err| invalid_dump(format!("failed to deserialize header: {err}")))?;
    if prefix.magic != CACHE_DUMP_MAGIC {
        return Err(invalid_dump("bad magic or legacy unversioned format"));
    }
    Ok(prefix)
}

fn parse_legacy_persisted_dump_with_limit<const PREALLOCATION_LIMIT: usize>(data: &[u8]) -> Result<PersistedCacheDump> {
    let dump = wincode::config::deserialize_exact::<PersistedCacheDump, _>(
        data,
        cache_wincode_config::<PREALLOCATION_LIMIT>(),
    )
    .map_err(|err| invalid_dump(format!("failed to deserialize: {err}")))?;

    if dump.magic != CACHE_DUMP_MAGIC {
        return Err(invalid_dump("bad magic or legacy unversioned format"));
    }
    if dump.version != LEGACY_CACHE_DUMP_VERSION && dump.version != PREVIOUS_CACHE_DUMP_VERSION {
        return Err(invalid_dump(format!(
            "unsupported legacy version {}, expected {} or {}",
            dump.version, LEGACY_CACHE_DUMP_VERSION, PREVIOUS_CACHE_DUMP_VERSION
        )));
    }
    Ok(dump)
}

#[cfg(test)]
fn parse_persisted_dump_with_limit<const PREALLOCATION_LIMIT: usize>(data: &[u8]) -> Result<PersistedCacheDump> {
    let prefix = parse_dump_prefix::<PREALLOCATION_LIMIT>(data)?;
    match prefix.version {
        LEGACY_CACHE_DUMP_VERSION | PREVIOUS_CACHE_DUMP_VERSION => {
            parse_legacy_persisted_dump_with_limit::<PREALLOCATION_LIMIT>(data)
        }
        CACHE_DUMP_VERSION => decode_v3_dump_for_test::<PREALLOCATION_LIMIT>(data),
        version => Err(invalid_dump(format!(
            "unsupported version {version}, expected {}, {} or {}",
            LEGACY_CACHE_DUMP_VERSION, PREVIOUS_CACHE_DUMP_VERSION, CACHE_DUMP_VERSION
        ))),
    }
}

#[cfg(test)]
fn parse_persisted_dump(data: &[u8]) -> Result<PersistedCacheDump> {
    parse_persisted_dump_with_limit::<MAX_PERSISTED_CACHE_DUMP_BYTES>(data)
}

/// Convert persisted key material into a runtime key.
///
/// `Ok(None)` is reserved for a valid entry that cannot safely be merged into
/// the current runtime configuration (currently an ECS-keyed entry while
/// `ecs_in_key == false`). Malformed key metadata is an error so a replacement
/// load can abort before mutating the live cache.
fn to_cache_key(entry: &PersistedCacheEntry, ecs_in_key: bool) -> Result<Option<CacheKey>> {
    let domain = normalize_cache_key_domain(&entry.domain)
        .ok_or_else(|| invalid_dump("entry contains invalid DNS domain text"))?;

    let ecs_scope = match (
        entry.ecs_family,
        entry.ecs_source_prefix,
        entry.ecs_scope_prefix,
        entry.ecs_network.as_ref(),
    ) {
        (None, None, None, None) => None,
        (Some(family), Some(source_prefix), Some(scope_prefix), Some(network)) => {
            let canonical = canonical_ecs_key_digest(family, source_prefix, scope_prefix, network)
                .ok_or_else(|| invalid_dump(format!("entry for {domain} contains noncanonical ECS metadata")))?;
            if !ecs_in_key {
                // Never merge persisted ECS variants into a shared non-ECS
                // bucket. Such entries can contain location-dependent answers.
                return Ok(None);
            }

            Some(canonical)
        }
        _ => {
            return Err(invalid_dump(format!(
                "entry for {domain} contains partial ECS metadata"
            )));
        }
    };

    Ok(Some(CacheKey {
        domain: domain.into(),
        record_type: RecordType::from(entry.record_type),
        dns_class: DNSClass::from(entry.dns_class),
        do_bit: entry.do_bit,
        cd_bit: entry.cd_bit,
        ecs_scope,
    }))
}

fn prepare_loaded_entry(
    entry: PersistedCacheEntry,
    ecs_in_key: bool,
    policy: CacheLoadPolicy,
    dump_version: u32,
    now_elapsed_ms: u64,
    downtime_ms: u64,
) -> Result<Option<PreparedCacheEntry>> {
    let remaining_before_clamp = entry.remaining_ttl_ms.saturating_sub(downtime_ms);
    if remaining_before_clamp == 0 {
        return Ok(None);
    }

    let effective_cache_age_ms = entry.cache_age_ms.saturating_add(downtime_ms);
    let effective_last_access_age_ms = entry.last_access_age_ms.saturating_add(downtime_ms);

    let Some(key) = to_cache_key(&entry, ecs_in_key)? else {
        return Ok(None);
    };

    let resp = Message::from_bytes(&entry.resp_bytes)
        .map_err(|err| invalid_dump(format!("failed to parse DNS message for {}: {}", entry.domain, err)))?;

    let disposition = response_disposition_for_cache(&resp, &key);
    if !is_cache_disposition_valid(disposition) {
        // A structurally valid dump can contain entries that are no longer
        // cacheable under current validation rules. Skip those entries.
        return Ok(None);
    }

    if !persisted_ecs_key_matches_response(&key, &resp) {
        return Err(invalid_dump(format!(
            "entry for {} contains ECS metadata inconsistent with its response",
            entry.domain
        )));
    }

    // Version 1 derived cache_age_ms from the freshness deadline. For an
    // entry that was already stale when dumped, that value is pinned at
    // ttl_ms and its real age is unrecoverable. Keep compatible v1 fresh
    // entries, whose age is exact, but conservatively drop ambiguous stale
    // entries instead of potentially reviving them under a new lazy TTL.
    if dump_version == LEGACY_CACHE_DUMP_VERSION && entry.cache_age_ms >= u64::from(entry.ttl).saturating_mul(1000) {
        return Ok(None);
    }

    let (ttl, fresh_remaining_ms, retention_remaining_ms) = clamp_persisted_cache_ttl(
        &resp,
        &key,
        disposition,
        entry.ttl,
        remaining_before_clamp,
        effective_cache_age_ms,
        policy,
    );
    if ttl == 0 || retention_remaining_ms == 0 {
        return Ok(None);
    }

    let expire_at_ms = now_elapsed_ms.saturating_add(retention_remaining_ms);
    let represented_cache_age_ms = effective_cache_age_ms.min(now_elapsed_ms);
    let cache_time_ms = now_elapsed_ms.saturating_sub(represented_cache_age_ms);
    let cache_age_offset_ms = effective_cache_age_ms.saturating_sub(represented_cache_age_ms);
    let last_access_ms = now_elapsed_ms.saturating_sub(effective_last_access_age_ms);

    // Freshness and stale retention are both calculated from the true
    // persisted age above. Preserve the part that the current process's
    // monotonic epoch cannot encode so later dumps continue that same age.
    let fresh_until_ms = now_elapsed_ms.saturating_add(fresh_remaining_ms);

    Ok(Some(PreparedCacheEntry {
        key,
        value: CacheItem::new_validated_with_age_offset(resp, ttl, fresh_until_ms, cache_age_offset_ms),
        cache_time_ms,
        expire_at_ms,
        last_access_ms,
        restore_cache_age_ms: effective_cache_age_ms,
        restore_last_access_age_ms: effective_last_access_age_ms,
    }))
}

struct RankedPreparedEntry {
    entry: PreparedCacheEntry,
    sequence: usize,
}

impl RankedPreparedEntry {
    #[inline]
    fn rank(&self) -> (u64, u64, usize) {
        (
            u64::MAX.saturating_sub(self.entry.restore_last_access_age_ms),
            u64::MAX.saturating_sub(self.entry.restore_cache_age_ms),
            self.sequence,
        )
    }
}

impl PartialEq for RankedPreparedEntry {
    fn eq(&self, other: &Self) -> bool {
        self.rank() == other.rank()
    }
}

impl Eq for RankedPreparedEntry {}

impl PartialOrd for RankedPreparedEntry {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for RankedPreparedEntry {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // Reverse the natural rank ordering so BinaryHeap::peek() is the
        // oldest retained candidate. A more-recent candidate can then replace
        // it in O(log cache_size) without materializing the whole dump twice.
        other.rank().cmp(&self.rank())
    }
}

struct PreparedEntryCollector {
    ecs_in_key: bool,
    policy: CacheLoadPolicy,
    dump_version: u32,
    now_elapsed_ms: u64,
    downtime_ms: u64,
    max_entries: usize,
    next_sequence: usize,
    retained: BinaryHeap<RankedPreparedEntry>,
    seen_keys: HashSet<CacheKey>,
}
impl PreparedEntryCollector {
    fn new(
        ecs_in_key: bool,
        policy: CacheLoadPolicy,
        dump_version: u32,
        dumped_at_unix_ms: u64,
        max_entries: usize,
        entry_count_hint: usize,
    ) -> Self {
        let now_elapsed_ms = AppClock::elapsed_millis();
        let now_unix_ms = AppClock::now_timestamp();
        Self {
            ecs_in_key,
            policy,
            dump_version,
            now_elapsed_ms,
            downtime_ms: now_unix_ms.saturating_sub(dumped_at_unix_ms),
            max_entries,
            next_sequence: 0,
            retained: BinaryHeap::with_capacity(max_entries.min(entry_count_hint)),
            seen_keys: HashSet::with_capacity(max_entries.min(entry_count_hint)),
        }
    }

    fn push(&mut self, persisted: PersistedCacheEntry) -> Result<()> {
        // Reject duplicate canonical cache keys before bounded retention.
        // This set stores only keys; Message/CacheItem allocations remain
        // bounded by max_entries even when the input contains many entries.
        if let Some(key) = to_cache_key(&persisted, self.ecs_in_key)?
            && !self.seen_keys.insert(key) {
                return Err(invalid_dump("duplicate canonical cache key"));
            }

        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);

        let Some(entry) = prepare_loaded_entry(
            persisted,
            self.ecs_in_key,
            self.policy,
            self.dump_version,
            self.now_elapsed_ms,
            self.downtime_ms,
        )?
        else {
            return Ok(());
        };
        if self.max_entries == 0 {
            // Continue validating every frame transactionally while retaining
            // no expensive decoded cache objects.
            return Ok(());
        }

        let candidate = RankedPreparedEntry { entry, sequence };
        if self.retained.len() < self.max_entries {
            self.retained.push(candidate);
            return Ok(());
        }

        let should_replace_oldest = self
            .retained
            .peek()
            .is_some_and(|oldest| candidate.rank() > oldest.rank());
        if should_replace_oldest {
            self.retained.pop();
            self.retained.push(candidate);
        }
        Ok(())
    }

    fn finish(self) -> Vec<PreparedCacheEntry> {
        let mut prepared: Vec<_> = self.retained.into_iter().collect();
        prepared.sort_unstable_by_key(|candidate| candidate.sequence);
        prepared.into_iter().map(|candidate| candidate.entry).collect()
    }
}

fn prepare_legacy_persisted_entries_bounded(
    dump: PersistedCacheDump,
    ecs_in_key: bool,
    policy: CacheLoadPolicy,
    max_entries: usize,
) -> Result<Vec<PreparedCacheEntry>> {
    let entry_count = dump.entries.len();
    let mut collector = PreparedEntryCollector::new(
        ecs_in_key,
        policy,
        dump.version,
        dump.dumped_at_unix_ms,
        max_entries,
        entry_count,
    );
    for persisted in dump.entries {
        collector.push(persisted)?;
    }
    Ok(collector.finish())
}

fn decode_v3_header<const PREALLOCATION_LIMIT: usize>(data: &[u8]) -> Result<(PersistedCacheDumpV3Header, usize)> {
    let header_size = v3_header_serialized_size::<PREALLOCATION_LIMIT>()?;
    if data.len() < header_size {
        return Err(invalid_dump("truncated v3 header"));
    }
    let header = wincode::config::deserialize_exact::<PersistedCacheDumpV3Header, _>(
        &data[..header_size],
        cache_wincode_config::<PREALLOCATION_LIMIT>(),
    )
    .map_err(|err| invalid_dump(format!("failed to deserialize v3 header: {err}")))?;
    if header.magic != CACHE_DUMP_MAGIC {
        return Err(invalid_dump("bad magic"));
    }
    if header.version != CACHE_DUMP_VERSION {
        return Err(invalid_dump(format!(
            "invalid framed dump version {}, expected {}",
            header.version, CACHE_DUMP_VERSION
        )));
    }
    Ok((header, header_size))
}

fn decode_v3_entry_frames<const PREALLOCATION_LIMIT: usize, F>(
    data: &[u8],
    mut on_entry: F,
) -> Result<(PersistedCacheDumpV3Header, usize)>
where
    F: FnMut(PersistedCacheEntry) -> Result<()>,
{
    let (header, mut cursor) = decode_v3_header::<PREALLOCATION_LIMIT>(data)?;
    let frame_len_size = frame_len_serialized_size::<PREALLOCATION_LIMIT>()?;
    let entry_count = usize::try_from(header.entry_count).map_err(|_| invalid_dump("entry count exceeds usize"))?;

    for _ in 0..entry_count {
        let len_end = cursor
            .checked_add(frame_len_size)
            .ok_or_else(|| invalid_dump("entry frame length offset overflow"))?;
        if len_end > data.len() {
            return Err(invalid_dump("truncated entry frame length"));
        }
        let frame_len = wincode::config::deserialize_exact::<u64, _>(
            &data[cursor..len_end],
            cache_wincode_config::<PREALLOCATION_LIMIT>(),
        )
        .map_err(|err| invalid_dump(format!("failed to deserialize entry frame length: {err}")))?;
        cursor = len_end;

        let frame_len = usize::try_from(frame_len).map_err(|_| invalid_dump("entry frame length exceeds usize"))?;
        let frame_end = cursor
            .checked_add(frame_len)
            .ok_or_else(|| invalid_dump("entry frame offset overflow"))?;
        if frame_end > data.len() {
            return Err(invalid_dump("truncated entry frame"));
        }

        let entry = wincode::config::deserialize_exact::<PersistedCacheEntry, _>(
            &data[cursor..frame_end],
            cache_wincode_config::<PREALLOCATION_LIMIT>(),
        )
        .map_err(|err| invalid_dump(format!("failed to deserialize entry frame: {err}")))?;
        on_entry(entry)?;
        cursor = frame_end;
    }

    if cursor != data.len() {
        return Err(invalid_dump("trailing bytes after final entry frame"));
    }
    Ok((header, entry_count))
}

fn prepare_v3_persisted_entries_bounded<const PREALLOCATION_LIMIT: usize>(
    data: &[u8],
    ecs_in_key: bool,
    policy: CacheLoadPolicy,
    max_entries: usize,
) -> Result<Vec<PreparedCacheEntry>> {
    let (header, _) = decode_v3_header::<PREALLOCATION_LIMIT>(data)?;
    let entry_count_hint = usize::try_from(header.entry_count).unwrap_or(max_entries);
    let mut collector = PreparedEntryCollector::new(
        ecs_in_key,
        policy,
        CACHE_DUMP_VERSION,
        header.dumped_at_unix_ms,
        max_entries,
        entry_count_hint,
    );
    decode_v3_entry_frames::<PREALLOCATION_LIMIT, _>(data, |entry| collector.push(entry))?;
    Ok(collector.finish())
}

#[cfg(test)]
fn decode_v3_dump_for_test<const PREALLOCATION_LIMIT: usize>(data: &[u8]) -> Result<PersistedCacheDump> {
    let mut entries = Vec::new();
    let (header, _) = decode_v3_entry_frames::<PREALLOCATION_LIMIT, _>(data, |entry| {
        entries.push(entry);
        Ok(())
    })?;
    Ok(PersistedCacheDump {
        magic: header.magic,
        version: header.version,
        dumped_at_unix_ms: header.dumped_at_unix_ms,
        entries,
    })
}

async fn read_cache_dump_file_bounded(dump_path: &str, expected_len: u64) -> Result<Option<Vec<u8>>> {
    let max_len = MAX_PERSISTED_CACHE_DUMP_BYTES as u64;

    if expected_len > max_len {
        warn!(
            "Cache dump {} is too large: {} bytes (limit {} bytes); ignoring persisted cache",
            dump_path, expected_len, MAX_PERSISTED_CACHE_DUMP_BYTES,
        );

        return Ok(None);
    }

    let file = File::open(dump_path).await?;

    //  Do not trust the previous metadata check as the sole protection.
    //  The file could have been replaced or grown after file_len_if_exists().
    //  Read at most limit + 1 bytes so memory usage remains bounded.
    let mut limited = file.take((MAX_PERSISTED_CACHE_DUMP_BYTES as u64).saturating_add(1));

    let initial_capacity = usize::try_from(expected_len)
        .unwrap_or(MAX_PERSISTED_CACHE_DUMP_BYTES)
        .min(MAX_PERSISTED_CACHE_DUMP_BYTES);

    let mut data = Vec::with_capacity(initial_capacity);

    limited.read_to_end(&mut data).await?;

    if data.len() > MAX_PERSISTED_CACHE_DUMP_BYTES {
        warn!(
            "Cache dump {} exceeded size limit while reading (limit {} bytes); ignoring persisted cache",
            dump_path, MAX_PERSISTED_CACHE_DUMP_BYTES,
        );

        return Ok(None);
    }

    Ok(Some(data))
}

pub(super) async fn load_cache_from_file(
    cache_map: &CacheMap,
    dump_path: &str,
    ecs_in_key: bool,
    ecs_lookup_index: Arc<EcsLookupIndex>,
    policy: CacheLoadPolicy,
    max_entries: usize,
) -> Result<()> {
    let Some(file_len) = file_len_if_exists(dump_path).await? else {
        return Ok(());
    };

    if file_len == 0 {
        return Ok(());
    }

    //  Persistence is optional. An oversized dump is treated in the same spirit
    //  as a corrupt/unsupported dump: log it and continue startup without
    //  persisted cache.
    let Some(data) = read_cache_dump_file_bounded(dump_path, file_len).await? else {
        return Ok(());
    };

    let cache_map = cache_map.clone();

    let loaded = match tokio::task::spawn_blocking(move || {
        load_cache_from_bytes_with_index_bounded::<MAX_PERSISTED_CACHE_DUMP_BYTES>(
            &cache_map,
            &data,
            ecs_in_key,
            policy,
            false,
            &ecs_lookup_index,
            max_entries,
        )
    })
    .await
    {
        Ok(Ok(loaded)) => loaded,

        Ok(Err(err)) => {
            // Persistence is optional. A corrupt, legacy, unsupported or
            // otherwise invalid dump must not prevent DNS service startup.
            warn!(
                "Failed to load cache dump from {}: {}; ignoring persisted cache",
                dump_path, err
            );

            return Ok(());
        }

        Err(err) => {
            return Err(DnsError::Runtime(format!("cache load worker failed: {err}")));
        }
    };

    if loaded > 0 {
        info!("Loaded {} cache entries from {}", loaded, dump_path);
    }

    Ok(())
}

#[cfg(test)]
pub(super) fn load_cache_from_bytes(
    cache_map: &CacheMap,
    data: &[u8],
    ecs_in_key: bool,
    policy: CacheLoadPolicy,
    replace: bool,
) -> Result<usize> {
    // Keep the test/utility entry point self-contained. Runtime startup and API
    // staging use `load_cache_from_bytes_with_index` so their plugin-level
    // per-key ECS lookup index is populated before entries become visible.
    let index = EcsLookupIndex::new();
    load_cache_from_bytes_with_index::<MAX_PERSISTED_CACHE_DUMP_BYTES>(
        cache_map, data, ecs_in_key, policy, replace, &index,
    )
}

#[cfg(test)]
fn load_cache_from_bytes_with_index<const PREALLOCATION_LIMIT: usize>(
    cache_map: &CacheMap,
    data: &[u8],
    ecs_in_key: bool,
    policy: CacheLoadPolicy,
    replace: bool,
    ecs_lookup_index: &EcsLookupIndex,
) -> Result<usize> {
    load_cache_from_bytes_with_index_bounded::<PREALLOCATION_LIMIT>(
        cache_map,
        data,
        ecs_in_key,
        policy,
        replace,
        ecs_lookup_index,
        usize::MAX,
    )
}

fn load_cache_from_bytes_with_index_bounded<const PREALLOCATION_LIMIT: usize>(
    cache_map: &CacheMap,
    data: &[u8],
    ecs_in_key: bool,
    policy: CacheLoadPolicy,
    replace: bool,
    ecs_lookup_index: &EcsLookupIndex,
    max_entries: usize,
) -> Result<usize> {
    // Transaction boundary: validate the entire dump before touching the
    // destination cache. Version 3 decodes one framed entry at a time, so it
    // never materializes Vec<PersistedCacheEntry>; only the retained top-N
    // cache objects plus duplicate-key metadata scale with input entry count.
    let prefix = parse_dump_prefix::<PREALLOCATION_LIMIT>(data)?;
    let prepared = match prefix.version {
        LEGACY_CACHE_DUMP_VERSION | PREVIOUS_CACHE_DUMP_VERSION => {
            let dump = parse_legacy_persisted_dump_with_limit::<PREALLOCATION_LIMIT>(data)?;
            prepare_legacy_persisted_entries_bounded(dump, ecs_in_key, policy, max_entries)?
        }
        CACHE_DUMP_VERSION => {
            prepare_v3_persisted_entries_bounded::<PREALLOCATION_LIMIT>(data, ecs_in_key, policy, max_entries)?
        }
        version => {
            return Err(invalid_dump(format!(
                "unsupported version {version}, expected {}, {} or {}",
                LEGACY_CACHE_DUMP_VERSION, PREVIOUS_CACHE_DUMP_VERSION, CACHE_DUMP_VERSION
            )));
        }
    };

    if replace {
        cache_map.clear();
    }

    let mut loaded = 0usize;
    for entry in prepared {
        // Publish the per-base-key ECS prefix membership before the cache
        // entry. A rejected/older insert may leave a harmless
        // false-positive membership, which maintenance later reconciles
        // from the authoritative cache map.
        ecs_lookup_index.observe_cache_key(&entry.key);
        let inserted = cache_map.insert_if_not_newer(
            entry.key,
            entry.value,
            entry.cache_time_ms,
            entry.expire_at_ms,
            entry.last_access_ms,
        );
        if inserted {
            loaded += 1;
        }
    }

    Ok(loaded)
}

/// Deserialize a dump into an isolated cache state for a later atomic publish.
///
/// The returned cache has never been visible to request handling, so a dropped
/// caller or cancelled blocking task cannot mutate the live cache.
#[cfg(feature = "api")]
pub(super) fn stage_cache_from_bytes<const PREALLOCATION_LIMIT: usize>(
    data: &[u8],
    ecs_in_key: bool,
    policy: CacheLoadPolicy,
    ecs_lookup_index: &EcsLookupIndex,
    capacity: usize,
    max_entries: usize,
) -> Result<CacheMap> {
    let staged = CacheMap::with_capacity(capacity);
    load_cache_from_bytes_with_index_bounded::<PREALLOCATION_LIMIT>(
        &staged,
        data,
        ecs_in_key,
        policy,
        false,
        ecs_lookup_index,
        max_entries,
    )?;
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::rdata::{CNAME, SOA};
    use crate::proto::{Name, Question, RData, Record};

    fn first_cache_entry(cache_map: &CacheMap) -> (CacheKey, TtlCacheHandle<CacheItem>) {
        let mut found = None;
        cache_map.visit_handles(|key, handle| {
            found = Some((key.clone(), handle));
            false
        });
        found.expect("cache entry should exist")
    }

    fn make_entry() -> PersistedCacheEntry {
        PersistedCacheEntry {
            domain: "WWW.Example.COM.".to_string(),
            record_type: u16::from(RecordType::AAAA),
            dns_class: u16::from(DNSClass::IN),
            do_bit: true,
            cd_bit: false,
            ecs_family: Some(2),
            ecs_source_prefix: Some(56),
            ecs_scope_prefix: Some(56),
            ecs_network: Some(vec![0x20, 0x01, 0x0D, 0xB8, 0, 0, 0]),
            resp_bytes: vec![0, 1, 2],
            cache_age_ms: 10,
            last_access_age_ms: 5,
            ttl: 60,
            remaining_ttl_ms: 30_000,
        }
    }

    fn serialize_dump_at_version(version: u32, entries: Vec<PersistedCacheEntry>, dumped_at_unix_ms: u64) -> Vec<u8> {
        if version != CACHE_DUMP_VERSION {
            return wincode::config::serialize(
                &PersistedCacheDump {
                    magic: CACHE_DUMP_MAGIC,
                    version,
                    dumped_at_unix_ms,
                    entries,
                },
                cache_wincode_config::<MAX_PERSISTED_CACHE_DUMP_BYTES>(),
            )
            .expect("legacy dump should serialize");
        }

        let header = PersistedCacheDumpV3Header {
            magic: CACHE_DUMP_MAGIC,
            version,
            dumped_at_unix_ms,
            entry_count: u64::try_from(entries.len()).expect("test entry count should fit u64"),
        };
        let mut encoded = wincode::config::serialize(&header, cache_wincode_config::<MAX_PERSISTED_CACHE_DUMP_BYTES>())
            .expect("v3 header should serialize");
        for entry in entries {
            let frame = wincode::config::serialize(&entry, cache_wincode_config::<MAX_PERSISTED_CACHE_DUMP_BYTES>())
                .expect("v3 entry should serialize");
            let frame_len = u64::try_from(frame.len()).expect("test frame length should fit u64");
            encoded.extend_from_slice(
                &wincode::config::serialize(&frame_len, cache_wincode_config::<MAX_PERSISTED_CACHE_DUMP_BYTES>())
                    .expect("frame length should serialize"),
            );
            encoded.extend_from_slice(&frame);
        }
        encoded
    }

    fn serialize_dump_at(entries: Vec<PersistedCacheEntry>, dumped_at_unix_ms: u64) -> Vec<u8> {
        serialize_dump_at_version(CACHE_DUMP_VERSION, entries, dumped_at_unix_ms)
    }

    fn serialize_current_dump(entries: Vec<PersistedCacheEntry>) -> Vec<u8> {
        serialize_dump_at(entries, AppClock::now_timestamp())
    }

    #[test]
    fn test_explicit_wincode_config_preserves_legacy_v2_wire_format() {
        let dump = PersistedCacheDump {
            magic: CACHE_DUMP_MAGIC,
            version: PREVIOUS_CACHE_DUMP_VERSION,
            dumped_at_unix_ms: 123_456,
            entries: vec![make_entry()],
        };

        let legacy_bytes = wincode::serialize(&dump).expect("default config should serialize");
        let configured_bytes =
            wincode::config::serialize(&dump, cache_wincode_config::<MAX_PERSISTED_CACHE_DUMP_BYTES>())
                .expect("explicit config should serialize");

        assert_eq!(configured_bytes, legacy_bytes);
    }

    #[test]
    fn test_explicit_preallocation_budget_allows_dump_above_default_four_mib() {
        const FOUR_MIB: usize = 4 * 1024 * 1024;
        const API_BUDGET: usize = 16 * 1024 * 1024;

        let mut entry = make_entry();
        entry.resp_bytes = vec![0xA5; 5 * 1024 * 1024];

        let bytes = serialize_dump_at_version(CACHE_DUMP_VERSION, vec![entry], 123_456);

        assert!(bytes.len() < API_BUDGET);
        assert!(parse_persisted_dump_with_limit::<FOUR_MIB>(&bytes).is_err());
        assert!(parse_persisted_dump_with_limit::<API_BUDGET>(&bytes).is_ok());
    }

    #[test]
    fn test_load_rejects_duplicate_canonical_cache_keys_before_bounded_retention() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(4);
        let now = AppClock::elapsed_millis();

        let domain = Arc::<str>::from("duplicate.example.com");
        let mut response = Message::new();
        response.set_rcode(crate::proto::Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii(domain.as_ref()).expect("test domain should parse"),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii(domain.as_ref()).expect("test domain should parse"),
            120,
            RData::A(crate::proto::rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));

        cache_map.insert_if_not_newer(
            CacheKey {
                domain,
                record_type: RecordType::A,
                dns_class: DNSClass::IN,
                do_bit: false,
                cd_bit: false,
                ecs_scope: None,
            },
            CacheItem::new_validated(response, 120, now.saturating_add(120_000)),
            now,
            now.saturating_add(120_000),
            now,
        );

        let dumped = dump_cache_to_bytes(&cache_map).expect("dump should succeed");
        let mut parsed = parse_persisted_dump(&dumped).expect("dump should parse");
        let duplicate = parsed.entries[0].clone();
        parsed.entries.push(duplicate);
        let duplicate_dump = serialize_dump_at_version(CACHE_DUMP_VERSION, parsed.entries, parsed.dumped_at_unix_ms);

        let destination = CacheMap::with_capacity(4);
        let index = EcsLookupIndex::new();
        let err = load_cache_from_bytes_with_index_bounded::<MAX_PERSISTED_CACHE_DUMP_BYTES>(
            &destination,
            &duplicate_dump,
            false,
            CacheLoadPolicy::default(),
            false,
            &index,
            1,
        )
        .expect_err("duplicate canonical keys must reject the whole dump");

        assert!(err.to_string().contains("duplicate canonical cache key"));
        assert_eq!(destination.len(), 0, "load must remain transactional");
    }

    #[test]
    fn test_dump_and_load_use_the_same_preallocation_budget() {
        const TEST_BUDGET: usize = 64 * 1024;
        const ENTRY_COUNT: usize = 128;

        AppClock::start();
        let cache_map = CacheMap::with_capacity(256);
        let now = AppClock::elapsed_millis();

        for index in 0..ENTRY_COUNT {
            let domain = Arc::<str>::from(format!("n{index}.example.com"));
            let mut response = Message::new();
            response.set_rcode(crate::proto::Rcode::NoError);
            response.add_question(Question::new(
                Name::from_ascii(domain.as_ref()).expect("test domain should parse"),
                RecordType::A,
                DNSClass::IN,
            ));
            response.add_answer(Record::from_rdata(
                Name::from_ascii(domain.as_ref()).expect("test domain should parse"),
                120,
                RData::A(crate::proto::rdata::A(std::net::Ipv4Addr::new(
                    192,
                    0,
                    2,
                    ((index % 250) + 1) as u8,
                ))),
            ));

            cache_map.insert_if_not_newer(
                CacheKey {
                    domain,
                    record_type: RecordType::A,
                    dns_class: DNSClass::IN,
                    do_bit: false,
                    cd_bit: false,
                    ecs_scope: None,
                },
                CacheItem::new_validated(response, 120, now.saturating_add(120_000)),
                now,
                now.saturating_add(120_000),
                now,
            );
        }

        let bytes = match dump_cache_to_bytes_with_limit::<TEST_BUDGET>(&cache_map, TEST_BUDGET)
            .expect("bounded dump should succeed")
        {
            CacheDumpOutcome::Complete(bytes) => bytes,
            CacheDumpOutcome::TooLarge { .. } => panic!("test dump should fit its budget"),
        };

        let restored = CacheMap::with_capacity(256);
        let index = EcsLookupIndex::new();
        let loaded = load_cache_from_bytes_with_index::<TEST_BUDGET>(
            &restored,
            &bytes,
            false,
            CacheLoadPolicy::default(),
            false,
            &index,
        )
        .expect("a dump emitted with a budget must load with the same budget");

        assert_eq!(loaded, ENTRY_COUNT);
        assert_eq!(restored.len(), ENTRY_COUNT);
    }

    fn cname_only_response_bytes() -> Vec<u8> {
        let mut response = Message::new();
        response.set_rcode(crate::proto::Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii("target.example.com.").unwrap())),
        ));
        response.to_bytes().expect("response should encode")
    }

    fn cname_nodata_response_bytes() -> Vec<u8> {
        cname_nodata_response_bytes_with_ttls(60, 30)
    }

    fn cname_nodata_response_bytes_with_ttls(cname_ttl: u32, negative_ttl: u32) -> Vec<u8> {
        let mut response = Message::new();
        response.set_rcode(crate::proto::Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            cname_ttl,
            RData::CNAME(CNAME(Name::from_ascii("target.example.com.").unwrap())),
        ));
        response.add_authority(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("hostmaster.example.com.").unwrap(),
                1,
                3600,
                600,
                86400,
                negative_ttl,
            )),
        ));
        response.to_bytes().expect("response should encode")
    }

    fn positive_response_message(ttl: u32) -> Message {
        let mut response = Message::new();
        response.set_rcode(crate::proto::Rcode::NoError);

        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));

        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::A(crate::proto::rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));

        response
    }

    fn positive_response_bytes(ttl: u32) -> Vec<u8> {
        positive_response_message(ttl)
            .to_bytes()
            .expect("response should encode")
    }

    fn valid_address_entry() -> PersistedCacheEntry {
        let mut entry = make_entry();
        entry.domain = "example.com.".to_string();
        entry.record_type = u16::from(RecordType::A);
        entry.ecs_family = None;
        entry.ecs_source_prefix = None;
        entry.ecs_scope_prefix = None;
        entry.ecs_network = None;
        entry.resp_bytes = cname_nodata_response_bytes();
        entry
    }

    fn positive_entry_for_domain(domain: &str, last_access_age_ms: u64) -> PersistedCacheEntry {
        let name = Name::from_ascii(domain).expect("test domain should parse");
        let mut response = Message::new();
        response.set_rcode(crate::proto::Rcode::NoError);
        response.add_question(Question::new(name.clone(), RecordType::A, DNSClass::IN));
        response.add_answer(Record::from_rdata(
            name,
            120,
            RData::A(crate::proto::rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));

        let mut entry = valid_address_entry();
        entry.domain = domain.to_string();
        entry.do_bit = false;
        entry.resp_bytes = response.to_bytes().expect("response should encode");
        entry.cache_age_ms = 10;
        entry.last_access_age_ms = last_access_age_ms;
        entry.ttl = 120;
        entry.remaining_ttl_ms = 120_000;
        entry
    }

    #[test]
    fn test_parse_persisted_dump_returns_error_for_invalid_bytes() {
        let parsed = parse_persisted_dump(b"not a valid cache dump");
        assert!(parsed.is_err());
    }

    #[test]
    fn test_parse_persisted_dump_rejects_trailing_bytes() {
        AppClock::start();
        let mut data = serialize_current_dump(Vec::new());
        data.extend_from_slice(b"garbage");
        assert!(parse_persisted_dump(&data).is_err());
    }

    #[test]
    fn test_bounded_load_retains_only_most_recent_entries() {
        AppClock::start();
        let entries = vec![
            positive_entry_for_domain("n0.example.com.", 500),
            positive_entry_for_domain("n1.example.com.", 400),
            positive_entry_for_domain("n2.example.com.", 300),
            positive_entry_for_domain("n3.example.com.", 200),
            positive_entry_for_domain("n4.example.com.", 100),
        ];
        let data = serialize_current_dump(entries);
        let cache_map = CacheMap::with_capacity(2);
        let index = EcsLookupIndex::new();

        let loaded = load_cache_from_bytes_with_index_bounded::<MAX_PERSISTED_CACHE_DUMP_BYTES>(
            &cache_map,
            &data,
            false,
            CacheLoadPolicy::default(),
            false,
            &index,
            2,
        )
        .expect("bounded dump should load");

        assert_eq!(loaded, 2);
        assert_eq!(cache_map.len(), 2);
        let mut domains = Vec::new();
        cache_map.visit_handles(|key, _| {
            domains.push(key.domain.to_string());
            true
        });
        domains.sort();
        assert_eq!(
            domains,
            vec!["n3.example.com".to_string(), "n4.example.com".to_string()],
        );
    }

    #[test]
    fn test_bounded_load_still_validates_entries_after_capacity_is_full() {
        AppClock::start();
        let mut corrupt = positive_entry_for_domain("bad.example.com.", 0);
        corrupt.ecs_family = Some(1);
        // Partial ECS metadata is structurally invalid and must reject the
        // entire transaction even though the retained candidate set is full.
        let data = serialize_current_dump(vec![positive_entry_for_domain("good.example.com.", 100), corrupt]);
        let cache_map = CacheMap::with_capacity(1);
        let index = EcsLookupIndex::new();

        let err = load_cache_from_bytes_with_index_bounded::<MAX_PERSISTED_CACHE_DUMP_BYTES>(
            &cache_map,
            &data,
            false,
            CacheLoadPolicy::default(),
            false,
            &index,
            1,
        )
        .expect_err("trailing invalid entry must reject the bounded load");

        assert!(err.to_string().contains("partial ECS metadata"));
        assert!(cache_map.is_empty());
    }

    #[test]
    fn test_parse_persisted_dump_rejects_unsupported_version() {
        AppClock::start();
        let data = wincode::config::serialize(
            &PersistedCacheDump {
                magic: CACHE_DUMP_MAGIC,
                version: CACHE_DUMP_VERSION + 1,
                dumped_at_unix_ms: AppClock::now_timestamp(),
                entries: Vec::new(),
            },
            cache_wincode_config::<MAX_PERSISTED_CACHE_DUMP_BYTES>(),
        )
        .expect("dump should serialize");
        assert!(parse_persisted_dump(&data).is_err());
    }

    #[test]
    fn test_load_cache_accepts_v2_dump() {
        AppClock::start();
        let mut entry = valid_address_entry();
        entry.ttl = 60;
        entry.cache_age_ms = 10_000;
        entry.remaining_ttl_ms = 50_000;
        entry.resp_bytes = positive_response_bytes(60);
        let data = serialize_dump_at_version(PREVIOUS_CACHE_DUMP_VERSION, vec![entry], AppClock::now_timestamp());

        let cache_map = CacheMap::with_capacity(1);
        assert_eq!(
            load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false)
                .expect("v2 restore should succeed"),
            1
        );
        assert_eq!(cache_map.len(), 1);
    }

    #[test]
    fn test_v3_streaming_decoder_rejects_trailing_bytes_transactionally() {
        AppClock::start();
        let mut entry = valid_address_entry();
        entry.resp_bytes = positive_response_bytes(60);
        let mut data = serialize_current_dump(vec![entry]);
        data.push(0xA5);

        let cache_map = CacheMap::with_capacity(1);
        let err = load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false)
            .expect_err("trailing bytes must reject framed dump");
        assert!(err.to_string().contains("trailing bytes"));
        assert!(cache_map.is_empty());
    }

    #[test]
    fn test_load_cache_accepts_v1_fresh_entry_with_exact_age() {
        AppClock::start();
        let mut entry = valid_address_entry();
        entry.ttl = 60;
        entry.cache_age_ms = 30_000;
        entry.remaining_ttl_ms = 30_000;
        entry.resp_bytes = positive_response_bytes(60);
        let data = serialize_dump_at_version(LEGACY_CACHE_DUMP_VERSION, vec![entry], AppClock::now_timestamp());

        let cache_map = CacheMap::with_capacity(1);
        assert_eq!(
            load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false,)
                .expect("v1 fresh restore should succeed"),
            1
        );
        assert_eq!(cache_map.len(), 1);
    }

    #[test]
    fn test_load_cache_drops_v1_stale_entry_with_ambiguous_age() {
        AppClock::start();
        let mut entry = valid_address_entry();
        entry.ttl = 60;
        entry.cache_age_ms = 60_000;
        entry.remaining_ttl_ms = 3_540_000;
        entry.resp_bytes = positive_response_bytes(60);
        let data = serialize_dump_at_version(LEGACY_CACHE_DUMP_VERSION, vec![entry], AppClock::now_timestamp());

        let cache_map = CacheMap::with_capacity(1);
        let policy = CacheLoadPolicy {
            lazy_cache_ttl: Some(3_600),
            ..CacheLoadPolicy::default()
        };
        assert_eq!(
            load_cache_from_bytes(&cache_map, &data, false, policy, false)
                .expect("v1 stale restore should be skipped safely"),
            0
        );
        assert!(cache_map.is_empty());
    }

    #[test]
    fn test_parse_persisted_dump_rejects_legacy_unversioned_dump() {
        let legacy = wincode::config::serialize(
            &vec![make_entry()],
            cache_wincode_config::<MAX_PERSISTED_CACHE_DUMP_BYTES>(),
        )
        .expect("legacy dump should serialize");
        assert!(parse_persisted_dump(&legacy).is_err());
    }

    #[test]
    fn test_to_cache_key_normalizes_domain_and_preserves_ecs_when_enabled() {
        let entry = make_entry();
        let cache_key = to_cache_key(&entry, true)
            .expect("ECS metadata should be valid")
            .expect("cache key should be built");

        assert_eq!(cache_key.domain.as_ref(), "www.example.com");
        assert_eq!(cache_key.record_type, RecordType::AAAA);
        assert_eq!(cache_key.dns_class, DNSClass::IN);
        assert!(cache_key.do_bit);
        assert!(!cache_key.cd_bit);
        let ecs = cache_key.ecs_scope.expect("ecs should be present");
        assert_eq!(ecs.family, 2);
        assert_eq!(ecs.source_prefix, 56);
        assert_eq!(ecs.scope_prefix, 56);
        assert_eq!(ecs.network_len, 7);
        assert_eq!(&ecs.network[..7], &[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0]);
    }

    #[test]
    fn test_to_cache_key_rejects_partial_ecs_metadata() {
        let mut entry = make_entry();
        entry.ecs_network = None;
        assert!(to_cache_key(&entry, true).is_err());
    }

    #[test]
    fn test_to_cache_key_rejects_oversized_ecs_network() {
        let mut entry = make_entry();
        entry.ecs_network = Some(vec![0; 17]);
        assert!(to_cache_key(&entry, true).is_err());
    }

    #[test]
    fn test_to_cache_key_rejects_noncanonical_network_length() {
        let mut entry = make_entry();
        entry.ecs_network = Some(vec![0; 6]);
        assert!(to_cache_key(&entry, true).is_err());
    }

    #[test]
    fn test_to_cache_key_rejects_nonzero_host_bits() {
        let mut entry = make_entry();
        entry.ecs_source_prefix = Some(57);
        entry.ecs_scope_prefix = Some(57);
        entry.ecs_network = Some(vec![0x20, 0x01, 0x0D, 0xB8, 0, 0, 1, 1]);
        assert!(to_cache_key(&entry, true).is_err());
    }

    #[test]
    fn test_to_cache_key_rejects_noncanonical_scope_combination() {
        let mut entry = make_entry();
        entry.ecs_scope_prefix = Some(48);
        assert!(to_cache_key(&entry, true).is_err());
    }

    #[test]
    fn test_to_cache_key_rejects_family_network_length_mismatch() {
        let mut entry = make_entry();
        entry.ecs_family = Some(1);
        entry.ecs_source_prefix = Some(24);
        entry.ecs_scope_prefix = Some(24);
        entry.ecs_network = Some(vec![192, 0, 2, 0]);
        assert!(to_cache_key(&entry, true).is_err());
    }

    #[test]
    fn test_to_cache_key_rejects_empty_normalized_domain() {
        let mut entry = make_entry();
        entry.domain = "   ".to_string();
        assert!(to_cache_key(&entry, false).is_err());
    }

    #[test]
    fn test_to_cache_key_skips_ecs_when_runtime_keying_is_disabled() {
        let entry = make_entry();
        let cache_key = to_cache_key(&entry, false).expect("entry should be structurally valid");
        assert_eq!(cache_key, None);
    }

    #[test]
    fn test_load_cache_skips_cname_only_address_entry() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(1);
        let mut entry = valid_address_entry();
        entry.resp_bytes = cname_only_response_bytes();

        let data = serialize_current_dump(vec![entry]);
        let loaded = load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false)
            .expect("load should succeed");

        assert_eq!(loaded, 0);
        assert_eq!(cache_map.len(), 0);
    }

    #[test]
    fn test_load_cache_keeps_cname_nodata_address_entry() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(1);
        let entry = valid_address_entry();

        let data = serialize_current_dump(vec![entry]);
        let loaded = load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false)
            .expect("load should succeed");

        assert_eq!(loaded, 1);
        assert_eq!(cache_map.len(), 1);
    }

    #[test]
    fn test_load_cache_rejects_response_question_mismatched_with_key() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(1);
        let mut entry = valid_address_entry();
        entry.domain = "other.example.com.".to_string();

        let data = serialize_current_dump(vec![entry]);
        let loaded = load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false)
            .expect("load should succeed");

        assert_eq!(loaded, 0);
        assert_eq!(cache_map.len(), 0);
    }

    #[test]
    fn test_load_cache_clamps_cname_nodata_to_cname_ttl() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(1);
        let mut entry = valid_address_entry();
        entry.ttl = 30;
        entry.remaining_ttl_ms = 30_000;
        entry.cache_age_ms = 2_000;
        entry.resp_bytes = cname_nodata_response_bytes_with_ttls(5, 30);

        let data = serialize_current_dump(vec![entry]);
        let loaded = load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false)
            .expect("load should succeed");
        let (_, stored) = first_cache_entry(&cache_map);

        assert_eq!(loaded, 1);
        assert_eq!(stored.value().ttl, 5);
        assert!(stored.expire_at_ms().saturating_sub(AppClock::elapsed_millis()) <= 3_000);
    }

    #[test]
    fn test_load_cache_skips_negative_entry_expired_by_clamped_ttl() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(1);
        let mut entry = valid_address_entry();
        entry.ttl = 30;
        entry.remaining_ttl_ms = 10_000;
        entry.cache_age_ms = 20_000;
        entry.resp_bytes = cname_nodata_response_bytes_with_ttls(5, 30);

        let data = serialize_current_dump(vec![entry]);
        let loaded = load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false)
            .expect("load should succeed");

        assert_eq!(loaded, 0);
        assert_eq!(cache_map.len(), 0);
    }

    #[test]
    fn test_load_cache_subtracts_process_downtime_from_remaining_ttl() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(1);
        let mut entry = valid_address_entry();
        entry.ttl = 60;
        entry.cache_age_ms = 5_000;
        entry.remaining_ttl_ms = 30_000;
        entry.resp_bytes = positive_response_bytes(60);

        let dumped_at = AppClock::now_timestamp().saturating_sub(10_000);
        let data = serialize_dump_at(vec![entry], dumped_at);
        let loaded = load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false)
            .expect("load should succeed");
        let (_, stored) = first_cache_entry(&cache_map);
        let remaining = stored.expire_at_ms().saturating_sub(AppClock::elapsed_millis());

        assert_eq!(loaded, 1);
        assert!(remaining <= 20_000, "remaining={remaining}");
        assert!(remaining >= 18_000, "remaining={remaining}");
    }

    #[test]
    fn test_redump_after_restart_does_not_rejuvenate_fresh_ttl() {
        AppClock::start();
        let first_cache = CacheMap::with_capacity(1);
        let mut entry = valid_address_entry();
        entry.ttl = 30;
        entry.cache_age_ms = 20_000;
        entry.remaining_ttl_ms = 30_000;

        let dumped_at = AppClock::now_timestamp().saturating_sub(5_000);
        let data = serialize_dump_at(vec![entry], dumped_at);
        load_cache_from_bytes(&first_cache, &data, false, CacheLoadPolicy::default(), false)
            .expect("first restore should succeed");

        let (_, first) = first_cache_entry(&first_cache);
        let first_fresh_remaining = first.value().fresh_until_ms.saturating_sub(AppClock::elapsed_millis());
        assert!(first_fresh_remaining <= 5_000, "fresh={first_fresh_remaining}");

        let redump = dump_cache_to_bytes(&first_cache).expect("redump should serialize");
        let second_cache = CacheMap::with_capacity(1);
        load_cache_from_bytes(&second_cache, &redump, false, CacheLoadPolicy::default(), false)
            .expect("second restore should succeed");

        let (_, second) = first_cache_entry(&second_cache);
        let second_fresh_remaining = second.value().fresh_until_ms.saturating_sub(AppClock::elapsed_millis());

        assert!(
            second_fresh_remaining <= first_fresh_remaining.saturating_add(50),
            "fresh TTL was rejuvenated: first={first_fresh_remaining}, second={second_fresh_remaining}"
        );
    }

    #[test]
    fn test_load_cache_drops_entry_expired_while_process_was_stopped() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(1);
        let mut entry = valid_address_entry();
        entry.remaining_ttl_ms = 5_000;

        let dumped_at = AppClock::now_timestamp().saturating_sub(10_000);
        let data = serialize_dump_at(vec![entry], dumped_at);
        let loaded = load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false)
            .expect("load should succeed");

        assert_eq!(loaded, 0);
        assert_eq!(cache_map.len(), 0);
    }

    #[test]
    fn test_replace_load_is_transactional_on_corrupt_entry() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(2);

        let initial = serialize_current_dump(vec![valid_address_entry()]);
        assert_eq!(
            load_cache_from_bytes(&cache_map, &initial, false, CacheLoadPolicy::default(), false)
                .expect("initial load should succeed"),
            1
        );
        assert_eq!(cache_map.len(), 1);

        let mut corrupt = valid_address_entry();
        corrupt.domain = "replacement.example.com.".to_string();
        corrupt.resp_bytes = vec![0, 1, 2];
        let corrupt_dump = serialize_current_dump(vec![corrupt]);

        let result = load_cache_from_bytes(&cache_map, &corrupt_dump, false, CacheLoadPolicy::default(), true);
        assert!(result.is_err());
        assert_eq!(
            cache_map.len(),
            1,
            "existing cache must survive a failed replacement load"
        );
    }

    #[test]
    fn test_replace_load_rejects_invalid_dump_without_clearing_cache() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(2);
        let initial = serialize_current_dump(vec![valid_address_entry()]);
        load_cache_from_bytes(&cache_map, &initial, false, CacheLoadPolicy::default(), false)
            .expect("initial load should succeed");
        assert_eq!(cache_map.len(), 1);

        let result = load_cache_from_bytes(&cache_map, b"not a dump", false, CacheLoadPolicy::default(), true);
        assert!(result.is_err());
        assert_eq!(cache_map.len(), 1);
    }

    #[test]
    fn test_load_cache_applies_current_positive_ttl_policy() {
        AppClock::start();
        let mut entry = valid_address_entry();
        entry.resp_bytes = positive_response_bytes(60);
        entry.ttl = 60;
        entry.remaining_ttl_ms = 60_000;
        let data = serialize_current_dump(vec![entry]);

        let capped_cache = CacheMap::with_capacity(1);
        let capped_policy = CacheLoadPolicy {
            max_positive_ttl: Some(10),
            ..CacheLoadPolicy::default()
        };
        assert_eq!(
            load_cache_from_bytes(&capped_cache, &data, false, capped_policy, false)
                .expect("capped restore should succeed"),
            1
        );
        let stored = first_cache_entry(&capped_cache);
        assert_eq!(stored.1.value().ttl, 10);
        assert!(stored.1.value().fresh_until_ms <= AppClock::elapsed_millis() + 10_000);

        let min_cache = CacheMap::with_capacity(1);
        let min_policy = CacheLoadPolicy {
            min_positive_ttl: Some(61),
            ..CacheLoadPolicy::default()
        };
        assert_eq!(
            load_cache_from_bytes(&min_cache, &data, false, min_policy, false)
                .expect("minimum TTL restore should succeed"),
            0
        );
    }

    #[test]
    fn test_load_cache_applies_current_negative_cache_policy() {
        AppClock::start();
        let data = serialize_current_dump(vec![valid_address_entry()]);
        let cache_map = CacheMap::with_capacity(1);
        let policy = CacheLoadPolicy {
            cache_negative: false,
            ..CacheLoadPolicy::default()
        };

        assert_eq!(
            load_cache_from_bytes(&cache_map, &data, false, policy, false)
                .expect("negative policy restore should succeed"),
            0
        );
        assert!(cache_map.is_empty());
    }

    #[test]
    fn test_load_cache_does_not_restore_expired_entry_as_fresh_after_ttl_relaxation() {
        AppClock::start();
        let mut entry = valid_address_entry();
        entry.resp_bytes = positive_response_bytes(300);
        // This was the effective freshness TTL when the dump was written.
        entry.ttl = 60;
        // The lazy retention period kept the entry in the dump after its
        // original freshness window had elapsed.
        entry.cache_age_ms = 600_000;
        entry.remaining_ttl_ms = 3_600_000;
        let data = serialize_current_dump(vec![entry]);

        let cache_map = CacheMap::with_capacity(1);
        let relaxed_policy = CacheLoadPolicy {
            max_positive_ttl: Some(300),
            ..CacheLoadPolicy::default()
        };

        assert_eq!(
            load_cache_from_bytes(&cache_map, &data, false, relaxed_policy, false)
                .expect("relaxed restore should succeed"),
            0
        );
        assert!(cache_map.is_empty());
    }

    #[test]
    fn test_load_cache_preserves_lazy_stale_retention_window() {
        AppClock::start();
        let mut entry = valid_address_entry();
        entry.resp_bytes = positive_response_bytes(60);
        entry.ttl = 60;
        entry.cache_age_ms = 120_000;
        entry.remaining_ttl_ms = 3_480_000;
        let data = serialize_current_dump(vec![entry]);

        let cache_map = CacheMap::with_capacity(1);
        let policy = CacheLoadPolicy {
            lazy_cache_ttl: Some(3_600),
            ..CacheLoadPolicy::default()
        };
        let load_started_at = AppClock::elapsed_millis();

        assert_eq!(
            load_cache_from_bytes(&cache_map, &data, false, policy, false).expect("lazy restore should succeed"),
            1
        );
        let load_finished_at = AppClock::elapsed_millis();
        let stored = first_cache_entry(&cache_map);
        assert!(stored.1.value().fresh_until_ms >= load_started_at);
        assert!(stored.1.value().fresh_until_ms <= load_finished_at);
        assert!(stored.1.expire_at_ms() > stored.1.value().fresh_until_ms);
        assert!(stored.1.expire_at_ms() >= load_started_at + 3_400_000);
    }

    #[test]
    fn test_redump_preserves_true_stale_age_and_shorter_lazy_ttl_drops_entry() {
        AppClock::start();
        let mut entry = valid_address_entry();
        entry.resp_bytes = positive_response_bytes(60);
        entry.ttl = 60;
        entry.cache_age_ms = 600_000;
        entry.remaining_ttl_ms = 3_000_000;
        let data = serialize_current_dump(vec![entry]);

        let first_cache = CacheMap::with_capacity(1);
        let old_policy = CacheLoadPolicy {
            lazy_cache_ttl: Some(3_600),
            ..CacheLoadPolicy::default()
        };
        assert_eq!(
            load_cache_from_bytes(&first_cache, &data, false, old_policy, false)
                .expect("stale restore should succeed under the old lazy window"),
            1
        );

        let redump = dump_cache_to_bytes(&first_cache).expect("redump should serialize");
        let parsed = parse_persisted_dump(&redump).expect("redump should parse");
        assert_eq!(parsed.version, CACHE_DUMP_VERSION);
        let redumped = parsed.entries.into_iter().next().expect("entry should be dumped");
        assert!(
            redumped.cache_age_ms >= 600_000,
            "stale cache age was rejuvenated to {}ms",
            redumped.cache_age_ms
        );

        let shortened_cache = CacheMap::with_capacity(1);
        let shortened_policy = CacheLoadPolicy {
            lazy_cache_ttl: Some(300),
            ..CacheLoadPolicy::default()
        };
        assert_eq!(
            load_cache_from_bytes(&shortened_cache, &redump, false, shortened_policy, false,)
                .expect("restore with shorter lazy TTL should succeed"),
            0
        );
        assert!(shortened_cache.is_empty());
    }

    #[test]
    fn test_load_cache_accepts_root_domain_entry() {
        AppClock::start();
        let mut response = Message::new();
        response.set_rcode(crate::proto::Rcode::NXDomain);

        let mut entry = valid_address_entry();
        entry.domain = ".".to_string();
        entry.resp_bytes = response.to_bytes().expect("root response should encode");
        entry.ttl = 60;
        entry.remaining_ttl_ms = 60_000;
        let data = serialize_current_dump(vec![entry]);
        let cache_map = CacheMap::with_capacity(1);

        assert_eq!(
            load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false,)
                .expect("root domain dump should load"),
            1
        );
        let (key, _) = first_cache_entry(&cache_map);
        assert_eq!(key.domain.as_ref(), ".");
    }

    #[test]
    fn test_load_cache_rejects_empty_domain_entry() {
        AppClock::start();
        let mut response = Message::new();
        response.set_rcode(crate::proto::Rcode::NXDomain);

        let mut entry = valid_address_entry();
        entry.domain = String::new();
        entry.resp_bytes = response.to_bytes().expect("response should encode");
        entry.ttl = 60;
        entry.remaining_ttl_ms = 60_000;
        let data = serialize_current_dump(vec![entry]);
        let cache_map = CacheMap::with_capacity(1);

        let err = load_cache_from_bytes(&cache_map, &data, false, CacheLoadPolicy::default(), false)
            .expect_err("empty domain dump entry must be rejected");

        assert!(err.to_string().contains("invalid DNS domain text"));
        assert!(cache_map.is_empty());
    }

    #[test]
    fn test_real_root_request_cache_dump_load_roundtrip() {
        AppClock::start();

        let mut request = Message::new();
        request.add_question(Question::new(Name::root(), RecordType::A, DNSClass::IN));
        let mut context =
            crate::core::context::DnsContext::new(std::net::SocketAddr::from(([127, 0, 0, 1], 5300)), request);
        let key = super::super::key::build_cache_key(&mut context, false)
            .expect("real root request should produce a cache key");
        assert_eq!(key.domain.as_ref(), ".");

        let mut response = Message::new();
        response.set_rcode(crate::proto::Rcode::NoError);
        response.add_question(Question::new(Name::root(), RecordType::A, DNSClass::IN));
        response.add_answer(Record::from_rdata(
            Name::root(),
            60,
            RData::A(crate::proto::rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));

        let now = AppClock::elapsed_millis();
        let cache_map = CacheMap::with_capacity(1);
        cache_map.insert_if_not_newer(
            key,
            CacheItem::new_validated(response, 60, now.saturating_add(60_000)),
            now,
            now.saturating_add(60_000),
            now,
        );

        let dump = dump_cache_to_bytes(&cache_map).expect("root cache should dump");
        let parsed = parse_persisted_dump(&dump).expect("root dump should parse");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].domain, ".");

        let restored = CacheMap::with_capacity(1);
        assert_eq!(
            load_cache_from_bytes(&restored, &dump, false, CacheLoadPolicy::default(), false,)
                .expect("root dump should restore"),
            1
        );
        let (restored_key, restored_entry) = first_cache_entry(&restored);
        assert_eq!(restored_key.domain.as_ref(), ".");
        assert_eq!(
            restored_entry
                .value()
                .resp
                .first_question()
                .expect("restored root response should keep its question")
                .name()
                .to_fqdn(),
            "."
        );
    }

    #[test]
    fn test_escaped_terminal_dot_request_cache_dump_load_roundtrip() {
        AppClock::start();

        let escaped_name = Name::from_ascii(r"foo\.").expect("escaped-dot name should parse");
        assert_eq!(escaped_name.normalized(), r"foo\.");

        let mut request = Message::new();
        request.add_question(Question::new(escaped_name.clone(), RecordType::A, DNSClass::IN));
        let mut context =
            crate::core::context::DnsContext::new(std::net::SocketAddr::from(([127, 0, 0, 1], 5300)), request);
        let key = super::super::key::build_cache_key(&mut context, false)
            .expect("escaped-dot request should produce a cache key");
        assert_eq!(key.domain.as_ref(), r"foo\.");

        let mut response = Message::new();
        response.set_rcode(crate::proto::Rcode::NoError);
        response.add_question(Question::new(escaped_name.clone(), RecordType::A, DNSClass::IN));
        response.add_answer(Record::from_rdata(
            escaped_name,
            60,
            RData::A(crate::proto::rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 2))),
        ));

        let now = AppClock::elapsed_millis();
        let cache_map = CacheMap::with_capacity(1);
        cache_map.insert_if_not_newer(
            key,
            CacheItem::new_validated(response, 60, now.saturating_add(60_000)),
            now,
            now.saturating_add(60_000),
            now,
        );

        let dump = dump_cache_to_bytes(&cache_map).expect("escaped-dot cache should dump");
        let parsed = parse_persisted_dump(&dump).expect("escaped-dot dump should parse");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].domain, r"foo\.");

        let restored = CacheMap::with_capacity(1);
        assert_eq!(
            load_cache_from_bytes(&restored, &dump, false, CacheLoadPolicy::default(), false,)
                .expect("escaped-dot dump should restore"),
            1
        );
        let (restored_key, restored_entry) = first_cache_entry(&restored);
        assert_eq!(restored_key.domain.as_ref(), r"foo\.");
        assert_eq!(
            restored_entry
                .value()
                .resp
                .first_question()
                .expect("restored escaped-dot response should keep its question")
                .name()
                .normalized(),
            r"foo\."
        );
    }

    #[test]
    fn test_scope_zero_ecs_entry_survives_dump_roundtrip() {
        AppClock::start();

        let cache_map = CacheMap::with_capacity(4);

        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));

        let mut request_edns = crate::proto::Edns::new();
        request_edns.insert(crate::proto::EdnsOption::Subnet(crate::proto::ClientSubnet::new(
            std::net::IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.set_edns(request_edns);

        let mut context =
            crate::core::context::DnsContext::new(std::net::SocketAddr::from(([127, 0, 0, 1], 5300)), request);

        let request_key = super::super::key::build_cache_key(&mut context, true).expect("request key should exist");

        let mut response = positive_response_message(120);

        let mut response_edns = crate::proto::Edns::new();
        response_edns.insert(crate::proto::EdnsOption::Subnet(crate::proto::ClientSubnet::new(
            std::net::IpAddr::from([203, 0, 113, 0]),
            24,
            0,
        )));
        response.set_edns(response_edns);

        let stored_key = super::super::key::cache_key_for_response_ecs_scope(&request_key, &response)
            .expect("ECS response should be cacheable");

        let now = AppClock::elapsed_millis();

        cache_map.insert_if_not_newer(
            stored_key,
            CacheItem::new_validated(response, 120, now.saturating_add(120_000)),
            now,
            now.saturating_add(120_000),
            now,
        );

        let dump = dump_cache_to_bytes(&cache_map).expect("dump should succeed");

        let restored = CacheMap::with_capacity(4);
        let index = EcsLookupIndex::new();

        let loaded = load_cache_from_bytes_with_index::<MAX_PERSISTED_CACHE_DUMP_BYTES>(
            &restored,
            &dump,
            true,
            CacheLoadPolicy::default(),
            false,
            &index,
        )
        .expect("SCOPE=0 dump should load");

        assert_eq!(loaded, 1);
        assert_eq!(restored.len(), 1);
        assert_eq!(index.observed_ipv4_prefixes(), 1);
    }

    #[test]
    fn bounded_dump_accepts_exact_size_and_rejects_one_byte_less() {
        AppClock::start();

        let cache_map = CacheMap::with_capacity(1);
        let now = AppClock::elapsed_millis();
        let key = CacheKey {
            domain: Arc::<str>::from("example.com"),
            record_type: RecordType::A,
            dns_class: DNSClass::IN,
            do_bit: false,
            cd_bit: false,
            ecs_scope: None,
        };
        cache_map.insert_if_not_newer(
            key,
            CacheItem::new_validated(positive_response_message(120), 120, now.saturating_add(120_000)),
            now,
            now.saturating_add(120_000),
            now,
        );

        let full = dump_cache_to_bytes(&cache_map).expect("dump should succeed");
        let exact_limit = full.len();

        match dump_cache_to_bytes_with_limit::<MAX_PERSISTED_CACHE_DUMP_BYTES>(&cache_map, exact_limit)
            .expect("exact-limit dump should succeed")
        {
            CacheDumpOutcome::Complete(bytes) => assert_eq!(bytes.len(), exact_limit),
            CacheDumpOutcome::TooLarge { .. } => panic!("exact limit must be accepted"),
        }

        match dump_cache_to_bytes_with_limit::<MAX_PERSISTED_CACHE_DUMP_BYTES>(&cache_map, exact_limit - 1)
            .expect("bounded dump should report size overflow")
        {
            CacheDumpOutcome::Complete(_) => panic!("one-byte-short limit must be rejected"),
            CacheDumpOutcome::TooLarge { limit, minimum_size } => {
                assert_eq!(limit, exact_limit - 1);
                assert!(minimum_size > limit);
            }
        }
    }
}
