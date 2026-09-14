// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{info, warn};

#[cfg(test)]
use super::CacheMetrics;
#[cfg(test)]
use super::key::EcsLookupIndex;
use super::key::{
    CacheKey, canonical_ecs_key_digest, normalize_cache_key_domain, normalize_domain_key,
};
#[cfg(test)]
use super::persistence::dump_cache_to_bytes;
use super::persistence::{
    CacheDumpOutcome, dump_cache_to_bytes_with_limit_for_mode, stage_cache_from_bytes,
};
use super::store::DnsCacheStore;
use super::{Cache, CacheItem, CacheLoadPolicy, CacheMap, CacheReclaimer};
use crate::api::query::{optional_text, parse_usize_param, visit_query_params};
use crate::api::{ApiHandler, json_error, json_ok, simple_response};
use crate::infra::cache::ttl::{TtlCacheHandle, TtlCachePruneMode};
use crate::infra::clock::AppClock;
use crate::infra::error::Result;
use crate::plugin::executor::rdata_json::{RDataPayloadMode, rdata_payload};
use crate::proto::{DNSClass, Record, RecordType};
use crate::register_plugin_api;

const MAX_CACHE_DUMP_BODY: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(super) struct CacheApiConfig {
    pub(super) ecs_in_key: bool,
    pub(super) policy: CacheLoadPolicy,
    pub(super) cache_reclaimer: CacheReclaimer,
}

pub(super) fn register(tag: &str, store: DnsCacheStore, config: CacheApiConfig) -> Result<()> {
    let CacheApiConfig {
        ecs_in_key,
        policy,
        cache_reclaimer,
    } = config;
    // The gate is an API-internal implementation detail. All destructive cache
    // management handlers share this same mutex.
    let mutation_gate = Arc::new(Mutex::new(()));

    register_plugin_api!(
        tag,
        |plugin_api|
        GET "/entries" => CacheEntriesListHandler {
            store: store.clone(),
        },
        DELETE_PREFIX "/entries/" => CacheEntryDeleteHandler {
            store: store.clone(),
            mutation_gate: mutation_gate.clone(),
            path_prefix: plugin_api.path("/entries/")?,
        },
        POST "/flush" => CacheFlushHandler {
            store: store.clone(),
            cache_reclaimer: cache_reclaimer.clone(),
            mutation_gate: mutation_gate.clone(),
        },
        GET "/dump" => CacheDumpHandler {
            store: store.clone(),
            tag: tag.to_string(),
            ecs_in_key,
        },
        POST "/load_dump" => CacheLoadDumpHandler {
            store,
            ecs_in_key,
            policy,
            cache_reclaimer,
            mutation_gate,
        },
    )?;
    Ok(())
}

#[derive(Debug)]
struct CacheFlushHandler {
    store: DnsCacheStore,
    cache_reclaimer: CacheReclaimer,
    mutation_gate: Arc<Mutex<()>>,
}

#[derive(Debug, Serialize)]
struct CacheFlushResponse {
    ok: bool,
    cleared_entries: usize,
}

#[async_trait]
impl ApiHandler for CacheFlushHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        // Reserve the only outstanding retirement slot before allocating the
        // replacement. This provides async backpressure when a previous large
        // generation is still being reclaimed.
        let reclaim_permit = match self.cache_reclaimer.reserve().await {
            Ok(permit) => permit,
            Err(err) => {
                warn!("Cache reclaimer reservation failed: {}", err);
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "cache_reclaimer_unavailable",
                    "cache reclaimer unavailable",
                );
            }
        };

        // Preparing a replacement DashMap can allocate. Keep that work off the
        // async worker just like dump parsing/pruning.
        let initial_capacity = Cache::initial_cache_capacity(self.store.cache_size());
        let replacement =
            match tokio::task::spawn_blocking(move || CacheMap::with_capacity(initial_capacity))
                .await
            {
                Ok(replacement) => replacement,
                Err(err) => {
                    warn!("Cache flush preparation worker failed: {}", err);
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "cache_worker_failed",
                        "cache flush preparation worker failed",
                    );
                }
            };

        let mutation_guard = self.mutation_gate.lock().await;
        let retired = self.store.replace_generation(&replacement, 0);
        let cleared_entries = retired.entry_count();
        drop(mutation_guard);

        // The commit is complete. Transfer the retired generation to the
        // dedicated reclaimer; no large map is dropped on this Tokio worker.
        self.cache_reclaimer.submit(retired, reclaim_permit);

        info!("cache flushed, cleared entries {}", cleared_entries);
        json_ok(
            StatusCode::OK,
            &CacheFlushResponse {
                ok: true,
                cleared_entries,
            },
        )
    }
}

#[derive(Debug)]
struct CacheDumpHandler {
    store: DnsCacheStore,
    tag: String,
    ecs_in_key: bool,
}

#[async_trait]
impl ApiHandler for CacheDumpHandler {
    async fn handle(&self, _request: Request<Bytes>) -> crate::api::ApiResponse {
        let store = self.store.clone();
        let ecs_in_key = self.ecs_in_key;
        match tokio::task::spawn_blocking(move || {
            dump_cache_to_bytes_with_limit_for_mode::<MAX_CACHE_DUMP_BODY>(
                store.cache_map(),
                MAX_CACHE_DUMP_BODY,
                ecs_in_key,
            )
        })
        .await
        {
            Ok(Ok(CacheDumpOutcome::Complete(bytes))) => {
                let mut response = simple_response(StatusCode::OK, Bytes::from(bytes));
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/octet-stream"),
                );
                if let Ok(value) = http::HeaderValue::from_str(&format!(
                    "attachment; filename=\"{}.dump\"",
                    self.tag
                )) {
                    response
                        .headers_mut()
                        .insert(http::header::CONTENT_DISPOSITION, value);
                }
                response
            }
            Ok(Ok(CacheDumpOutcome::TooLarge {
                limit,
                minimum_size,
            })) => {
                warn!(
                    minimum_size,
                    limit, "Cache dump exceeds API size limit; stopped before full serialization"
                );
                json_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "cache_dump_too_large",
                    "cache dump exceeds API size limit",
                )
            }
            Ok(Err(err)) => {
                warn!("Failed to dump cache via API: {}", err);
                simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Bytes::from("failed to dump cache"),
                )
            }
            Err(err) => {
                warn!("Cache dump worker failed: {}", err);
                simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Bytes::from("cache dump worker failed"),
                )
            }
        }
    }
}

#[derive(Debug)]
struct CacheLoadDumpHandler {
    store: DnsCacheStore,
    ecs_in_key: bool,
    policy: CacheLoadPolicy,
    cache_reclaimer: CacheReclaimer,
    mutation_gate: Arc<Mutex<()>>,
}

#[derive(Debug, Serialize)]
struct CacheLoadDumpResponse {
    ok: bool,
    loaded_entries: usize,
}

#[async_trait]
impl ApiHandler for CacheLoadDumpHandler {
    fn max_request_body_bytes(&self) -> usize {
        MAX_CACHE_DUMP_BODY
    }

    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        // Serialize large replacement generations before parsing/building a new
        // cache. This bounds current + staged + retired memory under repeated
        // load/flush requests without blocking a Tokio worker thread.
        let reclaim_permit = match self.cache_reclaimer.reserve().await {
            Ok(permit) => permit,
            Err(err) => {
                warn!("Cache reclaimer reservation failed: {}", err);
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "cache_reclaimer_unavailable",
                    "cache reclaimer unavailable",
                );
            }
        };

        // Acquire the destructive-mutation gate before the staged cache exists.
        // Use an owned guard so the guard can move into spawn_blocking together
        // with the reclaim permit. Once the blocking transaction starts there
        // is no async cancellation point between building the staged
        // cache and committing it, so a cancelled handler cannot drop a
        // large staged map on a Tokio worker while waiting for this
        // mutex.
        let mutation_guard = self.mutation_gate.clone().lock_owned().await;

        let body = request.into_body();
        let ecs_in_key = self.ecs_in_key;
        let cache_size = self.store.cache_size();
        let policy = self.policy;
        let store = self.store.clone();
        let ecs_lookup_index = store.ecs_lookup_index().clone();
        let cache_reclaimer = self.cache_reclaimer.clone();

        // Keep both the mutation guard and reclaim permit owned by the blocking
        // transaction for its entire lifetime. If the async request is
        // cancelled, an already-started spawn_blocking task continues
        // to completion while retaining both: no second destructive
        // mutation can interleave and no second large staged generation
        // can bypass the memory backpressure.
        let result = tokio::task::spawn_blocking(move || {
            let _mutation_guard = mutation_guard;
            // Keep the per-key ECS index publication-stable from staged entry
            // observation through the generation swap. Rebuilds may clear old
            // false-positive memberships, but must not erase memberships for
            // entries that are about to become live.
            let _ecs_index_publication = ecs_lookup_index.publication_guard();

            let staged_cache = stage_cache_from_bytes::<MAX_CACHE_DUMP_BODY>(
                &body,
                ecs_in_key,
                policy,
                &ecs_lookup_index,
                Cache::initial_cache_capacity(cache_size),
                cache_size,
            )?;
            let (expired_removed, evicted, after_len) = staged_cache.prune(
                TtlCachePruneMode::Exact {
                    max_size: cache_size,
                },
                AppClock::elapsed_millis(),
            );

            // Commit while still inside the blocking transaction. The staged
            // cache never crosses back to the async worker, and there is no
            // await/cancellation point between staging and this atomic swap.
            // Dirty accounting describes changes published to the live cache,
            // not transient work performed while building the isolated staged
            // generation. `replace_generation` counts the retired entries plus
            // the entries that actually became live.
            let retired = store.replace_generation(&staged_cache, after_len);

            // Transfer ownership of the old generation before leaving the
            // blocking transaction. Its final destruction is handled by the
            // dedicated reclaimer after pre-swap readers are gone.
            cache_reclaimer.submit(retired, reclaim_permit);

            Ok::<_, crate::infra::error::DnsError>((expired_removed, evicted, after_len))
        })
        .await;

        match result {
            Ok(Ok((expired_removed, evicted, after_len))) => {
                let total_removed = expired_removed.saturating_add(evicted);
                if total_removed > 0 {
                    let before_len = after_len.saturating_add(total_removed);
                    info!(
                        expired_removed = expired_removed,
                        evicted = evicted,
                        before = before_len,
                        after = after_len,
                        "cache dump load pruned entries"
                    );
                }
                json_ok(
                    StatusCode::OK,
                    &CacheLoadDumpResponse {
                        ok: true,
                        loaded_entries: after_len,
                    },
                )
            }
            Ok(Err(err)) => {
                warn!("Failed to load cache dump via API: {}", err);
                json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_cache_dump",
                    "failed to load cache dump",
                )
            }
            Err(err) => {
                warn!("Cache load worker failed: {}", err);
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "cache_worker_failed",
                    "cache load worker failed",
                )
            }
        }
    }
}

#[derive(Debug)]
struct CacheEntriesListHandler {
    store: DnsCacheStore,
}

#[derive(Debug)]
struct CacheEntryDeleteHandler {
    store: DnsCacheStore,
    mutation_gate: Arc<Mutex<()>>,
    path_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntryId {
    domain: String,
    record_type: u16,
    dns_class: u16,
    do_bit: bool,
    cd_bit: bool,
    ecs_scope: Option<CacheEntryEcsId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntryEcsId {
    family: u16,
    source_prefix: u8,
    scope_prefix: u8,
    network_len: u8,
    network: [u8; 16],
}

#[derive(Debug, Clone, Serialize)]
struct CacheEntriesResponse {
    ok: bool,
    entries: Vec<CacheEntryRow>,
    next_cursor: Option<String>,
    total_entries: usize,
}

#[derive(Debug, Clone, Serialize)]
struct CacheEntryDeleteResponse {
    ok: bool,
    deleted: bool,
}

#[derive(Debug, Clone, Serialize)]
struct CacheEntryRow {
    id: String,
    domain: String,
    record_type: String,
    dns_class: String,
    rcode: String,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
    ttl: u32,
    remaining_ttl: u32,
    fresh: bool,
    stale: bool,
    cache_time_ms: u64,
    expire_at_ms: u64,
    last_access_ms: u64,
    cache_time_unix_ms: u64,
    expire_at_unix_ms: u64,
    last_access_unix_ms: u64,
    do_bit: bool,
    cd_bit: bool,
    answers_json: Vec<CacheRecordJson>,
    authorities_json: Vec<CacheRecordJson>,
    additionals_json: Vec<CacheRecordJson>,
    signature_json: Vec<CacheRecordJson>,
    ecs_scope: Option<CacheEntryEcsRow>,
}

#[derive(Debug, Clone, Serialize)]
struct CacheRecordJson {
    name: String,
    class: String,
    ttl: u32,
    rr_type: String,
    payload_kind: String,
    payload_text: String,
    payload: Value,
}

#[derive(Debug, Clone, Serialize)]
struct CacheEntryEcsRow {
    family: u16,
    source_prefix: u8,
    scope_prefix: u8,
    network_hex: String,
}

struct CacheEntryPageCandidate {
    key: CacheKey,
    entry: TtlCacheHandle<CacheItem>,
}

impl PartialEq for CacheEntryPageCandidate {
    fn eq(&self, other: &Self) -> bool {
        cmp_cache_keys(&self.key, &other.key) == Ordering::Equal
    }
}

impl Eq for CacheEntryPageCandidate {}

impl PartialOrd for CacheEntryPageCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CacheEntryPageCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_cache_keys(&self.key, &other.key)
    }
}

#[async_trait]
impl ApiHandler for CacheEntriesListHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let query = match parse_cache_entries_query(request.uri().query()) {
            Ok(query) => query,

            Err(err) => {
                return json_error(StatusCode::BAD_REQUEST, "invalid_query", err);
            }
        };

        let now = AppClock::elapsed_millis();
        let now_unix_ms = AppClock::now_timestamp();
        let store = self.store.clone();

        match tokio::task::spawn_blocking(move || {
            // Keep only the smallest `limit + 1` keys after the cursor. This
            // preserves stable keyset pagination without cloning/sorting the
            // whole cache or retaining every cached response Arc.
            let candidate_limit = query.limit.saturating_add(1);
            let mut candidates = BinaryHeap::with_capacity(candidate_limit);
            let mut total_entries = 0usize;

            store.cache_map().visit_handles(|key, entry| {
                if entry.expire_at_ms() <= now || !cache_entry_matches_query(key, &query) {
                    return true;
                }

                total_entries = total_entries.saturating_add(1);

                if query
                    .cursor
                    .as_ref()
                    .is_some_and(|cursor| cmp_cache_keys(key, cursor) != Ordering::Greater)
                {
                    return true;
                }

                let should_keep = candidates.len() < candidate_limit
                    || candidates
                        .peek()
                        .is_some_and(|largest: &CacheEntryPageCandidate| {
                            cmp_cache_keys(key, &largest.key) == Ordering::Less
                        });

                if should_keep {
                    if candidates.len() == candidate_limit {
                        candidates.pop();
                    }
                    candidates.push(CacheEntryPageCandidate {
                        key: key.clone(),
                        entry,
                    });
                }

                true
            });

            let mut entries = candidates.into_vec();
            entries.sort_unstable_by(|left, right| cmp_cache_keys(&left.key, &right.key));

            let has_more = entries.len() > query.limit;
            if has_more {
                entries.truncate(query.limit);
            }

            // Cursor identifies the last key in this page rather than an
            // offset into a mutable collection.
            let next_cursor = if has_more {
                match entries
                    .last()
                    .map(|candidate| encode_cache_entry_id(&candidate.key))
                {
                    Some(Ok(cursor)) => Some(cursor),
                    Some(Err(err)) => {
                        warn!("Failed to encode cache entries cursor: {}", err);

                        return json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "cache_cursor_encode_failed",
                            "failed to encode cache entries cursor",
                        );
                    }
                    None => None,
                }
            } else {
                None
            };

            let rows = entries
                .iter()
                .filter_map(|candidate| {
                    cache_entry_row(&candidate.key, &candidate.entry, now, now_unix_ms).ok()
                })
                .collect::<Vec<_>>();

            json_ok(
                StatusCode::OK,
                &CacheEntriesResponse {
                    ok: true,
                    entries: rows,
                    next_cursor,
                    total_entries,
                },
            )
        })
        .await
        {
            Ok(response) => response,

            Err(err) => {
                warn!("Cache entries list worker failed: {}", err);

                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "cache_worker_failed",
                    "cache entries list failed",
                )
            }
        }
    }
}

#[async_trait]
impl ApiHandler for CacheEntryDeleteHandler {
    async fn handle(&self, request: Request<Bytes>) -> crate::api::ApiResponse {
        let _mutation_guard = self.mutation_gate.lock().await;
        let Some(raw_id) = request.uri().path().strip_prefix(self.path_prefix.as_str()) else {
            return simple_response(StatusCode::NOT_FOUND, Bytes::from("404 Not Found"));
        };
        if raw_id.is_empty() || raw_id.contains('/') {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_cache_entry_id",
                "invalid cache entry id",
            );
        }
        let key = match decode_cache_entry_id(raw_id) {
            Ok(key) => key,
            Err(err) => {
                return json_error(StatusCode::BAD_REQUEST, "invalid_cache_entry_id", err);
            }
        };
        if !self.store.remove(&key) {
            return json_error(
                StatusCode::NOT_FOUND,
                "cache_entry_not_found",
                "cache entry does not exist",
            );
        }
        json_ok(
            StatusCode::OK,
            &CacheEntryDeleteResponse {
                ok: true,
                deleted: true,
            },
        )
    }
}

#[derive(Debug, Clone)]
struct CacheEntriesQuery {
    limit: usize,

    /// Opaque keyset cursor. It is the immutable CacheKey of the last entry
    /// returned by the previous page.
    cursor: Option<CacheKey>,
    qname: Option<String>,
}

fn parse_cache_entries_query(
    query: Option<&str>,
) -> std::result::Result<CacheEntriesQuery, String> {
    let mut limit = 100usize;
    let mut cursor = None;
    let mut qname = None;

    visit_query_params(query, |key, value| {
        match key {
            "limit" => {
                limit =
                    parse_usize_param(value, |_| "limit must be a positive integer".to_string())?
                        .clamp(1, 500);
            }

            "cursor" => {
                cursor = optional_text(value)
                    .map(|raw| {
                        decode_cache_entry_id(raw.as_str())
                            .map_err(|err| format!("invalid cursor: {err}"))
                    })
                    .transpose()?;
            }

            "qname" => {
                qname = optional_text(value).map(|value| normalize_domain_key(value.as_str()));
            }

            _ => {}
        }

        Ok(())
    })?;

    Ok(CacheEntriesQuery {
        limit,
        cursor,
        qname,
    })
}

#[inline]
fn cmp_cache_keys(left: &CacheKey, right: &CacheKey) -> Ordering {
    left.domain
        .as_ref()
        .cmp(right.domain.as_ref())
        .then_with(|| u16::from(left.record_type).cmp(&u16::from(right.record_type)))
        .then_with(|| u16::from(left.dns_class).cmp(&u16::from(right.dns_class)))
        .then_with(|| left.do_bit.cmp(&right.do_bit))
        .then_with(|| left.cd_bit.cmp(&right.cd_bit))
        .then_with(|| {
            match (&left.ecs_scope, &right.ecs_scope) {
                (None, None) => Ordering::Equal,

                // Non-ECS variant sorts before ECS variants.
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,

                (Some(left_ecs), Some(right_ecs)) => left_ecs
                    .family
                    .cmp(&right_ecs.family)
                    .then_with(|| left_ecs.source_prefix.cmp(&right_ecs.source_prefix))
                    .then_with(|| left_ecs.scope_prefix.cmp(&right_ecs.scope_prefix))
                    .then_with(|| left_ecs.network_len.cmp(&right_ecs.network_len))
                    .then_with(|| left_ecs.network.cmp(&right_ecs.network)),
            }
        })
}

#[cfg(test)]
fn cache_entries_cursor_start<T>(entries: &[(CacheKey, T)], cursor: Option<&CacheKey>) -> usize {
    let Some(cursor) = cursor else {
        return 0;
    };

    match entries.binary_search_by(|(key, _)| cmp_cache_keys(key, cursor)) {
        Ok(index) => index.saturating_add(1),
        Err(index) => index,
    }
}

#[inline]
fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn cache_entry_matches_query(key: &CacheKey, query: &CacheEntriesQuery) -> bool {
    query
        .qname
        .as_deref()
        .is_none_or(|qname| contains_ascii_case_insensitive(key.domain.as_ref(), qname))
}

fn cache_entry_row(
    key: &CacheKey,
    entry: &TtlCacheHandle<CacheItem>,
    now: u64,
    now_unix_ms: u64,
) -> std::result::Result<CacheEntryRow, String> {
    let item = entry.value();
    let fresh = now < item.fresh_until_ms;
    let stale = !fresh && now < entry.expire_at_ms();
    let ecs_scope = match key.ecs_scope.as_ref() {
        Some(ecs) => {
            let network_len = usize::from(ecs.network_len);
            if network_len > ecs.network.len() {
                return Err("cache entry contains invalid ECS network length".to_string());
            }
            Some(CacheEntryEcsRow {
                family: ecs.family,
                source_prefix: ecs.source_prefix,
                scope_prefix: ecs.scope_prefix,
                network_hex: ecs.network[..network_len]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            })
        }
        None => None,
    };

    Ok(CacheEntryRow {
        id: encode_cache_entry_id(key)?,
        domain: key.domain.to_string(),
        record_type: key.record_type.to_string(),
        dns_class: key.dns_class.to_string(),
        rcode: item.resp.rcode().to_string(),
        answer_count: item.resp.answer_count(),
        authority_count: item.resp.authority_count(),
        additional_count: item.resp.additionals().len() as u16,
        ttl: item.ttl,
        remaining_ttl: entry
            .expire_at_ms()
            .saturating_sub(now)
            .saturating_div(1000) as u32,
        fresh,
        stale,
        cache_time_ms: entry.cache_time_ms(),
        expire_at_ms: entry.expire_at_ms(),
        last_access_ms: entry.last_access_ms(),
        cache_time_unix_ms: elapsed_to_unix_ms(entry.cache_time_ms(), now, now_unix_ms),
        expire_at_unix_ms: elapsed_to_unix_ms(entry.expire_at_ms(), now, now_unix_ms),
        last_access_unix_ms: elapsed_to_unix_ms(entry.last_access_ms(), now, now_unix_ms),
        do_bit: key.do_bit,
        cd_bit: key.cd_bit,
        answers_json: item.resp.answers().iter().map(cache_record_json).collect(),
        authorities_json: item
            .resp
            .authorities()
            .iter()
            .map(cache_record_json)
            .collect(),
        additionals_json: item
            .resp
            .additionals()
            .iter()
            .map(cache_record_json)
            .collect(),
        signature_json: item
            .resp
            .signature()
            .iter()
            .map(cache_record_json)
            .collect(),
        ecs_scope,
    })
}

fn elapsed_to_unix_ms(elapsed_ms: u64, now_ms: u64, now_unix_ms: u64) -> u64 {
    if elapsed_ms <= now_ms {
        now_unix_ms.saturating_sub(now_ms - elapsed_ms)
    } else {
        now_unix_ms.saturating_add(elapsed_ms - now_ms)
    }
}

fn cache_record_json(record: &Record) -> CacheRecordJson {
    let (payload_kind, payload_text, payload) =
        rdata_payload(record.data(), RDataPayloadMode::Cache);
    CacheRecordJson {
        name: record.name().to_fqdn(),
        class: dns_class_name(record.class()),
        ttl: record.ttl(),
        rr_type: record_type_name(record.rr_type()),
        payload_kind,
        payload_text,
        payload,
    }
}

fn dns_class_name(class: DNSClass) -> String {
    match class {
        DNSClass::Unknown(value) => format!("CLASS{value}"),
        DNSClass::OPT(value) => format!("OPT({value})"),
        _ => class.to_string(),
    }
}

fn record_type_name(record_type: RecordType) -> String {
    match record_type {
        RecordType::Unknown(value) => format!("TYPE{value}"),
        _ => record_type.to_string(),
    }
}

fn encode_cache_entry_id(key: &CacheKey) -> std::result::Result<String, String> {
    let id = CacheEntryId {
        domain: key.domain.to_string(),
        record_type: u16::from(key.record_type),
        dns_class: u16::from(key.dns_class),
        do_bit: key.do_bit,
        cd_bit: key.cd_bit,
        ecs_scope: key.ecs_scope.as_ref().map(|ecs| CacheEntryEcsId {
            family: ecs.family,
            source_prefix: ecs.source_prefix,
            scope_prefix: ecs.scope_prefix,
            network_len: ecs.network_len,
            network: ecs.network,
        }),
    };
    serde_json::to_vec(&id)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|err| format!("failed to encode cache entry id: {err}"))
}

fn decode_cache_entry_id(raw: &str) -> std::result::Result<CacheKey, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| "cache entry id is not valid base64url".to_string())?;
    let id: CacheEntryId = serde_json::from_slice(&bytes)
        .map_err(|_| "cache entry id is not valid json".to_string())?;

    let domain = normalize_cache_key_domain(&id.domain)
        .ok_or_else(|| "cache entry id domain is invalid DNS text".to_string())?;

    let ecs_scope = match id.ecs_scope {
        Some(ecs) => {
            let network_len = usize::from(ecs.network_len);
            if network_len > ecs.network.len() {
                return Err("cache entry id has invalid ECS network length".to_string());
            }
            canonical_ecs_key_digest(
                ecs.family,
                ecs.source_prefix,
                ecs.scope_prefix,
                &ecs.network[..network_len],
            )
            .ok_or_else(|| "cache entry id has noncanonical ECS metadata".to_string())
            .map(Some)?
        }
        None => None,
    };

    Ok(CacheKey {
        domain: domain.into(),
        record_type: id.record_type.into(),
        dns_class: id.dns_class.into(),
        do_bit: id.do_bit,
        cd_bit: id.cd_bit,
        ecs_scope,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::Mutex;

    use super::*;

    fn test_cache_reclaimer() -> CacheReclaimer {
        CacheReclaimer::new("api-test").expect("cache reclaimer should start")
    }

    fn test_store(cache_map: CacheMap, cache_size: usize) -> DnsCacheStore {
        let hints = Arc::new(EcsLookupIndex::new());
        let metrics = Arc::new(CacheMetrics::new("api-test".to_string()));
        DnsCacheStore::new(cache_map, cache_size, hints, metrics)
    }

    fn test_cache_key(domain: &str) -> CacheKey {
        CacheKey {
            domain: domain.into(),
            record_type: RecordType::A,
            dns_class: DNSClass::IN,
            do_bit: false,
            cd_bit: false,
            ecs_scope: None,
        }
    }

    #[test]
    fn parse_cache_entries_query_accepts_keyset_cursor_and_qname_filter() {
        let cursor_key = test_cache_key("cursor.example.com");

        let encoded_cursor = encode_cache_entry_id(&cursor_key).expect("cursor should encode");

        let raw_query = format!("limit=20&cursor={encoded_cursor}&qname=%20EXAMPLE.COM.%20");

        let query = parse_cache_entries_query(Some(&raw_query)).expect("query should parse");

        assert_eq!(query.limit, 20);

        assert_eq!(query.cursor.as_ref(), Some(&cursor_key));

        assert_eq!(query.qname.as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_cache_entries_query_preserves_escaped_terminal_dot() {
        let query = parse_cache_entries_query(Some(r"qname=foo%5C.")).expect("query should parse");

        assert_eq!(query.qname.as_deref(), Some(r"foo\."));
        assert!(cache_entry_matches_query(&test_cache_key(r"foo\."), &query));
    }

    #[test]
    fn cache_entry_matches_query_filters_qname_case_insensitively() {
        let query = CacheEntriesQuery {
            limit: 100,
            cursor: None,
            qname: Some("example.com".to_string()),
        };

        assert!(cache_entry_matches_query(
            &test_cache_key("www.Example.COM"),
            &query
        ));
        assert!(!cache_entry_matches_query(
            &test_cache_key("www.example.net"),
            &query
        ));
    }

    #[test]
    fn contains_ascii_case_insensitive_avoids_case_sensitive_qname_regression() {
        assert!(contains_ascii_case_insensitive(
            "WWW.Example.COM",
            "example.com"
        ));
        assert!(!contains_ascii_case_insensitive(
            "www.example.net",
            "example.com"
        ));
    }

    #[test]
    fn cache_entry_id_roundtrips_canonical_root_domain() {
        let key = test_cache_key(".");

        let encoded = encode_cache_entry_id(&key).expect("root cache id should encode");
        let decoded = decode_cache_entry_id(&encoded).expect("root cache id should decode");

        assert_eq!(decoded.domain.as_ref(), ".");
        assert_eq!(decoded, key);
    }

    #[test]
    fn cache_entry_id_roundtrips_escaped_terminal_dot() {
        let key = test_cache_key(r"foo\.");

        let encoded = encode_cache_entry_id(&key).expect("escaped-dot cache id should encode");
        let decoded = decode_cache_entry_id(&encoded).expect("escaped-dot cache id should decode");

        assert_eq!(decoded.domain.as_ref(), r"foo\.");
        assert_eq!(decoded, key);
    }

    #[test]
    fn decode_cache_entry_id_rejects_empty_domain() {
        let id = CacheEntryId {
            domain: String::new(),
            record_type: u16::from(RecordType::A),
            dns_class: u16::from(DNSClass::IN),
            do_bit: false,
            cd_bit: false,
            ecs_scope: None,
        };
        let raw = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&id).unwrap());

        assert!(decode_cache_entry_id(&raw).is_err());
    }

    #[test]
    fn decode_cache_entry_id_rejects_whitespace_only_domain() {
        let id = CacheEntryId {
            domain: "   ".to_string(),
            record_type: u16::from(RecordType::A),
            dns_class: u16::from(DNSClass::IN),
            do_bit: false,
            cd_bit: false,
            ecs_scope: None,
        };
        let raw = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&id).unwrap());

        assert!(decode_cache_entry_id(&raw).is_err());
    }

    #[test]
    fn decode_cache_entry_id_rejects_oversized_ecs_network_len() {
        let id = CacheEntryId {
            domain: "example.com".to_string(),
            record_type: u16::from(RecordType::A),
            dns_class: u16::from(DNSClass::IN),
            do_bit: false,
            cd_bit: false,
            ecs_scope: Some(CacheEntryEcsId {
                family: 2,
                source_prefix: 56,
                scope_prefix: 64,
                network_len: 17,
                network: [0; 16],
            }),
        };
        let raw = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&id).unwrap());
        assert!(decode_cache_entry_id(&raw).is_err());
    }

    #[test]
    fn decode_cache_entry_id_rejects_noncanonical_ecs_metadata() {
        let mut id = CacheEntryId {
            domain: "example.com".to_string(),
            record_type: u16::from(RecordType::A),
            dns_class: u16::from(DNSClass::IN),
            do_bit: false,
            cd_bit: false,
            ecs_scope: Some(CacheEntryEcsId {
                family: 1,
                source_prefix: 20,
                scope_prefix: 20,
                network_len: 3,
                network: [192, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            }),
        };

        id.ecs_scope.as_mut().unwrap().network[2] = 0x21;
        let raw = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&id).unwrap());
        assert!(decode_cache_entry_id(&raw).is_err());

        id.ecs_scope.as_mut().unwrap().network[2] = 0;
        id.ecs_scope.as_mut().unwrap().scope_prefix = 16;
        let raw = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&id).unwrap());
        assert!(decode_cache_entry_id(&raw).is_err());
    }

    #[tokio::test]
    async fn cache_reclaimer_reservation_applies_async_backpressure() {
        let reclaimer = test_cache_reclaimer();
        let first = reclaimer
            .reserve()
            .await
            .expect("first reclaim permit should be available");

        let waiter = tokio::spawn({
            let reclaimer = reclaimer.clone();
            async move { reclaimer.reserve().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("second reservation should wake after permit release")
            .expect("reservation task should not fail")
            .expect("cache reclaimer should remain available");
        drop(second);
    }

    #[tokio::test]
    async fn invalid_load_dump_returns_bad_request() {
        let cache_map = CacheMap::with_capacity(1);
        let handler = CacheLoadDumpHandler {
            store: test_store(cache_map, 1),
            ecs_in_key: false,
            policy: CacheLoadPolicy::default(),
            cache_reclaimer: test_cache_reclaimer(),
            mutation_gate: Arc::new(Mutex::new(())),
        };

        let response = handler
            .handle(Request::new(Bytes::from_static(b"not a cache dump")))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cache_mutation_handlers_serialize_load_and_flush() {
        AppClock::start();
        let cache_map = CacheMap::with_capacity(1);
        let store = test_store(cache_map.clone(), 1);
        let mutation_gate = Arc::new(Mutex::new(()));
        let reclaimer = test_cache_reclaimer();
        let flush = Arc::new(CacheFlushHandler {
            store: store.clone(),
            cache_reclaimer: reclaimer.clone(),
            mutation_gate: mutation_gate.clone(),
        });
        let load = Arc::new(CacheLoadDumpHandler {
            store,
            ecs_in_key: false,
            policy: CacheLoadPolicy::default(),
            cache_reclaimer: reclaimer,
            mutation_gate: mutation_gate.clone(),
        });
        let dump = dump_cache_to_bytes(&cache_map).expect("empty dump should serialize");

        let gate_guard = mutation_gate.lock().await;
        let load_task = tokio::spawn({
            let load = load.clone();
            async move { load.handle(Request::new(Bytes::from(dump))).await }
        });
        tokio::task::yield_now().await;
        assert!(!load_task.is_finished());
        drop(gate_guard);
        let _ = tokio::time::timeout(Duration::from_secs(1), load_task)
            .await
            .expect("load should run after the mutation gate is released");

        let gate_guard = mutation_gate.lock().await;
        let flush_task =
            tokio::spawn(async move { flush.handle(Request::new(Bytes::new())).await });
        tokio::task::yield_now().await;
        assert!(!flush_task.is_finished());
        drop(gate_guard);
        let _ = tokio::time::timeout(Duration::from_secs(1), flush_task)
            .await
            .expect("flush should run after the mutation gate is released");
    }

    #[test]
    fn parse_cache_entries_query_rejects_invalid_cursor() {
        let result = parse_cache_entries_query(Some("limit=20&cursor=not-a-valid-cursor"));

        assert!(result.is_err());
    }

    #[test]
    fn cache_entries_keyset_pagination_is_independent_of_last_access() {
        let key_a = test_cache_key("a.example.com");
        let key_b = test_cache_key("b.example.com");
        let key_c = test_cache_key("c.example.com");
        let key_d = test_cache_key("d.example.com");

        let mut entries = vec![
            (key_a.clone(), 400u64),
            (key_b.clone(), 300u64),
            (key_c.clone(), 200u64),
            (key_d.clone(), 100u64),
        ];

        entries.sort_unstable_by(|(left, _), (right, _)| cmp_cache_keys(left, right));

        let page1 = &entries[..2];

        assert_eq!(page1[0].0, key_a);
        assert_eq!(page1[1].0, key_b);

        let cursor = key_b.clone();

        //  D is heavily accessed between page requests.
        //
        //  Under the old last_access ordering this would move D to the front
        // and  shift the offset, causing duplicates/missing rows.
        for (key, last_access) in &mut entries {
            if *key == key_d {
                *last_access = 10_000;
            }
        }

        entries.sort_unstable_by(|(left, _), (right, _)| cmp_cache_keys(left, right));

        let start = cache_entries_cursor_start(&entries, Some(&cursor));

        assert_eq!(start, 2);

        assert_eq!(entries[start].0, key_c);
        assert_eq!(entries[start + 1].0, key_d);
    }

    #[test]
    fn cache_entries_keyset_cursor_survives_deleted_boundary_key() {
        let key_a = test_cache_key("a.example.com");
        let key_b = test_cache_key("b.example.com");
        let key_c = test_cache_key("c.example.com");
        let key_d = test_cache_key("d.example.com");

        // Previous page ended at B, but B disappeared before the next request.
        let cursor = key_b;

        let mut entries = vec![(key_a, ()), (key_c.clone(), ()), (key_d.clone(), ())];

        entries.sort_unstable_by(|(left, _), (right, _)| cmp_cache_keys(left, right));

        let start = cache_entries_cursor_start(&entries, Some(&cursor));

        assert_eq!(start, 1);
        assert_eq!(entries[start].0, key_c);
        assert_eq!(entries[start + 1].0, key_d);
    }
}
