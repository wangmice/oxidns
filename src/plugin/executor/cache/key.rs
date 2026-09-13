// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cache key composition helpers.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::core::context::DnsContext;
use crate::proto::{
    ClientSubnet, DNSClass, EdnsCode, EdnsOption, Message, MessageType, Name, Opcode, Question,
    RecordType,
};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(super) struct EcsScopeDigest {
    pub(super) family: u16,
    pub(super) source_prefix: u8,
    pub(super) scope_prefix: u8,
    pub(super) network_len: u8,
    pub(super) network: [u8; 16],
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(super) struct CacheKey {
    pub(super) domain: Arc<str>,
    pub(super) record_type: RecordType,
    pub(super) dns_class: DNSClass,
    pub(super) do_bit: bool,
    pub(super) cd_bit: bool,
    pub(super) ecs_scope: Option<EcsScopeDigest>,
}

impl CacheKey {
    #[inline]
    pub(super) fn question(&self) -> Option<Question> {
        let name = Name::from_ascii(self.domain.as_ref()).ok()?;
        Some(Question::new(name, self.record_type, self.dns_class))
    }

    #[inline]
    fn with_ecs_scope_prefix(&self, scope_prefix: u8) -> Self {
        let Some(ecs) = &self.ecs_scope else {
            return self.clone();
        };

        debug_assert!(
            scope_prefix <= ecs.source_prefix,
            "ECS scope prefix must not exceed the source prefix here"
        );

        let scope_prefix = scope_prefix.min(ecs.source_prefix);

        let mut network = [0u8; 16];
        let network_len = write_truncated_prefix(
            &ecs.network[..usize::from(ecs.network_len)],
            scope_prefix,
            &mut network,
        );

        Self {
            domain: self.domain.clone(),
            record_type: self.record_type,
            dns_class: self.dns_class,
            do_bit: self.do_bit,
            cd_bit: self.cd_bit,
            ecs_scope: Some(EcsScopeDigest {
                family: ecs.family,

                // For a reusable scoped cache key this field represents the
                // matching prefix.
                source_prefix: scope_prefix,
                scope_prefix,

                network_len,
                network,
            }),
        }
    }
}

#[inline]
fn canonical_domain_from_text(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let name = Name::from_ascii(trimmed).ok()?;
    if name.is_root() {
        Some(".".to_string())
    } else {
        Some(name.normalized().to_string())
    }
}

#[inline]
pub(super) fn normalize_domain_key(raw: &str) -> String {
    canonical_domain_from_text(raw).unwrap_or_else(|| raw.trim().to_ascii_lowercase())
}

/// Normalize domain text that is part of a serialized/runtime cache key.
///
/// Cache-key domains use DNS presentation syntax, so escaped label bytes such
/// as the literal dot in `foo\.` must be parsed before canonicalization. The
/// DNS root has one canonical representation: `.`. Empty, whitespace-only, or
/// malformed DNS presentation text is invalid.
#[inline]
pub(super) fn normalize_cache_key_domain(raw: &str) -> Option<String> {
    canonical_domain_from_text(raw)
}

#[inline]
fn cache_domain_from_name(name: &Name) -> Arc<str> {
    if name.is_root() {
        Arc::<str>::from(".")
    } else {
        Arc::<str>::from(name.normalized())
    }
}

#[inline]
pub(super) fn cache_domain_matches_name(domain: &str, name: &Name) -> bool {
    if name.is_root() {
        domain == "."
    } else {
        name.normalized() == domain
    }
}

#[inline]
fn write_truncated_prefix(src: &[u8], prefix: u8, out: &mut [u8; 16]) -> u8 {
    let max_bits = (src.len() * 8) as u8;
    let prefix = prefix.min(max_bits);
    if prefix == 0 {
        return 0;
    }

    let full_bytes = (prefix / 8) as usize;
    let remaining_bits = prefix % 8;

    if full_bytes > 0 {
        out[..full_bytes].copy_from_slice(&src[..full_bytes]);
    }

    if remaining_bits == 0 {
        full_bytes as u8
    } else {
        let mask = 0xFFu8 << (8 - remaining_bits);
        out[full_bytes] = src[full_bytes] & mask;
        (full_bytes as u8).saturating_add(1)
    }
}

/// Build the canonical ECS digest shape used by runtime cache keys.
///
/// Request-specific keys use `(source, scope=0)`; reusable keys use
/// `(source=scope)`. In both cases the stored network contains exactly the
/// significant source-prefix bytes and has zero host bits.
pub(super) fn canonical_ecs_key_digest(
    family: u16,
    source_prefix: u8,
    scope_prefix: u8,
    network: &[u8],
) -> Option<EcsScopeDigest> {
    let max_prefix = match family {
        1 => 32,
        2 => 128,
        _ => return None,
    };
    if source_prefix > max_prefix
        || scope_prefix > max_prefix
        || (scope_prefix != 0 && scope_prefix != source_prefix)
    {
        return None;
    }

    let required_len = usize::from(source_prefix.saturating_add(7) / 8);
    if network.len() != required_len {
        return None;
    }

    let remaining_bits = source_prefix % 8;
    if remaining_bits != 0
        && network
            .last()
            .is_some_and(|last| *last & (0xFFu8 >> remaining_bits) != 0)
    {
        return None;
    }

    let mut digest_network = [0u8; 16];
    digest_network[..required_len].copy_from_slice(network);
    Some(EcsScopeDigest {
        family,
        source_prefix,
        scope_prefix,
        network_len: required_len as u8,
        network: digest_network,
    })
}

//******wangmice *******/
#[inline]
fn ecs_prefixes_are_valid(subnet: &ClientSubnet) -> bool {
    let max_prefix = match subnet.addr() {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    subnet.source_prefix() <= max_prefix && subnet.scope_prefix() <= max_prefix
}
#[inline]
fn request_ecs_is_valid(subnet: &ClientSubnet) -> bool {
    ecs_prefixes_are_valid(subnet)
        // ECS queries must use SCOPE PREFIX-LENGTH zero.
        && subnet.scope_prefix() == 0
}
#[inline]
fn extract_ecs(message: &Message) -> Option<&ClientSubnet> {
    message
        .edns()
        .as_ref()
        .and_then(|edns| match edns.option(EdnsCode::Subnet) {
            Some(EdnsOption::Subnet(subnet)) => Some(subnet),
            _ => None,
        })
}

#[inline]
fn build_ecs_scope_digest(subnet: &ClientSubnet) -> EcsScopeDigest {
    let mut network = [0u8; 16];
    let (family, max_prefix, network_len) = match subnet.addr() {
        IpAddr::V4(v4) => {
            let len =
                write_truncated_prefix(&v4.octets(), subnet.source_prefix().min(32), &mut network);
            (1u16, 32u8, len)
        }
        IpAddr::V6(v6) => {
            let len =
                write_truncated_prefix(&v6.octets(), subnet.source_prefix().min(128), &mut network);
            (2u16, 128u8, len)
        }
    };

    let source_prefix = subnet.source_prefix().min(max_prefix);
    let scope_prefix = subnet.scope_prefix().min(max_prefix);

    EcsScopeDigest {
        family,
        source_prefix,
        scope_prefix,
        network_len,
        network,
    }
}

pub(super) fn build_cache_key(context: &mut DnsContext, ecs_in_key: bool) -> Option<CacheKey> {
    if !is_cacheable_request(&context.request) {
        return None;
    }

    let question = context.request.first_question()?;
    let domain = cache_domain_from_name(question.name());
    let record_type = question.qtype();
    let dns_class = question.qclass();

    let do_bit = context
        .request
        .edns()
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok);

    let cd_bit = context.request.checking_disabled();

    let request_ecs = extract_ecs(&context.request);

    let ecs_scope = if ecs_in_key {
        match request_ecs {
            Some(subnet) => {
                if !request_ecs_is_valid(subnet) {
                    return None;
                }

                Some(build_ecs_scope_digest(subnet))
            }
            None => None,
        }
    } else {
        None
    };

    Some(CacheKey {
        domain,
        record_type,
        dns_class,
        do_bit,
        cd_bit,
        ecs_scope,
    })
}

/// Re-key an ECS response by the scope advertised by the upstream server.
///
/// RFC 7871 semantics:
///
/// * FAMILY, SOURCE PREFIX-LENGTH and the significant ADDRESS bits in the
///   response must match the request.
/// * SCOPE PREFIX-LENGTH is reusable cache metadata.
/// * When SCOPE <= SOURCE, the answer may be shared by requests covered by that
///   scope.
/// * When SCOPE > SOURCE, the request did not provide enough address bits to
///   safely construct the narrower scope. In that case retain the original
///   request-specific key instead of widening/clamping it to SOURCE.
#[inline]
pub(super) fn cache_key_for_response_ecs_scope(
    key: &CacheKey,
    response: &Message,
) -> Option<CacheKey> {
    let response_subnet = extract_ecs(response);

    let Some(request_ecs) = &key.ecs_scope else {
        return response_subnet.is_none().then(|| key.clone());
    };

    let Some(response_subnet) = response_subnet else {
        return Some(key.clone());
    };

    if !ecs_prefixes_are_valid(response_subnet) {
        return None;
    }

    let response_ecs = build_ecs_scope_digest(response_subnet);

    if response_ecs.family != request_ecs.family
        || response_ecs.source_prefix != request_ecs.source_prefix
        || response_ecs.network_len != request_ecs.network_len
        || response_ecs.network[..usize::from(response_ecs.network_len)]
            != request_ecs.network[..usize::from(request_ecs.network_len)]
    {
        return None;
    }

    if response_ecs.scope_prefix > request_ecs.source_prefix {
        // RFC 7871 requires an exact-SOURCE cache entry in this case.
        // With the current key representation, SOURCE=/0 exact entries are
        // indistinguishable from globally reusable SCOPE=/0 entries. Reject
        // that one ambiguous case rather than risk cross-scope reuse.
        if request_ecs.source_prefix == 0 {
            return None;
        }

        return Some(key.clone());
    }

    Some(key.with_ecs_scope_prefix(response_ecs.scope_prefix))
}

/// Validate the ECS metadata stored alongside a persisted cache response.
///
/// A reusable response key has already been narrowed to the advertised scope,
/// so its key prefix is shorter than the response SOURCE prefix. A response
/// whose SCOPE is more specific than SOURCE remains under the original
/// request-specific key. Persistence stores only the final key, therefore both
/// representations need to be accepted explicitly here.
#[inline]
pub(super) fn persisted_ecs_key_matches_response(key: &CacheKey, response: &Message) -> bool {
    let response_subnet = extract_ecs(response);

    let Some(key_ecs) = &key.ecs_scope else {
        return response_subnet.is_none();
    };

    let Some(response_subnet) = response_subnet else {
        // Upstream response without ECS is retained under the original
        // request-specific key. Request ECS keys always have scope=0.
        return key_ecs.scope_prefix == 0;
    };

    if !ecs_prefixes_are_valid(response_subnet) {
        return false;
    }

    let response_ecs = build_ecs_scope_digest(response_subnet);

    if response_ecs.family != key_ecs.family {
        return false;
    }

    //  Canonical reusable SCOPE=0 entry.
    //  Example:
    //  request:
    //       203.0.113.0/24
    //  response:
    //       SOURCE=/24
    //       SCOPE=/0
    //  Runtime storage canonicalizes this to:
    //      key.source_prefix = 0
    //      key.scope_prefix  = 0
    //      key.network_len   = 0
    //  The original response SOURCE/address are deliberately no longer
    //  represented by the cache key because SCOPE=0 means the answer is
    //  reusable globally within this address family.
    if key_ecs.source_prefix == 0
        && key_ecs.scope_prefix == 0
        && key_ecs.network_len == 0
        && response_ecs.scope_prefix == 0
    {
        return true;
    }

    //   Request-specific key retained because response SCOPE > SOURCE.
    //  In this representation the key still carries the original request
    //  SOURCE prefix and address, while scope remains zero because the
    //   request itself necessarily had SCOPE=0.
    if key_ecs.scope_prefix == 0 {
        // SOURCE=/0 + SCOPE>0 cannot be represented without colliding with
        // a globally reusable SCOPE=/0 key. Runtime admission rejects this
        // shape, and persistence must reject legacy/crafted entries too.
        if key_ecs.source_prefix == 0 {
            return false;
        }

        return response_ecs.source_prefix == key_ecs.source_prefix
            && response_ecs.scope_prefix > key_ecs.source_prefix
            && ecs_network_prefix_matches(key_ecs, &response_ecs, key_ecs.source_prefix);
    }

    // Normal reusable scoped key.
    //
    // Runtime storage canonicalizes SOURCE to SCOPE:
    //
    // response: SOURCE=/24 SCOPE=/20
    // key:      SOURCE=/20 SCOPE=/20
    response_ecs.scope_prefix == key_ecs.scope_prefix
        && key_ecs.source_prefix == key_ecs.scope_prefix
        && response_ecs.source_prefix >= key_ecs.source_prefix
        && ecs_network_prefix_matches(key_ecs, &response_ecs, key_ecs.source_prefix)
}

#[inline]
fn ecs_network_prefix_matches(left: &EcsScopeDigest, right: &EcsScopeDigest, prefix: u8) -> bool {
    let full_bytes = usize::from(prefix / 8);
    if left.network[..full_bytes] != right.network[..full_bytes] {
        return false;
    }
    let remaining_bits = prefix % 8;
    remaining_bits == 0
        || (left.network[full_bytes] & (0xFFu8 << (8 - remaining_bits)))
            == (right.network[full_bytes] & (0xFFu8 << (8 - remaining_bits)))
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct EcsBaseKey {
    domain: Arc<str>,
    record_type: RecordType,
    dns_class: DNSClass,
    do_bit: bool,
    cd_bit: bool,
}

impl EcsBaseKey {
    #[inline]
    fn from_cache_key(key: &CacheKey) -> Self {
        Self {
            domain: key.domain.clone(),
            record_type: key.record_type,
            dns_class: key.dns_class,
            do_bit: key.do_bit,
            cd_bit: key.cd_bit,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct EcsPrefixBitmap {
    ipv4: u64,
    ipv6: [u64; 3],
}

impl EcsPrefixBitmap {
    #[inline]
    fn observe(&mut self, family: u16, prefix: u8) -> bool {
        match family {
            1 if prefix <= 32 => {
                let bit = 1u64 << prefix;
                let inserted = self.ipv4 & bit == 0;
                self.ipv4 |= bit;
                inserted
            }
            2 if prefix <= 128 => {
                let word = usize::from(prefix / 64);
                let bit = prefix % 64;
                let mask = 1u64 << bit;
                let inserted = self.ipv6[word] & mask == 0;
                self.ipv6[word] |= mask;
                inserted
            }
            _ => false,
        }
    }

    #[inline]
    fn snapshot_for(self, family: u16, max_prefix: u8) -> EcsPrefixMask {
        let mut words = match family {
            1 => [self.ipv4, 0, 0],
            2 => self.ipv6,
            _ => [0; 3],
        };

        let max_prefix = match family {
            1 => max_prefix.min(32),
            2 => max_prefix.min(128),
            _ => return EcsPrefixMask { words: [0; 3] },
        };
        let max_word = usize::from(max_prefix / 64);
        for word in words.iter_mut().skip(max_word + 1) {
            *word = 0;
        }
        let max_bit = max_prefix % 64;
        if max_bit < 63 {
            words[max_word] &= (1u64 << (max_bit + 1)) - 1;
        }

        EcsPrefixMask { words }
    }
}

/// Advisory reusable-ECS prefix index partitioned by the non-ECS cache key.
///
/// Each base DNS key owns its own IPv4/IPv6 prefix bitmap, so an ECS lookup is
/// never forced to probe prefixes that were observed only for unrelated names,
/// record types, classes, or DNSSEC flags. The main cache map remains
/// authoritative. Publications take a shared rebuild guard while setting the
/// per-key bit and publishing the cache entry. Maintenance installs a shadow
/// generation under the exclusive gate, scans the authoritative cache without
/// that gate, and mirrors concurrent publications into the shadow. The final
/// exclusive section only swaps the completed generation. Concurrent removals
/// may leave conservative false positives and schedule a later cleanup pass.
#[derive(Debug)]
pub(super) struct EcsLookupIndex {
    entries: ArcSwap<DashMap<EcsBaseKey, EcsPrefixBitmap>>,
    rebuild_gate: RwLock<()>,
    rebuild_shadow: ArcSwapOption<EcsLookupIndex>,
    stale_revision: AtomicU64,
    rebuilt_revision: AtomicU64,
    indexed_base_keys: AtomicU64,
    observed_ipv4_prefixes: AtomicU64,
    observed_ipv6_prefixes: AtomicU64,
}

impl Default for EcsLookupIndex {
    fn default() -> Self {
        Self {
            entries: ArcSwap::from_pointee(DashMap::new()),
            rebuild_gate: RwLock::new(()),
            rebuild_shadow: ArcSwapOption::empty(),
            stale_revision: AtomicU64::new(0),
            rebuilt_revision: AtomicU64::new(0),
            indexed_base_keys: AtomicU64::new(0),
            observed_ipv4_prefixes: AtomicU64::new(0),
            observed_ipv6_prefixes: AtomicU64::new(0),
        }
    }
}

impl EcsLookupIndex {
    #[inline]
    pub(super) fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub(super) fn tracks_cache_key(key: &CacheKey) -> bool {
        key.ecs_scope
            .as_ref()
            .is_some_and(|ecs| ecs.source_prefix == ecs.scope_prefix)
    }

    #[inline]
    pub(super) fn publication_guard(&self) -> std::sync::RwLockReadGuard<'_, ()> {
        self.rebuild_gate
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[inline]
    fn observe_prefix_for_key_local(&self, key: &CacheKey, family: u16, prefix: u8) {
        let base = EcsBaseKey::from_cache_key(key);
        let entries = self.entries.load();
        let inserted_prefix = match entries.entry(base) {
            Entry::Occupied(mut entry) => entry.get_mut().observe(family, prefix),
            Entry::Vacant(entry) => {
                let mut bitmap = EcsPrefixBitmap::default();
                let inserted = bitmap.observe(family, prefix);
                if inserted {
                    entry.insert(bitmap);
                    self.indexed_base_keys.fetch_add(1, Ordering::Relaxed);
                }
                inserted
            }
        };

        if inserted_prefix {
            match family {
                1 => {
                    self.observed_ipv4_prefixes.fetch_add(1, Ordering::Relaxed);
                }
                2 => {
                    self.observed_ipv6_prefixes.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }

    /// Record a key only when it is reusable by ECS scope.
    ///
    /// While a rebuild is active, publications are mirrored into its shadow
    /// snapshot. Callers that publish authoritative cache entries hold the
    /// shared `publication_guard`, so rebuild commit cannot detach the shadow
    /// between this observation and publication of the corresponding cache
    /// generation.
    #[inline]
    pub(super) fn observe_cache_key(&self, key: &CacheKey) {
        let Some(ecs) = &key.ecs_scope else {
            return;
        };
        if ecs.source_prefix != ecs.scope_prefix {
            return;
        }

        self.observe_prefix_for_key_local(key, ecs.family, ecs.scope_prefix);

        if let Some(shadow) = self.rebuild_shadow.load().as_ref() {
            shadow.observe_prefix_for_key_local(key, ecs.family, ecs.scope_prefix);
        }
    }

    #[inline]
    pub(super) fn mark_cache_key_maybe_stale(&self, key: &CacheKey) {
        if Self::tracks_cache_key(key) {
            self.mark_rebuild_needed();
        }
    }

    #[inline]
    pub(super) fn mark_rebuild_needed(&self) {
        self.stale_revision.fetch_add(1, Ordering::AcqRel);
    }

    #[inline]
    pub(super) fn needs_rebuild(&self) -> bool {
        self.stale_revision.load(Ordering::Acquire) != self.rebuilt_revision.load(Ordering::Acquire)
    }

    #[inline]
    pub(super) fn stale_revision(&self) -> u64 {
        self.stale_revision.load(Ordering::Acquire)
    }

    /// Start a rebuild generation without blocking ECS publications for the
    /// authoritative-cache scan.
    ///
    /// The shadow is installed while holding the exclusive publication gate.
    /// Subsequent successful ECS publications mirror their hints into both the
    /// live index and this shadow until commit detaches it. This means normal
    /// publications no longer invalidate an in-progress rebuild.
    pub(super) fn begin_rebuild(&self) -> Option<(Arc<Self>, u64)> {
        let _guard = self
            .rebuild_gate
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if self.rebuild_shadow.load().is_some() {
            return None;
        }

        let stale_revision = self.stale_revision.load(Ordering::Acquire);
        if stale_revision == self.rebuilt_revision.load(Ordering::Acquire) {
            return None;
        }

        let shadow = Arc::new(Self::new());
        self.rebuild_shadow.store(Some(shadow.clone()));
        Some((shadow, stale_revision))
    }

    /// Publish an active rebuild shadow.
    ///
    /// Deletions or evictions racing the scan are allowed to leave conservative
    /// false-positive hints in this generation. Their stale revision remains
    /// newer than `rebuilt_revision`, which schedules another cleanup pass. A
    /// successful publication cannot be missed because it is mirrored into the
    /// active shadow while holding the shared publication gate.
    pub(super) fn commit_rebuild(&self, rebuilt: &Arc<Self>, stale_revision: u64) -> bool {
        let (retired_entries, retired_shadow) = {
            let _guard = self
                .rebuild_gate
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            let active = self.rebuild_shadow.load_full();
            if active
                .as_ref()
                .is_none_or(|active| !Arc::ptr_eq(active, rebuilt))
            {
                return false;
            }

            // The write gate waits for every in-flight publication that could
            // still be mirroring into the shadow. Once acquired, both the
            // rebuilt entries and their counters are stable for this commit.
            let retired_entries = self.entries.swap(rebuilt.entries.load_full());
            self.indexed_base_keys.store(
                rebuilt.indexed_base_keys.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            self.observed_ipv4_prefixes.store(
                rebuilt.observed_ipv4_prefixes.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            self.observed_ipv6_prefixes.store(
                rebuilt.observed_ipv6_prefixes.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );

            // Only acknowledge stale work that existed when this generation
            // started. If a removal raced the scan, needs_rebuild() remains
            // true and a later pass cleans up any false-positive hint.
            self.rebuilt_revision
                .store(stale_revision, Ordering::Release);

            let retired_shadow = self.rebuild_shadow.swap(None);
            (retired_entries, retired_shadow)
        };

        // Neither a potentially large old index nor the rebuild wrapper is
        // destroyed while ECS publications are waiting on rebuild_gate.
        drop(retired_entries);
        drop(retired_shadow);
        true
    }

    #[inline]
    fn snapshot_for(&self, key: &CacheKey) -> EcsPrefixMask {
        let Some(ecs) = key.ecs_scope.as_ref() else {
            return EcsPrefixMask { words: [0; 3] };
        };
        let base = EcsBaseKey::from_cache_key(key);
        let entries = self.entries.load();
        entries
            .get(&base)
            .map(|bitmap| (*bitmap).snapshot_for(ecs.family, ecs.source_prefix))
            .unwrap_or(EcsPrefixMask { words: [0; 3] })
    }

    #[inline]
    pub(super) fn indexed_base_keys(&self) -> u64 {
        self.indexed_base_keys.load(Ordering::Relaxed)
    }

    #[inline]
    pub(super) fn observed_ipv4_prefixes(&self) -> u64 {
        self.observed_ipv4_prefixes.load(Ordering::Relaxed)
    }

    #[inline]
    pub(super) fn observed_ipv6_prefixes(&self) -> u64 {
        self.observed_ipv6_prefixes.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Copy)]
struct EcsPrefixMask {
    words: [u64; 3],
}

impl EcsPrefixMask {
    #[inline]
    fn pop_highest(&mut self) -> Option<u8> {
        for word_index in (0..self.words.len()).rev() {
            let word = self.words[word_index];
            if word == 0 {
                continue;
            }
            let bit = 63u32.saturating_sub(word.leading_zeros()) as u8;
            self.words[word_index] &= !(1u64 << bit);
            return Some((word_index as u8).saturating_mul(64).saturating_add(bit));
        }
        None
    }
}

/// Lazily return cache lookup candidates in RFC 7871 order.
///
/// For ECS requests, only reusable scope prefixes present in the advisory hint
/// per-base-key bitmap are materialized, longest-prefix first. The exact-SOURCE
/// request-specific key is always yielded last. For non-ECS requests, only the
/// ordinary request key is returned.
pub(super) struct CacheLookupKeys<'a> {
    key: &'a CacheKey,
    reusable_prefixes: EcsPrefixMask,
    exact_pending: bool,
}

impl<'a> CacheLookupKeys<'a> {
    #[inline]
    fn new(key: &'a CacheKey, index: &EcsLookupIndex) -> Self {
        let reusable_prefixes = index.snapshot_for(key);
        Self {
            key,
            reusable_prefixes,
            exact_pending: true,
        }
    }
}

impl<'a> Iterator for CacheLookupKeys<'a> {
    type Item = Cow<'a, CacheKey>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(scope_prefix) = self.reusable_prefixes.pop_highest() {
            let candidate = self.key.with_ecs_scope_prefix(scope_prefix);

            // SOURCE=/0 has the same concrete key shape as reusable SCOPE=/0.
            // Yield the concrete key only once.
            if candidate == *self.key {
                self.exact_pending = false;
                return Some(Cow::Borrowed(self.key));
            }

            return Some(Cow::Owned(candidate));
        }

        if self.exact_pending {
            self.exact_pending = false;
            return Some(Cow::Borrowed(self.key));
        }

        None
    }
}

#[inline]
pub(super) fn cache_lookup_keys<'a>(
    key: &'a CacheKey,
    index: &EcsLookupIndex,
) -> CacheLookupKeys<'a> {
    CacheLookupKeys::new(key, index)
}

/// Only cache ordinary unsigned single-question DNS queries.
#[inline]
pub(super) fn is_cacheable_request(request: &Message) -> bool {
    request.message_type() == MessageType::Query
        && request.opcode() == Opcode::Query
        && request.question_count() == 1
        && request.signature().is_empty()
        && request.edns().as_ref().is_none_or(|edns| {
            edns.version() == 0
                && edns
                    .options()
                    .iter()
                    .all(|option| matches!(option, EdnsOption::Subnet(_)))
        })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    fn exhaustive_index_for(key: &CacheKey) -> EcsLookupIndex {
        let index = EcsLookupIndex::new();
        if let Some(ecs) = &key.ecs_scope {
            for prefix in 0..=ecs.source_prefix {
                index.observe_cache_key(&key.with_ecs_scope_prefix(prefix));
            }
        }
        index
    }

    use super::*;
    use crate::proto::{DNSClass, Edns, EdnsOption, Message, Name, Question, RecordType};

    fn make_context(name: &str) -> DnsContext {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii(name).expect("query name should be valid"),
            RecordType::A,
            DNSClass::IN,
        ));
        DnsContext::new(SocketAddr::from(([127, 0, 0, 1], 5300)), request)
    }

    #[test]
    fn test_normalize_domain_key_trims_lowercases_and_strips_dot() {
        let normalized = normalize_domain_key("  WWW.Example.COM.  ");

        assert_eq!(normalized, "www.example.com");
    }

    #[test]
    fn test_normalize_domain_key_preserves_root_domain() {
        assert_eq!(normalize_domain_key(" . "), ".");
        assert_eq!(normalize_domain_key(""), "");
    }

    #[test]
    fn test_normalize_domain_key_preserves_escaped_terminal_dot() {
        assert_eq!(normalize_domain_key(r"foo\."), r"foo\.");
        assert_eq!(normalize_domain_key(r"foo\.."), r"foo\.");
        assert_eq!(normalize_domain_key(r"foo\046"), r"foo\.");
    }

    #[test]
    fn test_normalize_cache_key_domain_requires_valid_nonempty_dns_text() {
        assert_eq!(normalize_cache_key_domain(" . "), Some(".".to_string()));
        assert_eq!(normalize_cache_key_domain(""), None);
        assert_eq!(normalize_cache_key_domain("   "), None);
    }

    #[test]
    fn test_normalize_cache_key_domain_parses_dns_escapes() {
        assert_eq!(
            normalize_cache_key_domain(r"Foo\."),
            Some(r"foo\.".to_string())
        );
        assert_eq!(
            normalize_cache_key_domain(r"foo\.."),
            Some(r"foo\.".to_string())
        );
        assert_eq!(
            normalize_cache_key_domain(r"foo\046"),
            Some(r"foo\.".to_string())
        );
        assert_eq!(normalize_cache_key_domain("foo\\"), None);
    }

    #[test]
    fn test_build_cache_key_uses_dot_for_real_root_query() {
        let mut context = make_context(".");

        let cache_key = build_cache_key(&mut context, false).expect("root cache key should exist");

        assert_eq!(cache_key.domain.as_ref(), ".");
        assert_eq!(
            cache_key
                .question()
                .expect("root question should rebuild")
                .name()
                .to_fqdn(),
            "."
        );
    }

    #[test]
    fn test_write_truncated_prefix_masks_partial_byte() {
        let mut out = [0u8; 16];

        let network_len = write_truncated_prefix(&[0b1111_0000, 0b1010_1010], 12, &mut out);

        assert_eq!(network_len, 2);
        assert_eq!(out[0], 0b1111_0000);
        assert_eq!(out[1], 0b1010_0000);
    }

    #[test]
    fn test_build_ecs_scope_digest_clamps_prefix_and_truncates_network() {
        let subnet = ClientSubnet::new(IpAddr::from([192, 0, 2, 129]), 40, 48);

        let digest = build_ecs_scope_digest(&subnet);

        assert_eq!(digest.family, 1);
        assert_eq!(digest.source_prefix, 32);
        assert_eq!(digest.scope_prefix, 32);
        assert_eq!(digest.network_len, 4);
        assert_eq!(&digest.network[..4], &[192, 0, 2, 129]);
    }

    #[test]
    fn test_build_cache_key_uses_normalized_query_and_flags() {
        let mut context = make_context("WWW.Example.COM.");
        context.request.set_checking_disabled(true);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        context.request.set_edns(edns);

        let cache_key = build_cache_key(&mut context, false).expect("cache key should exist");

        assert_eq!(cache_key.domain.as_ref(), "www.example.com");
        assert_eq!(cache_key.record_type, RecordType::A);
        assert!(cache_key.do_bit);
        assert!(cache_key.cd_bit);
        assert_eq!(cache_key.ecs_scope, None);
    }

    #[test]
    fn test_build_cache_key_includes_ecs_when_enabled() {
        let mut context = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            20,
            0,
        )));
        context.request.set_edns(edns);

        let cache_key = build_cache_key(&mut context, true).expect("cache key should exist");

        let ecs = cache_key.ecs_scope.expect("ecs should be present");
        assert_eq!(ecs.family, 1);
        assert_eq!(ecs.source_prefix, 20);
        assert_eq!(ecs.scope_prefix, 0);
        assert_eq!(ecs.network_len, 3);
        assert_eq!(&ecs.network[..3], &[203, 0, 112]);
    }

    #[test]
    fn test_build_cache_key_rejects_ecs_request_with_nonzero_scope() {
        let mut context = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            20,
            24,
        )));
        context.request.set_edns(edns);

        assert!(build_cache_key(&mut context, true).is_none());
    }

    #[test]
    fn test_build_cache_key_rejects_invalid_ecs_even_when_keying_is_disabled() {
        let mut context = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            20,
            24,
        )));
        context.request.set_edns(edns);

        assert!(build_cache_key(&mut context, false).is_none());

        let mut context = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            33,
            0,
        )));
        context.request.set_edns(edns);

        assert!(build_cache_key(&mut context, false).is_none());
    }

    #[test]
    fn test_build_cache_key_ignores_ecs_when_keying_is_disabled() {
        let mut context = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            20,
            0,
        )));
        context.request.set_edns(edns);

        let cache_key = build_cache_key(&mut context, false).expect("cache key should exist");
        assert_eq!(cache_key.ecs_scope, None);
    }

    #[test]
    fn test_cache_lookup_keys_places_exact_source_after_covering_scopes() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let candidates = cache_lookup_keys(&request_key, &exhaustive_index_for(&request_key))
            .map(Cow::into_owned)
            .collect::<Vec<_>>();

        assert_eq!(
            candidates.first(),
            Some(&request_key.with_ecs_scope_prefix(24))
        );
        assert_eq!(candidates.last(), Some(&request_key));
        assert_eq!(candidates.len(), 26);
    }

    #[test]
    fn test_ecs_lookup_uses_only_observed_scope_prefixes() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([0x2001, 0xDB8, 0, 0, 0, 0, 0, 1]),
            128,
            0,
        )));
        request.request.set_edns(edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let index = EcsLookupIndex::new();
        for prefix in [0, 32, 48, 56, 64] {
            index.observe_cache_key(&request_key.with_ecs_scope_prefix(prefix));
        }

        let prefixes = cache_lookup_keys(&request_key, &index)
            .filter_map(|candidate| {
                if candidate.as_ref() == &request_key {
                    None
                } else {
                    candidate
                        .as_ref()
                        .ecs_scope
                        .as_ref()
                        .map(|ecs| ecs.scope_prefix)
                }
            })
            .collect::<Vec<_>>();

        assert_eq!(prefixes, vec![64, 56, 48, 32, 0]);
    }

    #[test]
    fn test_ecs_lookup_index_is_partitioned_by_base_cache_key() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([0x2001, 0xDB8, 0, 0, 0, 0, 0, 1]),
            128,
            0,
        )));
        request.request.set_edns(edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let index = EcsLookupIndex::new();
        let mut unrelated_key = request_key.with_ecs_scope_prefix(64);
        unrelated_key.domain = Arc::<str>::from("unrelated.example");
        index.observe_cache_key(&unrelated_key);

        let unrelated_candidates = cache_lookup_keys(&request_key, &index)
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        assert_eq!(unrelated_candidates, vec![request_key.clone()]);

        index.observe_cache_key(&request_key.with_ecs_scope_prefix(56));
        let candidates = cache_lookup_keys(&request_key, &index)
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].ecs_scope.as_ref().map(|ecs| ecs.scope_prefix),
            Some(56)
        );
        assert_eq!(candidates[1], request_key);
    }

    #[test]
    fn test_ecs_lookup_index_metrics_count_unique_memberships() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let index = EcsLookupIndex::new();
        let prefix_24 = request_key.with_ecs_scope_prefix(24);
        index.observe_cache_key(&prefix_24);
        index.observe_cache_key(&prefix_24);
        index.observe_cache_key(&request_key.with_ecs_scope_prefix(16));

        let mut unrelated = request_key.with_ecs_scope_prefix(24);
        unrelated.domain = Arc::<str>::from("unrelated.example");
        index.observe_cache_key(&unrelated);

        assert_eq!(index.indexed_base_keys(), 2);
        assert_eq!(index.observed_ipv4_prefixes(), 3);
        assert_eq!(index.observed_ipv6_prefixes(), 0);
    }

    #[test]
    fn test_ecs_rebuild_mirrors_concurrent_publication_and_commits() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let index = EcsLookupIndex::new();
        let prefix_24 = request_key.with_ecs_scope_prefix(24);
        index.observe_cache_key(&prefix_24);
        index.mark_rebuild_needed();

        let (rebuilt, stale_revision) = index.begin_rebuild().expect("rebuild should start");
        // Model the authoritative scan observing the entry that existed when
        // the rebuild started.
        rebuilt.observe_cache_key(&prefix_24);

        // Model a successful reusable-ECS publication racing the scan. The
        // publication guard makes the live+shadow hint update atomic with
        // respect to rebuild commit.
        {
            let _guard = index.publication_guard();
            index.observe_cache_key(&request_key.with_ecs_scope_prefix(16));
        }

        assert!(index.commit_rebuild(&rebuilt, stale_revision));
        assert!(!index.needs_rebuild());
        assert_eq!(index.indexed_base_keys(), 1);
        assert_eq!(index.observed_ipv4_prefixes(), 2);

        let prefixes = cache_lookup_keys(&request_key, &index)
            .filter_map(|candidate| {
                (candidate.as_ref() != &request_key).then(|| {
                    candidate
                        .as_ref()
                        .ecs_scope
                        .as_ref()
                        .expect("candidate should carry ECS")
                        .scope_prefix
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(prefixes, vec![24, 16]);
    }

    #[test]
    fn test_ecs_rebuild_commits_with_concurrent_stale_revision_and_schedules_cleanup() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let index = EcsLookupIndex::new();
        index.observe_cache_key(&request_key.with_ecs_scope_prefix(24));
        index.mark_rebuild_needed();

        let (rebuilt, stale_revision) = index.begin_rebuild().expect("rebuild should start");
        rebuilt.observe_cache_key(&request_key.with_ecs_scope_prefix(24));

        // A removal/eviction racing the scan may make this snapshot
        // conservatively stale, but must not prevent this pass from committing.
        index.mark_rebuild_needed();

        assert!(index.commit_rebuild(&rebuilt, stale_revision));
        assert!(index.needs_rebuild());
        assert_eq!(index.observed_ipv4_prefixes(), 1);
    }

    #[test]
    fn test_ecs_rebuild_commit_swaps_shadow_when_no_new_stale_work_arrives() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let index = EcsLookupIndex::new();
        index.observe_cache_key(&request_key.with_ecs_scope_prefix(24));
        index.mark_rebuild_needed();

        let (rebuilt, stale_revision) = index.begin_rebuild().expect("rebuild should start");
        rebuilt.observe_cache_key(&request_key.with_ecs_scope_prefix(16));

        assert!(index.commit_rebuild(&rebuilt, stale_revision));
        assert!(!index.needs_rebuild());
        assert_eq!(index.indexed_base_keys(), 1);
        assert_eq!(index.observed_ipv4_prefixes(), 1);
        assert_eq!(index.observed_ipv6_prefixes(), 0);

        let prefixes = cache_lookup_keys(&request_key, &index)
            .filter_map(|candidate| {
                (candidate.as_ref() != &request_key).then(|| {
                    candidate
                        .as_ref()
                        .ecs_scope
                        .as_ref()
                        .expect("candidate should carry ECS")
                        .scope_prefix
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(prefixes, vec![16]);
    }

    #[test]
    fn test_request_specific_ecs_key_does_not_create_hint() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let index = EcsLookupIndex::new();
        index.observe_cache_key(&request_key);

        let candidates = cache_lookup_keys(&request_key, &index)
            .map(Cow::into_owned)
            .collect::<Vec<_>>();
        assert_eq!(candidates, vec![request_key]);
    }

    #[test]
    fn test_non_ecs_lookup_borrows_request_key_without_candidates() {
        let mut request = make_context("example.com.");
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");
        let mut lookup_keys = cache_lookup_keys(&request_key, &exhaustive_index_for(&request_key));

        assert!(matches!(lookup_keys.next(), Some(Cow::Borrowed(key)) if key == &request_key));
        assert!(lookup_keys.next().is_none());
    }

    #[test]
    fn test_ecs_lookup_materializes_covering_scope_before_borrowed_exact_key() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");
        let mut lookup_keys = cache_lookup_keys(&request_key, &exhaustive_index_for(&request_key));

        assert!(matches!(lookup_keys.next(), Some(Cow::Owned(_))));

        let remaining = lookup_keys.collect::<Vec<_>>();
        assert!(matches!(remaining.last(), Some(Cow::Borrowed(_))));
        assert_eq!(
            remaining.last().map(|candidate| candidate.as_ref()),
            Some(&request_key)
        );
    }

    #[test]
    fn test_ecs_lookup_prefers_covering_scope_over_exact_source_fallback() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            20,
            0,
        )));
        request.request.set_edns(edns);

        let request_key = build_cache_key(&mut request, true).expect("request key should exist");
        let scoped_key = request_key.with_ecs_scope_prefix(20);

        // Both a reusable covering /20 entry and an exact-SOURCE fallback
        // entry exist. RFC 7871 longest-prefix matching must choose /20 first.
        let cached = [request_key.clone(), scoped_key.clone()];
        let first_hit = cache_lookup_keys(&request_key, &exhaustive_index_for(&request_key))
            .find(|candidate| cached.contains(candidate.as_ref()))
            .map(Cow::into_owned);

        assert_eq!(first_hit, Some(scoped_key));
    }

    #[test]
    fn test_ecs_lookup_uses_exact_source_when_no_covering_entry_exists() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            20,
            0,
        )));
        request.request.set_edns(edns);

        let request_key = build_cache_key(&mut request, true).expect("request key should exist");
        let cached = [request_key.clone()];
        let first_hit = cache_lookup_keys(&request_key, &exhaustive_index_for(&request_key))
            .find(|candidate| cached.contains(candidate.as_ref()))
            .map(Cow::into_owned);

        assert_eq!(first_hit, Some(request_key));
    }

    #[test]
    fn test_cache_lookup_keys_do_not_duplicate_zero_scope_request_key() {
        let mut request = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            0,
            0,
        )));
        request.request.set_edns(edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        assert_eq!(
            cache_lookup_keys(&request_key, &exhaustive_index_for(&request_key))
                .map(Cow::into_owned)
                .collect::<Vec<_>>(),
            vec![request_key]
        );
    }

    #[test]
    fn test_response_ecs_scope_key_matches_broader_client_prefix() {
        let mut request = make_context("example.com.");
        let mut request_edns = Edns::new();
        request_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(request_edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let mut response = Message::new();
        let mut response_edns = Edns::new();
        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 0]),
            24,
            20,
        )));
        response.set_edns(response_edns);
        let scoped_key =
            cache_key_for_response_ecs_scope(&request_key, &response).expect("ECS should match");

        let ecs = scoped_key
            .ecs_scope
            .as_ref()
            .expect("scope should be present");
        assert_eq!(ecs.source_prefix, 20);
        assert_eq!(ecs.scope_prefix, 20);
        assert_eq!(&ecs.network[..3], &[203, 0, 112]);

        let mut other_request = make_context("example.com.");
        let mut other_edns = Edns::new();
        other_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 127, 1]),
            24,
            0,
        )));
        other_request.request.set_edns(other_edns);
        let other_key =
            build_cache_key(&mut other_request, true).expect("request key should exist");

        assert!(
            cache_lookup_keys(&other_key, &exhaustive_index_for(&other_key))
                .any(|candidate| candidate.as_ref() == &scoped_key)
        );
    }

    #[test]
    fn test_ecs_refresh_validates_against_request_key_not_scoped_cache_key() {
        let mut request = make_context("example.com.");
        let mut request_edns = Edns::new();
        request_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(request_edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let mut response = Message::new();
        let mut response_edns = Edns::new();
        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 0]),
            24,
            16,
        )));
        response.set_edns(response_edns);

        let scoped_key = cache_key_for_response_ecs_scope(&request_key, &response)
            .expect("refresh response should be accepted for the request key");
        assert_ne!(scoped_key, request_key);
        assert!(cache_key_for_response_ecs_scope(&scoped_key, &response).is_none());
    }

    #[test]
    fn test_build_cache_key_returns_none_without_query() {
        let mut context = DnsContext::new(SocketAddr::from(([127, 0, 0, 1], 5300)), Message::new());

        let cache_key = build_cache_key(&mut context, true);

        assert_eq!(cache_key, None);
    }

    #[test]
    fn test_unsupported_edns_version_is_not_cacheable() {
        let mut context = make_context("example.com.");
        let mut edns = Edns::new();
        edns.set_version(1);
        context.request.set_edns(edns);

        assert!(!is_cacheable_request(&context.request));
    }

    #[test]
    fn test_non_query_and_request_bound_options_are_not_cacheable() {
        let mut context = make_context("example.com.");
        context.request.set_opcode(Opcode::Notify);
        assert!(!is_cacheable_request(&context.request));

        let mut context = make_context("example.com.");
        let mut edns = Edns::new();
        edns.insert(EdnsOption::Cookie(crate::proto::EdnsCookie::new(vec![
            1, 2,
        ])));
        context.request.set_edns(edns);
        assert!(!is_cacheable_request(&context.request));
    }

    #[test]
    fn test_response_ecs_scope_more_specific_than_source_stays_request_specific() {
        let mut request = make_context("example.com.");

        let mut request_edns = Edns::new();
        request_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            20,
            0,
        )));
        request.request.set_edns(request_edns);

        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let mut response = Message::new();
        let mut response_edns = Edns::new();

        // SOURCE matches the request (/20), but the server advertises a
        // narrower cache scope (/24).
        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 112, 0]),
            20,
            24,
        )));

        response.set_edns(response_edns);

        let scoped_key = cache_key_for_response_ecs_scope(&request_key, &response)
            .expect("ECS response should be accepted");

        // SCOPE > SOURCE must remain request-specific.
        assert_eq!(scoped_key, request_key);

        // A /24 request inside the same /20 must NOT hit the request-specific
        // /20 entry merely because its lookup candidates contain /20.
        let mut other_request = make_context("example.com.");

        let mut other_edns = Edns::new();
        other_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 1]),
            24,
            0,
        )));
        other_request.request.set_edns(other_edns);

        let other_key =
            build_cache_key(&mut other_request, true).expect("other request key should exist");

        assert!(
            !cache_lookup_keys(&other_key, &exhaustive_index_for(&other_key))
                .any(|candidate| candidate.as_ref() == &scoped_key)
        );
    }

    #[test]
    fn test_response_ecs_source_zero_with_positive_scope_is_not_cached() {
        let mut request = make_context("example.com.");
        let mut request_edns = Edns::new();
        request_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([0, 0, 0, 0]),
            0,
            0,
        )));
        request.request.set_edns(request_edns);

        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let mut response = Message::new();
        let mut response_edns = Edns::new();
        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([0, 0, 0, 0]),
            0,
            24,
        )));
        response.set_edns(response_edns);

        assert!(cache_key_for_response_ecs_scope(&request_key, &response).is_none());
        assert!(!persisted_ecs_key_matches_response(&request_key, &response));
    }

    #[test]
    fn test_response_ecs_rejects_mismatched_source_prefix() {
        let mut request = make_context("example.com.");

        let mut request_edns = Edns::new();
        request_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(request_edns);

        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let mut response = Message::new();
        let mut response_edns = Edns::new();

        // Same general address area but wrong SOURCE PREFIX-LENGTH.
        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 112, 0]),
            23,
            20,
        )));

        response.set_edns(response_edns);

        assert!(cache_key_for_response_ecs_scope(&request_key, &response).is_none());
    }

    #[test]
    fn test_persisted_ecs_key_matches_reusable_response_scope() {
        let mut request = make_context("example.com.");
        let mut request_edns = Edns::new();
        request_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(request_edns);
        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let mut response = Message::new();
        let mut response_edns = Edns::new();
        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 0]),
            24,
            20,
        )));
        response.set_edns(response_edns);
        let stored_key = cache_key_for_response_ecs_scope(&request_key, &response)
            .expect("response ECS should produce a reusable key");

        assert!(persisted_ecs_key_matches_response(&stored_key, &response));

        let mut mismatched_response = response.clone();
        let mut mismatched_edns = Edns::new();
        mismatched_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 129, 0]),
            24,
            20,
        )));
        mismatched_response.set_edns(mismatched_edns);
        assert!(!persisted_ecs_key_matches_response(
            &stored_key,
            &mismatched_response
        ));
    }

    #[test]
    fn test_persisted_ecs_key_matches_global_scope_zero_response() {
        let mut request = make_context("example.com.");

        let mut request_edns = Edns::new();
        request_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 199]),
            24,
            0,
        )));
        request.request.set_edns(request_edns);

        let request_key = build_cache_key(&mut request, true).expect("request key should exist");

        let mut response = Message::new();
        let mut response_edns = Edns::new();

        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 0]),
            24,
            0,
        )));

        response.set_edns(response_edns);

        let stored_key = cache_key_for_response_ecs_scope(&request_key, &response)
            .expect("response ECS should be accepted");

        let ecs = stored_key
            .ecs_scope
            .as_ref()
            .expect("stored key should contain ECS");

        assert_eq!(ecs.source_prefix, 0);
        assert_eq!(ecs.scope_prefix, 0);
        assert_eq!(ecs.network_len, 0);

        assert!(
            persisted_ecs_key_matches_response(&stored_key, &response,),
            "SCOPE=0 reusable ECS entry must survive persistence validation"
        );
    }
}
