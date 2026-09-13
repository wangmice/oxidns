// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Live DNS-cache store facade.
//!
//! `TtlCache` deliberately stays policy-agnostic. This layer owns DNS-level
//! lookup semantics and mutation side effects so callers do not interpret raw
//! TTL-container states or update the live map without persistence dirtiness,
//! ECS lookup hints, pressure signalling, and metrics staying in sync.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tracing::debug;

use super::key::{CacheKey, EcsLookupIndex, cache_lookup_keys};
use super::{
    CacheEntryHandle, CacheItem, CacheMap, CacheMetrics, cache_skip_reason_for_disposition,
    is_cache_disposition_valid, response_disposition_for_cache,
};
use crate::infra::cache::ttl::{
    TtlCacheConditionalMoveResult, TtlCacheHandleLookup, TtlCacheMoveMetadata, TtlCachePruneMode,
};

/// Cancellation-safe guard for one in-progress persistence dump.
///
/// The fields stay private so dump callers cannot partially commit or restore
/// mutation bookkeeping. Dropping an unresolved handoff automatically rolls
/// back the claimed mutation counter and dirty watermark.
#[derive(Debug)]
#[must_use = "an unresolved cache dump handoff rolls back when dropped"]
pub(super) struct CacheDumpHandoff {
    state: CacheMutationState,
    changed: u64,
    generation: u64,
    previous_dirty_since_ms: u64,
    resolved: bool,
}

impl CacheDumpHandoff {
    /// Commit a successful dump. Returns `true` when no newer mutation raced
    /// with the dump and the live cache is clean at this point.
    pub(super) fn complete(mut self) -> bool {
        self.state
            .inner
            .persisted_generation
            .store(self.generation, Ordering::Release);
        let clean = self.state.inner.dirty_generation.load(Ordering::Acquire) == self.generation;
        self.resolved = true;
        clean
    }

    /// Explicitly abort a failed dump. Cancellation and early-return paths do
    /// not need to call this because `Drop` performs the same rollback.
    pub(super) fn abort(mut self) {
        self.rollback();
    }

    fn rollback(&mut self) {
        if self.resolved {
            return;
        }
        self.state
            .inner
            .updated_keys
            .fetch_add(self.changed, Ordering::Relaxed);
        self.state.restore_dirty_since(self.previous_dirty_since_ms);
        self.resolved = true;
    }
}

impl Drop for CacheDumpHandoff {
    fn drop(&mut self) {
        self.rollback();
    }
}

/// Shared persistence-mutation bookkeeping.
///
/// All atomics are intentionally private. Callers operate on the dump state
/// machine instead of coordinating counters, generations, and watermarks by
/// convention.
#[derive(Debug)]
struct CacheMutationInner {
    updated_keys: AtomicU64,
    dirty_since_ms: AtomicU64,
    dirty_generation: AtomicU64,
    persisted_generation: AtomicU64,
}

#[derive(Clone, Debug)]
struct CacheMutationState {
    inner: Arc<CacheMutationInner>,
}

impl CacheMutationState {
    fn new() -> Self {
        Self {
            inner: Arc::new(CacheMutationInner {
                updated_keys: AtomicU64::new(0),
                dirty_since_ms: AtomicU64::new(0),
                dirty_generation: AtomicU64::new(0),
                persisted_generation: AtomicU64::new(0),
            }),
        }
    }

    #[inline]
    fn dirty_timestamp(now_ms: u64) -> u64 {
        // Zero is reserved as the clean/no-watermark sentinel.
        now_ms.max(1)
    }

    #[inline]
    fn mark_dirty(&self, changes: u64) {
        if changes == 0 {
            return;
        }

        let _ = self.inner.dirty_generation.try_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |generation| Some(generation.saturating_add(1).max(1)),
        );
        self.inner
            .updated_keys
            .fetch_add(changes, Ordering::Relaxed);

        // Preserve mutations that happen during the first millisecond of the
        // process lifetime; zero remains the initial timestamp sentinel.
        let now = Self::dirty_timestamp(crate::infra::clock::AppClock::elapsed_millis());
        let _ =
            self.inner
                .dirty_since_ms
                .compare_exchange(0, now, Ordering::AcqRel, Ordering::Relaxed);
    }

    #[inline]
    fn restore_dirty_since(&self, timestamp_ms: u64) {
        if timestamp_ms == 0 {
            return;
        }

        let _ =
            self.inner
                .dirty_since_ms
                .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    Some(if current == 0 {
                        timestamp_ms
                    } else {
                        current.min(timestamp_ms)
                    })
                });
    }

    #[inline]
    fn dump_age_due(
        now_ms: u64,
        dirty_since_ms: u64,
        max_dirty_age_ms: u64,
        check_interval_ms: u64,
    ) -> bool {
        dirty_since_ms != 0
            && now_ms.saturating_sub(dirty_since_ms)
                >= max_dirty_age_ms.saturating_sub(check_interval_ms)
    }

    /// Begin one dump if either enough mutations accumulated or the oldest
    /// unsaved mutation is old enough.
    ///
    /// The current mutation counter is temporarily claimed by this handoff. If
    /// no dump is due it is restored without advancing the dirty generation.
    fn begin_dump_if_due(
        &self,
        now_ms: u64,
        minimum_changes: u64,
        max_dirty_age_ms: u64,
        check_interval_ms: u64,
    ) -> Option<CacheDumpHandoff> {
        let changed = self.inner.updated_keys.swap(0, Ordering::AcqRel);
        let dirty_since = self.inner.dirty_since_ms.load(Ordering::Acquire);
        let dirty = self.inner.dirty_generation.load(Ordering::Acquire)
            != self.inner.persisted_generation.load(Ordering::Acquire);
        let age_due =
            dirty && Self::dump_age_due(now_ms, dirty_since, max_dirty_age_ms, check_interval_ms);

        if changed < minimum_changes && !age_due {
            // These are already-accounted mutations, so restoring the counter
            // must not advance the dirty generation or watermark.
            self.inner
                .updated_keys
                .fetch_add(changed, Ordering::Relaxed);
            return None;
        }

        // Capture the generation represented by this dump, then hand the old
        // dirty watermark to the dump. Mutations after this point install a
        // fresh watermark for the next generation.
        let generation = self.inner.dirty_generation.load(Ordering::Acquire);
        let previous_dirty_since_ms = self.inner.dirty_since_ms.swap(0, Ordering::AcqRel);

        // A mutation may race between the generation load and watermark swap.
        // Ensure that newer generation retains a conservative watermark.
        if self.inner.dirty_generation.load(Ordering::Acquire) != generation {
            let now = Self::dirty_timestamp(crate::infra::clock::AppClock::elapsed_millis());
            let mut current_since = self.inner.dirty_since_ms.load(Ordering::Acquire);
            loop {
                if current_since != 0 && current_since <= now {
                    break;
                }
                match self.inner.dirty_since_ms.compare_exchange_weak(
                    current_since,
                    now,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(actual) => current_since = actual,
                }
            }
        }

        Some(CacheDumpHandoff {
            state: self.clone(),
            changed,
            generation,
            previous_dirty_since_ms,
            resolved: false,
        })
    }
}

/// DNS-level result of one cache lookup.
///
/// TTL-container details such as `Expired` are intentionally hidden here.
/// Callers only need to distinguish a usable fresh response, a retained stale
/// response that may be refreshed, and a miss that should enter miss handling.
#[derive(Debug, Clone)]
pub(super) enum DnsCacheLookup {
    Fresh {
        entry: CacheEntryHandle,
        remaining_ttl: u32,
    },
    Stale {
        key: CacheKey,
        request_key: CacheKey,
        entry: CacheEntryHandle,
    },
    Miss {
        key: CacheKey,
    },
}

impl DnsCacheLookup {
    #[inline]
    pub(super) fn is_hit(&self) -> bool {
        !matches!(self, Self::Miss { .. })
    }
}

/// Live DNS-cache store.
///
/// All *online* reads and mutations of the published cache pass through this
/// facade. Staged/offline cache construction used by persistence remains free
/// to work directly with `CacheMap` because it is not visible to readers yet.
#[derive(Clone, Debug)]
pub(super) struct DnsCacheStore {
    cache_map: CacheMap,
    cache_size: usize,
    ecs_lookup_index: Arc<EcsLookupIndex>,
    pressure_requested: Arc<AtomicBool>,
    mutations: CacheMutationState,
    metrics: Arc<CacheMetrics>,
}

impl DnsCacheStore {
    pub(super) fn new(
        cache_map: CacheMap,
        cache_size: usize,
        ecs_lookup_index: Arc<EcsLookupIndex>,
        metrics: Arc<CacheMetrics>,
    ) -> Self {
        Self {
            cache_map,
            cache_size,
            ecs_lookup_index,
            pressure_requested: Arc::new(AtomicBool::new(false)),
            mutations: CacheMutationState::new(),
            metrics,
        }
    }

    #[inline]
    pub(super) fn cache_map(&self) -> &CacheMap {
        &self.cache_map
    }

    #[inline]
    pub(super) fn cache_size(&self) -> usize {
        self.cache_size
    }

    #[inline]
    pub(super) fn ecs_lookup_index(&self) -> &Arc<EcsLookupIndex> {
        &self.ecs_lookup_index
    }

    #[inline]
    pub(super) fn metrics(&self) -> &Arc<CacheMetrics> {
        &self.metrics
    }

    #[inline]
    pub(super) fn begin_dump_if_due(
        &self,
        now_ms: u64,
        minimum_changes: u64,
        max_dirty_age_ms: u64,
        check_interval_ms: u64,
    ) -> Option<CacheDumpHandoff> {
        self.mutations.begin_dump_if_due(
            now_ms,
            minimum_changes,
            max_dirty_age_ms,
            check_interval_ms,
        )
    }

    #[inline]
    pub(super) fn take_pressure_requested(&self) -> bool {
        self.pressure_requested.swap(false, Ordering::AcqRel)
    }

    /// Resolve one DNS cache lookup across ECS candidates.
    ///
    /// This is the read-side boundary for the live DNS cache. It owns candidate
    /// traversal, validation, fresh/stale classification, expiry accounting,
    /// and lookup metrics so executor code never needs to interpret raw
    /// `TtlCacheHandleLookup` states.
    #[inline]
    pub(super) fn lookup(
        &self,
        request_key: CacheKey,
        now_ms: u64,
        touch_interval_ms: u64,
        allow_stale: bool,
    ) -> DnsCacheLookup {
        self.metrics.lookup_total.fetch_add(1, Ordering::Relaxed);

        let ecs_lookup = request_key.ecs_scope.is_some();
        if ecs_lookup {
            self.metrics
                .ecs_lookup_requests_total
                .fetch_add(1, Ordering::Relaxed);
        }

        let mut expired = false;
        for candidate in cache_lookup_keys(&request_key, &self.ecs_lookup_index) {
            if ecs_lookup {
                self.metrics
                    .ecs_lookup_candidates_total
                    .fetch_add(1, Ordering::Relaxed);
                if candidate.as_ref() == &request_key {
                    self.metrics
                        .ecs_lookup_exact_fallback_total
                        .fetch_add(1, Ordering::Relaxed);
                }
            }

            let key = candidate.as_ref();
            match self
                .cache_map
                .get_retained_handle_status(key, now_ms, touch_interval_ms)
            {
                Some(TtlCacheHandleLookup::Hit(entry)) => {
                    let value = entry.value();
                    let invalid_disposition = if value.is_validated() {
                        None
                    } else {
                        let disposition = response_disposition_for_cache(&value.resp, key);
                        (!is_cache_disposition_valid(disposition)).then_some(disposition)
                    };

                    if let Some(disposition) = invalid_disposition {
                        if self.remove_handle(key, &entry) {
                            self.metrics
                                .record_skip(cache_skip_reason_for_disposition(disposition));
                            debug!(
                                "evicted invalid cache entry: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}",
                                key.domain,
                                key.record_type,
                                key.dns_class,
                                key.do_bit,
                                key.cd_bit,
                                key.ecs_scope.is_some()
                            );
                        }
                        continue;
                    }

                    if now_ms < value.fresh_until_ms {
                        self.metrics.fresh_hit_total.fetch_add(1, Ordering::Relaxed);
                        let remaining_ttl = value
                            .fresh_until_ms
                            .saturating_sub(now_ms)
                            .saturating_div(1000)
                            as u32;
                        debug!(
                            "cache hit: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}, kind=fresh",
                            key.domain,
                            key.record_type,
                            key.dns_class,
                            key.do_bit,
                            key.cd_bit,
                            key.ecs_scope.is_some()
                        );
                        return DnsCacheLookup::Fresh {
                            entry,
                            remaining_ttl,
                        };
                    }

                    if allow_stale && now_ms < entry.expire_at_ms() {
                        self.metrics.stale_hit_total.fetch_add(1, Ordering::Relaxed);
                        debug!(
                            "cache hit: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}, kind=stale",
                            key.domain,
                            key.record_type,
                            key.dns_class,
                            key.do_bit,
                            key.cd_bit,
                            key.ecs_scope.is_some()
                        );
                        return DnsCacheLookup::Stale {
                            key: key.clone(),
                            request_key: request_key.clone(),
                            entry,
                        };
                    }
                }
                Some(TtlCacheHandleLookup::Expired) => {
                    self.ecs_lookup_index.mark_cache_key_maybe_stale(key);
                    self.mutations.mark_dirty(1);
                    self.metrics.expired_total.fetch_add(1, Ordering::Relaxed);
                    expired = true;
                    debug!(
                        "cache expired: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}",
                        key.domain,
                        key.record_type,
                        key.dns_class,
                        key.do_bit,
                        key.cd_bit,
                        key.ecs_scope.is_some()
                    );
                }
                None => {}
            }
        }

        // Preserve the previous read-path metric semantics: an expired entry
        // removed during candidate traversal is an expiry event, not a miss.
        if !expired {
            if self.remove_if_expired(&request_key, now_ms) {
                debug!(
                    "cache expired: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}",
                    request_key.domain,
                    request_key.record_type,
                    request_key.dns_class,
                    request_key.do_bit,
                    request_key.cd_bit,
                    request_key.ecs_scope.is_some()
                );
            } else {
                self.metrics.miss_total.fetch_add(1, Ordering::Relaxed);
                debug!(
                    "cache miss: domain={}, type={:?}, class={:?}, do={}, cd={}, ecs={}",
                    request_key.domain,
                    request_key.record_type,
                    request_key.dns_class,
                    request_key.do_bit,
                    request_key.cd_bit,
                    request_key.ecs_scope.is_some()
                );
            }
        }

        DnsCacheLookup::Miss { key: request_key }
    }

    /// Publish a normal cache insert/update and all associated bookkeeping.
    pub(super) fn insert_or_update(
        &self,
        key: CacheKey,
        item: CacheItem,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
    ) -> bool {
        let tracks_ecs_prefix = EcsLookupIndex::tracks_cache_key(&key);
        let _index_publication =
            tracks_ecs_prefix.then(|| self.ecs_lookup_index.publication_guard());
        let inserted = self
            .cache_map
            .try_insert_or_update_with_limit_before_publish(
                key,
                item,
                cache_time_ms,
                expire_at_ms,
                last_access_ms,
                self.cache_size,
                |published_key| self.ecs_lookup_index.observe_cache_key(published_key),
            );
        if inserted {
            self.mutations.mark_dirty(1);
            self.metrics.insert_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.pressure_requested.store(true, Ordering::Release);
        }
        inserted
    }

    /// Replace a stale entry only if the expected stable handle is still live.
    pub(super) fn replace_handle(
        &self,
        key: CacheKey,
        expected: &CacheEntryHandle,
        item: CacheItem,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
    ) -> bool {
        let tracks_ecs_prefix = EcsLookupIndex::tracks_cache_key(&key);
        let _index_publication =
            tracks_ecs_prefix.then(|| self.ecs_lookup_index.publication_guard());
        self.ecs_lookup_index.observe_cache_key(&key);
        let replaced = self.cache_map.replace_handle(
            key,
            expected,
            item,
            cache_time_ms,
            expire_at_ms,
            last_access_ms,
        );
        if replaced {
            self.mutations.mark_dirty(1);
            self.metrics.insert_total.fetch_add(1, Ordering::Relaxed);
        } else if tracks_ecs_prefix {
            self.ecs_lookup_index.mark_rebuild_needed();
        }
        replaced
    }

    /// Re-key a stale ECS entry as one atomic freshness-aware mutation.
    pub(super) fn conditional_move_handle(
        &self,
        source_key: &CacheKey,
        target_key: CacheKey,
        expected: &CacheEntryHandle,
        item: CacheItem,
        metadata: TtlCacheMoveMetadata,
    ) -> TtlCacheConditionalMoveResult {
        let tracks_target_prefix = EcsLookupIndex::tracks_cache_key(&target_key);
        let _index_publication =
            tracks_target_prefix.then(|| self.ecs_lookup_index.publication_guard());
        self.ecs_lookup_index.observe_cache_key(&target_key);
        let refresh_time_ms = metadata.cache_time_ms;
        let result = self.cache_map.conditional_move_handle_if(
            source_key,
            target_key,
            expected,
            item,
            metadata,
            move |target, _expire_at_ms| target.fresh_until_ms <= refresh_time_ms,
        );
        match result {
            TtlCacheConditionalMoveResult::Moved => {
                self.mutations.mark_dirty(1);
                self.metrics.insert_total.fetch_add(1, Ordering::Relaxed);
            }
            TtlCacheConditionalMoveResult::Consolidated => {
                self.mutations.mark_dirty(1);
            }
            TtlCacheConditionalMoveResult::ReplacedTarget => {
                self.mutations.mark_dirty(1);
                self.metrics.insert_total.fetch_add(1, Ordering::Relaxed);
            }
            TtlCacheConditionalMoveResult::SourceChanged => {}
        }
        if matches!(result, TtlCacheConditionalMoveResult::SourceChanged) {
            if tracks_target_prefix {
                self.ecs_lookup_index.mark_rebuild_needed();
            }
        } else {
            self.ecs_lookup_index.mark_cache_key_maybe_stale(source_key);
        }
        result
    }

    /// Remove exactly the generation represented by `expected`.
    #[inline]
    pub(super) fn remove_handle(&self, key: &CacheKey, expected: &CacheEntryHandle) -> bool {
        let removed = self.cache_map.remove_handle(key, expected);
        if removed {
            self.ecs_lookup_index.mark_cache_key_maybe_stale(key);
            self.mutations.mark_dirty(1);
        }
        removed
    }

    /// Remove an entry only when it is expired, accounting for both the
    /// mutation and the expired-lookup metric.
    #[inline]
    fn remove_if_expired(&self, key: &CacheKey, now_ms: u64) -> bool {
        let removed = self.cache_map.remove_if_expired(key, now_ms);
        if removed {
            self.ecs_lookup_index.mark_cache_key_maybe_stale(key);
            self.mutations.mark_dirty(1);
            self.metrics.expired_total.fetch_add(1, Ordering::Relaxed);
        }
        removed
    }

    /// Remove one live entry by key (management API path).
    #[inline]
    pub(super) fn remove(&self, key: &CacheKey) -> bool {
        let removed = self.cache_map.remove(key);
        if removed {
            self.ecs_lookup_index.mark_cache_key_maybe_stale(key);
            self.mutations.mark_dirty(1);
        }
        removed
    }

    #[inline]
    pub(super) fn ecs_lookup_index_needs_rebuild(&self) -> bool {
        self.ecs_lookup_index.needs_rebuild()
    }

    pub(super) fn rebuild_ecs_lookup_index_if_needed(&self) {
        if !self.ecs_lookup_index.needs_rebuild() {
            return;
        }

        // Install a shadow generation under the short publication write gate,
        // then scan without holding it. Successful ECS publications are mirrored
        // into the shadow while the scan runs, so sustained write traffic cannot
        // starve rebuild progress. Concurrent removals may leave conservative
        // false positives; their newer stale revision schedules another pass.
        let Some((rebuilt, stale_revision)) = self.ecs_lookup_index.begin_rebuild() else {
            return;
        };
        self.cache_map.visit_keys_cloned_by_shard(|keys| {
            for key in keys {
                rebuilt.observe_cache_key(&key);
            }
            true
        });
        let _ = self
            .ecs_lookup_index
            .commit_rebuild(&rebuilt, stale_revision);
    }

    /// Prune the published cache and account for every removed entry exactly
    /// once. The returned tuple matches `TtlCache::prune`.
    pub(super) fn prune(&self, mode: TtlCachePruneMode, now_ms: u64) -> (usize, usize, usize) {
        let result = self.cache_map.prune(mode, now_ms);
        let removed = result.0.saturating_add(result.1);
        self.mutations.mark_dirty(removed as u64);
        if removed > 0 {
            self.ecs_lookup_index.mark_rebuild_needed();
        }
        result
    }

    /// Atomically publish a prepared cache generation and account for the
    /// visible replacement as one mutation transaction.
    #[cfg(feature = "api")]
    pub(super) fn replace_generation(
        &self,
        replacement: &CacheMap,
        published_entries: usize,
    ) -> crate::infra::cache::ttl::TtlCacheRetiredState<CacheKey, CacheItem> {
        let retired = self.cache_map.swap_retired(replacement);
        // New-generation ECS memberships must be observed before the swap by
        // the staging path. Old memberships are only false positives, so defer
        // their removal to maintenance instead of creating a publication gap.
        self.ecs_lookup_index.mark_rebuild_needed();
        let changed = (retired.entry_count() as u64).saturating_add(published_entries as u64);
        self.mutations.mark_dirty(changed);
        retired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::clock::AppClock;
    use crate::proto::{DNSClass, Message, RecordType};

    fn test_key(domain: &str) -> CacheKey {
        CacheKey {
            domain: domain.into(),
            record_type: RecordType::A,
            dns_class: DNSClass::IN,
            do_bit: false,
            cd_bit: false,
            ecs_scope: None,
        }
    }

    fn test_ecs_key(domain: &str, prefix: u8) -> CacheKey {
        let mut network = [0u8; 16];
        network[..4].copy_from_slice(&[203, 0, 113, 0]);
        CacheKey {
            domain: domain.into(),
            record_type: RecordType::A,
            dns_class: DNSClass::IN,
            do_bit: false,
            cd_bit: false,
            ecs_scope: Some(super::super::key::EcsScopeDigest {
                family: 1,
                source_prefix: prefix,
                scope_prefix: prefix,
                network_len: prefix.saturating_add(7) / 8,
                network,
            }),
        }
    }

    fn test_store(cache_size: usize) -> (DnsCacheStore, CacheMutationState, Arc<CacheMetrics>) {
        let cache_map = CacheMap::with_capacity(cache_size.max(1));
        let index = Arc::new(EcsLookupIndex::new());
        let metrics = Arc::new(CacheMetrics::new("store-test".to_string()));
        let store = DnsCacheStore::new(cache_map, cache_size, index, metrics.clone());
        let mutations = store.mutations.clone();
        (store, mutations, metrics)
    }

    #[test]
    fn insert_and_remove_keep_mutation_bookkeeping_together() {
        AppClock::start();
        let (store, mutations, metrics) = test_store(1);
        let now = AppClock::elapsed_millis();
        let key = test_key("example.com");
        let item = CacheItem::new_validated(Message::new(), 60, now.saturating_add(60_000));

        assert!(store.insert_or_update(key.clone(), item, now, now.saturating_add(60_000), now,));
        assert_eq!(mutations.inner.updated_keys.load(Ordering::Relaxed), 1);
        assert_eq!(mutations.inner.dirty_generation.load(Ordering::Acquire), 1);
        assert_eq!(metrics.insert_total.load(Ordering::Relaxed), 1);

        assert!(store.remove(&key));
        assert_eq!(mutations.inner.updated_keys.load(Ordering::Relaxed), 2);
        assert_eq!(mutations.inner.dirty_generation.load(Ordering::Acquire), 2);
    }

    #[test]
    fn conditional_move_consolidation_marks_cache_dirty_without_counting_insert() {
        AppClock::start();
        let (store, mutations, metrics) = test_store(4);
        let now = AppClock::elapsed_millis();
        let source = test_key("source.example");
        let target = test_key("target.example");

        assert!(store.insert_or_update(
            source.clone(),
            CacheItem::new_validated(Message::new(), 60, now.saturating_add(60_000)),
            now,
            now.saturating_add(60_000),
            now,
        ));
        assert!(store.insert_or_update(
            target.clone(),
            CacheItem::new_validated(Message::new(), 120, now.saturating_add(120_000)),
            now,
            now.saturating_add(120_000),
            now,
        ));
        let expected = store
            .cache_map()
            .get_retained_handle(&source, now, 0)
            .expect("source should exist");
        let before_dirty = mutations.inner.dirty_generation.load(Ordering::Acquire);
        let before_inserts = metrics.insert_total.load(Ordering::Relaxed);

        assert_eq!(
            store.conditional_move_handle(
                &source,
                target.clone(),
                &expected,
                CacheItem::new_validated(Message::new(), 30, now.saturating_add(30_000)),
                TtlCacheMoveMetadata {
                    cache_time_ms: now,
                    expire_at_ms: now.saturating_add(30_000),
                    last_access_ms: now,
                },
            ),
            TtlCacheConditionalMoveResult::Consolidated
        );

        assert!(
            store
                .cache_map()
                .get_retained_handle(&source, now, 0)
                .is_none()
        );
        let target_entry = store
            .cache_map()
            .get_retained_handle(&target, now, 0)
            .expect("existing target should remain");
        assert_eq!(target_entry.value().ttl, 120);
        assert_eq!(store.cache_map().entry_count(), 1);
        assert_eq!(
            mutations.inner.dirty_generation.load(Ordering::Acquire),
            before_dirty.saturating_add(1)
        );
        assert_eq!(metrics.insert_total.load(Ordering::Relaxed), before_inserts);
    }

    #[test]
    fn conditional_move_replaces_stale_retained_target() {
        AppClock::start();
        let (store, _mutations, metrics) = test_store(4);
        let now = AppClock::elapsed_millis();
        let commit_time = now.saturating_add(2_000);
        let source = test_ecs_key("stale-merge.example", 24);
        let target = test_ecs_key("stale-merge.example", 20);

        assert!(store.insert_or_update(
            source.clone(),
            CacheItem::new_validated(Message::new(), 60, now.saturating_add(1_000)),
            now,
            now.saturating_add(120_000),
            now,
        ));
        assert!(store.insert_or_update(
            target.clone(),
            CacheItem::new_validated(Message::new(), 120, now.saturating_add(1_000)),
            now,
            now.saturating_add(120_000),
            now,
        ));
        let expected = store
            .cache_map()
            .get_retained_handle(&source, now, 0)
            .expect("source should remain retained");
        let before_inserts = metrics.insert_total.load(Ordering::Relaxed);

        assert_eq!(
            store.conditional_move_handle(
                &source,
                target.clone(),
                &expected,
                CacheItem::new_validated(Message::new(), 30, commit_time.saturating_add(30_000),),
                TtlCacheMoveMetadata {
                    cache_time_ms: commit_time,
                    expire_at_ms: commit_time.saturating_add(60_000),
                    last_access_ms: commit_time,
                },
            ),
            TtlCacheConditionalMoveResult::ReplacedTarget
        );

        assert!(
            store
                .cache_map()
                .get_retained_handle(&source, commit_time, 0)
                .is_none()
        );
        let target_entry = store
            .cache_map()
            .get_retained_handle(&target, commit_time, 0)
            .expect("stale retained target should be replaced by refresh");
        assert_eq!(target_entry.value().ttl, 30);
        assert_eq!(store.cache_map().entry_count(), 1);
        assert_eq!(
            metrics.insert_total.load(Ordering::Relaxed),
            before_inserts.saturating_add(1)
        );
    }

    #[test]
    fn conditional_move_preserves_target_refreshed_before_commit() {
        AppClock::start();
        let (store, _mutations, metrics) = test_store(4);
        let now = AppClock::elapsed_millis();
        let commit_time = now.saturating_add(2_000);
        let source = test_ecs_key("race-merge.example", 24);
        let target = test_ecs_key("race-merge.example", 20);

        assert!(store.insert_or_update(
            source.clone(),
            CacheItem::new_validated(Message::new(), 60, now.saturating_add(1_000)),
            now,
            now.saturating_add(120_000),
            now,
        ));
        assert!(store.insert_or_update(
            target.clone(),
            CacheItem::new_validated(Message::new(), 120, now.saturating_add(1_000)),
            now,
            now.saturating_add(120_000),
            now,
        ));
        let expected = store
            .cache_map()
            .get_retained_handle(&source, now, 0)
            .expect("source should remain retained");

        // Model another refresh publishing a fresh target while this source
        // refresh is in flight. The conditional move must inspect the target
        // generation present at commit time and preserve it.
        assert!(store.insert_or_update(
            target.clone(),
            CacheItem::new_validated(Message::new(), 240, commit_time.saturating_add(240_000),),
            commit_time.saturating_sub(1),
            commit_time.saturating_add(300_000),
            commit_time.saturating_sub(1),
        ));
        let before_inserts = metrics.insert_total.load(Ordering::Relaxed);

        assert_eq!(
            store.conditional_move_handle(
                &source,
                target.clone(),
                &expected,
                CacheItem::new_validated(Message::new(), 30, commit_time.saturating_add(30_000),),
                TtlCacheMoveMetadata {
                    cache_time_ms: commit_time,
                    expire_at_ms: commit_time.saturating_add(60_000),
                    last_access_ms: commit_time,
                },
            ),
            TtlCacheConditionalMoveResult::Consolidated
        );

        assert!(
            store
                .cache_map()
                .get_retained_handle(&source, commit_time, 0)
                .is_none()
        );
        let target_entry = store
            .cache_map()
            .get_retained_handle(&target, commit_time, 0)
            .expect("concurrently refreshed target should be preserved");
        assert_eq!(target_entry.value().ttl, 240);
        assert_eq!(store.cache_map().entry_count(), 1);
        assert_eq!(metrics.insert_total.load(Ordering::Relaxed), before_inserts);
    }

    #[test]
    fn prune_marks_ecs_lookup_index_for_deferred_rebuild() {
        AppClock::start();
        let (store, _mutations, _metrics) = test_store(4);
        let now = AppClock::elapsed_millis().saturating_add(100);
        let expired = test_ecs_key("expired.example", 24);
        let live = test_ecs_key("live.example", 16);

        assert!(store.insert_or_update(
            expired,
            CacheItem::new_validated(Message::new(), 1, now),
            now.saturating_sub(1_000),
            now,
            now.saturating_sub(1_000),
        ));
        assert!(store.insert_or_update(
            live,
            CacheItem::new_validated(Message::new(), 60, now.saturating_add(60_000)),
            now,
            now.saturating_add(60_000),
            now,
        ));
        assert_eq!(store.ecs_lookup_index().observed_ipv4_prefixes(), 2);
        assert_eq!(store.ecs_lookup_index().indexed_base_keys(), 2);

        let (expired_removed, _, _) = store.prune(TtlCachePruneMode::Exact { max_size: 4 }, now);

        assert_eq!(expired_removed, 1);
        assert!(store.ecs_lookup_index_needs_rebuild());
        assert_eq!(store.ecs_lookup_index().observed_ipv4_prefixes(), 2);
        assert_eq!(store.ecs_lookup_index().indexed_base_keys(), 2);

        store.rebuild_ecs_lookup_index_if_needed();

        assert!(!store.ecs_lookup_index_needs_rebuild());
        assert_eq!(store.ecs_lookup_index().observed_ipv4_prefixes(), 1);
        assert_eq!(store.ecs_lookup_index().indexed_base_keys(), 1);
    }

    #[test]
    fn rejected_ecs_admission_does_not_publish_index_hints() {
        AppClock::start();
        let (store, _mutations, _metrics) = test_store(1);
        let now = AppClock::elapsed_millis();

        assert!(store.insert_or_update(
            test_ecs_key("resident.example", 24),
            CacheItem::new_validated(Message::new(), 60, now.saturating_add(60_000)),
            now,
            now.saturating_add(60_000),
            now,
        ));
        assert_eq!(store.ecs_lookup_index().indexed_base_keys(), 1);
        assert_eq!(store.ecs_lookup_index().observed_ipv4_prefixes(), 1);
        assert!(!store.ecs_lookup_index_needs_rebuild());

        for attempt in 0..128 {
            assert!(!store.insert_or_update(
                test_ecs_key(&format!("rejected-{attempt}.example"), 16),
                CacheItem::new_validated(Message::new(), 60, now.saturating_add(60_000)),
                now,
                now.saturating_add(60_000),
                now,
            ));
        }

        assert_eq!(store.cache_map().entry_count(), 1);
        assert_eq!(store.ecs_lookup_index().indexed_base_keys(), 1);
        assert_eq!(store.ecs_lookup_index().observed_ipv4_prefixes(), 1);
        assert!(!store.ecs_lookup_index_needs_rebuild());
        assert!(store.take_pressure_requested());
    }

    #[test]
    fn rejected_admission_requests_pressure_cleanup_without_dirtying_cache() {
        AppClock::start();
        let (store, mutations, metrics) = test_store(1);
        let now = AppClock::elapsed_millis();

        assert!(store.insert_or_update(
            test_key("one.example"),
            CacheItem::new_validated(Message::new(), 60, now.saturating_add(60_000)),
            now,
            now.saturating_add(60_000),
            now,
        ));
        let before_dirty = mutations.inner.dirty_generation.load(Ordering::Acquire);
        let before_inserts = metrics.insert_total.load(Ordering::Relaxed);

        assert!(!store.insert_or_update(
            test_key("two.example"),
            CacheItem::new_validated(Message::new(), 60, now.saturating_add(60_000)),
            now,
            now.saturating_add(60_000),
            now,
        ));
        assert!(store.take_pressure_requested());
        assert_eq!(
            mutations.inner.dirty_generation.load(Ordering::Acquire),
            before_dirty
        );
        assert_eq!(metrics.insert_total.load(Ordering::Relaxed), before_inserts);
    }

    #[test]
    fn lookup_classifies_fresh_stale_and_miss() {
        AppClock::start();
        let (store, _, metrics) = test_store(4);
        let now = AppClock::elapsed_millis();

        let fresh_key = test_key("fresh.example");
        assert!(store.insert_or_update(
            fresh_key.clone(),
            CacheItem::new_validated(Message::new(), 60, now.saturating_add(60_000)),
            now,
            now.saturating_add(60_000),
            now,
        ));
        let fresh = store.lookup(fresh_key, now, 0, false);
        assert!(matches!(
            fresh,
            DnsCacheLookup::Fresh {
                remaining_ttl: 60,
                ..
            }
        ));

        let stale_key = test_key("stale.example");
        assert!(store.insert_or_update(
            stale_key.clone(),
            CacheItem::new_validated(Message::new(), 60, now.saturating_sub(1)),
            now.saturating_sub(60_001),
            now.saturating_add(60_000),
            now,
        ));
        let stale = store.lookup(stale_key, now, 0, true);
        assert!(matches!(stale, DnsCacheLookup::Stale { .. }));

        let miss = store.lookup(test_key("missing.example"), now, 0, false);
        assert!(matches!(miss, DnsCacheLookup::Miss { .. }));
        assert_eq!(metrics.lookup_total.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.fresh_hit_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.stale_hit_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.miss_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn expired_lookup_accounts_for_internal_ttl_removal_once() {
        AppClock::start();
        let (store, mutations, metrics) = test_store(4);
        let now = AppClock::elapsed_millis();
        let key = test_key("expired.example");

        assert!(store.insert_or_update(
            key.clone(),
            CacheItem::new_validated(Message::new(), 1, now.saturating_add(1)),
            now,
            now.saturating_add(1),
            now,
        ));

        mutations.inner.updated_keys.store(0, Ordering::Release);
        mutations.inner.dirty_since_ms.store(0, Ordering::Release);
        mutations.inner.dirty_generation.store(0, Ordering::Release);
        metrics.expired_total.store(0, Ordering::Release);

        let result = store.lookup(key.clone(), now.saturating_add(2), 0, false);
        assert!(matches!(result, DnsCacheLookup::Miss { .. }));
        assert_eq!(mutations.inner.updated_keys.load(Ordering::Relaxed), 1);
        assert_eq!(mutations.inner.dirty_generation.load(Ordering::Acquire), 1);
        assert_eq!(metrics.expired_total.load(Ordering::Relaxed), 1);
        assert!(store.cache_map().is_empty());
    }

    #[test]
    fn dump_age_due_accounts_for_the_next_scheduler_tick() {
        let state = CacheMutationState::new();
        state.inner.dirty_generation.store(1, Ordering::Release);
        state.inner.dirty_since_ms.store(1, Ordering::Release);

        assert!(state.begin_dump_if_due(1, 1024, 120_000, 120_000).is_some());

        let state = CacheMutationState::new();
        state.inner.dirty_generation.store(1, Ordering::Release);
        state.inner.dirty_since_ms.store(1, Ordering::Release);
        assert!(
            state
                .begin_dump_if_due(120_000, 1024, 120_000, 120_000)
                .is_some()
        );

        let state = CacheMutationState::new();
        state.inner.dirty_generation.store(1, Ordering::Release);
        state.inner.dirty_since_ms.store(1, Ordering::Release);
        assert!(
            state
                .begin_dump_if_due(60_000, 1024, 120_000, 60_000)
                .is_none()
        );
        assert!(
            state
                .begin_dump_if_due(60_001, 1024, 120_000, 60_000)
                .is_some()
        );
    }

    #[test]
    fn dirty_timestamp_reserves_zero_for_clean_state() {
        assert_eq!(CacheMutationState::dirty_timestamp(0), 1);
        assert_eq!(CacheMutationState::dirty_timestamp(1), 1);
        assert_eq!(CacheMutationState::dirty_timestamp(42), 42);
    }

    #[test]
    fn successful_dump_handoff_clears_old_dirty_watermark() {
        let state = CacheMutationState::new();
        state.inner.dirty_since_ms.store(10, Ordering::Release);
        state.inner.dirty_generation.store(7, Ordering::Release);
        state.inner.updated_keys.store(1024, Ordering::Release);

        let handoff = state
            .begin_dump_if_due(20, 1024, 120_000, 60_000)
            .expect("dump should start");
        assert_eq!(handoff.generation, 7);
        assert_eq!(handoff.previous_dirty_since_ms, 10);
        assert_eq!(state.inner.dirty_since_ms.load(Ordering::Acquire), 0);

        assert!(handoff.complete());
        assert_eq!(state.inner.persisted_generation.load(Ordering::Acquire), 7);
        assert_eq!(state.inner.dirty_since_ms.load(Ordering::Acquire), 0);
    }

    #[test]
    fn dump_handoff_preserves_new_mutation_watermark() {
        AppClock::start();
        let state = CacheMutationState::new();
        state.inner.dirty_since_ms.store(10, Ordering::Release);
        state.inner.dirty_generation.store(7, Ordering::Release);
        state.inner.updated_keys.store(1024, Ordering::Release);

        let handoff = state
            .begin_dump_if_due(20, 1024, 120_000, 60_000)
            .expect("dump should start");
        assert_eq!(handoff.previous_dirty_since_ms, 10);
        assert_eq!(state.inner.dirty_since_ms.load(Ordering::Acquire), 0);

        state.mark_dirty(1);
        assert_eq!(state.inner.dirty_generation.load(Ordering::Acquire), 8);
        assert_ne!(state.inner.dirty_since_ms.load(Ordering::Acquire), 0);

        assert!(!handoff.complete());
        assert_eq!(state.inner.persisted_generation.load(Ordering::Acquire), 7);
        assert_ne!(state.inner.dirty_since_ms.load(Ordering::Acquire), 0);
    }

    #[test]
    fn failed_dump_restores_previous_dirty_watermark_and_change_count() {
        let state = CacheMutationState::new();
        state.inner.dirty_since_ms.store(100, Ordering::Release);
        state.inner.dirty_generation.store(5, Ordering::Release);
        state.inner.updated_keys.store(2048, Ordering::Release);

        let handoff = state
            .begin_dump_if_due(200, 1024, 120_000, 60_000)
            .expect("dump should start");
        assert_eq!(handoff.previous_dirty_since_ms, 100);
        assert_eq!(state.inner.updated_keys.load(Ordering::Acquire), 0);
        assert_eq!(state.inner.dirty_since_ms.load(Ordering::Acquire), 0);

        // Simulate a newer mutation during the failed dump.
        state.inner.dirty_since_ms.store(200, Ordering::Release);
        handoff.abort();

        assert_eq!(state.inner.updated_keys.load(Ordering::Acquire), 2048);
        assert_eq!(state.inner.dirty_since_ms.load(Ordering::Acquire), 100);
    }

    #[test]
    fn dropped_dump_handoff_rolls_back_for_cancellation_safety() {
        let state = CacheMutationState::new();
        state.inner.dirty_since_ms.store(100, Ordering::Release);
        state.inner.dirty_generation.store(5, Ordering::Release);
        state.inner.updated_keys.store(1024, Ordering::Release);

        let handoff = state
            .begin_dump_if_due(200, 1024, 120_000, 60_000)
            .expect("dump should start");
        assert_eq!(state.inner.updated_keys.load(Ordering::Acquire), 0);
        assert_eq!(state.inner.dirty_since_ms.load(Ordering::Acquire), 0);

        drop(handoff);

        assert_eq!(state.inner.updated_keys.load(Ordering::Acquire), 1024);
        assert_eq!(state.inner.dirty_since_ms.load(Ordering::Acquire), 100);
        assert_eq!(state.inner.persisted_generation.load(Ordering::Acquire), 0);
    }

    #[test]
    fn skipped_dump_restores_counter_without_advancing_generation() {
        let state = CacheMutationState::new();
        state.mark_dirty(7);
        let generation = state.inner.dirty_generation.load(Ordering::Acquire);
        let dirty_since = state.inner.dirty_since_ms.load(Ordering::Acquire);

        assert!(
            state
                .begin_dump_if_due(dirty_since, 1024, 120_000, 60_000)
                .is_none()
        );
        assert_eq!(state.inner.updated_keys.load(Ordering::Acquire), 7);
        assert_eq!(
            state.inner.dirty_generation.load(Ordering::Acquire),
            generation
        );
        assert_eq!(
            state.inner.dirty_since_ms.load(Ordering::Acquire),
            dirty_since
        );
    }
}
