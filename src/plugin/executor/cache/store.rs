// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! DNS-cache mutation facade.
//!
//! `TtlCache` deliberately stays policy-agnostic. This layer owns the DNS
//! cache's mutation side effects so callers cannot update the live map without
//! also updating persistence dirtiness, ECS lookup hints, pressure signalling,
//! and mutation metrics.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::key::{CacheKey, EcsPrefixHints};
use super::{CacheEntryHandle, CacheItem, CacheMap, CacheMetrics};
use crate::infra::cache::ttl::{
    TtlCacheConditionalMoveResult, TtlCacheHandleLookup, TtlCacheMoveMetadata,
    TtlCachePruneMode,
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
        self.state
            .restore_dirty_since(self.previous_dirty_since_ms);
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

        let _ = self
            .inner
            .dirty_generation
            .try_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                Some(generation.saturating_add(1).max(1))
            });
        self.inner.updated_keys.fetch_add(changes, Ordering::Relaxed);

        // Preserve mutations that happen during the first millisecond of the
        // process lifetime; zero remains the initial timestamp sentinel.
        let now = Self::dirty_timestamp(crate::infra::clock::AppClock::elapsed_millis());
        let _ = self.inner.dirty_since_ms.compare_exchange(
            0,
            now,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }

    #[inline]
    fn restore_dirty_since(&self, timestamp_ms: u64) {
        if timestamp_ms == 0 {
            return;
        }

        let _ = self
            .inner
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
        let age_due = dirty
            && Self::dump_age_due(
                now_ms,
                dirty_since,
                max_dirty_age_ms,
                check_interval_ms,
            );

        if changed < minimum_changes && !age_due {
            // These are already-accounted mutations, so restoring the counter
            // must not advance the dirty generation or watermark.
            self.inner.updated_keys.fetch_add(changed, Ordering::Relaxed);
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

/// Live DNS-cache store.
///
/// All *online* mutations of the published cache should pass through this
/// facade. Staged/offline cache construction used by persistence remains free
/// to work directly with `CacheMap` because it is not visible to readers yet.
#[derive(Clone, Debug)]
pub(super) struct DnsCacheStore {
    cache_map: CacheMap,
    cache_size: usize,
    ecs_prefix_hints: Arc<EcsPrefixHints>,
    pressure_requested: Arc<AtomicBool>,
    mutations: CacheMutationState,
    metrics: Arc<CacheMetrics>,
}

impl DnsCacheStore {
    pub(super) fn new(
        cache_map: CacheMap,
        cache_size: usize,
        ecs_prefix_hints: Arc<EcsPrefixHints>,
        metrics: Arc<CacheMetrics>,
    ) -> Self {
        Self {
            cache_map,
            cache_size,
            ecs_prefix_hints,
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
    pub(super) fn ecs_prefix_hints(&self) -> &Arc<EcsPrefixHints> {
        &self.ecs_prefix_hints
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

    /// Lookup one live entry. Expired-entry removal happens inside `TtlCache`;
    /// account for that mutation here before exposing the result to callers.
    #[inline]
    pub(super) fn get_retained_handle_status(
        &self,
        key: &CacheKey,
        now_ms: u64,
        touch_interval_ms: u64,
    ) -> Option<TtlCacheHandleLookup<CacheItem>> {
        let result = self
            .cache_map
            .get_retained_handle_status(key, now_ms, touch_interval_ms);
        if matches!(result.as_ref(), Some(TtlCacheHandleLookup::Expired)) {
            self.mutations.mark_dirty(1);
            self.metrics.expired_total.fetch_add(1, Ordering::Relaxed);
        }
        result
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
        // Publish the advisory prefix first. Hints are monotonic, so a failed
        // admission can only leave a harmless false-positive lookup bit.
        self.ecs_prefix_hints.observe_cache_key(&key);
        let inserted = self.cache_map.try_insert_or_update_with_limit(
            key,
            item,
            cache_time_ms,
            expire_at_ms,
            last_access_ms,
            self.cache_size,
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
        self.ecs_prefix_hints.observe_cache_key(&key);
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
        }
        replaced
    }

    /// Re-key a stale ECS entry as one atomic conditional mutation.
    pub(super) fn conditional_move_handle(
        &self,
        source_key: &CacheKey,
        target_key: CacheKey,
        expected: &CacheEntryHandle,
        item: CacheItem,
        metadata: TtlCacheMoveMetadata,
    ) -> TtlCacheConditionalMoveResult {
        self.ecs_prefix_hints.observe_cache_key(&target_key);
        let result = self.cache_map.conditional_move_handle(
            source_key,
            target_key,
            expected,
            item,
            metadata,
        );
        if result == TtlCacheConditionalMoveResult::Moved {
            self.mutations.mark_dirty(1);
            self.metrics.insert_total.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Remove exactly the generation represented by `expected`.
    #[inline]
    pub(super) fn remove_handle(&self, key: &CacheKey, expected: &CacheEntryHandle) -> bool {
        let removed = self.cache_map.remove_handle(key, expected);
        if removed {
            self.mutations.mark_dirty(1);
        }
        removed
    }

    /// Remove an entry only when it is expired, accounting for both the
    /// mutation and the expired-lookup metric.
    #[inline]
    pub(super) fn remove_if_expired(&self, key: &CacheKey, now_ms: u64) -> bool {
        let removed = self.cache_map.remove_if_expired(key, now_ms);
        if removed {
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
            self.mutations.mark_dirty(1);
        }
        removed
    }

    /// Prune the published cache and account for every removed entry exactly
    /// once. The returned tuple matches `TtlCache::prune`.
    pub(super) fn prune(
        &self,
        mode: TtlCachePruneMode,
        now_ms: u64,
    ) -> (usize, usize, usize) {
        let result = self.cache_map.prune(mode, now_ms);
        let removed = result.0.saturating_add(result.1);
        self.mutations.mark_dirty(removed as u64);
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

    fn test_store(cache_size: usize) -> (DnsCacheStore, CacheMutationState, Arc<CacheMetrics>) {
        let cache_map = CacheMap::with_capacity(cache_size.max(1));
        let hints = Arc::new(EcsPrefixHints::new());
        let metrics = Arc::new(CacheMetrics::new("store-test".to_string()));
        let store = DnsCacheStore::new(cache_map, cache_size, hints, metrics.clone());
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

        assert!(store.insert_or_update(
            key.clone(),
            item,
            now,
            now.saturating_add(60_000),
            now,
        ));
        assert_eq!(mutations.inner.updated_keys.load(Ordering::Relaxed), 1);
        assert_eq!(mutations.inner.dirty_generation.load(Ordering::Acquire), 1);
        assert_eq!(metrics.insert_total.load(Ordering::Relaxed), 1);

        assert!(store.remove(&key));
        assert_eq!(mutations.inner.updated_keys.load(Ordering::Relaxed), 2);
        assert_eq!(mutations.inner.dirty_generation.load(Ordering::Acquire), 2);
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
        assert_eq!(mutations.inner.dirty_generation.load(Ordering::Acquire), before_dirty);
        assert_eq!(metrics.insert_total.load(Ordering::Relaxed), before_inserts);
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

        let result = store.get_retained_handle_status(&key, now.saturating_add(2), 0);
        assert!(matches!(result, Some(TtlCacheHandleLookup::Expired)));
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
        assert!(state
            .begin_dump_if_due(120_000, 1024, 120_000, 120_000)
            .is_some());

        let state = CacheMutationState::new();
        state.inner.dirty_generation.store(1, Ordering::Release);
        state.inner.dirty_since_ms.store(1, Ordering::Release);
        assert!(state
            .begin_dump_if_due(60_000, 1024, 120_000, 60_000)
            .is_none());
        assert!(state
            .begin_dump_if_due(60_001, 1024, 120_000, 60_000)
            .is_some());
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

        assert!(state
            .begin_dump_if_due(dirty_since, 1024, 120_000, 60_000)
            .is_none());
        assert_eq!(state.inner.updated_keys.load(Ordering::Acquire), 7);
        assert_eq!(state.inner.dirty_generation.load(Ordering::Acquire), generation);
        assert_eq!(state.inner.dirty_since_ms.load(Ordering::Acquire), dirty_since);
    }

}
