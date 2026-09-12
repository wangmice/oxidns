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
use super::{CacheEntryHandle, CacheItem, CacheMap, CacheMetrics, mark_dirty};
use crate::infra::cache::ttl::{
    TtlCacheConditionalMoveResult, TtlCacheHandleLookup, TtlCacheMoveMetadata,
    TtlCachePruneMode,
};

/// Shared persistence-mutation bookkeeping.
#[derive(Clone, Debug)]
pub(super) struct CacheMutationState {
    pub(super) updated_keys: Arc<AtomicU64>,
    pub(super) dirty_since_ms: Arc<AtomicU64>,
    pub(super) dirty_generation: Arc<AtomicU64>,
    pub(super) persisted_generation: Arc<AtomicU64>,
}

impl CacheMutationState {
    pub(super) fn new() -> Self {
        Self {
            updated_keys: Arc::new(AtomicU64::new(0)),
            dirty_since_ms: Arc::new(AtomicU64::new(0)),
            dirty_generation: Arc::new(AtomicU64::new(0)),
            persisted_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    #[inline]
    pub(super) fn mark_dirty(&self, changes: u64) {
        mark_dirty(
            &self.updated_keys,
            &self.dirty_since_ms,
            &self.dirty_generation,
            changes,
        );
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
    pub(super) fn mutations(&self) -> &CacheMutationState {
        &self.mutations
    }

    #[inline]
    pub(super) fn metrics(&self) -> &Arc<CacheMetrics> {
        &self.metrics
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
        let mutations = store.mutations().clone();
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
        assert_eq!(mutations.updated_keys.load(Ordering::Relaxed), 1);
        assert_eq!(mutations.dirty_generation.load(Ordering::Acquire), 1);
        assert_eq!(metrics.insert_total.load(Ordering::Relaxed), 1);

        assert!(store.remove(&key));
        assert_eq!(mutations.updated_keys.load(Ordering::Relaxed), 2);
        assert_eq!(mutations.dirty_generation.load(Ordering::Acquire), 2);
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
        let before_dirty = mutations.dirty_generation.load(Ordering::Acquire);
        let before_inserts = metrics.insert_total.load(Ordering::Relaxed);

        assert!(!store.insert_or_update(
            test_key("two.example"),
            CacheItem::new_validated(Message::new(), 60, now.saturating_add(60_000)),
            now,
            now.saturating_add(60_000),
            now,
        ));
        assert!(store.take_pressure_requested());
        assert_eq!(mutations.dirty_generation.load(Ordering::Acquire), before_dirty);
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

        mutations.updated_keys.store(0, Ordering::Release);
        mutations.dirty_since_ms.store(0, Ordering::Release);
        mutations.dirty_generation.store(0, Ordering::Release);
        metrics.expired_total.store(0, Ordering::Release);

        let result = store.get_retained_handle_status(&key, now.saturating_add(2), 0);
        assert!(matches!(result, Some(TtlCacheHandleLookup::Expired)));
        assert_eq!(mutations.updated_keys.load(Ordering::Relaxed), 1);
        assert_eq!(mutations.dirty_generation.load(Ordering::Acquire), 1);
        assert_eq!(metrics.expired_total.load(Ordering::Relaxed), 1);
        assert!(store.cache_map().is_empty());
    }

}
