// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared TTL cache component.
//!
//! This module provides a reusable concurrent cache with:
//! - per-entry expiration timestamp
//! - last-access timestamp for sampled LRU eviction
//! - lightweight helpers for periodic cleanup tasks
//!
//! It is designed for plugin-level caches where each plugin keeps its own key
//! and value types but shares the same cache behavior.

use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use ahash::RandomState as AHashBuilder;
use arc_swap::ArcSwap;
use dashmap::{DashMap, Entry, SharedValue};
use rand::RngExt;

const LAST_ACCESS_EVICTING_BIT: u64 = 1 << 63;
const PERIODIC_MAINTENANCE_SAMPLE_SIZE: usize = 4096;
const PERIODIC_EVICTION_SAMPLE_KILL_DIVISOR: usize = 4;
const EXACT_COMPACT_CAPACITY_RATIO: usize = 2;

/// Immutable cache node stored behind a stable `Arc`.
///
/// Entry replacement always publishes a new node. The only mutable field is
/// the approximate last-access timestamp, which can be updated lock-free.
#[derive(Debug)]
struct TtlCacheNode<V> {
    value: V,
    cache_time_ms: u64,
    expire_at_ms: u64,
    last_access_ms: AtomicU64,
    generation: u64,
}

impl<V> TtlCacheNode<V> {
    #[inline]
    fn new(
        value: V,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
        generation: u64,
    ) -> Self {
        Self {
            value,
            cache_time_ms,
            expire_at_ms,
            last_access_ms: AtomicU64::new(last_access_ms & !LAST_ACCESS_EVICTING_BIT),
            generation,
        }
    }

    #[inline]
    fn last_access_ms(&self) -> u64 {
        self.last_access_ms.load(Ordering::Relaxed) & !LAST_ACCESS_EVICTING_BIT
    }

    #[inline]
    fn touch_last_access(&self, now_ms: u64) {
        debug_assert_eq!(now_ms & LAST_ACCESS_EVICTING_BIT, 0);
        let mut current = self.last_access_ms.load(Ordering::Relaxed);
        loop {
            if current & LAST_ACCESS_EVICTING_BIT != 0 || current >= now_ms {
                return;
            }
            match self.last_access_ms.compare_exchange_weak(
                current,
                now_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    #[inline]
    fn try_claim_eviction(&self, expected_last_access_ms: u64) -> bool {
        debug_assert_eq!(expected_last_access_ms & LAST_ACCESS_EVICTING_BIT, 0);
        self.last_access_ms
            .compare_exchange(
                expected_last_access_ms,
                expected_last_access_ms | LAST_ACCESS_EVICTING_BIT,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// Stable handle to one concrete cache entry generation.
///
/// Replacing a key creates a new node, so pointer identity is sufficient to
/// detect whether a refresh/remove operation still targets the same entry.
#[derive(Debug)]
pub struct TtlCacheHandle<V> {
    node: Arc<TtlCacheNode<V>>,
}

impl<V> Clone for TtlCacheHandle<V> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            node: self.node.clone(),
        }
    }
}

impl<V> TtlCacheHandle<V> {
    #[inline]
    pub fn value(&self) -> &V {
        &self.node.value
    }

    #[inline]
    pub fn cache_time_ms(&self) -> u64 {
        self.node.cache_time_ms
    }

    #[inline]
    pub fn expire_at_ms(&self) -> u64 {
        self.node.expire_at_ms
    }

    #[inline]
    pub fn last_access_ms(&self) -> u64 {
        self.node.last_access_ms()
    }

    #[inline]
    fn same_node(&self, other: &Arc<TtlCacheNode<V>>) -> bool {
        Arc::ptr_eq(&self.node, other)
    }
}

/// Result of a stable-handle retained-entry lookup.
#[derive(Debug)]
pub enum TtlCacheHandleLookup<V> {
    /// Entry exists and is still retained.
    Hit(TtlCacheHandle<V>),
    /// Entry existed but expired and was removed.
    Expired,
}

/// Outcome of a capacity-bounded conditional restore/insert.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TtlCacheInsertIfNotNewerResult {
    /// The entry was inserted or replaced.
    Inserted,
    /// A newer entry already occupies the key, so it was left untouched.
    NewerPresent,
    /// The key is vacant but the cache has no free capacity for a new entry.
    AtCapacity,
}

/// Outcome of atomically moving a conditionally matched entry to a different
/// key.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum TtlCacheConditionalMoveResult {
    /// The source still matched, the target was vacant, and the move committed.
    Moved,
    /// The source still matched and was removed because the target key already
    /// contained a retained entry. The existing target entry was preserved.
    Consolidated,
    /// The source still matched and the target existed but was already expired.
    /// Both old entries were removed and the refreshed value replaced the target.
    ReplacedExpiredTarget,
    /// The source entry was missing or no longer matched the supplied identity.
    SourceChanged,
}

/// Metadata for the entry created by a conditional move.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TtlCacheMoveMetadata {
    pub(crate) cache_time_ms: u64,
    pub(crate) expire_at_ms: u64,
    pub(crate) last_access_ms: u64,
}

/// Capacity policy for one background cache-pruning pass.
#[derive(Debug, Clone, Copy)]
pub enum TtlCachePruneMode {
    /// Trim only after crossing a high watermark, making bounded progress
    /// toward the low watermark on each periodic maintenance pass.
    Periodic {
        max_size: usize,
        high_watermark_pct: usize,
        low_watermark_pct: usize,
    },
    /// Trim every excess entry and retain at most `max_size` entries.
    Exact { max_size: usize },
}

#[derive(Debug)]
struct TtlCacheMaintenanceCandidate<K> {
    key: K,
    expire_at_ms: u64,
    last_access_ms: u64,
    generation: u64,
}

#[derive(Debug)]
struct TtlCacheState<K, V>
where
    K: Eq + Hash,
{
    map: DashMap<K, Arc<TtlCacheNode<V>>, AHashBuilder>,
    entry_count: AtomicUsize,
    next_generation: AtomicU64,
}

impl<K, V> TtlCacheState<K, V>
where
    K: Eq + Hash,
{
    fn with_capacity(capacity: usize) -> Self {
        Self {
            map: DashMap::with_capacity_and_hasher(capacity, AHashBuilder::default()),
            entry_count: AtomicUsize::new(0),
            next_generation: AtomicU64::new(0),
        }
    }

    #[inline]
    fn next_generation(&self) -> u64 {
        self.next_generation
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    #[inline]
    fn new_node(
        &self,
        value: V,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
    ) -> Arc<TtlCacheNode<V>> {
        Arc::new(TtlCacheNode::new(
            value,
            cache_time_ms,
            expire_at_ms,
            last_access_ms,
            self.next_generation(),
        ))
    }
}

/// Shared concurrent TTL cache.
#[derive(Debug)]
pub struct TtlCache<K, V>
where
    K: Eq + Hash,
{
    state: Arc<ArcSwap<TtlCacheState<K, V>>>,
}

/// Cache state detached by an atomic cache replacement.
///
/// Keeping the retired `Arc` inside this wrapper lets latency-sensitive callers
/// transfer ownership to a dedicated reclaimer instead of potentially dropping
/// a large map on the thread that commits the replacement.
pub struct TtlCacheRetiredState<K, V>
where
    K: Eq + Hash,
{
    state: Arc<TtlCacheState<K, V>>,
    entry_count: usize,
}

impl<K, V> TtlCacheRetiredState<K, V>
where
    K: Eq + Hash,
{
    /// Number of entries observed immediately after the state was retired.
    ///
    /// This is intentionally an observational statistic: operations that
    /// captured the old state before retirement can still complete against it,
    /// so the value need not equal the state's eventual quiescent entry count.
    #[inline]
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Reclaim the retired state only after all readers of that state are gone.
    ///
    /// `Err(self)` means another owner still exists; a background reclaimer can
    /// keep the returned wrapper and retry later. `Ok(())` guarantees the final
    /// destruction of the map happened in this call.
    #[inline]
    pub fn try_reclaim(self) -> std::result::Result<(), Self> {
        let Self { state, entry_count } = self;

        match Arc::try_unwrap(state) {
            Ok(state) => {
                drop(state);
                Ok(())
            }
            Err(state) => Err(Self { state, entry_count }),
        }
    }
}

impl<K, V> Clone for TtlCache<K, V>
where
    K: Eq + Hash,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash,
{
    /// Create cache using AHash hasher with expected capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            state: Arc::new(ArcSwap::from_pointee(TtlCacheState::with_capacity(
                capacity,
            ))),
        }
    }

    /// Current number of cached entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.state.load().map.len()
    }

    /// Returns true when cache has no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.state.load().map.is_empty()
    }
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash,
{
    /// Insert or update one entry using "now" for cache and access timestamps.
    #[inline]
    pub fn insert_or_update(&self, key: K, value: V, now_ms: u64, expire_at_ms: u64) {
        self.insert_or_update_with_meta(key, value, now_ms, expire_at_ms, now_ms);
    }

    /// Insert or update one entry with explicit metadata.
    pub fn insert_or_update_with_meta(
        &self,
        key: K,
        value: V,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
    ) {
        let state = self.state.load();
        let node = state.new_node(value, cache_time_ms, expire_at_ms, last_access_ms);
        match state.map.entry(key) {
            Entry::Occupied(mut e) => {
                e.insert(node);
            }
            Entry::Vacant(e) => {
                e.insert(node);
                state.entry_count.fetch_add(1, Ordering::Release);
            }
        }
    }

    /// Insert or update one entry while atomically rejecting new entries after
    /// `max_entries` has been reached. Existing keys are always updateable.
    pub fn try_insert_or_update_with_limit(
        &self,
        key: K,
        value: V,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
        max_entries: usize,
    ) -> bool {
        let state = self.state.load();
        match state.map.entry(key) {
            Entry::Occupied(mut e) => {
                e.insert(state.new_node(value, cache_time_ms, expire_at_ms, last_access_ms));
                true
            }
            Entry::Vacant(e) => {
                let mut count = state.entry_count.load(Ordering::Acquire);
                loop {
                    if count >= max_entries {
                        return false;
                    }
                    match state.entry_count.compare_exchange_weak(
                        count,
                        count + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break, // reserve a slot before physical insertion
                        Err(actual) => count = actual,
                    }
                }

                struct RollbackGuard<'a> {
                    entry_count: &'a AtomicUsize,
                    success: bool,
                }
                impl Drop for RollbackGuard<'_> {
                    fn drop(&mut self) {
                        if !self.success {
                            // Roll back the reserved slot if insertion cannot complete.
                            self.entry_count.fetch_sub(1, Ordering::Release);
                        }
                    }
                }

                let mut guard = RollbackGuard {
                    entry_count: &state.entry_count,
                    success: false,
                };

                e.insert(state.new_node(value, cache_time_ms, expire_at_ms, last_access_ms));
                guard.success = true;
                true
            }
        }
    }

    /// Replace an existing entry only if it is still the exact generation
    /// represented by `expected`.
    pub fn replace_handle(
        &self,
        key: K,
        expected: &TtlCacheHandle<V>,
        value: V,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
    ) -> bool {
        let state = self.state.load();
        let Entry::Occupied(mut entry) = state.map.entry(key) else {
            return false;
        };
        if !expected.same_node(entry.get()) {
            return false;
        }
        entry.insert(state.new_node(value, cache_time_ms, expire_at_ms, last_access_ms));
        true
    }

    /// Insert or update an entry unless a newer entry is already present.
    pub fn insert_if_not_newer(
        &self,
        key: K,
        value: V,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
    ) -> bool {
        let state = self.state.load();
        match state.map.entry(key) {
            Entry::Occupied(mut e) => {
                if e.get().cache_time_ms > cache_time_ms {
                    return false;
                }
                e.insert(state.new_node(value, cache_time_ms, expire_at_ms, last_access_ms));
                true
            }
            Entry::Vacant(e) => {
                e.insert(state.new_node(value, cache_time_ms, expire_at_ms, last_access_ms));
                state.entry_count.fetch_add(1, Ordering::Release);
                true
            }
        }
    }

    /// Insert or update an entry unless a newer entry is already present, while
    /// atomically enforcing `max_entries` for a vacant key.
    ///
    /// This is useful for rollback/restore paths: it never overwrites a newer
    /// concurrent value and never bypasses the hard cache-size limit.
    pub fn try_insert_if_not_newer_with_limit(
        &self,
        key: K,
        value: V,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
        max_entries: usize,
    ) -> TtlCacheInsertIfNotNewerResult {
        let state = self.state.load();
        match state.map.entry(key) {
            Entry::Occupied(mut e) => {
                if e.get().cache_time_ms > cache_time_ms {
                    return TtlCacheInsertIfNotNewerResult::NewerPresent;
                }
                e.insert(state.new_node(value, cache_time_ms, expire_at_ms, last_access_ms));
                TtlCacheInsertIfNotNewerResult::Inserted
            }
            Entry::Vacant(e) => {
                let mut count = state.entry_count.load(Ordering::Acquire);
                loop {
                    if count >= max_entries {
                        return TtlCacheInsertIfNotNewerResult::AtCapacity;
                    }
                    match state.entry_count.compare_exchange_weak(
                        count,
                        count + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break,
                        Err(actual) => count = actual,
                    }
                }

                struct RollbackGuard<'a> {
                    entry_count: &'a AtomicUsize,
                    success: bool,
                }
                impl Drop for RollbackGuard<'_> {
                    fn drop(&mut self) {
                        if !self.success {
                            self.entry_count.fetch_sub(1, Ordering::Release);
                        }
                    }
                }

                let mut guard = RollbackGuard {
                    entry_count: &state.entry_count,
                    success: false,
                };

                e.insert(state.new_node(value, cache_time_ms, expire_at_ms, last_access_ms));
                guard.success = true;
                TtlCacheInsertIfNotNewerResult::Inserted
            }
        }
    }

    /// Move one existing entry to a different key only when the source is still
    /// the exact generation represented by `expected`.
    ///
    /// If the target is vacant, the source is moved to the target with the
    /// supplied value and metadata. If the target already exists and is still
    /// retained, the matching source is removed atomically and the existing
    /// target is preserved. If that target is already expired, both old entries
    /// are removed and the refreshed value replaces the target atomically.
    ///
    /// The operation is bound to one cache state loaded at entry, so a
    /// concurrent [`Self::replace_with`] or [`Self::swap_retired`] cannot make
    /// a refresh that started on an old generation write into the
    /// replacement generation. Source and target shards are write-locked in
    /// stable shard order, making the identity check, target-vacancy check,
    /// removal, and insertion one conditional commit with respect to both
    /// keys.
    ///
    /// Moving an existing entry preserves cache cardinality, so capacity
    /// accounting does not need a release/reacquire cycle and concurrent
    /// bounded insertions cannot steal the source entry's slot mid-move.
    ///
    pub(crate) fn conditional_move_handle(
        &self,
        source_key: &K,
        target_key: K,
        expected: &TtlCacheHandle<V>,
        value: V,
        metadata: TtlCacheMoveMetadata,
    ) -> TtlCacheConditionalMoveResult {
        let state = self.state.load();

        if source_key == &target_key {
            return TtlCacheConditionalMoveResult::SourceChanged;
        }

        // Compute the exact 64-bit hashes used by DashMap's underlying
        // RawTable. `hash_usize()` would lose bits on 32-bit targets.
        let hash_key = |key: &K| state.map.hasher().hash_one(key);
        let source_hash = hash_key(source_key);
        let target_hash = hash_key(&target_key);
        let source_shard_index = state.map.determine_shard(source_hash as usize);
        let target_shard_index = state.map.determine_shard(target_hash as usize);
        let shards = state.map.shards();

        macro_rules! commit_same_shard {
            ($shard:expr) => {{
                let shard = &mut *$shard;

                let Some(source_bucket) = shard.find(source_hash, |(key, _)| key == source_key)
                else {
                    return TtlCacheConditionalMoveResult::SourceChanged;
                };

                let source_matches = unsafe {
                    let (_, stored) = source_bucket.as_ref();
                    expected.same_node(stored.get())
                };
                if !source_matches {
                    TtlCacheConditionalMoveResult::SourceChanged
                } else {
                    let target_expired = shard
                        .find(target_hash, |(key, _)| key == &target_key)
                        .map(|bucket| unsafe {
                            let (_, stored) = bucket.as_ref();
                            stored.get().expire_at_ms <= metadata.cache_time_ms
                        });

                    // SAFETY: `source_bucket` came from this write-locked
                    // RawTable and no mutation has happened since `find`.
                    let ((_removed_key, removed_value), _) =
                        unsafe { shard.remove(source_bucket) };
                    drop(removed_value);

                    match target_expired {
                        Some(false) => {
                            state.entry_count.fetch_sub(1, Ordering::Release);
                            TtlCacheConditionalMoveResult::Consolidated
                        }
                        Some(true) => {
                            let target_bucket = shard
                                .find(target_hash, |(key, _)| key == &target_key)
                                .expect("write-locked target disappeared during conditional move");
                            // SAFETY: the target bucket was found in this same
                            // write-locked table and no mutation followed `find`.
                            let ((_removed_key, removed_value), _) =
                                unsafe { shard.remove(target_bucket) };
                            drop(removed_value);
                            shard.insert(
                                target_hash,
                                (
                                    target_key,
                                    SharedValue::new(state.new_node(
                                        value,
                                        metadata.cache_time_ms,
                                        metadata.expire_at_ms,
                                        metadata.last_access_ms,
                                    )),
                                ),
                                |(key, _)| hash_key(key),
                            );
                            state.entry_count.fetch_sub(1, Ordering::Release);
                            TtlCacheConditionalMoveResult::ReplacedExpiredTarget
                        }
                        None => {
                            shard.insert(
                                target_hash,
                                (
                                    target_key,
                                    SharedValue::new(state.new_node(
                                        value,
                                        metadata.cache_time_ms,
                                        metadata.expire_at_ms,
                                        metadata.last_access_ms,
                                    )),
                                ),
                                |(key, _)| hash_key(key),
                            );
                            TtlCacheConditionalMoveResult::Moved
                        }
                    }
                }
            }};
        }

        macro_rules! commit_distinct_shards {
            ($source_shard:expr, $target_shard:expr) => {{
                let source_shard = &mut *$source_shard;
                let target_shard = &mut *$target_shard;

                let Some(source_bucket) =
                    source_shard.find(source_hash, |(key, _)| key == source_key)
                else {
                    return TtlCacheConditionalMoveResult::SourceChanged;
                };

                let source_matches = unsafe {
                    let (_, stored) = source_bucket.as_ref();
                    expected.same_node(stored.get())
                };
                if !source_matches {
                    TtlCacheConditionalMoveResult::SourceChanged
                } else {
                    let target_expired = target_shard
                        .find(target_hash, |(key, _)| key == &target_key)
                        .map(|bucket| unsafe {
                            let (_, stored) = bucket.as_ref();
                            stored.get().expire_at_ms <= metadata.cache_time_ms
                        });

                    // SAFETY: `source_bucket` belongs to the source shard,
                    // whose write guard remains held for the full commit.
                    let ((_removed_key, removed_value), _) =
                        unsafe { source_shard.remove(source_bucket) };
                    drop(removed_value);

                    match target_expired {
                        Some(false) => {
                            state.entry_count.fetch_sub(1, Ordering::Release);
                            TtlCacheConditionalMoveResult::Consolidated
                        }
                        Some(true) => {
                            let target_bucket = target_shard
                                .find(target_hash, |(key, _)| key == &target_key)
                                .expect("write-locked target disappeared during conditional move");
                            // SAFETY: the target bucket belongs to the target
                            // shard, whose write guard remains held.
                            let ((_removed_key, removed_value), _) =
                                unsafe { target_shard.remove(target_bucket) };
                            drop(removed_value);
                            target_shard.insert(
                                target_hash,
                                (
                                    target_key,
                                    SharedValue::new(state.new_node(
                                        value,
                                        metadata.cache_time_ms,
                                        metadata.expire_at_ms,
                                        metadata.last_access_ms,
                                    )),
                                ),
                                |(key, _)| hash_key(key),
                            );
                            state.entry_count.fetch_sub(1, Ordering::Release);
                            TtlCacheConditionalMoveResult::ReplacedExpiredTarget
                        }
                        None => {
                            target_shard.insert(
                                target_hash,
                                (
                                    target_key,
                                    SharedValue::new(state.new_node(
                                        value,
                                        metadata.cache_time_ms,
                                        metadata.expire_at_ms,
                                        metadata.last_access_ms,
                                    )),
                                ),
                                |(key, _)| hash_key(key),
                            );
                            TtlCacheConditionalMoveResult::Moved
                        }
                    }
                }
            }};
        }

        if source_shard_index == target_shard_index {
            let mut shard = shards[source_shard_index].write();
            commit_same_shard!(shard)
        } else if source_shard_index < target_shard_index {
            let mut source_shard = shards[source_shard_index].write();
            let mut target_shard = shards[target_shard_index].write();
            commit_distinct_shards!(source_shard, target_shard)
        } else {
            // Acquire lower shard index first to make cross-key moves deadlock
            // free even when two refreshes move keys in opposite directions.
            let mut target_shard = shards[target_shard_index].write();
            let mut source_shard = shards[source_shard_index].write();
            commit_distinct_shards!(source_shard, target_shard)
        }
    }

    /// Get one retained, non-expired stable handle and optionally refresh its
    /// access timestamp without reacquiring a DashMap write guard.
    ///
    /// This method only enforces the shared cache-retention deadline
    /// (`expire_at_ms`). Callers that need a fresh/stale split can apply their
    /// own semantics using the returned handle.
    #[inline]
    pub fn get_retained_handle_status(
        &self,
        key: &K,
        now_ms: u64,
        touch_interval_ms: u64,
    ) -> Option<TtlCacheHandleLookup<V>> {
        let state = self.state.load();
        loop {
            let entry = state.map.get(key)?;
            let node = entry.value().clone();
            drop(entry);

            if node.expire_at_ms <= now_ms {
                if state
                    .map
                    .remove_if(key, |_, existing| Arc::ptr_eq(existing, &node))
                    .is_some()
                {
                    state.entry_count.fetch_sub(1, Ordering::Release);
                    return Some(TtlCacheHandleLookup::Expired);
                }
                // A writer replaced the expired node after the read. Re-read
                // instead of reporting a miss for the replacement generation.
                continue;
            }

            if touch_interval_ms > 0 {
                let last_access_ms = node.last_access_ms();
                if now_ms.saturating_sub(last_access_ms) >= touch_interval_ms
                    && last_access_ms < now_ms
                {
                    node.touch_last_access(now_ms);
                }
            }

            return Some(TtlCacheHandleLookup::Hit(TtlCacheHandle { node }));
        }
    }

    /// Get one retained, non-expired stable handle.
    ///
    /// This is the common lookup for callers that do not need to distinguish a
    /// missing key from one that was just removed because it expired.
    #[inline]
    pub fn get_retained_handle(
        &self,
        key: &K,
        now_ms: u64,
        touch_interval_ms: u64,
    ) -> Option<TtlCacheHandle<V>> {
        match self.get_retained_handle_status(key, now_ms, touch_interval_ms) {
            Some(TtlCacheHandleLookup::Hit(handle)) => Some(handle),
            Some(TtlCacheHandleLookup::Expired) | None => None,
        }
    }

    /// Remove one entry only when already expired at `now_ms`.
    #[inline]
    pub fn remove_if_expired(&self, key: &K, now_ms: u64) -> bool {
        let state = self.state.load();
        let removed = state
            .map
            .remove_if(key, |_, existing| existing.expire_at_ms <= now_ms)
            .is_some();
        if removed {
            state.entry_count.fetch_sub(1, Ordering::Release);
        }
        removed
    }

    /// Remove one entry by key.
    #[inline]
    pub fn remove(&self, key: &K) -> bool {
        let state = self.state.load();
        let removed = state.map.remove(key).is_some();
        if removed {
            state.entry_count.fetch_sub(1, Ordering::Release);
        }
        removed
    }

    /// Remove one entry only if it is still the exact generation represented
    /// by `expected`.
    #[inline]
    pub fn remove_handle(&self, key: &K, expected: &TtlCacheHandle<V>) -> bool {
        let state = self.state.load();
        let removed = state
            .map
            .remove_if(key, |_, existing| expected.same_node(existing))
            .is_some();
        if removed {
            state.entry_count.fetch_sub(1, Ordering::Release);
        }
        removed
    }

    /// Remove all cached entries.
    #[inline]
    pub fn clear(&self) {
        let capacity = self.state.load().map.capacity();
        self.state
            .store(Arc::new(TtlCacheState::with_capacity(capacity)));
    }

    /// Atomically replace this cache's complete state with a prepared cache.
    ///
    /// Operations that started before this call continue against the old state
    /// and are linearized before the replacement. Later operations use the
    /// replacement state and its matching capacity accounting.
    ///
    /// This convenience method may reclaim the retired state on the caller
    /// thread. Latency-sensitive callers should use [`Self::swap_retired`].
    #[inline]
    pub fn replace_with(&self, replacement: &Self) {
        drop(self.swap_retired(replacement));
    }

    /// Atomically install a prepared cache state and return ownership of the
    /// retired state without reclaiming it on the caller thread.
    ///
    /// The returned wrapper can be sent to a dedicated reclaimer. Its
    /// `entry_count()` is an observation taken immediately after the old state
    /// is detached. Operations that obtained the old state before the swap may
    /// still finish against it, so this value is suitable for telemetry and
    /// mutation accounting but is not a quiescent/final entry count.
    #[inline]
    pub fn swap_retired(&self, replacement: &Self) -> TtlCacheRetiredState<K, V> {
        let retired = self.state.swap(replacement.state.load_full());
        let entry_count = retired.entry_count.load(Ordering::Acquire);
        TtlCacheRetiredState {
            state: retired,
            entry_count,
        }
    }
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Clone,
{
    /// Remove at most `limit` expired entries and return the removed count.
    ///
    /// The map is scanned at most once for this call. Keys are collected first
    /// so no iterator/shard read guard remains held while entries are removed.
    /// Conditional removal protects entries that are refreshed or replaced
    /// after they were observed as expired.
    fn remove_expired_up_to_from_state(
        state: &TtlCacheState<K, V>,
        now_ms: u64,
        limit: usize,
    ) -> usize {
        if limit == 0 {
            return 0;
        }

        let capacity_hint = limit.min(state.entry_count.load(Ordering::Acquire));
        let mut expired_keys = Vec::with_capacity(capacity_hint);
        for item in state.map.iter() {
            if item.value().expire_at_ms <= now_ms {
                expired_keys.push(item.key().clone());
                if expired_keys.len() >= limit {
                    break;
                }
            }
        }

        let mut removed = 0usize;
        for key in expired_keys {
            if state
                .map
                .remove_if(&key, |_, existing| existing.expire_at_ms <= now_ms)
                .is_some()
            {
                state.entry_count.fetch_sub(1, Ordering::Release);
                removed += 1;
            }
        }

        removed
    }

    /// Remove every expired entry from one detached/live state.
    ///
    /// This is intentionally O(N) and is reserved for exact/offline pruning
    /// where callers require complete expiration cleanup before enforcing a
    /// hard capacity bound. Periodic request-time maintenance must use bounded
    /// sampling instead.
    fn remove_all_expired_from_state(state: &TtlCacheState<K, V>, now_ms: u64) -> usize {
        let mut expired_keys = Vec::new();
        for item in state.map.iter() {
            if item.value().expire_at_ms <= now_ms {
                expired_keys.push(item.key().clone());
            }
        }

        let mut removed = 0usize;
        for key in expired_keys {
            if state
                .map
                .remove_if(&key, |_, existing| existing.expire_at_ms <= now_ms)
                .is_some()
            {
                state.entry_count.fetch_sub(1, Ordering::Release);
                removed += 1;
            }
        }
        removed
    }

    /// Compact an exact-pruned state when its backing hash table is much
    /// larger than the live population.
    ///
    /// Exact pruning is used for startup/API-import generations where doing
    /// one O(N) rehash off the request path is acceptable. Keeping a sparse
    /// table here would make later bounded bucket sampling unreliable because
    /// a small probe window could repeatedly miss every live bucket.
    fn compact_exact_state_if_sparse(state: &TtlCacheState<K, V>) -> bool {
        let live_entries = state.entry_count.load(Ordering::Acquire);
        let capacity = state.map.capacity();
        let compact_threshold = live_entries.saturating_mul(EXACT_COMPACT_CAPACITY_RATIO);

        if capacity == 0 || (live_entries > 0 && capacity <= compact_threshold) {
            return false;
        }

        // No DashMap guard/reference is alive here. `shrink_to_fit()` takes
        // shard write locks internally and may deadlock if called while a map
        // reference is held.
        state.map.shrink_to_fit();
        true
    }

    /// Remove at most `batch` expired entries and return removed count.
    #[inline]
    pub fn remove_expired_batch(&self, now_ms: u64, batch: usize) -> usize {
        let state = self.state.load();
        Self::remove_expired_up_to_from_state(&state, now_ms, batch)
    }

    /// Collect up to `limit` key + last-access pairs for sampled LRU eviction.
    #[inline]
    pub fn sample_last_access(&self, limit: usize) -> Vec<(K, u64)> {
        let state = self.state.load();
        Self::sample_sharded_bounded(&state, limit, |key, entry| {
            (key.clone(), entry.last_access_ms())
        })
    }

    /// Collect a bounded sample directly from DashMap shards.
    ///
    /// This deliberately avoids `DashMap::iter().skip(random_offset)`: skipping
    /// is linear in the offset and can walk half of a large map just to collect
    /// a small sample. Instead we visit shards in a random rotation and probe a
    /// bounded circular bucket window inside each shard. Sampling work is thus
    /// proportional to the requested sample size (plus the shard count), not to
    /// the total number of cache entries.
    ///
    /// Requires DashMap's `raw-api` feature because the public iterator has no
    /// API for seeking directly to a shard or bucket.
    fn sample_sharded_bounded<R>(
        state: &TtlCacheState<K, V>,
        limit: usize,
        mut project: impl FnMut(&K, &TtlCacheNode<V>) -> R,
    ) -> Vec<R> {
        const MAX_BUCKET_PROBES_PER_WANTED_ENTRY: usize = 8;

        let observed_len = state.entry_count.load(Ordering::Acquire);
        let sample_limit = limit.min(observed_len);
        if sample_limit == 0 {
            return Vec::new();
        }

        let shards = state.map.shards();
        if shards.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::rng();
        let start_shard = rng.random_range(0..shards.len());
        let mut remaining_population = observed_len;
        let mut remaining_target = sample_limit;
        let mut sample = Vec::with_capacity(sample_limit);

        for shard_step in 0..shards.len() {
            if remaining_target == 0 {
                break;
            }

            let shard_index = (start_shard + shard_step) % shards.len();
            let shard = shards[shard_index].read();
            let shard_len = shard.len();
            if shard_len == 0 {
                continue;
            }

            // Allocate the remaining sample approximately in proportion to each
            // shard's population. Saturating arithmetic also makes concurrent
            // inserts/removals harmless if `observed_len` is slightly stale.
            let wanted = if remaining_population <= shard_len {
                remaining_target.min(shard_len)
            } else {
                remaining_target
                    .saturating_mul(shard_len)
                    .saturating_add(remaining_population - 1)
                    .saturating_div(remaining_population)
                    .max(1)
                    .min(shard_len)
                    .min(remaining_target)
            };
            remaining_population = remaining_population.saturating_sub(shard_len);

            let bucket_count = shard.buckets();
            if bucket_count == 0 || wanted == 0 {
                continue;
            }

            let start_bucket = rng.random_range(0..bucket_count);
            let probe_limit = bucket_count.min(
                wanted
                    .saturating_mul(MAX_BUCKET_PROBES_PER_WANTED_ENTRY)
                    .max(wanted),
            );

            let before = sample.len();
            for bucket_step in 0..probe_limit {
                if sample.len() - before >= wanted {
                    break;
                }

                let bucket_index = (start_bucket + bucket_step) % bucket_count;

                // SAFETY: `bucket_index < bucket_count`; the shard read guard
                // remains held for the whole probe; `bucket()` is only used for
                // a bucket whose control byte says it is occupied.
                if unsafe { !shard.is_bucket_full(bucket_index) } {
                    continue;
                }
                let (key, shared_entry) = unsafe { shard.bucket(bucket_index).as_ref() };
                sample.push(project(key, shared_entry.get().as_ref()));
            }

            let collected = sample.len() - before;
            remaining_target = remaining_target.saturating_sub(collected);
        }

        sample
    }

    /// Visit cache entries through stable handles without cloning values.
    ///
    /// The callback runs while the corresponding DashMap read guard is held, so
    /// it must stay lightweight and must not call back into this cache.
    pub(crate) fn visit_handles(
        &self,
        mut visitor: impl FnMut(&K, TtlCacheHandle<V>) -> bool,
    ) {
        let state = self.state.load();
        for item in state.map.iter() {
            let handle = TtlCacheHandle {
                node: item.value().clone(),
            };
            if !visitor(item.key(), handle) {
                break;
            }
        }
    }

    /// Visit cache entries one shard at a time using stable handles.
    ///
    /// Only keys and `Arc` handles are cloned while the shard lock is held;
    /// expensive value processing can happen after the lock is released.
    pub(crate) fn visit_handles_cloned_by_shard(
        &self,
        mut visitor: impl FnMut(Vec<(K, TtlCacheHandle<V>)>) -> bool,
    ) where
        K: Clone,
    {
        let state = self.state.load();

        for shard_lock in state.map.shards() {
            let shard = shard_lock.read();
            let shard_len = shard.len();
            if shard_len == 0 {
                continue;
            }

            let mut entries = Vec::with_capacity(shard_len);
            let bucket_count = shard.buckets();
            for bucket_index in 0..bucket_count {
                // SAFETY: `bucket_index < bucket_count`; the shard read guard
                // remains held while checking and reading the bucket.
                if unsafe { !shard.is_bucket_full(bucket_index) } {
                    continue;
                }

                let (key, shared_entry) = unsafe { shard.bucket(bucket_index).as_ref() };
                entries.push((
                    key.clone(),
                    TtlCacheHandle {
                        node: shared_entry.get().clone(),
                    },
                ));
            }
            drop(shard);

            if !entries.is_empty() && !visitor(entries) {
                break;
            }
        }
    }
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Clone,
{
    /// Prune expired entries and evict according to an explicit capacity mode.
    ///
    /// `Exact` mode may scan the complete cache because callers require a hard
    /// capacity guarantee before publishing a prepared generation. `Periodic`
    /// mode is request-time maintenance and is deliberately bounded: one pass
    /// samples at most [`PERIODIC_MAINTENANCE_SAMPLE_SIZE`] entries and uses
    /// that same sample for expired-first cleanup and sampled LRU eviction.
    ///
    /// Returns `(expired_removed, evicted, after_len)`.
    pub fn prune(&self, mode: TtlCachePruneMode, now_ms: u64) -> (usize, usize, usize) {
        let state = self.state.load();

        match mode {
            TtlCachePruneMode::Exact { max_size } => {
                let expired_removed = Self::remove_all_expired_from_state(&state, now_ms);
                let current_size = state.entry_count.load(Ordering::Acquire);
                let evict_target = current_size.saturating_sub(max_size);

                let mut evicted = Self::evict_lru_sampled_internal(&state, evict_target);

                // Exact mode is used for prepared/replacement generations and
                // must actually enforce the configured capacity. Bounded
                // sampling can miss every live bucket in a sparse, previously
                // grown DashMap, so use a deterministic full-scan fallback only
                // for the remaining excess.
                let remaining_excess = state
                    .entry_count
                    .load(Ordering::Acquire)
                    .saturating_sub(max_size);
                if remaining_excess > 0 {
                    evicted = evicted.saturating_add(Self::evict_lru_exact_fallback(
                        &state,
                        remaining_excess,
                    ));
                }

                // Prepared/imported generations can temporarily grow far
                // beyond the configured size. Exact pruning removes entries
                // but hashbrown retains its bucket allocation, which can leave
                // the published map extremely sparse and make later bounded
                // periodic sampling miss live entries repeatedly. Compact only
                // when capacity is clearly disproportionate to the live set.
                Self::compact_exact_state_if_sparse(&state);

                (
                    expired_removed,
                    evicted,
                    state.entry_count.load(Ordering::Acquire),
                )
            }
            TtlCachePruneMode::Periodic {
                max_size,
                high_watermark_pct,
                low_watermark_pct,
            } => Self::prune_periodic_bounded(
                &state,
                now_ms,
                max_size,
                high_watermark_pct,
                low_watermark_pct,
            ),
        }
    }

    fn prune_periodic_bounded(
        state: &TtlCacheState<K, V>,
        now_ms: u64,
        max_size: usize,
        high_watermark_pct: usize,
        low_watermark_pct: usize,
    ) -> (usize, usize, usize) {
        let current_size = state.entry_count.load(Ordering::Acquire);
        if current_size == 0 {
            return (0, 0, 0);
        }

        // One bounded sample pays for both expiration cleanup and LRU
        // selection. This avoids an O(N) expiry sweep on every pressure pass
        // when few or no entries are expired.
        let sample_limit = PERIODIC_MAINTENANCE_SAMPLE_SIZE.min(current_size);
        let sample = Self::sample_sharded_bounded(state, sample_limit, |key, entry| {
            TtlCacheMaintenanceCandidate {
                key: key.clone(),
                expire_at_ms: entry.expire_at_ms,
                last_access_ms: entry.last_access_ms(),
                generation: entry.generation,
            }
        });

        if sample.is_empty() {
            return (0, 0, state.entry_count.load(Ordering::Acquire));
        }

        let sampled_all_entries = current_size <= PERIODIC_MAINTENANCE_SAMPLE_SIZE
            && sample.len() == current_size;
        let mut live_candidates = Vec::with_capacity(sample.len());
        let mut expired_removed = 0usize;

        for candidate in sample {
            if candidate.expire_at_ms <= now_ms {
                let removed = state
                    .map
                    .remove_if(&candidate.key, |_, existing| {
                        existing.generation == candidate.generation
                            && existing.expire_at_ms <= now_ms
                    })
                    .is_some();
                if removed {
                    state.entry_count.fetch_sub(1, Ordering::Release);
                    expired_removed += 1;
                }
            } else {
                live_candidates.push(candidate);
            }
        }

        let current_size = state.entry_count.load(Ordering::Acquire);
        let high_watermark = max_size
            .saturating_mul(high_watermark_pct)
            .saturating_div(100);
        if current_size <= high_watermark || live_candidates.is_empty() {
            return (
                expired_removed,
                0,
                state.entry_count.load(Ordering::Acquire),
            );
        }

        let low_watermark = max_size
            .saturating_mul(low_watermark_pct)
            .saturating_div(100);
        let evict_target = current_size.saturating_sub(low_watermark.min(current_size));
        if evict_target == 0 {
            return (
                expired_removed,
                0,
                state.entry_count.load(Ordering::Acquire),
            );
        }

        live_candidates.sort_unstable_by_key(|candidate| candidate.last_access_ms);

        // When the entire cache fits in one bounded sample, trimming directly
        // to the low watermark is still bounded and preserves the old behavior
        // for small caches. For larger caches, evict only the oldest fraction
        // of this sample so one maintenance pass has a fixed worst-case cost.
        let evict_limit = if sampled_all_entries {
            evict_target.min(live_candidates.len())
        } else {
            (live_candidates.len() / PERIODIC_EVICTION_SAMPLE_KILL_DIVISOR)
                .max(1)
                .min(evict_target)
        };

        let mut evicted = 0usize;
        for candidate in live_candidates.into_iter().take(evict_limit) {
            let removed = state
                .map
                .remove_if(&candidate.key, |_, existing| {
                    existing.generation == candidate.generation
                        && existing.try_claim_eviction(candidate.last_access_ms)
                })
                .is_some();
            if removed {
                state.entry_count.fetch_sub(1, Ordering::Release);
                evicted += 1;
            }
        }

        (
            expired_removed,
            evicted,
            state.entry_count.load(Ordering::Acquire),
        )
    }

    fn evict_lru_exact_fallback(state: &TtlCacheState<K, V>, target_to_kill: usize) -> usize {
        if target_to_kill == 0 {
            return 0;
        }

        // This path is intentionally O(N) and only runs when bounded sampling
        // could not satisfy Exact mode. Snapshot generation identity so a
        // replacement is never removed accidentally. A later access-time touch
        // does not invalidate the eviction decision: Exact mode prioritizes the
        // hard size bound once this fallback is required.
        let mut candidates = Vec::with_capacity(state.entry_count.load(Ordering::Acquire));
        for item in state.map.iter() {
            let entry = item.value();
            candidates.push((item.key().clone(), entry.last_access_ms(), entry.generation));
        }
        candidates
            .sort_unstable_by_key(|(_, last_access_ms, generation)| (*last_access_ms, *generation));

        let mut evicted = 0usize;
        for (key, _sampled_last_access_ms, sampled_generation) in candidates {
            if evicted >= target_to_kill {
                break;
            }
            let removed = state
                .map
                .remove_if(&key, |_, existing| {
                    existing.generation == sampled_generation
                })
                .is_some();
            if removed {
                evicted += 1;
                state.entry_count.fetch_sub(1, Ordering::Release);
            }
        }
        evicted
    }

    fn evict_lru_sampled_internal(state: &TtlCacheState<K, V>, target_to_kill: usize) -> usize {
        if target_to_kill == 0 {
            return 0;
        }

        const EVICTION_SAMPLE_SIZE: usize = 4096;
        // Only evict the oldest fraction of each sample. Keeping the candidate
        // sample independent from the remaining eviction target is what makes
        // the last-access ordering influence the selected victim set rather
        // than merely the order in which an already-selected set is removed.
        const EVICTION_SAMPLE_KILL_DIVISOR: usize = 4;

        let mut evicted_total = 0;
        while evicted_total < target_to_kill {
            // Avoid taking every DashMap shard lock just to compute the size on
            // each eviction round. The cache already maintains this count.
            let current_len = state.entry_count.load(Ordering::Acquire);
            if current_len == 0 {
                break;
            }

            // Sample size must not collapse to the number of entries still
            // needed. Otherwise target=1 samples one random entry and the LRU
            // sort below has no effect on victim selection.
            let sample_limit = EVICTION_SAMPLE_SIZE.min(current_len);

            if sample_limit == 0 {
                break;
            }

            let mut sample = Self::sample_sharded_bounded(state, sample_limit, |key, entry| {
                (key.clone(), entry.last_access_ms(), entry.generation)
            });

            if sample.is_empty() {
                break;
            }

            sample.sort_unstable_by_key(|(_, last_access_ms, _)| *last_access_ms);

            let remaining_to_kill = target_to_kill - evicted_total;
            let sample_kill_limit = (sample.len() / EVICTION_SAMPLE_KILL_DIVISOR)
                .max(1)
                .min(remaining_to_kill);

            let mut evicted_batch = 0;
            for (key, sampled_last_access_ms, sampled_generation) in
                sample.into_iter().take(sample_kill_limit)
            {
                let removed = state
                    .map
                    .remove_if(&key, |_, existing| {
                        existing.generation == sampled_generation
                            && existing.try_claim_eviction(sampled_last_access_ms)
                    })
                    .is_some();

                if removed {
                    evicted_batch += 1;
                    evicted_total += 1;
                    state.entry_count.fetch_sub(1, Ordering::Release);
                    if evicted_total >= target_to_kill {
                        break;
                    }
                }
            }

            if evicted_batch == 0 {
                break;
            }
        }

        evicted_total
    }
}

impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash,
{
    #[inline]
    pub fn entry_count(&self) -> usize {
        self.state.load().entry_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_get_and_remove_if_expired() {
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update("k", 1u32, 100, 200);

        let hit = cache
            .get_retained_handle(&"k", 150, 0)
            .expect("entry should exist");
        assert_eq!(*hit.value(), 1);

        assert!(cache.remove_if_expired(&"k", 250));
        assert!(cache.get_retained_handle(&"k", 260, 0).is_none());
    }

    #[test]
    fn stable_handle_lookup_does_not_require_clone_values() {
        #[derive(Debug)]
        struct NonClone(u32);

        let cache = TtlCache::with_capacity(1);
        cache.insert_or_update_with_meta("k", NonClone(7), 10, 100, 10);

        let handle = cache
            .get_retained_handle(&"k", 20, 0)
            .expect("entry should exist");
        assert_eq!(handle.value().0, 7);
        assert_eq!(cache.sample_last_access(1), vec![("k", 10)]);
    }

    #[test]
    fn test_try_insert_or_update_with_limit_rejects_new_entries_only() {
        let cache = TtlCache::with_capacity(2);
        assert!(cache.try_insert_or_update_with_limit("a", 1u32, 0, 100, 0, 2));
        assert!(cache.try_insert_or_update_with_limit("b", 2u32, 0, 100, 0, 2));
        assert!(!cache.try_insert_or_update_with_limit("c", 3u32, 0, 100, 0, 2));
        assert!(cache.try_insert_or_update_with_limit("a", 4u32, 0, 200, 0, 2));
        assert_eq!(cache.len(), 2);
        assert_eq!(*cache.get_retained_handle(&"a", 1, 0).unwrap().value(), 4);
    }

    #[test]
    fn test_bounded_expiry_cleanup_restores_admission_after_pressure() {
        let cache = TtlCache::with_capacity(2);
        assert!(cache.try_insert_or_update_with_limit("expired", 1u32, 0, 10, 0, 2));
        assert!(cache.try_insert_or_update_with_limit("live", 2u32, 0, 1_000, 0, 2));
        assert!(!cache.try_insert_or_update_with_limit("new", 3u32, 20, 1_000, 20, 2));

        assert_eq!(cache.remove_expired_batch(20, 1), 1);
        assert!(cache.try_insert_or_update_with_limit("new", 3u32, 20, 1_000, 20, 2));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_clear_isolated_from_inflight_removal_capacity_accounting() {
        let cache = TtlCache::with_capacity(1);
        assert!(cache.try_insert_or_update_with_limit("old", 1u32, 0, 100, 0, 1));

        let stale_state = cache.state.load_full();
        assert!(stale_state.map.remove("old").is_some());

        cache.clear();
        stale_state.entry_count.fetch_sub(1, Ordering::Release);

        assert!(cache.try_insert_or_update_with_limit("new", 2u32, 0, 100, 0, 1));
        assert_eq!(cache.len(), 1);
        assert_eq!(*cache.get_retained_handle(&"new", 1, 0).unwrap().value(), 2);
    }

    #[test]
    fn test_replace_with_swaps_complete_state_and_capacity_accounting() {
        let cache = TtlCache::with_capacity(2);
        cache.insert_or_update_with_meta("old", 1u32, 0, 100, 0);

        let replacement = TtlCache::with_capacity(1);
        assert!(replacement.try_insert_or_update_with_limit("new", 2u32, 0, 100, 0, 1));

        cache.replace_with(&replacement);

        assert!(cache.get_retained_handle(&"old", 1, 0).is_none());
        assert_eq!(*cache.get_retained_handle(&"new", 1, 0).unwrap().value(), 2);
        assert!(!cache.try_insert_or_update_with_limit("another", 3u32, 0, 100, 0, 1));
    }

    #[test]
    fn test_swap_retired_defers_final_destruction_until_reclaimed() {
        #[derive(Clone)]
        struct DropProbe(Arc<AtomicUsize>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let cache = TtlCache::with_capacity(1);
        cache.insert_or_update_with_meta("old", DropProbe(drops.clone()), 0, 100, 0);
        let replacement = TtlCache::with_capacity(1);

        let retired = cache.swap_retired(&replacement);
        assert_eq!(retired.entry_count(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert!(cache.is_empty());

        assert!(retired.try_reclaim().is_ok());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_retired_state_waits_for_outstanding_state_owner() {
        let cache = TtlCache::with_capacity(1);
        cache.insert_or_update_with_meta("old", 1u32, 0, 100, 0);

        // Model an operation that started before the swap and still owns the
        // old cache state. The reclaimer must not become the final
        // owner yet.
        let outstanding = cache.state.load_full();
        let replacement = TtlCache::with_capacity(1);
        let retired = cache.swap_retired(&replacement);

        let retired = retired
            .try_reclaim()
            .expect_err("outstanding reader must postpone reclamation");
        drop(outstanding);
        assert!(retired.try_reclaim().is_ok());
    }

    fn key_on_same_shard(cache: &TtlCache<u64, u32>, source: u64) -> u64 {
        let state = cache.state.load();
        let source_shard = state.map.determine_map(&source);
        (source + 1..)
            .find(|candidate| state.map.determine_map(candidate) == source_shard)
            .expect("a same-shard key should exist")
    }

    fn key_on_different_shard(cache: &TtlCache<u64, u32>, source: u64) -> u64 {
        let state = cache.state.load();
        let source_shard = state.map.determine_map(&source);
        (source + 1..)
            .find(|candidate| state.map.determine_map(candidate) != source_shard)
            .expect("a different-shard key should exist")
    }

    fn retained_handle(cache: &TtlCache<u64, u32>, key: &u64, now_ms: u64) -> TtlCacheHandle<u32> {
        match cache.get_retained_handle_status(key, now_ms, 0) {
            Some(TtlCacheHandleLookup::Hit(handle)) => handle,
            _ => panic!("entry should be retained"),
        }
    }

    #[test]
    fn conditional_move_same_shard_preserves_capacity_accounting() {
        let cache = TtlCache::with_capacity(4);
        let source = 1u64;
        let target = key_on_same_shard(&cache, source);
        cache.insert_or_update_with_meta(source, 10u32, 10, 100, 10);
        let expected = retained_handle(&cache, &source, 20);

        assert_eq!(
            cache.conditional_move_handle(
                &source,
                target,
                &expected,
                20u32,
                TtlCacheMoveMetadata {
                    cache_time_ms: 20,
                    expire_at_ms: 200,
                    last_access_ms: 20,
                },
            ),
            TtlCacheConditionalMoveResult::Moved
        );
        assert!(cache.get_retained_handle(&source, 20, 0).is_none());
        assert_eq!(*cache.get_retained_handle(&target, 20, 0).unwrap().value(), 20);
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn conditional_move_consolidates_existing_target_across_shards() {
        let cache = TtlCache::with_capacity(4);
        let source = 1u64;
        let target = key_on_different_shard(&cache, source);
        cache.insert_or_update_with_meta(source, 10u32, 10, 100, 10);
        cache.insert_or_update_with_meta(target, 99u32, 30, 300, 30);
        let expected = retained_handle(&cache, &source, 20);

        assert_eq!(
            cache.conditional_move_handle(
                &source,
                target,
                &expected,
                20u32,
                TtlCacheMoveMetadata {
                    cache_time_ms: 20,
                    expire_at_ms: 200,
                    last_access_ms: 20,
                },
            ),
            TtlCacheConditionalMoveResult::Consolidated
        );
        assert!(cache.get_retained_handle(&source, 20, 0).is_none());
        assert_eq!(*cache.get_retained_handle(&target, 20, 0).unwrap().value(), 99);
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn conditional_move_consolidates_existing_target_on_same_shard() {
        let cache = TtlCache::with_capacity(4);
        let source = 1u64;
        let target = key_on_same_shard(&cache, source);
        cache.insert_or_update_with_meta(source, 10u32, 10, 100, 10);
        cache.insert_or_update_with_meta(target, 99u32, 30, 300, 30);
        let expected = retained_handle(&cache, &source, 20);

        assert_eq!(
            cache.conditional_move_handle(
                &source,
                target,
                &expected,
                20u32,
                TtlCacheMoveMetadata {
                    cache_time_ms: 20,
                    expire_at_ms: 200,
                    last_access_ms: 20,
                },
            ),
            TtlCacheConditionalMoveResult::Consolidated
        );
        assert!(cache.get_retained_handle(&source, 20, 0).is_none());
        assert_eq!(*cache.get_retained_handle(&target, 20, 0).unwrap().value(), 99);
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn conditional_move_replaces_expired_target_across_shards() {
        let cache = TtlCache::with_capacity(4);
        let source = 1u64;
        let target = key_on_different_shard(&cache, source);
        cache.insert_or_update_with_meta(source, 10u32, 10, 500, 10);
        cache.insert_or_update_with_meta(target, 99u32, 10, 20, 10);
        let expected = retained_handle(&cache, &source, 15);

        assert_eq!(
            cache.conditional_move_handle(
                &source,
                target,
                &expected,
                77u32,
                TtlCacheMoveMetadata {
                    cache_time_ms: 30,
                    expire_at_ms: 300,
                    last_access_ms: 30,
                },
            ),
            TtlCacheConditionalMoveResult::ReplacedExpiredTarget
        );
        assert!(cache.get_retained_handle(&source, 30, 0).is_none());
        let target_entry = cache
            .get_retained_handle(&target, 30, 0)
            .expect("refreshed target should replace expired target");
        assert_eq!(*target_entry.value(), 77);
        assert_eq!(target_entry.expire_at_ms(), 300);
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn conditional_move_replaces_expired_target_on_same_shard() {
        let cache = TtlCache::with_capacity(4);
        let source = 1u64;
        let target = key_on_same_shard(&cache, source);
        cache.insert_or_update_with_meta(source, 10u32, 10, 500, 10);
        cache.insert_or_update_with_meta(target, 99u32, 10, 20, 10);
        let expected = retained_handle(&cache, &source, 15);

        assert_eq!(
            cache.conditional_move_handle(
                &source,
                target,
                &expected,
                77u32,
                TtlCacheMoveMetadata {
                    cache_time_ms: 30,
                    expire_at_ms: 300,
                    last_access_ms: 30,
                },
            ),
            TtlCacheConditionalMoveResult::ReplacedExpiredTarget
        );
        assert!(cache.get_retained_handle(&source, 30, 0).is_none());
        let target_entry = cache
            .get_retained_handle(&target, 30, 0)
            .expect("refreshed target should replace expired target");
        assert_eq!(*target_entry.value(), 77);
        assert_eq!(target_entry.expire_at_ms(), 300);
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn conditional_move_does_not_consolidate_when_source_changed() {
        let cache = TtlCache::with_capacity(4);
        let source = 1u64;
        let target = key_on_different_shard(&cache, source);
        cache.insert_or_update_with_meta(source, 10u32, 10, 100, 10);
        cache.insert_or_update_with_meta(target, 99u32, 30, 300, 30);
        let expected = retained_handle(&cache, &source, 20);
        cache.insert_or_update_with_meta(source, 11u32, 40, 400, 40);

        assert_eq!(
            cache.conditional_move_handle(
                &source,
                target,
                &expected,
                20u32,
                TtlCacheMoveMetadata {
                    cache_time_ms: 20,
                    expire_at_ms: 200,
                    last_access_ms: 20,
                },
            ),
            TtlCacheConditionalMoveResult::SourceChanged
        );
        assert_eq!(*cache.get_retained_handle(&source, 40, 0).unwrap().value(), 11);
        assert_eq!(*cache.get_retained_handle(&target, 40, 0).unwrap().value(), 99);
        assert_eq!(cache.entry_count(), 2);
    }

    #[test]
    fn conditional_move_rejects_handle_from_replaced_state() {
        let cache = TtlCache::with_capacity(4);
        let source = 1u64;
        let target = key_on_different_shard(&cache, source);
        cache.insert_or_update_with_meta(source, 10u32, 10, 100, 10);
        let expected = retained_handle(&cache, &source, 20);
        let replacement = TtlCache::with_capacity(4);
        cache.replace_with(&replacement);

        assert_eq!(
            cache.conditional_move_handle(
                &source,
                target,
                &expected,
                20u32,
                TtlCacheMoveMetadata {
                    cache_time_ms: 20,
                    expire_at_ms: 200,
                    last_access_ms: 20,
                },
            ),
            TtlCacheConditionalMoveResult::SourceChanged
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn replace_handle_rejects_replaced_generation() {
        let cache = TtlCache::with_capacity(1);
        cache.insert_or_update_with_meta("k", 1u32, 10, 100, 10);
        let expected = match cache.get_retained_handle_status(&"k", 20, 0) {
            Some(TtlCacheHandleLookup::Hit(handle)) => handle,
            _ => panic!("entry should exist"),
        };

        cache.insert_or_update_with_meta("k", 2u32, 20, 200, 20);
        assert!(!cache.replace_handle("k", &expected, 3, 30, 300, 30));
        assert_eq!(*cache.get_retained_handle(&"k", 20, 0).unwrap().value(), 2);

        let current = match cache.get_retained_handle_status(&"k", 20, 0) {
            Some(TtlCacheHandleLookup::Hit(handle)) => handle,
            _ => panic!("entry should exist"),
        };
        assert!(cache.replace_handle("k", &current, 3, 30, 300, 30));
        assert_eq!(*cache.get_retained_handle(&"k", 30, 0).unwrap().value(), 3);
    }

    #[test]
    fn eviction_claim_blocks_late_touch_without_exposing_marker() {
        let node = TtlCacheNode::new(1u32, 0, 100, 10, 1);

        assert!(node.try_claim_eviction(10));
        node.touch_last_access(20);
        assert_eq!(node.last_access_ms(), 10);
    }

    #[test]
    fn test_remove_expired_batch_and_sample_last_access() {
        let cache = TtlCache::with_capacity(8);
        cache.insert_or_update_with_meta("a", 1u32, 10, 20, 11);
        cache.insert_or_update_with_meta("b", 2u32, 10, 200, 12);
        cache.insert_or_update_with_meta("c", 3u32, 10, 15, 13);

        let removed = cache.remove_expired_batch(30, 10);
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 1);

        let sample = cache.sample_last_access(10);
        assert_eq!(sample.len(), 1);
        assert_eq!(sample[0].0, "b");
    }

    #[test]
    fn sharded_sample_is_bounded_and_returns_distinct_entries() {
        let cache = TtlCache::with_capacity(256);
        for key in 0u32..128 {
            cache.insert_or_update_with_meta(key, key, 10, 1_000, u64::from(key));
        }

        let sample = cache.sample_last_access(32);
        assert_eq!(sample.len(), 32);

        let mut keys: Vec<_> = sample.into_iter().map(|(key, _)| key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 32);
    }

    #[test]
    fn test_get_retained_handle_refreshes_last_access_after_touch_interval() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 100, 10);

        // Act
        let hit = cache
            .get_retained_handle(&"k", 25, 10)
            .expect("entry should exist");

        // Assert
        assert_eq!(hit.last_access_ms(), 25);
    }

    #[test]
    fn test_get_retained_handle_does_not_refresh_last_access_before_touch_interval() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 100, 10);

        // Act
        let hit = cache
            .get_retained_handle(&"k", 15, 10)
            .expect("entry should exist");

        // Assert
        assert_eq!(hit.last_access_ms(), 10);
    }

    #[test]
    fn test_get_retained_handle_removes_expired_entry() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 20, 10);

        // Act
        let hit = cache.get_retained_handle(&"k", 20, 10);

        // Assert
        assert!(hit.is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_get_retained_handle_status_reports_expired_entry() {
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 20, 10);

        let status = cache.get_retained_handle_status(&"k", 20, 10);

        assert!(matches!(status, Some(TtlCacheHandleLookup::Expired)));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_insert_or_update_replaces_existing_entry_without_growing_cache() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 20, 11);

        // Act
        cache.insert_or_update_with_meta("k", 2u32, 30, 40, 31);
        let stored = cache
            .get_retained_handle(&"k", 31, 0)
            .expect("entry should exist");

        // Assert
        assert_eq!(cache.len(), 1);
        assert_eq!(*stored.value(), 2);
        assert_eq!(stored.cache_time_ms(), 30);
        assert_eq!(stored.expire_at_ms(), 40);
        assert_eq!(stored.last_access_ms(), 31);
    }

    #[test]
    fn sampled_identity_rejects_same_timestamp_replacement() {
        let cache = TtlCache::with_capacity(1);
        cache.insert_or_update_with_meta("k", 1u32, 10, 100, 10);
        let sampled = cache
            .get_retained_handle(&"k", 10, 0)
            .expect("entry should exist");
        let sampled_last_access_ms = sampled.last_access_ms();
        let sampled_generation = sampled.node.generation;

        cache.insert_or_update_with_meta("k", 2u32, 10, 100, 10);
        let state = cache.state.load();
        assert!(
            state
                .map
                .remove_if(&"k", |_, existing| {
                    existing.last_access_ms() == sampled_last_access_ms
                        && existing.generation == sampled_generation
                })
                .is_none()
        );
        assert_eq!(*cache.get_retained_handle(&"k", 11, 0).unwrap().value(), 2);
    }

    #[test]
    fn sampled_eviction_selects_oldest_entry_when_target_is_smaller_than_sample() {
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("oldest", 1u32, 0, 1_000, 10);
        cache.insert_or_update_with_meta("warm", 2u32, 0, 1_000, 20);
        cache.insert_or_update_with_meta("hot", 3u32, 0, 1_000, 30);
        cache.insert_or_update_with_meta("hottest", 4u32, 0, 1_000, 40);

        let (_, evicted, after_len) = cache.prune(TtlCachePruneMode::Exact { max_size: 3 }, 1);

        assert_eq!(evicted, 1);
        assert_eq!(after_len, 3);
        assert!(cache.get_retained_handle(&"oldest", 1, 0).is_none());
        assert!(cache.get_retained_handle(&"warm", 1, 0).is_some());
        assert!(cache.get_retained_handle(&"hot", 1, 0).is_some());
        assert!(cache.get_retained_handle(&"hottest", 1, 0).is_some());
    }

    #[test]
    fn periodic_prune_with_full_watermarks_does_not_use_exact_trim() {
        let cache = TtlCache::with_capacity(2);
        cache.insert_or_update_with_meta("a", 1u32, 0, 100, 0);
        cache.insert_or_update_with_meta("b", 2u32, 0, 100, 0);

        let (_, evicted, after_len) = cache.prune(
            TtlCachePruneMode::Periodic {
                max_size: 2,
                high_watermark_pct: 100,
                low_watermark_pct: 100,
            },
            1,
        );

        assert_eq!(evicted, 0);
        assert_eq!(after_len, 2);
    }

    #[test]
    fn periodic_prune_bounds_lru_work_for_large_cache() {
        let cache = TtlCache::with_capacity(5_000);
        for idx in 0..5_000u64 {
            cache.insert_or_update_with_meta(idx, idx, 0, 100_000, idx);
        }

        let (expired_removed, evicted, after_len) = cache.prune(
            TtlCachePruneMode::Periodic {
                max_size: 4_096,
                high_watermark_pct: 95,
                low_watermark_pct: 85,
            },
            1,
        );

        assert_eq!(expired_removed, 0);
        assert!(evicted > 0);
        assert!(evicted <= PERIODIC_MAINTENANCE_SAMPLE_SIZE / 4);
        assert_eq!(after_len, 5_000 - evicted);
    }

    #[test]
    fn test_try_insert_if_not_newer_with_limit_respects_capacity() {
        let cache = TtlCache::with_capacity(4);
        assert!(cache.try_insert_or_update_with_limit("occupied", 1u32, 10, 100, 10, 1));

        assert_eq!(
            cache.try_insert_if_not_newer_with_limit("restore", 2u32, 5, 100, 5, 1),
            TtlCacheInsertIfNotNewerResult::AtCapacity
        );
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn test_try_insert_if_not_newer_with_limit_preserves_newer_entry() {
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 9u32, 100, 200, 100);

        assert_eq!(
            cache.try_insert_if_not_newer_with_limit("k", 1u32, 50, 150, 50, 1),
            TtlCacheInsertIfNotNewerResult::NewerPresent
        );
        assert_eq!(
            cache
                .get_retained_handle(&"k", 0, 0)
                .map(|entry| *entry.value()),
            Some(9)
        );
    }

    #[test]
    fn test_exact_prune_compacts_sparse_backing_table() {
        let cache = TtlCache::with_capacity(32_768);
        for key in 0u32..20_000 {
            cache.insert_or_update_with_meta(key, key, 0, 100_000, u64::from(key));
        }
        for key in 0u32..19_900 {
            assert!(cache.remove(&key));
        }

        let before_capacity = cache.state.load().map.capacity();
        assert!(before_capacity > cache.entry_count().saturating_mul(2));

        let (_, _, after_len) = cache.prune(TtlCachePruneMode::Exact { max_size: 10 }, 1);
        let after_capacity = cache.state.load().map.capacity();

        assert!(after_len <= 10, "Exact prune left {after_len} entries");
        assert!(cache.entry_count() <= 10);
        assert!(
            after_capacity < before_capacity,
            "Exact prune did not compact sparse table: before={before_capacity}, after={after_capacity}"
        );
    }

    #[test]
    fn periodic_prune_makes_progress_after_exact_compaction() {
        let cache = TtlCache::with_capacity(32_768);
        for key in 0u32..10_000 {
            cache.insert_or_update_with_meta(key, key, 0, 100_000, u64::from(key));
        }
        for key in 0u32..9_990 {
            assert!(cache.remove(&key));
        }

        let sparse_capacity = cache.state.load().map.capacity();
        cache.prune(TtlCachePruneMode::Exact { max_size: 10 }, 1);
        let compact_capacity = cache.state.load().map.capacity();
        assert!(compact_capacity < sparse_capacity);

        for key in 10_000u32..10_110 {
            cache.insert_or_update_with_meta(key, key, 0, 100_000, u64::from(key));
        }
        let before_len = cache.entry_count();

        let (expired_removed, evicted, after_len) = cache.prune(
            TtlCachePruneMode::Periodic {
                max_size: 100,
                high_watermark_pct: 95,
                low_watermark_pct: 85,
            },
            1,
        );

        assert_eq!(expired_removed, 0);
        assert!(evicted > 0, "periodic prune made no progress after compaction");
        assert_eq!(after_len, before_len - evicted);
    }

    #[test]
    fn test_insert_if_not_newer_preserves_live_entry() {
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 200, 300, 200);

        assert!(!cache.insert_if_not_newer("k", 2u32, 100, 150, 100));
        let stored = cache
            .get_retained_handle(&"k", 200, 0)
            .expect("entry should remain");

        assert_eq!(*stored.value(), 1);
        assert_eq!(stored.cache_time_ms(), 200);
    }
}
