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

use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use ahash::RandomState as AHashBuilder;
use arc_swap::ArcSwap;
use dashmap::{DashMap, Entry, SharedValue};
use rand::RngExt;

/// Snapshot of one cached entry with metadata.
#[derive(Debug, Clone)]
pub struct TtlCacheEntry<V> {
    /// User data stored in cache.
    pub value: V,
    /// Insert/update timestamp in milliseconds.
    pub cache_time_ms: u64,
    /// Expiration timestamp in milliseconds.
    pub expire_at_ms: u64,
    /// Last access timestamp in milliseconds.
    pub last_access_ms: u64,
    /// Monotonic identity assigned whenever this entry is replaced.
    generation: u64,
}

/// Result of a retained-entry lookup.
#[derive(Debug, Clone)]
pub enum TtlCacheLookup<V> {
    /// Entry exists and is still retained.
    Hit(TtlCacheEntry<V>),
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
    /// The source entry was missing or no longer matched the supplied identity.
    SourceChanged,
    /// The target key was already occupied, so neither entry was modified.
    TargetPresent,
}

/// Capacity policy for one background cache-pruning pass.
#[derive(Debug, Clone, Copy)]
pub enum TtlCachePruneMode {
    /// Trim only after crossing a high watermark, then target the low
    /// watermark.
    Periodic {
        max_size: usize,
        high_watermark_pct: usize,
        low_watermark_pct: usize,
    },
    /// Trim every excess entry and retain at most `max_size` entries.
    Exact { max_size: usize },
}

impl TtlCachePruneMode {
    #[inline]
    fn max_size(self) -> usize {
        match self {
            Self::Periodic { max_size, .. } | Self::Exact { max_size } => max_size,
        }
    }
}

#[derive(Debug)]
struct TtlCacheState<K, V>
where
    K: Eq + Hash,
{
    map: DashMap<K, TtlCacheEntry<V>, AHashBuilder>,
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
        match state.map.entry(key) {
            Entry::Occupied(mut e) => {
                let existing = e.get_mut();
                existing.value = value;
                existing.cache_time_ms = cache_time_ms;
                existing.expire_at_ms = expire_at_ms;
                existing.last_access_ms = last_access_ms;
                existing.generation = state.next_generation();
            }
            Entry::Vacant(e) => {
                e.insert(TtlCacheEntry {
                    value,
                    cache_time_ms,
                    expire_at_ms,
                    last_access_ms,
                    generation: state.next_generation(),
                });
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
                e.insert(TtlCacheEntry {
                    value,
                    cache_time_ms,
                    expire_at_ms,
                    last_access_ms,
                    generation: state.next_generation(),
                });
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
                        Ok(_) => break, // 预占位成功，跳出循环进入第二阶段
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
                            // 如果中途失败或被取消，将预占的名额无锁回滚
                            self.entry_count.fetch_sub(1, Ordering::Release);
                        }
                    }
                }

                let mut guard = RollbackGuard {
                    entry_count: &state.entry_count,
                    success: false,
                };

                // 执行真正的物理插入
                e.insert(TtlCacheEntry {
                    value,
                    cache_time_ms,
                    expire_at_ms,
                    last_access_ms,
                    generation: state.next_generation(),
                });

                // 物理插入成功，解除回滚守卫
                guard.success = true;
                true
            }
        }
    }

    /// Replace an existing entry only when it still matches `predicate`.
    pub fn replace_if(
        &self,
        key: K,
        value: V,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
        predicate: impl FnOnce(&TtlCacheEntry<V>) -> bool,
    ) -> bool {
        let state = self.state.load();
        let Entry::Occupied(mut entry) = state.map.entry(key) else {
            return false;
        };
        if !predicate(entry.get()) {
            return false;
        }
        entry.insert(TtlCacheEntry {
            value,
            cache_time_ms,
            expire_at_ms,
            last_access_ms,
            generation: state.next_generation(),
        });
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
                e.insert(TtlCacheEntry {
                    value,
                    cache_time_ms,
                    expire_at_ms,
                    last_access_ms,
                    generation: state.next_generation(),
                });
                true
            }
            Entry::Vacant(e) => {
                e.insert(TtlCacheEntry {
                    value,
                    cache_time_ms,
                    expire_at_ms,
                    last_access_ms,
                    generation: state.next_generation(),
                });
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
                e.insert(TtlCacheEntry {
                    value,
                    cache_time_ms,
                    expire_at_ms,
                    last_access_ms,
                    generation: state.next_generation(),
                });
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

                e.insert(TtlCacheEntry {
                    value,
                    cache_time_ms,
                    expire_at_ms,
                    last_access_ms,
                    generation: state.next_generation(),
                });
                guard.success = true;
                TtlCacheInsertIfNotNewerResult::Inserted
            }
        }
    }

    /// Move one existing entry to a different key only when the source still
    /// matches `predicate` and the target key is vacant.
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
    /// `predicate` runs while the affected shard write locks are held and must
    /// not call back into ordinary map operations on this cache.
    pub(crate) fn conditional_move_if(
        &self,
        source_key: &K,
        target_key: K,
        value: V,
        cache_time_ms: u64,
        expire_at_ms: u64,
        last_access_ms: u64,
        predicate: impl FnOnce(&TtlCacheEntry<V>) -> bool,
    ) -> TtlCacheConditionalMoveResult {
        let state = self.state.load();

        // Compute the exact 64-bit hashes used by DashMap's underlying
        // RawTable. `hash_usize()` would lose bits on 32-bit targets.
        let hash_key = |key: &K| {
            let mut hasher = state.map.hasher().build_hasher();
            key.hash(&mut hasher);
            hasher.finish()
        };
        let source_hash = hash_key(source_key);
        let target_hash = hash_key(&target_key);
        let source_shard_index = state.map.determine_shard(source_hash as usize);
        let target_shard_index = state.map.determine_shard(target_hash as usize);
        let shards = state.map.shards();

        macro_rules! commit_same_shard {
            ($shard:expr) => {{
                let shard = &mut *$shard;

                if shard
                    .find(target_hash, |(key, _)| key == &target_key)
                    .is_some()
                {
                    TtlCacheConditionalMoveResult::TargetPresent
                } else {
                    let Some(source_bucket) = shard.find(source_hash, |(key, _)| key == source_key)
                    else {
                        return TtlCacheConditionalMoveResult::SourceChanged;
                    };

                    let source_matches = unsafe {
                        let (_, stored) = source_bucket.as_ref();
                        predicate(stored.get())
                    };
                    if !source_matches {
                        TtlCacheConditionalMoveResult::SourceChanged
                    } else {
                        // SAFETY: `source_bucket` came from this write-locked
                        // RawTable and no mutation has happened since `find`.
                        let ((_removed_key, removed_value), _) =
                            unsafe { shard.remove(source_bucket) };
                        drop(removed_value);

                        shard.insert(
                            target_hash,
                            (
                                target_key,
                                SharedValue::new(TtlCacheEntry {
                                    value,
                                    cache_time_ms,
                                    expire_at_ms,
                                    last_access_ms,
                                    generation: state.next_generation(),
                                }),
                            ),
                            |(key, _)| hash_key(key),
                        );
                        TtlCacheConditionalMoveResult::Moved
                    }
                }
            }};
        }

        macro_rules! commit_distinct_shards {
            ($source_shard:expr, $target_shard:expr) => {{
                let source_shard = &mut *$source_shard;
                let target_shard = &mut *$target_shard;

                if target_shard
                    .find(target_hash, |(key, _)| key == &target_key)
                    .is_some()
                {
                    TtlCacheConditionalMoveResult::TargetPresent
                } else {
                    let Some(source_bucket) =
                        source_shard.find(source_hash, |(key, _)| key == source_key)
                    else {
                        return TtlCacheConditionalMoveResult::SourceChanged;
                    };

                    let source_matches = unsafe {
                        let (_, stored) = source_bucket.as_ref();
                        predicate(stored.get())
                    };
                    if !source_matches {
                        TtlCacheConditionalMoveResult::SourceChanged
                    } else {
                        // SAFETY: `source_bucket` belongs to the source shard,
                        // whose write guard remains held for the full commit.
                        let ((_removed_key, removed_value), _) =
                            unsafe { source_shard.remove(source_bucket) };
                        drop(removed_value);

                        target_shard.insert(
                            target_hash,
                            (
                                target_key,
                                SharedValue::new(TtlCacheEntry {
                                    value,
                                    cache_time_ms,
                                    expire_at_ms,
                                    last_access_ms,
                                    generation: state.next_generation(),
                                }),
                            ),
                            |(key, _)| hash_key(key),
                        );
                        TtlCacheConditionalMoveResult::Moved
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

    /// Get one retained, non-expired entry and optionally refresh its access
    /// timestamp.
    ///
    /// This method only enforces the shared cache-retention deadline
    /// (`expire_at_ms`). Callers that need a fresh/stale split can apply their
    /// own semantics using the returned metadata.
    #[inline]
    pub fn get_retained_cloned(
        &self,
        key: &K,
        now_ms: u64,
        touch_interval_ms: u64,
    ) -> Option<TtlCacheEntry<V>>
    where
        V: Clone,
    {
        match self.get_retained_cloned_status(key, now_ms, touch_interval_ms) {
            Some(TtlCacheLookup::Hit(entry)) => Some(entry),
            Some(TtlCacheLookup::Expired) | None => None,
        }
    }

    /// Get one retained entry and distinguish expired entries from missing
    /// keys while preserving the expired-entry removal behavior.
    #[inline]
    pub fn get_retained_cloned_status(
        &self,
        key: &K,
        now_ms: u64,
        touch_interval_ms: u64,
    ) -> Option<TtlCacheLookup<V>>
    where
        V: Clone,
    {
        let state = self.state.load();
        loop {
            let entry = state.map.get(key)?;
            if entry.expire_at_ms <= now_ms {
                drop(entry);
                if state
                    .map
                    .remove_if(key, |_, existing| existing.expire_at_ms <= now_ms)
                    .is_some()
                {
                    state.entry_count.fetch_sub(1, Ordering::Release);
                    return Some(TtlCacheLookup::Expired);
                }
                // A writer replaced the expired entry between the read and
                // conditional removal. Re-read instead of reporting a miss.
                continue;
            }

            let snapshot = TtlCacheEntry {
                value: entry.value.clone(),
                cache_time_ms: entry.cache_time_ms,
                expire_at_ms: entry.expire_at_ms,
                last_access_ms: entry.last_access_ms,
                generation: entry.generation,
            };
            drop(entry);

            if touch_interval_ms > 0
                && now_ms.saturating_sub(snapshot.last_access_ms) >= touch_interval_ms
                && let Some(mut existing) = state.map.get_mut(key)
                && existing.expire_at_ms > now_ms
                && existing.last_access_ms < now_ms
            {
                existing.last_access_ms = now_ms;
            }

            return Some(TtlCacheLookup::Hit(snapshot));
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

    /// Remove one entry only when the current entry matches `predicate`.
    #[inline]
    pub fn remove_if(&self, key: &K, predicate: impl FnOnce(&TtlCacheEntry<V>) -> bool) -> bool {
        let state = self.state.load();
        let removed = state
            .map
            .remove_if(key, |_, existing| predicate(existing))
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

    /// Remove at most `batch` expired entries and return removed count.
    #[inline]
    pub fn remove_expired_batch(&self, now_ms: u64, batch: usize) -> usize {
        let state = self.state.load();
        Self::remove_expired_up_to_from_state(&state, now_ms, batch)
    }

    /// Collect up to `limit` key + last-access pairs for sampled LRU eviction.
    #[inline]
    pub fn sample_last_access(&self, limit: usize) -> Vec<(K, u64)>
    where
        V: Clone,
    {
        self.sample_last_access_with_identity(limit)
            .into_iter()
            .map(|(key, last_access_ms, _)| (key, last_access_ms))
            .collect()
    }

    /// Collect a sample including the entry identity used for conditional
    /// eviction.
    #[inline]
    pub fn sample_last_access_with_identity(&self, limit: usize) -> Vec<(K, u64, V)>
    where
        V: Clone,
    {
        let state = self.state.load();
        Self::sample_sharded_bounded(&state, limit, |key, entry| {
            (key.clone(), entry.last_access_ms, entry.value.clone())
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
        mut project: impl FnMut(&K, &TtlCacheEntry<V>) -> R,
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
                sample.push(project(key, shared_entry.get()));
            }

            let collected = sample.len() - before;
            remaining_target = remaining_target.saturating_sub(collected);
        }

        sample
    }

    /// Visit cache entries by reference without cloning their values.
    ///
    /// The callback runs while the corresponding DashMap read guard is held, so
    /// it must stay lightweight and must not call back into this cache.
    /// Returning `false` stops traversal early.
    pub(crate) fn visit_entries(&self, mut visitor: impl FnMut(&K, &TtlCacheEntry<V>) -> bool) {
        let state = self.state.load();
        for item in state.map.iter() {
            if !visitor(item.key(), item.value()) {
                break;
            }
        }
    }

    /// Visit cache entries one shard at a time using cloned snapshots.
    ///
    /// The shard-local clone keeps expensive caller work (for example DNS
    /// message encoding during persistence) outside DashMap shard read locks,
    /// while avoiding a full-cache snapshot allocation. Returning `false` from
    /// the visitor stops traversal early.
    pub(crate) fn visit_entries_cloned_by_shard(
        &self,
        mut visitor: impl FnMut(Vec<(K, TtlCacheEntry<V>)>) -> bool,
    ) where
        K: Clone,
        V: Clone,
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
                let value = shared_entry.get();
                entries.push((
                    key.clone(),
                    TtlCacheEntry {
                        value: value.value.clone(),
                        cache_time_ms: value.cache_time_ms,
                        expire_at_ms: value.expire_at_ms,
                        last_access_ms: value.last_access_ms,
                        generation: value.generation,
                    },
                ));
            }
            drop(shard);

            if !entries.is_empty() && !visitor(entries) {
                break;
            }
        }
    }

    /// Snapshot all entries (key + metadata + cloned value).
    #[inline]
    pub fn iter_entries_cloned(&self) -> Vec<(K, TtlCacheEntry<V>)>
    where
        V: Clone,
    {
        let state = self.state.load();
        let mut entries = Vec::with_capacity(state.map.len());
        for item in state.map.iter() {
            let value = item.value();
            entries.push((
                item.key().clone(),
                TtlCacheEntry {
                    value: value.value.clone(),
                    cache_time_ms: value.cache_time_ms,
                    expire_at_ms: value.expire_at_ms,
                    last_access_ms: value.last_access_ms,
                    generation: value.generation,
                },
            ));
        }
        entries
    }
}
impl<K, V> TtlCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Prune expired entries and evict according to an explicit capacity mode.
    ///
    /// 返回值：一个三元组 `(expired_removed, evicted,
    /// after_len)`，用于上层插件打印物理日志。
    pub fn prune(&self, mode: TtlCachePruneMode, now_ms: u64) -> (usize, usize, usize) {
        let max_size = mode.max_size();

        // 1. Scan the map once and remove at most the bounded number of expired
        // entries. The previous 2K batching restarted `DashMap::iter()` for
        // every batch, so a 65K sweep could repeatedly walk the same
        // large live prefix.
        let expired_sweep_limit = max_size.clamp(8192, 65536);
        let state = self.state.load();
        let expired_removed =
            Self::remove_expired_up_to_from_state(&state, now_ms, expired_sweep_limit);

        let current_size = state.entry_count.load(Ordering::Relaxed);

        let mut evicted = 0;

        let evict_target = match mode {
            TtlCachePruneMode::Exact { .. } => current_size.saturating_sub(max_size),
            TtlCachePruneMode::Periodic {
                high_watermark_pct,
                low_watermark_pct,
                ..
            } => {
                let high_watermark = max_size
                    .saturating_mul(high_watermark_pct)
                    .saturating_div(100);
                if current_size <= high_watermark {
                    0
                } else {
                    let low_watermark = max_size
                        .saturating_mul(low_watermark_pct)
                        .saturating_div(100);
                    current_size.saturating_sub(low_watermark.min(current_size))
                }
            }
        };
        if evict_target > 0 {
            let evict_limit = match mode {
                TtlCachePruneMode::Exact { .. } | TtlCachePruneMode::Periodic { .. }
                    if max_size <= 100_000 =>
                {
                    evict_target
                }
                TtlCachePruneMode::Periodic { .. } => evict_target.min(65_536),
                TtlCachePruneMode::Exact { .. } => evict_target,
            };
            evicted = Self::evict_lru_sampled_internal(&state, evict_limit);
        }

        // Exact mode is used for prepared/replacement generations and must
        // actually enforce the configured capacity. Bounded sampling can miss
        // every live bucket in a very sparse, previously-grown DashMap, so use
        // a deterministic full-scan fallback only for the remaining
        // excess.
        if matches!(mode, TtlCachePruneMode::Exact { .. }) {
            let remaining_excess = state
                .entry_count
                .load(Ordering::Acquire)
                .saturating_sub(max_size);
            if remaining_excess > 0 {
                evicted = evicted
                    .saturating_add(Self::evict_lru_exact_fallback(&state, remaining_excess));
            }
        }

        let after_len = state.map.len();

        (expired_removed, evicted, after_len)
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
            candidates.push((item.key().clone(), entry.last_access_ms, entry.generation));
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
                (key.clone(), entry.last_access_ms, entry.generation)
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
                        existing.last_access_ms == sampled_last_access_ms
                            && existing.generation == sampled_generation
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
            .get_retained_cloned(&"k", 150, 0)
            .expect("entry should exist");
        assert_eq!(hit.value, 1);

        assert!(cache.remove_if_expired(&"k", 250));
        assert!(cache.get_retained_cloned(&"k", 260, 0).is_none());
    }

    #[test]
    fn test_try_insert_or_update_with_limit_rejects_new_entries_only() {
        let cache = TtlCache::with_capacity(2);
        assert!(cache.try_insert_or_update_with_limit("a", 1u32, 0, 100, 0, 2));
        assert!(cache.try_insert_or_update_with_limit("b", 2u32, 0, 100, 0, 2));
        assert!(!cache.try_insert_or_update_with_limit("c", 3u32, 0, 100, 0, 2));
        assert!(cache.try_insert_or_update_with_limit("a", 4u32, 0, 200, 0, 2));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get_retained_cloned(&"a", 1, 0).unwrap().value, 4);
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
        assert_eq!(cache.get_retained_cloned(&"new", 1, 0).unwrap().value, 2);
    }

    #[test]
    fn test_replace_with_swaps_complete_state_and_capacity_accounting() {
        let cache = TtlCache::with_capacity(2);
        cache.insert_or_update_with_meta("old", 1u32, 0, 100, 0);

        let replacement = TtlCache::with_capacity(1);
        assert!(replacement.try_insert_or_update_with_limit("new", 2u32, 0, 100, 0, 1));

        cache.replace_with(&replacement);

        assert!(cache.get_retained_cloned(&"old", 1, 0).is_none());
        assert_eq!(cache.get_retained_cloned(&"new", 1, 0).unwrap().value, 2);
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

    #[test]
    fn conditional_move_same_shard_preserves_capacity_accounting() {
        let cache = TtlCache::with_capacity(4);
        let source = 1u64;
        let target = key_on_same_shard(&cache, source);
        cache.insert_or_update_with_meta(source, 10u32, 10, 100, 10);

        assert_eq!(
            cache.conditional_move_if(&source, target, 20u32, 20, 200, 20, |entry| {
                entry.value == 10 && entry.cache_time_ms == 10
            }),
            TtlCacheConditionalMoveResult::Moved
        );
        assert!(cache.get_retained_cloned(&source, 20, 0).is_none());
        assert_eq!(cache.get_retained_cloned(&target, 20, 0).unwrap().value, 20);
        assert_eq!(cache.entry_count(), 1);
    }

    #[test]
    fn conditional_move_preserves_existing_target_and_source() {
        let cache = TtlCache::with_capacity(4);
        let source = 1u64;
        let target = key_on_different_shard(&cache, source);
        cache.insert_or_update_with_meta(source, 10u32, 10, 100, 10);
        cache.insert_or_update_with_meta(target, 99u32, 30, 300, 30);

        assert_eq!(
            cache.conditional_move_if(&source, target, 20u32, 20, 200, 20, |entry| {
                entry.value == 10 && entry.cache_time_ms == 10
            }),
            TtlCacheConditionalMoveResult::TargetPresent
        );
        assert_eq!(cache.get_retained_cloned(&source, 20, 0).unwrap().value, 10);
        assert_eq!(cache.get_retained_cloned(&target, 20, 0).unwrap().value, 99);
        assert_eq!(cache.entry_count(), 2);
    }

    #[test]
    fn conditional_move_stays_on_state_captured_before_replacement() {
        let cache = TtlCache::with_capacity(4);
        let source = 1u64;
        let target = key_on_different_shard(&cache, source);
        cache.insert_or_update_with_meta(source, 10u32, 10, 100, 10);
        let replacement = TtlCache::with_capacity(4);

        assert_eq!(
            cache.conditional_move_if(&source, target, 20u32, 20, 200, 20, |entry| {
                assert_eq!(entry.value, 10);
                cache.replace_with(&replacement);
                true
            }),
            TtlCacheConditionalMoveResult::Moved
        );

        // The move completed only against the state captured before the swap;
        // it cannot repopulate the newly installed generation.
        assert!(cache.is_empty());
        assert!(cache.get_retained_cloned(&source, 20, 0).is_none());
        assert!(cache.get_retained_cloned(&target, 20, 0).is_none());
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn test_replace_if_preserves_entry_when_identity_changed() {
        let cache = TtlCache::with_capacity(1);
        cache.insert_or_update_with_meta("k", 1u32, 10, 100, 10);

        cache.insert_or_update_with_meta("k", 2u32, 20, 200, 20);
        assert!(!cache.replace_if("k", 3, 30, 300, 30, |entry| {
            entry.cache_time_ms == 10 && entry.expire_at_ms == 100
        }));
        assert_eq!(cache.get_retained_cloned(&"k", 20, 0).unwrap().value, 2);

        assert!(cache.replace_if("k", 3, 30, 300, 30, |entry| {
            entry.cache_time_ms == 20 && entry.expire_at_ms == 200
        }));
        assert_eq!(cache.get_retained_cloned(&"k", 30, 0).unwrap().value, 3);
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

        let sample = cache.sample_last_access_with_identity(32);
        assert_eq!(sample.len(), 32);

        let mut keys: Vec<_> = sample.into_iter().map(|(key, _, _)| key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 32);
    }

    #[test]
    fn test_get_retained_cloned_refreshes_last_access_after_touch_interval() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 100, 10);

        // Act
        let hit = cache
            .get_retained_cloned(&"k", 25, 10)
            .expect("entry should exist");
        let (_, stored) = cache
            .iter_entries_cloned()
            .into_iter()
            .next()
            .expect("entry should remain cached");

        // Assert
        assert_eq!(hit.last_access_ms, 10);
        assert_eq!(stored.last_access_ms, 25);
    }

    #[test]
    fn test_get_retained_cloned_does_not_refresh_last_access_before_touch_interval() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 100, 10);

        // Act
        let _ = cache
            .get_retained_cloned(&"k", 15, 10)
            .expect("entry should exist");
        let (_, stored) = cache
            .iter_entries_cloned()
            .into_iter()
            .next()
            .expect("entry should remain cached");

        // Assert
        assert_eq!(stored.last_access_ms, 10);
    }

    #[test]
    fn test_get_retained_cloned_removes_expired_entry() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 20, 10);

        // Act
        let hit = cache.get_retained_cloned(&"k", 20, 10);

        // Assert
        assert!(hit.is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_get_retained_cloned_status_reports_expired_entry() {
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 20, 10);

        let status = cache.get_retained_cloned_status(&"k", 20, 10);

        assert!(matches!(status, Some(TtlCacheLookup::Expired)));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_insert_or_update_replaces_existing_entry_without_growing_cache() {
        // Arrange
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 10, 20, 11);

        // Act
        cache.insert_or_update_with_meta("k", 2u32, 30, 40, 31);
        let (_, stored) = cache
            .iter_entries_cloned()
            .into_iter()
            .next()
            .expect("entry should exist");

        // Assert
        assert_eq!(cache.len(), 1);
        assert_eq!(stored.value, 2);
        assert_eq!(stored.cache_time_ms, 30);
        assert_eq!(stored.expire_at_ms, 40);
        assert_eq!(stored.last_access_ms, 31);
    }

    #[test]
    fn sampled_identity_rejects_same_timestamp_replacement() {
        let cache = TtlCache::with_capacity(1);
        cache.insert_or_update_with_meta("k", 1u32, 10, 100, 10);
        let sampled = cache.iter_entries_cloned().pop().unwrap().1;

        cache.insert_or_update_with_meta("k", 2u32, 10, 100, 10);
        let state = cache.state.load();
        assert!(
            state
                .map
                .remove_if(&"k", |_, existing| {
                    existing.last_access_ms == sampled.last_access_ms
                        && existing.generation == sampled.generation
                })
                .is_none()
        );
        assert_eq!(cache.get_retained_cloned(&"k", 11, 0).unwrap().value, 2);
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
        assert!(cache.get_retained_cloned(&"oldest", 1, 0).is_none());
        assert!(cache.get_retained_cloned(&"warm", 1, 0).is_some());
        assert!(cache.get_retained_cloned(&"hot", 1, 0).is_some());
        assert!(cache.get_retained_cloned(&"hottest", 1, 0).is_some());
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
                .get_retained_cloned(&"k", 0, 0)
                .map(|entry| entry.value),
            Some(9)
        );
    }

    #[test]
    fn test_exact_prune_enforces_capacity_after_sparse_growth() {
        let cache = TtlCache::with_capacity(32_768);
        for key in 0u32..20_000 {
            cache.insert_or_update_with_meta(key, key, 0, 100_000, u64::from(key));
        }
        for key in 0u32..19_900 {
            assert!(cache.remove(&key));
        }

        let (_, _, after_len) = cache.prune(TtlCachePruneMode::Exact { max_size: 10 }, 1);
        assert!(after_len <= 10, "Exact prune left {after_len} entries");
        assert!(cache.entry_count() <= 10);
    }

    #[test]
    fn test_insert_if_not_newer_preserves_live_entry() {
        let cache = TtlCache::with_capacity(4);
        cache.insert_or_update_with_meta("k", 1u32, 200, 300, 200);

        assert!(!cache.insert_if_not_newer("k", 2u32, 100, 150, 100));
        let (_, stored) = cache
            .iter_entries_cloned()
            .into_iter()
            .next()
            .expect("entry should remain");

        assert_eq!(stored.value, 1);
        assert_eq!(stored.cache_time_ms, 200);
    }
}
