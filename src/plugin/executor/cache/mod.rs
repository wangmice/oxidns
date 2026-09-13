// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! DNS response cache executor plugin.
//!
//! Provides an in-memory cache keyed by normalized query name + query context
//! (qtype/qclass/DO/CD and optional ECS scope). Cache entries expire by TTL and
//! are periodically cleaned up.
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use dashmap::{DashMap, DashSet, Entry};
use serde::Deserialize;
use serde_yaml_ng::Value;
use tokio::sync::{Semaphore, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
#[cfg(feature = "api")]
use tokio::sync::OwnedSemaphorePermit;
use tracing::{Level, debug, event_enabled, warn};

use self::key::{
    CacheKey, EcsPrefixHints, build_cache_key as build_cache_key_internal,
    cache_domain_matches_name, cache_key_for_response_ecs_scope,
};
use self::persistence::{dump_cache_to_file, load_cache_from_file};
use self::store::{DnsCacheLookup, DnsCacheStore};
use crate::config::types::PluginConfig;
use crate::core::context::DnsContext;
use crate::core::response::{ResponseDisposition, classify_response};
#[cfg(feature = "api")]
use crate::infra::cache::ttl::TtlCacheRetiredState;
use crate::infra::cache::ttl::{
    TtlCache, TtlCacheConditionalMoveResult, TtlCacheHandle, TtlCacheMoveMetadata,
    TtlCachePruneMode,
};
use crate::infra::clock::AppClock;
use crate::infra::error::{DnsError, Result};
use crate::infra::observability::metrics::{
    MetricLabel, MetricSample, MetricSink, MetricSource, register_metric_source,
    unregister_metric_source,
};
use crate::infra::task as task_center;
use crate::plugin::executor::{ExecStep, Executor, ExecutorNext};
use crate::plugin::{Plugin, PluginFactory, UninitializedPlugin};
use crate::proto::{ClientSubnet, Edns, EdnsCode, EdnsOption, Message, MessageType, Opcode, RData};
use crate::{continue_next, plugin_factory};

#[cfg(feature = "api")]
mod api;
mod key;
mod persistence;
mod store;

// Default cache size.
const DEFAULT_CACHE_SIZE: usize = 1024;
// Default cleanup interval (seconds).
const DEFAULT_CLEANUP_INTERVAL: u64 = 60;
const PRESSURE_CHECK_INTERVAL: u64 = 1;
// Default dump interval (seconds).
const DEFAULT_DUMP_INTERVAL: u64 = 600;
// Minimum key updates required to trigger periodic dump.
const MINIMUM_CHANGES_TO_DUMP: u64 = 1024;
// Default fallback TTL (seconds) for NXDOMAIN/NODATA without SOA.
const DEFAULT_NEGATIVE_TTL_WITHOUT_SOA: u32 = 60;
// Default max TTL (seconds) for negative cache entries.
const DEFAULT_MAX_NEGATIVE_TTL: u32 = 300;
// Adaptive minimum intervals for updating LRU timestamp on cache hit.
const TOUCH_INTERVAL_REFRESH_MS: u64 = 1000;
const TOUCH_LOW_OCCUPANCY_PERCENT: usize = 50;
const TOUCH_MEDIUM_OCCUPANCY_PERCENT: usize = 75;
const TOUCH_HIGH_OCCUPANCY_PERCENT: usize = 90;
const TOUCH_MEDIUM_INTERVAL_MS: u64 = 30_000;
const TOUCH_HIGH_INTERVAL_MS: u64 = 5_000;
const TOUCH_CRITICAL_INTERVAL_MS: u64 = 1_000;
const SMALL_CACHE_TOUCH_SIZE: usize = 4096;
const MEDIUM_CACHE_TOUCH_SIZE: usize = 32_768;

// Cleanup tuning.
const MAX_INITIAL_CACHE_CAPACITY: usize = 16_384;
const EVICT_HIGH_WATERMARK_PERCENT: usize = 95;
const EVICT_LOW_WATERMARK_PERCENT: usize = 85;
const DEFAULT_LAZY_REFRESH_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_LAZY_REFRESH_CONCURRENCY: usize = 64;
const DEFAULT_LAZY_REFRESH_FAILURE_COOLDOWN_SECS: u64 = 30;
const DEFAULT_MISS_COALESCE_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_MISS_FLIGHT_ID: AtomicU64 = AtomicU64::new(1);
// Soft dirty-age target for low-churn caches. The effective target is never
// allowed to undercut the user-configured dump interval.
const DIRTY_DUMP_TARGET_SECS: u64 = 120;
const DIRTY_DUMP_TARGET_MS: u64 = DIRTY_DUMP_TARGET_SECS * 1000;
#[cfg(feature = "api")]
const MAX_PENDING_CACHE_RECLAIMS: usize = 1;

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
pub struct CacheConfig {
    /// Maximum number of entries allowed in the cache.
    size: Option<usize>,

    /// Optional override TTL (seconds) for newly cached responses.
    ///
    /// When set, this replaces computed positive/negative TTL.
    lazy_cache_ttl: Option<u32>,

    /// Maximum number of lazy refreshes allowed to run concurrently.
    ///
    /// Default: 64.
    lazy_refresh_concurrency: Option<usize>,

    /// Minimum retry delay (seconds) after a lazy refresh failure.
    ///
    /// Default: 30.
    lazy_refresh_failure_cooldown: Option<u64>,

    /// Optional path to persist cache contents.
    dump_file: Option<String>,

    /// Minimum interval (seconds) between automatic periodic dump checks.
    ///
    /// Shutdown and explicit API-triggered dumps are not delayed by this interval.
    dump_interval: Option<u64>,

    /// Whether to short-circuit the executor chain on cache hit.
    short_circuit: Option<bool>,

    /// Whether to cache negative responses (NXDOMAIN/NODATA).
    cache_negative: Option<bool>,

    /// Maximum TTL (seconds) for negative responses.
    max_negative_ttl: Option<u32>,

    /// Fallback TTL (seconds) when negative response has no SOA.
    ///
    /// If set to 0, negative response without SOA will not be cached.
    negative_ttl_without_soa: Option<u32>,

    /// Optional upper bound TTL (seconds) for positive responses.
    max_positive_ttl: Option<u32>,

    /// Optional lower bound TTL (seconds) for positive responses to be cached.
    min_positive_ttl: Option<u32>,

    /// Whether ECS scope is part of cache key.
    ///
    /// Default: false.
    ecs_in_key: Option<bool>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CacheLoadPolicy {
    lazy_cache_ttl: Option<u32>,
    cache_negative: bool,
    max_negative_ttl: u32,
    negative_ttl_without_soa: u32,
    max_positive_ttl: Option<u32>,
    min_positive_ttl: Option<u32>,
}

impl Default for CacheLoadPolicy {
    fn default() -> Self {
        Self {
            lazy_cache_ttl: None,
            cache_negative: true,
            max_negative_ttl: DEFAULT_MAX_NEGATIVE_TTL,
            negative_ttl_without_soa: DEFAULT_NEGATIVE_TTL_WITHOUT_SOA,
            max_positive_ttl: None,
            min_positive_ttl: None,
        }
    }
}

type CacheMap = TtlCache<CacheKey, CacheItem>;
type CacheEntryHandle = TtlCacheHandle<CacheItem>;

#[cfg(feature = "api")]
type CacheRetiredState = TtlCacheRetiredState<CacheKey, CacheItem>;

/// Dedicated retirement path for large cache states replaced by online API
/// mutations. A single permit intentionally serializes destructive replacement
/// work so prepared/current/retired cache generations cannot pile up in memory.
#[cfg(feature = "api")]
#[derive(Clone)]
pub(super) struct CacheReclaimer {
    sender: std::sync::mpsc::Sender<CacheReclaimJob>,
    slots: Arc<Semaphore>,
}

#[cfg(feature = "api")]
impl Debug for CacheReclaimer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheReclaimer")
            .field("max_pending", &MAX_PENDING_CACHE_RECLAIMS)
            .field("available_permits", &self.slots.available_permits())
            .finish()
    }
}

#[cfg(feature = "api")]
pub(super) type CacheReclaimPermit = OwnedSemaphorePermit;

#[cfg(feature = "api")]
struct CacheReclaimJob {
    retired: CacheRetiredState,
    permit: CacheReclaimPermit,
}

#[cfg(feature = "api")]
impl CacheReclaimer {
    pub(super) fn new(tag: &str) -> Result<Self> {
        let (sender, receiver) = std::sync::mpsc::channel::<CacheReclaimJob>();
        let thread_name = format!("cache-reclaimer:{tag}");

        std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    Self::reclaim_job(job);
                }
            })
            .map_err(|err| {
                DnsError::Runtime(format!("failed to start cache reclaimer thread: {err}"))
            })?;

        Ok(Self {
            sender,
            slots: Arc::new(Semaphore::new(MAX_PENDING_CACHE_RECLAIMS)),
        })
    }

    /// Reserve the one outstanding retirement slot before preparing a new cache
    /// generation. Waiting here is asynchronous and therefore provides memory
    /// backpressure without blocking a Tokio worker.
    pub(super) async fn reserve(&self) -> Result<CacheReclaimPermit> {
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DnsError::Runtime("cache reclaimer is closed".to_string()))?;
        Ok(permit)
    }

    /// Transfer a retired cache generation to the dedicated reclaimer. Sending
    /// on an unbounded std channel is non-blocking; the semaphore above bounds
    /// the number of outstanding generations instead of the channel itself.
    fn submit(&self, retired: CacheRetiredState, permit: CacheReclaimPermit) {
        let job = CacheReclaimJob { retired, permit };
        if let Err(err) = self.sender.send(job) {
            warn!("cache reclaimer thread disconnected; using blocking-pool fallback");
            let job = err.0;
            drop(tokio::task::spawn_blocking(move || Self::reclaim_job(job)));
        }
    }

    fn reclaim_job(job: CacheReclaimJob) {
        let CacheReclaimJob { retired, permit } = job;

        let reclaim_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            const MAX_RECLAIM_BACKOFF_MS: u64 = 32;

            let mut retired = retired;
            let mut backoff_ms = 1u64;
            loop {
                match retired.try_reclaim() {
                    Ok(()) => break,
                    Err(still_retired) => {
                        retired = still_retired;

                        // Cache operations normally retain state guards only
                        // briefly, so retry quickly at first. If a pre-swap
                        // reader holds the old generation for longer, back off
                        // exponentially to avoid waking this dedicated thread
                        // roughly 1000 times per second. The cap keeps reclaim
                        // latency bounded once the final reader releases.
                        std::thread::sleep(Duration::from_millis(backoff_ms));
                        backoff_ms = backoff_ms.saturating_mul(2).min(MAX_RECLAIM_BACKOFF_MS);
                    }
                }
            }
        }));

        if reclaim_result.is_err() {
            // Keep the reclaimer service alive even if an unexpected value
            // destructor panics while a retired generation is being destroyed.
            warn!("cache reclaimer caught a panic while dropping retired state");
        }

        // Releasing the permit only after reclamation (or a caught destructor
        // panic) bounds retired-generation memory, not merely queue length.
        drop(permit);
    }
}

#[derive(Debug)]
struct MissCoalescer {
    inflight: DashMap<CacheKey, Arc<MissFlight>>,
}

#[derive(Debug)]
struct MissFlight {
    id: u64,
    sender: watch::Sender<bool>,
}

impl MissCoalescer {
    fn new() -> Self {
        Self {
            inflight: DashMap::new(),
        }
    }

    fn register(&self, key: CacheKey, context: &DnsContext) -> MissRole<'_> {
        match self.inflight.entry(key.clone()) {
            Entry::Occupied(entry) => {
                let flight = entry.get();
                if context.runtime.has_miss_leader_ancestor(flight.id) {
                    MissRole::Reentrant
                } else {
                    MissRole::Follower(flight.sender.subscribe())
                }
            }
            Entry::Vacant(entry) => {
                let (sender, _receiver) = watch::channel(false);
                let flight = Arc::new(MissFlight {
                    id: NEXT_MISS_FLIGHT_ID.fetch_add(1, Ordering::Relaxed),
                    sender,
                });
                entry.insert(flight.clone());
                MissRole::Leader(MissLeader {
                    coalescer: self,
                    key,
                    flight,
                    completed: false,
                })
            }
        }
    }

    fn complete(&self, key: &CacheKey, flight: &Arc<MissFlight>, cached: bool) {
        let _ = self
            .inflight
            .remove_if(key, |_, current| Arc::ptr_eq(current, flight));
        let _ = flight.sender.send(cached);
    }
}

#[derive(Debug)]
enum MissRole<'a> {
    Leader(MissLeader<'a>),
    Follower(watch::Receiver<bool>),
    Reentrant,
}

#[derive(Debug)]
struct MissLeader<'a> {
    coalescer: &'a MissCoalescer,
    key: CacheKey,
    flight: Arc<MissFlight>,
    completed: bool,
}

impl MissLeader<'_> {
    #[inline]
    fn token(&self) -> u64 {
        self.flight.id
    }

    fn complete(mut self, cached: bool) {
        self.completed = true;
        self.coalescer.complete(&self.key, &self.flight, cached);
    }
}

impl Drop for MissLeader<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.coalescer.complete(&self.key, &self.flight, false);
        }
    }
}

#[derive(Debug)]
struct LazyRefreshGuard {
    inflight: Arc<DashSet<CacheKey>>,
    key: CacheKey,
}

impl Drop for LazyRefreshGuard {
    fn drop(&mut self) {
        self.inflight.remove(&self.key);
    }
}

#[derive(Debug)]
pub struct CacheItem {
    /// Cached DNS response message.
    resp: Message,

    /// TTL used for this cached entry (seconds).
    ttl: u32,

    /// Deadline when the response transitions from fresh to stale.
    fresh_until_ms: u64,

    /// Cache age that predates the current monotonic `cache_time_ms` epoch.
    ///
    /// Runtime entries start at zero. Persistence restore uses this offset to
    /// retain age accumulated before the current process started, so stale
    /// retention never rejuvenates across dump/restart cycles.
    cache_age_offset_ms: u64,

    /// Whether cache admission or persistence loading has already validated
    /// this response against its query key.
    validation: CacheEntryValidation,

    /// Process-local deadline before another failed lazy refresh may be retried.
    ///
    /// This is intentionally not persisted because `AppClock` uses a
    /// process-local monotonic epoch.
    lazy_refresh_retry_after_ms: AtomicU64,
}

impl Clone for CacheItem {
    fn clone(&self) -> Self {
        Self {
            resp: self.resp.clone(),
            ttl: self.ttl,
            fresh_until_ms: self.fresh_until_ms,
            cache_age_offset_ms: self.cache_age_offset_ms,
            validation: self.validation,
            lazy_refresh_retry_after_ms: AtomicU64::new(
                self.lazy_refresh_retry_after_ms.load(Ordering::Acquire),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheEntryValidation {
    Validated,
    #[cfg_attr(not(test), allow(dead_code))]
    Unknown,
}

impl CacheItem {
    #[cfg_attr(not(test), allow(dead_code))]
    fn new(resp: Message, ttl: u32, fresh_until_ms: u64) -> Self {
        Self {
            resp,
            ttl,
            fresh_until_ms,
            cache_age_offset_ms: 0,
            validation: CacheEntryValidation::Unknown,
            lazy_refresh_retry_after_ms: AtomicU64::new(0),
        }
    }

    fn new_validated(resp: Message, ttl: u32, fresh_until_ms: u64) -> Self {
        Self::new_validated_with_age_offset(resp, ttl, fresh_until_ms, 0)
    }

    fn new_validated_with_age_offset(
        resp: Message,
        ttl: u32,
        fresh_until_ms: u64,
        cache_age_offset_ms: u64,
    ) -> Self {
        Self {
            resp,
            ttl,
            fresh_until_ms,
            cache_age_offset_ms,
            validation: CacheEntryValidation::Validated,
            lazy_refresh_retry_after_ms: AtomicU64::new(0),
        }
    }

    #[inline]
    fn lazy_refresh_retry_allowed(&self, now_ms: u64) -> bool {
        now_ms >= self.lazy_refresh_retry_after_ms.load(Ordering::Acquire)
    }

    #[inline]
    fn defer_lazy_refresh(&self, now_ms: u64, cooldown_ms: u64) {
        self.lazy_refresh_retry_after_ms.store(
            now_ms.saturating_add(cooldown_ms),
            Ordering::Release,
        );
    }

    #[inline]
    fn total_cache_age_ms(&self, cache_time_ms: u64, now_elapsed_ms: u64) -> u64 {
        self.cache_age_offset_ms
            .saturating_add(now_elapsed_ms.saturating_sub(cache_time_ms))
    }

    #[inline]
    fn is_validated(&self) -> bool {
        self.validation == CacheEntryValidation::Validated
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheSkipReason {
    NoTtl,
    IncompleteAnswer,
    LowPositiveTtl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheTtlDecision {
    Cache(u32),
    Skip(CacheSkipReason),
}

#[derive(Debug)]
struct CacheMetrics {
    tag: String,
    lookup_total: AtomicU64,
    ecs_lookup_requests_total: AtomicU64,
    ecs_lookup_candidates_total: AtomicU64,
    ecs_lookup_exact_fallback_total: AtomicU64,
    fresh_hit_total: AtomicU64,
    stale_hit_total: AtomicU64,
    miss_total: AtomicU64,
    miss_coalesced_total: AtomicU64,
    miss_coalesce_timeout_total: AtomicU64,
    miss_coalesce_reentrant_total: AtomicU64,
    expired_total: AtomicU64,
    insert_total: AtomicU64,
    skip_truncated_total: AtomicU64,
    skip_no_ttl_total: AtomicU64,
    skip_incomplete_answer_total: AtomicU64,
    skip_low_positive_ttl_total: AtomicU64,
    lazy_refresh_started_total: AtomicU64,
    lazy_refresh_success_total: AtomicU64,
    lazy_refresh_failed_total: AtomicU64,
    lazy_refresh_skipped_busy_total: AtomicU64,
    lazy_refresh_skipped_cooldown_total: AtomicU64,
}

impl CacheMetrics {
    fn new(tag: String) -> Self {
        Self {
            tag,
            lookup_total: AtomicU64::new(0),
            ecs_lookup_requests_total: AtomicU64::new(0),
            ecs_lookup_candidates_total: AtomicU64::new(0),
            ecs_lookup_exact_fallback_total: AtomicU64::new(0),
            fresh_hit_total: AtomicU64::new(0),
            stale_hit_total: AtomicU64::new(0),
            miss_total: AtomicU64::new(0),
            miss_coalesced_total: AtomicU64::new(0),
            miss_coalesce_timeout_total: AtomicU64::new(0),
            miss_coalesce_reentrant_total: AtomicU64::new(0),
            expired_total: AtomicU64::new(0),
            insert_total: AtomicU64::new(0),
            skip_truncated_total: AtomicU64::new(0),
            skip_no_ttl_total: AtomicU64::new(0),
            skip_incomplete_answer_total: AtomicU64::new(0),
            skip_low_positive_ttl_total: AtomicU64::new(0),
            lazy_refresh_started_total: AtomicU64::new(0),
            lazy_refresh_success_total: AtomicU64::new(0),
            lazy_refresh_failed_total: AtomicU64::new(0),
            lazy_refresh_skipped_busy_total: AtomicU64::new(0),
            lazy_refresh_skipped_cooldown_total: AtomicU64::new(0),
        }
    }

    fn record_skip(&self, reason: CacheSkipReason) {
        match reason {
            CacheSkipReason::NoTtl => {
                self.skip_no_ttl_total.fetch_add(1, Ordering::Relaxed);
            }
            CacheSkipReason::IncompleteAnswer => {
                self.skip_incomplete_answer_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            CacheSkipReason::LowPositiveTtl => {
                self.skip_low_positive_ttl_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Debug)]
struct CacheMetricSource {
    store: DnsCacheStore,
}

impl CacheMetricSource {
    fn new(store: DnsCacheStore) -> Self {
        Self { store }
    }
}

impl MetricSource for CacheMetricSource {
    fn tag(&self) -> &str {
        self.store.metrics().tag.as_str()
    }

    fn plugin_type(&self) -> &'static str {
        "cache"
    }

    fn collect(&self, sink: &mut dyn MetricSink) {
        let metrics = self.store.metrics();
        let base = [MetricLabel::new("plugin_tag", metrics.tag.as_str())];
        sink.emit(MetricSample::counter(
            "cache_lookup_total",
            "Total cache lookups with a cacheable request key.",
            &base,
            metrics.lookup_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "cache_ecs_lookup_requests_total",
            "Total cache lookups carrying an ECS request key.",
            &base,
            metrics.ecs_lookup_requests_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "cache_ecs_lookup_candidates_total",
            "Total ECS cache key candidates probed after prefix-hint filtering.",
            &base,
            metrics.ecs_lookup_candidates_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "cache_ecs_lookup_exact_fallback_total",
            "Total ECS lookups that reached the exact-SOURCE fallback key.",
            &base,
            metrics.ecs_lookup_exact_fallback_total.load(Ordering::Relaxed),
        ));
        let ecs_v4 = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("family", "ipv4"),
        ];
        sink.emit(MetricSample::gauge(
            "cache_ecs_prefix_hint_count",
            "Number of reusable ECS scope prefixes observed by the monotonic hint bitmap.",
            &ecs_v4,
            u64::from(self.store.ecs_prefix_hints().observed_ipv4_prefixes()),
        ));
        let ecs_v6 = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("family", "ipv6"),
        ];
        sink.emit(MetricSample::gauge(
            "cache_ecs_prefix_hint_count",
            "Number of reusable ECS scope prefixes observed by the monotonic hint bitmap.",
            &ecs_v6,
            u64::from(self.store.ecs_prefix_hints().observed_ipv6_prefixes()),
        ));
        let fresh = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("kind", "fresh"),
        ];
        sink.emit(MetricSample::counter(
            "cache_hit_total",
            "Total cache hits by freshness kind.",
            &fresh,
            metrics.fresh_hit_total.load(Ordering::Relaxed),
        ));
        let stale = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("kind", "stale"),
        ];
        sink.emit(MetricSample::counter(
            "cache_hit_total",
            "Total cache hits by freshness kind.",
            &stale,
            metrics.stale_hit_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "cache_miss_total",
            "Total cache misses.",
            &base,
            metrics.miss_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "cache_miss_coalesced_total",
            "Total cache misses served by a concurrent in-flight fetch.",
            &base,
            metrics.miss_coalesced_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "cache_miss_coalesce_timeout_total",
            "Total cache miss coalescing waits that timed out.",
            &base,
            metrics.miss_coalesce_timeout_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "cache_miss_coalesce_reentrant_total",
            "Total recursive cache misses that bypassed waiting on an ancestor leader.",
            &base,
            metrics.miss_coalesce_reentrant_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "cache_expired_total",
            "Total cache lookups that found and removed expired entries.",
            &base,
            metrics.expired_total.load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::counter(
            "cache_insert_total",
            "Total cache entry inserts or updates.",
            &base,
            metrics.insert_total.load(Ordering::Relaxed),
        ));
        let skip_truncated = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("reason", "truncated"),
        ];
        sink.emit(MetricSample::counter(
            "cache_skip_total",
            "Total responses skipped by cache write policy.",
            &skip_truncated,
            metrics.skip_truncated_total.load(Ordering::Relaxed),
        ));
        let skip_no_ttl = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("reason", "no_ttl"),
        ];
        sink.emit(MetricSample::counter(
            "cache_skip_total",
            "Total responses skipped by cache write policy.",
            &skip_no_ttl,
            metrics.skip_no_ttl_total.load(Ordering::Relaxed),
        ));
        let skip_incomplete_answer = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("reason", "incomplete_answer"),
        ];
        sink.emit(MetricSample::counter(
            "cache_skip_total",
            "Total responses skipped by cache write policy.",
            &skip_incomplete_answer,
            metrics.skip_incomplete_answer_total.load(Ordering::Relaxed),
        ));
        let skip_low_positive_ttl = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("reason", "low_positive_ttl"),
        ];
        sink.emit(MetricSample::counter(
            "cache_skip_total",
            "Total responses skipped by cache write policy.",
            &skip_low_positive_ttl,
            metrics.skip_low_positive_ttl_total.load(Ordering::Relaxed),
        ));
        let lazy_started = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("result", "started"),
        ];
        sink.emit(MetricSample::counter(
            "cache_lazy_refresh_total",
            "Total lazy refresh attempts by result.",
            &lazy_started,
            metrics.lazy_refresh_started_total.load(Ordering::Relaxed),
        ));
        let lazy_success = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("result", "success"),
        ];
        sink.emit(MetricSample::counter(
            "cache_lazy_refresh_total",
            "Total lazy refresh attempts by result.",
            &lazy_success,
            metrics.lazy_refresh_success_total.load(Ordering::Relaxed),
        ));
        let lazy_failed = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("result", "failed"),
        ];
        sink.emit(MetricSample::counter(
            "cache_lazy_refresh_total",
            "Total lazy refresh attempts by result.",
            &lazy_failed,
            metrics.lazy_refresh_failed_total.load(Ordering::Relaxed),
        ));
        let lazy_skipped_busy = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("result", "skipped_busy"),
        ];
        sink.emit(MetricSample::counter(
            "cache_lazy_refresh_total",
            "Total lazy refresh attempts by result.",
            &lazy_skipped_busy,
            metrics
                .lazy_refresh_skipped_busy_total
                .load(Ordering::Relaxed),
        ));
        let lazy_skipped_cooldown = [
            MetricLabel::new("plugin_tag", metrics.tag.as_str()),
            MetricLabel::new("result", "skipped_cooldown"),
        ];
        sink.emit(MetricSample::counter(
            "cache_lazy_refresh_total",
            "Total lazy refresh attempts by result.",
            &lazy_skipped_cooldown,
            metrics
                .lazy_refresh_skipped_cooldown_total
                .load(Ordering::Relaxed),
        ));
        sink.emit(MetricSample::gauge(
            "cache_entry_count",
            "Current number of cache entries.",
            &base,
            self.store.cache_map().len() as u64,
        ));
    }
}

/// DNS response cache executor.
#[derive(Debug)]
pub struct Cache {
    /// Single live-state facade for cache data and mutation bookkeeping.
    store: DnsCacheStore,

    /// Plugin identifier.
    tag: String,

    /// Whether to cache negative responses (NXDOMAIN/NODATA).
    cache_negative: bool,

    /// Maximum TTL (seconds) for negative responses.
    max_negative_ttl: u32,

    /// Fallback TTL (seconds) when negative response has no SOA.
    ///
    /// If set to 0, negative response without SOA will not be cached.
    negative_ttl_without_soa: u32,

    /// Cache configuration parameters.
    config: CacheConfig,

    /// Whether to short-circuit the executor chain on cache hit.
    short_circuit: bool,

    /// Whether to include ECS scope in cache key.
    ecs_in_key: bool,

    /// Periodic dump task id, if dump persistence is enabled.
    dump_task_id: Mutex<Option<u64>>,

    /// Periodic cleanup task id.
    cleanup_task_id: Mutex<Option<u64>>,

    /// Deduplicates background refreshes for stale lazy cache hits.
    lazy_refresh_inflight: Arc<DashSet<CacheKey>>,

    /// Bounds concurrent lazy refreshes across distinct cache keys.
    lazy_refresh_slots: Arc<Semaphore>,

    /// Tracks all detached lazy refresh tasks so plugin teardown can await them.
    lazy_refresh_tasks: TaskTracker,

    /// Cancels in-flight lazy refreshes during plugin teardown.
    lazy_refresh_shutdown: CancellationToken,

    /// Serializes refresh admission against teardown closing the task tracker.
    lazy_refresh_accepting: Mutex<bool>,

    /// Coalesces concurrent upstream fetches for the same cache miss key.
    miss_coalescer: MissCoalescer,

    /// Cached hit-side last-access touch interval.
    touch_interval_ms: AtomicU64,

    /// Next timestamp when the hit-side touch interval may be recomputed.
    next_touch_interval_refresh_ms: AtomicU64,
}

impl Cache {
    #[inline]
    fn metrics(&self) -> &CacheMetrics {
        self.store.metrics().as_ref()
    }

    #[inline]
    fn cache_load_policy(&self) -> CacheLoadPolicy {
        CacheLoadPolicy {
            lazy_cache_ttl: self.config.lazy_cache_ttl,
            cache_negative: self.cache_negative,
            max_negative_ttl: self.max_negative_ttl,
            negative_ttl_without_soa: self.negative_ttl_without_soa,
            max_positive_ttl: self.config.max_positive_ttl,
            min_positive_ttl: self.config.min_positive_ttl,
        }
    }

    #[inline]
    fn dump_schedule(dump_interval: u64) -> (u64, u64, u64) {
        let dump_interval = dump_interval.max(1);
        let check_interval_ms = dump_interval.saturating_mul(1000);
        // `dump_interval` is a hard lower bound for periodic dumps. The
        // dirty-age target may defer low-churn dumps further, but it must
        // never shorten the user-configured interval.
        let dirty_age_target_ms = DIRTY_DUMP_TARGET_MS.max(check_interval_ms);
        (dump_interval, check_interval_ms, dirty_age_target_ms)
    }

    fn spawn_dump_task(&self, store: DnsCacheStore, dump_path: String, dump_interval: u64) -> u64 {
        let (dump_interval, check_interval_ms, dirty_age_target_ms) =
            Self::dump_schedule(dump_interval);
        task_center::spawn_fixed(
            format!("cache:{}:dump", self.tag),
            Duration::from_secs(dump_interval),
            move || {
                let store = store.clone();
                let dump_path = dump_path.clone();
                async move {
                    let Some(handoff) = store.begin_dump_if_due(
                        AppClock::elapsed_millis(),
                        MINIMUM_CHANGES_TO_DUMP,
                        dirty_age_target_ms,
                        check_interval_ms,
                    ) else {
                        return;
                    };

                    if let Err(e) = dump_cache_to_file(store.cache_map(), &dump_path).await {
                        handoff.abort();
                        warn!("Failed to dump cache to {}: {}", dump_path, e);
                    } else {
                        let _ = handoff.complete();
                    }
                }
            },
        )
    }

    fn spawn_cleanup_task(&self, store: DnsCacheStore) -> u64 {
        let cache_size = store.cache_size();
        let last_cleanup_ms = Arc::new(AtomicU64::new(0));
        let cleanup_in_progress = Arc::new(AtomicBool::new(false));
        task_center::spawn_fixed(
            format!("cache:{}:cleanup", self.tag),
            Duration::from_secs(PRESSURE_CHECK_INTERVAL),
            move || {
                let store = store.clone();
                let last_cleanup_ms = last_cleanup_ms.clone();
                let cleanup_in_progress = cleanup_in_progress.clone();
                async move {
                    let now = AppClock::elapsed_millis();
                    let pressure = store.take_pressure_requested();
                    let periodic_due = now.saturating_sub(last_cleanup_ms.load(Ordering::Acquire))
                        >= DEFAULT_CLEANUP_INTERVAL.saturating_mul(1000);
                    if !pressure && !periodic_due {
                        return;
                    }
                    if cleanup_in_progress
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        return;
                    }
                    last_cleanup_ms.store(now, Ordering::Release);
                    let prune = tokio::task::spawn_blocking(move || {
                        store.prune(
                            TtlCachePruneMode::Periodic {
                                max_size: cache_size,
                                high_watermark_pct: EVICT_HIGH_WATERMARK_PERCENT,
                                low_watermark_pct: EVICT_LOW_WATERMARK_PERCENT,
                            },
                            now,
                        )
                    })
                    .await;
                    let Ok((expired_removed, evicted, after_len)) = prune else {
                        cleanup_in_progress.store(false, Ordering::Release);
                        warn!("Cache cleanup worker failed");
                        return;
                    };
                    let total_removed = expired_removed.saturating_add(evicted);
                    if expired_removed > 0 {
                        debug!("Cleaned {} expired cache entries", expired_removed);
                    }
                    if evicted > 0 {
                        let before_len = after_len.saturating_add(total_removed);
                        warn!(
                            "LRU eviction: removed {} items, cache size {} -> {}",
                            evicted, before_len, after_len
                        );
                    }
                    cleanup_in_progress.store(false, Ordering::Release);
                }
            },
        )
    }

    #[inline]
    fn initial_cache_capacity(cache_size: usize) -> usize {
        cache_size.clamp(1, MAX_INITIAL_CACHE_CAPACITY)
    }

    fn new_store(tag: &str, cache_size: usize) -> DnsCacheStore {
        let cache_map = CacheMap::with_capacity(Self::initial_cache_capacity(cache_size));
        let ecs_prefix_hints = Arc::new(EcsPrefixHints::new());
        let metrics = Arc::new(CacheMetrics::new(tag.to_string()));
        DnsCacheStore::new(cache_map, cache_size, ecs_prefix_hints, metrics)
    }

    #[inline]
    fn adaptive_touch_interval_ms(cache_len: usize, cache_size: usize) -> u64 {
        let occupancy_percent = cache_len.saturating_mul(100) / cache_size.max(1);
        let interval = if occupancy_percent < TOUCH_LOW_OCCUPANCY_PERCENT {
            0
        } else if occupancy_percent < TOUCH_MEDIUM_OCCUPANCY_PERCENT {
            TOUCH_MEDIUM_INTERVAL_MS
        } else if occupancy_percent < TOUCH_HIGH_OCCUPANCY_PERCENT {
            TOUCH_HIGH_INTERVAL_MS
        } else {
            TOUCH_CRITICAL_INTERVAL_MS
        };

        Self::scale_touch_interval_ms(interval, cache_size)
    }

    #[inline]
    fn scale_touch_interval_ms(interval_ms: u64, cache_size: usize) -> u64 {
        if interval_ms == 0 {
            return 0;
        }

        if cache_size <= SMALL_CACHE_TOUCH_SIZE {
            return (interval_ms / 4).max(TOUCH_CRITICAL_INTERVAL_MS);
        }
        if cache_size <= MEDIUM_CACHE_TOUCH_SIZE {
            return (interval_ms / 2).max(TOUCH_CRITICAL_INTERVAL_MS);
        }

        interval_ms
    }

    #[inline]
    fn current_touch_interval_ms(&self, now: u64) -> u64 {
        let cached = self.touch_interval_ms.load(Ordering::Relaxed);
        let next_refresh = self.next_touch_interval_refresh_ms.load(Ordering::Relaxed);
        if now < next_refresh {
            return cached;
        }

        let new_next_refresh = now.saturating_add(TOUCH_INTERVAL_REFRESH_MS);
        if self
            .next_touch_interval_refresh_ms
            .compare_exchange(
                next_refresh,
                new_next_refresh,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return cached;
        }

        let interval = Self::adaptive_touch_interval_ms(
            self.store.cache_map().len(),
            self.store.cache_size(),
        );
        self.touch_interval_ms.store(interval, Ordering::Relaxed);
        interval
    }

    #[inline]
    fn build_cache_key(context: &mut DnsContext, ecs_in_key: bool) -> Option<CacheKey> {
        build_cache_key_internal(context, ecs_in_key)
    }

    #[inline]
    fn restore_cached_message(
        item: &CacheItem,
        request: &Message,
        mut response: Message,
    ) -> Message {
        response.questions_mut().clear();
        response.add_question(
            request
                .first_question()
                .cloned()
                .expect("cacheable request must contain one question"),
        );
        response.set_recursion_desired(request.recursion_desired());
        response.set_checking_disabled(request.checking_disabled());
        response.set_authentic_data(item.resp.authentic_data());
        response.set_message_type(MessageType::Response);
        response.set_opcode(Opcode::Query);
        response.signature_mut().clear();
        if let Some(request_edns) = request.edns().as_ref() {
            let mut edns = Edns::new();
            edns.set_udp_payload_size(request_edns.udp_payload_size());
            edns.set_version(request_edns.version());
            edns.flags_mut().z = request_edns.flags().z;
            edns.set_dnssec_ok(request_edns.flags().dnssec_ok);
            if let (
                Some(EdnsOption::Subnet(request_subnet)),
                Some(EdnsOption::Subnet(response_subnet)),
            ) = (
                request_edns.option(EdnsCode::Subnet),
                item.resp
                    .edns()
                    .as_ref()
                    .and_then(|response_edns| response_edns.option(EdnsCode::Subnet)),
            ) {
                edns.insert(EdnsOption::Subnet(ClientSubnet::new(
                    request_subnet.addr(),
                    request_subnet.source_prefix(),
                    response_subnet.scope_prefix(),
                )));
            }
            response.set_edns(edns);
        } else {
            response.edns_mut().take();
        }
        response
    }

    #[inline]
    fn restore_fresh_cached_message(
        item: &CacheItem,
        request: &Message,
        cache_age_ms: u64,
        remaining_ttl: u32,
    ) -> Message {
        let cache_age_secs = cache_age_ms
            .saturating_div(1000)
            .min(u64::from(u32::MAX)) as u32;
        let response = item.resp.clone_with_id_and_aged_record_ttls(
            request.id(),
            cache_age_secs,
            remaining_ttl,
        );
        Self::restore_cached_message(item, request, response)
    }

    #[inline]
    fn restore_stale_cached_message(
        item: &CacheItem,
        request: &Message,
        stale_ttl: u32,
    ) -> Message {
        let response = item
            .resp
            .clone_with_id_and_record_ttl(request.id(), stale_ttl);
        Self::restore_cached_message(item, request, response)
    }

    #[inline]
    fn stale_reply_ttl(&self, item: &CacheItem) -> u32 {
        self.config
            .lazy_cache_ttl
            .map(|ttl| ttl.min(item.ttl))
            .unwrap_or(item.ttl)
    }

    #[inline]
    fn compute_fresh_until_ms(now: u64, ttl: u32) -> u64 {
        now.saturating_add(u64::from(ttl) * 1000)
    }

    #[inline]
    fn compute_expire_time(&self, now: u64, ttl: u32, enable_lazy: bool) -> u64 {
        if enable_lazy && let Some(lazy_ttl) = self.config.lazy_cache_ttl {
            return now.saturating_add(u64::from(ttl.max(lazy_ttl)) * 1000);
        }
        Self::compute_fresh_until_ms(now, ttl)
    }

    #[inline]
    #[hotpath::measure]
    fn try_cache_hit(
        &self,
        context: &mut DnsContext,
        store: &DnsCacheStore,
    ) -> Option<DnsCacheLookup> {
        let request_key = Self::build_cache_key(context, self.ecs_in_key)?;
        let now = AppClock::elapsed_millis();
        let touch_interval_ms = self.current_touch_interval_ms(now);

        let lookup = store.lookup(
            request_key,
            now,
            touch_interval_ms,
            self.config.lazy_cache_ttl.is_some(),
        );

        match &lookup {
            DnsCacheLookup::Fresh {
                entry,
                remaining_ttl,
            } => {
                let value = entry.value();
                let cache_age_ms = value.total_cache_age_ms(entry.cache_time_ms(), now);
                let resp = Self::restore_fresh_cached_message(
                    value,
                    &context.request,
                    cache_age_ms,
                    *remaining_ttl,
                );
                context.set_response(resp);
            }
            DnsCacheLookup::Stale { entry, .. } => {
                let value = entry.value();
                let mut resp = Self::restore_stale_cached_message(
                    value,
                    &context.request,
                    self.stale_reply_ttl(value),
                );
                // AD reflects DNSSEC validation state at the time the response
                // was cached. Once an entry is stale, that assertion can no
                // longer be safely preserved (for example, its RRSIG may have
                // expired), so never serve stale data with AD set.
                resp.set_authentic_data(false);
                context.set_response(resp);
            }
            DnsCacheLookup::Miss { .. } => {}
        }

        Some(lookup)
    }

    #[inline]
    fn should_short_circuit(&self, cache_hit: bool) -> bool {
        if !cache_hit || !self.short_circuit {
            return false;
        }

        if event_enabled!(Level::DEBUG) {
            debug!("cache short-circuit hit");
        }

        true
    }

    #[inline]
    fn compute_positive_ttl_for_disposition(
        &self,
        response: &Message,
        disposition: ResponseDisposition,
    ) -> CacheTtlDecision {
        if !disposition.is_complete_positive() {
            return CacheTtlDecision::Skip(CacheSkipReason::NoTtl);
        }

        let Some(ttl) = response.min_answer_ttl() else {
            return CacheTtlDecision::Skip(CacheSkipReason::NoTtl);
        };
        let ttl = if let Some(max) = self.config.max_positive_ttl {
            ttl.min(max)
        } else {
            ttl
        };

        if ttl == 0 {
            return CacheTtlDecision::Skip(CacheSkipReason::NoTtl);
        }

        if let Some(min) = self.config.min_positive_ttl
            && ttl < min
        {
            return CacheTtlDecision::Skip(CacheSkipReason::LowPositiveTtl);
        }

        CacheTtlDecision::Cache(ttl)
    }

    #[inline]
    fn compute_negative_ttl_for_disposition(
        &self,
        response: &Message,
        key: &CacheKey,
        disposition: ResponseDisposition,
    ) -> Option<u32> {
        if !self.cache_negative {
            return None;
        }

        disposition.negative_kind()?;

        let mut ttl = if let Some(soa_ttl) = negative_ttl_from_soa_for_key(response, key) {
            soa_ttl
        } else {
            self.negative_ttl_without_soa
        };

        if let Some(answer_ttl) = min_answer_ttl_for_key(response, key) {
            ttl = ttl.min(answer_ttl);
        }
        ttl = ttl.min(self.max_negative_ttl);

        if ttl == 0 { None } else { Some(ttl) }
    }

    #[inline]
    fn compute_cache_ttl_for_disposition(
        &self,
        response: &Message,
        key: &CacheKey,
        disposition: ResponseDisposition,
    ) -> CacheTtlDecision {
        match disposition {
            ResponseDisposition::CompletePositive => {
                self.compute_positive_ttl_for_disposition(response, disposition)
            }
            ResponseDisposition::DefinitiveNegative(_) => self
                .compute_negative_ttl_for_disposition(response, key, disposition)
                .map(CacheTtlDecision::Cache)
                .unwrap_or(CacheTtlDecision::Skip(CacheSkipReason::NoTtl)),
            ResponseDisposition::IncompleteAlias => {
                CacheTtlDecision::Skip(CacheSkipReason::IncompleteAnswer)
            }
            ResponseDisposition::Other => CacheTtlDecision::Skip(CacheSkipReason::NoTtl),
        }
    }

    #[cfg(test)]
    fn compute_negative_ttl(&self, response: &Message, key: &CacheKey) -> Option<u32> {
        let disposition = response_disposition_for_cache(response, key);
        self.compute_negative_ttl_for_disposition(response, key, disposition)
    }

    #[cfg(test)]
    fn compute_cache_ttl(&self, response: &Message, key: &CacheKey) -> CacheTtlDecision {
        let disposition = response_disposition_for_cache(response, key);
        self.compute_cache_ttl_for_disposition(response, key, disposition)
    }

    #[inline]
    #[hotpath::measure]
    fn update_cache_entry(
        &self,
        store: &DnsCacheStore,
        key: CacheKey,
        response: Message,
        ttl: u32,
        disposition: ResponseDisposition,
    ) -> bool {
        let now = AppClock::elapsed_millis();
        let Some(key) = cache_key_for_response_ecs_scope(&key, &response) else {
            return false;
        };
        let fresh_until_ms = Self::compute_fresh_until_ms(now, ttl);
        let enable_lazy =
            self.config.lazy_cache_ttl.is_some() && disposition.is_complete_positive();
        let expire_time = self.compute_expire_time(now, ttl, enable_lazy);
        let item = CacheItem::new_validated(response, ttl, fresh_until_ms);
        debug!(
            "cached: domain={}, type={:?}, class={:?}, ttl={}",
            key.domain, key.record_type, key.dns_class, ttl
        );
        store.insert_or_update(key, item, now, expire_time, now)
    }

    fn try_start_lazy_refresh(
        &self,
        cache_key: &CacheKey,
        request_key: &CacheKey,
        refresh_entry: &CacheEntryHandle,
        store: &DnsCacheStore,
        context: &DnsContext,
        next: Option<&ExecutorNext>,
    ) {
        let Some(next) = next.cloned() else {
            return;
        };

        let now = AppClock::elapsed_millis();
        if !refresh_entry.value().lazy_refresh_retry_allowed(now) {
            self.metrics()
                .lazy_refresh_skipped_cooldown_total
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let refresh_permit = match self.lazy_refresh_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // Preserve per-key dedup semantics without mutating the
                // DashSet on the saturated fast path. If this key already has
                // a refresh in flight, it is a duplicate rather than a
                // global-concurrency rejection and should not count as busy.
                if !self.lazy_refresh_inflight.contains(cache_key) {
                    self.metrics()
                        .lazy_refresh_skipped_busy_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
        };

        // A duplicate can race with permit acquisition when global capacity
        // is still available. In that case the owned permit is released by
        // RAII immediately and only the existing per-key refresh continues.
        if !self.lazy_refresh_inflight.insert(cache_key.clone()) {
            return;
        }

        let refresh_guard = LazyRefreshGuard {
            inflight: self.lazy_refresh_inflight.clone(),
            key: cache_key.clone(),
        };
        let cache_key = cache_key.clone();
        let request_key = request_key.clone();
        let refresh_entry = refresh_entry.clone();
        let store = store.clone();
        let mut sub_ctx = context.copy_for_subquery();
        sub_ctx.clear_response();
        let lazy_cache_ttl = self.config.lazy_cache_ttl;
        let max_positive_ttl = self.config.max_positive_ttl;
        let min_positive_ttl = self.config.min_positive_ttl;
        let cache_negative = self.cache_negative;
        let max_negative_ttl = self.max_negative_ttl;
        let negative_ttl_without_soa = self.negative_ttl_without_soa;
        let metrics = self.store.metrics().clone();
        let shutdown = self.lazy_refresh_shutdown.clone();
        let failure_cooldown_ms = self
            .config
            .lazy_refresh_failure_cooldown
            .unwrap_or(DEFAULT_LAZY_REFRESH_FAILURE_COOLDOWN_SECS)
            .saturating_mul(1000);

        let refresh_task = async move {
            let _refresh_guard = refresh_guard;
            let _refresh_permit = refresh_permit;
            let refresh = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return,
                refresh = tokio::time::timeout(DEFAULT_LAZY_REFRESH_TIMEOUT, async {
                    let _ = next.next(&mut sub_ctx).await?;
                    Ok::<Option<Message>, DnsError>(sub_ctx.response().cloned())
                }) => refresh,
            };

            match refresh {
                Ok(Ok(Some(response))) if !response.truncated() => {
                    let (ttl, disposition) = compute_cache_ttl_with_policy(
                        &response,
                        &request_key,
                        max_positive_ttl,
                        min_positive_ttl,
                        cache_negative,
                        max_negative_ttl,
                        negative_ttl_without_soa,
                    );
                    if let CacheTtlDecision::Cache(ttl) = ttl {
                        let Some(response_key) =
                            cache_key_for_response_ecs_scope(&request_key, &response)
                        else {
                            refresh_entry.value().defer_lazy_refresh(
                                AppClock::elapsed_millis(),
                                failure_cooldown_ms,
                            );
                            metrics
                                .lazy_refresh_failed_total
                                .fetch_add(1, Ordering::Relaxed);
                            warn!(
                                "lazy cache refresh response has incompatible ECS for {}",
                                request_key.domain
                            );
                            return;
                        };
                        let now = AppClock::elapsed_millis();
                        let fresh_until_ms = Cache::compute_fresh_until_ms(now, ttl);
                        let enable_lazy =
                            lazy_cache_ttl.is_some() && disposition.is_complete_positive();
                        let expire_at_ms = if enable_lazy {
                            now.saturating_add(
                                u64::from(ttl.max(lazy_cache_ttl.unwrap_or(ttl))) * 1000,
                            )
                        } else {
                            fresh_until_ms
                        };
                        let new_item =
                            CacheItem::new_validated(response, ttl, fresh_until_ms);
                        let inserted = if response_key == cache_key {
                            store.replace_handle(
                                cache_key.clone(),
                                &refresh_entry,
                                new_item,
                                now,
                                expire_at_ms,
                                now,
                            )
                        } else {
                            matches!(
                                store.conditional_move_handle(
                                    &cache_key,
                                    response_key,
                                    &refresh_entry,
                                    new_item,
                                    TtlCacheMoveMetadata {
                                        cache_time_ms: now,
                                        expire_at_ms,
                                        last_access_ms: now,
                                    },
                                ),
                                TtlCacheConditionalMoveResult::Moved
                            )
                        };
                        if inserted {
                            metrics
                                .lazy_refresh_success_total
                                .fetch_add(1, Ordering::Relaxed);
                        } else {
                            metrics
                                .lazy_refresh_failed_total
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        if let CacheTtlDecision::Skip(reason) = ttl {
                            if reason == CacheSkipReason::LowPositiveTtl {
                                if store.remove_handle(&cache_key, &refresh_entry) {
                                    debug!(
                                        "evicted stale lazy cache entry after low positive TTL refresh: domain={}, type={:?}, class={:?}",
                                        cache_key.domain, cache_key.record_type, cache_key.dns_class
                                    );
                                }
                            } else {
                                refresh_entry.value().defer_lazy_refresh(
                                    AppClock::elapsed_millis(),
                                    failure_cooldown_ms,
                                );
                            }
                            metrics.record_skip(reason);
                        }
                        metrics
                            .lazy_refresh_failed_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(Ok(_)) => {
                    refresh_entry.value().defer_lazy_refresh(
                        AppClock::elapsed_millis(),
                        failure_cooldown_ms,
                    );
                    metrics
                        .lazy_refresh_failed_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                Ok(Err(err)) => {
                    refresh_entry.value().defer_lazy_refresh(
                        AppClock::elapsed_millis(),
                        failure_cooldown_ms,
                    );
                    metrics
                        .lazy_refresh_failed_total
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "lazy cache refresh failed for {}: {}",
                        request_key.domain, err
                    );
                }
                Err(_) => {
                    refresh_entry.value().defer_lazy_refresh(
                        AppClock::elapsed_millis(),
                        failure_cooldown_ms,
                    );
                    metrics
                        .lazy_refresh_failed_total
                        .fetch_add(1, Ordering::Relaxed);
                    warn!("lazy cache refresh timed out for {}", request_key.domain);
                }
            }
        };

        let accepting = self
            .lazy_refresh_accepting
            .lock()
            .expect("lazy_refresh_accepting poisoned");
        if !*accepting {
            return;
        }
        self.metrics()
            .lazy_refresh_started_total
            .fetch_add(1, Ordering::Relaxed);
        self.lazy_refresh_tasks.spawn(refresh_task);
        drop(accepting);
    }
}

#[async_trait]
impl Plugin for Cache {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
        if let Some(dump_file) = &self.config.dump_file {
            if let Err(e) = load_cache_from_file(
                self.store.cache_map(),
                dump_file,
                self.ecs_in_key,
                self.store.ecs_prefix_hints().clone(),
                self.cache_load_policy(),
            )
            .await
            {
                warn!("Failed to load cache from {}: {}", dump_file, e);
            } else {
                let store_for_prune = self.store.clone();
                let cache_size = self.store.cache_size();
                match tokio::task::spawn_blocking(move || {
                    store_for_prune.prune(
                        TtlCachePruneMode::Exact {
                            max_size: cache_size,
                        },
                        AppClock::elapsed_millis(),
                    )
                })
                .await
                {
                    Ok((expired_removed, evicted, after_len)) => {
                        let total_removed = expired_removed.saturating_add(evicted);
                        if total_removed > 0 {
                            let before_len = after_len.saturating_add(total_removed);
                            debug!(
                                expired_removed = expired_removed,
                                evicted = evicted,
                                before = before_len,
                                after = after_len,
                                "Pruned cache after loading dump"
                            );
                        }
                    }
                    Err(err) => warn!("Cache load prune worker failed: {}", err),
                }
            }
        }

        #[cfg(feature = "api")]
        {
            let cache_reclaimer = CacheReclaimer::new(&self.tag)?;
            api::register(
                &self.tag,
                self.store.clone(),
                api::CacheApiConfig {
                    ecs_in_key: self.ecs_in_key,
                    policy: self.cache_load_policy(),
                    cache_reclaimer,
                },
            )?;
        }
        register_metric_source(Arc::new(CacheMetricSource::new(self.store.clone())))?;

        if let Some(dump_file) = &self.config.dump_file {
            let dump_interval = self.config.dump_interval.unwrap_or(DEFAULT_DUMP_INTERVAL);
            let task_id =
                self.spawn_dump_task(self.store.clone(), dump_file.clone(), dump_interval);
            *self.dump_task_id.lock().expect("dump_task_id poisoned") = Some(task_id);
        }

        let cleanup_task_id = self.spawn_cleanup_task(self.store.clone());
        *self
            .cleanup_task_id
            .lock()
            .expect("cleanup_task_id poisoned") = Some(cleanup_task_id);
        Ok(())
    }

    async fn destroy(&self) -> Result<()> {
        unregister_metric_source(&self.tag);

        {
            let mut accepting = self
                .lazy_refresh_accepting
                .lock()
                .expect("lazy_refresh_accepting poisoned");
            *accepting = false;
            self.lazy_refresh_shutdown.cancel();
            self.lazy_refresh_tasks.close();
        }

        let dump_task_id = self
            .dump_task_id
            .lock()
            .expect("dump_task_id poisoned")
            .take();
        let cleanup_task_id = self
            .cleanup_task_id
            .lock()
            .expect("cleanup_task_id poisoned")
            .take();

        if let Some(task_id) = dump_task_id {
            task_center::stop_task(task_id).await;
        }
        if let Some(task_id) = cleanup_task_id {
            task_center::stop_task(task_id).await;
        }

        // No lazy refresh can be admitted after the gate closes above. Waiting
        // here guarantees the final dump observes every refresh mutation that
        // completed before shutdown and that no refresh can mutate afterward.
        self.lazy_refresh_tasks.wait().await;

        if let Some(dump_file) = &self.config.dump_file
            && let Err(e) = dump_cache_to_file(self.store.cache_map(), dump_file).await
        {
            warn!("Failed to dump cache to {}: {}", dump_file, e);
        }
        Ok(())
    }
}

#[async_trait]
impl Executor for Cache {
    fn with_next(&self) -> bool {
        true
    }

    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        self.execute_with_next(context, None).await
    }

    #[hotpath::measure]
    async fn execute_with_next(
        &self,
        context: &mut DnsContext,
        next: Option<ExecutorNext>,
    ) -> Result<ExecStep> {
        let store = &self.store;
        let cache_lookup = self.try_cache_hit(context, store);
        let cache_hit = cache_lookup
            .as_ref()
            .is_some_and(DnsCacheLookup::is_hit);

        if let Some(DnsCacheLookup::Stale {
            key,
            request_key,
            entry,
        }) = cache_lookup.as_ref()
        {
            self.try_start_lazy_refresh(
                key,
                request_key,
                entry,
                store,
                context,
                next.as_ref(),
            );
        }

        if self.should_short_circuit(cache_hit) {
            return Ok(ExecStep::Stop);
        }

        // Cache hit without short-circuit keeps chain running but does not
        // rewrite cache in post stage. This avoids TTL drift on repeated hits.
        if cache_hit {
            return continue_next!(next, context);
        }

        let Some(DnsCacheLookup::Miss { key }) = cache_lookup.as_ref() else {
            return continue_next!(next, context);
        };
        let key = key.clone();

        match self.miss_coalescer.register(key.clone(), context) {
            MissRole::Follower(mut ready) => {
                self.metrics()
                    .miss_coalesced_total
                    .fetch_add(1, Ordering::Relaxed);
                if tokio::time::timeout(DEFAULT_MISS_COALESCE_TIMEOUT, ready.changed())
                    .await
                    .is_err()
                {
                    self.metrics()
                        .miss_coalesce_timeout_total
                        .fetch_add(1, Ordering::Relaxed);
                }

                if ready.borrow().to_owned()
                    && self
                        .try_cache_hit(context, store)
                        .is_some_and(|lookup| lookup.is_hit())
                {
                    if self.should_short_circuit(true) {
                        return Ok(ExecStep::Stop);
                    }
                    return continue_next!(next, context);
                }

                // The leader did not produce a cacheable response. Resolve
                // this request directly instead of registering it again.
                return continue_next!(next, context);
            }
            MissRole::Reentrant => {
                self.metrics()
                    .miss_coalesce_reentrant_total
                    .fetch_add(1, Ordering::Relaxed);
                // This control flow is already inside the leader for the same
                // cache key. Waiting would deadlock until the follower timeout,
                // because that ancestor leader cannot complete before this
                // nested execution returns. Resolve downstream directly; the
                // ancestor leader remains responsible for the eventual cache
                // write and for waking independent followers.
                return continue_next!(next, context);
            }
            MissRole::Leader(leader) => {
                let previous_ancestry = context.runtime.push_miss_leader_ancestor(leader.token());
                let next_result = continue_next!(next, context);
                context
                    .runtime
                    .restore_miss_leader_ancestry(previous_ancestry);
                let next_step = next_result?;
                let cached = if let Some(response) = context.response() {
                    if response.truncated() {
                        self.metrics()
                            .skip_truncated_total
                            .fetch_add(1, Ordering::Relaxed);
                        false
                    } else {
                        let disposition = response_disposition_for_cache(response, &key);
                        match self.compute_cache_ttl_for_disposition(response, &key, disposition) {
                            CacheTtlDecision::Cache(ttl) => self.update_cache_entry(
                                store,
                                key,
                                response.clone(),
                                ttl,
                                disposition,
                            ),
                            CacheTtlDecision::Skip(reason) => {
                                self.metrics().record_skip(reason);
                                false
                            }
                        }
                    }
                } else {
                    false
                };
                leader.complete(cached);
                return Ok(next_step);
            }
        }
    }
}

fn compute_positive_ttl_with_policy(
    response: &Message,
    max_positive_ttl: Option<u32>,
    min_positive_ttl: Option<u32>,
) -> CacheTtlDecision {
    let Some(ttl) = response.min_answer_ttl() else {
        return CacheTtlDecision::Skip(CacheSkipReason::NoTtl);
    };
    let ttl = max_positive_ttl.map(|max| ttl.min(max)).unwrap_or(ttl);
    if ttl == 0 {
        return CacheTtlDecision::Skip(CacheSkipReason::NoTtl);
    }

    if let Some(min) = min_positive_ttl
        && ttl < min
    {
        return CacheTtlDecision::Skip(CacheSkipReason::LowPositiveTtl);
    }

    CacheTtlDecision::Cache(ttl)
}

fn compute_negative_ttl_with_policy(
    response: &Message,
    key: &CacheKey,
    cache_negative: bool,
    max_negative_ttl: u32,
    negative_ttl_without_soa: u32,
) -> Option<u32> {
    if !cache_negative {
        return None;
    }

    let mut ttl = negative_ttl_from_soa_for_key(response, key)
        .unwrap_or(negative_ttl_without_soa)
        .min(max_negative_ttl);
    if let Some(answer_ttl) = min_answer_ttl_for_key(response, key) {
        ttl = ttl.min(answer_ttl);
    }
    if ttl == 0 { None } else { Some(ttl) }
}

fn compute_cache_ttl_with_policy(
    response: &Message,
    key: &CacheKey,
    max_positive_ttl: Option<u32>,
    min_positive_ttl: Option<u32>,
    cache_negative: bool,
    max_negative_ttl: u32,
    negative_ttl_without_soa: u32,
) -> (CacheTtlDecision, ResponseDisposition) {
    let disposition = response_disposition_for_cache(response, key);
    let decision = match disposition {
        ResponseDisposition::CompletePositive => {
            compute_positive_ttl_with_policy(response, max_positive_ttl, min_positive_ttl)
        }
        ResponseDisposition::DefinitiveNegative(_) => {
            if let Some(ttl) = compute_negative_ttl_with_policy(
                response,
                key,
                cache_negative,
                max_negative_ttl,
                negative_ttl_without_soa,
            ) {
                CacheTtlDecision::Cache(ttl)
            } else {
                CacheTtlDecision::Skip(CacheSkipReason::NoTtl)
            }
        }
        ResponseDisposition::IncompleteAlias => {
            CacheTtlDecision::Skip(CacheSkipReason::IncompleteAnswer)
        }
        ResponseDisposition::Other => CacheTtlDecision::Skip(CacheSkipReason::NoTtl),
    };
    (decision, disposition)
}

#[inline]
fn response_disposition_for_cache(response: &Message, key: &CacheKey) -> ResponseDisposition {
    if let Some(question) = response.first_question() {
        if !cache_domain_matches_name(key.domain.as_ref(), question.name())
            || question.qtype() != key.record_type
            || question.qclass() != key.dns_class
        {
            return ResponseDisposition::Other;
        }
        return classify_response(response, Some(question));
    }

    let Some(question) = key.question() else {
        return ResponseDisposition::Other;
    };
    classify_response(response, Some(&question))
}

#[inline]
fn cache_skip_reason_for_disposition(disposition: ResponseDisposition) -> CacheSkipReason {
    match disposition {
        ResponseDisposition::IncompleteAlias => CacheSkipReason::IncompleteAnswer,
        _ => CacheSkipReason::NoTtl,
    }
}

#[inline]
fn is_cache_disposition_valid(disposition: ResponseDisposition) -> bool {
    matches!(
        disposition,
        ResponseDisposition::CompletePositive | ResponseDisposition::DefinitiveNegative(_)
    )
}

#[inline]
fn min_answer_ttl_for_key(response: &Message, key: &CacheKey) -> Option<u32> {
    response
        .answers()
        .iter()
        .filter(|record| record.class() == key.dns_class)
        .map(|record| record.ttl())
        .min()
}

#[inline]
fn negative_ttl_from_soa_for_key(response: &Message, key: &CacheKey) -> Option<u32> {
    response
        .authorities()
        .iter()
        .filter(|record| record.class() == key.dns_class)
        .filter_map(|record| match record.data() {
            RData::SOA(soa) => Some(record.ttl().min(soa.minimum())),
            _ => None,
        })
        .min()
}

fn clamp_persisted_cache_ttl(
    response: &Message,
    key: &CacheKey,
    disposition: ResponseDisposition,
    persisted_ttl: u32,
    remaining_ttl_ms: u64,
    cache_age_ms: u64,
    policy: CacheLoadPolicy,
) -> (u32, u64, u64) {
    let ttl = match disposition {
        ResponseDisposition::CompletePositive => {
            let Some(answer_ttl) = min_answer_ttl_for_key(response, key) else {
                return (0, 0, 0);
            };
            let ttl = policy
                .max_positive_ttl
                .map_or(answer_ttl, |max| answer_ttl.min(max));
            if ttl == 0 || policy.min_positive_ttl.is_some_and(|min| ttl < min) {
                return (0, 0, 0);
            }
            ttl
        }
        ResponseDisposition::DefinitiveNegative(_) => {
            if !policy.cache_negative {
                return (0, 0, 0);
            }
            let mut ttl = negative_ttl_from_soa_for_key(response, key)
                .unwrap_or(policy.negative_ttl_without_soa);
            if let Some(answer_ttl) = min_answer_ttl_for_key(response, key) {
                ttl = ttl.min(answer_ttl);
            }
            let ttl = ttl.min(policy.max_negative_ttl);
            if ttl == 0 {
                return (0, 0, 0);
            }
            ttl
        }
        _ => return (0, 0, 0),
    };

    // Never widen freshness beyond the effective TTL persisted in the dump.
    let ttl = ttl.min(persisted_ttl);
    if ttl == 0 {
        return (0, 0, 0);
    }

    let fresh_remaining_ms = remaining_ttl_ms.min(
        u64::from(ttl)
            .saturating_mul(1000)
            .saturating_sub(cache_age_ms),
    );
    let retention_limit_ms = policy
        .lazy_cache_ttl
        .map_or(u64::from(ttl), |lazy_ttl| u64::from(ttl.max(lazy_ttl)));
    let retention_remaining_ms = remaining_ttl_ms.min(
        retention_limit_ms
            .saturating_mul(1000)
            .saturating_sub(cache_age_ms),
    );
    let retention_remaining_ms = if matches!(disposition, ResponseDisposition::CompletePositive)
        && policy.lazy_cache_ttl.is_some()
    {
        retention_remaining_ms
    } else {
        fresh_remaining_ms
    };

    (ttl, fresh_remaining_ms, retention_remaining_ms)
}

fn parse_cache_config(args: Option<Value>) -> Result<CacheConfig> {
    if let Some(args) = args {
        return serde_yaml_ng::from_value::<CacheConfig>(args)
            .map_err(|e| DnsError::plugin(format!("failed to parse cache config: {}", e)));
    }

    Ok(CacheConfig {
        size: None,
        lazy_cache_ttl: None,
        lazy_refresh_concurrency: None,
        lazy_refresh_failure_cooldown: None,
        dump_file: None,
        dump_interval: None,
        short_circuit: None,
        cache_negative: None,
        max_negative_ttl: None,
        negative_ttl_without_soa: None,
        max_positive_ttl: None,
        min_positive_ttl: None,
        ecs_in_key: None,
    })
}

fn validate_cache_config(config: &CacheConfig) -> Result<()> {
    if let Some(size) = config.size
        && size == 0
    {
        return Err(DnsError::plugin("cache size must be greater than 0"));
    }

    if config.dump_file.is_some()
        && let Some(interval) = config.dump_interval
        && interval == 0
    {
        return Err(DnsError::plugin(
            "cache dump_interval must be greater than 0 when dump_file is set",
        ));
    }

    if let Some(ttl) = config.lazy_cache_ttl
        && ttl == 0
    {
        return Err(DnsError::plugin(
            "cache lazy_cache_ttl must be greater than 0",
        ));
    }

    if let Some(concurrency) = config.lazy_refresh_concurrency
        && concurrency == 0
    {
        return Err(DnsError::plugin(
            "cache lazy_refresh_concurrency must be greater than 0",
        ));
    }

    if let Some(cooldown) = config.lazy_refresh_failure_cooldown
        && cooldown == 0
    {
        return Err(DnsError::plugin(
            "cache lazy_refresh_failure_cooldown must be greater than 0",
        ));
    }

    if let Some(ttl) = config.max_negative_ttl
        && ttl == 0
    {
        return Err(DnsError::plugin(
            "cache max_negative_ttl must be greater than 0",
        ));
    }

    if let Some(ttl) = config.max_positive_ttl
        && ttl == 0
    {
        return Err(DnsError::plugin(
            "cache max_positive_ttl must be greater than 0",
        ));
    }

    if let Some(ttl) = config.min_positive_ttl
        && ttl == 0
    {
        return Err(DnsError::plugin(
            "cache min_positive_ttl must be greater than 0",
        ));
    }

    if let (Some(min), Some(max)) = (config.min_positive_ttl, config.max_positive_ttl)
        && min > max
    {
        return Err(DnsError::plugin(
            "cache min_positive_ttl must be less than or equal to max_positive_ttl",
        ));
    }

    Ok(())
}

/// Factory for creating cache executor plugins.
#[derive(Debug)]
#[plugin_factory("cache")]
pub struct CacheFactory;

impl PluginFactory for CacheFactory {
    fn create(
        &self,
        plugin_config: &PluginConfig,
        _init_context: &crate::plugin::PluginInitContext<'_>,
    ) -> Result<UninitializedPlugin> {
        let cache_config = parse_cache_config(plugin_config.args.clone())?;
        validate_cache_config(&cache_config)?;
        self.build_cache(plugin_config.tag.clone(), cache_config)
    }

    fn quick_setup(&self, tag: &str, param: Option<String>) -> Result<UninitializedPlugin> {
        let cache_config = parse_cache_quick_setup(param.as_deref().unwrap_or_default())?;
        validate_cache_config(&cache_config)?;
        self.build_cache(tag.to_string(), cache_config)
    }
}

impl CacheFactory {
    fn build_cache(&self, tag: String, cache_config: CacheConfig) -> Result<UninitializedPlugin> {
        let cache_size = cache_config.size.unwrap_or(DEFAULT_CACHE_SIZE);
        let lazy_refresh_concurrency = cache_config
            .lazy_refresh_concurrency
            .unwrap_or(DEFAULT_LAZY_REFRESH_CONCURRENCY);
        let store = Cache::new_store(&tag, cache_size);
        Ok(UninitializedPlugin::Executor(Box::new(Cache {
            store,
            tag,
            cache_negative: cache_config.cache_negative.unwrap_or(true),
            max_negative_ttl: cache_config
                .max_negative_ttl
                .unwrap_or(DEFAULT_MAX_NEGATIVE_TTL),
            negative_ttl_without_soa: cache_config
                .negative_ttl_without_soa
                .unwrap_or(DEFAULT_NEGATIVE_TTL_WITHOUT_SOA),
            short_circuit: cache_config.short_circuit.unwrap_or(false),
            ecs_in_key: cache_config.ecs_in_key.unwrap_or(false),
            config: cache_config,
            dump_task_id: Mutex::new(None),
            cleanup_task_id: Mutex::new(None),
            lazy_refresh_inflight: Arc::new(DashSet::new()),
            lazy_refresh_slots: Arc::new(Semaphore::new(lazy_refresh_concurrency)),
            lazy_refresh_tasks: TaskTracker::new(),
            lazy_refresh_shutdown: CancellationToken::new(),
            lazy_refresh_accepting: Mutex::new(true),
            miss_coalescer: MissCoalescer::new(),
            touch_interval_ms: AtomicU64::new(0),
            next_touch_interval_refresh_ms: AtomicU64::new(0),
        })))
    }
}

fn parse_cache_quick_setup(raw: &str) -> Result<CacheConfig> {
    let mut config = CacheConfig {
        size: None,
        lazy_cache_ttl: None,
        lazy_refresh_concurrency: None,
        lazy_refresh_failure_cooldown: None,
        dump_file: None,
        dump_interval: None,
        short_circuit: None,
        cache_negative: None,
        max_negative_ttl: None,
        negative_ttl_without_soa: None,
        max_positive_ttl: None,
        min_positive_ttl: None,
        ecs_in_key: None,
    };

    for token in raw.split_whitespace() {
        if token == "short_circuit" {
            config.short_circuit = Some(true);
            continue;
        }

        let Some(value) = token.strip_prefix("short_circuit=") else {
            return Err(DnsError::plugin(format!(
                "unsupported cache quick setup token '{}'",
                token
            )));
        };

        config.short_circuit = Some(match value {
            "true" => true,
            "false" => false,
            _ => {
                return Err(DnsError::plugin(format!(
                    "invalid short_circuit value '{}', expected true or false",
                    value
                )));
            }
        });
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use async_trait::async_trait;

    use super::*;
    use crate::plugin::executor::Executor;
    use crate::plugin::executor::sequence::chain::ChainProgram;
    use crate::proto::rdata::{CNAME, SOA};
    use crate::proto::{
        ClientSubnet, DNSClass, Edns, EdnsCode, EdnsOption, Message, Name, Question, RData, Rcode,
        Record, RecordType,
    };

    async fn wait_until<F>(description: &str, condition: F)
    where
        F: Fn() -> bool,
    {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect(description);
    }

    fn test_cache(config: CacheConfig) -> Cache {
        let cache_negative = config.cache_negative.unwrap_or(true);
        let max_negative_ttl = config.max_negative_ttl.unwrap_or(DEFAULT_MAX_NEGATIVE_TTL);
        let negative_ttl_without_soa = config
            .negative_ttl_without_soa
            .unwrap_or(DEFAULT_NEGATIVE_TTL_WITHOUT_SOA);
        let cache_size = config.size.unwrap_or(DEFAULT_CACHE_SIZE);
        let ecs_in_key = config.ecs_in_key.unwrap_or(false);
        let short_circuit = config.short_circuit.unwrap_or(false);
        let lazy_refresh_concurrency = config
            .lazy_refresh_concurrency
            .unwrap_or(DEFAULT_LAZY_REFRESH_CONCURRENCY);

        Cache {
            store: Cache::new_store("cache_test", cache_size),
            tag: "cache_test".to_string(),
            cache_negative,
            max_negative_ttl,
            negative_ttl_without_soa,
            short_circuit,
            ecs_in_key,
            config,
            dump_task_id: Mutex::new(None),
            cleanup_task_id: Mutex::new(None),
            lazy_refresh_inflight: Arc::new(DashSet::new()),
            lazy_refresh_slots: Arc::new(Semaphore::new(lazy_refresh_concurrency)),
            lazy_refresh_tasks: TaskTracker::new(),
            lazy_refresh_shutdown: CancellationToken::new(),
            lazy_refresh_accepting: Mutex::new(true),
            miss_coalescer: MissCoalescer::new(),
            touch_interval_ms: AtomicU64::new(0),
            next_touch_interval_refresh_ms: AtomicU64::new(0),
        }
    }

    fn default_test_config() -> CacheConfig {
        CacheConfig {
            size: Some(128),
            lazy_cache_ttl: None,
            lazy_refresh_concurrency: None,
            lazy_refresh_failure_cooldown: None,
            dump_file: None,
            dump_interval: None,
            short_circuit: Some(false),
            cache_negative: Some(true),
            max_negative_ttl: Some(DEFAULT_MAX_NEGATIVE_TTL),
            negative_ttl_without_soa: Some(DEFAULT_NEGATIVE_TTL_WITHOUT_SOA),
            max_positive_ttl: None,
            min_positive_ttl: None,
            ecs_in_key: None,
        }
    }

    #[test]
    fn parse_cache_quick_setup_supports_short_circuit() {
        let cfg = parse_cache_quick_setup("short_circuit=true").expect("quick setup should parse");
        assert_eq!(cfg.short_circuit, Some(true));
    }

    #[tokio::test]
    async fn miss_coalescer_notifies_followers_and_releases_key() {
        let coalescer = MissCoalescer::new();
        let key = cache_key_for_domain("example.com");

        let context = make_context(make_request_with_query("example.com.", false, false));
        let leader = match coalescer.register(key.clone(), &context) {
            MissRole::Leader(leader) => leader,
            MissRole::Follower(_) | MissRole::Reentrant => {
                panic!("first request should become leader")
            }
        };
        let mut follower = match coalescer.register(key.clone(), &context) {
            MissRole::Follower(receiver) => receiver,
            MissRole::Leader(_) | MissRole::Reentrant => {
                panic!("second independent request should become follower")
            }
        };

        leader.complete(true);
        follower
            .changed()
            .await
            .expect("leader completion should notify follower");
        assert!(*follower.borrow());

        assert!(matches!(
            coalescer.register(key, &context),
            MissRole::Leader(_)
        ));
    }

    #[test]
    fn miss_coalescer_detects_recursive_wait_on_ancestor_leader() {
        let coalescer = MissCoalescer::new();
        let key = cache_key_for_domain("reentrant.example");
        let mut context = make_context(make_request_with_query(
            "reentrant.example.",
            false,
            false,
        ));

        let leader = match coalescer.register(key.clone(), &context) {
            MissRole::Leader(leader) => leader,
            MissRole::Follower(_) | MissRole::Reentrant => {
                panic!("first request should become leader")
            }
        };
        let previous = context.runtime.push_miss_leader_ancestor(leader.token());

        assert!(matches!(
            coalescer.register(key.clone(), &context),
            MissRole::Reentrant
        ));

        context.runtime.restore_miss_leader_ancestry(previous);
        assert!(matches!(
            coalescer.register(key, &context),
            MissRole::Follower(_)
        ));
    }

    #[test]
    fn miss_coalescer_does_not_treat_sibling_branch_as_reentrant() {
        let coalescer = MissCoalescer::new();
        let outer_key = cache_key_for_domain("outer.example");
        let sibling_key = cache_key_for_domain("sibling.example");
        let mut parent = make_context(make_request_with_query("outer.example.", false, false));

        let outer_leader = match coalescer.register(outer_key, &parent) {
            MissRole::Leader(leader) => leader,
            MissRole::Follower(_) | MissRole::Reentrant => {
                panic!("outer request should become leader")
            }
        };
        let previous = parent
            .runtime
            .push_miss_leader_ancestor(outer_leader.token());

        let mut primary = parent.copy_for_subquery();
        let secondary = parent.copy_for_subquery();
        let sibling_leader = match coalescer.register(sibling_key.clone(), &primary) {
            MissRole::Leader(leader) => leader,
            MissRole::Follower(_) | MissRole::Reentrant => {
                panic!("primary sibling should become leader")
            }
        };
        let _ = primary
            .runtime
            .push_miss_leader_ancestor(sibling_leader.token());

        assert!(matches!(
            coalescer.register(sibling_key, &secondary),
            MissRole::Follower(_)
        ));

        parent.runtime.restore_miss_leader_ancestry(previous);
    }

    #[tokio::test]
    async fn recursive_cache_miss_bypasses_ancestor_wait_and_caches_once() {
        AppClock::start();
        let mut cache = test_cache(default_test_config());
        let _ = cache.init_for_test().await;
        let cache = Arc::new(cache);

        let terminal_calls = Arc::new(AtomicUsize::new(0));
        let terminal_program =
            ChainProgram::single_with_next_executor_for_test(Arc::new(StubRefreshExecutor {
                calls: terminal_calls.clone(),
            }));
        let inner_next = ExecutorNext::from_program_for_test(terminal_program, 0);
        let recursive_program = ChainProgram::single_with_next_executor_for_test(Arc::new(
            RecursiveCacheExecutor {
                cache: cache.clone(),
                inner_next,
            },
        ));
        let outer_next = ExecutorNext::from_program_for_test(recursive_program, 0);
        let mut context = make_context(make_request_with_query("example.com.", false, false));

        let step = tokio::time::timeout(
            Duration::from_secs(1),
            cache.execute_with_next(&mut context, Some(outer_next)),
        )
        .await
        .expect("recursive cache execution must not wait for miss coalescing timeout")
        .expect("recursive cache execution should succeed");

        assert_eq!(step, ExecStep::Next);
        assert_eq!(terminal_calls.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(cache.store.cache_map().len(), 1);
        assert_eq!(
            cache
                .store
                .metrics()
                .miss_coalesce_reentrant_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(
            cache
                .store
                .metrics()
                .miss_coalesce_timeout_total
                .load(AtomicOrdering::Relaxed),
            0
        );
    }

    #[test]
    fn initial_cache_capacity_is_bounded_for_large_limits() {
        assert_eq!(Cache::initial_cache_capacity(0), 1);
        assert_eq!(Cache::initial_cache_capacity(1024), 1024);
        assert_eq!(
            Cache::initial_cache_capacity(MAX_INITIAL_CACHE_CAPACITY * 10),
            MAX_INITIAL_CACHE_CAPACITY
        );
    }

    #[test]
    fn adaptive_touch_interval_tracks_occupancy_thresholds() {
        assert_eq!(Cache::adaptive_touch_interval_ms(49_000, 100_000), 0);
        assert_eq!(
            Cache::adaptive_touch_interval_ms(50_000, 100_000),
            TOUCH_MEDIUM_INTERVAL_MS
        );
        assert_eq!(
            Cache::adaptive_touch_interval_ms(75_000, 100_000),
            TOUCH_HIGH_INTERVAL_MS
        );
        assert_eq!(
            Cache::adaptive_touch_interval_ms(90_000, 100_000),
            TOUCH_CRITICAL_INTERVAL_MS
        );
    }

    #[test]
    fn adaptive_touch_interval_scales_for_small_caches() {
        assert_eq!(Cache::adaptive_touch_interval_ms(50, 100), 7_500);
        assert_eq!(Cache::adaptive_touch_interval_ms(75, 100), 1_250);
        assert_eq!(
            Cache::adaptive_touch_interval_ms(90, 100),
            TOUCH_CRITICAL_INTERVAL_MS
        );

        assert_eq!(Cache::adaptive_touch_interval_ms(5_000, 10_000), 15_000);
        assert_eq!(Cache::adaptive_touch_interval_ms(7_500, 10_000), 2_500);
        assert_eq!(
            Cache::adaptive_touch_interval_ms(9_000, 10_000),
            TOUCH_CRITICAL_INTERVAL_MS
        );
    }

    #[test]
    fn current_touch_interval_recomputes_at_most_once_per_refresh_window() {
        let mut cfg = default_test_config();
        cfg.size = Some(4);
        let cache = test_cache(cfg);
        let cache_map = cache.store.cache_map();
        for idx in 0..4 {
            insert_test_cache_entry(
                cache_map,
                format!("live-{idx}.example"),
                100_000,
                idx as u64,
            );
        }

        assert_eq!(
            cache.current_touch_interval_ms(10_000),
            TOUCH_CRITICAL_INTERVAL_MS
        );
        cache_map.remove(&cache_key_for_domain("live-0.example"));
        cache_map.remove(&cache_key_for_domain("live-1.example"));
        cache_map.remove(&cache_key_for_domain("live-2.example"));

        assert_eq!(
            cache.current_touch_interval_ms(10_500),
            TOUCH_CRITICAL_INTERVAL_MS
        );
        assert_eq!(cache.current_touch_interval_ms(11_000), 0);
    }

    fn make_context(request: Message) -> DnsContext {
        DnsContext::new("127.0.0.1:5300".parse::<SocketAddr>().unwrap(), request)
    }

    fn make_request_with_query(name: &str, do_bit: bool, cd_bit: bool) -> Message {
        make_request_with_qtype(name, RecordType::A, do_bit, cd_bit)
    }

    fn make_request_with_qtype(
        name: &str,
        qtype: RecordType,
        do_bit: bool,
        cd_bit: bool,
    ) -> Message {
        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii(name).unwrap(),
            qtype,
            DNSClass::IN,
        ));
        request.set_checking_disabled(cd_bit);

        let mut edns = Edns::new();
        edns.flags_mut().dnssec_ok = do_bit;
        request.set_edns(edns);

        request
    }

    fn cache_key_for_domain(domain: impl Into<String>) -> CacheKey {
        cache_key_for_domain_and_type(domain, RecordType::A)
    }

    fn cache_key_for_domain_and_type(
        domain: impl Into<String>,
        record_type: RecordType,
    ) -> CacheKey {
        CacheKey {
            domain: Arc::from(domain.into()),
            record_type,
            dns_class: DNSClass::IN,
            do_bit: false,
            cd_bit: false,
            ecs_scope: None,
        }
    }

    fn insert_test_cache_entry(cache_map: &CacheMap, domain: String, expire_at: u64, last: u64) {
        cache_map.insert_or_update_with_meta(
            cache_key_for_domain(domain),
            CacheItem::new(Message::new(), 60, expire_at),
            last,
            expire_at,
            last,
        );
    }

    fn cacheable_response_for_domain(domain: &str, ttl: u32) -> Message {
        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii(domain).unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii(domain).unwrap(),
            ttl,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));
        response
    }

    fn cname_only_response_for_domain(domain: &str, ttl: u32) -> Message {
        cname_only_response_for_domain_and_type(domain, ttl, RecordType::A)
    }

    fn cname_only_response_for_domain_and_type(
        domain: &str,
        ttl: u32,
        record_type: RecordType,
    ) -> Message {
        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii(domain).unwrap(),
            record_type,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii(domain).unwrap(),
            ttl,
            RData::CNAME(CNAME(Name::from_ascii("target.example.com.").unwrap())),
        ));
        response
    }

    fn cname_with_a_response_for_domain(domain: &str, cname_ttl: u32, a_ttl: u32) -> Message {
        let mut response = cname_only_response_for_domain(domain, cname_ttl);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("target.example.com.").unwrap(),
            a_ttl,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));
        response
    }

    #[test]
    fn periodic_prune_bounds_large_expired_backlog_per_pass() {
        let cache_map = CacheMap::with_capacity(16);
        let now = 10_000u64;
        let expired_count = 8_704;
        for idx in 0..expired_count {
            insert_test_cache_entry(
                &cache_map,
                format!("expired-{idx}.example"),
                now.saturating_sub(1),
                idx as u64,
            );
        }

        // Periodic maintenance samples at most 4096 entries. Even when every
        // entry is expired, one pressure pass must not turn into a full-table
        // sweep. Full expiry cleanup is reserved for Exact mode.
        let (expired_removed, evicted, after_len) = cache_map.prune(
            TtlCachePruneMode::Periodic {
                max_size: expired_count,
                high_watermark_pct: 100,
                low_watermark_pct: 100,
            },
            now,
        );

        assert!(expired_removed > 0);
        assert!(expired_removed <= 4096);
        assert_eq!(evicted, 0);
        assert_eq!(after_len, expired_count - expired_removed);
        assert_eq!(cache_map.len(), after_len);
    }

    #[test]
    fn exact_prune_removes_complete_expired_backlog() {
        let cache_map = CacheMap::with_capacity(16);
        let now = 10_000u64;
        let expired_count = 8_704;
        for idx in 0..expired_count {
            insert_test_cache_entry(
                &cache_map,
                format!("expired-{idx}.example"),
                now.saturating_sub(1),
                idx as u64,
            );
        }

        let (expired_removed, evicted, after_len) = cache_map.prune(
            TtlCachePruneMode::Exact {
                max_size: expired_count,
            },
            now,
        );

        assert_eq!(expired_removed, expired_count);
        assert_eq!(evicted, 0);
        assert_eq!(after_len, 0);
        assert!(cache_map.is_empty());
    }

    #[test]
    fn periodic_prune_trims_small_cache_to_low_watermark() {
        let cache_map = CacheMap::with_capacity(4);
        let now = 10_000u64;
        for idx in 0..32 {
            insert_test_cache_entry(
                &cache_map,
                format!("live-{idx}.example"),
                now.saturating_add(60_000),
                idx as u64,
            );
        }

        let (expired_removed, evicted, after_len) = cache_map.prune(
            TtlCachePruneMode::Periodic {
                max_size: 8,
                high_watermark_pct: EVICT_HIGH_WATERMARK_PERCENT,
                low_watermark_pct: EVICT_LOW_WATERMARK_PERCENT,
            },
            now,
        );

        assert_eq!(expired_removed, 0);
        assert_eq!(evicted, 26);
        assert_eq!(after_len, 6);
        assert_eq!(cache_map.len(), 6);
    }

    #[test]
    fn periodic_prune_releases_slot_for_single_entry_cache() {
        let cache_map = CacheMap::with_capacity(1);
        let now = 10_000u64;
        insert_test_cache_entry(
            &cache_map,
            "live.example".to_string(),
            now.saturating_add(60_000),
            1,
        );

        let (expired_removed, evicted, after_len) = cache_map.prune(
            TtlCachePruneMode::Periodic {
                max_size: 1,
                high_watermark_pct: EVICT_HIGH_WATERMARK_PERCENT,
                low_watermark_pct: EVICT_LOW_WATERMARK_PERCENT,
            },
            now,
        );

        assert_eq!(expired_removed, 0);
        assert_eq!(evicted, 1);
        assert_eq!(after_len, 0);
        assert!(cache_map.is_empty());
    }

    #[test]
    fn load_prune_trims_large_cache_to_configured_limit() {
        let cache_size = 100_001;
        let excess = 65_553;
        let live_count = cache_size + excess;
        let cache_map = CacheMap::with_capacity(Cache::initial_cache_capacity(cache_size));
        let now = 10_000u64;
        for idx in 0..live_count {
            insert_test_cache_entry(
                &cache_map,
                format!("live-{idx}.example"),
                now.saturating_add(60_000),
                idx as u64,
            );
        }

        let (expired_removed, evicted, after_len) = cache_map.prune(
            TtlCachePruneMode::Exact {
                max_size: cache_size,
            },
            now,
        );

        assert_eq!(expired_removed, 0);
        assert_eq!(evicted, excess);
        assert_eq!(after_len, cache_size);
        assert_eq!(cache_map.len(), cache_size);
    }

    fn add_ecs(request: &mut Message, subnet: &str) {
        let mut edns = request.edns().clone().unwrap_or_default();
        edns.insert(EdnsOption::Subnet(subnet.parse().unwrap()));
        request.set_edns(edns);
    }

    #[derive(Debug)]
    struct StubRefreshExecutor {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Plugin for StubRefreshExecutor {
        fn tag(&self) -> &str {
            "stub_refresh_executor"
        }

        async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for StubRefreshExecutor {
        fn with_next(&self) -> bool {
            true
        }

        async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
            Ok(ExecStep::Next)
        }

        async fn execute_with_next(
            &self,
            context: &mut DnsContext,
            next: Option<ExecutorNext>,
        ) -> Result<ExecStep> {
            self.calls.fetch_add(1, AtomicOrdering::Relaxed);
            let mut response = Message::new();
            response.set_rcode(Rcode::NoError);
            response.add_question(Question::new(
                Name::from_ascii("example.com.").unwrap(),
                RecordType::A,
                DNSClass::IN,
            ));
            response.add_answer(Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                55,
                RData::A(crate::proto::rdata::A(Ipv4Addr::new(9, 9, 9, 9))),
            ));
            if let Some(EdnsOption::Subnet(request_subnet)) = context
                .request
                .edns()
                .as_ref()
                .and_then(|edns| edns.option(EdnsCode::Subnet))
            {
                let mut edns = Edns::new();
                edns.insert(EdnsOption::Subnet(ClientSubnet::new(
                    request_subnet.addr(),
                    request_subnet.source_prefix(),
                    16,
                )));
                response.set_edns(edns);
            }
            context.set_response(response);
            continue_next!(next, context)
        }
    }

    #[derive(Debug)]
    struct RecursiveCacheExecutor {
        cache: Arc<Cache>,
        inner_next: ExecutorNext,
    }

    #[async_trait]
    impl Plugin for RecursiveCacheExecutor {
        fn tag(&self) -> &str {
            "recursive_cache_executor"
        }

        async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for RecursiveCacheExecutor {
        fn with_next(&self) -> bool {
            true
        }

        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            self.cache
                .execute_with_next(context, Some(self.inner_next.clone()))
                .await
        }

        async fn execute_with_next(
            &self,
            context: &mut DnsContext,
            _next: Option<ExecutorNext>,
        ) -> Result<ExecStep> {
            self.execute(context).await
        }
    }

    #[derive(Debug)]
    struct BlockingRefreshExecutor {
        started: Arc<AtomicUsize>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl Plugin for BlockingRefreshExecutor {
        fn tag(&self) -> &str {
            "blocking_refresh_executor"
        }
    }

    #[async_trait]
    impl Executor for BlockingRefreshExecutor {
        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            self.started.fetch_add(1, AtomicOrdering::Relaxed);
            self.release.notified().await;

            let question = context
                .request
                .first_question()
                .cloned()
                .expect("refresh request should contain a question");
            let mut response = Message::new();
            response.set_rcode(Rcode::NoError);
            response.add_question(question.clone());
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                55,
                RData::A(crate::proto::rdata::A(Ipv4Addr::new(9, 9, 9, 9))),
            ));
            context.set_response(response);
            Ok(ExecStep::Next)
        }
    }

    #[derive(Debug)]
    struct FailingRefreshExecutor;

    #[async_trait]
    impl Plugin for FailingRefreshExecutor {
        fn tag(&self) -> &str {
            "failing_refresh_executor"
        }
    }

    #[async_trait]
    impl Executor for FailingRefreshExecutor {
        async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
            Err(DnsError::plugin("refresh failed"))
        }
    }

    #[derive(Debug)]
    struct LowTtlRefreshExecutor;

    #[async_trait]
    impl Plugin for LowTtlRefreshExecutor {
        fn tag(&self) -> &str {
            "low_ttl_refresh_executor"
        }
    }

    #[async_trait]
    impl Executor for LowTtlRefreshExecutor {
        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            let mut response = Message::new();
            response.set_rcode(Rcode::NoError);
            response.add_question(Question::new(
                Name::from_ascii("example.com.").unwrap(),
                RecordType::A,
                DNSClass::IN,
            ));
            response.add_answer(Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                3,
                RData::A(crate::proto::rdata::A(Ipv4Addr::new(9, 9, 9, 9))),
            ));
            context.set_response(response);
            Ok(ExecStep::Next)
        }
    }

    #[derive(Debug)]
    struct CnameOnlyRefreshExecutor;

    #[async_trait]
    impl Plugin for CnameOnlyRefreshExecutor {
        fn tag(&self) -> &str {
            "cname_only_refresh_executor"
        }
    }

    #[async_trait]
    impl Executor for CnameOnlyRefreshExecutor {
        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            context.set_response(cname_only_response_for_domain("example.com.", 60));
            Ok(ExecStep::Next)
        }
    }

    #[derive(Debug)]
    struct BlockingLowTtlRefreshExecutor {
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl Plugin for BlockingLowTtlRefreshExecutor {
        fn tag(&self) -> &str {
            "blocking_low_ttl_refresh_executor"
        }
    }

    #[async_trait]
    impl Executor for BlockingLowTtlRefreshExecutor {
        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            self.release.notified().await;
            let mut response = Message::new();
            response.set_rcode(Rcode::NoError);
            response.add_question(Question::new(
                Name::from_ascii("example.com.").unwrap(),
                RecordType::A,
                DNSClass::IN,
            ));
            response.add_answer(Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                3,
                RData::A(crate::proto::rdata::A(Ipv4Addr::new(9, 9, 9, 9))),
            ));
            context.set_response(response);
            Ok(ExecStep::Next)
        }
    }

    #[test]
    fn cache_key_uses_normalized_domain_from_query_view() {
        let mut ctx_upper = make_context(make_request_with_query("Example.COM.", false, false));
        let mut ctx_lower = make_context(make_request_with_query("example.com", false, false));

        let key_upper = Cache::build_cache_key(&mut ctx_upper, true).unwrap();
        let key_lower = Cache::build_cache_key(&mut ctx_lower, true).unwrap();

        assert_eq!(key_upper.domain.as_ref(), "example.com");
        assert_eq!(key_upper, key_lower);
    }

    #[test]
    fn cache_key_separates_do_cd_and_ecs_when_enabled() {
        let mut req_base = make_request_with_query("example.com.", false, false);
        let req_do = make_request_with_query("example.com.", true, false);
        let req_cd = make_request_with_query("example.com.", false, true);

        add_ecs(&mut req_base, "192.0.2.0/24");
        let mut req_ecs_other = make_request_with_query("example.com.", false, false);
        add_ecs(&mut req_ecs_other, "192.0.3.0/24");

        let mut ctx_base = make_context(req_base);
        let mut ctx_do = make_context(req_do);
        let mut ctx_cd = make_context(req_cd);
        let mut ctx_ecs_other = make_context(req_ecs_other);

        let key_base = Cache::build_cache_key(&mut ctx_base, true).unwrap();
        let key_do = Cache::build_cache_key(&mut ctx_do, true).unwrap();
        let key_cd = Cache::build_cache_key(&mut ctx_cd, true).unwrap();
        let key_ecs_other = Cache::build_cache_key(&mut ctx_ecs_other, true).unwrap();

        assert_ne!(key_base, key_do);
        assert_ne!(key_base, key_cd);
        assert_ne!(key_base, key_ecs_other);
    }

    #[test]
    fn cache_key_rejects_ecs_when_disabled() {
        let mut req_ecs_a = make_request_with_query("example.com.", false, false);
        add_ecs(&mut req_ecs_a, "192.0.2.0/24");

        let mut req_ecs_b = make_request_with_query("example.com.", false, false);
        add_ecs(&mut req_ecs_b, "192.0.3.0/24");

        let mut ctx_ecs_a = make_context(req_ecs_a);
        let mut ctx_ecs_b = make_context(req_ecs_b);

        assert!(Cache::build_cache_key(&mut ctx_ecs_a, false).is_none());
        assert!(Cache::build_cache_key(&mut ctx_ecs_b, false).is_none());
    }

    #[tokio::test]
    async fn cache_hit_reuses_response_ecs_scope_for_matching_client_prefix() {
        AppClock::start();
        let mut config = default_test_config();
        config.ecs_in_key = Some(true);
        let mut cache = test_cache(config);
        let _ = cache.init_for_test().await;

        let mut first_request = make_request_with_query("example.com.", false, false);
        add_ecs(&mut first_request, "203.0.113.199/24");
        let mut first_context = make_context(first_request);
        let first_key = Cache::build_cache_key(&mut first_context, true).unwrap();

        let mut response = cacheable_response_for_domain("example.com.", 120);
        let mut response_edns = Edns::new();
        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 0]),
            24,
            20,
        )));
        response.set_edns(response_edns);
        let disposition = response_disposition_for_cache(&response, &first_key);
        assert!(cache.update_cache_entry(
            &cache.store,
            first_key,
            response,
            120,
            disposition,
        ));

        let mut second_request = make_request_with_query("example.com.", false, false);
        add_ecs(&mut second_request, "203.0.127.1/24");
        let mut second_context = make_context(second_request);

        let lookup = cache
            .try_cache_hit(&mut second_context, &cache.store)
            .expect("cache lookup should exist");
        assert!(matches!(lookup, DnsCacheLookup::Fresh { .. }));
        let response = second_context
            .response()
            .expect("cache hit should set response");
        assert_eq!(
            response
                .edns()
                .as_ref()
                .and_then(|edns| edns.option(EdnsCode::Subnet)),
            Some(&EdnsOption::Subnet(ClientSubnet::new(
                IpAddr::from([203, 0, 127, 1]),
                24,
                20,
            )))
        );
    }

    #[tokio::test]
    async fn cache_rejects_response_with_mismatched_ecs_address() {
        AppClock::start();
        let mut config = default_test_config();
        config.ecs_in_key = Some(true);
        let mut cache = test_cache(config);
        let _ = cache.init_for_test().await;

        let mut request = make_request_with_query("example.com.", false, false);
        add_ecs(&mut request, "203.0.113.199/24");
        let mut context = make_context(request);
        let key = Cache::build_cache_key(&mut context, true).expect("cache key should exist");

        let mut response = cacheable_response_for_domain("example.com.", 120);
        let mut response_edns = Edns::new();
        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 114, 0]),
            24,
            20,
        )));
        response.set_edns(response_edns);
        let disposition = response_disposition_for_cache(&response, &key);

        assert!(!cache.update_cache_entry(
            &cache.store,
            key,
            response,
            120,
            disposition,
        ));
        assert_eq!(cache.store.cache_map().len(), 0);
    }

    #[test]
    fn rewrite_response_ttls_skips_opt_record() {
        let mut response = Message::new();
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));
        let mut edns = Edns::new();
        edns.set_udp_payload_size(1232);
        edns.flags_mut().dnssec_ok = true;
        response.set_edns(edns);

        response.rewrite_record_ttls(|_| 42);

        assert_eq!(response.answers()[0].ttl(), 42);
        let edns = response.edns().as_ref().expect("edns should exist");
        assert_eq!(edns.udp_payload_size(), 1232);
        assert!(edns.flags().dnssec_ok);
    }

    #[tokio::test]
    async fn cache_hit_low_occupancy_does_not_update_last_access() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.size = Some(128);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let now = AppClock::elapsed_millis();
        let last_access_ms = now.saturating_sub(60_000);

        cache.store.cache_map().insert_or_update_with_meta(
            key.clone(),
            CacheItem::new(
                cacheable_response_for_domain("example.com.", 120),
                120,
                now.saturating_add(120_000),
            ),
            now,
            now.saturating_add(120_000),
            last_access_ms,
        );

        let lookup = cache
            .try_cache_hit(&mut context, &cache.store)
            .expect("cache lookup should exist");
        assert!(matches!(lookup, DnsCacheLookup::Fresh { .. }));

        let stored = cache
            .store
            .cache_map()
            .get_retained_handle(&key, AppClock::elapsed_millis(), 0)
            .expect("entry should remain cached");
        assert_eq!(stored.last_access_ms(), last_access_ms);
    }

    #[test]
    fn negative_ttl_uses_soa_and_applies_max_cap() {
        let mut cfg = default_test_config();
        cfg.max_negative_ttl = Some(20);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_rcode(Rcode::NXDomain);
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
                30,
            )),
        ));

        assert_eq!(
            cache.compute_negative_ttl(&response, &cache_key_for_domain("example.com")),
            Some(20)
        );
    }

    #[test]
    fn negative_ttl_without_soa_uses_fallback() {
        let mut cfg = default_test_config();
        cfg.negative_ttl_without_soa = Some(45);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_rcode(Rcode::NXDomain);

        assert_eq!(
            cache.compute_negative_ttl(&response, &cache_key_for_domain("example.com")),
            Some(45)
        );
    }

    #[test]
    fn negative_ttl_without_soa_zero_disables_negative_cache() {
        let mut cfg = default_test_config();
        cfg.negative_ttl_without_soa = Some(0);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_rcode(Rcode::NXDomain);

        assert_eq!(
            cache.compute_negative_ttl(&response, &cache_key_for_domain("example.com")),
            None
        );
    }

    #[test]
    fn servfail_is_not_cacheable() {
        let cache = test_cache(default_test_config());

        let mut response = Message::new();
        response.set_rcode(Rcode::ServFail);

        assert_eq!(
            cache.compute_cache_ttl(&response, &cache_key_for_domain("example.com")),
            CacheTtlDecision::Skip(CacheSkipReason::NoTtl)
        );
    }

    #[test]
    fn min_positive_ttl_skips_low_ttl_positive_response() {
        let mut cfg = default_test_config();
        cfg.min_positive_ttl = Some(4);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            3,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        assert_eq!(
            cache.compute_cache_ttl(&response, &cache_key_for_domain("example.com")),
            CacheTtlDecision::Skip(CacheSkipReason::LowPositiveTtl)
        );
    }

    #[test]
    fn min_positive_ttl_allows_equal_ttl_positive_response() {
        let mut cfg = default_test_config();
        cfg.min_positive_ttl = Some(4);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            4,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        assert_eq!(
            cache.compute_cache_ttl(&response, &cache_key_for_domain("example.com")),
            CacheTtlDecision::Cache(4)
        );
    }

    #[test]
    fn max_positive_ttl_cap_is_checked_before_min_positive_ttl() {
        let mut cfg = default_test_config();
        cfg.max_positive_ttl = Some(10);
        cfg.min_positive_ttl = Some(20);
        let cache = test_cache(cfg);

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            30,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        assert_eq!(
            cache.compute_cache_ttl(&response, &cache_key_for_domain("example.com")),
            CacheTtlDecision::Skip(CacheSkipReason::LowPositiveTtl)
        );
    }

    #[test]
    fn cname_only_response_is_not_positive_cacheable_for_address_key() {
        let cache = test_cache(default_test_config());
        let response = cname_only_response_for_domain("example.com.", 60);

        assert_eq!(
            cache.compute_cache_ttl(&response, &cache_key_for_domain("example.com")),
            CacheTtlDecision::Skip(CacheSkipReason::IncompleteAnswer)
        );
        assert_eq!(
            cache.compute_negative_ttl(&response, &cache_key_for_domain("example.com")),
            None
        );
    }

    #[test]
    fn cname_chain_with_requested_answer_is_positive_cacheable() {
        let cache = test_cache(default_test_config());
        let response = cname_with_a_response_for_domain("example.com.", 30, 120);

        assert_eq!(
            cache.compute_cache_ttl(&response, &cache_key_for_domain("example.com")),
            CacheTtlDecision::Cache(30)
        );
    }

    #[test]
    fn cname_with_soa_is_negative_cacheable_for_address_key() {
        let cache = test_cache(default_test_config());
        let mut response = cname_only_response_for_domain("example.com.", 60);
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
                30,
            )),
        ));

        assert_eq!(
            cache.compute_cache_ttl(&response, &cache_key_for_domain("example.com")),
            CacheTtlDecision::Cache(30)
        );
    }

    #[test]
    fn cname_nodata_ttl_does_not_exceed_cname_ttl() {
        let cache = test_cache(default_test_config());
        let mut response = cname_only_response_for_domain("example.com.", 5);
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
                30,
            )),
        ));

        assert_eq!(
            cache.compute_cache_ttl(&response, &cache_key_for_domain("example.com")),
            CacheTtlDecision::Cache(5)
        );
    }

    #[test]
    fn cache_rejects_response_question_mismatched_with_key() {
        let cache = test_cache(default_test_config());
        let response = cacheable_response_for_domain("other.example.com.", 60);

        assert_eq!(
            cache.compute_cache_ttl(&response, &cache_key_for_domain("example.com")),
            CacheTtlDecision::Skip(CacheSkipReason::NoTtl)
        );
    }

    #[test]
    fn any_query_allows_non_empty_cname_answer() {
        let cache = test_cache(default_test_config());
        let response = cname_only_response_for_domain_and_type("example.com.", 60, RecordType::ANY);

        assert_eq!(
            cache.compute_cache_ttl(
                &response,
                &cache_key_for_domain_and_type("example.com", RecordType::ANY),
            ),
            CacheTtlDecision::Cache(60)
        );
    }

    #[test]
    fn empty_noerror_remains_nodata_but_cname_only_does_not() {
        let cache = test_cache(default_test_config());
        let mut nodata = Message::new();
        nodata.set_rcode(Rcode::NoError);
        let cname_only = cname_only_response_for_domain("example.com.", 60);

        let key = cache_key_for_domain("example.com");
        assert_eq!(cache.compute_negative_ttl(&nodata, &key), Some(60));
        assert_eq!(cache.compute_negative_ttl(&cname_only, &key), None);
    }

    #[tokio::test]
    async fn truncated_response_is_not_cached() {
        AppClock::start();
        let mut cache = test_cache(default_test_config());
        let _ = cache.init_for_test().await;

        let mut context = make_context(make_request_with_query("example.com.", false, false));

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.set_truncated(true);
        context.set_response(response);

        cache.execute_with_next(&mut context, None).await.unwrap();

        let cache_map = cache.store.cache_map();
        assert_eq!(cache_map.len(), 0);
        assert_eq!(
            cache.store.metrics()
                .skip_truncated_total
                .load(AtomicOrdering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn cache_miss_with_short_circuit_returns_downstream_step_after_caching() {
        AppClock::start();
        let mut config = default_test_config();
        config.short_circuit = Some(true);
        let mut cache = test_cache(config);
        let _ = cache.init_for_test().await;

        let calls = Arc::new(AtomicUsize::new(0));
        let program =
            ChainProgram::single_with_next_executor_for_test(Arc::new(StubRefreshExecutor {
                calls: calls.clone(),
            }));
        let next = ExecutorNext::from_program_for_test(program, 0);
        let mut context = make_context(make_request_with_query("example.com.", false, false));

        let step = cache
            .execute_with_next(&mut context, Some(next))
            .await
            .expect("cache execution should succeed");

        assert_eq!(step, ExecStep::Next);
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(cache.store.cache_map().len(), 1);
    }

    #[tokio::test]
    async fn cname_only_response_is_not_cached_under_address_key() {
        AppClock::start();
        let mut cache = test_cache(default_test_config());
        let _ = cache.init_for_test().await;

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        context.set_response(cname_only_response_for_domain("example.com.", 60));

        cache.execute_with_next(&mut context, None).await.unwrap();

        assert_eq!(cache.store.cache_map().len(), 0);
        assert_eq!(cache.store.metrics().insert_total.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(
            cache.store.metrics()
                .skip_incomplete_answer_total
                .load(AtomicOrdering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn restored_cname_only_address_entry_is_evicted_before_cache_hit() {
        AppClock::start();
        let mut cache = test_cache(default_test_config());
        let _ = cache.init_for_test().await;

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key,
            CacheItem::new(
                cname_only_response_for_domain("example.com.", 60),
                60,
                now.saturating_add(60_000),
            ),
            now,
            now.saturating_add(60_000),
            now,
        );

        let lookup = cache
            .try_cache_hit(&mut context, &cache.store)
            .expect("cache lookup should exist");

        assert!(matches!(lookup, DnsCacheLookup::Miss { .. }));
        assert!(context.response().is_none());
        assert_eq!(cache.store.cache_map().len(), 0);
        assert_eq!(cache.store.metrics().miss_total.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(
            cache.store.metrics()
                .skip_incomplete_answer_total
                .load(AtomicOrdering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn restored_cname_only_address_entry_is_not_served_as_lazy_stale_hit() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key,
            CacheItem::new(
                cname_only_response_for_domain("example.com.", 60),
                60,
                now.saturating_sub(1_000),
            ),
            now.saturating_sub(61_000),
            now.saturating_add(30_000),
            now,
        );

        let lookup = cache
            .try_cache_hit(&mut context, &cache.store)
            .expect("cache lookup should exist");

        assert!(matches!(lookup, DnsCacheLookup::Miss { .. }));
        assert!(context.response().is_none());
        assert_eq!(cache.store.cache_map().len(), 0);
        assert_eq!(cache.store.metrics().miss_total.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(
            cache.store.metrics().stale_hit_total.load(AtomicOrdering::Relaxed),
            0
        );
        assert_eq!(
            cache.store.metrics()
                .skip_incomplete_answer_total
                .load(AtomicOrdering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn any_query_caches_non_empty_cname_answer() {
        AppClock::start();
        let mut cache = test_cache(default_test_config());
        let _ = cache.init_for_test().await;

        let mut context = make_context(make_request_with_qtype(
            "example.com.",
            RecordType::ANY,
            false,
            false,
        ));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        context.set_response(cname_only_response_for_domain_and_type(
            "example.com.",
            60,
            RecordType::ANY,
        ));

        cache.execute_with_next(&mut context, None).await.unwrap();

        assert_eq!(cache.store.metrics().insert_total.load(AtomicOrdering::Relaxed), 1);
        assert!(
            cache.store.cache_map()
                .get_retained_handle(&key, AppClock::elapsed_millis(), 0)
                .is_some()
        );
    }

    #[tokio::test]
    async fn cache_hit_sets_outbound_message_response() {
        AppClock::start();
        let mut cache = test_cache(default_test_config());
        let _ = cache.init_for_test().await;

        let mut request = make_request_with_query("example.com.", true, true);
        request.set_id(7);
        request.set_recursion_desired(true);
        request
            .first_question_mut()
            .unwrap()
            .set_name(Name::from_ascii("WWW.Example.COM.").unwrap());
        let mut request_edns = Edns::new();
        request_edns.set_udp_payload_size(4096);
        request_edns.set_dnssec_ok(true);
        request.set_edns(request_edns);
        let mut context = make_context(request.clone());
        let key = Cache::build_cache_key(&mut context, false).unwrap();

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.set_authentic_data(true);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let disposition = response_disposition_for_cache(&response, &key);
        cache.update_cache_entry(
            &cache.store,
            key,
            response,
            120,
            disposition,
        );

        let lookup = cache
            .try_cache_hit(&mut context, &cache.store)
            .expect("cache lookup should exist");
        assert!(matches!(lookup, DnsCacheLookup::Fresh { .. }));
        assert!(context.response().is_some_and(|response| {
            response.has_answer_ip(|ip| ip == std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        }));
        let response = context.response().expect("cache hit should set response");
        assert_eq!(response.id(), 7);
        assert_eq!(response.first_question(), request.first_question());
        assert!(response.recursion_desired());
        assert!(response.checking_disabled());
        assert!(response.authentic_data(), "fresh cache hit should preserve AD");
        assert!(response.edns().as_ref().unwrap().flags().dnssec_ok);
        assert_eq!(response.edns().as_ref().unwrap().udp_payload_size(), 4096);
        assert!(response.edns().as_ref().unwrap().options().is_empty());
        assert!(
            (119..=120).contains(&response.answers()[0].ttl()),
            "fresh cache hit should preserve the original TTL or decrement by at most one second"
        );
        assert_eq!(cache.store.metrics().lookup_total.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(
            cache.store.metrics().fresh_hit_total.load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(cache.store.metrics().insert_total.load(AtomicOrdering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fresh_cache_hit_ages_record_ttls_independently() {
        AppClock::start();
        let cache = test_cache(default_test_config());

        let request = make_request_with_query("example.com.", false, false);
        let mut context = make_context(request);
        let key = Cache::build_cache_key(&mut context, false).unwrap();

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            300,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));
        response.add_authority(Record::from_rdata(
            Name::from_ascii("ns.example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(2, 2, 2, 2))),
        ));
        response.add_additional(Record::from_rdata(
            Name::from_ascii("glue.example.com.").unwrap(),
            30,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(3, 3, 3, 3))),
        ));

        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key,
            CacheItem::new_validated_with_age_offset(
                response,
                300,
                now.saturating_add(240_000),
                60_000,
            ),
            now,
            now.saturating_add(240_000),
            now,
        );

        let lookup = cache
            .try_cache_hit(&mut context, &cache.store)
            .expect("cache lookup should exist");
        assert!(matches!(lookup, DnsCacheLookup::Fresh { .. }));

        let restored = context.response().expect("fresh hit should populate response");
        assert_eq!(restored.answers().len(), 1);
        assert!(
            (239..=240).contains(&restored.answers()[0].ttl()),
            "answer TTL should reflect both record age and the fresh-entry TTL cap"
        );
        assert_eq!(restored.authorities().len(), 1);
        assert!(
            (59..=60).contains(&restored.authorities()[0].ttl()),
            "authority TTL should age from its own original TTL"
        );
        assert!(
            restored.additionals().is_empty(),
            "expired additional data must not survive a fresh cache hit"
        );
    }

    #[test]
    fn restore_cached_message_preserves_response_ecs_scope_only() {
        let mut request = make_request_with_query("example.com.", false, false);
        let mut request_edns = Edns::new();
        request_edns.set_udp_payload_size(4096);
        request_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 99]),
            24,
            0,
        )));
        request.set_edns(request_edns);

        let mut cached_response = cacheable_response_for_domain("example.com.", 120);
        let mut response_edns = Edns::new();
        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 0]),
            24,
            20,
        )));
        response_edns.insert(EdnsOption::Cookie(crate::proto::EdnsCookie::new(vec![
            1, 2,
        ])));
        cached_response.set_edns(response_edns);
        let item = CacheItem::new(cached_response, 120, 120_000);

        let response = item
            .resp
            .clone_with_id_and_record_ttl(request.id(), 60);
        let restored = Cache::restore_cached_message(&item, &request, response);
        let edns = restored
            .edns()
            .as_ref()
            .expect("response should retain EDNS");

        assert_eq!(edns.udp_payload_size(), 4096);
        assert_eq!(
            edns.option(EdnsCode::Subnet),
            Some(&EdnsOption::Subnet(ClientSubnet::new(
                IpAddr::from([203, 0, 113, 99]),
                24,
                20,
            )))
        );
        assert_eq!(edns.options().len(), 1);
    }

    #[tokio::test]
    async fn lazy_cache_hit_returns_stale_response_with_lazy_ttl() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let mut request = make_request_with_query("example.com.", false, false);
        request.set_id(9);
        let mut context = make_context(request);
        let key = Cache::build_cache_key(&mut context, false).unwrap();

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.set_authentic_data(true);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key,
            CacheItem::new(response, 120, now.saturating_sub(1_000)),
            now.saturating_sub(121_000),
            now.saturating_add(10_000),
            now.saturating_sub(100),
        );

        let lookup = cache
            .try_cache_hit(&mut context, &cache.store)
            .expect("cache lookup should exist");
        assert!(matches!(lookup, DnsCacheLookup::Stale { .. }));
        let response = context
            .response()
            .expect("stale cache hit should populate response");
        assert_eq!(response.id(), 9);
        assert_eq!(response.answers()[0].ttl(), 30);
        assert!(
            !response.authentic_data(),
            "stale cache hit must clear AD because cached validation state may no longer be valid"
        );
        assert_eq!(cache.store.metrics().lookup_total.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(
            cache.store.metrics().stale_hit_total.load(AtomicOrdering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn ecs_lazy_cache_hit_returns_stale_response() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(3_600);
        cfg.ecs_in_key = Some(true);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let mut request = make_request_with_query("example.com.", false, false);
        add_ecs(&mut request, "203.0.113.199/24");
        let mut context = make_context(request);
        let key = Cache::build_cache_key(&mut context, true).unwrap();
        let mut response = cacheable_response_for_domain("example.com.", 120);
        let mut response_edns = Edns::new();
        response_edns.insert(EdnsOption::Subnet(ClientSubnet::new(
            IpAddr::from([203, 0, 113, 0]),
            24,
            20,
        )));
        response.set_edns(response_edns);
        let stored_key = cache_key_for_response_ecs_scope(&key, &response)
            .expect("initial ECS response should produce a scoped cache key");
        let now = AppClock::elapsed_millis();

        cache.store.ecs_prefix_hints().observe_cache_key(&stored_key);
        cache.store.cache_map().insert_or_update_with_meta(
            stored_key.clone(),
            CacheItem::new_validated(
                response,
                120,
                now.saturating_sub(1),
            ),
            now.saturating_sub(121_000),
            now.saturating_add(3_000_000),
            now,
        );

        let lookup = cache
            .try_cache_hit(&mut context, &cache.store)
            .expect("cache lookup should exist");
        assert!(matches!(lookup, DnsCacheLookup::Stale { .. }));
        assert_eq!(
            cache.store.metrics().stale_hit_total.load(AtomicOrdering::Relaxed),
            1
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let program =
            ChainProgram::single_with_next_executor_for_test(Arc::new(StubRefreshExecutor {
                calls: calls.clone(),
            }));
        let next = ExecutorNext::from_program_for_test(program, 0);
        cache
            .execute_with_next(&mut context, Some(next))
            .await
            .expect("stale ECS refresh should succeed");
        wait_until("ECS lazy refresh should complete", || {
            cache.store.metrics()
                .lazy_refresh_success_total
                .load(AtomicOrdering::Relaxed)
                == 1
        })
        .await;
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 2);
        assert!(
            cache.store.cache_map()
                .get_retained_handle(&stored_key, AppClock::elapsed_millis(), 0)
                .is_none()
        );
    }

    #[tokio::test]
    async fn cache_metrics_distinguish_miss_and_expired_lookup() {
        AppClock::start();
        let mut cache = test_cache(default_test_config());
        let _ = cache.init_for_test().await;

        let mut miss = make_context(make_request_with_query("missing.example.", false, false));
        let miss_lookup = cache
            .try_cache_hit(&mut miss, &cache.store)
            .expect("cache lookup should exist");
        assert!(matches!(miss_lookup, DnsCacheLookup::Miss { .. }));

        let mut expired = make_context(make_request_with_query("expired.example.", false, false));
        let key = Cache::build_cache_key(&mut expired, false).unwrap();
        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("expired.example.").unwrap(),
            1,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));
        cache.store.cache_map().insert_or_update_with_meta(
            key,
            CacheItem::new(response, 1, AppClock::elapsed_millis()),
            0,
            AppClock::elapsed_millis(),
            0,
        );

        let expired_lookup = cache
            .try_cache_hit(&mut expired, &cache.store)
            .expect("cache lookup should exist");
        assert!(matches!(expired_lookup, DnsCacheLookup::Miss { .. }));

        assert_eq!(cache.store.metrics().lookup_total.load(AtomicOrdering::Relaxed), 2);
        assert_eq!(cache.store.metrics().miss_total.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(cache.store.metrics().expired_total.load(AtomicOrdering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cache_metrics_record_no_ttl_skip() {
        AppClock::start();
        let mut cache = test_cache(default_test_config());
        let _ = cache.init_for_test().await;

        let mut context = make_context(make_request_with_query("servfail.example.", false, false));
        context.set_response({
            let mut response = Message::new();
            response.set_rcode(Rcode::ServFail);
            response
        });

        cache.execute_with_next(&mut context, None).await.unwrap();

        assert_eq!(
            cache.store.metrics()
                .skip_no_ttl_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(cache.store.metrics().insert_total.load(AtomicOrdering::Relaxed), 0);
    }

    #[tokio::test]
    async fn cache_metrics_record_low_positive_ttl_skip() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.min_positive_ttl = Some(4);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        context.set_response({
            let mut response = Message::new();
            response.set_rcode(Rcode::NoError);
            response.add_answer(Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                3,
                RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
            ));
            response
        });

        cache.execute_with_next(&mut context, None).await.unwrap();

        assert_eq!(cache.store.cache_map().len(), 0);
        assert_eq!(
            cache.store.metrics()
                .skip_low_positive_ttl_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(cache.store.metrics().insert_total.load(AtomicOrdering::Relaxed), 0);
    }

    #[tokio::test]
    async fn lazy_cache_ttl_does_not_shorten_fresh_window() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let mut context = make_context(make_request_with_query("example.com.", false, false));

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let disposition = response_disposition_for_cache(&response, &key);
        cache.update_cache_entry(
            &cache.store,
            key.clone(),
            response,
            120,
            disposition,
        );

        let stored = cache.store.cache_map()
            .get_retained_handle(&key, AppClock::elapsed_millis(), 0)
            .expect("entry should be present");
        assert_eq!(
            stored
                .expire_at_ms()
                .saturating_sub(stored.value().fresh_until_ms)
                / 1000,
            0
        );
        assert_eq!(
            stored
                .value()
                .fresh_until_ms
                .saturating_sub(stored.cache_time_ms())
                / 1000,
            120
        );
    }

    #[tokio::test]
    async fn stale_hit_triggers_only_one_background_refresh() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        cfg.short_circuit = Some(true);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let calls = Arc::new(AtomicUsize::new(0));
        let program =
            ChainProgram::single_with_next_executor_for_test(Arc::new(StubRefreshExecutor {
                calls: calls.clone(),
            }));
        let next = ExecutorNext::from_program_for_test(program, 0);

        let mut context_a = make_context(make_request_with_query("example.com.", false, false));
        let mut context_b = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context_a, false).unwrap();

        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key.clone(),
            CacheItem::new(response, 120, now.saturating_sub(1_000)),
            now.saturating_sub(121_000),
            now.saturating_add(10_000),
            now.saturating_sub(100),
        );

        let _ = cache
            .execute_with_next(&mut context_a, Some(next.clone()))
            .await
            .unwrap();
        let _ = cache
            .execute_with_next(&mut context_b, Some(next))
            .await
            .unwrap();

        wait_until("lazy refresh should complete", || {
            cache.store.metrics()
                .lazy_refresh_success_total
                .load(AtomicOrdering::Relaxed)
                == 1
        })
        .await;

        assert_eq!(calls.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_started_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_success_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(cache.store.metrics().insert_total.load(AtomicOrdering::Relaxed), 1);
        let stored = cache.store.cache_map()
            .get_retained_handle(&key, AppClock::elapsed_millis(), 0)
            .expect("entry should exist");
        assert!(
            stored
                .value()
                .resp
                .has_answer_ip(|ip| ip == std::net::IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
        );
    }

    #[tokio::test]
    async fn lazy_refresh_concurrency_limit_skips_busy_keys_without_queueing() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        cfg.lazy_refresh_concurrency = Some(1);
        cfg.short_circuit = Some(true);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let program = ChainProgram::single_with_next_executor_for_test(Arc::new(
            BlockingRefreshExecutor {
                started: started.clone(),
                release: release.clone(),
            },
        ));
        let next = ExecutorNext::from_program_for_test(program, 0);

        let mut context_a = make_context(make_request_with_query("a.example.", false, false));
        let mut context_b = make_context(make_request_with_query("b.example.", false, false));
        let key_a = Cache::build_cache_key(&mut context_a, false).unwrap();
        let key_b = Cache::build_cache_key(&mut context_b, false).unwrap();
        let now = AppClock::elapsed_millis();
        for (key, domain) in [
            (key_a, "a.example."),
            (key_b.clone(), "b.example."),
        ] {
            cache.store.cache_map().insert_or_update_with_meta(
                key,
                CacheItem::new(
                    cacheable_response_for_domain(domain, 120),
                    120,
                    now.saturating_sub(1_000),
                ),
                now.saturating_sub(121_000),
                now.saturating_add(10_000),
                now.saturating_sub(100),
            );
        }

        cache
            .execute_with_next(&mut context_a, Some(next.clone()))
            .await
            .expect("first stale hit should be served");
        wait_until("first lazy refresh should start", || {
            started.load(AtomicOrdering::Relaxed) == 1
        })
        .await;

        cache
            .execute_with_next(&mut context_b, Some(next.clone()))
            .await
            .expect("busy stale hit should still be served");

        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_started_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_skipped_busy_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(started.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_failed_total
                .load(AtomicOrdering::Relaxed),
            0
        );

        release.notify_one();
        wait_until("first lazy refresh should complete", || {
            cache.store.metrics()
                .lazy_refresh_success_total
                .load(AtomicOrdering::Relaxed)
                == 1
        })
        .await;

        context_b.clear_response();
        cache
            .execute_with_next(&mut context_b, Some(next))
            .await
            .expect("second key should retry once capacity is available");
        wait_until("second lazy refresh should start after permit release", || {
            started.load(AtomicOrdering::Relaxed) == 2
        })
        .await;
        release.notify_one();
        wait_until("second lazy refresh should complete", || {
            cache.store.metrics()
                .lazy_refresh_success_total
                .load(AtomicOrdering::Relaxed)
                == 2
        })
        .await;

        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_started_total
                .load(AtomicOrdering::Relaxed),
            2
        );
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_skipped_busy_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert!(
            cache.store.cache_map()
                .get_retained_handle(&key_b, AppClock::elapsed_millis(), 0)
                .is_some()
        );
    }

    #[tokio::test]
    async fn lazy_refresh_same_key_dedup_does_not_count_as_busy_when_saturated() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        cfg.lazy_refresh_concurrency = Some(1);
        cfg.short_circuit = Some(true);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let program = ChainProgram::single_with_next_executor_for_test(Arc::new(
            BlockingRefreshExecutor {
                started: started.clone(),
                release: release.clone(),
            },
        ));
        let next = ExecutorNext::from_program_for_test(program, 0);

        let mut context = make_context(make_request_with_query("same.example.", false, false));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key.clone(),
            CacheItem::new(
                cacheable_response_for_domain("same.example.", 120),
                120,
                now.saturating_sub(1_000),
            ),
            now.saturating_sub(121_000),
            now.saturating_add(10_000),
            now.saturating_sub(100),
        );

        cache
            .execute_with_next(&mut context, Some(next.clone()))
            .await
            .expect("first stale hit should start refresh");
        wait_until("first same-key refresh should start", || {
            started.load(AtomicOrdering::Relaxed) == 1
        })
        .await;

        context.clear_response();
        cache
            .execute_with_next(&mut context, Some(next))
            .await
            .expect("duplicate stale hit should still be served");

        assert_eq!(started.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_started_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_skipped_busy_total
                .load(AtomicOrdering::Relaxed),
            0,
            "same-key deduplication must not be reported as global busy"
        );
        assert!(cache.lazy_refresh_inflight.contains(&key));
        assert_eq!(cache.lazy_refresh_inflight.len(), 1);

        release.notify_one();
        wait_until("same-key refresh should complete", || {
            cache.store.metrics()
                .lazy_refresh_success_total
                .load(AtomicOrdering::Relaxed)
                == 1
        })
        .await;
    }

    #[tokio::test]
    async fn destroy_cancels_lazy_refresh_and_closes_admission() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        cfg.lazy_refresh_concurrency = Some(1);
        cfg.short_circuit = Some(true);
        let mut cache = test_cache(cfg);
        cache.init_for_test().await.expect("cache init should succeed");

        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let program = ChainProgram::single_with_next_executor_for_test(Arc::new(
            BlockingRefreshExecutor {
                started: started.clone(),
                release: release.clone(),
            },
        ));
        let next = ExecutorNext::from_program_for_test(program, 0);

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key.clone(),
            CacheItem::new(
                cacheable_response_for_domain("example.com.", 120),
                120,
                now.saturating_sub(1_000),
            ),
            now.saturating_sub(121_000),
            now.saturating_add(10_000),
            now.saturating_sub(100),
        );

        cache
            .execute_with_next(&mut context, Some(next.clone()))
            .await
            .expect("stale hit should start lazy refresh");
        wait_until("lazy refresh should start", || {
            started.load(AtomicOrdering::Relaxed) == 1
        })
        .await;

        tokio::time::timeout(Duration::from_secs(1), cache.destroy())
            .await
            .expect("cache destroy should not wait for blocked upstream refresh")
            .expect("cache destroy should succeed");

        assert!(cache.lazy_refresh_inflight.is_empty());
        assert_eq!(cache.lazy_refresh_slots.available_permits(), 1);
        assert!(
            !*cache
                .lazy_refresh_accepting
                .lock()
                .expect("lazy_refresh_accepting poisoned")
        );
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_success_total
                .load(AtomicOrdering::Relaxed),
            0
        );
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_failed_total
                .load(AtomicOrdering::Relaxed),
            0
        );

        context.clear_response();
        cache
            .execute_with_next(&mut context, Some(next))
            .await
            .expect("stale response should still be served after refresh admission closes");
        tokio::task::yield_now().await;
        assert_eq!(started.load(AtomicOrdering::Relaxed), 1);
        assert!(cache.lazy_refresh_inflight.is_empty());

        release.notify_waiters();
        let stored = cache.store.cache_map()
            .get_retained_handle(&key, AppClock::elapsed_millis(), 0)
            .expect("stale cache entry should remain after refresh cancellation");
        assert!(
            stored
                .value()
                .resp
                .has_answer_ip(|ip| ip == IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
    }

    #[tokio::test]
    async fn lazy_refresh_does_not_update_address_key_with_cname_only_response() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        cfg.short_circuit = Some(true);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let program =
            ChainProgram::single_with_next_executor_for_test(Arc::new(CnameOnlyRefreshExecutor));
        let next = ExecutorNext::from_program_for_test(program, 0);

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let old_response = cacheable_response_for_domain("example.com.", 120);
        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key.clone(),
            CacheItem::new(old_response, 120, now.saturating_sub(1_000)),
            now.saturating_sub(121_000),
            now.saturating_add(10_000),
            now.saturating_sub(100),
        );

        let _ = cache
            .execute_with_next(&mut context, Some(next))
            .await
            .unwrap();
        wait_until("lazy refresh CNAME-only skip should be recorded", || {
            cache.store.metrics()
                .lazy_refresh_failed_total
                .load(AtomicOrdering::Relaxed)
                == 1
        })
        .await;

        assert_eq!(cache.store.metrics().insert_total.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(
            cache.store.metrics()
                .skip_incomplete_answer_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        let stored = cache.store.cache_map()
            .get_retained_handle(&key, AppClock::elapsed_millis(), 0)
            .expect("old stale entry should remain present");
        assert!(
            stored
                .value()
                .resp
                .has_answer_ip(|ip| ip == std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
    }

    #[tokio::test]
    async fn lazy_refresh_metrics_record_failed_refresh() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        cfg.short_circuit = Some(true);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let program =
            ChainProgram::single_with_next_executor_for_test(Arc::new(FailingRefreshExecutor));
        let next = ExecutorNext::from_program_for_test(program, 0);

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key,
            CacheItem::new(response, 120, now.saturating_sub(1_000)),
            now.saturating_sub(121_000),
            now.saturating_add(10_000),
            now.saturating_sub(100),
        );

        let _ = cache
            .execute_with_next(&mut context, Some(next))
            .await
            .unwrap();
        wait_until("lazy refresh failure should be recorded", || {
            cache.store.metrics()
                .lazy_refresh_failed_total
                .load(AtomicOrdering::Relaxed)
                == 1
        })
        .await;

        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_started_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_failed_total
                .load(AtomicOrdering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn lazy_refresh_failure_cooldown_suppresses_immediate_retry() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        cfg.lazy_refresh_failure_cooldown = Some(30);
        cfg.short_circuit = Some(true);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let program =
            ChainProgram::single_with_next_executor_for_test(Arc::new(FailingRefreshExecutor));
        let next = ExecutorNext::from_program_for_test(program, 0);

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key.clone(),
            CacheItem::new(response, 120, now.saturating_sub(1_000)),
            now.saturating_sub(121_000),
            now.saturating_add(60_000),
            now.saturating_sub(100),
        );

        cache
            .execute_with_next(&mut context, Some(next.clone()))
            .await
            .expect("stale hit should be served while refresh fails");
        wait_until("first lazy refresh failure should be recorded", || {
            cache.store.metrics()
                .lazy_refresh_failed_total
                .load(AtomicOrdering::Relaxed)
                == 1
        })
        .await;
        wait_until("failed refresh should leave the per-key inflight set", || {
            cache.lazy_refresh_inflight.is_empty()
        })
        .await;

        let stored = cache.store.cache_map()
            .get_retained_handle(&key, AppClock::elapsed_millis(), 0)
            .expect("stale entry should remain after refresh failure");
        assert!(!stored
            .value()
            .lazy_refresh_retry_allowed(AppClock::elapsed_millis()));

        context.clear_response();
        cache
            .execute_with_next(&mut context, Some(next.clone()))
            .await
            .expect("cooldown hit should still serve stale response");

        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_started_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_skipped_cooldown_total
                .load(AtomicOrdering::Relaxed),
            1
        );

        stored.value().defer_lazy_refresh(0, 0);
        context.clear_response();
        cache
            .execute_with_next(&mut context, Some(next))
            .await
            .expect("refresh should retry after the cooldown expires");
        wait_until("second lazy refresh failure should be recorded", || {
            cache.store.metrics()
                .lazy_refresh_failed_total
                .load(AtomicOrdering::Relaxed)
                == 2
        })
        .await;

        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_started_total
                .load(AtomicOrdering::Relaxed),
            2
        );
    }

    #[tokio::test]
    async fn lazy_refresh_skips_low_positive_ttl_response() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        cfg.min_positive_ttl = Some(4);
        cfg.short_circuit = Some(true);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let program =
            ChainProgram::single_with_next_executor_for_test(Arc::new(LowTtlRefreshExecutor));
        let next = ExecutorNext::from_program_for_test(program, 0);

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let mut response = Message::new();
        response.set_rcode(Rcode::NoError);
        response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key.clone(),
            CacheItem::new(response, 120, now.saturating_sub(1_000)),
            now.saturating_sub(121_000),
            now.saturating_add(10_000),
            now.saturating_sub(100),
        );

        let _ = cache
            .execute_with_next(&mut context, Some(next))
            .await
            .unwrap();
        wait_until("lazy refresh low ttl skip should be recorded", || {
            cache.store.metrics()
                .skip_low_positive_ttl_total
                .load(AtomicOrdering::Relaxed)
                == 1
        })
        .await;

        assert_eq!(
            cache.store.metrics()
                .lazy_refresh_failed_total
                .load(AtomicOrdering::Relaxed),
            1
        );
        assert!(
            cache.store.cache_map()
                .get_retained_handle(&key, AppClock::elapsed_millis(), 0)
                .is_none(),
            "low TTL refresh should evict the old stale cache entry"
        );
    }

    #[tokio::test]
    async fn lazy_refresh_low_ttl_skip_does_not_remove_newer_cache_entry() {
        AppClock::start();
        let mut cfg = default_test_config();
        cfg.lazy_cache_ttl = Some(30);
        cfg.min_positive_ttl = Some(4);
        cfg.short_circuit = Some(true);
        let mut cache = test_cache(cfg);
        let _ = cache.init_for_test().await;

        let release = Arc::new(tokio::sync::Notify::new());
        let program = ChainProgram::single_with_next_executor_for_test(Arc::new(
            BlockingLowTtlRefreshExecutor {
                release: release.clone(),
            },
        ));
        let next = ExecutorNext::from_program_for_test(program, 0);

        let mut context = make_context(make_request_with_query("example.com.", false, false));
        let key = Cache::build_cache_key(&mut context, false).unwrap();
        let mut stale_response = Message::new();
        stale_response.set_rcode(Rcode::NoError);
        stale_response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        stale_response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
        ));

        let now = AppClock::elapsed_millis();
        cache.store.cache_map().insert_or_update_with_meta(
            key.clone(),
            CacheItem::new(
                stale_response,
                120,
                now.saturating_sub(1_000),
            ),
            now.saturating_sub(121_000),
            now.saturating_add(10_000),
            now.saturating_sub(100),
        );

        let _ = cache
            .execute_with_next(&mut context, Some(next))
            .await
            .unwrap();
        wait_until("lazy refresh should be waiting", || {
            cache.store.metrics()
                .lazy_refresh_started_total
                .load(AtomicOrdering::Relaxed)
                == 1
        })
        .await;

        let mut newer_response = Message::new();
        newer_response.set_rcode(Rcode::NoError);
        newer_response.add_question(Question::new(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        newer_response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            90,
            RData::A(crate::proto::rdata::A(Ipv4Addr::new(2, 2, 2, 2))),
        ));
        cache.store.cache_map().insert_or_update_with_meta(
            key.clone(),
            CacheItem::new(
                newer_response,
                90,
                now.saturating_add(90_000),
            ),
            now.saturating_add(1),
            now.saturating_add(90_000),
            now.saturating_add(1),
        );

        release.notify_one();
        wait_until("lazy refresh low ttl skip should be recorded", || {
            cache.store.metrics()
                .skip_low_positive_ttl_total
                .load(AtomicOrdering::Relaxed)
                == 1
        })
        .await;

        let stored = cache.store.cache_map()
            .get_retained_handle(&key, AppClock::elapsed_millis(), 0)
            .expect("newer cache entry should remain present");
        assert!(
            stored
                .value()
                .resp
                .has_answer_ip(|ip| ip == std::net::IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)))
        );
    }

    #[test]
    fn dump_schedule_preserves_user_interval_above_dirty_age_target() {
        let (interval_secs, check_interval_ms, dirty_age_target_ms) =
            Cache::dump_schedule(7_200);

        assert_eq!(interval_secs, 7_200);
        assert_eq!(check_interval_ms, 7_200_000);
        assert_eq!(dirty_age_target_ms, 7_200_000);
    }

    #[test]
    fn dump_schedule_keeps_dirty_age_target_for_short_intervals() {
        let (interval_secs, check_interval_ms, dirty_age_target_ms) =
            Cache::dump_schedule(60);

        assert_eq!(interval_secs, 60);
        assert_eq!(check_interval_ms, 60_000);
        assert_eq!(dirty_age_target_ms, DIRTY_DUMP_TARGET_MS);
    }

    #[test]
    fn validate_config_rejects_zero_dump_interval_when_dump_file_is_set() {
        let cfg = CacheConfig {
            size: Some(128),
            lazy_cache_ttl: None,
            lazy_refresh_concurrency: None,
            lazy_refresh_failure_cooldown: None,
            dump_file: Some("cache.dump".to_string()),
            dump_interval: Some(0),
            short_circuit: Some(false),
            cache_negative: Some(true),
            max_negative_ttl: Some(60),
            negative_ttl_without_soa: Some(60),
            max_positive_ttl: None,
            min_positive_ttl: None,
            ecs_in_key: None,
        };

        assert!(validate_cache_config(&cfg).is_err());
    }

    #[test]
    fn validate_config_rejects_zero_lazy_refresh_concurrency() {
        let mut cfg = default_test_config();
        cfg.lazy_refresh_concurrency = Some(0);

        assert!(validate_cache_config(&cfg).is_err());
    }

    #[test]
    fn validate_config_rejects_zero_lazy_refresh_failure_cooldown() {
        let mut cfg = default_test_config();
        cfg.lazy_refresh_failure_cooldown = Some(0);

        assert!(validate_cache_config(&cfg).is_err());
    }

    #[test]
    fn validate_config_rejects_zero_min_positive_ttl() {
        let mut cfg = default_test_config();
        cfg.min_positive_ttl = Some(0);

        assert!(validate_cache_config(&cfg).is_err());
    }

    #[test]
    fn validate_config_rejects_min_positive_ttl_above_max_positive_ttl() {
        let mut cfg = default_test_config();
        cfg.min_positive_ttl = Some(11);
        cfg.max_positive_ttl = Some(10);

        assert!(validate_cache_config(&cfg).is_err());
    }
}
