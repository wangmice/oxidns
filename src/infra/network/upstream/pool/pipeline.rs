// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fmt::Debug;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use futures::FutureExt;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::infra::clock::AppClock;
use crate::infra::error::{DnsError, Result};
use crate::infra::network::metrics::UpstreamTimeoutStage;
use crate::infra::network::upstream::pool::{
    Connection, ConnectionBuilder, ConnectionPool, DeadlineOutcome, ManagedMaintenanceTask,
    QueryDeadline, QueryTimeoutPolicy, start_maintenance,
};
use crate::infra::task as task_center;
use crate::proto::Message;

const POOL_RETRY_BACKOFF: Duration = Duration::from_millis(10);
const MULTIPLEXED_EXPANSION_MIN_INTERVAL_MS: u64 = 50;
const MULTIPLEXED_MAX_CONCURRENT_BUILDS: usize = 2;
const MULTIPLEXED_EXPANSION_BACKOFF_BASE_MS: u64 = 100;
const MULTIPLEXED_EXPANSION_BACKOFF_MAX_MS: u64 = 2_000;

#[derive(Debug, Clone, Copy)]
struct PacedExpansionPolicy;

#[derive(Debug, Clone)]
struct ConnectFailureObservation {
    at_ms: u64,
    message: String,
}

const SLOT_ACTIVE: u8 = 0;
const SLOT_RETIRING: u8 = 1;
const SLOT_CLOSED: u8 = 2;

#[derive(Debug)]
pub struct PipelinePool<C: Connection> {
    /// Round-robin index for load balancing across slots.
    index: AtomicUsize,
    /// List of connection slots (lock-free with ArcSwap).
    slots: ArcSwap<Vec<Arc<PipelineSlot<C>>>>,
    /// Connections currently being built and reserved against max_size.
    reserved_slots: AtomicUsize,
    /// Maximum number of connections allowed.
    max_size: usize,
    /// Minimum number of connections to maintain.
    min_size: usize,
    /// Maximum number of concurrent queries per connection.
    max_load: u16,
    /// Maximum allowed idle time before a connection is dropped.
    max_idle: Duration,
    /// Factory to create new connections.
    connection_builder: Arc<dyn ConnectionBuilder<C>>,
    /// Per-query timeout policy for acquired slots.
    timeout_policy: QueryTimeoutPolicy,
    /// Timeout used only by background prefill/maintenance expansion.
    connect_timeout: Duration,
    /// Monotonic connection id source.
    next_id: AtomicU16,
    /// Notify query waiters when stream capacity changes.
    release_notified: Arc<Notify>,
    /// Notify the paced expansion worker when a whole pool slot becomes
    /// reservable again. Kept separate from query wakeups to avoid a waiter
    /// stampede when a retiring slot finally drains.
    expansion_capacity_notified: Arc<Notify>,
    /// Background maintenance task registered in task center.
    maintenance_task_handle: Mutex<Option<task_center::ManagedTaskHandle>>,
    /// Multiplexed pools use a background paced expansion controller.
    paced_expansion: Option<PacedExpansionPolicy>,
    /// Cancels detached multiplexed connection builds when this pool is dropped.
    /// Build tasks intentionally do not retain `Arc<PipelinePool<_>>`, so a
    /// reload or pool swap can end the old generation immediately.
    paced_build_shutdown: CancellationToken,
    /// Weak self-reference used to spawn expansion workers without retaining the pool forever.
    self_weak: Weak<PipelinePool<C>>,
    /// A pressure change arrived while the expansion worker was running or exiting.
    expansion_requested: AtomicBool,
    /// Ensures at most one paced expansion worker exists for this pool.
    expansion_worker_running: AtomicBool,
    /// Queries currently waiting because no slot had usable capacity.
    acquire_waiters: AtomicUsize,
    /// Suppress redundant controller wakeups while every pool slot is occupied
    /// by a healthy active connection and `max_size` prevents further growth.
    expansion_quiescent_at_capacity: AtomicBool,
    /// Gate for level-triggered soft-pressure probes. The gate is re-armed by
    /// a detached timer so high-QPS acquisitions do not read the monotonic
    /// clock on every hit above the soft threshold.
    soft_probe_ready: AtomicBool,
    /// Monotonic start time of the most recent connection build.
    last_expand_start_ms: AtomicU64,
    /// Earliest time another build may start after connection-creation failures.
    next_expand_at_ms: AtomicU64,
    /// Consecutive background connection-creation failures.
    connect_failure_streak: AtomicU32,
    /// Most recent background connection failure. Writes are rare; foreground
    /// pool-acquire timeouts take a lock-free snapshot so failure storms do not
    /// serialize on a shared mutex.
    last_connect_failure: ArcSwapOption<ConnectFailureObservation>,
}

#[async_trait]
impl<C: Connection> ConnectionPool<C> for PipelinePool<C> {
    async fn query(&self, request: Message, deadline: QueryDeadline) -> Result<Message> {
        let lease = self.acquire(deadline).await?;
        let result = deadline
            .run(lease.connection().query(request, deadline))
            .await;

        match result {
            DeadlineOutcome::Completed(result) => {
                if !lease.connection().available() {
                    lease.close();
                }
                result
            }
            DeadlineOutcome::Expired => {
                let timeout_error = deadline.timeout_error_for(UpstreamTimeoutStage::QueryIo);
                match self.timeout_policy {
                    QueryTimeoutPolicy::Reuse => {}
                    QueryTimeoutPolicy::Retire => lease.retire(),
                    QueryTimeoutPolicy::Close => lease.close(),
                }
                Err(timeout_error)
            }
        }
    }

    async fn maintain(&self) {
        let now = AppClock::elapsed_millis();
        let slots = self.slots.load();
        if slots.is_empty() {
            drop(slots);
            if self.min_size > 0 {
                if self.paced_expansion.is_some() {
                    self.expansion_quiescent_at_capacity
                        .store(false, Ordering::Release);
                    self.request_paced_expansion();
                } else {
                    let _ = self
                        .expand(QueryDeadline::background(self.connect_timeout))
                        .await;
                }
            }
            return;
        }

        let mut keep = Vec::with_capacity(slots.len());
        let mut idle_candidates = Vec::new();
        let mut close_after_swap = Vec::new();

        for slot in slots.iter() {
            let (state, inflight) = slot.snapshot();
            if state == SLOT_ACTIVE && slot.connection().available() {
                let idle = now.saturating_sub(slot.connection().last_used());
                if inflight == 0 && idle >= self.max_idle.as_millis() as u64 {
                    idle_candidates.push(slot.clone());
                } else {
                    keep.push(slot.clone());
                }
            } else if state == SLOT_RETIRING && inflight > 0 {
                keep.push(slot.clone());
            } else if inflight > 0 {
                slot.close();
                keep.push(slot.clone());
            } else {
                slot.close();
                close_after_swap.push(slot.clone());
            }
        }

        while keep.len() < self.min_size {
            let Some(slot) = idle_candidates.pop() else {
                break;
            };
            keep.push(slot);
        }
        for slot in idle_candidates {
            if slot.close_if_idle() {
                close_after_swap.push(slot);
            } else {
                keep.push(slot);
            }
        }

        let new_len = keep.len();
        if !Arc::ptr_eq(&slots, &self.slots.compare_and_swap(&slots, Arc::new(keep))) {
            for slot in close_after_swap {
                slot.close();
            }
            self.notify_removed_pool_slot();
            return;
        }

        for slot in &close_after_swap {
            slot.close();
        }

        if !close_after_swap.is_empty() {
            debug!(
                "Pipeline pool maintenance: removed {} slots, {} active",
                close_after_swap.len(),
                new_len
            );
            self.notify_removed_pool_slot();
        }

        if new_len < self.min_size {
            if self.paced_expansion.is_some() {
                self.request_paced_expansion();
            } else {
                let _ = self
                    .expand(QueryDeadline::background(self.connect_timeout))
                    .await;
            }
        }
    }

    #[cfg(test)]
    fn configured_min_size(&self) -> usize {
        self.min_size
    }
}

impl<C: Connection> PipelinePool<C> {
    pub fn new(
        min_size: usize,
        max_size: usize,
        max_load: u16,
        idle_time: Duration,
        connection_builder: Box<dyn ConnectionBuilder<C>>,
        timeout_policy: QueryTimeoutPolicy,
        connect_timeout: Duration,
    ) -> Arc<PipelinePool<C>> {
        Self::new_inner(
            min_size,
            max_size,
            max_load,
            idle_time,
            connection_builder,
            timeout_policy,
            connect_timeout,
            None,
        )
    }

    /// Build a pool for multiplexed transports (H2/H3/DoQ). Connection
    /// creation is detached from query lifetimes and paced by one background
    /// worker so bursts cannot create a handshake storm.
    pub fn new_multiplexed(
        min_size: usize,
        max_size: usize,
        max_load: u16,
        idle_time: Duration,
        connection_builder: Box<dyn ConnectionBuilder<C>>,
        timeout_policy: QueryTimeoutPolicy,
        connect_timeout: Duration,
    ) -> Arc<PipelinePool<C>> {
        Self::new_inner(
            min_size,
            max_size,
            max_load,
            idle_time,
            connection_builder,
            timeout_policy,
            connect_timeout,
            Some(PacedExpansionPolicy),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        min_size: usize,
        max_size: usize,
        max_load: u16,
        idle_time: Duration,
        connection_builder: Box<dyn ConnectionBuilder<C>>,
        timeout_policy: QueryTimeoutPolicy,
        connect_timeout: Duration,
        paced_expansion: Option<PacedExpansionPolicy>,
    ) -> Arc<PipelinePool<C>> {
        let pool = Arc::new_cyclic(|weak| Self {
            index: AtomicUsize::new(0),
            slots: ArcSwap::from_pointee(Vec::new()),
            reserved_slots: AtomicUsize::new(0),
            max_size,
            min_size,
            max_load: max_load.max(1),
            max_idle: idle_time,
            connection_builder: Arc::from(connection_builder),
            timeout_policy,
            connect_timeout,
            next_id: AtomicU16::new(1),
            release_notified: Arc::new(Notify::new()),
            expansion_capacity_notified: Arc::new(Notify::new()),
            maintenance_task_handle: Mutex::new(None),
            paced_expansion,
            paced_build_shutdown: CancellationToken::new(),
            self_weak: weak.clone(),
            expansion_requested: AtomicBool::new(false),
            expansion_worker_running: AtomicBool::new(false),
            acquire_waiters: AtomicUsize::new(0),
            expansion_quiescent_at_capacity: AtomicBool::new(false),
            soft_probe_ready: AtomicBool::new(true),
            last_expand_start_ms: AtomicU64::new(u64::MAX),
            next_expand_at_ms: AtomicU64::new(0),
            connect_failure_streak: AtomicU32::new(0),
            last_connect_failure: ArcSwapOption::empty(),
        });
        start_maintenance(&pool);
        if min_size > 0 {
            if pool.paced_expansion.is_some() {
                pool.request_paced_expansion();
            } else {
                let arc = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = arc
                        .expand(QueryDeadline::background(arc.connect_timeout))
                        .await
                    {
                        warn!("Failed to prefill PipelinePool: {:?}", e);
                    }
                });
            }
        }
        pool
    }

    async fn acquire(&self, deadline: QueryDeadline) -> Result<PipelineLease<'_, C>> {
        if self.paced_expansion.is_some() {
            return self.acquire_paced(deadline).await;
        }
        self.acquire_legacy(deadline).await
    }

    async fn acquire_legacy(&self, deadline: QueryDeadline) -> Result<PipelineLease<'_, C>> {
        loop {
            if let Some(slot) = self.try_acquire_existing() {
                return Ok(PipelineLease::new(slot, &self.release_notified));
            }

            if let Some(reservation) = self.try_reserve_slot() {
                match self.expand_one(reservation, deadline).await {
                    Ok(Some(slot)) => {
                        if slot.try_acquire(self.max_load) {
                            return Ok(PipelineLease::new(slot, &self.release_notified));
                        }
                        self.release_notified.notify_waiters();
                    }
                    Ok(None) => {
                        self.wait_backoff(deadline).await?;
                    }
                    Err(e) => {
                        if deadline.remaining().is_none() {
                            return Err(e);
                        }
                        debug!("Failed to create pipeline-pool connection: {:?}", e);
                        self.wait_backoff(deadline).await?;
                    }
                }
            } else {
                // Pool is saturated. Register as a waiter *before* the final
                // re-check so a slot released between the checks above and the
                // await is not lost: `enable()` claims any stored `notify_one`
                // permit, and once registered we are guaranteed to observe a
                // later `notify_waiters` from a close/retire/expand event.
                let notified = self.release_notified.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if let Some(slot) = self.try_acquire_existing() {
                    return Ok(PipelineLease::new(slot, &self.release_notified));
                }
                if let Some(reservation) = self.try_reserve_slot() {
                    match self.expand_one(reservation, deadline).await {
                        Ok(Some(slot)) => {
                            if slot.try_acquire(self.max_load) {
                                return Ok(PipelineLease::new(slot, &self.release_notified));
                            }
                            self.release_notified.notify_waiters();
                        }
                        Ok(None) => {
                            self.wait_backoff(deadline).await?;
                            continue;
                        }
                        Err(e) => {
                            if deadline.remaining().is_none() {
                                return Err(e);
                            }
                            debug!("Failed to create pipeline-pool connection: {:?}", e);
                            self.wait_backoff(deadline).await?;
                            continue;
                        }
                    }
                }
                match deadline.run(notified.as_mut()).await {
                    DeadlineOutcome::Completed(()) => {}
                    DeadlineOutcome::Expired => {
                        return Err(deadline.timeout_error_for(UpstreamTimeoutStage::PoolAcquire));
                    }
                }
            }
        }
    }

    fn try_acquire_existing(&self) -> Option<Arc<PipelineSlot<C>>> {
        let slots = self.slots.load();
        let len = slots.len();
        if len == 0 {
            return None;
        }

        let start_idx = self.index.fetch_add(1, Ordering::Relaxed) % len;
        for offset in 0..len {
            let idx = (start_idx + offset) % len;
            let slot = &slots[idx];
            if slot.try_acquire(self.max_load) {
                return Some(slot.clone());
            }
        }

        None
    }

    fn try_acquire_existing_observed(&self) -> Option<AcquiredSlot<C>> {
        let slots = self.slots.load();
        let len = slots.len();
        if len == 0 {
            self.expansion_quiescent_at_capacity
                .store(false, Ordering::Release);
            return None;
        }

        let start_idx = self.index.fetch_add(1, Ordering::Relaxed) % len;
        let mut saw_replacement_candidate = false;
        for offset in 0..len {
            let idx = (start_idx + offset) % len;
            let slot = &slots[idx];
            if let Some(load) = slot.try_acquire_observed(self.max_load) {
                if saw_replacement_candidate {
                    self.expansion_quiescent_at_capacity
                        .store(false, Ordering::Release);
                    self.request_paced_expansion();
                }
                return Some(AcquiredSlot {
                    slot: slot.clone(),
                    inflight: load.inflight,
                    capacity: load.capacity,
                });
            }
            saw_replacement_candidate |= slot.needs_replacement();
        }

        if saw_replacement_candidate {
            // An internally closed/retiring multiplexed connection can become
            // replaceable without going through the pool controller. A failed
            // foreground scan already touched every slot, so use that
            // observation to lift hard-cap quiescence without another scan.
            self.expansion_quiescent_at_capacity
                .store(false, Ordering::Release);
        }
        None
    }

    async fn acquire_paced(&self, deadline: QueryDeadline) -> Result<PipelineLease<'_, C>> {
        if let Some(acquired) = self.try_acquire_existing_observed() {
            self.maybe_request_soft_expansion(acquired.inflight, acquired.capacity);
            return Ok(PipelineLease::new_paced(
                acquired.slot,
                self.release_notified.as_ref(),
                self.expansion_capacity_notified.as_ref(),
                &self.expansion_quiescent_at_capacity,
            ));
        }

        let mut waiter = PoolAcquireWaiter::new(self);
        self.request_paced_expansion();

        loop {
            // Register before the final capacity check so a release/insert in
            // the check-to-sleep window cannot be lost.
            let notified = self.release_notified.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if let Some(acquired) = self.try_acquire_existing_observed() {
                // Stop advertising hard pressure before soft-pressure
                // accounting; otherwise the worker can briefly count a query
                // that has already obtained capacity as still waiting.
                waiter.leave();
                self.maybe_request_soft_expansion(acquired.inflight, acquired.capacity);
                return Ok(PipelineLease::new_paced(
                    acquired.slot,
                    self.release_notified.as_ref(),
                    self.expansion_capacity_notified.as_ref(),
                    &self.expansion_quiescent_at_capacity,
                ));
            }

            self.request_paced_expansion();
            match deadline.run(notified.as_mut()).await {
                DeadlineOutcome::Completed(()) => {}
                DeadlineOutcome::Expired => {
                    return Err(self.paced_pool_acquire_timeout_error(deadline));
                }
            }
        }
    }

    #[inline]
    fn maybe_request_soft_expansion(&self, inflight: u16, capacity: u16) {
        if capacity <= 1 {
            return;
        }
        let soft_threshold = capacity.div_ceil(2);
        if inflight < soft_threshold
            || self.expansion_quiescent_at_capacity.load(Ordering::Relaxed)
            || self.expansion_worker_running.load(Ordering::Relaxed)
            || !self.soft_probe_ready.load(Ordering::Relaxed)
        {
            return;
        }

        // Level-triggered probes preserve aggregate-pressure and dynamic peer
        // capacity handling without paying an Instant read on every hot-path
        // acquisition. Only one query per interval closes the gate; a detached
        // weak timer re-arms it without retaining or polling the pool.
        if self
            .soft_probe_ready
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        self.request_paced_expansion();
        let weak = self.self_weak.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(MULTIPLEXED_EXPANSION_MIN_INTERVAL_MS)).await;
            if let Some(pool) = weak.upgrade() {
                pool.soft_probe_ready.store(true, Ordering::Release);
            }
        });
    }

    fn request_paced_expansion(&self) {
        if self.paced_expansion.is_none()
            || self.expansion_quiescent_at_capacity.load(Ordering::Acquire)
        {
            return;
        }

        self.expansion_requested.store(true, Ordering::Release);
        if self
            .expansion_worker_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let weak = self.self_weak.clone();
        tokio::spawn(async move {
            Self::supervise_paced_expansion_worker(weak).await;
        });
    }

    async fn supervise_paced_expansion_worker(weak: Weak<Self>) {
        let mut lifecycle = PacedExpansionWorkerLifecycle::new(weak.clone());
        loop {
            let outcome = AssertUnwindSafe(Self::run_paced_expansion_worker(weak.clone()))
                .catch_unwind()
                .await;
            match outcome {
                Ok(()) => {
                    lifecycle.disarm();
                    return;
                }
                Err(_) => {
                    let Some(pool) = weak.upgrade() else {
                        lifecycle.disarm();
                        return;
                    };

                    // A panic must not leave `expansion_worker_running=true`
                    // with no live worker. Keep ownership of the running flag
                    // in this supervisor, re-arm demand, and reuse the same
                    // bounded connection-failure backoff before retrying. This
                    // also prevents a deterministic builder panic from turning
                    // into a tight respawn loop.
                    pool.expansion_requested.store(true, Ordering::Release);
                    let delay_ms = pool.record_connect_failure_backoff();
                    warn!(
                        delay_ms,
                        "Multiplexed pipeline expansion worker panicked; retrying after backoff"
                    );
                    drop(pool);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    async fn run_paced_expansion_worker(weak: Weak<Self>) {
        loop {
            let Some(pool) = weak.upgrade() else {
                return;
            };

            // Consume all requests observed up to this point. Any request that
            // arrives after the swap leaves the flag set for the next
            // iteration or the exit handshake below.
            pool.expansion_requested.swap(false, Ordering::AcqRel);

            let state = pool.paced_expansion_state();
            match state {
                PacedExpansionState::Idle => {
                    // Publish the idle state before the final request check. A
                    // concurrent requester either observes `running=true` and
                    // leaves `requested=true` for us, or observes `running=false`
                    // and starts the replacement worker itself.
                    pool.expansion_worker_running
                        .store(false, Ordering::Release);
                    if !pool.expansion_requested.swap(false, Ordering::AcqRel) {
                        return;
                    }
                    if pool
                        .expansion_worker_running
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        return;
                    }
                    continue;
                }
                PacedExpansionState::Saturated => {
                    // `max_size` is occupied entirely by healthy active
                    // connections. Further hard-pressure requests cannot make
                    // expansion possible, so suppress their controller wakeups
                    // until a slot actually becomes replaceable. Revalidate
                    // after publishing the flag to close a capacity-change race.
                    pool.expansion_quiescent_at_capacity
                        .store(true, Ordering::Release);
                    if pool.paced_expansion_state() != PacedExpansionState::Saturated {
                        pool.expansion_quiescent_at_capacity
                            .store(false, Ordering::Release);
                        continue;
                    }

                    // Requests that raced before quiescence was visible are
                    // redundant at the hard cap. Capacity-changing paths clear
                    // the quiescent flag; if that happens during this exit
                    // handshake, explicitly restart the controller.
                    pool.expansion_requested.store(false, Ordering::Release);
                    pool.expansion_worker_running
                        .store(false, Ordering::Release);
                    if !pool.expansion_quiescent_at_capacity.load(Ordering::Acquire) {
                        pool.request_paced_expansion();
                    }
                    return;
                }
                PacedExpansionState::ExpandSoft | PacedExpansionState::ExpandHard => {}
            }

            let delay = pool.paced_expansion_delay();
            if !delay.is_zero() {
                drop(pool);
                tokio::time::sleep(delay).await;
                continue;
            }

            let state = pool.paced_expansion_state();
            let build_limit = match pool.paced_build_limit(state) {
                Some(limit) => limit,
                None => continue,
            };

            if pool.reserved_slots.load(Ordering::Acquire) >= build_limit {
                // The controller remains unique, but connection handshakes are
                // detached and may overlap. Wait for one build reservation to
                // finish instead of spinning while the bounded build window is
                // full.
                let capacity_changed = pool.expansion_capacity_notified.clone();
                let notified = capacity_changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if pool.reserved_slots.load(Ordering::Acquire) >= build_limit {
                    drop(pool);
                    notified.as_mut().await;
                    continue;
                }
            }

            let mut reservation = pool.try_reserve_paced_slot();
            if reservation.is_none() {
                // A retiring/in-flight slot or an already-running connection
                // build can temporarily occupy max_size even though no new
                // build may start. Register before the final re-check to close
                // the notify-before-sleep race.
                let capacity_changed = pool.expansion_capacity_notified.clone();
                let notified = capacity_changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                reservation = pool.try_reserve_paced_slot();
                if reservation.is_none() {
                    // A successful concurrent build may have filled max_size
                    // between the pressure check and reservation attempt. Let
                    // the top of the loop publish hard-cap quiescence instead
                    // of waiting for an event that may never arrive.
                    if matches!(
                        pool.paced_expansion_state(),
                        PacedExpansionState::Idle | PacedExpansionState::Saturated
                    ) {
                        continue;
                    }

                    drop(reservation);
                    drop(pool);
                    notified.as_mut().await;
                    continue;
                }
            }
            let Some(reservation) = reservation else {
                unreachable!("pipeline reservation was checked above");
            };

            if !matches!(
                pool.paced_expansion_state(),
                PacedExpansionState::ExpandSoft | PacedExpansionState::ExpandHard
            ) {
                drop(reservation);
                continue;
            }

            pool.last_expand_start_ms
                .store(AppClock::elapsed_millis(), Ordering::Release);
            Self::spawn_paced_build(pool.clone(), reservation);
        }
    }

    fn spawn_paced_build(pool: Arc<Self>, reservation: PacedSlotReservation<C>) {
        // Extract everything the network handshake needs before spawning it.
        // In particular, the detached task must not retain `Arc<PipelinePool>`:
        // otherwise an old pool generation survives reload/pool swap until the
        // connection timeout and may continue satisfying its old `min_size`.
        let weak = pool.self_weak.clone();
        let builder = pool.connection_builder.clone();
        let shutdown = pool.paced_build_shutdown.clone();
        let connect_timeout = pool.connect_timeout;
        let id = pool.next_id.fetch_add(1, Ordering::Relaxed);
        drop(pool);

        tokio::spawn(async move {
            let deadline = QueryDeadline::background(connect_timeout);
            let build = AssertUnwindSafe(deadline.run(builder.create_connection(id, deadline)))
                .catch_unwind();
            tokio::pin!(build);

            let outcome = tokio::select! {
                biased;
                outcome = build.as_mut() => outcome,
                _ = shutdown.cancelled() => {
                    // Dropping the builder future cancels the in-flight
                    // handshake. The reservation only holds a weak pool
                    // reference, so this cannot keep an obsolete pool alive.
                    drop(reservation);
                    return;
                }
            };

            let Some(pool) = weak.upgrade() else {
                // The pool disappeared after the build completed but before
                // publication. Never leak a successfully created connection
                // from an obsolete generation.
                if let Ok(DeadlineOutcome::Completed(Ok(conn))) = outcome {
                    conn.close();
                }
                drop(reservation);
                return;
            };

            match outcome {
                Ok(DeadlineOutcome::Completed(Ok(conn))) => {
                    let _ = pool.publish_paced_connection(reservation, conn);
                    pool.connect_failure_streak.store(0, Ordering::Release);
                    pool.next_expand_at_ms.store(0, Ordering::Release);
                    pool.clear_connect_failure();
                }
                Ok(DeadlineOutcome::Completed(Err(e))) => {
                    drop(reservation);
                    pool.record_connect_failure(&e);
                    let delay_ms = pool.record_connect_failure_backoff();
                    debug!(
                        delay_ms,
                        error = ?e,
                        "Multiplexed pipeline expansion failed; backing off"
                    );
                }
                Ok(DeadlineOutcome::Expired) => {
                    drop(reservation);
                    let e = deadline.timeout_error_for(UpstreamTimeoutStage::ConnectionCreate);
                    pool.record_connect_failure(&e);
                    let delay_ms = pool.record_connect_failure_backoff();
                    debug!(
                        delay_ms,
                        error = ?e,
                        "Multiplexed pipeline expansion timed out; backing off"
                    );
                }
                Err(_) => {
                    drop(reservation);
                    pool.record_connect_failure_message(
                        "multiplexed connection builder panicked".to_string(),
                    );
                    let delay_ms = pool.record_connect_failure_backoff();
                    warn!(
                        delay_ms,
                        "Multiplexed pipeline connection build panicked; backing off"
                    );
                }
            }

            // The reservation has released its build slot by here and already
            // notified a controller waiting on the bounded build window.
            // Re-evaluate level-triggered pressure after the outcome is recorded.
            pool.request_paced_expansion();
        });
    }

    fn publish_paced_connection(
        &self,
        reservation: PacedSlotReservation<C>,
        conn: Arc<C>,
    ) -> Option<Arc<PipelineSlot<C>>> {
        self.register_connection_unavailable_notify(&conn);
        let slot = Arc::new(PipelineSlot::new(conn));
        if self.insert_slot(slot.clone()) {
            reservation.commit();
            debug!(
                "Pipeline pool expanded: total={}/{}",
                self.slots.load().len(),
                self.max_size
            );
            self.notify_inserted_query_capacity(&slot);
            Some(slot)
        } else {
            slot.close();
            None
        }
    }

    fn paced_expansion_state(&self) -> PacedExpansionState {
        let pressure = self.pool_pressure();
        if pressure.active_connections < self.min_size {
            return if pressure.active_connections < self.max_size {
                PacedExpansionState::ExpandHard
            } else {
                PacedExpansionState::Saturated
            };
        }
        if pressure.active_connections >= self.max_size {
            return PacedExpansionState::Saturated;
        }

        let waiters = self.acquire_waiters.load(Ordering::Acquire);
        if waiters > pressure.free_capacity {
            return PacedExpansionState::ExpandHard;
        }

        if pressure.total_capacity > 0
            && pressure.total_inflight.saturating_mul(2) >= pressure.total_capacity
        {
            return PacedExpansionState::ExpandSoft;
        }

        PacedExpansionState::Idle
    }

    /// Return the total number of concurrent connection builds justified by
    /// current pressure. Existing reservations consume this budget; the value
    /// is a target, while `MULTIPLEXED_MAX_CONCURRENT_BUILDS` is only a ceiling.
    fn paced_build_limit(&self, state: PacedExpansionState) -> Option<usize> {
        match state {
            PacedExpansionState::Idle | PacedExpansionState::Saturated => None,
            PacedExpansionState::ExpandSoft => Some(1),
            PacedExpansionState::ExpandHard => {
                let pressure = self.pool_pressure();
                let waiters = self.acquire_waiters.load(Ordering::Acquire);
                let min_size_builds = self.min_size.saturating_sub(pressure.active_connections);
                let waiter_deficit = waiters.saturating_sub(pressure.free_capacity);
                let per_connection = usize::from(self.max_load.max(1));
                let waiter_builds = waiter_deficit.div_ceil(per_connection);
                let available_pool_slots =
                    self.max_size.saturating_sub(pressure.active_connections);
                let justified = min_size_builds
                    .max(waiter_builds)
                    .min(available_pool_slots)
                    .min(MULTIPLEXED_MAX_CONCURRENT_BUILDS);

                (justified > 0).then_some(justified)
            }
        }
    }

    fn notify_expansion_capacity_change(&self) {
        self.expansion_quiescent_at_capacity
            .store(false, Ordering::Release);
        self.expansion_capacity_notified.notify_waiters();
    }

    /// Removing a whole pool slot creates room for a replacement connection,
    /// but does not itself create usable DNS stream capacity. Multiplexed
    /// query waiters stay asleep until a replacement is inserted; legacy
    /// pools keep their historical wake-all behavior because foreground
    /// acquirers may compete directly for expansion reservations.
    fn notify_removed_pool_slot(&self) {
        if self.paced_expansion.is_some() {
            self.notify_expansion_capacity_change();
        } else {
            self.release_notified.notify_waiters();
        }
    }

    fn pool_pressure(&self) -> PoolPressure {
        let slots = self.slots.load();
        let mut pressure = PoolPressure::default();
        for slot in slots.iter() {
            let (state, inflight) = slot.snapshot();
            if state != SLOT_ACTIVE || !slot.connection().available() {
                continue;
            }
            let capacity_u16 = slot.effective_max_load(self.max_load);
            let capacity = usize::from(capacity_u16);
            pressure.active_connections += 1;
            pressure.total_inflight += usize::from(inflight.min(capacity_u16));
            pressure.total_capacity += capacity;
            pressure.free_capacity += capacity.saturating_sub(usize::from(inflight));
        }
        pressure
    }

    fn paced_expansion_delay(&self) -> Duration {
        let now = AppClock::elapsed_millis();
        let last_start = self.last_expand_start_ms.load(Ordering::Acquire);
        let paced_at = if last_start == u64::MAX {
            0
        } else {
            last_start.saturating_add(MULTIPLEXED_EXPANSION_MIN_INTERVAL_MS)
        };
        let retry_at = self.next_expand_at_ms.load(Ordering::Acquire);
        let allowed_at = paced_at.max(retry_at);
        Duration::from_millis(allowed_at.saturating_sub(now))
    }

    fn record_connect_failure(&self, error: &DnsError) {
        self.record_connect_failure_message(error.to_string());
    }

    fn record_connect_failure_message(&self, message: String) {
        self.last_connect_failure
            .store(Some(Arc::new(ConnectFailureObservation {
                at_ms: AppClock::elapsed_millis(),
                message,
            })));
    }

    fn clear_connect_failure(&self) {
        self.last_connect_failure.store(None);
    }

    fn paced_pool_acquire_timeout_error(&self, deadline: QueryDeadline) -> DnsError {
        let failure = self.last_connect_failure.load_full();
        if let Some(failure) = failure.filter(|failure| failure.at_ms >= deadline.started_at_ms) {
            let detail = format!(
                "last upstream connection attempt failed: {}",
                failure.message
            );
            deadline.timeout_error_for_with_detail(UpstreamTimeoutStage::PoolAcquire, &detail)
        } else {
            deadline.timeout_error_for(UpstreamTimeoutStage::PoolAcquire)
        }
    }

    fn record_connect_failure_backoff(&self) -> u64 {
        let failure = self
            .connect_failure_streak
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        let shift = failure.saturating_sub(1).min(31);
        let delay_ms = MULTIPLEXED_EXPANSION_BACKOFF_BASE_MS
            .saturating_mul(1u64 << shift)
            .min(MULTIPLEXED_EXPANSION_BACKOFF_MAX_MS);
        self.next_expand_at_ms.store(
            AppClock::elapsed_millis().saturating_add(delay_ms),
            Ordering::Release,
        );
        delay_ms
    }

    async fn expand(&self, deadline: QueryDeadline) -> Result<()> {
        let current_len = self.slots.load().len();
        if current_len >= self.max_size {
            return Ok(());
        }

        let target = if current_len >= self.min_size {
            1
        } else {
            self.min_size - current_len
        };
        let want = target.min(self.max_size - current_len);

        for _ in 0..want {
            let Some(reservation) = self.try_reserve_slot() else {
                break;
            };
            self.expand_one(reservation, deadline).await?;
        }

        Ok(())
    }

    async fn expand_one(
        &self,
        reservation: SlotReservation<'_, C>,
        deadline: QueryDeadline,
    ) -> Result<Option<Arc<PipelineSlot<C>>>> {
        let result = self.create_and_insert_slot(deadline).await;
        if matches!(&result, Ok(Some(_))) {
            reservation.commit();
        }
        result
    }

    async fn create_and_insert_slot(
        &self,
        deadline: QueryDeadline,
    ) -> Result<Option<Arc<PipelineSlot<C>>>> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        match deadline
            .run(self.connection_builder.create_connection(id, deadline))
            .await
        {
            DeadlineOutcome::Completed(Ok(conn)) => {
                if self.paced_expansion.is_some() {
                    self.register_connection_unavailable_notify(&conn);
                }
                let slot = Arc::new(PipelineSlot::new(conn));
                if self.insert_slot(slot.clone()) {
                    debug!(
                        "Pipeline pool expanded: total={}/{}",
                        self.slots.load().len(),
                        self.max_size
                    );
                    self.notify_inserted_query_capacity(&slot);
                    Ok(Some(slot))
                } else {
                    slot.close();
                    Ok(None)
                }
            }
            DeadlineOutcome::Completed(Err(e)) => Err(e),
            DeadlineOutcome::Expired => {
                Err(deadline.timeout_error_for(UpstreamTimeoutStage::ConnectionCreate))
            }
        }
    }

    fn register_connection_unavailable_notify(&self, conn: &Arc<C>) {
        let weak = self.self_weak.clone();
        conn.register_unavailable_notify(Arc::new(move || {
            let Some(pool) = weak.upgrade() else {
                return;
            };
            // Connection loss creates potential whole-slot replacement
            // capacity, not usable DNS stream capacity. Re-arm the controller
            // directly and leave foreground waiters asleep until a real stream
            // is released or a replacement connection is published.
            pool.notify_expansion_capacity_change();
            pool.request_paced_expansion();
        }));
    }

    fn notify_inserted_query_capacity(&self, slot: &PipelineSlot<C>) {
        if self.paced_expansion.is_none() {
            self.release_notified.notify_waiters();
            return;
        }

        let waiters = self.acquire_waiters.load(Ordering::Acquire);
        let capacity = usize::from(slot.effective_max_load(self.max_load));
        let wake_count = waiters.min(capacity.max(1));
        for _ in 0..wake_count {
            self.release_notified.notify_one();
        }
    }

    fn insert_slot(&self, slot: Arc<PipelineSlot<C>>) -> bool {
        let inserted = AtomicBool::new(false);
        self.slots.rcu(|old_slots| {
            let mut new_slots = Vec::with_capacity(old_slots.len() + 1);
            for existing in old_slots.iter() {
                if existing.is_drained_unusable() {
                    existing.close();
                } else {
                    new_slots.push(existing.clone());
                }
            }
            let current_len = new_slots.len();
            if current_len >= self.max_size {
                inserted.store(false, Ordering::Relaxed);
                if current_len == old_slots.len() {
                    return old_slots.clone();
                }
                return Arc::new(new_slots);
            }

            new_slots.push(slot.clone());
            inserted.store(true, Ordering::Relaxed);
            Arc::new(new_slots)
        });
        inserted.load(Ordering::Relaxed)
    }

    fn try_reserve_slot(&self) -> Option<SlotReservation<'_, C>> {
        loop {
            let reserved = self.reserved_slots.load(Ordering::Acquire);
            let active = self.usable_or_inflight_slot_count();
            if active.saturating_add(reserved) >= self.max_size {
                return None;
            }
            match self.reserved_slots.compare_exchange_weak(
                reserved,
                reserved + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(SlotReservation::new(self)),
                Err(_) => continue,
            }
        }
    }

    fn try_reserve_paced_slot(&self) -> Option<PacedSlotReservation<C>> {
        loop {
            let reserved = self.reserved_slots.load(Ordering::Acquire);
            let active = self.usable_or_inflight_slot_count();
            if active.saturating_add(reserved) >= self.max_size {
                return None;
            }
            match self.reserved_slots.compare_exchange_weak(
                reserved,
                reserved + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(PacedSlotReservation::new(self.self_weak.clone()));
                }
                Err(_) => continue,
            }
        }
    }

    fn usable_or_inflight_slot_count(&self) -> usize {
        let slots = self.slots.load();
        let mut active = 0usize;
        let mut has_drained = false;
        for slot in slots.iter() {
            if slot.is_drained_unusable() {
                slot.close();
                has_drained = true;
            } else {
                active += 1;
            }
        }
        if !has_drained {
            return active;
        }

        let mut pruned = Vec::with_capacity(active);
        pruned.extend(
            slots
                .iter()
                .filter(|slot| !slot.is_drained_unusable())
                .cloned(),
        );
        let pruned_len = pruned.len();
        if Arc::ptr_eq(
            &slots,
            &self.slots.compare_and_swap(&slots, Arc::new(pruned)),
        ) {
            self.notify_removed_pool_slot();
            pruned_len
        } else {
            self.slots
                .load()
                .iter()
                .filter(|slot| !slot.is_drained_unusable())
                .count()
        }
    }

    async fn wait_backoff(&self, deadline: QueryDeadline) -> Result<()> {
        let Some(remaining) = deadline.remaining() else {
            return Err(deadline.timeout_error_for(UpstreamTimeoutStage::PoolAcquire));
        };
        let delay = remaining.min(POOL_RETRY_BACKOFF);
        match deadline.run(tokio::time::sleep(delay)).await {
            DeadlineOutcome::Completed(()) => Ok(()),
            DeadlineOutcome::Expired => {
                Err(deadline.timeout_error_for(UpstreamTimeoutStage::PoolAcquire))
            }
        }
    }
}

#[derive(Debug)]
struct AcquiredSlot<C: Connection> {
    slot: Arc<PipelineSlot<C>>,
    inflight: u16,
    capacity: u16,
}

#[derive(Debug, Clone, Copy)]
struct AcquiredLoad {
    inflight: u16,
    capacity: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacedExpansionState {
    Idle,
    Saturated,
    ExpandSoft,
    ExpandHard,
}

#[derive(Debug, Default)]
struct PoolPressure {
    active_connections: usize,
    total_inflight: usize,
    total_capacity: usize,
    free_capacity: usize,
}

#[derive(Debug)]
struct PipelineSlot<C: Connection> {
    conn: Arc<C>,
    /// Slot lifecycle state and in-flight borrow count share one atomic word so
    /// idle retirement and new borrows cannot observe or publish split state.
    /// Low 16 bits hold the in-flight count; bits 16..=17 hold the state.
    state_and_inflight: AtomicU32,
}

const SLOT_INFLIGHT_MASK: u32 = u16::MAX as u32;
const SLOT_STATE_SHIFT: u32 = 16;

#[inline]
const fn pack_slot_state(state: u8, inflight: u16) -> u32 {
    ((state as u32) << SLOT_STATE_SHIFT) | inflight as u32
}

#[inline]
const fn unpack_slot_state(word: u32) -> u8 {
    ((word >> SLOT_STATE_SHIFT) & 0b11) as u8
}

#[inline]
const fn unpack_slot_inflight(word: u32) -> u16 {
    (word & SLOT_INFLIGHT_MASK) as u16
}

impl<C: Connection> PipelineSlot<C> {
    fn new(conn: Arc<C>) -> Self {
        Self {
            conn,
            state_and_inflight: AtomicU32::new(pack_slot_state(SLOT_ACTIVE, 0)),
        }
    }

    fn connection(&self) -> &C {
        &self.conn
    }

    #[inline]
    fn snapshot(&self) -> (u8, u16) {
        let word = self.state_and_inflight.load(Ordering::Acquire);
        (unpack_slot_state(word), unpack_slot_inflight(word))
    }

    #[cfg(test)]
    fn inflight(&self) -> u16 {
        self.snapshot().1
    }

    #[cfg(test)]
    fn state(&self) -> u8 {
        self.snapshot().0
    }

    #[inline]
    fn effective_max_load(&self, max_load: u16) -> u16 {
        max_load.min(self.conn.max_concurrent_queries())
    }

    fn try_acquire(&self, max_load: u16) -> bool {
        if !self.conn.available() {
            return false;
        }

        let effective_max_load = self.effective_max_load(max_load);
        let mut current = self.state_and_inflight.load(Ordering::Acquire);
        loop {
            if unpack_slot_state(current) != SLOT_ACTIVE {
                return false;
            }

            let inflight = unpack_slot_inflight(current);
            if inflight >= effective_max_load {
                return false;
            }

            let next = pack_slot_state(SLOT_ACTIVE, inflight + 1);
            match self.state_and_inflight.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if self.conn.available() {
                        return true;
                    }
                    self.release_without_notify();
                    return false;
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn try_acquire_observed(&self, max_load: u16) -> Option<AcquiredLoad> {
        if !self.conn.available() {
            return None;
        }

        let effective_max_load = self.effective_max_load(max_load);
        let mut current = self.state_and_inflight.load(Ordering::Acquire);
        loop {
            if unpack_slot_state(current) != SLOT_ACTIVE {
                return None;
            }

            let inflight = unpack_slot_inflight(current);
            if inflight >= effective_max_load {
                return None;
            }

            let next_inflight = inflight + 1;
            let next = pack_slot_state(SLOT_ACTIVE, next_inflight);
            match self.state_and_inflight.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if self.conn.available() {
                        return Some(AcquiredLoad {
                            inflight: next_inflight,
                            capacity: effective_max_load,
                        });
                    }
                    self.release_without_notify();
                    return None;
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn release(&self, notify: &Notify) -> bool {
        let drained_unusable = self.release_inner();
        // Releasing one in-flight query frees exactly one unit of stream load,
        // so wake a single query waiter. Whole-slot capacity changes are sent
        // through the dedicated expansion notifier by PipelineLease::drop.
        notify.notify_one();
        drained_unusable
    }

    fn release_without_notify(&self) {
        let _ = self.release_inner();
    }

    /// Returns true when this release drains a non-active slot completely.
    fn release_inner(&self) -> bool {
        let mut current = self.state_and_inflight.load(Ordering::Acquire);
        loop {
            let state = unpack_slot_state(current);
            let inflight = unpack_slot_inflight(current);
            debug_assert!(inflight > 0, "pipeline slot inflight underflow");
            if inflight == 0 {
                return false;
            }

            let next = pack_slot_state(state, inflight - 1);
            match self.state_and_inflight.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // An asynchronously failed multiplexed connection can keep
                    // the slot state ACTIVE until its final lease drains. Treat
                    // that transition as whole-slot capacity becoming reusable.
                    let drained_unusable =
                        inflight == 1 && (state != SLOT_ACTIVE || !self.conn.available());
                    if drained_unusable {
                        self.close();
                    }
                    return drained_unusable;
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn retire(&self) {
        let mut current = self.state_and_inflight.load(Ordering::Acquire);
        loop {
            match unpack_slot_state(current) {
                SLOT_ACTIVE => {
                    let inflight = unpack_slot_inflight(current);
                    let next = pack_slot_state(SLOT_RETIRING, inflight);
                    match self.state_and_inflight.compare_exchange_weak(
                        current,
                        next,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            if inflight == 0 {
                                self.close();
                            }
                            return;
                        }
                        Err(observed) => current = observed,
                    }
                }
                SLOT_RETIRING => {
                    if unpack_slot_inflight(current) == 0 {
                        self.close();
                    }
                    return;
                }
                SLOT_CLOSED => return,
                _ => return,
            }
        }
    }

    fn close(&self) {
        let mut current = self.state_and_inflight.load(Ordering::Acquire);
        loop {
            if unpack_slot_state(current) == SLOT_CLOSED {
                return;
            }
            let next = pack_slot_state(SLOT_CLOSED, unpack_slot_inflight(current));
            match self.state_and_inflight.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.conn.close();
                    return;
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn close_if_idle(&self) -> bool {
        // Idle close competes with borrow on the exact same atomic word. If a
        // borrower changes ACTIVE/0 -> ACTIVE/1 first, this CAS fails and the
        // healthy connection stays reusable. If maintenance wins, no later
        // borrower can enter a CLOSED slot.
        match self.state_and_inflight.compare_exchange(
            pack_slot_state(SLOT_ACTIVE, 0),
            pack_slot_state(SLOT_CLOSED, 0),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                self.conn.close();
                true
            }
            Err(current) => {
                unpack_slot_state(current) == SLOT_CLOSED && unpack_slot_inflight(current) == 0
            }
        }
    }

    fn needs_replacement(&self) -> bool {
        let state = unpack_slot_state(self.state_and_inflight.load(Ordering::Acquire));
        state != SLOT_ACTIVE || !self.conn.available()
    }

    fn is_drained_unusable(&self) -> bool {
        let (state, inflight) = self.snapshot();
        inflight == 0 && (state != SLOT_ACTIVE || !self.conn.available())
    }
}

struct PipelineLease<'a, C: Connection> {
    slot: Arc<PipelineSlot<C>>,
    notify: &'a Notify,
    expansion_capacity_notify: Option<&'a Notify>,
    expansion_quiescent_at_capacity: Option<&'a AtomicBool>,
}

impl<'a, C: Connection> PipelineLease<'a, C> {
    fn new(slot: Arc<PipelineSlot<C>>, notify: &'a Notify) -> Self {
        Self {
            slot,
            notify,
            expansion_capacity_notify: None,
            expansion_quiescent_at_capacity: None,
        }
    }

    fn new_paced(
        slot: Arc<PipelineSlot<C>>,
        notify: &'a Notify,
        expansion_capacity_notify: &'a Notify,
        expansion_quiescent_at_capacity: &'a AtomicBool,
    ) -> Self {
        Self {
            slot,
            notify,
            expansion_capacity_notify: Some(expansion_capacity_notify),
            expansion_quiescent_at_capacity: Some(expansion_quiescent_at_capacity),
        }
    }

    fn connection(&self) -> &C {
        self.slot.connection()
    }

    fn retire(&self) {
        self.slot.retire();
        if self.expansion_capacity_notify.is_some() {
            // Retiring a multiplexed slot removes capacity; it does not create
            // stream capacity for blocked queries. Re-arm expansion directly
            // and let a replacement insertion perform bounded query wakeups.
            self.notify_paced_capacity_change();
        } else {
            self.notify.notify_waiters();
        }
    }

    fn close(&self) {
        self.slot.close();
        if self.expansion_capacity_notify.is_some() {
            self.notify_paced_capacity_change();
        } else {
            self.notify.notify_waiters();
        }
    }

    fn notify_paced_capacity_change(&self) {
        if let Some(quiescent) = self.expansion_quiescent_at_capacity {
            quiescent.store(false, Ordering::Release);
        }
        if let Some(notify) = self.expansion_capacity_notify {
            notify.notify_waiters();
        }
    }
}

impl<C: Connection> Drop for PipelineLease<'_, C> {
    fn drop(&mut self) {
        if self.slot.release(self.notify) {
            self.notify_paced_capacity_change();
        }
    }
}

struct PacedExpansionWorkerLifecycle<C: Connection> {
    pool: Weak<PipelinePool<C>>,
    armed: bool,
}

impl<C: Connection> PacedExpansionWorkerLifecycle<C> {
    fn new(pool: Weak<PipelinePool<C>>) -> Self {
        Self { pool, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<C: Connection> Drop for PacedExpansionWorkerLifecycle<C> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(pool) = self.pool.upgrade() else {
            return;
        };

        // Task abortion/cancellation cannot be caught with `catch_unwind`.
        // Publish the worker as absent and re-arm demand. Waking query waiters
        // gives a live cold-pool request an immediate chance to restart the
        // controller; min-conns pools are also recovered by maintenance.
        pool.expansion_requested.store(true, Ordering::Release);
        pool.expansion_worker_running
            .store(false, Ordering::Release);
        pool.release_notified.notify_waiters();
    }
}

struct PoolAcquireWaiter<'a, C: Connection> {
    pool: &'a PipelinePool<C>,
    active: bool,
}

impl<'a, C: Connection> PoolAcquireWaiter<'a, C> {
    fn new(pool: &'a PipelinePool<C>) -> Self {
        pool.acquire_waiters.fetch_add(1, Ordering::AcqRel);
        Self { pool, active: true }
    }

    fn leave(&mut self) {
        if self.active {
            self.active = false;
            self.pool.acquire_waiters.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl<C: Connection> Drop for PoolAcquireWaiter<'_, C> {
    fn drop(&mut self) {
        self.leave();
    }
}

struct SlotReservation<'a, C: Connection> {
    pool: &'a PipelinePool<C>,
    active: bool,
}

impl<'a, C: Connection> SlotReservation<'a, C> {
    fn new(pool: &'a PipelinePool<C>) -> Self {
        Self { pool, active: true }
    }

    fn commit(mut self) {
        self.active = false;
        self.pool.reserved_slots.fetch_sub(1, Ordering::Release);
    }
}

impl<C: Connection> Drop for SlotReservation<'_, C> {
    fn drop(&mut self) {
        if self.active {
            self.pool.reserved_slots.fetch_sub(1, Ordering::Release);
            if self.pool.paced_expansion.is_some() {
                // Releasing a failed/cancelled paced build frees only a pool
                // reservation; it does not create DNS stream capacity. Wake
                // the expansion controller, but leave query waiters asleep
                // until a real slot is published or an active stream releases.
                self.pool.notify_expansion_capacity_change();
            } else {
                // Legacy pools let foreground acquirers compete for expansion
                // reservations, so releasing one must wake those waiters.
                self.pool.release_notified.notify_waiters();
            }
        }
    }
}

struct PacedSlotReservation<C: Connection> {
    pool: Weak<PipelinePool<C>>,
    active: bool,
}

impl<C: Connection> PacedSlotReservation<C> {
    fn new(pool: Weak<PipelinePool<C>>) -> Self {
        Self { pool, active: true }
    }

    fn commit(mut self) {
        self.active = false;
        if let Some(pool) = self.pool.upgrade() {
            pool.reserved_slots.fetch_sub(1, Ordering::Release);
            pool.notify_expansion_capacity_change();
        }
    }
}

impl<C: Connection> Drop for PacedSlotReservation<C> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(pool) = self.pool.upgrade() {
            pool.reserved_slots.fetch_sub(1, Ordering::Release);
            pool.notify_expansion_capacity_change();
        }
    }
}

impl<C: Connection> ManagedMaintenanceTask for PipelinePool<C> {
    fn maintenance_task_handle(&self) -> &Mutex<Option<task_center::ManagedTaskHandle>> {
        &self.maintenance_task_handle
    }

    fn maintenance_task_name(&self) -> String {
        "upstream_pipeline_pool:maintenance".to_string()
    }
}

impl<C: Connection> Drop for PipelinePool<C> {
    fn drop(&mut self) {
        self.paced_build_shutdown.cancel();

        let task_handle = self
            .maintenance_task_handle
            .lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(handle) = task_handle {
            handle.stop_detached();
        }

        let slots = self.slots.load();
        for slot in slots.iter() {
            slot.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize};

    use async_trait::async_trait;

    use super::*;
    use crate::infra::error::{DnsError, Result};
    use crate::infra::network::upstream::conn::PoolUnavailableNotify;

    #[derive(Debug)]
    struct MockConnection {
        available: AtomicBool,
        using_count: AtomicU32,
        last_used: AtomicU64,
        close_calls: AtomicUsize,
        max_concurrent_queries: AtomicU16,
        query_delay: Duration,
        pool_unavailable_notify: PoolUnavailableNotify,
    }

    impl MockConnection {
        fn new(available: bool, using_count: u32, last_used: u64) -> Self {
            Self {
                available: AtomicBool::new(available),
                using_count: AtomicU32::new(using_count),
                last_used: AtomicU64::new(last_used),
                close_calls: AtomicUsize::new(0),
                max_concurrent_queries: AtomicU16::new(u16::MAX),
                query_delay: Duration::ZERO,
                pool_unavailable_notify: PoolUnavailableNotify::default(),
            }
        }

        fn with_query_delay(mut self, query_delay: Duration) -> Self {
            self.query_delay = query_delay;
            self
        }

        fn close_calls(&self) -> usize {
            self.close_calls.load(Ordering::Relaxed)
        }

        fn set_max_concurrent_queries(&self, max: u16) {
            self.max_concurrent_queries.store(max, Ordering::Release);
        }

        fn mark_unavailable(&self) {
            if self.available.swap(false, Ordering::AcqRel) {
                self.pool_unavailable_notify.notify_pool();
            }
        }
    }

    #[async_trait]
    impl Connection for MockConnection {
        fn close(&self) {
            self.close_calls.fetch_add(1, Ordering::Relaxed);
            self.mark_unavailable();
        }

        async fn query(&self, request: Message, _deadline: QueryDeadline) -> Result<Message> {
            self.using_count.fetch_add(1, Ordering::Relaxed);
            if !self.query_delay.is_zero() {
                tokio::time::sleep(self.query_delay).await;
            }
            self.using_count.fetch_sub(1, Ordering::Relaxed);
            Ok(request)
        }

        fn using_count(&self) -> u32 {
            self.using_count.load(Ordering::Relaxed)
        }

        fn available(&self) -> bool {
            self.available.load(Ordering::Relaxed)
        }

        fn register_unavailable_notify(&self, notify: Arc<dyn Fn() + Send + Sync>) {
            self.pool_unavailable_notify.register(notify);
            if !self.available.load(Ordering::Acquire) {
                self.pool_unavailable_notify.notify_pool();
            }
        }

        fn max_concurrent_queries(&self) -> u16 {
            self.max_concurrent_queries.load(Ordering::Acquire)
        }

        fn last_used(&self) -> u64 {
            self.last_used.load(Ordering::Relaxed)
        }
    }

    #[derive(Debug)]
    struct MockBuilder {
        planned: Mutex<VecDeque<Result<Arc<MockConnection>>>>,
    }

    impl MockBuilder {
        fn new(planned: Vec<Result<Arc<MockConnection>>>) -> Self {
            Self {
                planned: Mutex::new(planned.into()),
            }
        }
    }

    #[async_trait]
    impl ConnectionBuilder<MockConnection> for MockBuilder {
        async fn create_connection(
            &self,
            _conn_id: u16,
            _deadline: QueryDeadline,
        ) -> Result<Arc<MockConnection>> {
            self.planned
                .lock()
                .expect("builder plan lock should not be poisoned")
                .pop_front()
                .unwrap_or_else(|| Err(DnsError::runtime("no planned connection")))
        }
    }

    #[derive(Debug)]
    struct PanicOnceBuilder {
        calls: Arc<AtomicUsize>,
        connection: Arc<MockConnection>,
    }

    #[async_trait]
    impl ConnectionBuilder<MockConnection> for PanicOnceBuilder {
        async fn create_connection(
            &self,
            _conn_id: u16,
            _deadline: QueryDeadline,
        ) -> Result<Arc<MockConnection>> {
            let call = self.calls.fetch_add(1, Ordering::AcqRel);
            if call == 0 {
                panic!("planned multiplexed connection-builder panic");
            }
            Ok(self.connection.clone())
        }
    }

    #[derive(Debug, Default)]
    struct BuilderStats {
        calls: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    #[derive(Debug)]
    struct TrackingBuilder {
        stats: Arc<BuilderStats>,
        build_delay: Duration,
        query_delay: Duration,
    }

    #[derive(Debug, Default)]
    struct LifecycleBuilderStats {
        calls: AtomicUsize,
        cancelled: AtomicUsize,
    }

    struct LifecycleBuildGuard(Arc<LifecycleBuilderStats>);

    impl Drop for LifecycleBuildGuard {
        fn drop(&mut self) {
            self.0.cancelled.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[derive(Debug)]
    struct LifecycleBlockingBuilder {
        stats: Arc<LifecycleBuilderStats>,
    }

    #[async_trait]
    impl ConnectionBuilder<MockConnection> for LifecycleBlockingBuilder {
        async fn create_connection(
            &self,
            _conn_id: u16,
            _deadline: QueryDeadline,
        ) -> Result<Arc<MockConnection>> {
            self.stats.calls.fetch_add(1, Ordering::AcqRel);
            let _guard = LifecycleBuildGuard(self.stats.clone());
            std::future::pending::<()>().await;
            unreachable!("lifecycle test builder must be cancelled")
        }
    }

    impl TrackingBuilder {
        fn new(stats: Arc<BuilderStats>, build_delay: Duration, query_delay: Duration) -> Self {
            Self {
                stats,
                build_delay,
                query_delay,
            }
        }
    }

    #[async_trait]
    impl ConnectionBuilder<MockConnection> for TrackingBuilder {
        async fn create_connection(
            &self,
            _conn_id: u16,
            _deadline: QueryDeadline,
        ) -> Result<Arc<MockConnection>> {
            self.stats.calls.fetch_add(1, Ordering::AcqRel);
            let active = self.stats.active.fetch_add(1, Ordering::AcqRel) + 1;
            self.stats.max_active.fetch_max(active, Ordering::AcqRel);
            if !self.build_delay.is_zero() {
                tokio::time::sleep(self.build_delay).await;
            }
            self.stats.active.fetch_sub(1, Ordering::AcqRel);
            Ok(Arc::new(
                MockConnection::new(true, 0, AppClock::elapsed_millis())
                    .with_query_delay(self.query_delay),
            ))
        }
    }

    fn make_paced_pool(
        min_size: usize,
        max_size: usize,
        max_load: u16,
        builder: TrackingBuilder,
    ) -> Arc<PipelinePool<MockConnection>> {
        AppClock::start();
        PipelinePool::new_multiplexed(
            min_size,
            max_size,
            max_load,
            Duration::from_secs(30),
            Box::new(builder),
            QueryTimeoutPolicy::Reuse,
            Duration::from_secs(1),
        )
    }

    fn make_pool(
        min_size: usize,
        max_size: usize,
        max_load: u16,
        idle_secs: u64,
        builder: MockBuilder,
        initial_connections: Vec<Arc<MockConnection>>,
    ) -> PipelinePool<MockConnection> {
        make_pool_with_timeout_policy(
            min_size,
            max_size,
            max_load,
            idle_secs,
            builder,
            initial_connections,
            QueryTimeoutPolicy::Retire,
        )
    }

    fn make_pool_with_timeout_policy(
        min_size: usize,
        max_size: usize,
        max_load: u16,
        idle_secs: u64,
        builder: MockBuilder,
        initial_connections: Vec<Arc<MockConnection>>,
        timeout_policy: QueryTimeoutPolicy,
    ) -> PipelinePool<MockConnection> {
        AppClock::start();
        let slots = initial_connections
            .into_iter()
            .map(|conn| Arc::new(PipelineSlot::new(conn)))
            .collect();
        PipelinePool {
            index: AtomicUsize::new(0),
            slots: ArcSwap::from_pointee(slots),
            reserved_slots: AtomicUsize::new(0),
            max_size,
            min_size,
            max_load: max_load.max(1),
            max_idle: Duration::from_secs(idle_secs),
            connection_builder: Arc::new(builder),
            timeout_policy,
            connect_timeout: Duration::from_secs(5),
            next_id: AtomicU16::new(1),
            release_notified: Arc::new(Notify::new()),
            expansion_capacity_notified: Arc::new(Notify::new()),
            maintenance_task_handle: Mutex::new(None),
            paced_expansion: None,
            paced_build_shutdown: CancellationToken::new(),
            self_weak: Weak::new(),
            expansion_requested: AtomicBool::new(false),
            expansion_worker_running: AtomicBool::new(false),
            acquire_waiters: AtomicUsize::new(0),
            expansion_quiescent_at_capacity: AtomicBool::new(false),
            soft_probe_ready: AtomicBool::new(true),
            last_expand_start_ms: AtomicU64::new(u64::MAX),
            next_expand_at_ms: AtomicU64::new(0),
            connect_failure_streak: AtomicU32::new(0),
            last_connect_failure: ArcSwapOption::empty(),
        }
    }

    #[tokio::test]
    async fn test_acquire_uses_round_robin_across_connections() {
        let first = Arc::new(MockConnection::new(true, 0, 0));
        let second = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(
            0,
            2,
            4,
            10,
            MockBuilder::new(vec![]),
            vec![first.clone(), second.clone()],
        );

        let first_lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("first acquire should succeed");
        let second_lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("second acquire should succeed");

        assert!(Arc::ptr_eq(&first_lease.slot.conn, &first));
        assert!(Arc::ptr_eq(&second_lease.slot.conn, &second));
    }

    #[tokio::test]
    async fn test_acquire_expands_when_pool_is_empty() {
        let created = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(
            0,
            1,
            4,
            10,
            MockBuilder::new(vec![Ok(created.clone())]),
            vec![],
        );

        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_millis(100)))
            .await
            .expect("acquire should expand an empty pool");

        assert!(Arc::ptr_eq(&lease.slot.conn, &created));
        assert_eq!(pool.slots.load().len(), 1);
    }

    #[tokio::test]
    async fn test_acquire_does_not_oversell_max_load() {
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(0, 1, 2, 10, MockBuilder::new(vec![]), vec![conn.clone()]);

        let lease_a = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("first acquire should succeed");
        let lease_b = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("second acquire should succeed");
        let blocked = tokio::time::timeout(
            Duration::from_millis(20),
            pool.acquire(QueryDeadline::new(Duration::from_secs(1))),
        )
        .await;

        assert!(blocked.is_err());
        assert_eq!(lease_a.slot.inflight(), 2);
        drop(lease_b);
    }

    #[tokio::test]
    async fn test_acquire_waits_until_slot_release() {
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        let pool = Arc::new(make_pool(
            0,
            1,
            1,
            10,
            MockBuilder::new(vec![]),
            vec![conn.clone()],
        ));
        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("first acquire should succeed");

        let waiting_pool = pool.clone();
        let expected_conn = conn.clone();
        let waiter = tokio::spawn(async move {
            let next = waiting_pool
                .acquire(QueryDeadline::new(Duration::from_secs(1)))
                .await?;
            Ok::<_, DnsError>(Arc::ptr_eq(&next.slot.conn, &expected_conn))
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(lease);

        let matched = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should be woken")
            .expect("join should succeed")
            .expect("acquire should succeed");

        assert!(matched);
    }

    #[tokio::test]
    async fn test_acquire_replaces_drained_slot_after_capacity_is_freed() {
        AppClock::start();
        let stale = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        let replacement = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        let pool = Arc::new(make_pool(
            0,
            1,
            1,
            10,
            MockBuilder::new(vec![Ok(replacement.clone())]),
            vec![stale.clone()],
        ));
        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("first acquire should saturate the only slot");

        let waiting_pool = pool.clone();
        let expected_replacement = replacement.clone();
        let waiter = tokio::spawn(async move {
            let next = waiting_pool
                .acquire(QueryDeadline::new(Duration::from_secs(1)))
                .await?;
            Ok::<_, DnsError>(Arc::ptr_eq(&next.slot.conn, &expected_replacement))
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        lease.close();
        drop(lease);

        let matched = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should not remain parked after capacity is freed")
            .expect("join should succeed")
            .expect("acquire should create a replacement slot");

        assert!(matched);
        assert_eq!(stale.close_calls(), 1);
        assert_eq!(pool.slots.load().len(), 1);
    }

    #[tokio::test]
    async fn test_query_timeout_retires_slot_without_closing_active_peer() {
        AppClock::start();
        let conn = Arc::new(
            MockConnection::new(true, 0, AppClock::elapsed_millis())
                .with_query_delay(Duration::from_secs(60)),
        );
        let pool = make_pool(0, 1, 2, 10, MockBuilder::new(vec![]), vec![conn.clone()]);

        let fast_lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("acquire should succeed");
        let result = pool
            .query(
                Message::new(),
                QueryDeadline::new(Duration::from_millis(10)),
            )
            .await;

        assert!(result.is_err());
        assert_eq!(conn.close_calls(), 0);
        assert_eq!(pool.slots.load()[0].state(), SLOT_RETIRING);
        drop(fast_lease);
        assert_eq!(conn.close_calls(), 1);
    }

    #[tokio::test]
    async fn test_query_timeout_reuse_keeps_available_slot_active() {
        AppClock::start();
        let conn = Arc::new(
            MockConnection::new(true, 0, AppClock::elapsed_millis())
                .with_query_delay(Duration::from_secs(60)),
        );
        let pool = make_pool_with_timeout_policy(
            0,
            1,
            2,
            10,
            MockBuilder::new(vec![]),
            vec![conn.clone()],
            QueryTimeoutPolicy::Reuse,
        );

        let result = pool
            .query(
                Message::new(),
                QueryDeadline::new(Duration::from_millis(10)),
            )
            .await;

        assert!(result.is_err());
        assert_eq!(conn.close_calls(), 0);
        assert_eq!(pool.slots.load()[0].state(), SLOT_ACTIVE);

        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("available connection should remain reusable after a stream-local timeout");
        assert!(Arc::ptr_eq(&lease.slot.conn, &conn));
    }

    #[tokio::test]
    async fn test_maintain_removes_retired_drained_slot() {
        AppClock::start();
        let conn = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        let slot = Arc::new(PipelineSlot::new(conn.clone()));
        slot.retire();
        let pool = make_pool(0, 1, 4, 10, MockBuilder::new(vec![]), vec![]);
        pool.slots.store(Arc::new(vec![slot]));

        pool.maintain().await;

        assert!(pool.slots.load().is_empty());
        assert_eq!(conn.close_calls(), 1);
    }

    #[tokio::test]
    async fn test_acquire_replaces_drained_unusable_slot_at_capacity() {
        AppClock::start();
        let stale = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        let replacement = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        let pool = make_pool(
            0,
            1,
            4,
            10,
            MockBuilder::new(vec![Ok(replacement.clone())]),
            vec![stale.clone()],
        );
        pool.slots.load()[0].close();

        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_millis(100)))
            .await
            .expect("closed slot should be pruned before reserving a replacement");

        assert!(Arc::ptr_eq(&lease.slot.conn, &replacement));
        assert_eq!(pool.slots.load().len(), 1);
        assert_eq!(stale.close_calls(), 1);
    }

    #[tokio::test]
    async fn test_maintain_keeps_retiring_slot_until_inflight_drains() {
        AppClock::start();
        let conn = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        let pool = make_pool(0, 1, 4, 10, MockBuilder::new(vec![]), vec![conn.clone()]);
        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("acquire should succeed");
        lease.retire();

        pool.maintain().await;

        assert_eq!(pool.slots.load().len(), 1);
        assert_eq!(conn.close_calls(), 0);

        drop(lease);
        assert_eq!(conn.close_calls(), 1);
    }

    #[tokio::test]
    async fn test_maintain_drops_idle_and_invalid_connections() {
        AppClock::start();
        let idle = Arc::new(MockConnection::new(true, 0, 0));
        let invalid = Arc::new(MockConnection::new(false, 0, 0));
        let pool = make_pool(
            0,
            4,
            4,
            0,
            MockBuilder::new(vec![]),
            vec![idle.clone(), invalid.clone()],
        );

        pool.maintain().await;

        assert_eq!(idle.close_calls(), 1);
        assert_eq!(invalid.close_calls(), 1);
        assert!(pool.slots.load().is_empty());
    }

    #[tokio::test]
    async fn test_maintain_marks_removed_idle_slot_closed() {
        AppClock::start();
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(0, 1, 4, 0, MockBuilder::new(vec![]), vec![conn.clone()]);
        let slot = pool.slots.load()[0].clone();

        pool.maintain().await;

        assert_eq!(slot.state(), SLOT_CLOSED);
        assert!(!slot.try_acquire(1));
        assert_eq!(conn.close_calls(), 1);
        assert!(pool.slots.load().is_empty());
    }

    #[tokio::test]
    async fn test_maintain_reuses_idle_connection_to_preserve_min_size() {
        AppClock::start();
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(1, 1, 4, 0, MockBuilder::new(vec![]), vec![conn.clone()]);

        pool.maintain().await;

        assert_eq!(conn.close_calls(), 0);
        assert_eq!(pool.slots.load().len(), 1);
    }

    #[test]
    fn test_close_if_idle_preserves_connection_when_borrower_wins_race() {
        AppClock::start();
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        let slot = PipelineSlot::new(conn.clone());

        // Model the real race: maintenance selected an apparently idle slot,
        // but a borrower atomically claimed it before maintenance committed
        // the idle close. The borrower wins, so maintenance must leave this
        // healthy connection active instead of retiring it after it became
        // useful again.
        assert!(slot.try_acquire(4));

        assert!(
            !slot.close_if_idle(),
            "idle close must lose when a borrower already owns the slot"
        );
        assert_eq!(
            slot.state(),
            SLOT_ACTIVE,
            "a racing successful borrow must keep the connection reusable"
        );
        assert_eq!(conn.close_calls(), 0);

        slot.release_without_notify();
        assert_eq!(slot.state(), SLOT_ACTIVE);
        assert_eq!(conn.close_calls(), 0);
        assert!(
            slot.try_acquire(4),
            "the healthy connection should remain reusable after the racing lease drains"
        );
        slot.release_without_notify();
    }

    #[test]
    fn test_close_if_idle_winner_blocks_late_borrower() {
        AppClock::start();
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        let slot = PipelineSlot::new(conn.clone());

        assert!(slot.close_if_idle());
        assert_eq!(slot.state(), SLOT_CLOSED);
        assert!(!slot.try_acquire(4));
        assert_eq!(conn.close_calls(), 1);
    }

    #[tokio::test]
    async fn test_maintain_keeps_idle_connection_with_inflight_queries() {
        AppClock::start();
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(0, 1, 4, 0, MockBuilder::new(vec![]), vec![conn.clone()]);
        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("acquire should succeed");

        pool.maintain().await;

        assert_eq!(conn.close_calls(), 0);
        assert_eq!(pool.slots.load().len(), 1);
        drop(lease);
    }

    #[tokio::test]
    async fn test_acquire_replaces_unavailable_idle_active_slot_at_capacity() {
        AppClock::start();
        let stale = Arc::new(MockConnection::new(false, 0, AppClock::elapsed_millis()));
        let replacement = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        let pool = make_pool(
            0,
            1,
            1,
            10,
            MockBuilder::new(vec![Ok(replacement.clone())]),
            vec![stale.clone()],
        );

        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_millis(100)))
            .await
            .expect("unavailable idle slot should be replaced immediately");

        assert!(Arc::ptr_eq(&lease.slot.conn, &replacement));
        assert_eq!(stale.close_calls(), 1);
        assert_eq!(pool.slots.load().len(), 1);
    }

    #[test]
    fn test_drop_closes_all_pipeline_connections() {
        let first = Arc::new(MockConnection::new(true, 0, 0));
        let second = Arc::new(MockConnection::new(true, 0, 0));
        let pool = make_pool(
            0,
            2,
            1,
            10,
            MockBuilder::new(vec![]),
            vec![first.clone(), second.clone()],
        );

        drop(pool);

        assert_eq!(first.close_calls(), 1);
        assert_eq!(second.close_calls(), 1);
    }
    #[test]
    fn test_pipeline_slot_tracks_dynamic_connection_load_limit() {
        let conn = Arc::new(MockConnection::new(true, 0, 0));
        conn.set_max_concurrent_queries(2);
        let slot = PipelineSlot::new(conn.clone());

        assert!(slot.try_acquire(32));
        assert!(slot.try_acquire(32));
        assert!(!slot.try_acquire(32));

        conn.set_max_concurrent_queries(4);
        assert!(slot.try_acquire(32));
        assert!(slot.try_acquire(32));
        assert!(!slot.try_acquire(32));

        slot.release_without_notify();
        slot.release_without_notify();
        slot.release_without_notify();
        slot.release_without_notify();
    }

    #[tokio::test]
    async fn test_paced_cold_start_bounds_parallel_connection_builds() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            4,
            2,
            TrackingBuilder::new(
                stats.clone(),
                Duration::from_millis(120),
                Duration::from_millis(200),
            ),
        );

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                pool.query(Message::new(), QueryDeadline::new(Duration::from_secs(2)))
                    .await
            }));
        }
        for task in tasks {
            task.await
                .expect("query task should join")
                .expect("query should complete");
        }

        assert_eq!(
            stats.max_active.load(Ordering::Acquire),
            MULTIPLEXED_MAX_CONCURRENT_BUILDS
        );
        assert!(stats.calls.load(Ordering::Acquire) >= 2);
        assert!(pool.slots.load().len() >= 2);
    }

    #[tokio::test]
    async fn test_paced_min_size_counts_inflight_build_reservations() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            1,
            4,
            32,
            TrackingBuilder::new(stats.clone(), Duration::from_millis(120), Duration::ZERO),
        );

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(stats.calls.load(Ordering::Acquire), 1);
        assert_eq!(stats.max_active.load(Ordering::Acquire), 1);

        tokio::time::timeout(Duration::from_millis(150), async {
            loop {
                if pool.slots.load().len() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("min-size prefill should complete with one connection");

        assert_eq!(stats.calls.load(Ordering::Acquire), 1);
        assert_eq!(pool.slots.load().len(), 1);
    }

    #[tokio::test]
    async fn test_paced_build_does_not_retain_pool_after_drop() {
        AppClock::start();
        let stats = Arc::new(LifecycleBuilderStats::default());
        let pool = PipelinePool::new_multiplexed(
            1,
            1,
            32,
            Duration::from_secs(30),
            Box::new(LifecycleBlockingBuilder {
                stats: stats.clone(),
            }),
            QueryTimeoutPolicy::Reuse,
            Duration::from_secs(30),
        );
        let weak = Arc::downgrade(&pool);

        tokio::time::timeout(Duration::from_millis(250), async {
            while stats.calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("paced connection build should start");

        drop(pool);

        tokio::time::timeout(Duration::from_millis(250), async {
            loop {
                if weak.upgrade().is_none() && stats.cancelled.load(Ordering::Acquire) == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the pool should cancel the detached build without retaining the pool");

        assert_eq!(stats.calls.load(Ordering::Acquire), 1);
        assert_eq!(stats.cancelled.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn test_paced_hard_cap_quiesces_until_connection_becomes_replaceable() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            1,
            1,
            TrackingBuilder::new(stats.clone(), Duration::ZERO, Duration::ZERO),
        );
        let existing = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        pool.slots.store(Arc::new(vec![Arc::new(PipelineSlot::new(
            existing.clone(),
        ))]));

        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("existing connection should be acquirable");
        pool.request_paced_expansion();

        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if pool.expansion_quiescent_at_capacity.load(Ordering::Acquire)
                    && !pool.expansion_worker_running.load(Ordering::Acquire)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("hard-cap controller should enter quiescence");

        for _ in 0..1_000 {
            pool.request_paced_expansion();
        }
        tokio::task::yield_now().await;
        assert!(!pool.expansion_worker_running.load(Ordering::Acquire));
        assert!(!pool.expansion_requested.load(Ordering::Acquire));
        assert_eq!(stats.calls.load(Ordering::Acquire), 0);

        // Releasing ordinary stream capacity does not make another pool slot
        // possible and should therefore keep hard-cap quiescence intact. Once
        // the connection itself becomes unavailable, the next foreground scan
        // observes that replacement is possible and re-arms the controller.
        drop(lease);
        assert!(pool.expansion_quiescent_at_capacity.load(Ordering::Acquire));
        existing.close();

        pool.query(Message::new(), QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("an unavailable hard-cap connection should be replaced");
        assert_eq!(stats.calls.load(Ordering::Acquire), 1);
        assert_eq!(pool.slots.load().len(), 1);
    }

    #[tokio::test]
    async fn test_paced_slot_close_does_not_broadcast_query_waiters() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            1,
            4,
            TrackingBuilder::new(stats, Duration::from_millis(200), Duration::ZERO),
        );
        let existing = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        pool.register_connection_unavailable_notify(&existing);
        pool.slots
            .store(Arc::new(vec![Arc::new(PipelineSlot::new(existing))]));
        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("existing connection should be acquirable");
        pool.acquire_waiters.store(10, Ordering::Release);

        let mut waiters = Vec::new();
        for _ in 0..10 {
            let notified = pool.release_notified.notified();
            waiters.push(Box::pin(notified));
        }
        for waiter in &mut waiters {
            waiter.as_mut().enable();
        }

        lease.close();

        let ready = waiters
            .into_iter()
            .filter_map(|waiter| waiter.now_or_never())
            .count();
        assert_eq!(ready, 0);
        pool.acquire_waiters.store(0, Ordering::Release);
        drop(lease);
    }

    #[tokio::test]
    async fn test_async_unavailable_replenishes_min_size_without_query_waiters() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            1,
            2,
            8,
            TrackingBuilder::new(stats.clone(), Duration::ZERO, Duration::ZERO),
        );

        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if pool.slots.load().len() == 1 && stats.calls.load(Ordering::Acquire) == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("initial min-size prefill should complete");

        let failed = pool.slots.load_full()[0].conn.clone();
        failed.mark_unavailable();

        tokio::time::timeout(Duration::from_millis(150), async {
            loop {
                let slots = pool.slots.load();
                if stats.calls.load(Ordering::Acquire) >= 2
                    && slots.len() == 1
                    && slots[0].connection().available()
                    && !Arc::ptr_eq(&slots[0].conn, &failed)
                {
                    break;
                }
                drop(slots);
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("async loss should immediately replenish min_size without a foreground query");

        assert_eq!(stats.calls.load(Ordering::Acquire), 2);
        assert_eq!(pool.acquire_waiters.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn test_async_unavailable_does_not_broadcast_query_waiters() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            1,
            4,
            TrackingBuilder::new(stats, Duration::from_millis(200), Duration::ZERO),
        );
        let existing = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        pool.register_connection_unavailable_notify(&existing);
        pool.slots.store(Arc::new(vec![Arc::new(PipelineSlot::new(
            existing.clone(),
        ))]));
        pool.acquire_waiters.store(10, Ordering::Release);

        let mut waiters = Vec::new();
        for _ in 0..10 {
            let notified = pool.release_notified.notified();
            waiters.push(Box::pin(notified));
        }
        for waiter in &mut waiters {
            waiter.as_mut().enable();
        }

        existing.mark_unavailable();
        tokio::time::sleep(Duration::from_millis(10)).await;

        let ready = waiters
            .into_iter()
            .filter_map(|waiter| waiter.now_or_never())
            .count();
        assert_eq!(ready, 0);
        pool.acquire_waiters.store(0, Ordering::Release);
    }

    #[test]
    fn test_paced_pruning_dead_slot_does_not_broadcast_query_waiters() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            1,
            4,
            TrackingBuilder::new(stats, Duration::ZERO, Duration::ZERO),
        );
        let dead = Arc::new(MockConnection::new(false, 0, AppClock::elapsed_millis()));
        pool.slots
            .store(Arc::new(vec![Arc::new(PipelineSlot::new(dead))]));

        let mut waiters = Vec::new();
        for _ in 0..10 {
            waiters.push(Box::pin(pool.release_notified.notified()));
        }
        for waiter in &mut waiters {
            waiter.as_mut().enable();
        }

        assert_eq!(pool.usable_or_inflight_slot_count(), 0);

        let ready = waiters
            .into_iter()
            .filter_map(|waiter| waiter.now_or_never())
            .count();
        assert_eq!(ready, 0);
    }

    #[tokio::test]
    async fn test_paced_maintenance_removal_does_not_broadcast_query_waiters() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            1,
            4,
            TrackingBuilder::new(stats, Duration::ZERO, Duration::ZERO),
        );
        let dead = Arc::new(MockConnection::new(false, 0, AppClock::elapsed_millis()));
        pool.slots
            .store(Arc::new(vec![Arc::new(PipelineSlot::new(dead))]));

        let mut waiters = Vec::new();
        for _ in 0..10 {
            waiters.push(Box::pin(pool.release_notified.notified()));
        }
        for waiter in &mut waiters {
            waiter.as_mut().enable();
        }

        pool.maintain().await;

        let ready = waiters
            .into_iter()
            .filter_map(|waiter| waiter.now_or_never())
            .count();
        assert_eq!(ready, 0);
        assert!(pool.slots.load().is_empty());
    }

    #[tokio::test]
    async fn test_async_unavailable_wakes_capacity_wait_without_fallback() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            1,
            1,
            TrackingBuilder::new(stats.clone(), Duration::ZERO, Duration::ZERO),
        );
        let existing = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        pool.register_connection_unavailable_notify(&existing);
        pool.slots.store(Arc::new(vec![Arc::new(PipelineSlot::new(
            existing.clone(),
        ))]));

        let held = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("existing connection should be acquirable");

        let waiter_pool = pool.clone();
        let waiter = tokio::spawn(async move {
            waiter_pool
                .acquire(QueryDeadline::new(Duration::from_millis(150)))
                .await
                .map(drop)
        });

        tokio::time::timeout(Duration::from_millis(50), async {
            loop {
                if pool.acquire_waiters.load(Ordering::Acquire) == 1
                    && pool.expansion_quiescent_at_capacity.load(Ordering::Acquire)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second acquire should wait at the hard cap");

        // Simulate an H2/H3/DoQ driver observing remote connection loss while
        // one stream lease is still held. The unavailable callback re-arms the
        // paced controller directly, but max_size remains occupied until
        // `held` drains.
        existing.mark_unavailable();
        tokio::time::timeout(Duration::from_millis(50), async {
            loop {
                if pool.expansion_worker_running.load(Ordering::Acquire)
                    && !pool.expansion_requested.load(Ordering::Acquire)
                    && !pool.expansion_quiescent_at_capacity.load(Ordering::Acquire)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("controller should observe asynchronous unavailability");

        // Give the worker time to reach its capacity wait. The old 250 ms
        // fallback path would then miss the final ACTIVE/unavailable drain and
        // let the 150 ms foreground deadline expire.
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(held);

        tokio::time::timeout(Duration::from_millis(100), waiter)
            .await
            .expect("replacement should not depend on a periodic fallback")
            .expect("waiter task should join")
            .expect("waiter should acquire the replacement connection");

        assert_eq!(stats.calls.load(Ordering::Acquire), 1);
        assert_eq!(pool.slots.load().len(), 1);
    }

    #[tokio::test]
    async fn test_inserted_multiplexed_capacity_wakes_only_matching_waiters() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            2,
            4,
            TrackingBuilder::new(stats, Duration::ZERO, Duration::ZERO),
        );
        pool.acquire_waiters.store(10, Ordering::Release);

        let mut waiters = Vec::new();
        for _ in 0..10 {
            let notified = pool.release_notified.notified();
            waiters.push(Box::pin(notified));
        }
        for waiter in &mut waiters {
            waiter.as_mut().enable();
        }

        let slot = PipelineSlot::new(Arc::new(MockConnection::new(
            true,
            0,
            AppClock::elapsed_millis(),
        )));
        pool.notify_inserted_query_capacity(&slot);

        let ready = waiters
            .into_iter()
            .filter_map(|waiter| waiter.now_or_never())
            .count();
        assert_eq!(ready, 4);
    }

    #[tokio::test]
    async fn test_paced_build_outlives_triggering_query_deadline() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            1,
            32,
            TrackingBuilder::new(stats.clone(), Duration::from_millis(80), Duration::ZERO),
        );

        let result = pool
            .query(
                Message::new(),
                QueryDeadline::new(Duration::from_millis(20)),
            )
            .await;
        assert!(
            result.is_err(),
            "triggering query should exhaust its own deadline"
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(stats.calls.load(Ordering::Acquire), 1);
        assert_eq!(pool.slots.load().len(), 1);
    }

    #[tokio::test]
    async fn test_soft_threshold_does_not_block_foreground_acquire() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            2,
            32,
            TrackingBuilder::new(stats.clone(), Duration::from_millis(100), Duration::ZERO),
        );
        let existing = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        pool.slots
            .store(Arc::new(vec![Arc::new(PipelineSlot::new(existing))]));

        let mut leases = Vec::new();
        for _ in 0..15 {
            leases.push(
                pool.acquire(QueryDeadline::new(Duration::from_secs(1)))
                    .await
                    .expect("pre-threshold acquire should succeed"),
            );
        }

        let sixteenth = tokio::time::timeout(
            Duration::from_millis(20),
            pool.acquire(QueryDeadline::new(Duration::from_secs(1))),
        )
        .await
        .expect("soft expansion must not delay the triggering acquire")
        .expect("threshold acquire should succeed");
        leases.push(sixteenth);

        tokio::time::sleep(Duration::from_millis(130)).await;
        assert_eq!(stats.calls.load(Ordering::Acquire), 1);
        assert_eq!(pool.slots.load().len(), 2);
        drop(leases);
    }

    #[tokio::test]
    async fn test_soft_expansion_uses_aggregate_pool_pressure() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            3,
            32,
            TrackingBuilder::new(stats.clone(), Duration::ZERO, Duration::ZERO),
        );
        let first = Arc::new(PipelineSlot::new(Arc::new(MockConnection::new(
            true,
            0,
            AppClock::elapsed_millis(),
        ))));
        let second = Arc::new(PipelineSlot::new(Arc::new(MockConnection::new(
            true,
            0,
            AppClock::elapsed_millis(),
        ))));
        for _ in 0..20 {
            assert!(first.try_acquire(32));
        }
        for _ in 0..2 {
            assert!(second.try_acquire(32));
        }
        pool.slots
            .store(Arc::new(vec![first.clone(), second.clone()]));

        pool.request_paced_expansion();
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(stats.calls.load(Ordering::Acquire), 0);
        assert_eq!(pool.slots.load().len(), 2);
        for _ in 0..20 {
            first.release_without_notify();
        }
        for _ in 0..2 {
            second.release_without_notify();
        }
    }

    #[tokio::test]
    async fn test_level_triggered_soft_probe_handles_dynamic_capacity_reduction() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            2,
            32,
            TrackingBuilder::new(stats.clone(), Duration::ZERO, Duration::ZERO),
        );
        let existing = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        pool.slots.store(Arc::new(vec![Arc::new(PipelineSlot::new(
            existing.clone(),
        ))]));

        let mut leases = Vec::new();
        for _ in 0..10 {
            leases.push(
                pool.acquire(QueryDeadline::new(Duration::from_secs(1)))
                    .await
                    .expect("initial acquire should succeed below the original soft threshold"),
            );
        }
        assert_eq!(stats.calls.load(Ordering::Acquire), 0);

        // Simulate an H2 peer reducing SETTINGS_MAX_CONCURRENT_STREAMS from at
        // least 32 to 16. The new soft threshold is 8, already below the
        // current ten in-flight borrows, so no exact threshold edge remains.
        existing.set_max_concurrent_queries(16);
        leases.push(
            pool.acquire(QueryDeadline::new(Duration::from_secs(1)))
                .await
                .expect("post-SETTINGS acquire should still use remaining capacity"),
        );

        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if pool.slots.load().len() == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("level-triggered probe should expand after dynamic capacity reduction");
        assert_eq!(stats.calls.load(Ordering::Acquire), 1);
        drop(leases);
    }

    #[tokio::test]
    async fn test_level_triggered_probe_preserves_aggregate_no_edge_expansion() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            3,
            32,
            TrackingBuilder::new(stats.clone(), Duration::ZERO, Duration::ZERO),
        );
        let first = Arc::new(PipelineSlot::new(Arc::new(MockConnection::new(
            true,
            0,
            AppClock::elapsed_millis(),
        ))));
        let second = Arc::new(PipelineSlot::new(Arc::new(MockConnection::new(
            true,
            0,
            AppClock::elapsed_millis(),
        ))));
        for _ in 0..20 {
            assert!(first.try_acquire(32));
        }

        for _ in 0..11 {
            assert!(second.try_acquire(32));
        }
        pool.slots
            .store(Arc::new(vec![first.clone(), second.clone()]));
        pool.index.store(0, Ordering::Relaxed);

        // Aggregate starts at 31/64. The next round-robin acquire lands on
        // conn1 and raises it from 20 to 21, so aggregate becomes 32/64 while
        // neither connection crosses the exact local 16-stream edge.
        let lease = pool
            .acquire(QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("level-triggered soft probe should not block foreground acquire");
        assert!(Arc::ptr_eq(&lease.slot, &first));

        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if pool.slots.load().len() == 3 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aggregate fifty-percent pressure should expand without an exact local edge");
        assert_eq!(stats.calls.load(Ordering::Acquire), 1);

        drop(lease);

        for _ in 0..20 {
            first.release_without_notify();
        }
        for _ in 0..11 {
            second.release_without_notify();
        }
    }

    #[tokio::test]
    async fn test_soft_probe_does_not_leave_background_polling_worker() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            2,
            32,
            TrackingBuilder::new(stats.clone(), Duration::ZERO, Duration::ZERO),
        );
        let first = Arc::new(PipelineSlot::new(Arc::new(MockConnection::new(
            true,
            0,
            AppClock::elapsed_millis(),
        ))));
        let second = Arc::new(PipelineSlot::new(Arc::new(MockConnection::new(
            true,
            0,
            AppClock::elapsed_millis(),
        ))));
        for _ in 0..20 {
            assert!(first.try_acquire(32));
        }
        pool.slots.store(Arc::new(vec![first.clone(), second]));

        // Local load is above 50%, but aggregate load is only 20/64. A soft
        // probe should run once and then let the worker go idle instead of
        // retaining the old 50ms Watch polling loop.
        pool.maybe_request_soft_expansion(20, 32);
        assert!(!pool.soft_probe_ready.load(Ordering::Acquire));
        for _ in 0..1_000 {
            pool.maybe_request_soft_expansion(20, 32);
        }
        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if !pool.expansion_worker_running.load(Ordering::Acquire) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("soft probe worker should return to idle when aggregate load is low");

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(!pool.expansion_worker_running.load(Ordering::Acquire));
        assert!(pool.soft_probe_ready.load(Ordering::Acquire));
        assert_eq!(stats.calls.load(Ordering::Acquire), 0);

        for _ in 0..20 {
            first.release_without_notify();
        }
    }

    #[tokio::test]
    async fn test_paced_worker_wakes_when_retiring_slot_frees_pool_capacity() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            1,
            32,
            TrackingBuilder::new(stats.clone(), Duration::ZERO, Duration::ZERO),
        );
        let retiring = Arc::new(PipelineSlot::new(Arc::new(MockConnection::new(
            true,
            0,
            AppClock::elapsed_millis(),
        ))));
        assert!(retiring.try_acquire(32));
        retiring.retire();
        pool.slots.store(Arc::new(vec![retiring.clone()]));

        // Keep the retiring slot's final in-flight borrow alive so max_size is
        // occupied but no connection can accept a new query.
        let retiring_lease = PipelineLease::new_paced(
            retiring,
            pool.release_notified.as_ref(),
            pool.expansion_capacity_notified.as_ref(),
            &pool.expansion_quiescent_at_capacity,
        );

        let waiting_pool = pool.clone();
        let waiter = tokio::spawn(async move {
            let lease = waiting_pool
                .acquire(QueryDeadline::new(Duration::from_secs(1)))
                .await?;
            drop(lease);
            Ok::<(), DnsError>(())
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            stats.calls.load(Ordering::Acquire),
            0,
            "replacement must wait while the retiring slot still occupies max_size"
        );

        // The final release broadcasts the dedicated pool-capacity event, so
        // the replacement build can start immediately without polling.
        drop(retiring_lease);
        tokio::time::timeout(Duration::from_millis(150), async {
            loop {
                if stats.calls.load(Ordering::Acquire) == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("capacity notification should wake paced expansion immediately");

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiting acquire should complete")
            .expect("waiting acquire task should join")
            .expect("waiting acquire should succeed");
        assert_eq!(stats.calls.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_paced_expansion_failure_backoff_caps_at_two_seconds() {
        let pool = make_pool(0, 1, 32, 30, MockBuilder::new(vec![]), vec![]);
        assert_eq!(pool.record_connect_failure_backoff(), 100);
        assert_eq!(pool.record_connect_failure_backoff(), 200);
        assert_eq!(pool.record_connect_failure_backoff(), 400);
        assert_eq!(pool.record_connect_failure_backoff(), 800);
        assert_eq!(pool.record_connect_failure_backoff(), 1_600);
        assert_eq!(pool.record_connect_failure_backoff(), 2_000);
        assert_eq!(pool.record_connect_failure_backoff(), 2_000);
    }

    #[tokio::test]
    async fn test_paced_worker_does_not_keep_pool_alive_during_backoff() {
        AppClock::start();
        let pool = PipelinePool::new_multiplexed(
            1,
            1,
            32,
            Duration::from_secs(30),
            Box::new(MockBuilder::new(vec![Err(DnsError::runtime(
                "planned connect failure",
            ))])),
            QueryTimeoutPolicy::Reuse,
            Duration::from_secs(1),
        );
        let weak = Arc::downgrade(&pool);

        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(pool);
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(
            weak.upgrade().is_none(),
            "backoff worker must not self-retain the pool"
        );
    }

    #[tokio::test]
    async fn test_paced_timeout_reports_recent_connection_failure() {
        AppClock::start();
        let pool = PipelinePool::new_multiplexed(
            0,
            1,
            32,
            Duration::from_secs(30),
            Box::new(MockBuilder::new(vec![
                Err(DnsError::runtime("planned connect failure")),
                Err(DnsError::runtime("planned connect failure")),
            ])),
            QueryTimeoutPolicy::Reuse,
            Duration::from_secs(1),
        );

        let error = pool
            .query(
                Message::new(),
                QueryDeadline::new(Duration::from_millis(250)),
            )
            .await
            .expect_err("query should expire while connection creation is backing off");
        let error = error.to_string();
        assert!(error.contains("DNS query timeout"));
        assert!(error.contains("planned connect failure"));
    }

    #[tokio::test]
    async fn test_paced_reservation_drop_does_not_wake_query_waiters() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            2,
            32,
            TrackingBuilder::new(stats, Duration::ZERO, Duration::ZERO),
        );

        let query_waiter = pool.release_notified.notified();
        tokio::pin!(query_waiter);
        query_waiter.as_mut().enable();
        let expansion_waiter = pool.expansion_capacity_notified.notified();
        tokio::pin!(expansion_waiter);
        expansion_waiter.as_mut().enable();

        let reservation = pool
            .try_reserve_slot()
            .expect("paced pool should reserve an expansion slot");
        drop(reservation);

        tokio::time::timeout(Duration::from_millis(50), expansion_waiter.as_mut())
            .await
            .expect("paced reservation release should wake the expansion controller");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), query_waiter.as_mut())
                .await
                .is_err(),
            "paced reservation release must not wake DNS query waiters without new stream capacity"
        );
    }

    #[tokio::test]
    async fn test_legacy_reservation_drop_still_wakes_query_waiters() {
        let pool = make_pool(0, 2, 32, 30, MockBuilder::new(vec![]), vec![]);
        let query_waiter = pool.release_notified.notified();
        tokio::pin!(query_waiter);
        query_waiter.as_mut().enable();
        let reservation = pool
            .try_reserve_slot()
            .expect("legacy pool should reserve an expansion slot");
        drop(reservation);

        tokio::time::timeout(Duration::from_millis(50), query_waiter.as_mut())
            .await
            .expect("legacy reservation release should preserve waiter wakeup semantics");
    }

    #[tokio::test]
    async fn test_paced_worker_recovers_after_builder_panic() {
        AppClock::start();
        let calls = Arc::new(AtomicUsize::new(0));
        let connection = Arc::new(MockConnection::new(true, 0, AppClock::elapsed_millis()));
        let pool = PipelinePool::new_multiplexed(
            0,
            1,
            32,
            Duration::from_secs(30),
            Box::new(PanicOnceBuilder {
                calls: calls.clone(),
                connection: connection.clone(),
            }),
            QueryTimeoutPolicy::Reuse,
            Duration::from_secs(1),
        );

        let response = tokio::time::timeout(
            Duration::from_secs(2),
            pool.query(Message::new(), QueryDeadline::new(Duration::from_secs(2))),
        )
        .await
        .expect("supervisor should recover before the query timeout")
        .expect("second connection attempt should succeed");
        assert_eq!(response.id(), 0);
        assert_eq!(calls.load(Ordering::Acquire), 2);
        assert_eq!(pool.slots.load().len(), 1);
        assert_eq!(pool.connect_failure_streak.load(Ordering::Acquire), 0);

        tokio::time::timeout(Duration::from_millis(200), async {
            while pool.expansion_worker_running.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("recovered worker should eventually publish the idle state");
    }

    #[tokio::test]
    async fn test_paced_worker_lifecycle_drop_rearms_cancelled_worker() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            1,
            32,
            TrackingBuilder::new(stats, Duration::ZERO, Duration::ZERO),
        );
        pool.expansion_worker_running.store(true, Ordering::Release);
        pool.expansion_requested.store(false, Ordering::Release);

        let notified = pool.release_notified.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let lifecycle = PacedExpansionWorkerLifecycle::new(Arc::downgrade(&pool));
        drop(lifecycle);

        assert!(!pool.expansion_worker_running.load(Ordering::Acquire));
        assert!(pool.expansion_requested.load(Ordering::Acquire));
        tokio::time::timeout(Duration::from_millis(50), notified.as_mut())
            .await
            .expect("abnormal worker drop should wake cold-pool query waiters");
    }
}
