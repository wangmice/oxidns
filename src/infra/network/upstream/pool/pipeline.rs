// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tokio::sync::Notify;
use tracing::{debug, warn};

use crate::infra::clock::AppClock;
use crate::infra::error::Result;
use crate::infra::network::metrics::UpstreamTimeoutStage;
use crate::infra::network::upstream::pool::{
    Connection, ConnectionBuilder, ConnectionPool, DeadlineOutcome, ManagedMaintenanceTask,
    QueryDeadline, QueryTimeoutPolicy, start_maintenance,
};
use crate::infra::task as task_center;
use crate::proto::Message;

const POOL_RETRY_BACKOFF: Duration = Duration::from_millis(10);
const MULTIPLEXED_EXPANSION_MIN_INTERVAL_MS: u64 = 50;
const MULTIPLEXED_SLOT_CAPACITY_FALLBACK_MS: u64 = 250;
const MULTIPLEXED_EXPANSION_BACKOFF_BASE_MS: u64 = 100;
const MULTIPLEXED_EXPANSION_BACKOFF_MAX_MS: u64 = 2_000;

#[derive(Debug, Clone, Copy)]
struct PacedExpansionPolicy;

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
    connection_builder: Box<dyn ConnectionBuilder<C>>,
    /// Per-query timeout policy for acquired slots.
    timeout_policy: QueryTimeoutPolicy,
    /// Timeout used only by background prefill/maintenance expansion.
    connect_timeout: Duration,
    /// Monotonic connection id source.
    next_id: AtomicU16,
    /// Notify query waiters when stream capacity changes.
    release_notified: Notify,
    /// Notify the paced expansion worker when a whole pool slot becomes
    /// reservable again. Kept separate from query wakeups to avoid a waiter
    /// stampede when a retiring slot finally drains.
    expansion_capacity_notified: Arc<Notify>,
    /// Background maintenance task registered in task center.
    maintenance_task_handle: Mutex<Option<task_center::ManagedTaskHandle>>,
    /// Multiplexed pools use a background paced expansion controller.
    paced_expansion: Option<PacedExpansionPolicy>,
    /// Weak self-reference used to spawn expansion workers without retaining the pool forever.
    self_weak: Weak<PipelinePool<C>>,
    /// A pressure change arrived while the expansion worker was running or exiting.
    expansion_requested: AtomicBool,
    /// Ensures at most one paced expansion worker exists for this pool.
    expansion_worker_running: AtomicBool,
    /// Queries currently waiting because no slot had usable capacity.
    acquire_waiters: AtomicUsize,
    /// Monotonic start time of the most recent connection build.
    last_expand_start_ms: AtomicU64,
    /// Earliest time another build may start after connection-creation failures.
    next_expand_at_ms: AtomicU64,
    /// Consecutive background connection-creation failures.
    connect_failure_streak: AtomicU32,
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
            self.release_notified.notify_waiters();
            self.expansion_capacity_notified.notify_waiters();
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
            self.release_notified.notify_waiters();
            self.expansion_capacity_notified.notify_waiters();
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
            connection_builder,
            timeout_policy,
            connect_timeout,
            next_id: AtomicU16::new(1),
            release_notified: Notify::new(),
            expansion_capacity_notified: Arc::new(Notify::new()),
            maintenance_task_handle: Mutex::new(None),
            paced_expansion,
            self_weak: weak.clone(),
            expansion_requested: AtomicBool::new(false),
            expansion_worker_running: AtomicBool::new(false),
            acquire_waiters: AtomicUsize::new(0),
            last_expand_start_ms: AtomicU64::new(u64::MAX),
            next_expand_at_ms: AtomicU64::new(0),
            connect_failure_streak: AtomicU32::new(0),
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
            return None;
        }

        let start_idx = self.index.fetch_add(1, Ordering::Relaxed) % len;
        for offset in 0..len {
            let idx = (start_idx + offset) % len;
            let slot = &slots[idx];
            if let Some(load) = slot.try_acquire_observed(self.max_load) {
                return Some(AcquiredSlot {
                    slot: slot.clone(),
                    inflight: load.inflight,
                    capacity: load.capacity,
                });
            }
        }

        None
    }

    async fn acquire_paced(&self, deadline: QueryDeadline) -> Result<PipelineLease<'_, C>> {
        if let Some(acquired) = self.try_acquire_existing_observed() {
            self.maybe_request_soft_expansion(acquired.inflight, acquired.capacity);
            return Ok(PipelineLease::new_paced(
                acquired.slot,
                &self.release_notified,
                self.expansion_capacity_notified.as_ref(),
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
                    &self.release_notified,
                    self.expansion_capacity_notified.as_ref(),
                ));
            }

            self.request_paced_expansion();
            match deadline.run(notified.as_mut()).await {
                DeadlineOutcome::Completed(()) => {}
                DeadlineOutcome::Expired => {
                    return Err(deadline.timeout_error_for(UpstreamTimeoutStage::PoolAcquire));
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
        if inflight == soft_threshold {
            self.request_paced_expansion();
        }
    }

    fn request_paced_expansion(&self) {
        if self.paced_expansion.is_none() {
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
            Self::run_paced_expansion_worker(weak).await;
        });
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

            match pool.paced_expansion_state() {
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
                PacedExpansionState::Watch => {
                    // A connection is already at or above its local 50% mark,
                    // but aggregate pool occupancy is still below 50%. Keep a
                    // low-frequency watch alive so load moving onto another,
                    // less-busy connection cannot cross the aggregate threshold
                    // without another local edge-trigger event.
                    drop(pool);
                    tokio::time::sleep(Duration::from_millis(
                        MULTIPLEXED_EXPANSION_MIN_INTERVAL_MS,
                    ))
                    .await;
                    continue;
                }
                PacedExpansionState::Expand => {}
            }

            let delay = pool.paced_expansion_delay();
            if !delay.is_zero() {
                drop(pool);
                tokio::time::sleep(delay).await;
                continue;
            }
            if pool.paced_expansion_state() != PacedExpansionState::Expand {
                continue;
            }

            let mut reservation = pool.try_reserve_slot();
            if reservation.is_none() {
                // A retiring/in-flight slot can temporarily occupy
                // max_size even though it cannot accept new queries.
                // Register before the final re-check to close the
                // notify-before-sleep race. The notifier is Arc-backed so
                // the worker can release its strong pool reference while
                // waiting. A low-frequency timer remains only as a safety
                // net for unexpected missed-notification paths.
                let capacity_changed = pool.expansion_capacity_notified.clone();
                let notified = capacity_changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                reservation = pool.try_reserve_slot();
                if reservation.is_none() {
                    // `SlotReservation` borrows `pool`. Consume the empty
                    // option before dropping the Arc so the borrow cannot be
                    // extended across the capacity wait.
                    drop(reservation);
                    drop(pool);
                    tokio::select! {
                        _ = notified.as_mut() => {}
                        _ = tokio::time::sleep(Duration::from_millis(
                            MULTIPLEXED_SLOT_CAPACITY_FALLBACK_MS,
                        )) => {}
                    }
                    continue;
                }
            }
            let Some(reservation) = reservation else {
                unreachable!("pipeline reservation was checked above");
            };
            if pool.paced_expansion_state() != PacedExpansionState::Expand {
                drop(reservation);
                continue;
            }
            pool.last_expand_start_ms
                .store(AppClock::elapsed_millis(), Ordering::Release);

            let deadline = QueryDeadline::background(pool.connect_timeout);
            match pool.expand_one(reservation, deadline).await {
                Ok(Some(_)) => {
                    pool.connect_failure_streak.store(0, Ordering::Release);
                    pool.next_expand_at_ms.store(0, Ordering::Release);
                }
                Ok(None) => {
                    // Capacity changed while the connection was being built.
                    // Re-evaluate instead of treating it as a transport failure.
                }
                Err(e) => {
                    let delay_ms = pool.record_connect_failure_backoff();
                    debug!(
                        delay_ms,
                        error = ?e,
                        "Multiplexed pipeline expansion failed; backing off"
                    );
                }
            }
        }
    }

    fn paced_expansion_state(&self) -> PacedExpansionState {
        let pressure = self.pool_pressure();
        if pressure.active_connections < self.min_size {
            return if pressure.active_connections < self.max_size {
                PacedExpansionState::Expand
            } else {
                PacedExpansionState::Idle
            };
        }
        if pressure.active_connections >= self.max_size {
            return PacedExpansionState::Idle;
        }

        let waiters = self.acquire_waiters.load(Ordering::Acquire);
        if waiters > pressure.free_capacity {
            return PacedExpansionState::Expand;
        }

        if pressure.total_capacity > 0
            && pressure.total_inflight.saturating_mul(2) >= pressure.total_capacity
        {
            return PacedExpansionState::Expand;
        }

        if pressure.has_half_loaded_connection {
            PacedExpansionState::Watch
        } else {
            PacedExpansionState::Idle
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
            if capacity_u16 > 1 && inflight >= capacity_u16.div_ceil(2) {
                pressure.has_half_loaded_connection = true;
            }
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
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        match deadline
            .run(self.connection_builder.create_connection(id, deadline))
            .await
        {
            DeadlineOutcome::Completed(Ok(conn)) => {
                let slot = Arc::new(PipelineSlot::new(conn));
                if self.insert_slot(slot.clone()) {
                    reservation.commit();
                    debug!(
                        "Pipeline pool expanded: total={}/{}",
                        self.slots.load().len(),
                        self.max_size
                    );
                    self.release_notified.notify_waiters();
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
            self.release_notified.notify_waiters();
            self.expansion_capacity_notified.notify_waiters();
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
    Watch,
    Expand,
}

#[derive(Debug, Default)]
struct PoolPressure {
    active_connections: usize,
    total_inflight: usize,
    total_capacity: usize,
    free_capacity: usize,
    has_half_loaded_connection: bool,
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
                    let drained_unusable = inflight == 1 && state != SLOT_ACTIVE;
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

    fn is_drained_unusable(&self) -> bool {
        let (state, inflight) = self.snapshot();
        inflight == 0 && (state != SLOT_ACTIVE || !self.conn.available())
    }
}

struct PipelineLease<'a, C: Connection> {
    slot: Arc<PipelineSlot<C>>,
    notify: &'a Notify,
    expansion_capacity_notify: Option<&'a Notify>,
}

impl<'a, C: Connection> PipelineLease<'a, C> {
    fn new(slot: Arc<PipelineSlot<C>>, notify: &'a Notify) -> Self {
        Self {
            slot,
            notify,
            expansion_capacity_notify: None,
        }
    }

    fn new_paced(
        slot: Arc<PipelineSlot<C>>,
        notify: &'a Notify,
        expansion_capacity_notify: &'a Notify,
    ) -> Self {
        Self {
            slot,
            notify,
            expansion_capacity_notify: Some(expansion_capacity_notify),
        }
    }

    fn connection(&self) -> &C {
        self.slot.connection()
    }

    fn retire(&self) {
        self.slot.retire();
        self.notify.notify_waiters();
    }

    fn close(&self) {
        self.slot.close();
        self.notify.notify_waiters();
    }
}

impl<C: Connection> Drop for PipelineLease<'_, C> {
    fn drop(&mut self) {
        if self.slot.release(self.notify)
            && let Some(notify) = self.expansion_capacity_notify
        {
            notify.notify_waiters();
        }
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
            self.pool.release_notified.notify_waiters();
            self.pool.expansion_capacity_notified.notify_waiters();
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

    #[derive(Debug)]
    struct MockConnection {
        available: AtomicBool,
        using_count: AtomicU32,
        last_used: AtomicU64,
        close_calls: AtomicUsize,
        max_concurrent_queries: AtomicU16,
        query_delay: Duration,
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
    }

    #[async_trait]
    impl Connection for MockConnection {
        fn close(&self) {
            self.close_calls.fetch_add(1, Ordering::Relaxed);
            self.available.store(false, Ordering::Relaxed);
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
            connection_builder: Box::new(builder),
            timeout_policy,
            connect_timeout: Duration::from_secs(5),
            next_id: AtomicU16::new(1),
            release_notified: Notify::new(),
            expansion_capacity_notified: Arc::new(Notify::new()),
            maintenance_task_handle: Mutex::new(None),
            paced_expansion: None,
            self_weak: Weak::new(),
            expansion_requested: AtomicBool::new(false),
            expansion_worker_running: AtomicBool::new(false),
            acquire_waiters: AtomicUsize::new(0),
            last_expand_start_ms: AtomicU64::new(u64::MAX),
            next_expand_at_ms: AtomicU64::new(0),
            connect_failure_streak: AtomicU32::new(0),
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
    async fn test_paced_cold_start_serializes_connection_builds() {
        let stats = Arc::new(BuilderStats::default());
        let pool = make_paced_pool(
            0,
            4,
            2,
            TrackingBuilder::new(
                stats.clone(),
                Duration::from_millis(20),
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

        assert_eq!(stats.max_active.load(Ordering::Acquire), 1);
        assert!(stats.calls.load(Ordering::Acquire) >= 2);
        assert!(pool.slots.load().len() >= 2);
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
    async fn test_soft_watch_catches_aggregate_threshold_without_new_local_edge() {
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
        pool.slots
            .store(Arc::new(vec![first.clone(), second.clone()]));

        // 20/64 is below aggregate 50%, but conn1 is already locally above
        // its 16/32 soft threshold. The worker must stay armed in Watch state.
        pool.request_paced_expansion();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(stats.calls.load(Ordering::Acquire), 0);
        assert_eq!(pool.paced_expansion_state(), PacedExpansionState::Watch);

        // Raise only conn2 to 12/32. No connection crosses a local 16-stream
        // edge here, yet aggregate load becomes exactly 32/64 = 50%.
        for _ in 0..12 {
            assert!(second.try_acquire(32));
        }
        assert_eq!(pool.paced_expansion_state(), PacedExpansionState::Expand);

        tokio::time::timeout(Duration::from_millis(150), async {
            loop {
                if stats.calls.load(Ordering::Acquire) == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("soft watch should detect aggregate threshold without a new local edge");
        assert_eq!(pool.slots.load().len(), 3);

        for _ in 0..20 {
            first.release_without_notify();
        }
        for _ in 0..12 {
            second.release_without_notify();
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
            &pool.release_notified,
            pool.expansion_capacity_notified.as_ref(),
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

        // The final release broadcasts the dedicated pool-capacity event. The
        // replacement build should start well before the 250ms fallback timer.
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
}
