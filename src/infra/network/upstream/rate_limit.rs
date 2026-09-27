// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, warn};

use crate::infra::clock::AppClock;
use crate::infra::error::{DnsError, Result};
use crate::infra::network::upstream::config::ConnectionInfo;
use crate::infra::network::upstream::pool::QueryDeadline;
use crate::infra::network::upstream::traits::Upstream;
use crate::proto::Message;

const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(60);
const MAX_SERVER_RETRY_AFTER: Duration = Duration::from_secs(300);
const CANCELLED_PROBE_RETRY: Duration = Duration::from_millis(500);
const COOLING_BIT: u64 = 1;
const GENERATION_MASK: u64 = u64::MAX >> 1;

#[derive(Debug)]
pub(crate) struct DohRateLimitedUpstream {
    inner: Box<dyn Upstream>,
    state: DohRateLimitState,
}

impl DohRateLimitedUpstream {
    pub(crate) fn new(inner: Box<dyn Upstream>) -> Self {
        Self {
            inner,
            state: DohRateLimitState::new(DEFAULT_INITIAL_BACKOFF, DEFAULT_MAX_BACKOFF),
        }
    }
}

#[async_trait]
impl Upstream for DohRateLimitedUpstream {
    async fn inner_query(&self, request: Message, deadline: QueryDeadline) -> Result<Message> {
        let mut permit = self.state.acquire()?;
        let result = self.inner.query_with_deadline(request, deadline).await;

        match &result {
            Ok(_) if permit.is_probe() => {
                if self.state.reset_after_probe_success(&permit) {
                    let info = self.inner.connection_info();
                    debug!(
                        upstream = %info.raw_addr,
                        upstream_tag = info.tag.as_deref().unwrap_or(""),
                        "DoH upstream rate-limit probe succeeded; cooldown cleared"
                    );
                }
                permit.complete();
            }
            Err(DnsError::DohRateLimited { retry_after, .. }) => {
                let observation = self.state.record_rate_limit(&permit, *retry_after);
                if observation.entered_new_cooldown {
                    let info = self.inner.connection_info();
                    warn!(
                        upstream = %info.raw_addr,
                        upstream_tag = info.tag.as_deref().unwrap_or(""),
                        cooldown_ms = observation.cooldown_ms,
                        retry_after_ms = observation.retry_after_ms,
                        backoff_streak = observation.backoff_streak,
                        "DoH upstream returned HTTP 429; entering rate-limit cooldown"
                    );
                }
                permit.complete();
            }
            Err(_) if permit.is_probe() => {
                self.state.rearm_probe(&permit);
                permit.complete();
            }
            _ => {}
        }

        result
    }

    async fn query_with_deadline(
        &self,
        request: Message,
        deadline: QueryDeadline,
    ) -> Result<Message> {
        // The wrapped upstream owns the actual deadline enforcement. Calling
        // the trait default here would perform a redundant `remaining()`
        // preflight before `inner_query` delegates the same deadline again.
        self.inner_query(request, deadline).await
    }

    fn connection_info(&self) -> &ConnectionInfo {
        self.inner.connection_info()
    }

    fn temporary_unavailable_for_ms(&self) -> Option<u64> {
        self.state.temporary_unavailable_for_ms()
    }

    fn handles_query_deadline(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct DohRateLimitState {
    state_word: AtomicU64,
    cooldown_until_ms: AtomicU64,
    probe_inflight: AtomicBool,
    slow: Mutex<SlowState>,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
}

#[derive(Debug, Default)]
struct SlowState {
    backoff_streak: u32,
}

impl DohRateLimitState {
    fn new(initial_backoff: Duration, max_backoff: Duration) -> Self {
        let initial_backoff_ms = duration_millis_u64(initial_backoff).max(1);
        let max_backoff_ms = duration_millis_u64(max_backoff).max(initial_backoff_ms);
        Self {
            state_word: AtomicU64::new(pack_state(0, false)),
            cooldown_until_ms: AtomicU64::new(0),
            probe_inflight: AtomicBool::new(false),
            slow: Mutex::new(SlowState::default()),
            initial_backoff_ms,
            max_backoff_ms,
        }
    }

    fn temporary_unavailable_for_ms(&self) -> Option<u64> {
        let word = self.state_word.load(Ordering::Acquire);
        if !is_cooling(word) {
            return None;
        }
        if self.probe_inflight.load(Ordering::Acquire) {
            return Some(1);
        }

        let now = AppClock::elapsed_millis();
        let until = self.cooldown_until_ms.load(Ordering::Acquire);
        (until > now).then_some(until - now)
    }

    fn acquire(&self) -> Result<RateLimitPermit<'_>> {
        loop {
            let word = self.state_word.load(Ordering::Acquire);
            let generation = state_generation(word);
            if !is_cooling(word) {
                return Ok(RateLimitPermit::normal(self, generation));
            }

            let now = AppClock::elapsed_millis();
            let until = self.cooldown_until_ms.load(Ordering::Acquire);
            if until > now {
                return Err(DnsError::rate_limit_cooldown(until - now));
            }

            if self
                .probe_inflight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(DnsError::rate_limit_cooldown(1));
            }

            let slow = self.lock_slow();
            let current_word = self.state_word.load(Ordering::Acquire);
            let now = AppClock::elapsed_millis();
            let latest_until = self.cooldown_until_ms.load(Ordering::Acquire);
            if current_word != word || latest_until > now {
                drop(slow);
                self.probe_inflight.store(false, Ordering::Release);
                continue;
            }
            drop(slow);

            return Ok(RateLimitPermit::probe(self, generation));
        }
    }

    fn record_rate_limit(
        &self,
        permit: &RateLimitPermit<'_>,
        retry_after: Option<Duration>,
    ) -> RateLimitObservation {
        let now = AppClock::elapsed_millis();
        let retry_after_ms = retry_after
            .map(|duration| duration.min(MAX_SERVER_RETRY_AFTER))
            .map(duration_millis_u64)
            .unwrap_or(0);
        let mut slow = self.lock_slow();
        let word = self.state_word.load(Ordering::Acquire);
        let current_generation = state_generation(word);

        if permit.is_probe() {
            if !is_cooling(word) || permit.generation != current_generation {
                return RateLimitObservation::ignored(retry_after_ms, slow.backoff_streak);
            }
            return self.enter_cooldown(&mut slow, current_generation, now, retry_after_ms);
        }

        if !is_cooling(word) && permit.generation == current_generation {
            return self.enter_cooldown(&mut slow, current_generation, now, retry_after_ms);
        }

        if is_cooling(word)
            && next_generation(permit.generation) == current_generation
            && !self.probe_inflight.load(Ordering::Acquire)
        {
            let requested_until = now.saturating_add(retry_after_ms);
            let current_until = self.cooldown_until_ms.load(Ordering::Acquire);
            if requested_until > current_until {
                self.cooldown_until_ms
                    .store(requested_until, Ordering::Release);
            }
            return RateLimitObservation {
                entered_new_cooldown: false,
                cooldown_ms: current_until.max(requested_until).saturating_sub(now),
                retry_after_ms,
                backoff_streak: slow.backoff_streak,
            };
        }

        RateLimitObservation::ignored(retry_after_ms, slow.backoff_streak)
    }

    fn enter_cooldown(
        &self,
        slow: &mut SlowState,
        generation: u64,
        now: u64,
        retry_after_ms: u64,
    ) -> RateLimitObservation {
        let streak_before = slow.backoff_streak;
        slow.backoff_streak = slow.backoff_streak.saturating_add(1);
        let local_backoff_ms = self.backoff_for_streak(streak_before);
        let cooldown_ms = local_backoff_ms.max(retry_after_ms).max(1);
        self.cooldown_until_ms
            .store(now.saturating_add(cooldown_ms), Ordering::Release);
        self.state_word.store(
            pack_state(next_generation(generation), true),
            Ordering::Release,
        );

        RateLimitObservation {
            entered_new_cooldown: true,
            cooldown_ms,
            retry_after_ms,
            backoff_streak: slow.backoff_streak,
        }
    }

    fn reset_after_probe_success(&self, permit: &RateLimitPermit<'_>) -> bool {
        let mut slow = self.lock_slow();
        let word = self.state_word.load(Ordering::Acquire);
        if !permit.is_probe() || !is_cooling(word) || permit.generation != state_generation(word) {
            return false;
        }

        slow.backoff_streak = 0;
        self.cooldown_until_ms.store(0, Ordering::Release);
        self.state_word.store(
            pack_state(next_generation(permit.generation), false),
            Ordering::Release,
        );
        true
    }

    fn rearm_probe(&self, permit: &RateLimitPermit<'_>) {
        let slow = self.lock_slow();
        let word = self.state_word.load(Ordering::Acquire);
        if !permit.is_probe() || !is_cooling(word) || permit.generation != state_generation(word) {
            return;
        }

        let streak_index = slow.backoff_streak.saturating_sub(1);
        let delay_ms = self.backoff_for_streak(streak_index);
        let now = AppClock::elapsed_millis();
        self.cooldown_until_ms
            .store(now.saturating_add(delay_ms), Ordering::Release);
    }

    fn rearm_cancelled_probe(&self, generation: u64) {
        let _slow = self.lock_slow();
        let word = self.state_word.load(Ordering::Acquire);
        if !is_cooling(word) || generation != state_generation(word) {
            return;
        }

        let delay_ms = duration_millis_u64(CANCELLED_PROBE_RETRY);
        let now = AppClock::elapsed_millis();
        let requested_until = now.saturating_add(delay_ms);
        let current_until = self.cooldown_until_ms.load(Ordering::Acquire);
        if requested_until > current_until {
            self.cooldown_until_ms
                .store(requested_until, Ordering::Release);
        }
    }

    fn backoff_for_streak(&self, streak: u32) -> u64 {
        let shift = streak.min(31);
        self.initial_backoff_ms
            .saturating_mul(1_u64 << shift)
            .min(self.max_backoff_ms)
    }

    fn lock_slow(&self) -> MutexGuard<'_, SlowState> {
        self.slow
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Debug)]
struct RateLimitObservation {
    entered_new_cooldown: bool,
    cooldown_ms: u64,
    retry_after_ms: u64,
    backoff_streak: u32,
}

impl RateLimitObservation {
    fn ignored(retry_after_ms: u64, backoff_streak: u32) -> Self {
        Self {
            entered_new_cooldown: false,
            cooldown_ms: 0,
            retry_after_ms,
            backoff_streak,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PermitKind {
    Normal,
    Probe,
}

#[derive(Debug)]
struct RateLimitPermit<'a> {
    state: &'a DohRateLimitState,
    generation: u64,
    kind: PermitKind,
    completed: bool,
}

impl<'a> RateLimitPermit<'a> {
    fn normal(state: &'a DohRateLimitState, generation: u64) -> Self {
        Self {
            state,
            generation,
            kind: PermitKind::Normal,
            completed: false,
        }
    }

    fn probe(state: &'a DohRateLimitState, generation: u64) -> Self {
        Self {
            state,
            generation,
            kind: PermitKind::Probe,
            completed: false,
        }
    }

    fn is_probe(&self) -> bool {
        self.kind == PermitKind::Probe
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for RateLimitPermit<'_> {
    fn drop(&mut self) {
        if !self.is_probe() {
            return;
        }
        if !self.completed {
            self.state.rearm_cancelled_probe(self.generation);
        }
        self.state.probe_inflight.store(false, Ordering::Release);
    }
}

fn pack_state(generation: u64, cooling: bool) -> u64 {
    ((generation & GENERATION_MASK) << 1) | if cooling { 1 } else { 0 }
}

fn state_generation(word: u64) -> u64 {
    word >> 1
}

fn is_cooling(word: u64) -> bool {
    word & COOLING_BIT != 0
}

fn next_generation(generation: u64) -> u64 {
    generation.wrapping_add(1) & GENERATION_MASK
}

fn duration_millis_u64(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> DohRateLimitState {
        AppClock::start();
        DohRateLimitState::new(Duration::from_millis(100), Duration::from_millis(600))
    }

    #[test]
    fn healthy_fast_path_does_not_enter_cooldown() {
        let state = state();
        let permit = state.acquire().expect("healthy query should be admitted");
        assert!(!permit.is_probe());
        assert_eq!(state.temporary_unavailable_for_ms(), None);
    }

    #[test]
    fn same_429_wave_does_not_escalate_backoff_repeatedly() {
        let state = state();
        let first = state.acquire().expect("first query should be admitted");
        let second = state.acquire().expect("second query should be admitted");

        let first_observation = state.record_rate_limit(&first, None);
        let second_observation = state.record_rate_limit(&second, None);

        assert!(first_observation.entered_new_cooldown);
        assert!(!second_observation.entered_new_cooldown);
        assert_eq!(state.lock_slow().backoff_streak, 1);
    }

    #[test]
    fn stale_429_cannot_reclose_after_probe_success() {
        let state = state();
        let old = state.acquire().expect("old query should be admitted");
        state.record_rate_limit(&old, None);
        state.cooldown_until_ms.store(0, Ordering::Release);

        let mut probe = state.acquire().expect("probe should be admitted");
        assert!(probe.is_probe());
        assert!(state.reset_after_probe_success(&probe));
        probe.complete();
        drop(probe);

        let stale = state.record_rate_limit(&old, Some(Duration::from_secs(5)));
        assert!(!stale.entered_new_cooldown);
        assert!(!is_cooling(state.state_word.load(Ordering::Acquire)));
        assert_eq!(state.lock_slow().backoff_streak, 0);
    }

    #[test]
    fn probe_429_advances_exactly_one_backoff_generation() {
        let state = state();
        let first = state.acquire().expect("query should be admitted");
        state.record_rate_limit(&first, None);
        state.cooldown_until_ms.store(0, Ordering::Release);

        let mut probe = state.acquire().expect("probe should be admitted");
        let observation = state.record_rate_limit(&probe, None);
        probe.complete();

        assert!(observation.entered_new_cooldown);
        assert_eq!(observation.backoff_streak, 2);
        assert_eq!(observation.cooldown_ms, 200);
    }

    #[test]
    fn retry_after_is_capped() {
        let state = state();
        let permit = state.acquire().expect("query should be admitted");
        let observation = state.record_rate_limit(&permit, Some(Duration::from_secs(86_400)));

        assert_eq!(
            observation.retry_after_ms,
            duration_millis_u64(MAX_SERVER_RETRY_AFTER)
        );
        assert_eq!(
            observation.cooldown_ms,
            duration_millis_u64(MAX_SERVER_RETRY_AFTER)
        );
    }

    #[test]
    fn cancelled_probe_is_rearmed_and_gate_is_released() {
        let state = state();
        let first = state.acquire().expect("query should be admitted");
        state.record_rate_limit(&first, None);
        state.cooldown_until_ms.store(0, Ordering::Release);

        let probe = state.acquire().expect("probe should be admitted");
        assert!(probe.is_probe());
        let before_drop_ms = AppClock::elapsed_millis();
        drop(probe);

        assert!(!state.probe_inflight.load(Ordering::Acquire));
        assert!(is_cooling(state.state_word.load(Ordering::Acquire)));
        let cooldown_until_ms = state.cooldown_until_ms.load(Ordering::Acquire);
        assert!(
            cooldown_until_ms
                >= before_drop_ms.saturating_add(duration_millis_u64(CANCELLED_PROBE_RETRY))
        );
        let remaining_ms = cooldown_until_ms.saturating_sub(AppClock::elapsed_millis());
        assert!(remaining_ms <= duration_millis_u64(CANCELLED_PROBE_RETRY));
    }
}
