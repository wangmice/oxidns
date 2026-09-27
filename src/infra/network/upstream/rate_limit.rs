// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::atomic::{AtomicU64, Ordering};
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
const BACKOFF_STREAK_SHIFT: u32 = 1;
const BACKOFF_STREAK_BITS: u32 = 6;
const BACKOFF_STREAK_VALUE_MASK: u64 = (1_u64 << BACKOFF_STREAK_BITS) - 1;
const BACKOFF_STREAK_MASK: u64 = BACKOFF_STREAK_VALUE_MASK << BACKOFF_STREAK_SHIFT;
const GENERATION_SHIFT: u32 = BACKOFF_STREAK_SHIFT + BACKOFF_STREAK_BITS;
const GENERATION_MASK: u64 = u64::MAX >> GENERATION_SHIFT;

// Low 40 bits hold process-relative milliseconds (~34 years). Upper 24 bits
// tag the state generation that owns the deadline.
const COOLDOWN_GENERATION_SHIFT: u32 = 40;
const COOLDOWN_UNTIL_MASK: u64 = (1_u64 << COOLDOWN_GENERATION_SHIFT) - 1;
const COOLDOWN_GENERATION_MASK: u64 = u64::MAX >> COOLDOWN_GENERATION_SHIFT;

const PROBE_PHASE_BITS: u32 = 2;
const PROBE_PHASE_MASK: u64 = (1_u64 << PROBE_PHASE_BITS) - 1;
const PROBE_EPOCH_SHIFT: u32 = PROBE_PHASE_BITS;
const PROBE_EPOCH_MASK: u64 = u64::MAX >> PROBE_EPOCH_SHIFT;

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
        if permit.is_probe() {
            self.state.begin_probe_io(&mut permit)?;
        }
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
    cooldown_word: AtomicU64,
    probe_word: AtomicU64,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u64)]
enum ProbePhase {
    Idle = 0,
    Active = 1,
    Committing = 2,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProbeInvalidation {
    SuccessCommitting,
    ActiveInvalidated { guard_epoch: u64 },
    NoActiveProbe,
}

impl DohRateLimitState {
    fn new(initial_backoff: Duration, max_backoff: Duration) -> Self {
        let initial_backoff_ms = duration_millis_u64(initial_backoff).max(1);
        let max_backoff_ms = duration_millis_u64(max_backoff).max(initial_backoff_ms);
        Self {
            state_word: AtomicU64::new(pack_state(0, false, 0)),
            cooldown_word: AtomicU64::new(pack_cooldown(0, 0)),
            probe_word: AtomicU64::new(pack_probe(0, ProbePhase::Idle)),
            initial_backoff_ms,
            max_backoff_ms,
        }
    }

    fn temporary_unavailable_for_ms(&self) -> Option<u64> {
        let word = self.state_word.load(Ordering::Acquire);
        let generation = state_generation(word);
        if !is_cooling(word) {
            return None;
        }
        if probe_phase(self.probe_word.load(Ordering::Acquire)) != ProbePhase::Idle {
            return Some(1);
        }

        let cooldown = self.cooldown_word.load(Ordering::Acquire);
        if !cooldown_matches_generation(cooldown, generation) {
            return Some(1);
        }
        let now = AppClock::elapsed_millis();
        let until = cooldown_until_ms(cooldown);
        until.checked_sub(now).filter(|remaining| *remaining != 0)
    }

    fn acquire(&self) -> Result<RateLimitPermit<'_>> {
        loop {
            let word = self.state_word.load(Ordering::Acquire);
            let generation = state_generation(word);
            if !is_cooling(word) {
                return Ok(RateLimitPermit::normal(self, generation));
            }

            let cooldown = self.cooldown_word.load(Ordering::Acquire);
            if !cooldown_matches_generation(cooldown, generation) {
                return Err(DnsError::rate_limit_cooldown(1));
            }
            let now = AppClock::elapsed_millis();
            let until = cooldown_until_ms(cooldown);
            if until > now {
                return Err(DnsError::rate_limit_cooldown(until - now));
            }

            let Some(probe_epoch) = self.reserve_probe() else {
                return Err(DnsError::rate_limit_cooldown(1));
            };

            let current_word = self.state_word.load(Ordering::Acquire);
            let latest_cooldown = self.cooldown_word.load(Ordering::Acquire);
            let now = AppClock::elapsed_millis();
            if current_word != word
                || self.probe_word.load(Ordering::Acquire)
                    != pack_probe(probe_epoch, ProbePhase::Active)
                || !cooldown_matches_generation(latest_cooldown, generation)
                || cooldown_until_ms(latest_cooldown) > now
            {
                self.release_probe_slot(probe_epoch);
                continue;
            }

            return Ok(RateLimitPermit::probe(self, generation, probe_epoch));
        }
    }

    fn begin_probe_io(&self, permit: &mut RateLimitPermit<'_>) -> Result<()> {
        debug_assert!(permit.is_probe());
        let expected_probe = pack_probe(permit.probe_epoch, ProbePhase::Active);
        let word = self.state_word.load(Ordering::Acquire);
        let cooldown = self.cooldown_word.load(Ordering::Acquire);
        let now = AppClock::elapsed_millis();

        if self.probe_word.load(Ordering::Acquire) != expected_probe
            || !is_cooling(word)
            || state_generation(word) != permit.generation
            || !cooldown_matches_generation(cooldown, permit.generation)
            || cooldown_until_ms(cooldown) > now
        {
            self.release_probe_slot(permit.probe_epoch);
            let retry_after_ms = if cooldown_matches_generation(cooldown, permit.generation) {
                cooldown_until_ms(cooldown).saturating_sub(now).max(1)
            } else {
                1
            };
            return Err(DnsError::rate_limit_cooldown(retry_after_ms));
        }

        permit.in_flight = true;
        Ok(())
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

        loop {
            let word = self.state_word.load(Ordering::Acquire);
            let current_generation = state_generation(word);
            let backoff_streak = state_backoff_streak(word);

            if permit.is_probe() {
                if !is_cooling(word) {
                    return RateLimitObservation::ignored(retry_after_ms, backoff_streak);
                }
                if permit.generation != current_generation {
                    return self.record_cooling_rate_limit(current_generation, now, retry_after_ms);
                }

                // Generation ownership alone is not sufficient for a probe:
                // a same-wave 429 may already have invalidated this permit's
                // probe epoch while leaving the cooldown generation intact.
                if !self.try_claim_probe_rate_limit(permit) {
                    return self.record_invalidated_probe_rate_limit(
                        current_generation,
                        backoff_streak,
                        now,
                        retry_after_ms,
                    );
                }

                if let Some(observation) =
                    self.try_enter_cooldown(word, current_generation, now, retry_after_ms)
                {
                    return observation;
                }
                self.revert_probe_commit_claim(permit.probe_epoch);
                continue;
            }

            if !is_cooling(word) && permit.generation == current_generation {
                if let Some(observation) =
                    self.try_enter_cooldown(word, current_generation, now, retry_after_ms)
                {
                    return observation;
                }
                continue;
            }

            if is_cooling(word) {
                return self.record_cooling_rate_limit(current_generation, now, retry_after_ms);
            }

            return RateLimitObservation::ignored(retry_after_ms, backoff_streak);
        }
    }

    fn record_cooling_rate_limit(
        &self,
        generation: u64,
        now: u64,
        retry_after_ms: u64,
    ) -> RateLimitObservation {
        let word = self.state_word.load(Ordering::Acquire);
        if !is_cooling(word) || state_generation(word) != generation {
            return RateLimitObservation::ignored(retry_after_ms, state_backoff_streak(word));
        }
        let backoff_streak = state_backoff_streak(word);

        let invalidation = self.invalidate_active_probe();

        let current_until = self.cooldown_until_for_generation(generation).unwrap_or(0);
        let local_rearm_ms = if current_until <= now {
            self.backoff_for_streak(backoff_streak.saturating_sub(1))
        } else {
            0
        };
        let requested_until = now.saturating_add(retry_after_ms.max(local_rearm_ms));
        let previous_generation = previous_generation(generation);
        let Some(cooldown_until) =
            self.advance_cooldown_generation(previous_generation, generation, requested_until)
        else {
            self.finish_probe_invalidation(invalidation);
            return RateLimitObservation::ignored(retry_after_ms, backoff_streak);
        };
        self.finish_probe_invalidation(invalidation);

        if invalidation == ProbeInvalidation::NoActiveProbe {
            // Catch a probe reservation that raced with the deadline update.
            let raced = self.invalidate_active_probe();
            self.finish_probe_invalidation(raced);
        }

        RateLimitObservation {
            entered_new_cooldown: false,
            cooldown_ms: cooldown_until.saturating_sub(now),
            retry_after_ms,
            backoff_streak,
        }
    }

    fn record_invalidated_probe_rate_limit(
        &self,
        generation: u64,
        backoff_streak: u32,
        now: u64,
        retry_after_ms: u64,
    ) -> RateLimitObservation {
        let word = self.state_word.load(Ordering::Acquire);
        if !is_cooling(word) || state_generation(word) != generation {
            return RateLimitObservation::ignored(retry_after_ms, state_backoff_streak(word));
        }

        // The probe is stale, so it must not advance either generation or
        // streak. Its 429 is still a useful server signal, however: it may
        // extend the current cooldown, but it can never shorten a deadline
        // that was already published by the request which invalidated it.
        let current_until = self.cooldown_until_for_generation(generation).unwrap_or(0);
        let local_rearm_ms = if current_until <= now {
            self.backoff_for_streak(backoff_streak.saturating_sub(1))
        } else {
            0
        };
        let requested_until = now.saturating_add(retry_after_ms.max(local_rearm_ms));
        let Some(cooldown_until) = self.extend_cooldown_for_generation(generation, requested_until)
        else {
            return RateLimitObservation::ignored(retry_after_ms, backoff_streak);
        };

        RateLimitObservation {
            entered_new_cooldown: false,
            cooldown_ms: cooldown_until.saturating_sub(now),
            retry_after_ms,
            backoff_streak,
        }
    }

    fn try_enter_cooldown(
        &self,
        expected_word: u64,
        generation: u64,
        now: u64,
        retry_after_ms: u64,
    ) -> Option<RateLimitObservation> {
        let streak_before = state_backoff_streak(expected_word);
        let backoff_streak = streak_before
            .saturating_add(1)
            .min(BACKOFF_STREAK_VALUE_MASK as u32);
        let local_backoff_ms = self.backoff_for_streak(streak_before);
        let cooldown_ms = local_backoff_ms.max(retry_after_ms).max(1);
        let next_generation = next_generation(generation);
        let next_word = pack_state(next_generation, true, backoff_streak);

        self.state_word
            .compare_exchange(
                expected_word,
                next_word,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;

        let cooldown_until = now.saturating_add(cooldown_ms);
        let Some(published_until) =
            self.advance_cooldown_generation(generation, next_generation, cooldown_until)
        else {
            // Do not leave state and deadline ownership permanently split if
            // publication cannot complete.
            let _ = self.state_word.compare_exchange(
                next_word,
                expected_word,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return None;
        };

        Some(RateLimitObservation {
            entered_new_cooldown: true,
            cooldown_ms: published_until.saturating_sub(now),
            retry_after_ms,
            backoff_streak,
        })
    }

    fn reset_after_probe_success(&self, permit: &RateLimitPermit<'_>) -> bool {
        if !self.try_claim_probe_success(permit) {
            return false;
        }

        let cooldown = self.cooldown_word.load(Ordering::Acquire);
        let word = self.state_word.load(Ordering::Acquire);
        let now = AppClock::elapsed_millis();
        if !permit.is_probe()
            || !is_cooling(word)
            || permit.generation != state_generation(word)
            || !cooldown_matches_generation(cooldown, permit.generation)
            || cooldown_until_ms(cooldown) > now
        {
            self.revert_probe_commit_claim(permit.probe_epoch);
            return false;
        }

        let previous_until = cooldown_until_ms(cooldown);
        let next_generation = next_generation(permit.generation);
        if !self.clear_cooldown_generation(cooldown, permit.generation, next_generation) {
            self.revert_probe_commit_claim(permit.probe_epoch);
            return false;
        }

        let next_word = pack_state(next_generation, false, 0);
        match self
            .state_word
            .compare_exchange(word, next_word, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(_) => {
                // `Committing` prevents a same-wave 429 from taking ownership
                // during the success transition, so restoring the old owner is
                // safe if the state CAS unexpectedly loses.
                let _ = self.restore_cooldown_generation(
                    next_generation,
                    permit.generation,
                    previous_until,
                );
                self.revert_probe_commit_claim(permit.probe_epoch);
                false
            }
        }
    }

    fn rearm_probe(&self, permit: &RateLimitPermit<'_>) {
        let word = self.state_word.load(Ordering::Acquire);
        if !permit.is_probe()
            || !permit.in_flight
            || !is_cooling(word)
            || permit.generation != state_generation(word)
            || self.probe_word.load(Ordering::Acquire)
                != pack_probe(permit.probe_epoch, ProbePhase::Active)
        {
            return;
        }

        let streak_index = state_backoff_streak(word).saturating_sub(1);
        let delay_ms = self.backoff_for_streak(streak_index);
        let now = AppClock::elapsed_millis();
        let _ =
            self.extend_cooldown_for_generation(permit.generation, now.saturating_add(delay_ms));
    }

    fn rearm_cancelled_probe(&self, permit: &RateLimitPermit<'_>) {
        let word = self.state_word.load(Ordering::Acquire);
        if !is_cooling(word)
            || permit.generation != state_generation(word)
            || self.probe_word.load(Ordering::Acquire)
                != pack_probe(permit.probe_epoch, ProbePhase::Active)
        {
            return;
        }

        let delay_ms = duration_millis_u64(CANCELLED_PROBE_RETRY);
        let now = AppClock::elapsed_millis();
        let requested_until = now.saturating_add(delay_ms);
        let _ = self.extend_cooldown_for_generation(permit.generation, requested_until);
    }

    fn backoff_for_streak(&self, streak: u32) -> u64 {
        let shift = streak.min(31);
        self.initial_backoff_ms
            .saturating_mul(1_u64 << shift)
            .min(self.max_backoff_ms)
    }

    fn reserve_probe(&self) -> Option<u64> {
        loop {
            let current = self.probe_word.load(Ordering::Acquire);
            if probe_phase(current) != ProbePhase::Idle {
                return None;
            }
            let epoch = next_probe_epoch(probe_epoch(current));
            let active = pack_probe(epoch, ProbePhase::Active);
            match self.probe_word.compare_exchange_weak(
                current,
                active,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(epoch),
                Err(_) => continue,
            }
        }
    }

    /// Release only the probe slot owned by `epoch`.
    ///
    /// A stale permit may run `Drop` after another request has already
    /// reserved a newer epoch. Matching the epoch makes release idempotent and
    /// prevents the stale owner from clearing the newer request's slot.
    fn release_probe_slot(&self, epoch: u64) {
        loop {
            let current = self.probe_word.load(Ordering::Acquire);
            if probe_epoch(current) != epoch {
                return;
            }
            match probe_phase(current) {
                ProbePhase::Active | ProbePhase::Committing => {
                    let idle = pack_probe(epoch, ProbePhase::Idle);
                    if self
                        .probe_word
                        .compare_exchange_weak(current, idle, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return;
                    }
                }
                ProbePhase::Idle => return,
            }
        }
    }

    fn finish_probe_invalidation(&self, invalidation: ProbeInvalidation) {
        if let ProbeInvalidation::ActiveInvalidated { guard_epoch } = invalidation {
            self.release_probe_slot(guard_epoch);
        }
    }

    fn invalidate_active_probe(&self) -> ProbeInvalidation {
        loop {
            let current = self.probe_word.load(Ordering::Acquire);
            match probe_phase(current) {
                ProbePhase::Committing => return ProbeInvalidation::SuccessCommitting,
                ProbePhase::Active => {
                    let guard_epoch = next_probe_epoch(probe_epoch(current));
                    let invalidated = pack_probe(guard_epoch, ProbePhase::Active);
                    if self
                        .probe_word
                        .compare_exchange_weak(
                            current,
                            invalidated,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return ProbeInvalidation::ActiveInvalidated { guard_epoch };
                    }
                }
                ProbePhase::Idle => return ProbeInvalidation::NoActiveProbe,
            }
        }
    }

    fn try_claim_probe_rate_limit(&self, permit: &RateLimitPermit<'_>) -> bool {
        if !permit.is_probe() || !permit.in_flight {
            return false;
        }

        self.probe_word
            .compare_exchange(
                pack_probe(permit.probe_epoch, ProbePhase::Active),
                pack_probe(permit.probe_epoch, ProbePhase::Committing),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn try_claim_probe_success(&self, permit: &RateLimitPermit<'_>) -> bool {
        if !permit.is_probe() || !permit.in_flight {
            return false;
        }

        let word = self.state_word.load(Ordering::Acquire);
        let cooldown = self.cooldown_word.load(Ordering::Acquire);
        let now = AppClock::elapsed_millis();
        if !is_cooling(word)
            || state_generation(word) != permit.generation
            || !cooldown_matches_generation(cooldown, permit.generation)
            || cooldown_until_ms(cooldown) > now
        {
            return false;
        }

        let active = pack_probe(permit.probe_epoch, ProbePhase::Active);
        let committing = pack_probe(permit.probe_epoch, ProbePhase::Committing);
        if self
            .probe_word
            .compare_exchange(active, committing, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }

        // A late same-wave 429 may have extended cooldown just before the
        // success claim. Recheck after the CAS so the newer server signal wins
        // if it was already published.
        let current_word = self.state_word.load(Ordering::Acquire);
        let latest_cooldown = self.cooldown_word.load(Ordering::Acquire);
        let now = AppClock::elapsed_millis();
        if !is_cooling(current_word)
            || state_generation(current_word) != permit.generation
            || !cooldown_matches_generation(latest_cooldown, permit.generation)
            || cooldown_until_ms(latest_cooldown) > now
        {
            self.revert_probe_commit_claim(permit.probe_epoch);
            return false;
        }
        true
    }

    fn revert_probe_commit_claim(&self, epoch: u64) {
        let _ = self.probe_word.compare_exchange(
            pack_probe(epoch, ProbePhase::Committing),
            pack_probe(epoch, ProbePhase::Active),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn cooldown_until_for_generation(&self, generation: u64) -> Option<u64> {
        let cooldown = self.cooldown_word.load(Ordering::Acquire);
        cooldown_matches_generation(cooldown, generation).then_some(cooldown_until_ms(cooldown))
    }

    /// Publish or extend the deadline for the current cooling generation.
    ///
    /// The caller must name both the immediately previous generation and the
    /// current generation. This lets a same-wave request help finish the
    /// publication window after another request has already advanced
    /// `state_word`, while preventing an old writer from retagging a deadline
    /// after the state has moved on again.
    fn advance_cooldown_generation(
        &self,
        previous_generation: u64,
        generation: u64,
        requested_until_ms: u64,
    ) -> Option<u64> {
        loop {
            let state = self.state_word.load(Ordering::Acquire);
            if !is_cooling(state) || state_generation(state) != generation {
                return None;
            }

            let current = self.cooldown_word.load(Ordering::Acquire);
            if cooldown_matches_generation(current, generation) {
                let current_until = cooldown_until_ms(current);
                if requested_until_ms <= current_until {
                    return Some(current_until);
                }
                let next = pack_cooldown(generation, requested_until_ms);
                match self.cooldown_word.compare_exchange_weak(
                    current,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Some(cooldown_until_ms(next)),
                    Err(_) => continue,
                }
            }

            if !cooldown_matches_generation(current, previous_generation) {
                return None;
            }

            let next = pack_cooldown(
                generation,
                requested_until_ms.max(cooldown_until_ms(current)),
            );
            match self.cooldown_word.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(cooldown_until_ms(next)),
                Err(_) => continue,
            }
        }
    }

    fn clear_cooldown_generation(
        &self,
        expected: u64,
        previous_generation: u64,
        generation: u64,
    ) -> bool {
        if !cooldown_matches_generation(expected, previous_generation) {
            return false;
        }

        // Use the exact snapshot validated by probe success. If a late 429
        // extends the deadline after that validation, this CAS fails and the
        // success path must not erase the newer server signal.
        self.cooldown_word
            .compare_exchange(
                expected,
                pack_cooldown(generation, 0),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn restore_cooldown_generation(
        &self,
        previous_generation: u64,
        generation: u64,
        until_ms: u64,
    ) -> bool {
        loop {
            let current = self.cooldown_word.load(Ordering::Acquire);
            if cooldown_matches_generation(current, generation) {
                return true;
            }
            if !cooldown_matches_generation(current, previous_generation) {
                return false;
            }
            let next = pack_cooldown(generation, until_ms);
            match self.cooldown_word.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    fn extend_cooldown_for_generation(
        &self,
        generation: u64,
        requested_until_ms: u64,
    ) -> Option<u64> {
        loop {
            let state = self.state_word.load(Ordering::Acquire);
            if !is_cooling(state) || state_generation(state) != generation {
                return None;
            }

            let current = self.cooldown_word.load(Ordering::Acquire);
            if !cooldown_matches_generation(current, generation) {
                return None;
            }
            let current_until = cooldown_until_ms(current);
            if requested_until_ms <= current_until {
                return Some(current_until);
            }

            let next = pack_cooldown(generation, requested_until_ms);
            match self.cooldown_word.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(cooldown_until_ms(next)),
                Err(_) => continue,
            }
        }
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
    probe_epoch: u64,
    in_flight: bool,
    completed: bool,
}

impl<'a> RateLimitPermit<'a> {
    fn normal(state: &'a DohRateLimitState, generation: u64) -> Self {
        Self {
            state,
            generation,
            kind: PermitKind::Normal,
            probe_epoch: 0,
            in_flight: false,
            completed: false,
        }
    }

    fn probe(state: &'a DohRateLimitState, generation: u64, probe_epoch: u64) -> Self {
        Self {
            state,
            generation,
            kind: PermitKind::Probe,
            probe_epoch,
            in_flight: false,
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
        if self.in_flight && !self.completed {
            self.state.rearm_cancelled_probe(self);
        }
        self.state.release_probe_slot(self.probe_epoch);
    }
}

fn pack_state(generation: u64, cooling: bool, backoff_streak: u32) -> u64 {
    ((generation & GENERATION_MASK) << GENERATION_SHIFT)
        | (((backoff_streak as u64) & BACKOFF_STREAK_VALUE_MASK) << BACKOFF_STREAK_SHIFT)
        | if cooling { COOLING_BIT } else { 0 }
}

fn state_generation(word: u64) -> u64 {
    word >> GENERATION_SHIFT
}

fn state_backoff_streak(word: u64) -> u32 {
    ((word & BACKOFF_STREAK_MASK) >> BACKOFF_STREAK_SHIFT) as u32
}

fn is_cooling(word: u64) -> bool {
    word & COOLING_BIT != 0
}

fn pack_cooldown(generation: u64, until_ms: u64) -> u64 {
    ((generation & COOLDOWN_GENERATION_MASK) << COOLDOWN_GENERATION_SHIFT)
        | until_ms.min(COOLDOWN_UNTIL_MASK)
}

fn cooldown_generation(word: u64) -> u64 {
    word >> COOLDOWN_GENERATION_SHIFT
}

fn cooldown_until_ms(word: u64) -> u64 {
    word & COOLDOWN_UNTIL_MASK
}

fn cooldown_matches_generation(word: u64, generation: u64) -> bool {
    cooldown_generation(word) == (generation & COOLDOWN_GENERATION_MASK)
}

fn pack_probe(epoch: u64, phase: ProbePhase) -> u64 {
    ((epoch & PROBE_EPOCH_MASK) << PROBE_EPOCH_SHIFT) | phase as u64
}

fn probe_epoch(word: u64) -> u64 {
    word >> PROBE_EPOCH_SHIFT
}

fn probe_phase(word: u64) -> ProbePhase {
    match word & PROBE_PHASE_MASK {
        0 => ProbePhase::Idle,
        1 => ProbePhase::Active,
        2 => ProbePhase::Committing,
        _ => unreachable!("probe phase uses only values 0..=2"),
    }
}

fn next_generation(generation: u64) -> u64 {
    generation.wrapping_add(1) & GENERATION_MASK
}

fn previous_generation(generation: u64) -> u64 {
    generation.wrapping_sub(1) & GENERATION_MASK
}

fn next_probe_epoch(epoch: u64) -> u64 {
    epoch.wrapping_add(1) & PROBE_EPOCH_MASK
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
        let word = state.state_word.load(Ordering::Acquire);

        assert!(first_observation.entered_new_cooldown);
        assert!(!second_observation.entered_new_cooldown);
        assert_eq!(state_generation(word), 1);
        assert_eq!(state_backoff_streak(word), 1);
    }

    fn expire_current_cooldown(state: &DohRateLimitState) {
        let word = state.state_word.load(Ordering::Acquire);
        let generation = state_generation(word);
        state
            .cooldown_word
            .store(pack_cooldown(generation, 0), Ordering::Release);
    }

    fn current_cooldown_until(state: &DohRateLimitState) -> u64 {
        let generation = state_generation(state.state_word.load(Ordering::Acquire));
        state
            .cooldown_until_for_generation(generation)
            .expect("cooldown generation should be published")
    }

    #[test]
    fn concurrent_429_wave_advances_backoff_once() {
        let state = state();
        let permits = (0..32)
            .map(|_| state.acquire().expect("query should be admitted"))
            .collect::<Vec<_>>();

        std::thread::scope(|scope| {
            let state_ref = &state;
            for permit in &permits {
                scope.spawn(move || {
                    state_ref.record_rate_limit(permit, None);
                });
            }
        });

        let word = state.state_word.load(Ordering::Acquire);
        assert!(is_cooling(word));
        assert_eq!(state_generation(word), 1);
        assert_eq!(state_backoff_streak(word), 1);
    }

    #[test]
    fn same_wave_retry_after_can_help_publish_first_cooldown() {
        let state = state();
        let first = state.acquire().expect("first query should be admitted");
        let second = state.acquire().expect("second query should be admitted");

        // Deterministically model the first request being paused immediately
        // after it wins the state transition but before it publishes the
        // matching cooldown owner/deadline.
        let expected_word = state.state_word.load(Ordering::Acquire);
        let previous_generation = state_generation(expected_word);
        let generation = next_generation(previous_generation);
        let next_word = pack_state(generation, true, 1);
        state
            .state_word
            .compare_exchange(
                expected_word,
                next_word,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .expect("first request should win the initial cooldown transition");

        let pending_cooldown = state.cooldown_word.load(Ordering::Acquire);
        assert!(cooldown_matches_generation(
            pending_cooldown,
            previous_generation
        ));

        let before = AppClock::elapsed_millis();
        let observation = state.record_rate_limit(&second, Some(Duration::from_secs(300)));
        assert!(!observation.entered_new_cooldown);

        let helped_until = current_cooldown_until(&state);
        assert!(helped_until >= before.saturating_add(300_000));

        // The original winner now resumes with only its local 100 ms backoff.
        // Its publication must observe the already-assisted 300 second
        // deadline rather than replacing it.
        let winner_until = state
            .advance_cooldown_generation(
                previous_generation,
                generation,
                before.saturating_add(100),
            )
            .expect("original winner should observe completed publication");
        assert_eq!(winner_until, helped_until);

        let word = state.state_word.load(Ordering::Acquire);
        assert_eq!(state_generation(word), generation);
        assert_eq!(state_backoff_streak(word), 1);

        drop(first);
    }

    #[test]
    fn stale_probe_release_cannot_clear_newer_owner() {
        let state = state();

        let stale_epoch = state.reserve_probe().expect("first probe should reserve");
        state.release_probe_slot(stale_epoch);

        let newer_epoch = state.reserve_probe().expect("second probe should reserve");
        assert_ne!(newer_epoch, stale_epoch);
        assert_eq!(
            state.probe_word.load(Ordering::Acquire),
            pack_probe(newer_epoch, ProbePhase::Active)
        );

        // Simulate the first permit's delayed Drop. It must not release the
        // slot currently owned by the newer epoch.
        state.release_probe_slot(stale_epoch);
        assert_eq!(
            state.probe_word.load(Ordering::Acquire),
            pack_probe(newer_epoch, ProbePhase::Active)
        );

        state.release_probe_slot(newer_epoch);
        assert_eq!(
            probe_phase(state.probe_word.load(Ordering::Acquire)),
            ProbePhase::Idle
        );
    }

    #[test]
    fn invalidation_guard_is_released_by_invalidator_not_stale_permit() {
        let state = state();
        let owner_epoch = state.reserve_probe().expect("probe should reserve");

        let invalidation = state.invalidate_active_probe();
        let ProbeInvalidation::ActiveInvalidated { guard_epoch } = invalidation else {
            panic!("active probe should be invalidated");
        };
        assert_ne!(guard_epoch, owner_epoch);

        // The stale owner cannot clear the invalidation guard.
        state.release_probe_slot(owner_epoch);
        assert_eq!(
            state.probe_word.load(Ordering::Acquire),
            pack_probe(guard_epoch, ProbePhase::Active)
        );

        state.finish_probe_invalidation(invalidation);
        assert_eq!(
            probe_phase(state.probe_word.load(Ordering::Acquire)),
            ProbePhase::Idle
        );
    }

    #[test]
    fn expired_cooldown_status_does_not_underflow() {
        let state = state();
        let permit = state.acquire().expect("query should be admitted");
        state.record_rate_limit(&permit, None);
        expire_current_cooldown(&state);
        std::thread::sleep(Duration::from_millis(2));

        assert_eq!(state.temporary_unavailable_for_ms(), None);
    }

    #[test]
    fn late_retry_after_cancels_reserved_probe_before_io() {
        let state = state();
        let first = state.acquire().expect("first query should be admitted");
        let late = state.acquire().expect("late query should be admitted");
        state.record_rate_limit(&first, None);
        expire_current_cooldown(&state);

        let mut probe = state.acquire().expect("probe should be reserved");
        assert!(probe.is_probe());
        assert!(!probe.in_flight);

        let before = AppClock::elapsed_millis();
        state.record_rate_limit(&late, Some(Duration::from_secs(5)));
        assert!(current_cooldown_until(&state) >= before.saturating_add(5_000));
        assert!(matches!(
            state.begin_probe_io(&mut probe),
            Err(DnsError::RateLimitCooldown { .. })
        ));
        drop(probe);
        assert_eq!(
            probe_phase(state.probe_word.load(Ordering::Acquire)),
            ProbePhase::Idle
        );
    }

    #[test]
    fn late_retry_after_invalidates_inflight_probe_success() {
        let state = state();
        let first = state.acquire().expect("first query should be admitted");
        let late = state.acquire().expect("late query should be admitted");
        state.record_rate_limit(&first, None);
        expire_current_cooldown(&state);

        let mut probe = state.acquire().expect("probe should be reserved");
        state
            .begin_probe_io(&mut probe)
            .expect("probe should enter in-flight state");
        let before = AppClock::elapsed_millis();
        state.record_rate_limit(&late, Some(Duration::from_secs(5)));
        assert!(current_cooldown_until(&state) >= before.saturating_add(5_000));
        assert!(!state.reset_after_probe_success(&probe));
        assert!(is_cooling(state.state_word.load(Ordering::Acquire)));

        probe.complete();
        drop(probe);
        assert_eq!(
            probe_phase(state.probe_word.load(Ordering::Acquire)),
            ProbePhase::Idle
        );
    }

    #[test]
    fn invalidated_probe_429_preserves_newer_retry_after_and_streak() {
        let state = state();
        let first = state.acquire().expect("first query should be admitted");
        let late = state.acquire().expect("late query should be admitted");
        state.record_rate_limit(&first, None);
        expire_current_cooldown(&state);

        let mut probe = state.acquire().expect("probe should be admitted");
        state
            .begin_probe_io(&mut probe)
            .expect("probe should enter in-flight state");

        let before = AppClock::elapsed_millis();
        state.record_rate_limit(&late, Some(Duration::from_secs(300)));
        let extended_until = current_cooldown_until(&state);
        assert!(extended_until >= before.saturating_add(300_000));

        let observation = state.record_rate_limit(&probe, None);
        probe.complete();
        drop(probe);

        let word = state.state_word.load(Ordering::Acquire);
        assert!(is_cooling(word));
        assert_eq!(state_generation(word), 1);
        assert_eq!(state_backoff_streak(word), 1);
        assert!(!observation.entered_new_cooldown);
        assert_eq!(current_cooldown_until(&state), extended_until);
    }

    #[test]
    fn probe_429_transition_never_shortens_existing_deadline() {
        let state = state();
        let first = state.acquire().expect("first query should be admitted");
        state.record_rate_limit(&first, None);
        expire_current_cooldown(&state);

        let mut probe = state.acquire().expect("probe should be admitted");
        state
            .begin_probe_io(&mut probe)
            .expect("probe should enter in-flight state");

        let generation = state_generation(state.state_word.load(Ordering::Acquire));
        let before = AppClock::elapsed_millis();
        let longer_until = before.saturating_add(5_000);
        assert_eq!(
            state.extend_cooldown_for_generation(generation, longer_until),
            Some(longer_until)
        );

        let observation = state.record_rate_limit(&probe, None);
        probe.complete();
        drop(probe);

        assert!(observation.entered_new_cooldown);
        assert!(current_cooldown_until(&state) >= longer_until);
    }

    #[test]
    fn stale_429_cannot_reclose_after_probe_success() {
        let state = state();
        let old = state.acquire().expect("old query should be admitted");
        state.record_rate_limit(&old, None);
        expire_current_cooldown(&state);

        let mut probe = state.acquire().expect("probe should be admitted");
        assert!(probe.is_probe());
        state
            .begin_probe_io(&mut probe)
            .expect("probe should enter in-flight state");
        assert!(state.reset_after_probe_success(&probe));
        probe.complete();
        drop(probe);

        let stale = state.record_rate_limit(&old, Some(Duration::from_secs(5)));
        assert!(!stale.entered_new_cooldown);
        let word = state.state_word.load(Ordering::Acquire);
        assert!(!is_cooling(word));
        assert_eq!(state_backoff_streak(word), 0);
    }

    #[test]
    fn probe_429_advances_exactly_one_backoff_generation() {
        let state = state();
        let first = state.acquire().expect("query should be admitted");
        state.record_rate_limit(&first, None);
        expire_current_cooldown(&state);

        let mut probe = state.acquire().expect("probe should be admitted");
        state
            .begin_probe_io(&mut probe)
            .expect("probe should enter in-flight state");
        let observation = state.record_rate_limit(&probe, None);
        probe.complete();
        drop(probe);

        assert!(observation.entered_new_cooldown);
        assert_eq!(observation.backoff_streak, 2);
        assert_eq!(observation.cooldown_ms, 200);
        let word = state.state_word.load(Ordering::Acquire);
        assert_eq!(state_generation(word), 2);
        assert_eq!(state_backoff_streak(word), 2);
    }

    #[test]
    fn multi_generation_stale_429_extends_current_cooldown_without_advancing_streak() {
        let state = state();
        let stale = state.acquire().expect("stale query should be admitted");
        let first = state.acquire().expect("first query should be admitted");

        state.record_rate_limit(&first, None);
        expire_current_cooldown(&state);

        let mut probe = state.acquire().expect("probe should be admitted");
        state
            .begin_probe_io(&mut probe)
            .expect("probe should enter in-flight state");
        let probe_observation = state.record_rate_limit(&probe, None);
        probe.complete();
        drop(probe);

        assert!(probe_observation.entered_new_cooldown);
        let before = AppClock::elapsed_millis();
        let stale_observation = state.record_rate_limit(&stale, Some(Duration::from_secs(300)));

        let word = state.state_word.load(Ordering::Acquire);
        assert!(is_cooling(word));
        assert_eq!(state_generation(word), 2);
        assert_eq!(state_backoff_streak(word), 2);
        assert!(!stale_observation.entered_new_cooldown);
        assert!(
            current_cooldown_until(&state) >= before.saturating_add(300_000),
            "stale but newly received 429 must preserve its Retry-After"
        );
    }

    #[test]
    fn stale_probe_429_extends_newer_cooling_generation_without_advancing_streak() {
        let state = state();
        let first = state.acquire().expect("first query should be admitted");
        let late = state.acquire().expect("late query should be admitted");
        state.record_rate_limit(&first, None);
        expire_current_cooldown(&state);

        let mut stale_probe = state.acquire().expect("probe should be admitted");
        state
            .begin_probe_io(&mut stale_probe)
            .expect("probe should enter in-flight state");

        // A same-wave normal request invalidates this probe without advancing
        // the cooldown generation.
        state.record_rate_limit(&late, None);
        expire_current_cooldown(&state);

        // A replacement probe then observes another 429 and advances the
        // limiter to the next cooling generation while `stale_probe` is still
        // outstanding.
        let mut replacement = state
            .acquire()
            .expect("replacement probe should be admitted");
        state
            .begin_probe_io(&mut replacement)
            .expect("replacement probe should enter in-flight state");
        let replacement_observation = state.record_rate_limit(&replacement, None);
        replacement.complete();
        drop(replacement);
        assert!(replacement_observation.entered_new_cooldown);

        let before = AppClock::elapsed_millis();
        let observation = state.record_rate_limit(&stale_probe, Some(Duration::from_secs(300)));
        stale_probe.complete();
        drop(stale_probe);

        let current = state.state_word.load(Ordering::Acquire);
        assert_eq!(state_generation(current), 2);
        assert_eq!(state_backoff_streak(current), 2);
        assert!(!observation.entered_new_cooldown);
        assert!(current_cooldown_until(&state) >= before.saturating_add(300_000));
    }

    #[test]
    fn stale_generation_cannot_overwrite_newer_cooldown_owner() {
        let state = state();
        let first = state.acquire().expect("first query should be admitted");
        state.record_rate_limit(&first, None);
        expire_current_cooldown(&state);

        let mut probe = state.acquire().expect("probe should be admitted");
        state
            .begin_probe_io(&mut probe)
            .expect("probe should enter in-flight state");
        assert!(state.reset_after_probe_success(&probe));
        probe.complete();
        drop(probe);

        let next = state
            .acquire()
            .expect("healthy generation should admit a new query");
        state.record_rate_limit(&next, Some(Duration::from_secs(5)));

        let current_word = state.state_word.load(Ordering::Acquire);
        let current_generation = state_generation(current_word);
        let current_cooldown = state.cooldown_word.load(Ordering::Acquire);
        assert!(is_cooling(current_word));
        assert!(cooldown_matches_generation(
            current_cooldown,
            current_generation
        ));

        assert_eq!(state.extend_cooldown_for_generation(1, u64::MAX), None);
        assert_eq!(
            state.cooldown_word.load(Ordering::Acquire),
            current_cooldown
        );
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
        expire_current_cooldown(&state);

        let mut probe = state.acquire().expect("probe should be admitted");
        assert!(probe.is_probe());
        state
            .begin_probe_io(&mut probe)
            .expect("probe should enter in-flight state");
        let before_drop_ms = AppClock::elapsed_millis();
        drop(probe);

        assert_eq!(
            probe_phase(state.probe_word.load(Ordering::Acquire)),
            ProbePhase::Idle
        );
        assert!(is_cooling(state.state_word.load(Ordering::Acquire)));
        let cooldown_until_ms = current_cooldown_until(&state);
        assert!(
            cooldown_until_ms
                >= before_drop_ms.saturating_add(duration_millis_u64(CANCELLED_PROBE_RETRY))
        );
        let remaining_ms = cooldown_until_ms.saturating_sub(AppClock::elapsed_millis());
        assert!(remaining_ms > 0);
        assert!(remaining_ms <= duration_millis_u64(CANCELLED_PROBE_RETRY));
    }
}
