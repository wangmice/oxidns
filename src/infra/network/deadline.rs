// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared network operation deadlines.

use std::future::Future;
use std::time::Duration;

use crate::infra::clock::AppClock;
use crate::infra::error::DnsError;
use crate::infra::network::metrics::{self, UpstreamTimeoutStage};

/// Outcome of running a future under a query deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineOutcome<T> {
    Completed(T),
    Expired,
}

/// Per-query network deadline measured by the process-wide application clock.
///
/// The deadline is intentionally based on `AppClock::elapsed_millis()` so
/// related network paths can share one monotonic budget across bootstrap,
/// pool acquisition, connection expansion, handshakes, and DNS I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryDeadline {
    pub started_at_ms: u64,
    pub expires_at_ms: u64,
    track_upstream_timeout_metrics: bool,
}

impl QueryDeadline {
    pub fn new(timeout: Duration) -> Self {
        Self::new_with_metric_tracking(timeout, true)
    }

    /// Deadline for background pool maintenance/prefill work.
    ///
    /// Background connection upkeep shares the same timeout machinery but must
    /// not inflate query-facing upstream timeout metrics.
    pub(crate) fn background(timeout: Duration) -> Self {
        Self::new_with_metric_tracking(timeout, false)
    }

    fn new_with_metric_tracking(timeout: Duration, track_upstream_timeout_metrics: bool) -> Self {
        let started_at_ms = AppClock::elapsed_millis();
        let timeout_ms = duration_millis_u64(timeout);
        Self {
            started_at_ms,
            expires_at_ms: started_at_ms.saturating_add(timeout_ms),
            track_upstream_timeout_metrics,
        }
    }

    /// Return the earlier of this deadline and a new relative timeout while
    /// preserving whether upstream timeout metrics are tracked.
    pub(crate) fn capped(self, timeout: Duration) -> Self {
        let timeout_deadline =
            Self::new_with_metric_tracking(timeout, self.track_upstream_timeout_metrics);
        if timeout_deadline.expires_at_ms < self.expires_at_ms {
            timeout_deadline
        } else {
            self
        }
    }

    pub fn remaining(&self) -> Option<Duration> {
        let now = AppClock::elapsed_millis();
        if now >= self.expires_at_ms {
            None
        } else {
            Some(Duration::from_millis(self.expires_at_ms - now))
        }
    }

    pub async fn run<F, T>(&self, fut: F) -> DeadlineOutcome<T>
    where
        F: Future<Output = T>,
    {
        let Some(remaining) = self.remaining() else {
            return DeadlineOutcome::Expired;
        };

        match tokio::time::timeout(remaining, fut).await {
            Ok(value) => DeadlineOutcome::Completed(value),
            Err(_) => DeadlineOutcome::Expired,
        }
    }

    pub fn timeout_error(&self) -> DnsError {
        DnsError::plugin(format!(
            "DNS query timeout after {:?}",
            Duration::from_millis(self.expires_at_ms.saturating_sub(self.started_at_ms))
        ))
    }

    /// Record and construct a timeout error for the stage that exhausted this query deadline.
    pub(crate) fn timeout_error_for(&self, stage: UpstreamTimeoutStage) -> DnsError {
        if self.track_upstream_timeout_metrics {
            metrics::upstream_timeout(stage);
        }
        self.timeout_error()
    }
}

fn duration_millis_u64(duration: Duration) -> u64 {
    if duration.is_zero() {
        return 0;
    }
    duration.as_millis().try_into().unwrap_or(u64::MAX).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_deadline_preserves_timeout_metric_scope() {
        AppClock::start();

        let query = QueryDeadline::new(Duration::from_secs(5));
        let query_capped = query.capped(Duration::from_secs(1));
        assert!(query_capped.track_upstream_timeout_metrics);

        let background = QueryDeadline::background(Duration::from_secs(5));
        let background_capped = background.capped(Duration::from_secs(1));
        assert!(!background_capped.track_upstream_timeout_metrics);
    }
}
