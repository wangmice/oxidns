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
    timeout_metric_scope: TimeoutMetricScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeoutMetricScope {
    Query,
    Connection,
    None,
}

impl QueryDeadline {
    pub fn new(timeout: Duration) -> Self {
        Self::new_with_metric_scope(timeout, TimeoutMetricScope::Query)
    }

    /// Deadline for background pool maintenance/prefill work.
    ///
    /// Background connection upkeep shares the same timeout machinery but must
    /// not inflate query-facing upstream timeout metrics.
    pub(crate) fn background(timeout: Duration) -> Self {
        Self::new_with_metric_scope(timeout, TimeoutMetricScope::None)
    }

    /// Deadline for detached background connection creation.
    ///
    /// These operations are not owned by one foreground query, but connection
    /// establishment failures still need stage-level observability. Only
    /// connection-create and protocol-handshake timeouts are recorded.
    pub(crate) fn background_connection(timeout: Duration) -> Self {
        Self::new_with_metric_scope(timeout, TimeoutMetricScope::Connection)
    }

    fn new_with_metric_scope(timeout: Duration, timeout_metric_scope: TimeoutMetricScope) -> Self {
        let started_at_ms = AppClock::elapsed_millis();
        let timeout_ms = duration_millis_u64(timeout);
        Self {
            started_at_ms,
            expires_at_ms: started_at_ms.saturating_add(timeout_ms),
            timeout_metric_scope,
        }
    }

    /// Return the earlier of this deadline and a new relative timeout while
    /// preserving the upstream timeout metric scope.
    pub(crate) fn capped(self, timeout: Duration) -> Self {
        let timeout_deadline = Self::new_with_metric_scope(timeout, self.timeout_metric_scope);
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

    fn timeout_duration(&self) -> Duration {
        Duration::from_millis(self.expires_at_ms.saturating_sub(self.started_at_ms))
    }

    pub fn timeout_error(&self) -> DnsError {
        DnsError::plugin(format!(
            "DNS query timeout after {:?}",
            self.timeout_duration()
        ))
    }

    fn tracks_timeout_metric(&self, stage: UpstreamTimeoutStage) -> bool {
        match self.timeout_metric_scope {
            TimeoutMetricScope::Query => true,
            TimeoutMetricScope::Connection => matches!(
                stage,
                UpstreamTimeoutStage::ConnectionCreate | UpstreamTimeoutStage::ProtocolHandshake
            ),
            TimeoutMetricScope::None => false,
        }
    }

    fn record_timeout_metric(&self, stage: UpstreamTimeoutStage) {
        if self.tracks_timeout_metric(stage) {
            metrics::upstream_timeout(stage);
        }
    }

    /// Record and construct a timeout error for the stage that exhausted this query deadline.
    pub(crate) fn timeout_error_for(&self, stage: UpstreamTimeoutStage) -> DnsError {
        self.record_timeout_metric(stage);
        self.timeout_error()
    }

    /// Record a staged timeout while preserving a diagnostic detail gathered by
    /// the caller during the same query lifetime.
    pub(crate) fn timeout_error_for_with_detail(
        &self,
        stage: UpstreamTimeoutStage,
        detail: &str,
    ) -> DnsError {
        self.record_timeout_metric(stage);
        DnsError::plugin(format!(
            "DNS query timeout after {:?}; {detail}",
            self.timeout_duration()
        ))
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
    fn timeout_error_with_detail_preserves_context() {
        AppClock::start();
        // This test only verifies error-detail formatting. Use a silent
        // background deadline so parallel metrics tests are not affected by
        // an unrelated global timeout-counter increment.
        let deadline = QueryDeadline::background(Duration::from_millis(25));
        let error = deadline.timeout_error_for_with_detail(
            UpstreamTimeoutStage::PoolAcquire,
            "last upstream connection attempt failed: planned failure",
        );
        let error = error.to_string();
        assert!(error.contains("DNS query timeout"));
        assert!(error.contains("planned failure"));
    }

    #[test]
    fn capped_deadline_preserves_timeout_metric_scope() {
        AppClock::start();

        let query = QueryDeadline::new(Duration::from_secs(5));
        let query_capped = query.capped(Duration::from_secs(1));
        assert_eq!(query_capped.timeout_metric_scope, TimeoutMetricScope::Query);

        let connection = QueryDeadline::background_connection(Duration::from_secs(5));
        let connection_capped = connection.capped(Duration::from_secs(1));
        assert_eq!(
            connection_capped.timeout_metric_scope,
            TimeoutMetricScope::Connection
        );

        let background = QueryDeadline::background(Duration::from_secs(5));
        let background_capped = background.capped(Duration::from_secs(1));
        assert_eq!(
            background_capped.timeout_metric_scope,
            TimeoutMetricScope::None
        );
    }

    #[test]
    fn connection_background_tracks_only_connection_stages() {
        AppClock::start();
        let deadline = QueryDeadline::background_connection(Duration::from_secs(5));

        assert!(deadline.tracks_timeout_metric(UpstreamTimeoutStage::ConnectionCreate));
        assert!(deadline.tracks_timeout_metric(UpstreamTimeoutStage::ProtocolHandshake));
        assert!(!deadline.tracks_timeout_metric(UpstreamTimeoutStage::PoolAcquire));
        assert!(!deadline.tracks_timeout_metric(UpstreamTimeoutStage::QueryIo));
    }
}
