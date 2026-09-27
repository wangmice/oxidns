// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use rand::RngExt;
use tokio::task::JoinSet;
use tracing::{Level, debug, event_enabled, info};

use super::config::ForwardErrorPolicy;
use super::metrics::ForwardMetrics;
use super::selection::{ResponseSelectionMode, SelectedResponse, select_response};
use super::{contextualize_upstream_error, is_timeout_error};
use crate::core::context::DnsContext;
use crate::core::response::{ResponseDisposition, classify_response as classify_dns_response};
use crate::infra::error::{DnsError, Result};
use crate::infra::network::upstream::{QueryDeadline, Upstream};
use crate::infra::observability::metrics::{register_metric_source, unregister_metric_source};
use crate::plugin::Plugin;
use crate::plugin::executor::{ExecStep, Executor};
use crate::proto::Message;

#[derive(Debug)]
pub(super) struct ConcurrentForwarder {
    /// Plugin identifier
    pub(super) tag: String,

    /// Fixed active upstream fanout, computed at creation time.
    pub(super) active_concurrent: usize,

    /// Whether any configured upstream can enter the DoH HTTP 429 cooldown.
    pub(super) has_doh_upstream: bool,

    pub(super) upstreams: Arc<Vec<Arc<dyn Upstream>>>,

    /// Whether to stop the executor chain after a successful upstream response.
    pub(super) short_circuit: bool,

    /// Behavior after all usable upstream attempts fail.
    pub(super) on_error: ForwardErrorPolicy,

    pub(super) response_selection: ResponseSelectionMode,

    pub(super) metrics: Arc<ForwardMetrics>,
}

#[derive(Debug)]
struct QueryDispatch {
    upstreams: Arc<Vec<Arc<dyn Upstream>>>,
    request: Message,
    next_candidate: AtomicUsize,
}

#[async_trait]
impl Plugin for ConcurrentForwarder {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
        info!("DNS ConcurrentForwarder initialized tag: {}", self.tag);
        register_metric_source(self.metrics.clone())
    }

    async fn destroy(&self) -> Result<()> {
        unregister_metric_source(&self.tag);
        Ok(())
    }
}

#[async_trait]
impl Executor for ConcurrentForwarder {
    #[hotpath::measure]
    async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
        let start_ms = self.metrics.record_query_start();
        let (response, last_error, timed_out) = self.query_upstreams(context.request.clone()).await;
        if let Some(selected) = response {
            if selected.disposition == Some(ResponseDisposition::IncompleteAlias) {
                self.metrics.record_incomplete_alias_selected();
            }
            context.set_response(selected.message);
            self.metrics.record_success(start_ms);
            return Ok(self.completion_step());
        }

        let err = last_error.unwrap_or_else(|| "no upstream response".to_string());
        self.metrics.record_error(start_ms, timed_out);
        debug!(
            forward_tag = %self.tag,
            error = %err,
            "forward plugin failed across all concurrent upstreams"
        );
        if self.on_error == ForwardErrorPolicy::Continue {
            return Ok(ExecStep::Next);
        }
        Err(DnsError::plugin(format!(
            "forward plugin '{}' failed across all concurrent upstreams: {}",
            self.tag, err
        )))
    }
}

impl ConcurrentForwarder {
    #[inline]
    fn completion_step(&self) -> ExecStep {
        if self.short_circuit {
            ExecStep::Stop
        } else {
            ExecStep::Next
        }
    }

    async fn query_upstreams(
        &self,
        request: Message,
    ) -> (Option<SelectedResponse>, Option<String>, bool) {
        let total_upstreams = self.upstreams.len();
        if total_upstreams == 0 {
            return (None, Some("no upstream configured".to_string()), false);
        }

        let active_concurrent = self.active_concurrent.min(total_upstreams);
        let start_idx = rand::rng().random_range(0..total_upstreams);

        // The default `concurrent: 1` path needs no shared dispatch object,
        // atomic cursor, or task spawn. A local cursor preserves candidate
        // replacement when a DoH upstream has to be skipped after entering
        // cooldown without adding synchronization to the default hot path.
        if active_concurrent == 1 {
            return self.query_single_lane(request, start_idx).await;
        }

        // Non-DoH upstreams cannot enter the HTTP 429 cooldown state. The
        // factory caches that fact once, so UDP/TCP/DoT/DoQ forwarding keeps
        // the original fixed fan-out path with no per-query scan, dispatcher
        // allocation, or candidate-cursor atomic.
        if !self.has_doh_upstream {
            return self
                .query_fixed_lanes(request, start_idx, active_concurrent)
                .await;
        }

        self.query_retry_lanes(request, start_idx, active_concurrent)
            .await
    }

    async fn query_single_lane(
        &self,
        request: Message,
        start_idx: usize,
    ) -> (Option<SelectedResponse>, Option<String>, bool) {
        let mut next_candidate = 0_usize;
        match query_retry_lane(
            self.upstreams.as_slice(),
            &request,
            || {
                let current = next_candidate;
                next_candidate += 1;
                current
            },
            start_idx,
            self.metrics.as_ref(),
        )
        .await
        {
            Ok(response) => {
                let disposition = match self.response_selection {
                    ResponseSelectionMode::Fastest => None,
                    _ => Some(classify_dns_response(&response, request.first_question())),
                };
                (
                    Some(SelectedResponse {
                        message: response,
                        disposition,
                    }),
                    None,
                    false,
                )
            }
            Err(err) => {
                let timed_out = is_timeout_error(&err);
                (None, Some(err.to_string()), timed_out)
            }
        }
    }

    async fn query_fixed_lanes(
        &self,
        request: Message,
        start_idx: usize,
        active_concurrent: usize,
    ) -> (Option<SelectedResponse>, Option<String>, bool) {
        let mut join_set = JoinSet::new();

        for i in 0..active_concurrent {
            let selected_idx = (start_idx + i) % self.upstreams.len();
            let upstream = self.upstreams[selected_idx].clone();
            let message = request.clone();
            let query_id = message.id();
            let metrics = self.metrics.clone();
            join_set.spawn(async move {
                let up_start = metrics.record_upstream_start(selected_idx);
                match upstream.query(message).await {
                    Ok(response) => {
                        metrics.record_upstream_success(selected_idx, up_start);
                        if event_enabled!(Level::DEBUG) {
                            let info = upstream.connection_info();
                            debug!(
                                upstream_index = selected_idx,
                                upstream = %info.raw_addr,
                                upstream_tag = info.tag.as_deref().unwrap_or(""),
                                query_id,
                                "DNS upstream query succeeded"
                            );
                        }
                        Ok(response)
                    }
                    Err(err) => {
                        metrics.record_upstream_error(
                            selected_idx,
                            up_start,
                            is_timeout_error(&err),
                        );
                        let info = upstream.connection_info();
                        if event_enabled!(Level::DEBUG) {
                            debug!(
                                upstream_index = selected_idx,
                                upstream = %info.raw_addr,
                                upstream_tag = info.tag.as_deref().unwrap_or(""),
                                query_id,
                                error = %err,
                                "DNS upstream query failed"
                            );
                        }
                        Err(contextualize_upstream_error(info, err))
                    }
                }
            });
        }

        let question = match self.response_selection {
            ResponseSelectionMode::Fastest => None,
            _ => request.first_question(),
        };
        select_response(
            &mut join_set,
            active_concurrent,
            question,
            self.response_selection,
        )
        .await
    }

    async fn query_retry_lanes(
        &self,
        request: Message,
        start_idx: usize,
        active_concurrent: usize,
    ) -> (Option<SelectedResponse>, Option<String>, bool) {
        let mut join_set = JoinSet::new();
        // One allocation contains both the immutable request and shared
        // candidate cursor. This replaces the previous two Arc allocations.
        let dispatch = Arc::new(QueryDispatch {
            upstreams: self.upstreams.clone(),
            request,
            next_candidate: AtomicUsize::new(0),
        });

        for _ in 0..active_concurrent {
            let dispatch = dispatch.clone();
            let metrics = self.metrics.clone();
            join_set.spawn(async move {
                let next_candidate = &dispatch.next_candidate;
                query_retry_lane(
                    dispatch.upstreams.as_slice(),
                    &dispatch.request,
                    || next_candidate.fetch_add(1, Ordering::Relaxed),
                    start_idx,
                    metrics.as_ref(),
                )
                .await
            });
        }

        let question = match self.response_selection {
            ResponseSelectionMode::Fastest => None,
            _ => dispatch.request.first_question(),
        };
        select_response(
            &mut join_set,
            active_concurrent,
            question,
            self.response_selection,
        )
        .await
    }
}

async fn query_retry_lane<F>(
    upstreams: &[Arc<dyn Upstream>],
    request: &Message,
    mut next_candidate: F,
    start_idx: usize,
    metrics: &ForwardMetrics,
) -> Result<Message>
where
    F: FnMut() -> usize + Send,
{
    let mut last_cooldown_ms = None;
    let mut last_retry_error = None;
    // The first actual upstream attempt establishes the total budget for this
    // lane. Later 429 replacements share that absolute deadline instead of
    // receiving a fresh full timeout.
    let mut lane_deadline: Option<(QueryDeadline, Duration)> = None;
    let query_id = request.id();

    loop {
        if let Some((deadline, _)) = lane_deadline
            && deadline.remaining().is_none()
        {
            if let Some(err) = last_retry_error.take()
                && is_timeout_error(&err)
            {
                return Err(err);
            }
            return Err(deadline.timeout_error());
        }

        let offset = next_candidate();
        if offset >= upstreams.len() {
            return Err(last_retry_error
                .unwrap_or_else(|| DnsError::rate_limit_cooldown(last_cooldown_ms.unwrap_or(1))));
        }

        let selected_idx = (start_idx + offset) % upstreams.len();
        let upstream = &upstreams[selected_idx];
        if let Some(remaining_ms) = upstream.temporary_unavailable_for_ms() {
            last_cooldown_ms =
                Some(last_cooldown_ms.map_or(remaining_ms, |old: u64| old.min(remaining_ms)));
            continue;
        }

        let had_lane_deadline = lane_deadline.is_some();
        let upstream_timeout = upstream.timeout();
        let deadline = match lane_deadline {
            Some((deadline, first_timeout)) if upstream_timeout < first_timeout => {
                deadline.capped(upstream_timeout)
            }
            Some((deadline, _)) => deadline,
            None => {
                let deadline = QueryDeadline::new(upstream_timeout);
                lane_deadline = Some((deadline, upstream_timeout));
                deadline
            }
        };

        let up_start = metrics.record_upstream_start(selected_idx);
        match upstream
            .query_with_deadline(request.clone(), deadline)
            .await
        {
            Ok(response) => {
                metrics.record_upstream_success(selected_idx, up_start);
                if event_enabled!(Level::DEBUG) {
                    let info = upstream.connection_info();
                    debug!(
                        upstream_index = selected_idx,
                        upstream = %info.raw_addr,
                        upstream_tag = info.tag.as_deref().unwrap_or(""),
                        query_id,
                        "DNS upstream query succeeded"
                    );
                }
                return Ok(response);
            }
            Err(DnsError::RateLimitCooldown { retry_after_ms }) => {
                // Admission lost a race with another 429 after the lock-free
                // precheck. No upstream I/O happened, so do not count it as an
                // attempted upstream query.
                metrics.cancel_upstream_start(selected_idx);
                if !had_lane_deadline {
                    lane_deadline = None;
                }
                last_cooldown_ms = Some(
                    last_cooldown_ms.map_or(retry_after_ms, |old: u64| old.min(retry_after_ms)),
                );
                continue;
            }
            Err(err) => {
                let timed_out = is_timeout_error(&err);
                metrics.record_upstream_error(selected_idx, up_start, timed_out);
                let info = upstream.connection_info();
                if event_enabled!(Level::DEBUG) {
                    debug!(
                        upstream_index = selected_idx,
                        upstream = %info.raw_addr,
                        upstream_tag = info.tag.as_deref().unwrap_or(""),
                        query_id,
                        error = %err,
                        "DNS upstream query failed"
                    );
                }
                let retry_elsewhere = matches!(&err, DnsError::DohRateLimited { .. })
                    || upstream.temporary_unavailable_for_ms().is_some();
                let err = contextualize_upstream_error(info, err);
                if retry_elsewhere {
                    // A candidate-specific timeout may be shorter than the
                    // lane budget. Continue only while the original lane
                    // deadline still has time remaining.
                    if timed_out
                        && lane_deadline.is_some_and(|(deadline, _)| deadline.remaining().is_none())
                    {
                        return Err(err);
                    }
                    last_retry_error = Some(err);
                    continue;
                }
                return Err(err);
            }
        }
    }
}
