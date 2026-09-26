// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use rand::RngExt;
use tokio::task::JoinSet;
use tracing::{Level, debug, event_enabled, info};

use super::metrics::ForwardMetrics;
use super::selection::{ResponseSelectionMode, SelectedResponse, select_response};
use super::{contextualize_upstream_error, is_timeout_error};
use crate::core::context::DnsContext;
use crate::core::response::ResponseDisposition;
use crate::infra::error::{DnsError, Result};
use crate::infra::network::upstream::Upstream;
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

    pub(super) upstreams: Arc<Vec<Arc<dyn Upstream>>>,

    /// Whether to stop the executor chain after a successful upstream response.
    pub(super) short_circuit: bool,

    pub(super) response_selection: ResponseSelectionMode,

    pub(super) metrics: Arc<ForwardMetrics>,
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

        let mut join_set = JoinSet::new();
        let upstreams = self.upstreams.clone();
        let request = Arc::new(request);
        let next_candidate = Arc::new(AtomicUsize::new(0));
        let start_idx = rand::rng().random_range(0..total_upstreams);

        for _ in 0..self.active_concurrent.min(total_upstreams) {
            let upstreams = upstreams.clone();
            let request  = request.clone();
            let next_candidate = next_candidate.clone();
            let metrics = self.metrics.clone();
            join_set.spawn(async move {
                let mut last_cooldown_ms = None;
                let mut last_retry_error = None;
                loop {
                    let offset = next_candidate.fetch_add(1, Ordering::Relaxed);
                    if offset >= upstreams.len() {
                        return Err(last_retry_error.unwrap_or_else(|| {
                            DnsError::rate_limit_cooldown(last_cooldown_ms.unwrap_or(1))
                        }));
                    }

                    let selected_idx = (start_idx + offset) % upstreams.len();
                    let upstream = upstreams[selected_idx].clone();
                    if let Some(remaining_ms) = upstream.temporary_unavailable_for_ms() {
                        last_cooldown_ms = Some(
                            last_cooldown_ms.map_or(remaining_ms, |old: u64| old.min(remaining_ms)),
                        );
                        continue;
                    }

                    let query_id = request.id();
                    let up_start = metrics.record_upstream_start(selected_idx);
                    match upstream.query(request.as_ref().clone()).await {
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
                            last_cooldown_ms = Some(
                                last_cooldown_ms
                                    .map_or(retry_after_ms, |old: u64| old.min(retry_after_ms)),
                            );
                            continue;
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
                            let retry_elsewhere = matches!(&err, DnsError::DohRateLimited { .. })
                                || upstream.temporary_unavailable_for_ms().is_some();
                            let err = contextualize_upstream_error(info, err);
                            if retry_elsewhere {
                                last_retry_error = Some(err);
                                continue;
                            }
                            return Err(err);
                        }
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
            self.active_concurrent.min(total_upstreams),
            question,
            self.response_selection,
        )
        .await
    }
}
