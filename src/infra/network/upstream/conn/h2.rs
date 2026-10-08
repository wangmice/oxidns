// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{BufMut, Bytes};
use h2::client::{ResponseFuture, SendRequest};
use h2::{Ping, PingPong, SendStream};
use http::Version;
use tokio::select;
use tokio::sync::Notify;
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{debug, trace, warn};

use super::{PoolCapacityNotify, PoolUnavailableNotify};
use crate::infra::clock::AppClock;
use crate::infra::error::{DnsError, Result};
use crate::infra::network::buffer_pool::wire_buffer_pool;
use crate::infra::network::dial::{DialTarget, SocketOptions, TlsDialOptions, connect_tls};
use crate::infra::network::metrics::{
    KeepaliveResult, NetworkProtocol, UpstreamTimeoutStage, upstream_keepalive,
};
use crate::infra::network::proxy::{Socks5Opt, connect_tcp};
use crate::infra::network::response_validation::{DnsResponseIdPolicy, validate_dns_response};
use crate::infra::network::upstream::conn::doh::{
    MAX_DOH_DNS_BODY_SIZE, MAX_DOH_ERROR_BODY_SIZE, build_dns_get_request, build_dns_post_request,
    build_doh_request_uri, get_cap_buf_with_context_len, parse_doh_retry_after,
    validate_doh_content_type,
};
use crate::infra::network::upstream::pool::{ConnectionBuilder, DeadlineOutcome, QueryDeadline};
use crate::infra::network::upstream::{Connection, ConnectionInfo};
use crate::proto::Message;

const H2_DATA_FRAME_BUDGET: usize = 256 * 1024;
const H2_KEEPALIVE_ACK_TIMEOUT: Duration = Duration::from_secs(5);
const H2_STREAM_LIMIT_REFRESH_INTERVAL: Duration = Duration::from_millis(50);

// Pack lifecycle bits and the in-flight query count into one atomic word.
// Query admission and failed-keepalive retirement therefore share one atomic
// modification order, closing the race without a mutex or a CAS loop on the
// H2 query hot path.
// A connection can expose at most a u16 stream limit. Keep the packed query
// count in the low 16 bits, reserve bit 16 as a transient overflow marker,
// and leave a wide gap before lifecycle state bits so count arithmetic cannot
// carry into KEEPALIVE_GATE or CLOSED.
const H2_ACTIVITY_COUNT_MASK: u32 = u16::MAX as u32;
const H2_ACTIVITY_COUNT_OVERFLOW: u32 = 1 << 16;
const H2_ACTIVITY_KEEPALIVE_GATE: u32 = 1 << 30;
const H2_ACTIVITY_CLOSED: u32 = 1 << 31;
const H2_ACTIVITY_STATE_MASK: u32 =
    H2_ACTIVITY_COUNT_OVERFLOW | H2_ACTIVITY_KEEPALIVE_GATE | H2_ACTIVITY_CLOSED;
const H2_ACTIVITY_QUERY_MASK: u32 = H2_ACTIVITY_COUNT_MASK | H2_ACTIVITY_COUNT_OVERFLOW;

#[inline]
fn h2_now_tick_ms() -> u32 {
    AppClock::elapsed_millis() as u32
}

#[inline]
fn h2_elapsed_tick_ms(now_tick: u32, earlier_tick: u32) -> u32 {
    now_tick.wrapping_sub(earlier_tick)
}

#[inline]
fn h2_reconstruct_last_used_ms(now_ms: u64, last_used_tick: u32) -> u64 {
    let age_ms = h2_elapsed_tick_ms(now_ms as u32, last_used_tick) as u64;
    now_ms.saturating_sub(age_ms)
}

struct H2ActivityGuard<'a> {
    connection: &'a H2Connection,
}

impl Drop for H2ActivityGuard<'_> {
    fn drop(&mut self) {
        self.connection.release_query_activity();
    }
}

#[inline]
fn h2_pool_stream_limit(peer_limit: usize) -> u16 {
    peer_limit.clamp(1, u16::MAX as usize) as u16
}

#[inline]
fn update_h2_pool_stream_limit(cached: &AtomicU16, peer_limit: usize) -> Option<(u16, u16)> {
    let current = h2_pool_stream_limit(peer_limit);
    let previous = cached.swap(current, Ordering::AcqRel);
    (current > previous).then_some((previous, current))
}

enum H2RecvError {
    Connection(DnsError),
    Stream(DnsError),
    HttpStatus(DnsError),
    InvalidResponse(DnsError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H2KeepaliveRetirement {
    Retired,
    Deferred,
    Preserved,
}

fn classify_h2_error(context: &str, error: h2::Error) -> H2RecvError {
    let connection_scoped = error.is_go_away() || error.is_io();
    let error = DnsError::protocol(format!("{context}: {error}"));
    if connection_scoped {
        H2RecvError::Connection(error)
    } else {
        H2RecvError::Stream(error)
    }
}

async fn poll_keepalive_probe_until_timeout<F>(
    mut probe: std::pin::Pin<&mut F>,
    ack_timeout: Duration,
) -> Option<F::Output>
where
    F: std::future::Future + ?Sized,
{
    let timeout_sleep = sleep(ack_timeout);
    tokio::pin!(timeout_sleep);
    select! {
        biased;
        result = probe.as_mut() => Some(result),
        _ = timeout_sleep.as_mut() => None,
    }
}

async fn run_h2_keepalive(
    conn: Weak<H2Connection>,
    mut ping_pong: PingPong,
    interval: Duration,
    ack_timeout: Duration,
) {
    if interval.is_zero() {
        return;
    }
    let interval_ms = interval.as_millis().min(u64::MAX as u128) as u64;

    loop {
        sleep(interval).await;

        let Some(conn) = conn.upgrade() else {
            return;
        };
        if conn.is_closed() {
            return;
        }
        if conn.using_count() != 0 {
            continue;
        }

        // Snapshot successful DNS activity immediately before starting the
        // liveness probe. A generation change while the PING is pending proves
        // the connection transported useful DNS traffic even if the PING fails.
        let success_generation_before_ping = conn.success_generation.load(Ordering::Acquire);

        let last_used_before_ping = conn.last_used();
        let idle_ms = AppClock::elapsed_millis().saturating_sub(last_used_before_ping);
        if idle_ms < interval_ms {
            continue;
        }

        let ping = ping_pong.ping(Ping::opaque());
        tokio::pin!(ping);
        match poll_keepalive_probe_until_timeout(ping.as_mut(), ack_timeout).await {
            Some(Ok(_)) => {
                upstream_keepalive(NetworkProtocol::Doh2, KeepaliveResult::Success);
                trace!(
                    conn_id = conn.id,
                    upstream = %conn.upstream,
                    idle_ms,
                    "H2 keepalive ping acknowledged"
                );
            }
            Some(Err(error)) => {
                upstream_keepalive(NetworkProtocol::Doh2, KeepaliveResult::Failed);
                match conn.retire_after_keepalive_failure(success_generation_before_ping) {
                    H2KeepaliveRetirement::Retired => debug!(
                        conn_id = conn.id,
                        upstream = %conn.upstream,
                        ?error,
                        "H2 keepalive ping failed; retiring idle connection"
                    ),
                    H2KeepaliveRetirement::Deferred => debug!(
                        conn_id = conn.id,
                        upstream = %conn.upstream,
                        ?error,
                        "H2 keepalive ping failed during DNS activity; deferring retirement until overlapping queries drain"
                    ),
                    H2KeepaliveRetirement::Preserved => debug!(
                        conn_id = conn.id,
                        upstream = %conn.upstream,
                        ?error,
                        "H2 keepalive ping failed, but overlapping DNS activity proved the connection healthy"
                    ),
                }
                return;
            }
            None => {
                upstream_keepalive(NetworkProtocol::Doh2, KeepaliveResult::Timeout);
                let retirement =
                    conn.retire_after_keepalive_failure(success_generation_before_ping);
                match retirement {
                    H2KeepaliveRetirement::Retired => debug!(
                        conn_id = conn.id,
                        upstream = %conn.upstream,
                        timeout_ms = ack_timeout.as_millis(),
                        "H2 keepalive ping timed out; retiring idle connection"
                    ),
                    H2KeepaliveRetirement::Deferred => debug!(
                        conn_id = conn.id,
                        upstream = %conn.upstream,
                        timeout_ms = ack_timeout.as_millis(),
                        "H2 keepalive ping timed out during DNS activity; deferring retirement until overlapping queries drain"
                    ),
                    H2KeepaliveRetirement::Preserved => debug!(
                        conn_id = conn.id,
                        upstream = %conn.upstream,
                        timeout_ms = ack_timeout.as_millis(),
                        "H2 keepalive ping timed out, but overlapping DNS activity proved the connection healthy"
                    ),
                }
                if retirement == H2KeepaliveRetirement::Retired {
                    return;
                }

                // `h2` permits only one user PING at a time. Dropping the
                // timed-out future leaves that PING pending internally, so a
                // preserved connection could never start keepalive again.
                // Keep polling the same probe until a late PONG (or transport
                // closure) resolves it. Do not retain the H2Connection itself
                // while waiting indefinitely.
                let weak_conn = Arc::downgrade(&conn);
                drop(conn);
                match ping.await {
                    Ok(_) => {
                        let Some(conn) = weak_conn.upgrade() else {
                            return;
                        };
                        if conn.is_closed() {
                            return;
                        }
                        let reopened_gate = conn.clear_keepalive_retirement_gate();
                        trace!(
                            conn_id = conn.id,
                            upstream = %conn.upstream,
                            reopened_gate,
                            "H2 keepalive late ping acknowledgement received"
                        );
                    }
                    Err(error) => {
                        debug!(?error, "H2 keepalive pending ping failed after timeout");
                        return;
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct H2Connection {
    connection_info: Arc<ConnectionInfo>,
    id: u16,
    upstream: String,
    sender: SendRequest<Bytes>,
    /// Lifecycle bits plus the low 16-bit in-flight query count.
    activity: AtomicU32,
    /// Successful DNS response generation captured when a failed keepalive
    /// starts retirement. Read only on the failed-keepalive cold path.
    keepalive_failure_generation: AtomicU32,
    /// Increments after each validated DNS response. Generation comparison,
    /// rather than timestamp comparison, avoids same-millisecond false negatives.
    success_generation: AtomicU32,
    transport_error_reported: AtomicBool,
    /// Low 32 bits of AppClock milliseconds. Age calculations use wrapping
    /// subtraction; the public u64 timestamp is reconstructed on the cold path.
    last_used: AtomicU32,
    request_uri: String,
    use_post: bool,
    close_notify: Notify,
    /// Wakes queries that arrived while failed-keepalive retirement gated
    /// admission. The query hot path touches this only when the gate is set.
    keepalive_gate_notify: Notify,
    pool_unavailable_notify: PoolUnavailableNotify,
    pool_capacity_notify: PoolCapacityNotify,
    cached_stream_limit: AtomicU16,
}

#[async_trait]
impl Connection for H2Connection {
    fn close(&self) {
        if !self.mark_closed() {
            return;
        }
        debug!(conn_id = self.id,
            upstream = %self.upstream,
            upstream_tag = %self.connection_info.tag.as_deref().unwrap_or("<untagged>"),
            upstream_host = %self.connection_info.server_name,
            upstream_port = self.connection_info.port, "Closing DoH connection");
        // A single background driver waits for this signal. `notify_one()`
        // stores a permit when the waiter has not registered yet,
        // avoiding a lost close wakeup.
        // Also wake queries parked behind a keepalive retirement gate so they
        // can observe CLOSED instead of waiting indefinitely.
        self.keepalive_gate_notify.notify_waiters();
        self.close_notify.notify_one();
    }

    async fn query(&self, request: Message, _deadline: QueryDeadline) -> Result<Message> {
        let _guard = self.acquire_query_activity().await?;
        // Preserve the old second close check so a transport error that races
        // query admission is observed before a new H2 stream starts.
        if self.is_closed() {
            return Err(DnsError::protocol("DoH connection closed"));
        }
        self.query_inner(request).await
    }

    fn using_count(&self) -> u32 {
        let activity = self.activity.load(Ordering::Relaxed);
        if activity & H2_ACTIVITY_COUNT_OVERFLOW != 0 {
            return H2_ACTIVITY_COUNT_MASK;
        }
        activity & H2_ACTIVITY_COUNT_MASK
    }

    fn available(&self) -> bool {
        !self.is_closed()
    }

    fn register_unavailable_notify(&self, notify: Arc<dyn Fn() + Send + Sync>) {
        self.pool_unavailable_notify.register(notify);
        if self.is_closed() {
            self.pool_unavailable_notify.notify_pool();
        }
    }

    fn register_capacity_increase_notify(&self, notify: Arc<dyn Fn(u16, u16) + Send + Sync>) {
        // Cache refreshes are owned by the connection driver so updates stay
        // single-writer and cannot be reordered by registration racing a tick.
        self.pool_capacity_notify.register(notify);
    }

    fn max_concurrent_queries(&self) -> u16 {
        // Pool lookup is a high-QPS hot path. Keep it lock-free instead of
        // calling h2's `current_max_send_streams()`, which takes the protocol
        // stream-state mutex internally. The connection driver refreshes this
        // cache on a low-frequency cold path.
        self.cached_stream_limit.load(Ordering::Acquire)
    }

    fn last_used(&self) -> u64 {
        // Read the tick before the clock so a concurrent successful query cannot
        // publish a timestamp from the future relative to this snapshot.
        let last_used_tick = self.last_used.load(Ordering::Acquire);
        let now_ms = AppClock::elapsed_millis();
        h2_reconstruct_last_used_ms(now_ms, last_used_tick)
    }
}

impl H2Connection {
    fn refresh_pool_stream_limit(&self) {
        if let Some((previous, current)) = update_h2_pool_stream_limit(
            &self.cached_stream_limit,
            self.sender.current_max_send_streams(),
        ) {
            self.pool_capacity_notify.notify_pool(previous, current);
        }
    }

    #[inline]
    fn is_closed(&self) -> bool {
        self.activity.load(Ordering::Acquire) & H2_ACTIVITY_CLOSED != 0
    }

    fn release_query_activity(&self) {
        let previous = self.activity.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(
            previous & H2_ACTIVITY_QUERY_MASK != 0,
            "H2 query activity counter underflow"
        );

        // Keep the normal query-completion path to one packed-state bit test.
        // Generation loads and gate mutation stay on the failed-keepalive path.
        if previous & H2_ACTIVITY_KEEPALIVE_GATE == 0 {
            return;
        }
        if previous & (H2_ACTIVITY_COUNT_OVERFLOW | H2_ACTIVITY_CLOSED) != 0 {
            return;
        }

        // A single validated response is enough to disprove the failed PING as
        // a connection-level liveness signal. Reopen admission immediately;
        // do not make new queries wait for unrelated slow streams to drain.
        if self.cancel_keepalive_retirement_if_successful() {
            return;
        }

        // With no successful DNS evidence yet, only the final overlapping
        // activity release may turn the failed PING into connection retirement.
        // This also covers a query that arrived after the gate, temporarily
        // incremented the packed count, and then backed out before waiting.
        if previous & H2_ACTIVITY_COUNT_MASK == 1 {
            let _ = self.finish_keepalive_retirement();
        }
    }

    fn wake_keepalive_gate_waiters(&self) {
        self.keepalive_gate_notify.notify_waiters();
    }

    fn clear_keepalive_retirement_gate(&self) -> bool {
        let previous = self
            .activity
            .fetch_and(!H2_ACTIVITY_KEEPALIVE_GATE, Ordering::AcqRel);
        if previous & H2_ACTIVITY_KEEPALIVE_GATE == 0 {
            return false;
        }
        self.wake_keepalive_gate_waiters();
        true
    }

    fn cancel_keepalive_retirement_if_successful(&self) -> bool {
        let observed_generation = self.keepalive_failure_generation.load(Ordering::Acquire);
        if self.success_generation.load(Ordering::Acquire) == observed_generation {
            return false;
        }

        let _ = self.clear_keepalive_retirement_gate();
        true
    }

    async fn acquire_query_activity(&self) -> Result<H2ActivityGuard<'_>> {
        loop {
            // `fetch_add` participates in the same modification order as the
            // keepalive gate's `fetch_or`. A query admitted before the gate is
            // visible to retirement; a query arriving after it cannot start
            // protocol work and simply retries once the cold-path gate clears.
            let previous = self.activity.fetch_add(1, Ordering::AcqRel);
            let state = previous & H2_ACTIVITY_STATE_MASK;

            if previous & H2_ACTIVITY_COUNT_MASK == H2_ACTIVITY_COUNT_MASK {
                self.activity.fetch_sub(1, Ordering::Release);
                return Err(DnsError::protocol("H2 in-flight query counter exhausted"));
            }

            // Another admission may briefly expose the overflow marker while
            // rolling back an exhausted count. Back out directly instead of
            // running normal release logic, because the low count bits are
            // wrapped during this transient state.
            if state & H2_ACTIVITY_COUNT_OVERFLOW != 0 {
                self.activity.fetch_sub(1, Ordering::Release);
                if state & H2_ACTIVITY_CLOSED != 0 {
                    return Err(DnsError::protocol("DoH connection closed"));
                }
                return Err(DnsError::protocol("H2 in-flight query counter exhausted"));
            }

            if state & H2_ACTIVITY_CLOSED != 0 {
                self.release_query_activity();
                return Err(DnsError::protocol("DoH connection closed"));
            }

            if state & H2_ACTIVITY_KEEPALIVE_GATE != 0 {
                self.release_query_activity();

                // Register before the final state re-check. `notify_waiters`
                // does not retain permits, so enabling the Notified future
                // first avoids losing a gate-clear/close wakeup in between.
                let notified = self.keepalive_gate_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                let current = self.activity.load(Ordering::Acquire);
                if current & H2_ACTIVITY_CLOSED != 0 {
                    return Err(DnsError::protocol("DoH connection closed"));
                }
                if current & H2_ACTIVITY_KEEPALIVE_GATE != 0 {
                    notified.await;
                }
                continue;
            }

            return Ok(H2ActivityGuard { connection: self });
        }
    }

    fn retire_after_keepalive_failure(
        &self,
        observed_success_generation: u32,
    ) -> H2KeepaliveRetirement {
        // Publish the successful-response generation before the gate. Any query
        // release that observes the gate is therefore guaranteed to see this
        // baseline and can detect useful DNS activity while the PING was pending.
        self.keepalive_failure_generation
            .store(observed_success_generation, Ordering::Release);

        // Gate new query admission first. Because this is the same atomic word
        // as the in-flight count, `previous` is an exact snapshot of whether a
        // query won admission before the keepalive retirement gate.
        let previous = self
            .activity
            .fetch_or(H2_ACTIVITY_KEEPALIVE_GATE, Ordering::AcqRel);

        if previous & H2_ACTIVITY_CLOSED != 0 {
            return H2KeepaliveRetirement::Retired;
        }

        // Useful DNS traffic may already have completed while the PING was
        // pending. In that case the failed PING is stale evidence: reopen
        // admission immediately even if another older stream is still slow.
        if self.cancel_keepalive_retirement_if_successful() {
            return if self.is_closed() {
                H2KeepaliveRetirement::Retired
            } else {
                H2KeepaliveRetirement::Preserved
            };
        }

        if previous & H2_ACTIVITY_QUERY_MASK != 0 {
            // Do not kill a stream that entered while the PING was pending.
            // Keep the admission gate set only while there is still no
            // successful DNS evidence. Any successful release will reopen it.
            return H2KeepaliveRetirement::Deferred;
        }

        self.finish_keepalive_retirement()
    }

    fn finish_keepalive_retirement(&self) -> H2KeepaliveRetirement {
        if self.is_closed() {
            return H2KeepaliveRetirement::Retired;
        }

        // Re-check successful DNS activity because a response may race the last
        // overlapping query release after an earlier cold-path check.
        if self.cancel_keepalive_retirement_if_successful() {
            return if self.is_closed() {
                H2KeepaliveRetirement::Retired
            } else {
                H2KeepaliveRetirement::Preserved
            };
        }

        // The PING failed and every overlapping DNS query drained without a
        // successful response. Treat that combination as connection-level
        // liveness failure and let the pool build a replacement.
        self.close();
        H2KeepaliveRetirement::Retired
    }

    fn mark_closed(&self) -> bool {
        let previous = self.activity.fetch_or(H2_ACTIVITY_CLOSED, Ordering::AcqRel);
        if previous & H2_ACTIVITY_CLOSED != 0 {
            return false;
        }
        self.pool_unavailable_notify.notify_pool();
        true
    }

    fn report_transport_error(&self, raw_id: u16, error: &DnsError) {
        if !self.transport_error_reported.swap(true, Ordering::AcqRel) {
            warn!(
                conn_id = self.id,
            upstream = %self.upstream,
                raw_id,
                ?error,
                "H2 connection transport error"
            );
        } else {
            debug!(
                conn_id = self.id,
            upstream = %self.upstream,
                raw_id,
                ?error,
                "H2 stream failed after connection transport error"
            );
        }
    }

    async fn query_inner(&self, request: Message) -> Result<Message> {
        let raw_id = request.id();
        let mut body_bytes = wire_buffer_pool().acquire();
        request.append_to_with_id(0, &mut body_bytes)?;

        let (http_request, post_body) = if self.use_post {
            (
                build_dns_post_request(self.request_uri.as_str(), Version::HTTP_2)?,
                Some(Bytes::copy_from_slice(body_bytes.as_slice())),
            )
        } else {
            (
                build_dns_get_request(
                    self.request_uri.as_str(),
                    body_bytes.as_slice(),
                    Version::HTTP_2,
                )?,
                None,
            )
        };
        drop(body_bytes);

        // `ready()` is the authoritative protocol-level backpressure point.
        // The h2 state machine updates it when peer SETTINGS change during the
        // connection lifetime, while the pool separately enforces OxiDNS's
        // local per-connection load cap.
        let mut sender = match self.sender.clone().ready().await {
            Ok(sender) => sender,
            Err(error) => match classify_h2_error("H2 sender readiness error", error) {
                H2RecvError::Connection(error) => {
                    self.close();
                    self.report_transport_error(raw_id, &error);
                    return Err(error);
                }
                H2RecvError::Stream(error) => return Err(error),
                H2RecvError::HttpStatus(_) | H2RecvError::InvalidResponse(_) => unreachable!(),
            },
        };

        let end_stream = post_body.is_none();
        let (response_future, mut send_stream) = match sender.send_request(http_request, end_stream)
        {
            Ok(value) => value,
            Err(error) => match classify_h2_error("H2 send_request error", error) {
                H2RecvError::Connection(error) => {
                    self.close();
                    self.report_transport_error(raw_id, &error);
                    return Err(error);
                }
                H2RecvError::Stream(error) => return Err(error),
                H2RecvError::HttpStatus(_) | H2RecvError::InvalidResponse(_) => unreachable!(),
            },
        };

        if let Some(post_body) = post_body
            && let Err(error) = send_stream.send_data(post_body, true)
        {
            match classify_h2_error("H2 send_data error", error) {
                H2RecvError::Connection(error) => {
                    self.close();
                    self.report_transport_error(raw_id, &error);
                    return Err(error);
                }
                H2RecvError::Stream(error) => return Err(error),
                H2RecvError::HttpStatus(_) | H2RecvError::InvalidResponse(_) => unreachable!(),
            }
        }

        match recv(response_future, &mut send_stream).await {
            Ok(bytes) => {
                let mut resp = Message::from_bytes(&bytes)?;
                validate_dns_response(&request, &resp, DnsResponseIdPolicy::Exact(0))?;
                resp.set_id(raw_id);
                self.last_used.store(h2_now_tick_ms(), Ordering::Relaxed);
                self.success_generation.fetch_add(1, Ordering::Release);
                trace!(conn_id = self.id,
            upstream = %self.upstream, raw_id, "Received H2 response");
                Ok(resp)
            }
            Err(H2RecvError::Connection(e)) => {
                self.close();
                self.report_transport_error(raw_id, &e);
                Err(e)
            }
            Err(
                H2RecvError::Stream(e)
                | H2RecvError::HttpStatus(e)
                | H2RecvError::InvalidResponse(e),
            ) => Err(e),
        }
    }
}

/// Builder
#[derive(Debug)]
pub struct H2ConnectionBuilder {
    target: DialTarget,
    upstream: String,
    socket_options: SocketOptions,
    request_uri: String,
    use_post: bool,
    insecure_skip_verify: bool,
    socks5: Option<Socks5Opt>,
    keepalive_interval: Option<Duration>,
}

impl H2ConnectionBuilder {
    pub fn new(connection_info: &ConnectionInfo) -> Self {
        Self {
            upstream: connection_info.raw_addr.clone(),
            target: DialTarget::new(
                connection_info.remote_ip,
                connection_info.server_name.clone(),
                connection_info.port,
            ),
            socket_options: SocketOptions::new(
                connection_info.so_mark,
                connection_info.bind_to_device.clone(),
            ),
            request_uri: build_doh_request_uri(connection_info),
            use_post: connection_info.use_post,
            insecure_skip_verify: connection_info.insecure_skip_verify,
            socks5: connection_info.socks5.clone(),
            keepalive_interval: connection_info.keepalive_interval,
        }
    }
}

#[async_trait]
impl ConnectionBuilder<H2Connection> for H2ConnectionBuilder {
    async fn create_connection(
        &self,
        conn_id: u16,
        deadline: QueryDeadline,
        connection_info: Arc<ConnectionInfo>,
    ) -> Result<Arc<H2Connection>> {
        let stream = match deadline
            .run(connect_tcp(
                self.target.clone(),
                self.socket_options.clone(),
                self.socks5.clone(),
            ))
            .await
        {
            DeadlineOutcome::Completed(result) => result?,
            DeadlineOutcome::Expired => {
                return Err(deadline.timeout_error_for(UpstreamTimeoutStage::ConnectionCreate));
            }
        };

        let tls_stream = connect_tls(
            stream,
            TlsDialOptions::new(
                self.target.clone(),
                self.insecure_skip_verify,
                deadline.remaining().ok_or_else(|| {
                    deadline.timeout_error_for(UpstreamTimeoutStage::ConnectionCreate)
                })?,
                vec![b"h2".to_vec()],
            )
            .with_query_deadline(deadline, UpstreamTimeoutStage::ProtocolHandshake),
        )
        .await?;

        let mut builder = h2::client::Builder::new();
        builder.data_frame_budget(H2_DATA_FRAME_BUDGET);

        let (sender, mut connection) = match deadline.run(builder.handshake(tls_stream)).await {
            DeadlineOutcome::Completed(Ok(value)) => value,
            DeadlineOutcome::Completed(Err(e)) => {
                return Err(DnsError::protocol(format!("H2 handshake error: {}", e)));
            }
            DeadlineOutcome::Expired => {
                return Err(deadline.timeout_error_for(UpstreamTimeoutStage::ProtocolHandshake));
            }
        };

        let ping_pong = connection.ping_pong();
        let initial_stream_limit = h2_pool_stream_limit(sender.current_max_send_streams());

        let h2_conn = Arc::new(H2Connection {
            connection_info,
            id: conn_id,
            upstream: self.upstream.clone(),
            sender,
            activity: AtomicU32::new(0),
            keepalive_failure_generation: AtomicU32::new(0),
            success_generation: AtomicU32::new(0),
            transport_error_reported: AtomicBool::new(false),
            last_used: AtomicU32::new(h2_now_tick_ms()),
            request_uri: self.request_uri.clone(),
            use_post: self.use_post,
            close_notify: Notify::new(),
            keepalive_gate_notify: Notify::new(),
            pool_unavailable_notify: PoolUnavailableNotify::default(),
            pool_capacity_notify: PoolCapacityNotify::default(),
            cached_stream_limit: AtomicU16::new(initial_stream_limit),
        });

        if let (Some(ping_pong), Some(interval)) = (ping_pong, self.keepalive_interval) {
            let keepalive_conn = Arc::downgrade(&h2_conn);
            tokio::spawn(run_h2_keepalive(
                keepalive_conn,
                ping_pong,
                interval,
                H2_KEEPALIVE_ACK_TIMEOUT,
            ));
        }

        let _conn = h2_conn.clone();
        tokio::spawn(async move {
            let mut stream_limit_refresh = interval(H2_STREAM_LIMIT_REFRESH_INTERVAL);
            stream_limit_refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
            // `interval()` fires immediately once. Consume that tick so the
            // driver starts with the handshake snapshot and refreshes at the
            // configured cadence afterwards.
            stream_limit_refresh.tick().await;
            tokio::pin!(connection);
            // Keep one Notified future alive across timer ticks. Recreating it
            // inside `select!` would make the close branch cancellation-unsafe:
            // a timer tick winning the race could drop an already-notified
            // future and lose the single `notify_one()` permit from `close()`.
            let close_notified = _conn.close_notify.notified();
            tokio::pin!(close_notified);

            loop {
                select! {
                    res = connection.as_mut() => {
                        _conn.close();
                        match res {
                            Ok(()) => debug!(conn_id, upstream = %_conn.upstream, "H2 connection closed"),
                            Err(e) => debug!(conn_id, upstream = %_conn.upstream, ?e, "H2 connection error"),
                        }
                        break;
                    }
                    _ = close_notified.as_mut() => {
                        debug!(conn_id, upstream = %_conn.upstream, "H2 connection closed by notify");
                        break;
                    }
                    _ = stream_limit_refresh.tick() => {
                        _conn.refresh_pool_stream_limit();
                    }
                }
            }
        });

        Ok(h2_conn)
    }
}

async fn recv(
    response_future: ResponseFuture,
    send_stream: &mut SendStream<Bytes>,
) -> std::result::Result<Bytes, H2RecvError> {
    let response = response_future
        .await
        .map_err(|e| classify_h2_error("H2 response error", e))?;

    let status_code = response.status();
    if status_code == http::StatusCode::TOO_MANY_REQUESTS {
        let retry_after = parse_doh_retry_after(response.headers());
        send_stream.send_reset(h2::Reason::CANCEL);
        return Err(H2RecvError::HttpStatus(DnsError::doh_rate_limited(
            retry_after,
            "response body skipped after rate-limit headers",
        )));
    }

    if status_code.is_success() {
        validate_doh_content_type(response.headers()).map_err(H2RecvError::InvalidResponse)?;
    }
    let body_limit = if status_code.is_success() {
        MAX_DOH_DNS_BODY_SIZE
    } else {
        MAX_DOH_ERROR_BODY_SIZE
    };
    let mut response_bytes = get_cap_buf_with_context_len(&response, body_limit);
    let mut body = response.into_body();
    let mut flow_control = body.flow_control().clone();
    let mut truncated = false;

    while let Some(partial_bytes) = body.data().await {
        let partial_bytes = partial_bytes.map_err(|e| classify_h2_error("H2 body error", e))?;
        let chunk_len = partial_bytes.len();
        let remaining = body_limit.saturating_sub(response_bytes.len());
        let exceeds_limit = chunk_len > remaining;

        if exceeds_limit {
            if !status_code.is_success() {
                response_bytes.put_slice(&partial_bytes[..remaining]);
                truncated = true;
            }
        } else {
            response_bytes.put_slice(&partial_bytes);
        }

        // `h2` does not automatically return receive-window capacity after a
        // DATA frame is yielded. We have finished consuming (or
        // deliberately discarding) the entire chunk at this point, so
        // release the full frame length before waiting for the next
        // one. Otherwise a response larger than the current
        // stream window can stall indefinitely.
        if chunk_len != 0 {
            flow_control
                .release_capacity(chunk_len)
                .map_err(|e| classify_h2_error("H2 flow-control release error", e))?;
        }

        if exceeds_limit {
            if status_code.is_success() {
                return Err(H2RecvError::InvalidResponse(DnsError::protocol(
                    "DoH response body exceeds the 65535-byte DNS message limit",
                )));
            }
            break;
        }
    }

    if !status_code.is_success() {
        let error_string = String::from_utf8_lossy(response_bytes.as_ref());
        let suffix = if truncated { " (truncated)" } else { "" };
        Err(H2RecvError::HttpStatus(DnsError::protocol(format!(
            "http unsuccessful code: {}, message: {}{}",
            status_code, error_string, suffix
        ))))
    } else {
        Ok(response_bytes.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_h2_connection(
        last_used: u32,
    ) -> (
        Arc<H2Connection>,
        PingPong,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let _connection = h2::server::handshake(server_io)
                .await
                .expect("server handshake should succeed");
            std::future::pending::<()>().await;
        });

        let (sender, mut driver) = h2::client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let ping_pong = driver.ping_pong().expect("ping/pong should be available");
        let driver_task = tokio::spawn(async move {
            let _ = driver.await;
        });

        let connection = Arc::new(H2Connection {
            connection_info: Arc::new(
                ConnectionInfo::with_addr("https://dns.example.test/dns-query")
                    .expect("connection info should parse"),
            ),
            id: 1,
            upstream: "https://dns.example.test/dns-query".to_string(),
            sender,
            activity: AtomicU32::new(0),
            keepalive_failure_generation: AtomicU32::new(0),
            success_generation: AtomicU32::new(0),
            transport_error_reported: AtomicBool::new(false),
            last_used: AtomicU32::new(last_used),
            request_uri: "/dns-query".to_string(),
            use_post: false,
            close_notify: Notify::new(),
            keepalive_gate_notify: Notify::new(),
            pool_unavailable_notify: PoolUnavailableNotify::default(),
            pool_capacity_notify: PoolCapacityNotify::default(),
            cached_stream_limit: AtomicU16::new(1),
        });

        (connection, ping_pong, driver_task, server_task)
    }

    #[tokio::test]
    async fn keepalive_timeout_keeps_pending_probe_alive_for_late_completion() {
        let (sender, receiver) = tokio::sync::oneshot::channel::<u8>();
        let probe = async move {
            receiver
                .await
                .expect("late keepalive completion should still be observed")
        };
        tokio::pin!(probe);

        assert_eq!(
            poll_keepalive_probe_until_timeout(probe.as_mut(), Duration::from_millis(1)).await,
            None,
            "the first wait should report timeout without consuming the pending probe"
        );
        sender
            .send(7)
            .expect("timed-out probe future must still be alive");
        assert_eq!(probe.await, 7);
    }

    #[tokio::test]
    async fn late_keepalive_ack_reopens_deferred_gate_without_dns_success() {
        AppClock::start();
        let (connection, _ping_pong, driver_task, server_task) = test_h2_connection(10).await;
        let slow_query = connection
            .acquire_query_activity()
            .await
            .expect("query should enter before keepalive retirement is gated");

        assert_eq!(
            connection.retire_after_keepalive_failure(0),
            H2KeepaliveRetirement::Deferred
        );
        assert_ne!(
            connection.activity.load(Ordering::Acquire) & H2_ACTIVITY_KEEPALIVE_GATE,
            0,
            "failed keepalive must gate admission while liveness is unresolved"
        );

        assert!(
            connection.clear_keepalive_retirement_gate(),
            "a late PONG must cancel deferred retirement"
        );
        assert_eq!(
            connection.activity.load(Ordering::Acquire) & H2_ACTIVITY_KEEPALIVE_GATE,
            0
        );

        let admitted_query = tokio::time::timeout(
            Duration::from_millis(50),
            connection.acquire_query_activity(),
        )
        .await
        .expect("late PONG must reopen admission before the old slow query drains")
        .expect("connection should remain available after late PONG");
        drop(admitted_query);
        drop(slow_query);
        assert!(connection.available());

        driver_task.abort();
        server_task.abort();
    }

    #[test]
    fn h2_tick_age_and_timestamp_reconstruction_survive_u32_wrap() {
        let earlier_tick = u32::MAX - 4;
        let now_tick = 5;
        assert_eq!(h2_elapsed_tick_ms(now_tick, earlier_tick), 10);

        let now_ms = u32::MAX as u64 + 6;
        assert_eq!(
            h2_reconstruct_last_used_ms(now_ms, earlier_tick),
            u32::MAX as u64 - 4
        );
    }

    #[test]
    fn h2_activity_layout_keeps_counter_carry_out_of_lifecycle_bits() {
        assert_eq!(H2_ACTIVITY_COUNT_MASK, u16::MAX as u32);
        assert_eq!(H2_ACTIVITY_COUNT_OVERFLOW, 1 << 16);
        assert_eq!(H2_ACTIVITY_KEEPALIVE_GATE, 1 << 30);
        assert_eq!(H2_ACTIVITY_CLOSED, 1 << 31);
        assert_eq!(
            H2_ACTIVITY_QUERY_MASK & (H2_ACTIVITY_KEEPALIVE_GATE | H2_ACTIVITY_CLOSED),
            0
        );
    }

    #[tokio::test]
    async fn keepalive_timeout_retires_connection_and_notifies_pool() {
        AppClock::start();
        let (connection, ping_pong, driver_task, server_task) = test_h2_connection(0).await;
        let notifications = Arc::new(AtomicU32::new(0));
        let notifications_for_callback = notifications.clone();
        connection
            .pool_unavailable_notify
            .register(Arc::new(move || {
                notifications_for_callback.fetch_add(1, Ordering::Relaxed);
            }));

        run_h2_keepalive(
            Arc::downgrade(&connection),
            ping_pong,
            Duration::from_millis(1),
            Duration::from_millis(20),
        )
        .await;

        assert!(
            !connection.available(),
            "a failed keepalive must make the H2 connection unavailable"
        );
        assert_eq!(
            notifications.load(Ordering::Relaxed),
            1,
            "retiring the connection must notify its owning pool"
        );

        driver_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn keepalive_timeout_retires_after_overlapping_query_finishes_without_success() {
        AppClock::start();
        let (connection, _ping_pong, driver_task, server_task) = test_h2_connection(10).await;
        let notifications = Arc::new(AtomicU32::new(0));
        let notifications_for_callback = notifications.clone();
        connection
            .pool_unavailable_notify
            .register(Arc::new(move || {
                notifications_for_callback.fetch_add(1, Ordering::Relaxed);
            }));

        let query_guard = connection
            .acquire_query_activity()
            .await
            .expect("query should enter before keepalive retirement is gated");

        assert_eq!(
            connection.retire_after_keepalive_failure(0),
            H2KeepaliveRetirement::Deferred,
            "a query admitted while the ping is pending must defer retirement"
        );
        assert!(connection.available());
        assert_eq!(connection.using_count(), 1);

        drop(query_guard);
        assert_eq!(connection.using_count(), 0);
        assert!(
            !connection.available(),
            "a failed keepalive plus a drained query with no successful response must retire the connection"
        );
        assert_eq!(
            notifications.load(Ordering::Relaxed),
            1,
            "deferred retirement must notify the owning pool exactly once"
        );

        driver_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn keepalive_failure_reopens_gate_when_success_precedes_failure_with_slow_query() {
        AppClock::start();
        let (connection, _ping_pong, driver_task, server_task) = test_h2_connection(10).await;

        let successful_query = connection
            .acquire_query_activity()
            .await
            .expect("successful query should enter before the keepalive failure");
        let slow_query = connection
            .acquire_query_activity()
            .await
            .expect("slow query should enter before the keepalive failure");

        connection
            .success_generation
            .fetch_add(1, Ordering::Release);
        drop(successful_query);
        assert_eq!(connection.using_count(), 1);

        assert_eq!(
            connection.retire_after_keepalive_failure(0),
            H2KeepaliveRetirement::Preserved,
            "success during the pending PING must cancel retirement immediately"
        );
        assert_eq!(
            connection.activity.load(Ordering::Acquire) & H2_ACTIVITY_KEEPALIVE_GATE,
            0,
            "a prior successful response must not leave admission gated behind a slow query"
        );

        let admitted_query = tokio::time::timeout(
            Duration::from_millis(50),
            connection.acquire_query_activity(),
        )
        .await
        .expect("new query should not wait for the slow overlapping query")
        .expect("connection should remain available after successful DNS activity");
        drop(admitted_query);

        drop(slow_query);
        assert!(connection.available());

        driver_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn keepalive_failure_reopens_gate_on_first_success_while_slow_query_remains() {
        AppClock::start();
        let (connection, _ping_pong, driver_task, server_task) = test_h2_connection(10).await;

        let successful_query = connection
            .acquire_query_activity()
            .await
            .expect("successful query should enter before keepalive retirement is gated");
        let slow_query = connection
            .acquire_query_activity()
            .await
            .expect("slow query should enter before keepalive retirement is gated");

        assert_eq!(
            connection.retire_after_keepalive_failure(0),
            H2KeepaliveRetirement::Deferred,
            "failed PING must initially wait while no DNS query has succeeded"
        );
        assert_ne!(
            connection.activity.load(Ordering::Acquire) & H2_ACTIVITY_KEEPALIVE_GATE,
            0,
            "admission must remain gated until useful DNS activity proves transport health"
        );

        connection
            .success_generation
            .fetch_add(1, Ordering::Release);
        drop(successful_query);

        assert_eq!(connection.using_count(), 1);
        assert_eq!(
            connection.activity.load(Ordering::Acquire) & H2_ACTIVITY_KEEPALIVE_GATE,
            0,
            "the first successful overlapping response must reopen admission immediately"
        );

        let admitted_query = tokio::time::timeout(
            Duration::from_millis(50),
            connection.acquire_query_activity(),
        )
        .await
        .expect("new query should be released before the unrelated slow query drains")
        .expect("connection should remain available after successful DNS activity");
        drop(admitted_query);

        drop(slow_query);
        assert!(connection.available());

        driver_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn keepalive_timeout_preserves_connection_when_overlapping_query_succeeds() {
        AppClock::start();
        let (connection, _ping_pong, driver_task, server_task) = test_h2_connection(10).await;

        let query_guard = connection
            .acquire_query_activity()
            .await
            .expect("query should enter before keepalive retirement is gated");

        assert_eq!(
            connection.retire_after_keepalive_failure(0),
            H2KeepaliveRetirement::Deferred,
            "retirement must wait for the overlapping query"
        );

        // Keep last_used unchanged to prove success detection does not depend
        // on millisecond timestamp granularity.
        connection
            .success_generation
            .fetch_add(1, Ordering::Release);
        drop(query_guard);

        assert!(
            connection.available(),
            "successful DNS activity must cancel deferred keepalive retirement"
        );
        assert_eq!(connection.using_count(), 0);
        assert_eq!(
            connection.activity.load(Ordering::Acquire) & H2_ACTIVITY_KEEPALIVE_GATE,
            0,
            "successful DNS activity must reopen query admission"
        );

        driver_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn keepalive_timeout_preserves_connection_after_query_completed_while_ping_pending() {
        AppClock::start();
        let (connection, _ping_pong, driver_task, server_task) = test_h2_connection(10).await;

        let query_guard = connection
            .acquire_query_activity()
            .await
            .expect("query should enter before keepalive retirement is gated");
        // Keep last_used unchanged to prove success detection does not depend
        // on millisecond timestamp granularity.
        connection
            .success_generation
            .fetch_add(1, Ordering::Release);
        drop(query_guard);

        assert_eq!(
            connection.retire_after_keepalive_failure(0),
            H2KeepaliveRetirement::Preserved,
            "successful DNS activity during the pending ping must preserve the connection"
        );
        assert!(connection.available());
        assert_eq!(connection.using_count(), 0);

        driver_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn recv_releases_flow_control_capacity_between_data_frames() {
        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io)
                .await
                .expect("server handshake should succeed");
            let Some(Ok((_request, mut respond))) = connection.accept().await else {
                panic!("server should receive one request");
            };

            let response = http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/dns-message")
                .body(())
                .expect("response should build");
            let mut send_stream = respond
                .send_response(response, false)
                .expect("response headers should send");
            send_stream
                .send_data(Bytes::from(vec![0x5A; 128]), true)
                .expect("response body should queue");

            // Keep driving the server connection so WINDOW_UPDATE frames from
            // the client can release additional stream capacity.
            while let Some(result) = connection.accept().await {
                if let Err(error) = result {
                    panic!("server connection failed: {error}");
                }
            }
        });

        let mut client_builder = h2::client::Builder::new();
        client_builder.initial_window_size(16);
        let (mut sender, connection) = client_builder
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        sender = sender
            .ready()
            .await
            .expect("client sender should become ready");
        let request = http::Request::builder()
            .method("GET")
            .uri("https://dns.example.test/dns-query")
            .body(())
            .expect("request should build");
        let (response_future, mut send_stream) = sender
            .send_request(request, true)
            .expect("request should send");

        let response_bytes = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            recv(response_future, &mut send_stream),
        )
        .await
        .expect("response should not stall on the 16-byte H2 receive window");
        let response_bytes = match response_bytes {
            Ok(bytes) => bytes,
            Err(_) => panic!("response body should be received successfully"),
        };

        assert_eq!(response_bytes.len(), 128);
        assert!(response_bytes.iter().all(|byte| *byte == 0x5A));

        drop(sender);
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn recv_classifies_rst_stream_as_stream_local() {
        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io)
                .await
                .expect("server handshake should succeed");
            let Some(Ok((_request, mut respond))) = connection.accept().await else {
                panic!("server should receive one request");
            };
            respond.send_reset(h2::Reason::CANCEL);

            while let Some(result) = connection.accept().await {
                if let Err(error) = result {
                    panic!("server connection failed: {error}");
                }
            }
        });

        let (mut sender, connection) = h2::client::handshake(client_io)
            .await
            .expect("client handshake should succeed");
        let client_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        sender = sender
            .ready()
            .await
            .expect("client sender should become ready");
        let request = http::Request::builder()
            .method("GET")
            .uri("https://dns.example.test/dns-query")
            .body(())
            .expect("request should build");
        let (response_future, mut send_stream) = sender
            .send_request(request, true)
            .expect("request should send");

        match recv(response_future, &mut send_stream).await {
            Err(H2RecvError::Stream(_)) => {}
            Err(_) => panic!("RST_STREAM must remain stream-local"),
            Ok(_) => panic!("RST_STREAM must fail the request"),
        }

        drop(sender);
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn recv_returns_429_without_waiting_for_response_body() {
        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io)
                .await
                .expect("server handshake should succeed");
            let Some(Ok((_request, mut respond))) = connection.accept().await else {
                panic!("server should receive one request");
            };

            let response = http::Response::builder()
                .status(http::StatusCode::TOO_MANY_REQUESTS)
                .header(http::header::RETRY_AFTER, "7")
                .body(())
                .expect("response should build");
            let _open_body = respond
                .send_response(response, false)
                .expect("429 headers should send");

            while let Some(result) = connection.accept().await {
                if let Err(error) = result {
                    panic!("server connection failed: {error}");
                }
            }
        });

        let (mut sender, connection) = h2::client::handshake(client_io)
            .await
            .expect("client handshake should succeed");
        let client_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        sender = sender
            .ready()
            .await
            .expect("client sender should become ready");
        let request = http::Request::builder()
            .method("GET")
            .uri("https://dns.example.test/dns-query")
            .body(())
            .expect("request should build");
        let (response_future, mut send_stream) = sender
            .send_request(request, true)
            .expect("request should send");

        let error = tokio::time::timeout(
            Duration::from_millis(250),
            recv(response_future, &mut send_stream),
        )
        .await
        .expect("429 headers should be returned without waiting for body EOF")
        .expect_err("429 must be returned as an HTTP status error");

        match error {
            H2RecvError::HttpStatus(DnsError::DohRateLimited { retry_after, .. }) => {
                assert_eq!(retry_after, Some(Duration::from_secs(7)));
            }
            _ => panic!("expected structured 429 response"),
        }

        drop(sender);
        client_task.abort();
        server_task.abort();
    }

    #[test]
    fn test_h2_pool_stream_limit_keeps_liveness_floor_and_clamps_large_values() {
        assert_eq!(h2_pool_stream_limit(0), 1);
        assert_eq!(h2_pool_stream_limit(1), 1);
        assert_eq!(h2_pool_stream_limit(8), 8);
        assert_eq!(h2_pool_stream_limit(u16::MAX as usize), u16::MAX);
        assert_eq!(h2_pool_stream_limit(usize::MAX), u16::MAX);
    }

    #[test]
    fn test_h2_pool_stream_limit_cache_reports_only_increases() {
        let cached = AtomicU16::new(8);

        assert_eq!(update_h2_pool_stream_limit(&cached, 4), None);
        assert_eq!(cached.load(Ordering::Acquire), 4);
        assert_eq!(update_h2_pool_stream_limit(&cached, 4), None);
        assert_eq!(update_h2_pool_stream_limit(&cached, 16), Some((4, 16)));
        assert_eq!(cached.load(Ordering::Acquire), 16);
    }

    #[test]
    fn test_builder_new_uses_https_request_uri_and_flags() {
        let mut connection_info = ConnectionInfo::with_addr("https://dns.example.com/dns-query")
            .expect("connection info should parse");
        connection_info.insecure_skip_verify = true;
        connection_info.so_mark = Some(42);
        connection_info.bind_to_device = Some("utun9".to_string());
        connection_info.keepalive_interval = Some(Duration::from_secs(5));

        let builder = H2ConnectionBuilder::new(&connection_info);

        assert_eq!(builder.target.port(), 443);
        assert_eq!(builder.target.host(), "dns.example.com");
        assert_eq!(
            builder.request_uri,
            "https://dns.example.com/dns-query?dns="
        );
        assert!(builder.insecure_skip_verify);
        assert_eq!(builder.keepalive_interval, Some(Duration::from_secs(5)));
        assert_eq!(builder.socket_options.so_mark(), Some(42));
        assert_eq!(builder.socket_options.bind_to_device(), Some("utun9"));
    }

    #[test]
    fn test_builder_new_uses_post_uri_without_dns_parameter() {
        let mut connection_info =
            ConnectionInfo::with_addr("https://dns.example.com/dns-query?token=abc&profile=fast")
                .expect("connection info should parse");
        connection_info.use_post = true;

        let builder = H2ConnectionBuilder::new(&connection_info);

        assert!(builder.use_post);
        assert_eq!(
            builder.request_uri,
            "https://dns.example.com/dns-query?token=abc&profile=fast"
        );
    }

    #[test]
    fn test_builder_new_preserves_fixed_doh_query_parameters() {
        let connection_info =
            ConnectionInfo::with_addr("https://dns.example.com/dns-query?token=abc&profile=fast")
                .expect("connection info should parse");

        let builder = H2ConnectionBuilder::new(&connection_info);

        assert_eq!(
            builder.request_uri,
            "https://dns.example.com/dns-query?token=abc&profile=fast&dns="
        );
    }
}
