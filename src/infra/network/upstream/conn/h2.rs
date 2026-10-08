// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later
use std::fmt::Debug;
#[cfg(test)]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{BufMut, Bytes};
use h2::client::{ResponseFuture, SendRequest};
use h2::{Ping, PingPong, SendStream};
use http::Version;
use tokio::select;
use tokio::sync::Notify;
use tokio::time::{MissedTickBehavior, interval, sleep, timeout};
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
const H2_ACTIVITY_COUNT_MASK: u64 = u32::MAX as u64;
const H2_ACTIVITY_KEEPALIVE_GATE: u64 = 1 << 62;
const H2_ACTIVITY_CLOSED: u64 = 1 << 63;
const H2_ACTIVITY_STATE_MASK: u64 = H2_ACTIVITY_KEEPALIVE_GATE | H2_ACTIVITY_CLOSED;

struct H2ActivityGuard<'a>(&'a AtomicU64);

impl Drop for H2ActivityGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
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

fn classify_h2_error(context: &str, error: h2::Error) -> H2RecvError {
    let connection_scoped = error.is_go_away() || error.is_io();
    let error = DnsError::protocol(format!("{context}: {error}"));
    if connection_scoped {
        H2RecvError::Connection(error)
    } else {
        H2RecvError::Stream(error)
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

        let last_used_before_ping = conn.last_used();
        let idle_ms = AppClock::elapsed_millis().saturating_sub(last_used_before_ping);
        if idle_ms < interval_ms {
            continue;
        }

        match timeout(ack_timeout, ping_pong.ping(Ping::opaque())).await {
            Ok(Ok(_)) => {
                upstream_keepalive(NetworkProtocol::Doh2, KeepaliveResult::Success);
                trace!(
                    conn_id = conn.id,
                    upstream = %conn.upstream,
                    idle_ms,
                    "H2 keepalive ping acknowledged"
                );
            }
            Ok(Err(error)) => {
                upstream_keepalive(NetworkProtocol::Doh2, KeepaliveResult::Failed);
                if conn.retire_after_keepalive_failure(last_used_before_ping) {
                    debug!(
                        conn_id = conn.id,
                        upstream = %conn.upstream,
                        ?error,
                        "H2 keepalive ping failed; retiring idle connection"
                    );
                } else {
                    debug!(
                        conn_id = conn.id,
                        upstream = %conn.upstream,
                        ?error,
                        "H2 keepalive ping failed during DNS activity; keeping connection open and disabling keepalive"
                    );
                }
                return;
            }
            Err(_) => {
                upstream_keepalive(NetworkProtocol::Doh2, KeepaliveResult::Timeout);
                if conn.retire_after_keepalive_failure(last_used_before_ping) {
                    debug!(
                        conn_id = conn.id,
                        upstream = %conn.upstream,
                        timeout_ms = ack_timeout.as_millis(),
                        "H2 keepalive ping timed out; retiring idle connection"
                    );
                } else {
                    debug!(
                        conn_id = conn.id,
                        upstream = %conn.upstream,
                        timeout_ms = ack_timeout.as_millis(),
                        "H2 keepalive ping timed out during DNS activity; keeping connection open and disabling keepalive"
                    );
                }
                return;
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
    /// Lifecycle bits plus the lower 32-bit in-flight query count.
    activity: AtomicU64,
    transport_error_reported: AtomicBool,
    last_used: AtomicU64,
    request_uri: String,
    use_post: bool,
    close_notify: Notify,
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
        (self.activity.load(Ordering::Relaxed) & H2_ACTIVITY_COUNT_MASK) as u32
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
        self.last_used.load(Ordering::Relaxed)
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

            if state & H2_ACTIVITY_CLOSED != 0 {
                self.activity.fetch_sub(1, Ordering::Release);
                return Err(DnsError::protocol("DoH connection closed"));
            }

            if state & H2_ACTIVITY_KEEPALIVE_GATE != 0 {
                self.activity.fetch_sub(1, Ordering::Release);
                tokio::task::yield_now().await;
                continue;
            }

            return Ok(H2ActivityGuard(&self.activity));
        }
    }

    fn retire_after_keepalive_failure(&self, observed_last_used: u64) -> bool {
        // Gate new query admission first. Because this is the same atomic word
        // as the in-flight count, `previous` is an exact snapshot of whether a
        // query won admission before the keepalive retirement gate.
        let previous = self
            .activity
            .fetch_or(H2_ACTIVITY_KEEPALIVE_GATE, Ordering::AcqRel);

        if previous & H2_ACTIVITY_CLOSED != 0 {
            return true;
        }

        let had_active_query = previous & H2_ACTIVITY_COUNT_MASK != 0;
        // A successful query that completed while the PING was pending proves
        // useful transport activity. The guard's Release decrement and this
        // AcqRel RMW make the preceding last_used update visible here.
        let had_successful_activity = self.last_used.load(Ordering::Acquire) != observed_last_used;

        if had_active_query || had_successful_activity {
            self.activity
                .fetch_and(!H2_ACTIVITY_KEEPALIVE_GATE, Ordering::Release);
            return self.is_closed();
        }

        self.close();
        true
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
                self.last_used
                    .store(AppClock::elapsed_millis(), Ordering::Relaxed);
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
            activity: AtomicU64::new(0),
            transport_error_reported: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
            request_uri: self.request_uri.clone(),
            use_post: self.use_post,
            close_notify: Notify::new(),
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
        last_used: u64,
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
            activity: AtomicU64::new(0),
            transport_error_reported: AtomicBool::new(false),
            last_used: AtomicU64::new(last_used),
            request_uri: "/dns-query".to_string(),
            use_post: false,
            close_notify: Notify::new(),
            pool_unavailable_notify: PoolUnavailableNotify::default(),
            pool_capacity_notify: PoolCapacityNotify::default(),
            cached_stream_limit: AtomicU16::new(1),
        });

        (connection, ping_pong, driver_task, server_task)
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
    async fn keepalive_timeout_does_not_close_query_started_while_ping_pending() {
        AppClock::start();
        let (connection, _ping_pong, driver_task, server_task) = test_h2_connection(10).await;

        let query_guard = connection
            .acquire_query_activity()
            .await
            .expect("query should enter before keepalive retirement is gated");

        assert!(
            !connection.retire_after_keepalive_failure(10),
            "a query admitted while the ping is pending must defer retirement"
        );
        assert!(connection.available());
        assert_eq!(connection.using_count(), 1);

        drop(query_guard);
        assert_eq!(connection.using_count(), 0);

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
        connection.last_used.store(11, Ordering::Relaxed);
        drop(query_guard);

        assert!(
            !connection.retire_after_keepalive_failure(10),
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
