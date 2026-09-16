// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use http::header::CONTENT_LENGTH;
use rustls::ServerConfig;
use tokio::sync::{OwnedSemaphorePermit, oneshot, watch};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::plugin::server::http::extract_client_ip;
use crate::plugin::server::http::http_dispatcher::HttpDispatcher;
use crate::plugin::server::http::http3_quinn::{
    H3PeerStopQueue, H3PeerStoppedFuture, H3PeerStoppedResult, ServerBidiStream,
    ServerQuinnConnection,
};
use crate::plugin::server::{
    ConnectionGuard, DEFAULT_QUIC_MAX_BIDI_STREAMS, DEFAULT_SERVER_MAX_INFLIGHT_REQUESTS,
    InboundRequestLimiter, quic_endpoint,
};

const MAX_HTTP3_BODY_SIZE: usize = 64 * 1024;
const HTTP3_REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP3_REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP3_REQUEST_EXECUTION_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP3_RESPONSE_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP3_REQUEST_LIFETIME_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
struct H3RequestDeadline {
    at: Instant,
}

#[derive(Clone, Copy, Debug)]
struct H3PhaseDeadline {
    at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct H3RequestTimedOut;

#[derive(Debug)]
enum H3PhaseOutcome<T> {
    Completed(T),
    PeerStopped(H3PeerStoppedResult),
    Deadline,
}

impl H3RequestDeadline {
    #[inline]
    fn new() -> Self {
        Self {
            at: Instant::now() + HTTP3_REQUEST_LIFETIME_TIMEOUT,
        }
    }

    #[inline]
    fn phase(&self, timeout: Duration) -> H3PhaseDeadline {
        H3PhaseDeadline {
            at: self.at.min(Instant::now() + timeout),
        }
    }
}

impl H3PhaseDeadline {
    #[inline]
    fn after(timeout: Duration) -> Self {
        Self {
            at: Instant::now() + timeout,
        }
    }

    #[inline]
    async fn run<F>(&self, future: F) -> Result<F::Output, H3RequestTimedOut>
    where
        F: Future,
    {
        timeout_at(self.at, future)
            .await
            .map_err(|_| H3RequestTimedOut)
    }
}

#[inline]
async fn run_h3_phase<F>(
    peer_stopped: &mut H3PeerStoppedFuture,
    deadline: H3PhaseDeadline,
    future: F,
) -> H3PhaseOutcome<F::Output>
where
    F: Future,
{
    tokio::select! {
        biased;
        stopped = peer_stopped.as_mut() => H3PhaseOutcome::PeerStopped(stopped),
        result = deadline.run(future) => match result {
            Ok(value) => H3PhaseOutcome::Completed(value),
            Err(_) => H3PhaseOutcome::Deadline,
        },
    }
}

#[derive(Debug)]
enum H3BodyReadError {
    Http(http::StatusCode),
}

type H3ServerRequestStream = h3::server::RequestStream<ServerBidiStream<Bytes>, Bytes>;

enum H3HeaderOutcome {
    Resolved {
        request: http::Request<()>,
        stream: H3ServerRequestStream,
        peer_stopped: H3PeerStoppedFuture,
    },
    Failed(h3::error::StreamError),
    PeerStopped(H3PeerStoppedResult),
    Deadline,
}

async fn resolve_h3_headers(
    resolver: h3::server::RequestResolver<ServerQuinnConnection, Bytes>,
    mut peer_stopped: H3PeerStoppedFuture,
    header_deadline: H3PhaseDeadline,
) -> H3HeaderOutcome {
    match run_h3_phase(
        &mut peer_stopped,
        header_deadline,
        resolver.resolve_request(),
    )
    .await
    {
        H3PhaseOutcome::Completed(Ok((request, stream))) => H3HeaderOutcome::Resolved {
            request,
            stream,
            peer_stopped,
        },
        H3PhaseOutcome::Completed(Err(error)) => H3HeaderOutcome::Failed(error),
        H3PhaseOutcome::PeerStopped(stopped) => H3HeaderOutcome::PeerStopped(stopped),
        H3PhaseOutcome::Deadline => H3HeaderOutcome::Deadline,
    }
}

/// Main HTTP/3 server loop (over QUIC)
///
/// Creates an HTTP/3 endpoint, accepts QUIC connections, and spawns
/// handler tasks for each connection and per-stream request. Uses a task
/// tracker and cancellation token to manage active connections without
/// polling completed tasks from the accept loop.
///
/// # Architecture
/// - Binds a UDP socket for QUIC
/// - Requires TLS configuration (HTTP/3 mandates TLS over QUIC)
/// - Accepts QUIC connections and performs HTTP/3 handshake
/// - Spawns a task per connection and per request for concurrency
///
/// # Parameters
/// - `addr`: Listen address
/// - `dispatcher`: HTTP request dispatcher for routing
/// - `server_config`: TLS server config (required for HTTP/3)
/// - `idle_timeout`: Connection idle timeout in seconds (transport-level)
/// - `src_ip_header`: HTTP header name to extract real client IP
/// - `request_limiter`: Shared server-wide request admission budget
#[hotpath::measure]
#[allow(clippy::too_many_arguments)]
pub async fn run_server(
    addr: SocketAddr,
    dispatcher: Arc<HttpDispatcher>,
    mut server_config: ServerConfig,
    idle_timeout: Duration,
    src_ip_header: Option<String>,
    request_limiter: InboundRequestLimiter,
    mut shutdown_rx: watch::Receiver<bool>,
    startup_tx: Option<oneshot::Sender<Result<(), String>>>,
) {
    let mut startup_tx = startup_tx;
    server_config = http3_server_config(server_config);

    let endpoint = match quic_endpoint::build_quic_endpoint(addr, server_config, idle_timeout) {
        Ok(value) => value,
        Err(e) => {
            if let Some(tx) = startup_tx.take() {
                let _ = tx.send(Err(format!("QUIC endpoint build failed: {}", e)));
            }
            error!("QUIC endpoint build failed: {}", e);
            return;
        }
    };

    if let Some(tx) = startup_tx.take() {
        let _ = tx.send(Ok(()));
    }

    info!(
        listen = %addr,
        idle_timeout_secs = idle_timeout.as_secs(),
        max_inflight_requests = DEFAULT_SERVER_MAX_INFLIGHT_REQUESTS,
        max_bidi_streams = DEFAULT_QUIC_MAX_BIDI_STREAMS,
        "HTTP/3 server listening"
    );

    // Wrap header name in Arc to avoid cloning Strings per request
    let src_ip_header = src_ip_header.map(Arc::from);

    let tasks = TaskTracker::new();
    let shutdown_token = CancellationToken::new();
    let active_connections = Arc::new(AtomicU64::new(0));
    loop {
        // Accept new connections
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    break;
                }
            }
            accept_result = endpoint.accept() => {
                if let Some(connecting) = accept_result {
                    let active = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                    let dispatcher = dispatcher.clone();
                    let src_ip_header = src_ip_header.clone();
                    let task_shutdown = shutdown_token.clone();
                    let active_connections = active_connections.clone();
                    let request_limiter = request_limiter.clone();
                    tasks.spawn(async move {
                        let _connection_guard =
                            ConnectionGuard::new(active_connections.clone(), connecting.remote_address(), "HTTP/3");
                        let request_tasks = TaskTracker::new();
                        let request_cancel = CancellationToken::new();
                        let connection_request_tasks = request_tasks.clone();
                        let connection_request_cancel = request_cancel.clone();

                        tokio::select! {
                            _ = task_shutdown.cancelled() => {}
                            _ = handle_h3_connection(
                                connecting,
                                dispatcher,
                                src_ip_header,
                                request_limiter,
                                connection_request_tasks,
                                connection_request_cancel,
                            ) => {}
                        }

                        request_cancel.cancel();
                        request_tasks.close();
                        request_tasks.wait().await;
                    });
                    debug!("New QUIC connection started (active: {})", active);
                }
            }
        }
    }

    shutdown_token.cancel();
    tasks.close();
    tasks.wait().await;
    info!(listen = %addr, "HTTP/3 server stopped");
}

/// Handle a single QUIC connection and all its HTTP/3 request streams
#[hotpath::measure]
async fn handle_h3_connection(
    connecting: quinn::Incoming,
    dispatcher: Arc<HttpDispatcher>,
    src_ip_header: Option<Arc<str>>,
    request_limiter: InboundRequestLimiter,
    request_tasks: TaskTracker,
    request_cancel: CancellationToken,
) {
    let src = connecting.remote_address();

    let connection = match connecting.await {
        Ok(c) => c,
        Err(e) => {
            warn!("QUIC handshake failed for {}: {}", src, e);
            return;
        }
    };

    let server_name = extract_tls_server_name(&connection).map(Arc::<str>::from);
    let connection_liveness = connection.clone();

    debug!("HTTP/3 connection established with {}", src);

    let peer_stops = H3PeerStopQueue::default();
    let transport = ServerQuinnConnection::new(connection, peer_stops.clone());
    let mut h3_conn: h3::server::Connection<ServerQuinnConnection, Bytes> =
        match h3::server::Connection::new(transport).await {
            Ok(conn) => conn,
            Err(e) => {
                debug!("HTTP/3 handshake error from {}: {}", src, e);
                return;
            }
        };

    // Header resolution stays inside the connection task instead of spawning
    // one Tokio task per incomplete request. `FuturesUnordered` lets later
    // streams make progress while one peer withholds HEADERS, while QUIC's
    // max-bidi-stream limit still bounds this set per connection.
    let mut pending_headers = FuturesUnordered::new();

    loop {
        tokio::select! {
            biased;
            _ = request_cancel.cancelled() => return,
            resolved = pending_headers.next(), if !pending_headers.is_empty() => {
                let Some(resolved) = resolved else {
                    continue;
                };

                let (request, mut stream, mut peer_stopped) = match resolved {
                    H3HeaderOutcome::Resolved {
                        request,
                        stream,
                        peer_stopped,
                    } => (request, stream, peer_stopped),
                    H3HeaderOutcome::Failed(error) => {
                        warn!("Failed to resolve HTTP/3 request from {}: {}", src, error);
                        continue;
                    }
                    H3HeaderOutcome::PeerStopped(stopped) => {
                        log_h3_peer_stop(src, "request headers", &stopped);
                        continue;
                    }
                    H3HeaderOutcome::Deadline => {
                        warn!(
                            client = %src,
                            "HTTP/3 request header deadline exceeded; dropping stream"
                        );
                        continue;
                    }
                };

                // Preserve the global admission invariant: a fully resolved
                // request obtains capacity before its handler task is spawned.
                // When the server is saturated, stopping accept on this
                // connection is intentional bounded backpressure.
                let permit = tokio::select! {
                    biased;
                    stopped = peer_stopped.as_mut() => {
                        cancel_h3_stream_after_peer_stop(
                            &mut stream,
                            src,
                            "admission",
                            stopped,
                        );
                        continue;
                    }
                    _ = request_cancel.cancelled() => return,
                    _ = connection_liveness.closed() => return,
                    permit = request_limiter.acquire() => permit,
                };

                let dispatcher = dispatcher.clone();
                let src_ip_header = src_ip_header.clone();
                let server_name = server_name.clone();
                let task_cancel = request_cancel.clone();
                let request_deadline = H3RequestDeadline::new();

                request_tasks.spawn(async move {
                    tokio::select! {
                        _ = task_cancel.cancelled() => {}
                        _ = handle_h3_request(
                            request,
                            stream,
                            dispatcher,
                            src,
                            src_ip_header,
                            server_name,
                            request_deadline,
                            peer_stopped,
                            permit,
                        ) => {}
                    }
                });
            }
            accepted = h3_conn.accept() => {
                let resolver = match accepted {
                    Ok(Some(request)) => request,
                    Ok(None) => {
                        debug!("HTTP/3 connection closed by {}", src);
                        return;
                    }
                    Err(e) => {
                        warn!("HTTP/3 connection accept error from {}: {}", src, e);
                        // `h3::server::Connection::accept` reports
                        // connection-level errors. The h3 crate caches handled
                        // connection errors, so retrying can spin on the same
                        // terminal error.
                        return;
                    }
                };

                // `ServerQuinnConnection::poll_accept_bidi` publishes the
                // passive STOP_SENDING watcher immediately before h3 returns
                // this resolver. One accept loop per connection keeps the
                // lock-free FIFO aligned with accepted stream order.
                let Some(peer_stopped) = peer_stops.pop_front() else {
                    warn!(
                        client = %src,
                        "HTTP/3 accepted request missing peer STOP_SENDING watcher"
                    );
                    return;
                };

                let header_deadline = H3PhaseDeadline::after(HTTP3_REQUEST_HEADER_TIMEOUT);
                pending_headers.push(resolve_h3_headers(
                    resolver,
                    peer_stopped,
                    header_deadline,
                ));
            }
        }
    }
}

/// Handle a single HTTP/3 request stream
async fn handle_h3_request(
    request: http::Request<()>,
    mut stream: H3ServerRequestStream,
    dispatcher: Arc<HttpDispatcher>,
    src: SocketAddr,
    src_ip_header: Option<Arc<str>>,
    server_name: Option<Arc<str>>,
    request_deadline: H3RequestDeadline,
    mut peer_stopped: H3PeerStoppedFuture,
    permit: OwnedSemaphorePermit,
) {
    let method = request.method().clone();
    let uri = request.uri();
    let path = Arc::from(uri.path());
    let query = uri.query().map(Arc::from);
    let headers = request.headers();

    let client_addr = extract_client_ip(headers, &src_ip_header, src);

    debug!(
        "Received {} {} from {} (real: {})",
        method, path, src, client_addr
    );

    // One timer covers the entire body phase. Individual DATA frames do not
    // refresh it, and the peer STOP_SENDING watcher can still cancel the
    // admitted request immediately while the body is incomplete.
    let body_deadline = request_deadline.phase(HTTP3_REQUEST_BODY_TIMEOUT);
    let body = match run_h3_phase(
        &mut peer_stopped,
        body_deadline,
        read_h3_body(&mut stream, src),
    )
    .await
    {
        H3PhaseOutcome::Completed(Ok(body)) => body,
        H3PhaseOutcome::Completed(Err(H3BodyReadError::Http(status))) => {
            // Error response flow control belongs to the transport, not the
            // shared executor admission budget.
            drop(permit);
            let response_deadline = request_deadline.phase(HTTP3_RESPONSE_SEND_TIMEOUT);
            let _ = send_h3_error_response(&mut stream, status, src, response_deadline).await;
            return;
        }
        H3PhaseOutcome::Deadline => {
            cancel_h3_stream_on_deadline(&mut stream, src, "request body");
            return;
        }
        H3PhaseOutcome::PeerStopped(stopped) => {
            cancel_h3_stream_after_peer_stop(&mut stream, src, "request body", stopped);
            return;
        }
    };

    let executor_deadline = request_deadline.phase(HTTP3_REQUEST_EXECUTION_TIMEOUT);
    let response = match run_h3_phase(
        &mut peer_stopped,
        executor_deadline,
        dispatcher.handle_request(method, path, query, body, client_addr, server_name),
    )
    .await
    {
        H3PhaseOutcome::Completed(response) => response,
        H3PhaseOutcome::PeerStopped(stopped) => {
            cancel_h3_stream_after_peer_stop(&mut stream, src, "executor", stopped);
            return;
        }
        H3PhaseOutcome::Deadline => {
            cancel_h3_stream_on_deadline(&mut stream, src, "executor");
            return;
        }
    };

    // The admission budget protects request parsing/execution and upstream
    // work. Once the DNS response exists, slow client flow control must not
    // consume one of the shared HTTP/2 + HTTP/3 request permits.
    drop(permit);

    let (parts, response_bytes) = response.into_parts();

    let h3_response = match http::Response::builder()
        .status(parts.status)
        .version(parts.version)
        .body(())
    {
        Ok(mut resp) => {
            *resp.headers_mut() = parts.headers;
            resp
        }
        Err(e) => {
            warn!("Failed to build HTTP/3 response: {}", e);
            let response_deadline = request_deadline.phase(HTTP3_RESPONSE_SEND_TIMEOUT);
            let _ = send_h3_error_response(
                &mut stream,
                http::StatusCode::INTERNAL_SERVER_ERROR,
                src,
                response_deadline,
            )
            .await;
            return;
        }
    };

    let response_deadline = request_deadline.phase(HTTP3_RESPONSE_SEND_TIMEOUT);
    let _ = send_h3_response(
        &mut stream,
        h3_response,
        response_bytes,
        src,
        response_deadline,
    )
    .await;
}

#[inline]
async fn read_h3_body(
    stream: &mut H3ServerRequestStream,
    src: SocketAddr,
) -> Result<Bytes, H3BodyReadError> {
    let mut buf = BytesMut::with_capacity(2048);

    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) => {
                buf.put(chunk);
                if buf.len() > MAX_HTTP3_BODY_SIZE {
                    warn!(
                        "HTTP/3 request body too large from {}: {} bytes",
                        src,
                        buf.len()
                    );
                    return Err(H3BodyReadError::Http(http::StatusCode::PAYLOAD_TOO_LARGE));
                }
            }
            Ok(None) => return Ok(buf.freeze()),
            Err(e) => {
                warn!("Failed to read HTTP/3 request body from {}: {}", src, e);
                return Err(H3BodyReadError::Http(http::StatusCode::BAD_REQUEST));
            }
        }
    }
}

#[inline]
async fn send_h3_response(
    stream: &mut H3ServerRequestStream,
    response: http::Response<()>,
    response_bytes: Bytes,
    src: SocketAddr,
    response_deadline: H3PhaseDeadline,
) -> Result<(), ()> {
    let send = async {
        stream.send_response(response).await?;
        stream.send_data(response_bytes).await?;
        stream.finish().await
    };

    match response_deadline.run(send).await {
        Ok(Ok(())) => {
            debug!("Response sent to {}", src);
            Ok(())
        }
        Ok(Err(e)) => {
            // A peer STOP_SENDING is surfaced by the Quinn-backed send path as
            // a stream error, so the response phase does not need a second
            // passive stopped watcher/select on every write step.
            debug!("HTTP/3 response stream ended for {}: {}", src, e);
            Err(())
        }
        Err(_) => {
            cancel_h3_stream_on_deadline(stream, src, "response send");
            Err(())
        }
    }
}

#[inline]
async fn send_h3_error_response(
    stream: &mut H3ServerRequestStream,
    status: http::StatusCode,
    src: SocketAddr,
    response_deadline: H3PhaseDeadline,
) -> Result<(), ()> {
    let response = match http::Response::builder()
        .status(status)
        .header(CONTENT_LENGTH, 0)
        .body(())
    {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to build HTTP/3 error response for {}: {}", src, e);
            return Err(());
        }
    };

    let send = async {
        stream.send_response(response).await?;
        stream.finish().await
    };

    match response_deadline.run(send).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            debug!("HTTP/3 error response stream ended for {}: {}", src, e);
            Err(())
        }
        Err(_) => {
            cancel_h3_stream_on_deadline(stream, src, "error response send");
            Err(())
        }
    }
}

#[inline]
fn log_h3_peer_stop(src: SocketAddr, phase: &'static str, stopped: &H3PeerStoppedResult) {
    match stopped {
        Ok(code) => debug!(
            client = %src,
            phase,
            %code,
            "Cancelling HTTP/3 request after client STOP_SENDING"
        ),
        Err(error) => debug!(
            client = %src,
            phase,
            error = ?error,
            "QUIC connection lost while HTTP/3 request was active"
        ),
    }
}

#[inline]
fn cancel_h3_stream(stream: &mut h3::server::RequestStream<ServerBidiStream<Bytes>, Bytes>) {
    stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
}

#[inline]
fn cancel_h3_stream_after_peer_stop(
    stream: &mut h3::server::RequestStream<ServerBidiStream<Bytes>, Bytes>,
    src: SocketAddr,
    phase: &'static str,
    stopped: H3PeerStoppedResult,
) {
    log_h3_peer_stop(src, phase, &stopped);
    cancel_h3_stream(stream);
}

#[inline]
fn cancel_h3_stream_on_deadline(
    stream: &mut h3::server::RequestStream<ServerBidiStream<Bytes>, Bytes>,
    src: SocketAddr,
    phase: &'static str,
) {
    warn!(client = %src, phase, "HTTP/3 request deadline exceeded; cancelling stream");
    cancel_h3_stream(stream);
}

#[inline]
fn extract_tls_server_name(connection: &quinn::Connection) -> Option<String> {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.server_name)
        .map(|name| name.to_ascii_lowercase())
}

fn http3_server_config(mut server_config: ServerConfig) -> ServerConfig {
    server_config.alpn_protocols = vec![b"h3".to_vec()];
    server_config
}

#[cfg(test)]
mod tests {
    use std::fmt::{Debug, Formatter};

    use rustls::ServerConfig;
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;

    use super::*;

    struct RejectingResolver;

    impl Debug for RejectingResolver {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str("RejectingResolver")
        }
    }

    impl ResolvesServerCert for RejectingResolver {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            None
        }
    }

    fn dummy_server_config() -> ServerConfig {
        crate::infra::network::tls_config::install_default_provider();
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(RejectingResolver))
    }

    #[test]
    fn test_http3_server_config_sets_h3_alpn() {
        let server_config = http3_server_config(dummy_server_config());

        assert_eq!(server_config.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[tokio::test(start_paused = true)]
    async fn phase_deadline_is_absolute_across_repeated_operations() {
        let phase_deadline = H3PhaseDeadline {
            at: Instant::now() + Duration::from_secs(5),
        };

        let first = phase_deadline
            .run(tokio::time::sleep(Duration::from_secs(3)))
            .await;
        assert!(
            first.is_ok(),
            "the first operation should finish before the deadline"
        );

        let second = phase_deadline
            .run(tokio::time::sleep(Duration::from_secs(3)))
            .await;
        assert!(
            second.is_err(),
            "repeated operations must share one absolute phase deadline"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn request_lifetime_caps_later_phase_deadline() {
        let request_deadline = H3RequestDeadline::new();
        tokio::time::advance(Duration::from_secs(28)).await;
        let response_deadline = request_deadline.phase(HTTP3_RESPONSE_SEND_TIMEOUT);

        let result = response_deadline
            .run(tokio::time::sleep(Duration::from_secs(3)))
            .await;

        assert!(
            result.is_err(),
            "a phase cap must never extend the admitted request lifetime"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn peer_stop_cancels_stalled_phase_and_releases_admission_permit() {
        let limiter = InboundRequestLimiter::new(1);
        let permit = limiter.acquire().await;
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dropped_in_task = dropped.clone();

        let request = tokio::spawn(async move {
            struct DropSignal(Arc<std::sync::atomic::AtomicBool>);
            impl Drop for DropSignal {
                fn drop(&mut self) {
                    self.0.store(true, std::sync::atomic::Ordering::Release);
                }
            }

            let _permit = permit;
            let mut peer_stopped: H3PeerStoppedFuture = Box::pin(async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(quinn::VarInt::from_u32(0x10C))
            });
            let phase_deadline = H3PhaseDeadline {
                at: Instant::now() + Duration::from_secs(30),
            };
            let stalled = async move {
                let _drop_signal = DropSignal(dropped_in_task);
                std::future::pending::<()>().await;
            };

            assert!(matches!(
                run_h3_phase(&mut peer_stopped, phase_deadline, stalled).await,
                H3PhaseOutcome::PeerStopped(Ok(_))
            ));
        });

        request.await.expect("peer-stop task should complete");
        assert!(
            dropped.load(std::sync::atomic::Ordering::Acquire),
            "dropping the stalled executor future must propagate cancellation"
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), limiter.acquire())
            .await
            .expect("peer STOP_SENDING must release admission capacity");
    }

    #[tokio::test(start_paused = true)]
    async fn request_deadline_releases_admission_permit_when_work_stalls() {
        let limiter = InboundRequestLimiter::new(1);
        let permit = limiter.acquire().await;
        let request_deadline = H3RequestDeadline::new();
        let executor_deadline = request_deadline.phase(HTTP3_REQUEST_EXECUTION_TIMEOUT);

        let request = tokio::spawn(async move {
            let _permit = permit;
            let timed_out = executor_deadline
                .run(std::future::pending::<()>())
                .await
                .is_err();
            assert!(
                timed_out,
                "stalled request work must hit the request deadline"
            );
        });

        request.await.expect("deadline task should complete");

        let _ = tokio::time::timeout(Duration::from_secs(1), limiter.acquire())
            .await
            .expect("request deadline must release admission capacity");
    }
}
