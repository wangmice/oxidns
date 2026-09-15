// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use http::header::CONTENT_LENGTH;
use rustls::ServerConfig;
use tokio::sync::{oneshot, watch};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::plugin::server::http::extract_client_ip;
use crate::plugin::server::http::http_dispatcher::HttpDispatcher;
use crate::plugin::server::{
    ConnectionGuard, DEFAULT_QUIC_MAX_BIDI_STREAMS, DEFAULT_SERVER_MAX_INFLIGHT_REQUESTS,
    InboundRequestLimiter, quic_endpoint,
};

const MAX_HTTP3_BODY_SIZE: usize = 64 * 1024;
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
    async fn run<F>(&self, future: F) -> Result<F::Output, H3RequestTimedOut>
    where
        F: Future,
    {
        timeout_at(self.at, future)
            .await
            .map_err(|_| H3RequestTimedOut)
    }
}

#[derive(Debug)]
enum H3BodyReadError {
    Http(http::StatusCode),
    Deadline,
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

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
        match h3::server::Connection::new(h3_quinn::Connection::new(connection)).await {
            Ok(conn) => conn,
            Err(e) => {
                debug!("HTTP/3 handshake error from {}: {}", src, e);
                return;
            }
        };

    loop {
        let accepted = tokio::select! {
            _ = request_cancel.cancelled() => return,
            accepted = h3_conn.accept() => accepted,
        };

        let (request, stream) = match accepted {
            Ok(Some(request)) => {
                let resolved = tokio::select! {
                    _ = request_cancel.cancelled() => return,
                    resolved = request.resolve_request() => resolved,
                };
                match resolved {
                    Ok(resolved) => resolved,
                    Err(e) => {
                        warn!("Failed to resolve HTTP/3 request from {}: {}", src, e);
                        continue;
                    }
                }
            }
            Ok(None) => {
                debug!("HTTP/3 connection closed by {}", src);
                return;
            }
            Err(e) => {
                warn!("HTTP/3 connection accept error from {}: {}", src, e);
                // `h3::server::Connection::accept` reports connection-level
                // errors. The h3 crate caches handled connection errors, so
                // retrying accept can complete immediately with the same error.
                return;
            }
        };

        // Acquire capacity before spawning the request task. While saturated,
        // stop accepting additional H3 streams and let QUIC/H3 flow control
        // provide bounded backpressure rather than accumulating waiter tasks.
        let permit = tokio::select! {
            _ = request_cancel.cancelled() => return,
            _ = connection_liveness.closed() => return,
            permit = request_limiter.acquire() => permit,
        };

        let dispatcher = dispatcher.clone();
        let src_ip_header = src_ip_header.clone();
        let server_name = server_name.clone();
        let task_cancel = request_cancel.clone();
        // Start one absolute lifetime deadline after admission. Each phase
        // applies its own cap within the remaining lifetime budget, preventing
        // slow body chunks or flow-controlled response writes from extending
        // the time this request can retain a global admission permit.
        let request_deadline = H3RequestDeadline::new();

        request_tasks.spawn(async move {
            let _permit = permit;
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
                ) => {}
            }
        });
    }
}

/// Handle a single HTTP/3 request stream
async fn handle_h3_request(
    request: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    dispatcher: Arc<HttpDispatcher>,
    src: SocketAddr,
    src_ip_header: Option<Arc<str>>,
    server_name: Option<Arc<str>>,
    request_deadline: H3RequestDeadline,
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

    let body_deadline = request_deadline.phase(HTTP3_REQUEST_BODY_TIMEOUT);
    let body = match read_h3_body(&mut stream, src, body_deadline).await {
        Ok(body) => body,
        Err(H3BodyReadError::Http(status)) => {
            let response_deadline = request_deadline.phase(HTTP3_RESPONSE_SEND_TIMEOUT);
            let _ = send_h3_error_response(&mut stream, status, src, response_deadline).await;
            return;
        }
        Err(H3BodyReadError::Deadline) => {
            cancel_h3_stream_on_deadline(&mut stream, src, "request body");
            return;
        }
    };

    let executor_deadline = request_deadline.phase(HTTP3_REQUEST_EXECUTION_TIMEOUT);
    let response = match executor_deadline
        .run(dispatcher.handle_request(method, path, query, body, client_addr, server_name))
        .await
    {
        Ok(response) => response,
        Err(_) => {
            cancel_h3_stream_on_deadline(&mut stream, src, "executor");
            return;
        }
    };

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

    match response_deadline
        .run(stream.send_response(h3_response))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!("Failed to send HTTP/3 response headers to {}: {}", src, e);
            return;
        }
        Err(_) => {
            cancel_h3_stream_on_deadline(&mut stream, src, "response headers");
            return;
        }
    }

    match response_deadline
        .run(stream.send_data(response_bytes))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!("Failed to send HTTP/3 response body to {}: {}", src, e);
            return;
        }
        Err(_) => {
            cancel_h3_stream_on_deadline(&mut stream, src, "response body");
            return;
        }
    }

    match response_deadline.run(stream.finish()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!("Failed to finish HTTP/3 response stream to {}: {}", src, e);
            return;
        }
        Err(_) => {
            cancel_h3_stream_on_deadline(&mut stream, src, "response finish");
            return;
        }
    }

    debug!("Response sent to {}", src);
}

#[inline]
async fn read_h3_body(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    src: SocketAddr,
    body_deadline: H3PhaseDeadline,
) -> Result<Bytes, H3BodyReadError> {
    let mut buf = BytesMut::with_capacity(2048);

    loop {
        match body_deadline.run(stream.recv_data()).await {
            Ok(Ok(Some(chunk))) => {
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
            Ok(Ok(None)) => return Ok(buf.freeze()),
            Ok(Err(e)) => {
                warn!("Failed to read HTTP/3 request body from {}: {}", src, e);
                return Err(H3BodyReadError::Http(http::StatusCode::BAD_REQUEST));
            }
            Err(_) => return Err(H3BodyReadError::Deadline),
        }
    }
}

#[inline]
async fn send_h3_error_response(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
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

    match response_deadline.run(stream.send_response(response)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(
                "Failed to send HTTP/3 error response headers to {}: {}",
                src, e
            );
            return Err(());
        }
        Err(_) => {
            cancel_h3_stream_on_deadline(stream, src, "error response headers");
            return Err(());
        }
    }

    match response_deadline.run(stream.finish()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(
                "Failed to finish HTTP/3 error response stream to {}: {}",
                src, e
            );
            return Err(());
        }
        Err(_) => {
            cancel_h3_stream_on_deadline(stream, src, "error response finish");
            return Err(());
        }
    }

    Ok(())
}

#[inline]
fn cancel_h3_stream_on_deadline(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    src: SocketAddr,
    phase: &'static str,
) {
    warn!(client = %src, phase, "HTTP/3 request deadline exceeded; cancelling stream");
    stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
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
