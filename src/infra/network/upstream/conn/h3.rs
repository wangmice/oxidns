// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes};
use futures::future::poll_fn;
use h3::client::{RequestStream, SendRequest};
use h3_quinn::{BidiStream, OpenStreams};
use http::{Request, Version};
use tokio::select;
use tokio::sync::Notify;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use super::{UsingCountGuard, quic_idle_timeout};
use crate::infra::clock::AppClock;
use crate::infra::error::{DnsError, Result};
use crate::infra::network::buffer_pool::wire_buffer_pool;
use crate::infra::network::dial::{
    DialTarget, QuicDialOptions, SocketOptions, UdpDialOptions, connect_quic,
    connect_quic_abstract, connect_udp,
};
use crate::infra::network::metrics::UpstreamTimeoutStage;
use crate::infra::network::proxy::Socks5Opt;
use crate::infra::network::response_validation::{DnsResponseIdPolicy, validate_dns_response};
use crate::infra::network::transport::socks5_quic::Socks5QuicSocket;
use crate::infra::network::upstream::conn::doh::{
    MAX_DOH_DNS_BODY_SIZE, MAX_DOH_ERROR_BODY_SIZE, build_dns_get_request, build_doh_request_uri,
    get_cap_buf_with_context_len, validate_doh_content_type,
};
use crate::infra::network::upstream::pool::{ConnectionBuilder, DeadlineOutcome, QueryDeadline};
use crate::infra::network::upstream::{Connection, ConnectionInfo};
use crate::proto::Message;

const H3_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

async fn run_bounded_h3_shutdown<F, C>(timeout_duration: Duration, graceful: F, force_close: C)
where
    F: Future<Output = ()>,
    C: FnOnce(),
{
    if timeout(timeout_duration, graceful).await.is_err() {
        force_close();
    }
}

enum H3RecvError {
    Connection(DnsError),
    Stream(DnsError),
    HttpStatus(DnsError),
    InvalidResponse(DnsError),
}

fn classify_h3_stream_error(context: &str, error: h3::error::StreamError) -> H3RecvError {
    let connection_scoped = matches!(
        error,
        h3::error::StreamError::ConnectionError(_) | h3::error::StreamError::RemoteClosing
    );
    let error = DnsError::protocol(format!("{context}: {error}"));
    if connection_scoped {
        H3RecvError::Connection(error)
    } else {
        H3RecvError::Stream(error)
    }
}

pub struct H3Connection {
    id: u16,
    upstream: String,
    sender: SendRequest<OpenStreams, Bytes>,
    using_count: AtomicU32,
    closed: AtomicBool,
    last_used: AtomicU64,
    request_uri: String,
    close_notify: Notify,
}
impl Debug for H3Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("H3Connection")
    }
}

#[async_trait]
impl Connection for H3Connection {
    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        debug!(conn_id = self.id,
            upstream = %self.upstream, "Closing H3 connection");
        self.close_notify.notify_one();
    }

    async fn query(&self, request: Message, _deadline: QueryDeadline) -> Result<Message> {
        if self.closed.load(Ordering::Acquire) {
            return Err(DnsError::protocol("H3 connection closed"));
        }
        self.using_count.fetch_add(1, Ordering::Relaxed);
        // Guard ensures using_count is decremented even if this future is
        // cancelled by an outer timeout (cancel-safety).
        let _guard = UsingCountGuard(&self.using_count);
        if self.closed.load(Ordering::Acquire) {
            return Err(DnsError::protocol("H3 connection closed"));
        }
        self.query_inner(request).await
    }

    fn using_count(&self) -> u32 {
        self.using_count.load(Ordering::Relaxed)
    }

    fn available(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }

    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }
}

impl H3Connection {
    async fn query_inner(&self, request: Message) -> Result<Message> {
        let mut body_bytes = wire_buffer_pool().acquire();
        request.append_to_with_id(0, &mut body_bytes)?;

        let http_request = build_dns_get_request(
            self.request_uri.as_str(),
            body_bytes.as_slice(),
            Version::HTTP_3,
        )?;
        drop(body_bytes);

        self.do_request(http_request, &request).await
    }

    async fn do_request(&self, http_request: Request<()>, request: &Message) -> Result<Message> {
        let raw_id = request.id();
        let mut request_stream = match self.sender.clone().send_request(http_request).await {
            Ok(stream) => stream,
            Err(error) => match classify_h3_stream_error("H3 send_request error", error) {
                H3RecvError::Connection(error) => {
                    self.close();
                    return Err(error);
                }
                H3RecvError::Stream(error) => return Err(error),
                H3RecvError::HttpStatus(_) | H3RecvError::InvalidResponse(_) => unreachable!(),
            },
        };

        if let Err(error) = request_stream.finish().await {
            match classify_h3_stream_error("H3 finish stream error", error) {
                H3RecvError::Connection(error) => {
                    self.close();
                    return Err(error);
                }
                H3RecvError::Stream(error) => return Err(error),
                H3RecvError::HttpStatus(_) | H3RecvError::InvalidResponse(_) => unreachable!(),
            }
        }

        match recv(request_stream).await {
            Ok(bytes) => {
                let mut resp = Message::from_bytes(&bytes)?;
                validate_dns_response(request, &resp, DnsResponseIdPolicy::Exact(0))?;
                resp.set_id(raw_id);
                self.last_used
                    .store(AppClock::elapsed_millis(), Ordering::Relaxed);
                trace!(conn_id = self.id,
            upstream = %self.upstream, raw_id, "Received H3 response");
                Ok(resp)
            }
            Err(H3RecvError::Connection(e)) => {
                self.close();
                Err(e)
            }
            Err(
                H3RecvError::Stream(e)
                | H3RecvError::HttpStatus(e)
                | H3RecvError::InvalidResponse(e),
            ) => Err(e),
        }
    }
}

/// Builder
#[derive(Debug)]
pub struct H3ConnectionBuilder {
    target: DialTarget,
    upstream: String,
    socket_options: SocketOptions,
    socks5: Option<Socks5Opt>,
    request_uri: String,
    insecure_skip_verify: bool,
    timeout: std::time::Duration,
    keepalive_interval: Option<std::time::Duration>,
}

impl H3ConnectionBuilder {
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
            socks5: connection_info.socks5.clone(),
            request_uri: build_doh_request_uri(connection_info),
            insecure_skip_verify: connection_info.insecure_skip_verify,
            timeout: connection_info.timeout,
            keepalive_interval: connection_info.keepalive_interval,
        }
    }
}

#[async_trait]
impl ConnectionBuilder<H3Connection> for H3ConnectionBuilder {
    async fn create_connection(
        &self,
        conn_id: u16,
        deadline: QueryDeadline,
    ) -> Result<Arc<H3Connection>> {
        let dial_options = QuicDialOptions::new(
            self.target.clone(),
            self.insecure_skip_verify,
            deadline.remaining().ok_or_else(|| {
                deadline.timeout_error_for(UpstreamTimeoutStage::ConnectionCreate)
            })?,
            quic_idle_timeout(self.timeout),
            vec![b"h3".to_vec()],
        )
        .with_query_deadline(deadline, UpstreamTimeoutStage::ProtocolHandshake)
        .with_keep_alive_interval(self.keepalive_interval);
        let quic_conn = if let Some(socks5) = self.socks5.clone() {
            let (socket, peer_addr) = match deadline
                .run(Socks5QuicSocket::connect(
                    self.target.clone(),
                    self.socket_options.clone(),
                    socks5,
                ))
                .await
            {
                DeadlineOutcome::Completed(result) => result?,
                DeadlineOutcome::Expired => {
                    return Err(deadline.timeout_error_for(UpstreamTimeoutStage::ConnectionCreate));
                }
            };
            connect_quic_abstract(socket, peer_addr, dial_options).await?
        } else {
            let socket = match deadline
                .run(connect_udp(UdpDialOptions::new(
                    self.target.clone(),
                    self.socket_options.clone(),
                )))
                .await
            {
                DeadlineOutcome::Completed(result) => result?,
                DeadlineOutcome::Expired => {
                    return Err(deadline.timeout_error_for(UpstreamTimeoutStage::ConnectionCreate));
                }
            };
            connect_quic(socket, dial_options).await?
        };

        let force_close_conn = quic_conn.clone();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let (mut driver, send_request) = match deadline.run(h3::client::new(h3_conn)).await {
            DeadlineOutcome::Completed(Ok(value)) => value,
            DeadlineOutcome::Completed(Err(e)) => {
                return Err(DnsError::protocol(format!("h3 connection failed: {e}")));
            }
            DeadlineOutcome::Expired => {
                return Err(deadline.timeout_error_for(UpstreamTimeoutStage::ProtocolHandshake));
            }
        };

        let h3_conn = Arc::new(H3Connection {
            id: conn_id,
            upstream: self.upstream.clone(),
            sender: send_request,
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
            using_count: AtomicU32::new(0),
            request_uri: self.request_uri.clone(),
            close_notify: Notify::new(),
        });

        let _conn = h3_conn.clone();

        let _driver_handle = tokio::spawn(async move {
            select! {
                _ = poll_fn(|cx| driver.poll_close(cx)) => {
                    _conn.closed.store(true, Ordering::Release);
                    debug!(conn_id, upstream = %_conn.upstream, "H3 connection poll closed");
                }
                _ = _conn.close_notify.notified() => {
                    debug!(conn_id, upstream = %_conn.upstream, "H3 connection shutdown requested");
                    let graceful_upstream = _conn.upstream.clone();
                    let force_close_upstream = _conn.upstream.clone();
                    run_bounded_h3_shutdown(
                        H3_GRACEFUL_SHUTDOWN_TIMEOUT,
                        async {
                            if let Err(e) = driver.shutdown(0).await {
                                warn!(conn_id, upstream = %graceful_upstream, error = ?e, "H3 graceful shutdown failed");
                            }
                            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
                        },
                        move || {
                            warn!(
                                conn_id,
                                upstream = %force_close_upstream,
                                timeout_secs = H3_GRACEFUL_SHUTDOWN_TIMEOUT.as_secs(),
                                "H3 graceful shutdown deadline exceeded; force closing QUIC transport"
                            );
                            force_close_conn.close(
                                quinn::VarInt::from_u64(h3::error::Code::H3_NO_ERROR.value())
                                    .expect("H3_NO_ERROR must fit in a QUIC varint"),
                                b"h3 graceful shutdown deadline",
                            );
                        },
                    )
                    .await;
                }
            }
        });

        Ok(h3_conn)
    }
}

async fn recv(
    mut request_stream: RequestStream<BidiStream<Bytes>, Bytes>,
) -> std::result::Result<Bytes, H3RecvError> {
    let response = request_stream
        .recv_response()
        .await
        .map_err(|e| classify_h3_stream_error("H3 response error", e))?;

    let status_code = response.status();
    if status_code.is_success() {
        validate_doh_content_type(response.headers()).map_err(H3RecvError::InvalidResponse)?;
    }
    let body_limit = if status_code.is_success() {
        MAX_DOH_DNS_BODY_SIZE
    } else {
        MAX_DOH_ERROR_BODY_SIZE
    };
    let mut response_bytes = get_cap_buf_with_context_len(&response, body_limit);
    let mut truncated = false;

    while let Some(partial_bytes) = request_stream
        .recv_data()
        .await
        .map_err(|e| classify_h3_stream_error("H3 recv_data error", e))?
    {
        let remaining = body_limit.saturating_sub(response_bytes.len());
        if partial_bytes.remaining() > remaining {
            if status_code.is_success() {
                return Err(H3RecvError::InvalidResponse(DnsError::protocol(
                    "DoH response body exceeds the 65535-byte DNS message limit",
                )));
            }
            response_bytes.put(partial_bytes.take(remaining));
            truncated = true;
            break;
        }
        response_bytes.put(partial_bytes);
    }

    if !status_code.is_success() {
        let error_string = String::from_utf8_lossy(response_bytes.as_ref());
        let suffix = if truncated { " (truncated)" } else { "" };

        Err(H3RecvError::HttpStatus(DnsError::protocol(format!(
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

    #[test]
    fn classify_remote_closing_as_connection_scoped() {
        let error = classify_h3_stream_error(
            "H3 send_request error",
            h3::error::StreamError::RemoteClosing,
        );
        assert!(matches!(error, H3RecvError::Connection(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_h3_shutdown_forces_transport_close_after_deadline() {
        let forced = Arc::new(AtomicBool::new(false));
        let forced_for_close = forced.clone();

        run_bounded_h3_shutdown(
            Duration::from_secs(1),
            std::future::pending::<()>(),
            move || {
                forced_for_close.store(true, Ordering::Release);
            },
        )
        .await;

        assert!(
            forced.load(Ordering::Acquire),
            "stalled graceful shutdown must force-close the QUIC transport"
        );
    }

    #[test]
    fn test_builder_new_uses_http3_request_uri_and_flags() {
        let mut connection_info = ConnectionInfo::with_addr("h3://dns.example.com/dns-query")
            .expect("connection info should parse");
        connection_info.timeout = std::time::Duration::from_secs(4);
        connection_info.insecure_skip_verify = true;
        connection_info.so_mark = Some(7);
        connection_info.bind_to_device = Some("utun1".to_string());
        connection_info.keepalive_interval = Some(std::time::Duration::from_secs(5));

        let builder = H3ConnectionBuilder::new(&connection_info);

        assert_eq!(builder.target.port(), 443);
        assert_eq!(builder.target.host(), "dns.example.com");
        assert_eq!(
            builder.request_uri,
            "https://dns.example.com/dns-query?dns="
        );
        assert!(builder.insecure_skip_verify);
        assert_eq!(builder.timeout, std::time::Duration::from_secs(4));
        assert_eq!(
            builder.keepalive_interval,
            Some(std::time::Duration::from_secs(5))
        );
        assert_eq!(builder.socket_options.so_mark(), Some(7));
        assert_eq!(builder.socket_options.bind_to_device(), Some("utun1"));
    }

    #[test]
    fn test_builder_new_preserves_fixed_doh_query_parameters() {
        let connection_info =
            ConnectionInfo::with_addr("h3://dns.example.com/dns-query?token=abc&profile=fast")
                .expect("connection info should parse");

        let builder = H3ConnectionBuilder::new(&connection_info);

        assert_eq!(
            builder.request_uri,
            "https://dns.example.com/dns-query?token=abc&profile=fast&dns="
        );
    }
}
