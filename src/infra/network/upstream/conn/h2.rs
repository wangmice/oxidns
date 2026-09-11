// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::{BufMut, Bytes};
use h2::client::{ResponseFuture, SendRequest};
use http::Version;
use tokio::select;
use tokio::sync::Notify;
use tracing::{debug, trace, warn};

use super::UsingCountGuard;
use crate::infra::clock::AppClock;
use crate::infra::error::{DnsError, Result};
use crate::infra::network::buffer_pool::wire_buffer_pool;
use crate::infra::network::dial::{DialTarget, SocketOptions, TlsDialOptions, connect_tls};
use crate::infra::network::proxy::{Socks5Opt, connect_tcp};
use crate::infra::network::upstream::conn::doh::{
    MAX_DOH_DNS_BODY_SIZE, MAX_DOH_ERROR_BODY_SIZE, build_dns_get_request, build_doh_request_uri,
    get_cap_buf_with_context_len,
};
use crate::infra::network::upstream::pool::{ConnectionBuilder, DeadlineOutcome, QueryDeadline};
use crate::infra::network::upstream::{Connection, ConnectionInfo};
use crate::proto::Message;

enum H2RecvError {
    Transport(DnsError),
    HttpStatus(DnsError),
    InvalidResponse(DnsError),
}

#[derive(Debug)]
pub struct H2Connection {
    id: u16,
    sender: SendRequest<Bytes>,
    using_count: AtomicU32,
    closed: AtomicBool,
    last_used: AtomicU64,
    request_uri: String,
    close_notify: Notify,
}

#[async_trait]
impl Connection for H2Connection {
    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        debug!(conn_id = self.id, "Closing DoH connection");
        // A single background driver waits for this signal. `notify_one()`
        // stores a permit when the waiter has not registered yet,
        // avoiding a lost close wakeup.
        self.close_notify.notify_one();
    }

    async fn query(&self, request: Message, _deadline: QueryDeadline) -> Result<Message> {
        if self.closed.load(Ordering::Acquire) {
            return Err(DnsError::protocol("DoH connection closed"));
        }
        self.using_count.fetch_add(1, Ordering::Relaxed);
        // Guard ensures using_count is decremented even if this future is
        // cancelled by an outer timeout (cancel-safety).
        let _guard = UsingCountGuard(&self.using_count);
        if self.closed.load(Ordering::Acquire) {
            return Err(DnsError::protocol("DoH connection closed"));
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

impl H2Connection {
    async fn query_inner(&self, request: Message) -> Result<Message> {
        let raw_id = request.id();
        let mut body_bytes = wire_buffer_pool().acquire();
        request.append_to_with_id(0, &mut body_bytes)?;

        let request = build_dns_get_request(
            self.request_uri.as_str(),
            body_bytes.as_slice(),
            Version::HTTP_2,
        )?;
        drop(body_bytes);

        let mut sender = self.sender.clone().ready().await.map_err(|e| {
            self.close();
            DnsError::protocol(format!("H2 sender readiness error: {e}"))
        })?;

        // DoH GET carries the DNS payload in the URI, so the request body is
        // empty. Mark the stream as finished when sending headers,
        // otherwise some servers will wait for an end-of-stream signal
        // and never produce a response.
        let (response_future, _send_stream) = sender.send_request(request, true).map_err(|e| {
            self.close();
            DnsError::protocol(format!("H2 send_request error: {e}"))
        })?;

        match recv(response_future).await {
            Ok(bytes) => {
                let mut resp = Message::from_bytes(&bytes)?;
                resp.set_id(raw_id);
                self.last_used
                    .store(AppClock::elapsed_millis(), Ordering::Relaxed);
                trace!(conn_id = self.id, raw_id, "Received H2 response");
                Ok(resp)
            }
            Err(H2RecvError::Transport(e)) => {
                self.close();
                warn!(conn_id = self.id, raw_id, ?e, "H2 request error");
                Err(e)
            }
            Err(H2RecvError::HttpStatus(e) | H2RecvError::InvalidResponse(e)) => Err(e),
        }
    }
}

/// Builder
#[derive(Debug)]
pub struct H2ConnectionBuilder {
    target: DialTarget,
    socket_options: SocketOptions,
    request_uri: String,
    insecure_skip_verify: bool,
    socks5: Option<Socks5Opt>,
}

impl H2ConnectionBuilder {
    pub fn new(connection_info: &ConnectionInfo) -> Self {
        Self {
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
            insecure_skip_verify: connection_info.insecure_skip_verify,
            socks5: connection_info.socks5.clone(),
        }
    }
}

#[async_trait]
impl ConnectionBuilder<H2Connection> for H2ConnectionBuilder {
    async fn create_connection(
        &self,
        conn_id: u16,
        deadline: QueryDeadline,
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
            DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
        };

        let tls_stream = connect_tls(
            stream,
            TlsDialOptions::new(
                self.target.clone(),
                self.insecure_skip_verify,
                deadline
                    .remaining()
                    .ok_or_else(|| deadline.timeout_error())?,
                vec![b"h2".to_vec()],
            ),
        )
        .await?;

        let (sender, connection) = match deadline
            .run(h2::client::Builder::new().handshake(tls_stream))
            .await
        {
            DeadlineOutcome::Completed(Ok(value)) => value,
            DeadlineOutcome::Completed(Err(e)) => {
                return Err(DnsError::protocol(format!("H2 handshake error: {}", e)));
            }
            DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
        };

        let h2_conn = Arc::new(H2Connection {
            id: conn_id,
            sender,
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
            using_count: AtomicU32::new(0),
            request_uri: self.request_uri.clone(),
            close_notify: Notify::new(),
        });

        let _conn = h2_conn.clone();
        tokio::spawn(async move {
            select! {
                res = connection => {
                    _conn.close();
                    match res {
                        Ok(()) => debug!(conn_id, "H2 connection closed"),
                        Err(e) => debug!(conn_id, ?e, "H2 connection error"),
                    }
                }
                _ = _conn.close_notify.notified() => {
                    debug!(conn_id, "H2 connection closed by notify");
                }
            }
        });

        Ok(h2_conn)
    }
}

async fn recv(response_future: ResponseFuture) -> std::result::Result<Bytes, H2RecvError> {
    let response = response_future.await.map_err(|e| {
        H2RecvError::Transport(DnsError::protocol(format!("H2 response error: {}", e)))
    })?;

    let status_code = response.status();
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
        let partial_bytes = partial_bytes.map_err(|e| {
            H2RecvError::Transport(DnsError::protocol(format!("H2 body error: {}", e)))
        })?;
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
            flow_control.release_capacity(chunk_len).map_err(|e| {
                H2RecvError::Transport(DnsError::protocol(format!(
                    "H2 flow-control release error: {e}"
                )))
            })?;
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
        let (response_future, _send_stream) = sender
            .send_request(request, true)
            .expect("request should send");

        let response_bytes =
            tokio::time::timeout(std::time::Duration::from_secs(2), recv(response_future))
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

    #[test]
    fn test_builder_new_uses_https_request_uri_and_flags() {
        let mut connection_info = ConnectionInfo::with_addr("https://dns.example.com/dns-query")
            .expect("connection info should parse");
        connection_info.insecure_skip_verify = true;
        connection_info.so_mark = Some(42);
        connection_info.bind_to_device = Some("utun9".to_string());

        let builder = H2ConnectionBuilder::new(&connection_info);

        assert_eq!(builder.target.port(), 443);
        assert_eq!(builder.target.host(), "dns.example.com");
        assert_eq!(
            builder.request_uri,
            "https://dns.example.com/dns-query?dns="
        );
        assert!(builder.insecure_skip_verify);
        assert_eq!(builder.socket_options.so_mark(), Some(42));
        assert_eq!(builder.socket_options.bind_to_device(), Some("utun9"));
    }
}
