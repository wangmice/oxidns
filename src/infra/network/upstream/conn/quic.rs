// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use async_trait::async_trait;
use tokio::select;
use tokio::sync::Notify;
use tracing::{debug, trace, warn};

use super::{UsingCountGuard, quic_idle_timeout};
use crate::infra::clock::AppClock;
use crate::infra::error::{DnsError, Result};
use crate::infra::network::deadline::DeadlineOutcome;
use crate::infra::network::dial::{
    DialTarget, QuicDialOptions, SocketOptions, UdpDialOptions, connect_quic,
    connect_quic_abstract, connect_udp,
};
use crate::infra::network::metrics::UpstreamTimeoutStage;
use crate::infra::network::proxy::Socks5Opt;
use crate::infra::network::response_validation::{DnsResponseIdPolicy, validate_dns_response};
use crate::infra::network::transport::quic::{
    QuicReadError, QuicTransport, QuicTransportReader, QuicTransportWriter, QuicWriteError,
};
use crate::infra::network::transport::socks5_quic::Socks5QuicSocket;
use crate::infra::network::upstream::pool::{ConnectionBuilder, QueryDeadline};
use crate::infra::network::upstream::{Connection, ConnectionInfo};
use crate::proto::Message;

const DOQ_NO_ERROR: u32 = 0x0;
const DOQ_PROTOCOL_ERROR: u32 = 0x2;
const DOQ_REQUEST_CANCELLED: u32 = 0x3;

struct DoqQueryStream {
    reader: QuicTransportReader,
    writer: QuicTransportWriter,
    send_finished: bool,
    completed: bool,
}

impl DoqQueryStream {
    fn new(reader: QuicTransportReader, writer: QuicTransportWriter) -> Self {
        Self {
            reader,
            writer,
            send_finished: false,
            completed: false,
        }
    }
}

impl Drop for DoqQueryStream {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if !self.send_finished {
            self.writer.reset(DOQ_REQUEST_CANCELLED);
        }
        self.reader.stop(DOQ_REQUEST_CANCELLED);
    }
}

pub struct QuicConnection {
    id: u16,
    upstream: String,
    transport: QuicTransport,
    using_count: AtomicU32,
    closed: AtomicBool,
    last_used: AtomicU64,
    close_notify: Notify,
}

impl Debug for QuicConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("QuicConnection")
    }
}

impl QuicConnection {
    fn close_with_code(&self, code: u32, reason: &[u8]) -> bool {
        if self.closed.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.transport.close_with_code(code, reason);
        self.close_notify.notify_waiters();
        true
    }
}

#[async_trait]
impl Connection for QuicConnection {
    /// Gracefully close the QUIC connection
    ///
    /// Sends QUIC CONNECTION_CLOSE frame to peer and notifies background tasks.
    /// This is idempotent - multiple calls are safe.
    fn close(&self) {
        if self.close_with_code(DOQ_NO_ERROR, b"closing") {
            debug!(
                conn_id = self.id,
            upstream = %self.upstream,
                "Closing QUIC connection, sending CONNECTION_CLOSE frame"
            );
        }
    }

    /// Send a DNS query over QUIC (DoQ - DNS over QUIC, RFC 9250)
    ///
    /// # Arguments
    /// * `request` - DNS query message to send
    ///
    /// # Returns
    /// - `Ok(DnsResponse)` if response received within timeout
    /// - `Err(DnsError)` if connection closed, stream open fails, or timeout
    ///   occurs
    ///
    /// # Protocol
    /// Each DNS query uses a new bidirectional QUIC stream:
    /// - 2-byte big-endian length prefix
    /// - DNS message body
    /// - Stream is closed after message sent/received
    ///
    /// This follows RFC 9250 (DNS over Dedicated QUIC Connections)
    async fn query(&self, request: Message, _deadline: QueryDeadline) -> Result<Message> {
        if self.closed.load(Ordering::Acquire) {
            return Err(DnsError::protocol("Cannot query on closed QUIC connection"));
        }
        self.using_count.fetch_add(1, Ordering::Relaxed);
        // Guard ensures using_count is decremented even if this future is
        // cancelled by an outer timeout (cancel-safety).
        let _guard = UsingCountGuard(&self.using_count);
        if self.closed.load(Ordering::Acquire) {
            return Err(DnsError::protocol("Cannot query on closed QUIC connection"));
        }

        // Open a new bidirectional stream (reader/writer) via connection
        // wrapper
        let (reader, writer) = match self.transport.open_bi().await {
            Ok((reader, writer)) => (reader, writer),
            Err(e) => {
                self.close();
                return Err(DnsError::protocol(format!(
                    "Failed to open QUIC bidirectional stream: {}",
                    e
                )));
            }
        };
        let mut stream = DoqQueryStream::new(reader, writer);

        let raw_id = request.id();
        if let Err(e) = stream.writer.write_message_doq(&request).await {
            match e {
                QuicWriteError::Stopped(code) => {
                    self.close_with_code(DOQ_PROTOCOL_ERROR, b"peer sent STOP_SENDING");
                    warn!(
                                conn_id = self.id,
                    upstream = %self.upstream,
                                query_id = raw_id,
                                %code,
                                "DoQ peer sent forbidden STOP_SENDING"
                            );
                    return Err(DnsError::protocol(format!(
                        "DoQ peer sent STOP_SENDING with code {code}"
                    )));
                }
                QuicWriteError::ConnectionLost(error) => {
                    self.close();
                    return Err(DnsError::protocol(format!(
                        "QUIC connection lost while writing DoQ query: {error}"
                    )));
                }
                QuicWriteError::Stream(message) => {
                    return Err(DnsError::protocol(format!(
                        "Failed to write DNS query to QUIC stream: {message}"
                    )));
                }
                QuicWriteError::Encode(message) => {
                    return Err(DnsError::protocol(format!(
                        "Failed to encode DNS query for QUIC stream: {message}"
                    )));
                }
            }
        }
        if let Err(e) = stream.writer.finish() {
            debug!(
                conn_id = self.id,
            upstream = %self.upstream,
                error = ?e,
                "Failed to finish DoQ send stream"
            );
            return Err(DnsError::protocol(format!(
                "Failed to finish QUIC send stream: {}",
                e
            )));
        }
        stream.send_finished = true;

        match stream.reader.read_message_doq().await {
            Ok(mut resp) => {
                stream.completed = true;
                validate_dns_response(&request, &resp, DnsResponseIdPolicy::Exact(0))?;
                resp.set_id(raw_id);
                self.last_used
                    .store(AppClock::elapsed_millis(), Ordering::Relaxed);
                trace!(
                        conn_id = self.id,
                upstream = %self.upstream,
                        query_id = raw_id,
                        "Successfully received DNS response over QUIC"
                    );
                Ok(resp)
            }
            Err(QuicReadError::StreamReset(code)) => {
                warn!(
                        conn_id = self.id,
                upstream = %self.upstream,
                        query_id = raw_id,
                        %code,
                        "DoQ transaction reset by server"
                    );
                Err(DnsError::protocol(format!(
                    "DoQ transaction reset by server with code {code}"
                )))
            }
            Err(QuicReadError::Protocol(message)) => {
                self.close_with_code(DOQ_PROTOCOL_ERROR, b"DoQ protocol error");
                warn!(
                        conn_id = self.id,
                upstream = %self.upstream,
                        query_id = raw_id,
                        error = %message,
                        "Fatal DoQ protocol error"
                    );
                Err(DnsError::protocol(message))
            }
            Err(QuicReadError::ConnectionLost(e)) => {
                self.close();
                warn!(
                        conn_id = self.id,
                upstream = %self.upstream,
                        query_id = raw_id,
                        error = ?e,
                        "QUIC connection lost while reading DoQ response"
                    );
                Err(DnsError::protocol(format!("QUIC connection lost: {e}")))
            }
            Err(QuicReadError::Stream(message)) => {
                debug!(
                        conn_id = self.id,
                upstream = %self.upstream,
                        query_id = raw_id,
                        error = %message,
                        "DoQ stream read error"
                    );
                Err(DnsError::protocol(message))
            }
        }
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

/// Builder
#[derive(Debug)]
pub struct QuicConnectionBuilder {
    target: DialTarget,
    upstream: String,
    socket_options: SocketOptions,
    socks5: Option<Socks5Opt>,
    insecure_skip_verify: bool,
    timeout: std::time::Duration,
    keepalive_interval: Option<std::time::Duration>,
}

impl QuicConnectionBuilder {
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
            insecure_skip_verify: connection_info.insecure_skip_verify,
            timeout: connection_info.timeout,
            keepalive_interval: connection_info.keepalive_interval,
        }
    }
}

#[async_trait]
impl ConnectionBuilder<QuicConnection> for QuicConnectionBuilder {
    /// Establish a new QUIC connection for DNS over QUIC (DoQ)
    ///
    /// # Returns
    /// Arc-wrapped QuicConnection with background monitoring task spawned
    ///
    /// # Protocol
    /// - Uses QUIC with TLS 1.3 (per RFC 9250)
    /// - Each DNS query uses a new bidirectional stream
    /// - Connection can be reused for multiple queries
    ///
    /// # Performance
    /// - 0-RTT support for resumed connections
    /// - Multiplexed streams avoid head-of-line blocking
    /// - Native congestion control and loss recovery
    async fn create_connection(
        &self,
        conn_id: u16,
        deadline: QueryDeadline,
    ) -> Result<Arc<QuicConnection>> {
        let dial_options = QuicDialOptions::new(
            self.target.clone(),
            self.insecure_skip_verify,
            deadline.remaining().ok_or_else(|| {
                deadline.timeout_error_for(UpstreamTimeoutStage::ConnectionCreate)
            })?,
            quic_idle_timeout(self.timeout),
            vec![b"doq".to_vec()],
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

        debug!(
            conn_id,
            upstream = %self.upstream,
            server_name = %self.target.host(),
            remote_addr = ?quic_conn.remote_address(),
            "Established QUIC connection for DoQ (DNS over QUIC)"
        );

        let quic_conn = Arc::new(QuicConnection {
            id: conn_id,
            upstream: self.upstream.clone(),
            transport: QuicTransport::new(quic_conn),
            closed: AtomicBool::new(false),
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
            using_count: AtomicU32::new(0),
            close_notify: Notify::new(),
        });

        // Spawn background task to monitor connection health
        let _conn = quic_conn.clone();
        tokio::spawn(async move {
            select! {
                _ = _conn.transport.closed() => {
                    // Mark the QuicConnection as unavailable so the pool removes
                    // it on the next query or maintenance cycle instead of
                    // continuing to try open_bi() on a dead transport.
                    _conn.close();
                    debug!(
                        conn_id,
                        upstream = %_conn.upstream,
                        "QUIC connection closed by remote peer or network error"
                    );
                }
                _ = _conn.close_notify.notified() => {
                    debug!(
                        conn_id,
                        upstream = %_conn.upstream,
                        "QUIC connection closed by local request"
                    );
                }
            }
            // Ensure the underlying QUIC connection is properly closed
            let _ = _conn.transport.close(b"driver task ending");
        });

        Ok(quic_conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::network::upstream::ConnectionType;

    #[test]
    fn test_builder_new_copies_quic_connection_fields() {
        let mut connection_info = ConnectionInfo::with_addr("quic://dns.example.com")
            .expect("connection info should parse");
        connection_info.timeout = std::time::Duration::from_secs(3);
        connection_info.insecure_skip_verify = true;
        connection_info.so_mark = Some(9);
        connection_info.bind_to_device = Some("wg0".to_string());
        connection_info.keepalive_interval = Some(std::time::Duration::from_secs(4));

        let builder = QuicConnectionBuilder::new(&connection_info);

        assert_eq!(connection_info.connection_type, ConnectionType::DoQ);
        assert_eq!(builder.target.port(), 853);
        assert_eq!(builder.target.host(), "dns.example.com");
        assert!(builder.insecure_skip_verify);
        assert_eq!(builder.timeout, std::time::Duration::from_secs(3));
        assert_eq!(
            builder.keepalive_interval,
            Some(std::time::Duration::from_secs(4))
        );
        assert_eq!(builder.socket_options.so_mark(), Some(9));
        assert_eq!(builder.socket_options.bind_to_device(), Some("wg0"));
    }
}
