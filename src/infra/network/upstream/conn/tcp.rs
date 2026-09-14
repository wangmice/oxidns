// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};

use crate::infra::clock::AppClock;
use crate::infra::error::{DnsError, Result};
#[cfg(feature = "upstream-dot")]
use crate::infra::network::dial::TlsDialOptions;
#[cfg(feature = "upstream-dot")]
use crate::infra::network::dial::connect_tls;
use crate::infra::network::dial::{DialTarget, SocketOptions};
use crate::infra::network::proxy::{Socks5Opt, connect_tcp};
#[cfg(feature = "upstream-dot")]
use crate::infra::network::transport::tcp::TcpTransport;
use crate::infra::network::transport::tcp::{TcpTransportReader, TcpTransportWriter};
use crate::infra::network::upstream::conn::request_map::RequestMap;
use crate::infra::network::upstream::pool::{
    Connection, ConnectionBuilder, DeadlineOutcome, QueryDeadline,
};
use crate::infra::network::upstream::{ConnectionInfo, ConnectionType};
use crate::proto::Message;

/// Represents a single persistent TCP-based DNS connection.
/// Handles both plaintext TCP and TLS (DoT) connections, supporting
/// asynchronous DNS queries and concurrent request tracking.
#[derive(Debug)]
pub struct TcpConnection {
    /// Unique connection ID for logging/tracing.
    id: u16,
    /// Bounded sender for outbound TCP messages.
    sender: Sender<QueuedQuery>,
    /// Latched cancellation signal for background read/write tasks.
    close_token: CancellationToken,
    /// Map of active DNS queries (query_id → response channel sender).
    request_map: RequestMap,
    /// Whether the connection is marked as closed.
    closed: AtomicBool,
    /// Indicates if the connection is currently writable.
    writeable: AtomicBool,
    /// Timestamp (ms) of last successful activity.
    last_used: AtomicU64,
}

#[cfg(test)]
const DEFAULT_REQUEST_MAP_CAPACITY: u16 = 64;

const WRITE_STATE_QUEUED: u8 = 0;
const WRITE_STATE_WRITING: u8 = 1;
const WRITE_STATE_CANCELED: u8 = 2;

#[derive(Debug)]
struct QueuedQuery {
    message: Message,
    query_id: u16,
    write_state: Arc<AtomicU8>,
}

#[derive(Debug)]
struct QueuedWriteGuard {
    write_state: Arc<AtomicU8>,
}

impl QueuedWriteGuard {
    fn new() -> Self {
        Self {
            write_state: Arc::new(AtomicU8::new(WRITE_STATE_QUEUED)),
        }
    }

    fn state(&self) -> Arc<AtomicU8> {
        Arc::clone(&self.write_state)
    }
}

impl Drop for QueuedWriteGuard {
    fn drop(&mut self) {
        // Cancellation may suppress only work that has not started writing.
        // Once the sender owns WRITING, the full DNS-over-TCP frame must be
        // completed (or the connection closed) so a partial frame cannot
        // corrupt subsequent messages on the byte stream.
        let _ = self.write_state.compare_exchange(
            WRITE_STATE_QUEUED,
            WRITE_STATE_CANCELED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

#[async_trait]
impl Connection for TcpConnection {
    /// Gracefully close the TCP connection and notify background tasks
    ///
    /// This method is idempotent - multiple calls are safe and will only close
    /// once. Background read/write tasks will be notified and gracefully
    /// shut down.
    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return; // Already closed, no-op
        }
        // Cancel pending requests first so the reader task can terminate
        // without waiting for per-query timeouts, and all callers are
        // unblocked promptly.
        let cleared = self.request_map.clear();
        debug!(
            conn_id = self.id,
            canceled_queries = cleared,
            "Initiating TCP connection close sequence"
        );
        self.close_token.cancel();
    }

    /// Sends a DNS query and waits asynchronously for its corresponding
    /// response
    ///
    /// # Arguments
    /// * `request` - DNS query message to send
    ///
    /// # Returns
    /// - `Ok(DnsResponse)` if response received within timeout
    /// - `Err(DnsError)` if connection closed, timeout occurs, or network error
    ///
    /// # Performance
    /// Uses TCP length-prefixed framing (2-byte BE length header) as per RFC
    /// 1035
    async fn query(&self, request: Message, _deadline: QueryDeadline) -> Result<Message> {
        if self.closed.load(Ordering::Acquire) {
            return Err(DnsError::protocol(format!(
                "Cannot query on closed TCP connection (id={})",
                self.id
            )));
        }

        // Register query and get unique ID for request/response matching
        let (tx, rx) = oneshot::channel();
        let mut query_guard = self.request_map.store_for_request(tx, &request)?;
        let query_id = query_guard.query_id();
        if self.closed.load(Ordering::Acquire) {
            return Err(DnsError::protocol(format!(
                "Cannot query on closed TCP connection (id={})",
                self.id
            )));
        }

        trace!(
            conn_id = self.id,
            query_id,
            active_queries = self.using_count(),
            "Sending DNS query over TCP"
        );

        let raw_id = request.id();

        // Queue the message for the background sender task. The bounded
        // channel applies backpressure if the socket writer falls behind. A
        // per-query atomic state lets cancellation suppress queued work without
        // relying on the reusable 16-bit DNS ID as a generation token.
        let write_guard = QueuedWriteGuard::new();
        if let Err(e) = self
            .sender
            .send(QueuedQuery {
                message: request,
                query_id,
                write_state: write_guard.state(),
            })
            .await
        {
            let _ = query_guard.remove();
            self.close();
            error!(
                conn_id = self.id,
                query_id,
                error = ?e,
                "Failed to queue DNS query Message (sender channel closed)"
            );
            return Err(DnsError::protocol(e.to_string()));
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(DnsError::protocol(format!(
                "Cannot query on closed TCP connection (id={})",
                self.id
            )));
        }

        match rx.await {
            Ok(mut res) => {
                query_guard.disarm();
                res.set_id(raw_id); // Restore original query ID
                trace!(
                    conn_id = self.id,
                    query_id, "Successfully received DNS response over TCP"
                );
                Ok(res)
            }
            Err(_) => {
                warn!(
                    conn_id = self.id,
                    query_id, "DNS query canceled (response channel dropped)"
                );
                Err(DnsError::protocol("request canceled"))
            }
        }
    }

    fn using_count(&self) -> u32 {
        u32::from(self.request_map.size())
    }

    fn available(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && self.writeable.load(Ordering::Acquire)
    }

    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }
}

impl TcpConnection {
    /// Create a new `TcpConnection` instance wrapping a socket writer
    ///
    /// # Arguments
    /// * `conn_id` - Unique connection identifier for logging and debugging
    /// * `sender` - Bounded channel for queuing outbound DNS messages
    fn new(conn_id: u16, sender: Sender<QueuedQuery>, request_map_capacity: u16) -> Self {
        debug!(
            conn_id,
            "Initialized TCP connection wrapper with async I/O tasks"
        );
        Self {
            id: conn_id,
            sender,
            close_token: CancellationToken::new(),
            request_map: RequestMap::with_capacity(request_map_capacity),
            closed: AtomicBool::new(false),
            writeable: AtomicBool::new(true),
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
        }
    }

    /// Background task: sends queued DNS requests through the TCP writer
    ///
    /// Continuously drains the outbound message queue and writes to the TCP
    /// stream. Connection cancellation interrupts both queue waits and an
    /// in-flight socket write.
    ///
    /// # Error Handling
    /// Write errors trigger connection closure and notify waiting queries
    async fn send_dns_request<S: AsyncWrite + Unpin>(
        self: Arc<Self>,
        mut writer: TcpTransportWriter<S>,
        mut receiver: Receiver<QueuedQuery>,
    ) {
        debug!(
            conn_id = self.id,
            "TCP sender task started, ready to transmit queued messages"
        );

        loop {
            let queued = select! {
                biased;
                _ = self.close_token.cancelled() => {
                    debug!(
                        conn_id = self.id,
                        "TCP sender observed connection cancellation"
                    );
                    break;
                }
                queued = receiver.recv() => match queued {
                    Some(queued) => queued,
                    None => break,
                },
            };

            if queued
                .write_state
                .compare_exchange(
                    WRITE_STATE_QUEUED,
                    WRITE_STATE_WRITING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                trace!(
                    conn_id = self.id,
                    query_id = queued.query_id,
                    "Skipping canceled queued TCP query"
                );
                continue;
            }

            let write_result = select! {
                biased;
                _ = self.close_token.cancelled() => {
                    debug!(
                        conn_id = self.id,
                        "TCP sender canceled an in-flight write during close"
                    );
                    break;
                }
                result = writer.write_message_with_id(&queued.message, queued.query_id) => result,
            };

            if let Err(e) = write_result {
                error!(
                    conn_id = self.id,
                    error = ?e,
                    "TCP write failed, marking connection as non-writable"
                );
                self.writeable.store(false, Ordering::Release);
                self.close();
                break;
            }
        }

        debug!(conn_id = self.id, "TCP sender task exiting");
    }

    /// Background task: reads DNS responses from the upstream TCP connection
    ///
    /// Implements TCP length-prefixed message framing (RFC 1035):
    /// - Reads 2-byte big-endian length prefix
    /// - Reads message body of specified length
    /// - Matches response to pending query by ID
    /// - Delivers response via oneshot channel
    ///
    /// # Buffer Management
    /// Uses a rolling buffer to handle partial reads and multiple messages per
    /// read
    async fn listen_dns_response<S: AsyncRead + Unpin>(
        self: Arc<Self>,
        mut reader: TcpTransportReader<S>,
    ) {
        debug!(
            conn_id = self.id,
            "TCP listener task started, waiting for DNS responses"
        );

        loop {
            let result = select! {
                biased;
                _ = self.close_token.cancelled() => {
                    debug!(
                        conn_id = self.id,
                        pending_queries = self.request_map.size(),
                        "TCP listener observed connection cancellation"
                    );
                    break;
                }
                result = reader.read_message() => result,
            };

            match result {
                Ok(msg) => {
                    let id = msg.id();
                    if let Some(sender) = self.request_map.take_for_response(id, &msg) {
                        let _ = sender.send(msg);
                        self.last_used
                            .store(AppClock::elapsed_millis(), Ordering::Relaxed);
                        trace!(
                            conn_id = self.id,
                            query_id = id,
                            "Matched and delivered DNS response to waiting query"
                        );
                    } else {
                        trace!(
                            conn_id = self.id,
                            query_id = id,
                            "Discarded DNS response (no matching query or fingerprint mismatch)"
                        );
                    }
                }
                Err(e) => {
                    debug!(
                        conn_id = self.id,
                        error = ?e,
                        "TCP read error or EOF, closing connection"
                    );
                    self.close();
                    break;
                }
            }
        }

        debug!(conn_id = self.id, "TCP listener task terminated");
    }
}

/// Builder that establishes new TCP or TLS (DoT) DNS connections.
#[derive(Debug)]
pub struct TcpConnectionBuilder {
    target: DialTarget,
    socket_options: SocketOptions,
    tls_enabled: bool,
    #[cfg_attr(not(feature = "upstream-dot"), allow(dead_code))]
    insecure_skip_verify: bool,
    connection_type: ConnectionType,
    request_map_capacity: u16,
    socks5: Option<Socks5Opt>,
}

impl TcpConnectionBuilder {
    pub fn new(connection_info: &ConnectionInfo, request_map_capacity: u16) -> Self {
        #[cfg(feature = "upstream-dot")]
        let tls_enabled = matches!(connection_info.connection_type, ConnectionType::DoT);
        #[cfg(not(feature = "upstream-dot"))]
        let tls_enabled = false;
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
            tls_enabled,
            insecure_skip_verify: connection_info.insecure_skip_verify,
            connection_type: connection_info.connection_type,
            request_map_capacity,
            socks5: connection_info.socks5.clone(),
        }
    }
}

#[async_trait]
impl ConnectionBuilder<TcpConnection> for TcpConnectionBuilder {
    /// Establish a new TCP or TLS connection to the DNS server
    ///
    /// # Returns
    /// Arc-wrapped TcpConnection with background I/O tasks spawned
    ///
    /// # Performance
    /// - TCP_NODELAY enabled for low-latency queries
    /// - Async I/O with separate reader/writer tasks
    /// - TLS handshake performed asynchronously if enabled
    async fn create_connection(
        &self,
        conn_id: u16,
        deadline: QueryDeadline,
    ) -> Result<Arc<TcpConnection>> {
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

        debug!(
            conn_id,
            connection_type = ?self.connection_type,
            remote = ?stream.peer_addr(),
            tls_enabled = self.tls_enabled,
            "Established TCP connection to DNS server"
        );

        let (sender, receiver) = channel(usize::from(self.request_map_capacity));
        let connection = TcpConnection::new(conn_id, sender, self.request_map_capacity);
        let arc = Arc::new(connection);

        if self.tls_enabled {
            #[cfg(feature = "upstream-dot")]
            {
                let tls_stream = connect_tls(
                    stream,
                    TlsDialOptions::new(
                        self.target.clone(),
                        self.insecure_skip_verify,
                        deadline
                            .remaining()
                            .ok_or_else(|| deadline.timeout_error())?,
                        vec![b"dot".to_vec()],
                    ),
                )
                .await?;

                let transport = TcpTransport::new(tls_stream);
                let (reader, writer) = transport.into_split();
                tokio::spawn(TcpConnection::listen_dns_response(arc.clone(), reader));
                tokio::spawn(TcpConnection::send_dns_request(
                    arc.clone(),
                    writer,
                    receiver,
                ));
            }
            #[cfg(not(feature = "upstream-dot"))]
            return Err(DnsError::plugin(
                "upstream DoT is not compiled into this build; \
                 rebuild with --features upstream-dot",
            ));
        } else {
            // Plain TCP can be split into independent owned halves, avoiding
            // the shared lock that `tokio::io::split` (used for TLS) imposes on
            // every read/write. The reader and writer tasks then run fully
            // concurrently without contending on the connection.
            let (read_half, write_half) = stream.into_split();
            let reader = TcpTransportReader::new(read_half);
            let writer = TcpTransportWriter::new(write_half);
            tokio::spawn(TcpConnection::listen_dns_response(arc.clone(), reader));
            tokio::spawn(TcpConnection::send_dns_request(
                arc.clone(),
                writer,
                receiver,
            ));
        }

        Ok(arc)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    #[cfg(feature = "upstream-dot")]
    use crate::infra::network::upstream::ConnectionType;

    #[cfg(feature = "upstream-dot")]
    #[test]
    fn test_builder_new_marks_dot_connections_as_tls_enabled() {
        let mut connection_info = ConnectionInfo::with_addr("tls://dns.example.com:853")
            .expect("connection info should parse");
        connection_info.timeout = Duration::from_secs(9);
        connection_info.insecure_skip_verify = true;

        let builder = TcpConnectionBuilder::new(&connection_info, DEFAULT_REQUEST_MAP_CAPACITY);

        assert_eq!(connection_info.connection_type, ConnectionType::DoT);
        assert!(builder.tls_enabled);
        assert_eq!(builder.target.port(), 853);
        assert_eq!(builder.request_map_capacity, DEFAULT_REQUEST_MAP_CAPACITY);
        assert_eq!(builder.target.host(), "dns.example.com");
        assert!(builder.insecure_skip_verify);
    }

    #[tokio::test]
    async fn test_query_returns_error_when_connection_is_closed() {
        AppClock::start();
        let (sender, _receiver) = channel(usize::from(DEFAULT_REQUEST_MAP_CAPACITY));
        let connection = TcpConnection::new(7, sender, DEFAULT_REQUEST_MAP_CAPACITY);
        connection.close();

        let result = connection
            .query(
                Message::new(),
                QueryDeadline::new(Duration::from_millis(10)),
            )
            .await;

        assert!(result.is_err());
        assert_eq!(connection.using_count(), 0);
        assert!(!connection.available());
    }

    #[tokio::test]
    async fn test_close_before_listener_start_is_latched() {
        AppClock::start();
        let (sender, _receiver) = channel(usize::from(DEFAULT_REQUEST_MAP_CAPACITY));
        let connection = Arc::new(TcpConnection::new(9, sender, DEFAULT_REQUEST_MAP_CAPACITY));
        connection.close();

        let (client, _server) = tokio::io::duplex(64);
        let reader = TcpTransportReader::new(client);
        let task = tokio::spawn(TcpConnection::listen_dns_response(
            Arc::clone(&connection),
            reader,
        ));

        tokio::time::timeout(Duration::from_millis(100), task)
            .await
            .expect("latched close must stop a listener started after close")
            .expect("listener task should not panic");
    }

    #[tokio::test]
    async fn test_close_cancels_blocked_tcp_write() {
        use tokio::io::AsyncReadExt;

        AppClock::start();
        let (sender, receiver) = channel(usize::from(DEFAULT_REQUEST_MAP_CAPACITY));
        let queue = sender.clone();
        let connection = Arc::new(TcpConnection::new(10, sender, DEFAULT_REQUEST_MAP_CAPACITY));
        let (client, mut server) = tokio::io::duplex(1);
        let writer = TcpTransportWriter::new(client);
        let task = tokio::spawn(TcpConnection::send_dns_request(
            Arc::clone(&connection),
            writer,
            receiver,
        ));

        queue
            .send(QueuedQuery {
                message: Message::new(),
                query_id: 1,
                write_state: Arc::new(AtomicU8::new(WRITE_STATE_QUEUED)),
            })
            .await
            .expect("sender task should still own the receiver");

        // Observe one byte to prove write_all() has started. With a one-byte
        // duplex buffer and no further reads, the remaining frame is blocked.
        let mut first = [0u8; 1];
        tokio::time::timeout(Duration::from_millis(100), server.read_exact(&mut first))
            .await
            .expect("writer should start writing")
            .expect("first byte should be readable");

        connection.close();
        tokio::time::timeout(Duration::from_millis(100), task)
            .await
            .expect("close must cancel an in-flight blocked write")
            .expect("sender task should not panic");
    }

    #[tokio::test]
    async fn test_sender_skips_query_cancelled_before_write() {
        AppClock::start();
        let (sender, receiver) = channel(2);
        let queue = sender.clone();
        let connection = Arc::new(TcpConnection::new(11, sender, DEFAULT_REQUEST_MAP_CAPACITY));
        let (client, server) = tokio::io::duplex(1024);
        let writer = TcpTransportWriter::new(client);
        let task = tokio::spawn(TcpConnection::send_dns_request(
            Arc::clone(&connection),
            writer,
            receiver,
        ));

        queue
            .send(QueuedQuery {
                message: Message::new(),
                query_id: 1,
                write_state: Arc::new(AtomicU8::new(WRITE_STATE_CANCELED)),
            })
            .await
            .expect("sender task should still own the receiver");
        queue
            .send(QueuedQuery {
                message: Message::new(),
                query_id: 2,
                write_state: Arc::new(AtomicU8::new(WRITE_STATE_QUEUED)),
            })
            .await
            .expect("sender task should still own the receiver");

        let mut reader = TcpTransportReader::new(server);
        let message = tokio::time::timeout(Duration::from_millis(100), reader.read_message())
            .await
            .expect("live queued query should be written")
            .expect("live queued query should decode");
        assert_eq!(message.id(), 2);

        connection.close();
        tokio::time::timeout(Duration::from_millis(100), task)
            .await
            .expect("close must stop sender task")
            .expect("sender task should not panic");
    }

    #[tokio::test]
    async fn test_query_removes_request_when_cancelled() {
        AppClock::start();
        let (sender, _receiver) = channel(usize::from(DEFAULT_REQUEST_MAP_CAPACITY));
        let connection = TcpConnection::new(8, sender, DEFAULT_REQUEST_MAP_CAPACITY);

        let result = tokio::time::timeout(
            Duration::from_millis(10),
            connection.query(Message::new(), QueryDeadline::new(Duration::from_secs(1))),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(connection.using_count(), 0);
        assert!(connection.available());
    }
}
