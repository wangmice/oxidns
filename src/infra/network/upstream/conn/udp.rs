// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;
use tracing::{debug, error, trace, warn};

use crate::infra::clock::AppClock;
use crate::infra::error::{DnsError, Result};
use crate::infra::network::dial::{DialTarget, SocketOptions, UdpDialOptions, connect_udp};
use crate::infra::network::proxy::Socks5Opt;
use crate::infra::network::transport::udp::UdpTransport;
use crate::infra::network::upstream::ConnectionInfo;
use crate::infra::network::upstream::conn::request_map::RequestMap;
use crate::infra::network::upstream::pool::{Connection, ConnectionBuilder, QueryDeadline};
use crate::proto::Message;

const UDP_RECV_BUFFER_SIZE: usize = 8_196;
const UDP_RECV_ERROR_BACKOFF_BASE_MS: u64 = 10;
const UDP_RECV_ERROR_BACKOFF_MAX_MS: u64 = 250;

/// Represents a single UDP connection used in DNS upstream queries.
/// Each connection manages its own socket and maintains a mapping
/// of request IDs to response channels for asynchronous query handling.
#[derive(Debug)]
pub struct UdpConnection {
    /// Unique connection ID (for debugging/tracing)
    id: u16,
    /// Stable upstream identity used to disambiguate per-pool connection IDs.
    upstream: String,
    /// The underlying UDP transport bound to a local address
    transport: UdpTransport,
    /// Notifier used to signal connection closure
    close_notify: Notify,
    /// Mapping between DNS query IDs and response channels
    request_map: RequestMap,
    /// Timestamp of last activity (milliseconds)
    last_used: AtomicU64,
    /// Connection closed flag (prevents use after closure and ensures
    /// idempotent close)
    closed: AtomicBool,
}

#[cfg(test)]
const DEFAULT_REQUEST_MAP_CAPACITY: u16 = 64;

/// Retry delay for initial DNS query attempts
const RETRY_TIMEOUT: Duration = Duration::from_secs(1);

#[async_trait]
impl Connection for UdpConnection {
    /// Close this UDP connection and notify all waiting tasks
    ///
    /// UDP connections are stateless, so close mainly signals the listener task
    /// to exit. This method is idempotent - multiple calls are safe and
    /// will only execute once.
    fn close(&self) {
        // Atomically set closed flag and check previous value
        if self.closed.swap(true, Ordering::SeqCst) {
            return; // Already closed, no-op
        }
        // Cancel every pending query before waking the listener so the
        // background task can observe an empty request map and drop the
        // socket immediately instead of waiting for per-query timeouts
        // to age out.
        let cleared = self.request_map.clear();
        debug!(
            conn_id = self.id,
            upstream = %self.upstream,
            canceled_queries = cleared,
            "Closing UDP connection and signaling listener task"
        );
        self.close_notify.notify_one();
    }

    /// Send a DNS query and wait asynchronously for its response
    ///
    /// # Arguments
    /// * `request` - DNS query message to send
    ///
    /// # Returns
    /// - `Ok(DnsResponse)` if response received
    /// - `Err(DnsError)` if both attempts timeout or network error occurs
    ///
    /// # Retry Strategy
    /// - First attempt: 1 second timeout (quick retry on packet loss)
    /// - Second attempt: configured timeout (allows for slower network)
    ///
    /// This two-stage approach improves resilience against UDP packet loss
    /// while maintaining low latency for successful queries.
    async fn query(&self, request: Message, deadline: QueryDeadline) -> Result<Message> {
        if self.closed.load(Ordering::Acquire) {
            return Err(DnsError::protocol("UDP connection is closed"));
        }

        let raw_id = request.id();

        for attempt in 0..2 {
            let Some(remaining) = deadline.remaining() else {
                return Err(deadline.timeout_error());
            };
            let current_timeout = if attempt == 0 {
                remaining.min(RETRY_TIMEOUT)
            } else {
                remaining
            };

            let (tx, rx) = oneshot::channel();
            let mut query_guard = self.request_map.store_for_request(tx, &request)?;
            let query_id = query_guard.query_id();
            if self.closed.load(Ordering::Acquire) {
                return Err(DnsError::protocol("UDP connection is closed"));
            }

            trace!(
                conn_id = self.id,
            upstream = %self.upstream,
                attempt,
                query_id,
                timeout_ms = current_timeout.as_millis(),
                "Sending DNS query over UDP"
            );

            // Send UDP datagram via transport
            match self
                .transport
                .write_message_with_id(&request, query_id)
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    error!(conn_id = self.id,
            upstream = %self.upstream, err = %e, "Failed to send UDP query");
                    self.close();
                    return Err(e);
                }
            }

            // Wait for response with timeout
            match timeout(current_timeout, rx).await {
                Ok(res) => match res {
                    Ok(mut response) => {
                        query_guard.disarm();
                        response.set_id(raw_id);
                        trace!(conn_id = self.id,
            upstream = %self.upstream, query_id, raw_id, "Received UDP response");
                        return Ok(response);
                    }
                    Err(_canceled) => {
                        trace!(
                            conn_id = self.id,
            upstream = %self.upstream,
                            query_id, "Listener dropped channel, retrying"
                        );
                        continue;
                    }
                },
                Err(_elapsed) => {
                    trace!(
                        conn_id = self.id,
            upstream = %self.upstream,
                        query_id,
                        timeout_ms = current_timeout.as_millis(),
                        "UDP response timeout"
                    );
                    continue;
                }
            }
        }

        Err(DnsError::protocol("UDP query timed out after retries"))
    }

    /// Return the number of active queries currently tracked by this
    /// connection.
    fn using_count(&self) -> u32 {
        u32::from(self.request_map.size())
    }

    /// Check if the UDP connection is available for new queries
    ///
    /// Returns false if the connection has been closed (e.g., due to send
    /// failure)
    fn available(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }

    /// Return the timestamp (in ms) of last successful activity.
    fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }
}

impl UdpConnection {
    /// Construct a new UDP connection with the given parameters
    ///
    /// # Arguments
    /// * `conn_id` - Unique connection identifier for logging
    /// * `transport` - Pre-configured direct or SOCKS5 UDP transport
    fn new(
        conn_id: u16,
        upstream: String,
        transport: UdpTransport,
        request_map_capacity: u16,
    ) -> UdpConnection {
        Self {
            id: conn_id,
            upstream,
            transport,
            close_notify: Notify::new(),
            request_map: RequestMap::with_capacity(request_map_capacity),
            last_used: AtomicU64::new(AppClock::elapsed_millis()),
            closed: AtomicBool::new(false), // Initially open
        }
    }

    /// Asynchronously listen for DNS responses and deliver them to matching
    /// queries
    ///
    /// Continuously receives UDP datagrams and matches them to pending queries
    /// by ID. This task runs per connection until all requests complete or
    /// the connection closes.
    ///
    /// # Buffer Size
    /// Direct UDP keeps the bounded DNS-sized buffer. SOCKS5 uses a full UDP
    /// datagram buffer so the SOCKS5 header and the maximum DNS payload can be
    /// received and decoded in place without a separate temporary allocation.
    async fn listen_dns_response(self: Arc<Self>) {
        let mut buf = vec![0u8; self.transport.recv_buffer_size(UDP_RECV_BUFFER_SIZE)];
        let mut closing = false;
        let mut consecutive_recv_errors = 0u32;

        debug!(
            conn_id = self.id,
            upstream = %self.upstream,
            "UDP listener task started, waiting for DNS responses"
        );

        loop {
            if (closing || self.closed.load(Ordering::Acquire)) && self.request_map.is_empty() {
                debug!(conn_id = self.id,
            upstream = %self.upstream, "Listener exiting (connection dropped)");
                break;
            }

            select! {
                biased;
                _ = self.transport.control_closed(), if !closing => {
                    warn!(
                        conn_id = self.id,
            upstream = %self.upstream,
                        "SOCKS5 UDP control connection closed; retiring UDP connection"
                    );
                    self.close();
                    closing = true;
                    continue;
                }
                recv = self.transport.read_message(&mut buf) => {
                    match recv {
                        Ok(msg) => {
                            consecutive_recv_errors = 0;
                            let id = msg.id();
                            if let Some(sender) = self.request_map.take_for_response(id, &msg) {
                                let _ = sender.send(msg);
                                self.last_used.store(AppClock::elapsed_millis(), Ordering::Relaxed);
                                trace!(
                                    conn_id = self.id,
            upstream = %self.upstream,
                                    id,
                                    "Delivered UDP response to waiting query"
                                );
                            } else {
                                trace!(
                                    conn_id = self.id,
            upstream = %self.upstream,
                                    id,
                                    "No pending query or response fingerprint mismatch"
                                );
                            }
                        }
                        Err(e) => {
                            if self.closed.load(Ordering::Acquire) {
                                closing = true; // graceful shutdown path
                                continue;
                            }
                            consecutive_recv_errors = consecutive_recv_errors.saturating_add(1);
                            let backoff = udp_recv_error_backoff(consecutive_recv_errors);
                            if consecutive_recv_errors == 1 || consecutive_recv_errors.is_power_of_two() {
                                warn!(
                                    conn_id = self.id,
            upstream = %self.upstream,
                                    err = %e,
                                    consecutive_errors = consecutive_recv_errors,
                                    backoff_ms = backoff.as_millis(),
                                    "UDP listener receive error; backing off"
                                );
                            } else {
                                debug!(
                                    conn_id = self.id,
            upstream = %self.upstream,
                                    err = %e,
                                    consecutive_errors = consecutive_recv_errors,
                                    backoff_ms = backoff.as_millis(),
                                    "UDP listener receive error; backing off"
                                );
                            }

                            select! {
                                biased;
                                _ = self.close_notify.notified() => {
                                    closing = true;
                                }
                                _ = tokio::time::sleep(backoff) => {}
                            }
                            continue;
                        }
                    }
                }
                _ = self.close_notify.notified() => {
                    closing = true;
                }
            }
        }
    }
}

fn udp_recv_error_backoff(consecutive_errors: u32) -> Duration {
    let shift = consecutive_errors.saturating_sub(1).min(5);
    let delay_ms = (UDP_RECV_ERROR_BACKOFF_BASE_MS << shift).min(UDP_RECV_ERROR_BACKOFF_MAX_MS);
    Duration::from_millis(delay_ms)
}

/// Builder for creating new `UdpConnection` instances.
#[derive(Debug)]
pub struct UdpConnectionBuilder {
    target: DialTarget,
    upstream: String,
    socket_options: SocketOptions,
    socks5: Option<Socks5Opt>,
    request_map_capacity: u16,
}

impl UdpConnectionBuilder {
    /// Initialize a new builder using upstream connection info.
    pub fn new(connection_info: &ConnectionInfo, request_map_capacity: u16) -> Self {
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
            request_map_capacity,
        }
    }
}

#[async_trait]
impl ConnectionBuilder<UdpConnection> for UdpConnectionBuilder {
    /// Create a new UDP connection, bind it locally, connect to remote server,
    /// and spawn a background listener task to handle responses
    ///
    /// # Returns
    /// Arc-wrapped UdpConnection with background listener task spawned
    ///
    /// # Performance
    /// - Non-blocking socket I/O
    /// - Single listener task handles all responses for this connection
    /// - Zero-copy where possible (direct socket buffer to DNS parser)
    async fn create_connection(
        &self,
        conn_id: u16,
        _deadline: QueryDeadline,
    ) -> Result<Arc<UdpConnection>> {
        let transport = if let Some(socks5) = self.socks5.clone() {
            UdpTransport::new_socks5(self.target.clone(), self.socket_options.clone(), socks5)
                .await?
        } else {
            let socket = connect_udp(UdpDialOptions::new(
                self.target.clone(),
                self.socket_options.clone(),
            ))
            .await?;
            debug!(
                conn_id,
                upstream = %self.upstream,
                local_addr = ?socket.local_addr(),
                remote_addr = ?socket.peer_addr(),
                "Established UDP connection to DNS server"
            );
            UdpTransport::new(UdpSocket::from_std(socket)?)
        };

        let connection = UdpConnection::new(
            conn_id,
            self.upstream.clone(),
            transport,
            self.request_map_capacity,
        );
        let arc = Arc::new(connection);

        // Spawn background task for listening responses
        tokio::spawn(UdpConnection::listen_dns_response(arc.clone()));

        Ok(arc)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    #[test]
    fn udp_receive_error_backoff_is_bounded_and_exponential() {
        assert_eq!(udp_recv_error_backoff(1), Duration::from_millis(10));
        assert_eq!(udp_recv_error_backoff(2), Duration::from_millis(20));
        assert_eq!(udp_recv_error_backoff(5), Duration::from_millis(160));
        assert_eq!(udp_recv_error_backoff(6), Duration::from_millis(250));
        assert_eq!(udp_recv_error_backoff(64), Duration::from_millis(250));
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;
    use crate::infra::network::upstream::ConnectionType;
    use crate::proto::{DNSClass, Name, Question, RecordType};

    #[test]
    fn test_builder_new_copies_connection_info_fields() {
        let mut connection_info =
            ConnectionInfo::with_addr("udp://1.1.1.1:5300").expect("connection info should parse");
        connection_info.timeout = Duration::from_secs(7);
        connection_info.so_mark = Some(100);
        connection_info.bind_to_device = Some("en0".to_string());

        let builder = UdpConnectionBuilder::new(&connection_info, DEFAULT_REQUEST_MAP_CAPACITY);

        assert_eq!(connection_info.connection_type, ConnectionType::UDP);
        assert_eq!(builder.target.remote_ip(), connection_info.remote_ip);
        assert_eq!(builder.target.port(), 5300);
        assert_eq!(builder.request_map_capacity, DEFAULT_REQUEST_MAP_CAPACITY);
        assert_eq!(builder.target.host(), "1.1.1.1");
        assert_eq!(builder.socket_options.so_mark(), Some(100));
        assert_eq!(builder.socket_options.bind_to_device(), Some("en0"));
    }

    #[tokio::test]
    async fn socks5_udp_query_runs_through_connection_builder() {
        AppClock::start();
        let relay = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("UDP relay should bind");
        let relay_addr = relay.local_addr().expect("relay should have an address");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("SOCKS5 listener should bind");
        let proxy_addr = listener.local_addr().expect("proxy should have an address");
        let (close_proxy, close_proxy_rx) = oneshot::channel();

        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("proxy should accept");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            let mut associate = [0u8; 10];
            stream.read_exact(&mut associate).await.unwrap();
            assert_eq!(associate, [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

            let mut response = vec![0x05, 0x00, 0x00, 0x01];
            response.extend_from_slice(&match relay_addr.ip() {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(_) => unreachable!("relay is IPv4"),
            });
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&response).await.unwrap();
            let _ = close_proxy_rx.await;
        });

        let relay_task = tokio::spawn(async move {
            let mut packet = [0u8; 1024];
            let (len, client) = relay.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..10], &[0, 0, 0, 1, 8, 8, 8, 8, 0, 53]);
            // Convert the echoed DNS query into a response. Fingerprint
            // matching deliberately rejects packets with QR=0 even when the
            // DNS ID and question section match.
            packet[12] |= 0x80;
            relay.send_to(&packet[..len], client).await.unwrap();
        });

        let mut info = ConnectionInfo::with_addr("udp://8.8.8.8:53").unwrap();
        info.socks5 = Some(Socks5Opt {
            username: None,
            password: None,
            socket_addr: proxy_addr,
        });
        let builder = UdpConnectionBuilder::new(&info, DEFAULT_REQUEST_MAP_CAPACITY);
        let connection = builder
            .create_connection(1, QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("SOCKS5 UDP connection should be created");

        let mut request = Message::new();
        request.set_id(0xCAFE);
        request.add_question(Question::new(
            Name::from_ascii("example.com").unwrap(),
            RecordType::A,
            DNSClass::IN,
        ));
        let response = connection
            .query(request, QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("SOCKS5 UDP query should complete");

        assert_eq!(response.id(), 0xCAFE);
        connection.close();
        relay_task.await.unwrap();
        let _ = close_proxy.send(());
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_control_close_marks_udp_connection_unavailable() {
        AppClock::start();
        let relay = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("UDP relay should bind");
        let relay_addr = relay.local_addr().expect("relay should have an address");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("SOCKS5 listener should bind");
        let proxy_addr = listener.local_addr().expect("proxy should have an address");

        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("proxy should accept");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            let mut associate = [0u8; 10];
            stream.read_exact(&mut associate).await.unwrap();
            assert_eq!(associate, [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

            let mut response = vec![0x05, 0x00, 0x00, 0x01];
            response.extend_from_slice(&match relay_addr.ip() {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(_) => unreachable!("relay is IPv4"),
            });
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&response).await.unwrap();
            // Dropping the TCP stream invalidates the UDP association per RFC
            // 1928.
        });

        let mut info = ConnectionInfo::with_addr("udp://8.8.8.8:53").unwrap();
        info.socks5 = Some(Socks5Opt {
            username: None,
            password: None,
            socket_addr: proxy_addr,
        });
        let builder = UdpConnectionBuilder::new(&info, DEFAULT_REQUEST_MAP_CAPACITY);
        let connection = builder
            .create_connection(2, QueryDeadline::new(Duration::from_secs(1)))
            .await
            .expect("SOCKS5 UDP connection should be created");

        proxy.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while connection.available() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("control-channel close should retire the UDP connection promptly");

        assert!(!connection.available());
    }
}
