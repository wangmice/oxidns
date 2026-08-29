// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::SocketAddr;

use fast_socks5::client::Socks5Datagram;
use fast_socks5::util::target_addr::TargetAddr;
use tokio::net::{TcpStream, UdpSocket};

use crate::infra::error::{DnsError, Result};
use crate::infra::network::buffer_pool::wire_buffer_pool;
use crate::infra::network::dial::{
    DialTarget, SocketOptions, TcpDialOptions, bind_udp, connect_tcp as dial_connect_tcp,
};
use crate::infra::network::proxy::Socks5Opt;
use crate::proto::Message;

/// UDP transport wrapper for DNS messages.
///
/// Designed to be consistent with other transport modules: provides
/// `write_message` and `read_message` methods operating on OxiDNS messages.
///
/// Supports both connected-client style I/O (`read_message`/`write_message`)
/// and unconnected-server style I/O (`read_message_from`/`write_message_to`).
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpTransportSocket,
}

#[derive(Debug)]
enum UdpTransportSocket {
    Direct(UdpSocket),
    Socks5 {
        datagram: Socks5Datagram<TcpStream>,
        target: TargetAddr,
    },
}

fn socks5_response_source_matches(expected: &TargetAddr, received: &TargetAddr) -> bool {
    match (expected, received) {
        (TargetAddr::Ip(expected), TargetAddr::Ip(received)) => expected == received,
        (
            TargetAddr::Domain(expected_domain, expected_port),
            TargetAddr::Domain(received_domain, received_port),
        ) => {
            expected_port == received_port
                && expected_domain
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(received_domain.trim_end_matches('.'))
        }
        (TargetAddr::Domain(_, expected_port), TargetAddr::Ip(received)) => {
            *expected_port == received.port()
        }
        _ => false,
    }
}

impl UdpTransport {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket: UdpTransportSocket::Direct(socket),
        }
    }

    pub(crate) async fn new_socks5(
        target: DialTarget,
        socket_options: SocketOptions,
        socks5: Socks5Opt,
    ) -> Result<Self> {
        let proxy_target = DialTarget::from_socket_addr(socks5.socket_addr);
        let proxy_stream = dial_connect_tcp(
            TcpDialOptions::new(proxy_target).with_socket_options(socket_options.clone()),
        )
        .await?;
        let bind_addr = match socks5.socket_addr {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
        };
        let udp_socket = UdpSocket::from_std(bind_udp(bind_addr, &socket_options)?)?;
        let datagram = match (socks5.username.as_deref(), socks5.password.as_deref()) {
            (Some(username), Some(password)) => {
                Socks5Datagram::use_socket_with_password(
                    proxy_stream,
                    udp_socket,
                    username,
                    password,
                )
                .await?
            }
            _ => Socks5Datagram::use_socket(proxy_stream, udp_socket).await?,
        };
        let target = if let Some(remote_ip) = target.remote_ip() {
            TargetAddr::Ip(SocketAddr::new(remote_ip, target.port()))
        } else {
            TargetAddr::Domain(target.host().to_string(), target.port())
        };
        Ok(Self {
            socket: UdpTransportSocket::Socks5 { datagram, target },
        })
    }

    pub(crate) fn recv_buffer_size(&self, direct_size: usize) -> usize {
        match self.socket {
            UdpTransportSocket::Direct(_) => direct_size,
            UdpTransportSocket::Socks5 { .. } => usize::from(u16::MAX),
        }
    }

    /// Receive one UDP datagram and decode it as a DNS message.
    /// Blocks until a datagram arrives or the socket errors.
    #[inline]
    #[hotpath::measure]
    pub async fn read_message(&self, buf: &mut [u8]) -> Result<Message> {
        let n = match &self.socket {
            UdpTransportSocket::Direct(socket) => socket
                .recv(buf)
                .await
                .map_err(|e| DnsError::protocol(format!("UDP recv error: {e}")))?,
            UdpTransportSocket::Socks5 { datagram, target } => {
                let (n, source) = datagram
                    .recv_from(buf)
                    .await
                    .map_err(|e| DnsError::protocol(format!("SOCKS5 UDP recv error: {e}")))?;
                if !socks5_response_source_matches(target, &source) {
                    return Err(DnsError::protocol(format!(
                        "SOCKS5 UDP response source mismatch: expected {target}, received {source}"
                    )));
                }
                n
            }
        };

        Message::from_bytes(&buf[..n])
            .map_err(|e| DnsError::protocol(format!("Failed to parse DNS message from UDP: {e}")))
    }

    /// Receive one UDP datagram from any peer and decode it as a DNS message.
    #[inline]
    #[hotpath::measure]
    pub async fn read_message_from(&self, buf: &mut [u8]) -> Result<(Message, SocketAddr)> {
        let UdpTransportSocket::Direct(socket) = &self.socket else {
            return Err(DnsError::protocol(
                "SOCKS5 UDP transport does not support unconnected receive",
            ));
        };
        let (n, addr) = socket
            .recv_from(buf)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to recv_from UDP: {e}")))?;

        let msg = Message::from_bytes(&buf[..n]).map_err(|e| {
            DnsError::protocol(format!("Failed to parse DNS message from UDP: {e}"))
        })?;
        Ok((msg, addr))
    }

    /// Serialize and send a DNS message while overriding the wire ID.
    #[inline]
    #[hotpath::measure]
    pub async fn write_message_with_id(&self, msg: &Message, id: u16) -> Result<()> {
        let mut bytes = wire_buffer_pool().acquire();
        msg.append_to_with_id(id, &mut bytes)?;

        let n = match &self.socket {
            UdpTransportSocket::Direct(socket) => socket
                .send(&bytes)
                .await
                .map_err(|e| DnsError::protocol(format!("UDP send error: {e}")))?,
            UdpTransportSocket::Socks5 { datagram, target } => datagram
                .send_to(&bytes, target.clone())
                .await
                .map_err(|e| DnsError::protocol(format!("SOCKS5 UDP send error: {e}")))?,
        };

        if n != bytes.len() {
            return Err(DnsError::protocol(format!(
                "Partial UDP send: sent {n} of {} bytes",
                bytes.len()
            )));
        }
        Ok(())
    }

    #[inline]
    #[hotpath::measure]
    pub async fn write_message_to(
        &self,
        msg: &Message,
        to: SocketAddr,
        max_payload: u16,
    ) -> Result<()> {
        let UdpTransportSocket::Direct(socket) = &self.socket else {
            return Err(DnsError::protocol(
                "SOCKS5 UDP transport does not support unconnected send",
            ));
        };
        let max_payload = usize::from(max_payload);
        let mut bytes = wire_buffer_pool().acquire();
        msg.append_to_with_limit(max_payload, &mut bytes)?;
        let n = socket
            .send_to(&bytes, to)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to send_to UDP: {e}")))?;
        if n != bytes.len() {
            return Err(DnsError::protocol(format!(
                "Partial UDP send_to: sent {n} of {} bytes",
                bytes.len()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;
    use crate::proto::{DNSClass, Name, Question, RecordType};

    #[test]
    fn socks5_response_source_rejects_wrong_upstream() {
        let expected = TargetAddr::Ip("8.8.8.8:53".parse().unwrap());
        let correct = TargetAddr::Ip("8.8.8.8:53".parse().unwrap());
        let wrong_ip = TargetAddr::Ip("1.1.1.1:53".parse().unwrap());
        let wrong_port = TargetAddr::Ip("8.8.8.8:5353".parse().unwrap());

        assert!(socks5_response_source_matches(&expected, &correct));
        assert!(!socks5_response_source_matches(&expected, &wrong_ip));
        assert!(!socks5_response_source_matches(&expected, &wrong_port));

        let expected_domain = TargetAddr::Domain("dns.example".to_string(), 53);
        assert!(socks5_response_source_matches(
            &expected_domain,
            &TargetAddr::Ip("192.0.2.1:53".parse().unwrap())
        ));
        assert!(!socks5_response_source_matches(
            &expected_domain,
            &TargetAddr::Ip("192.0.2.1:5353".parse().unwrap())
        ));
    }

    #[tokio::test]
    async fn new_socks5_requests_udp_associate() {
        let relay = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("UDP relay should bind");
        let relay_addr = relay
            .local_addr()
            .expect("UDP relay should have an address");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("SOCKS5 listener should bind");
        let proxy_addr = listener
            .local_addr()
            .expect("SOCKS5 listener should have an address");
        let (close_proxy, close_proxy_rx) = oneshot::channel();

        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("proxy should accept");
            let mut greeting = [0u8; 3];
            stream
                .read_exact(&mut greeting)
                .await
                .expect("proxy should read greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream
                .write_all(&[0x05, 0x00])
                .await
                .expect("proxy should select no-auth");

            let mut request = [0u8; 4];
            stream
                .read_exact(&mut request)
                .await
                .expect("proxy should read UDP associate request");
            assert_eq!(request, [0x05, 0x03, 0x00, 0x04]);
            let mut client_addr = [0u8; 18];
            stream
                .read_exact(&mut client_addr)
                .await
                .expect("proxy should read UDP associate client address");
            assert_eq!(client_addr, [0; 18]);

            let mut response = vec![0x05, 0x00, 0x00, 0x01];
            response.extend_from_slice(&match relay_addr.ip() {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(_) => unreachable!("relay is IPv4"),
            });
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream
                .write_all(&response)
                .await
                .expect("proxy should accept UDP association");
            let _ = close_proxy_rx.await;
        });

        let transport = UdpTransport::new_socks5(
            DialTarget::new(
                Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                "dns.google".to_string(),
                53,
            ),
            SocketOptions::default(),
            Socks5Opt {
                username: None,
                password: None,
                socket_addr: proxy_addr,
            },
        )
        .await
        .expect("SOCKS5 UDP association should be established");
        assert_eq!(transport.recv_buffer_size(8_196), 65_535);

        let relay_task = tokio::spawn(async move {
            let mut packet = [0u8; 1024];
            let (len, client) = relay
                .recv_from(&mut packet)
                .await
                .expect("relay should receive SOCKS5 UDP packet");
            assert_eq!(&packet[..4], &[0x00, 0x00, 0x00, 0x01]);
            assert_eq!(&packet[4..8], &[8, 8, 8, 8]);
            assert_eq!(&packet[8..10], &53u16.to_be_bytes());
            relay
                .send_to(&packet[..len], client)
                .await
                .expect("relay should echo SOCKS5 UDP packet");
        });

        let mut request = Message::new();
        request.add_question(Question::new(
            Name::from_ascii("example.com").expect("name should be valid"),
            RecordType::A,
            DNSClass::IN,
        ));
        transport
            .write_message_with_id(&request, 0xBEEF)
            .await
            .expect("SOCKS5 UDP transport should send DNS query");
        let mut buf = [0u8; 1024];
        let response = transport
            .read_message(&mut buf)
            .await
            .expect("SOCKS5 UDP transport should receive DNS response");
        assert_eq!(response.id(), 0xBEEF);
        relay_task.await.expect("relay task should complete");
        let _ = close_proxy.send(());
        proxy.await.expect("proxy task should complete");
    }
}
