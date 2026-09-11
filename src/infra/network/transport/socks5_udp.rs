// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared SOCKS5 UDP association helpers.
//!
//! `fast-socks5::Socks5Datagram` requires the UDP socket to be bound before the
//! proxy returns the UDP relay address. That couples the local socket family to
//! information we do not have yet and breaks when an IPv4 SOCKS5 control
//! connection returns an IPv6 UDP relay (or vice versa). This module performs
//! the UDP ASSOCIATE handshake first, then creates the UDP socket in the
//! relay's actual address family.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use fast_socks5::client::{Config, Socks5Stream};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{AuthenticationMethod, Socks5Command};
use tokio::net::{TcpStream, UdpSocket};

use crate::infra::error::{DnsError, Result};
use crate::infra::network::dial::{
    DialTarget, SocketOptions, TcpDialOptions, bind_udp, connect_tcp as dial_connect_tcp,
};
use crate::infra::network::proxy::Socks5Opt;

pub(crate) const SOCKS5_UDP_HEADER_MAX_SIZE: usize = 3 + 1 + 1 + 255 + 2;
const SMALL_SEND_BUFFER_SIZE: usize = 2_048;

/// A live SOCKS5 UDP association.
///
/// The TCP control stream is retained for the lifetime of the association, as
/// required by RFC 1928. The UDP socket is connected to the proxy's relay.
#[derive(Debug)]
pub(crate) struct Socks5UdpAssociation {
    socket: UdpSocket,
    #[allow(dead_code)]
    control: Socks5Stream<TcpStream>,
}

impl Socks5UdpAssociation {
    pub(crate) async fn connect(socket_options: SocketOptions, socks5: Socks5Opt) -> Result<Self> {
        let proxy_target = DialTarget::from_socket_addr(socks5.socket_addr);
        let proxy_stream = dial_connect_tcp(
            TcpDialOptions::new(proxy_target).with_socket_options(socket_options.clone()),
        )
        .await?;
        let proxy_peer = proxy_stream.peer_addr()?;

        let auth = match (socks5.username.as_ref(), socks5.password.as_ref()) {
            (Some(username), Some(password)) => Some(AuthenticationMethod::Password {
                username: username.clone(),
                password: password.clone(),
            }),
            _ => None,
        };

        let mut control = Socks5Stream::use_stream(proxy_stream, auth, Config::default()).await?;

        // Preserve the request shape used by fast-socks5: when the client does
        // not yet know its externally visible UDP endpoint, advertise an
        // all-zero address and port. The proxy's reply decides the
        // relay family.
        let client_src = TargetAddr::Ip("[::]:0".parse().expect("valid unspecified IPv6 address"));
        let relay = control
            .request(Socks5Command::UDPAssociate, client_src)
            .await?;
        let relay_addr = resolve_relay_addr(&relay, proxy_peer)?;

        let bind_addr = unspecified_for(relay_addr);
        let udp_socket = UdpSocket::from_std(bind_udp(bind_addr, &socket_options)?)?;
        udp_socket.connect(relay_addr).await?;

        Ok(Self {
            socket: udp_socket,
            control,
        })
    }

    #[inline]
    pub(crate) fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    pub(crate) async fn send_to(&self, data: &[u8], target: &TargetAddr) -> io::Result<usize> {
        let mut header = [0u8; SOCKS5_UDP_HEADER_MAX_SIZE];
        let header_len = write_socks5_udp_header(&mut header, target)?;
        let total_len = header_len.checked_add(data.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "SOCKS5 UDP packet too large")
        })?;

        let sent = if total_len <= SMALL_SEND_BUFFER_SIZE {
            let mut buf = [0u8; SMALL_SEND_BUFFER_SIZE];
            buf[..header_len].copy_from_slice(&header[..header_len]);
            buf[header_len..total_len].copy_from_slice(data);
            self.socket.send(&buf[..total_len]).await?
        } else {
            let mut buf = Vec::with_capacity(total_len);
            buf.extend_from_slice(&header[..header_len]);
            buf.extend_from_slice(data);
            self.socket.send(&buf).await?
        };

        if sent < header_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial SOCKS5 UDP header send",
            ));
        }
        Ok(sent - header_len)
    }

    pub(crate) async fn recv_from(&self, data_store: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        let size = self.socket.recv(data_store).await?;
        let packet = data_store.get(..size).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 UDP datagram length",
            )
        })?;
        let (source, payload_offset) = parse_socks5_udp_packet(packet)?;
        let payload_len = size - payload_offset;
        data_store.copy_within(payload_offset..size, 0);
        Ok((payload_len, source))
    }
}

fn resolve_relay_addr(relay: &TargetAddr, proxy_peer: SocketAddr) -> Result<SocketAddr> {
    let mut addrs = relay.to_socket_addrs().map_err(|e| {
        DnsError::protocol(format!("Failed to resolve SOCKS5 UDP relay {relay}: {e}"))
    })?;
    let mut relay_addr = addrs
        .next()
        .ok_or_else(|| DnsError::protocol("SOCKS5 UDP relay resolved to no addresses"))?;

    // Some SOCKS5 servers report an unspecified BND.ADDR and expect the client
    // to use the address of the TCP control peer with the returned UDP port.
    if relay_addr.ip().is_unspecified() {
        relay_addr.set_ip(proxy_peer.ip());
    }

    Ok(relay_addr)
}

#[inline]
fn unspecified_for(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
    }
}

pub(crate) fn write_socks5_udp_header(buf: &mut [u8], target: &TargetAddr) -> io::Result<usize> {
    if buf.len() < SOCKS5_UDP_HEADER_MAX_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5 UDP header buffer is too small",
        ));
    }

    buf[..3].copy_from_slice(&[0, 0, 0]);
    let mut pos = 3;
    match target {
        TargetAddr::Ip(SocketAddr::V4(addr)) => {
            buf[pos] = 0x01;
            pos += 1;
            buf[pos..pos + 4].copy_from_slice(&addr.ip().octets());
            pos += 4;
            buf[pos..pos + 2].copy_from_slice(&addr.port().to_be_bytes());
            pos += 2;
        }
        TargetAddr::Ip(SocketAddr::V6(addr)) => {
            buf[pos] = 0x04;
            pos += 1;
            buf[pos..pos + 16].copy_from_slice(&addr.ip().octets());
            pos += 16;
            buf[pos..pos + 2].copy_from_slice(&addr.port().to_be_bytes());
            pos += 2;
        }
        TargetAddr::Domain(domain, port) => {
            let len = u8::try_from(domain.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 target domain is too long",
                )
            })?;
            buf[pos..pos + 2].copy_from_slice(&[0x03, len]);
            pos += 2;
            buf[pos..pos + domain.len()].copy_from_slice(domain.as_bytes());
            pos += domain.len();
            buf[pos..pos + 2].copy_from_slice(&port.to_be_bytes());
            pos += 2;
        }
    }
    Ok(pos)
}

pub(crate) fn parse_socks5_udp_packet(packet: &[u8]) -> io::Result<(TargetAddr, usize)> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 UDP reserved bytes",
        ));
    }
    if packet[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fragmented SOCKS5 UDP packets are unsupported",
        ));
    }

    match packet[3] {
        0x01 => {
            if packet.len() < 10 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated IPv4 header",
                ));
            }
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7])),
                u16::from_be_bytes([packet[8], packet[9]]),
            );
            Ok((TargetAddr::Ip(addr), 10))
        }
        0x04 => {
            if packet.len() < 22 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated IPv6 header",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[4..20]);
            let addr = SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([packet[20], packet[21]]),
            );
            Ok((TargetAddr::Ip(addr), 22))
        }
        0x03 => {
            let Some(&len) = packet.get(4) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated domain header",
                ));
            };
            let end = 5 + usize::from(len);
            if packet.len() < end + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated domain address",
                ));
            }
            let domain = std::str::from_utf8(&packet[5..end])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain name"))?;
            let port = u16::from_be_bytes([packet[end], packet[end + 1]]);
            Ok((TargetAddr::Domain(domain.to_string(), port), end + 2))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SOCKS5 UDP address type",
        )),
    }
}

pub(crate) fn response_source_matches(expected: &TargetAddr, received: &TargetAddr) -> bool {
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::oneshot;

    use super::*;

    async fn run_cross_family_association_test(listener: TcpListener, relay: UdpSocket) {
        let relay_addr = relay.local_addr().expect("relay should have an address");
        let proxy_addr = listener.local_addr().expect("proxy should have an address");
        let (close_proxy, close_proxy_rx) = oneshot::channel();

        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("proxy should accept");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            let mut associate = [0u8; 22];
            stream.read_exact(&mut associate).await.unwrap();
            assert_eq!(&associate[..4], &[0x05, 0x03, 0x00, 0x04]);
            assert_eq!(&associate[4..], &[0u8; 18]);

            let mut response = vec![0x05, 0x00, 0x00];
            match relay_addr {
                SocketAddr::V4(addr) => {
                    response.push(0x01);
                    response.extend_from_slice(&addr.ip().octets());
                    response.extend_from_slice(&addr.port().to_be_bytes());
                }
                SocketAddr::V6(addr) => {
                    response.push(0x04);
                    response.extend_from_slice(&addr.ip().octets());
                    response.extend_from_slice(&addr.port().to_be_bytes());
                }
            }
            stream.write_all(&response).await.unwrap();
            let _ = close_proxy_rx.await;
        });

        let association = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            Socks5UdpAssociation::connect(
                SocketOptions::default(),
                Socks5Opt {
                    username: None,
                    password: None,
                    socket_addr: proxy_addr,
                },
            ),
        )
        .await
        .expect("cross-family UDP association should not time out")
        .expect("cross-family UDP association should connect");

        assert_eq!(association.get_ref().peer_addr().unwrap(), relay_addr);
        assert_eq!(
            association.get_ref().local_addr().unwrap().is_ipv4(),
            relay_addr.is_ipv4()
        );

        let target = TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
        association
            .send_to(b"ping", &target)
            .await
            .expect("SOCKS5 UDP payload should send");

        let mut packet = [0u8; 128];
        let (len, client) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay.recv_from(&mut packet),
        )
        .await
        .expect("SOCKS5 UDP relay should receive without timing out")
        .unwrap();
        assert_eq!(&packet[..10], &[0, 0, 0, 1, 8, 8, 8, 8, 0, 53]);
        assert_eq!(&packet[10..len], b"ping");
        relay.send_to(&packet[..len], client).await.unwrap();

        let mut payload = [0u8; 128];
        let (len, source) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            association.recv_from(&mut payload),
        )
        .await
        .expect("SOCKS5 UDP response should not time out")
        .unwrap();
        assert_eq!(source, target);
        assert_eq!(&payload[..len], b"ping");

        let _ = close_proxy.send(());
        tokio::time::timeout(std::time::Duration::from_secs(2), proxy)
            .await
            .expect("SOCKS5 proxy task should finish without timing out")
            .unwrap();
    }

    #[tokio::test]
    async fn ipv4_proxy_can_use_ipv6_udp_relay() {
        let Ok(relay) = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).await
        else {
            return;
        };
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("IPv4 SOCKS5 listener should bind");
        run_cross_family_association_test(listener, relay).await;
    }

    #[tokio::test]
    async fn ipv6_proxy_can_use_ipv4_udp_relay() {
        let Ok(listener) =
            TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).await
        else {
            return;
        };

        let relay = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("IPv4 relay should bind");
        run_cross_family_association_test(listener, relay).await;
    }
}
