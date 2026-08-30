// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::cell::RefCell;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use fast_socks5::client::Socks5Datagram;
use fast_socks5::util::target_addr::TargetAddr;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::ReadBuf;
use tokio::net::{TcpStream, UdpSocket};

use crate::infra::error::Result;
use crate::infra::network::dial::{
    DialTarget, SocketOptions, TcpDialOptions, bind_udp, connect_tcp as dial_connect_tcp,
};
use crate::infra::network::proxy::Socks5Opt;

const MAX_UDP_PACKET_SIZE: usize = 65_535;

#[derive(Debug)]
pub(crate) struct Socks5QuicSocket {
    datagram: Socks5Datagram<TcpStream>,
    target: TargetAddr,
    peer_addr: SocketAddr,
}

thread_local! {
    static RECV_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; MAX_UDP_PACKET_SIZE]);
}

impl Socks5QuicSocket {
    pub(crate) async fn connect(
        target: DialTarget,
        socket_options: SocketOptions,
        socks5: Socks5Opt,
    ) -> Result<(Arc<dyn AsyncUdpSocket>, SocketAddr)> {
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
        let target_addr = if let Some(remote_ip) = target.remote_ip() {
            TargetAddr::Ip(SocketAddr::new(remote_ip, target.port()))
        } else {
            TargetAddr::Domain(target.host().to_string(), target.port())
        };
        let peer_addr = target
            .remote_ip()
            .map(|ip| SocketAddr::new(ip, target.port()))
            .unwrap_or_else(|| SocketAddr::new(socks5.socket_addr.ip(), target.port()));
        let socket = Arc::new(Self {
            datagram,
            target: target_addr,
            peer_addr,
        });
        Ok((socket, peer_addr))
    }
}

impl AsyncUdpSocket for Socks5QuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Socks5QuicPoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS5 QUIC socket does not support UDP segmentation",
            ));
        }
        if transmit.destination != self.peer_addr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC transmit destination does not match SOCKS5 upstream",
            ));
        }
        let mut header = [0u8; SOCKS5_UDP_HEADER_MAX_SIZE];
        let header_len = write_socks5_udp_header(&mut header, &self.target)?;

        if header_len + transmit.contents.len() <= SMALL_SEND_BUFFER_SIZE {
            let mut buf = [0u8; SMALL_SEND_BUFFER_SIZE];
            buf[..header_len].copy_from_slice(&header[..header_len]);
            buf[header_len..header_len + transmit.contents.len()]
                .copy_from_slice(transmit.contents);
            send_complete(self, &buf[..header_len + transmit.contents.len()])
        } else {
            let mut buf = Vec::with_capacity(header_len + transmit.contents.len());
            buf.extend_from_slice(&header[..header_len]);
            buf.extend_from_slice(transmit.contents);
            send_complete(self, &buf)
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(output) = bufs.first_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC receive buffer is empty",
            )));
        };
        let Some(output_meta) = meta.first_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC receive metadata is empty",
            )));
        };
        RECV_BUF.with(|raw| {
            let Ok(mut raw) = raw.try_borrow_mut() else {
                return Poll::Ready(Err(io::Error::other(
                    "SOCKS5 QUIC receive buffer is already in use",
                )));
            };
            let mut read_buf = ReadBuf::new(raw.as_mut_slice());
            match self.datagram.get_ref().poll_recv(cx, &mut read_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let (source, payload) = match parse_socks5_udp_packet(read_buf.filled()) {
                        Ok(parsed) => parsed,
                        Err(err) => return Poll::Ready(Err(err)),
                    };
                    if !response_source_matches(&self.target, &source) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "SOCKS5 QUIC response source mismatch: expected {}, received {}",
                                self.target, source
                            ),
                        )));
                    }
                    if payload.len() > output.len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "SOCKS5 QUIC packet exceeds receive buffer",
                        )));
                    }
                    output[..payload.len()].copy_from_slice(payload);
                    *output_meta = RecvMeta {
                        addr: self.peer_addr,
                        len: payload.len(),
                        stride: payload.len(),
                        ecn: None,
                        dst_ip: None,
                    };
                    Poll::Ready(Ok(1))
                }
            }
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.datagram.get_ref().local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct Socks5QuicPoller {
    socket: Arc<Socks5QuicSocket>,
}

impl UdpPoller for Socks5QuicPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.datagram.get_ref().poll_send_ready(cx)
    }
}

const SOCKS5_UDP_HEADER_MAX_SIZE: usize = 3 + 1 + 1 + 255 + 2;
const SMALL_SEND_BUFFER_SIZE: usize = 2_048;

fn send_complete(socket: &Socks5QuicSocket, buf: &[u8]) -> io::Result<()> {
    let sent = socket.datagram.get_ref().try_send(buf)?;
    if sent != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial SOCKS5 QUIC UDP send",
        ));
    }
    Ok(())
}

fn write_socks5_udp_header(buf: &mut [u8], target: &TargetAddr) -> io::Result<usize> {
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

fn parse_socks5_udp_packet(packet: &[u8]) -> io::Result<(TargetAddr, &[u8])> {
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
            Ok((TargetAddr::Ip(addr), &packet[10..]))
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
            Ok((TargetAddr::Ip(addr), &packet[22..]))
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
            Ok((
                TargetAddr::Domain(domain.to_string(), port),
                &packet[end + 2..],
            ))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SOCKS5 UDP address type",
        )),
    }
}

fn response_source_matches(expected: &TargetAddr, received: &TargetAddr) -> bool {
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;

    use futures::future::poll_fn;
    use quinn::udp::Transmit;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::oneshot;

    use super::*;
    use crate::infra::network::proxy::Socks5Opt;

    #[test]
    fn response_source_rejects_wrong_upstream() {
        let expected = TargetAddr::Ip("8.8.8.8:53".parse().unwrap());
        let correct = TargetAddr::Ip("8.8.8.8:53".parse().unwrap());
        let wrong_ip = TargetAddr::Ip("1.1.1.1:53".parse().unwrap());
        let wrong_port = TargetAddr::Ip("8.8.8.8:5353".parse().unwrap());

        assert!(response_source_matches(&expected, &correct));
        assert!(!response_source_matches(&expected, &wrong_ip));
        assert!(!response_source_matches(&expected, &wrong_port));

        let expected_domain = TargetAddr::Domain("dns.example".to_string(), 853);
        assert!(response_source_matches(
            &expected_domain,
            &TargetAddr::Ip("192.0.2.1:853".parse().unwrap())
        ));
        assert!(!response_source_matches(
            &expected_domain,
            &TargetAddr::Ip("192.0.2.1:854".parse().unwrap())
        ));
        assert!(response_source_matches(
            &TargetAddr::Domain("dns.example.".to_string(), 853),
            &TargetAddr::Domain("DNS.EXAMPLE".to_string(), 853)
        ));
    }

    #[test]
    fn parses_socks5_udp_ipv4_packet() {
        let packet = [0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 1, 2, 3];
        let (source, payload) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(source, TargetAddr::Ip("8.8.8.8:53".parse().unwrap()));
        assert_eq!(payload, &[1, 2, 3]);
    }

    #[test]
    fn parses_socks5_udp_ipv6_packet() {
        let mut packet = vec![0, 0, 0, 0x04];
        packet.extend_from_slice(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&853u16.to_be_bytes());
        packet.extend_from_slice(&[9, 8, 7]);
        let (source, payload) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(source, TargetAddr::Ip("[2001:db8::1]:853".parse().unwrap()));
        assert_eq!(payload, &[9, 8, 7]);
    }

    #[test]
    fn parses_socks5_udp_domain_packet() {
        let packet = [
            0, 0, 0, 0x03, 11, b'd', b'n', b's', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
            53, 4, 5, 6,
        ];
        let (source, payload) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(source, TargetAddr::Domain("dns.example".to_string(), 53));
        assert_eq!(payload, &[4, 5, 6]);
    }

    #[test]
    fn rejects_fragmented_socks5_udp_packet() {
        let packet = [0, 0, 1, 1, 8, 8, 8, 8, 0, 53];
        let err = parse_socks5_udp_packet(&packet).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn rejects_invalid_socks5_udp_reserved_bytes() {
        let packet = [1, 0, 0, 1, 8, 8, 8, 8, 0, 53];
        let err = parse_socks5_udp_packet(&packet).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn connect_requests_udp_associate_and_round_trips_payload() {
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
        let upstream_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let expected_peer = SocketAddr::new(upstream_ip, 853);
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

        let (socket, peer_addr) = Socks5QuicSocket::connect(
            DialTarget::new(Some(upstream_ip), "dns.google".to_string(), 853),
            SocketOptions::default(),
            Socks5Opt {
                username: None,
                password: None,
                socket_addr: proxy_addr,
            },
        )
        .await
        .expect("SOCKS5 QUIC socket should connect");

        assert_eq!(peer_addr, expected_peer);

        let relay_task = tokio::spawn(async move {
            let mut packet = [0u8; 4096];
            let (len, client) = relay
                .recv_from(&mut packet)
                .await
                .expect("relay should receive SOCKS5 UDP packet");
            assert_eq!(&packet[..4], &[0x00, 0x00, 0x00, 0x01]);
            assert_eq!(&packet[4..8], &[8, 8, 8, 8]);
            assert_eq!(&packet[8..10], &853u16.to_be_bytes());
            relay
                .send_to(&packet[..len], client)
                .await
                .expect("relay should echo SOCKS5 UDP packet");
        });

        let payload = vec![0xA5; 3_000];
        socket
            .try_send(&Transmit {
                destination: peer_addr,
                contents: &payload,
                segment_size: None,
                src_ip: None,
                ecn: None,
            })
            .expect("QUIC transmit should succeed");

        let mut output = [0u8; 4096];
        let mut meta = [RecvMeta {
            addr: peer_addr,
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];
        let received = poll_fn(|cx| {
            Pin::new(&socket).poll_recv(cx, &mut [IoSliceMut::new(&mut output)], &mut meta)
        })
        .await
        .expect("QUIC receive should succeed");
        assert_eq!(received, 1);
        assert_eq!(meta[0].len, payload.len());
        assert_eq!(&output[..payload.len()], payload.as_slice());

        relay_task.await.expect("relay task should complete");
        let _ = close_proxy.send(());
        proxy.await.expect("proxy task should complete");
    }

    #[tokio::test]
    async fn connect_authenticates_udp_associate_with_password() {
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

        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("proxy should accept");
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
            stream.write_all(&[0x05, 0x02]).await.unwrap();

            let mut auth = [0u8; 15];
            stream.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth, *b"\x01\x04user\x08password");
            stream.write_all(&[0x01, 0x00]).await.unwrap();

            let mut associate = [0u8; 22];
            stream.read_exact(&mut associate).await.unwrap();
            assert_eq!(&associate[..4], &[0x05, 0x03, 0x00, 0x04]);

            let mut response = vec![0x05, 0x00, 0x00, 0x01];
            response.extend_from_slice(&match relay_addr.ip() {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(_) => unreachable!("relay is IPv4"),
            });
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&response).await.unwrap();
        });

        let (_socket, peer_addr) = Socks5QuicSocket::connect(
            DialTarget::new(
                Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                "dns.google".to_string(),
                853,
            ),
            SocketOptions::default(),
            Socks5Opt {
                username: Some("user".to_string()),
                password: Some("password".to_string()),
                socket_addr: proxy_addr,
            },
        )
        .await
        .expect("authenticated SOCKS5 QUIC socket should connect");

        assert_eq!(
            peer_addr,
            SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 853)
        );
        proxy.await.expect("proxy task should complete");
    }

    #[tokio::test]
    async fn connect_uses_domain_target_when_remote_ip_is_unknown() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (close_proxy, close_proxy_rx) = oneshot::channel();

        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let mut associate = [0u8; 22];
            stream.read_exact(&mut associate).await.unwrap();
            let mut response = vec![0x05, 0x00, 0x00, 0x01];
            response.extend_from_slice(&match relay_addr.ip() {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(_) => unreachable!("relay is IPv4"),
            });
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&response).await.unwrap();
            let _ = close_proxy_rx.await;
        });

        let (socket, peer_addr) = Socks5QuicSocket::connect(
            DialTarget::new(None, "dns.example".to_string(), 853),
            SocketOptions::default(),
            Socks5Opt {
                username: None,
                password: None,
                socket_addr: proxy_addr,
            },
        )
        .await
        .unwrap();

        assert_eq!(peer_addr, SocketAddr::new(proxy_addr.ip(), 853));

        let relay_task = tokio::spawn(async move {
            let mut packet = [0u8; 1024];
            let (len, client) = relay.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..4], &[0x00, 0x00, 0x00, 0x03]);
            assert_eq!(packet[4], 11);
            assert_eq!(&packet[5..16], b"dns.example");
            assert_eq!(&packet[16..18], &853u16.to_be_bytes());
            relay.send_to(&packet[..len], client).await.unwrap();
        });

        socket
            .try_send(&Transmit {
                destination: peer_addr,
                contents: b"domain-target",
                segment_size: None,
                src_ip: None,
                ecn: None,
            })
            .unwrap();

        relay_task.await.unwrap();
        let _ = close_proxy.send(());
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn try_send_rejects_mismatched_quic_destination() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (close_proxy, close_proxy_rx) = oneshot::channel();

        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let mut associate = [0u8; 22];
            stream.read_exact(&mut associate).await.unwrap();
            let mut response = vec![0x05, 0x00, 0x00, 0x01];
            response.extend_from_slice(&match relay_addr.ip() {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(_) => unreachable!("relay is IPv4"),
            });
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&response).await.unwrap();
            let _ = close_proxy_rx.await;
        });

        let upstream = SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 853);
        let (socket, peer_addr) = Socks5QuicSocket::connect(
            DialTarget::new(Some(upstream.ip()), "dns.google".to_string(), 853),
            SocketOptions::default(),
            Socks5Opt {
                username: None,
                password: None,
                socket_addr: proxy_addr,
            },
        )
        .await
        .unwrap();
        assert_eq!(peer_addr, upstream);

        let wrong_destination = SocketAddr::new(Ipv4Addr::new(1, 1, 1, 1).into(), 853);
        let err = socket
            .try_send(&Transmit {
                destination: wrong_destination,
                contents: b"x",
                segment_size: None,
                src_ip: None,
                ecn: None,
            })
            .expect_err("mismatched destination should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let _ = close_proxy.send(());
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn try_send_rejects_udp_segmentation() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (close_proxy, close_proxy_rx) = oneshot::channel();

        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let mut associate = [0u8; 22];
            stream.read_exact(&mut associate).await.unwrap();
            let mut response = vec![0x05, 0x00, 0x00, 0x01];
            response.extend_from_slice(&match relay_addr.ip() {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(_) => unreachable!("relay is IPv4"),
            });
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&response).await.unwrap();
            let _ = close_proxy_rx.await;
        });

        let upstream = SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 853);
        let (socket, peer_addr) = Socks5QuicSocket::connect(
            DialTarget::new(Some(upstream.ip()), "dns.google".to_string(), 853),
            SocketOptions::default(),
            Socks5Opt {
                username: None,
                password: None,
                socket_addr: proxy_addr,
            },
        )
        .await
        .unwrap();

        let err = socket
            .try_send(&Transmit {
                destination: peer_addr,
                contents: b"x",
                segment_size: Some(1200),
                src_ip: None,
                ecn: None,
            })
            .expect_err("UDP segmentation should be unsupported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        let _ = close_proxy.send(());
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn poll_recv_rejects_response_source_mismatch() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (close_proxy, close_proxy_rx) = oneshot::channel();

        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();
            let mut associate = [0u8; 22];
            stream.read_exact(&mut associate).await.unwrap();
            let mut response = vec![0x05, 0x00, 0x00, 0x01];
            response.extend_from_slice(&match relay_addr.ip() {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(_) => unreachable!("relay is IPv4"),
            });
            response.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&response).await.unwrap();
            let _ = close_proxy_rx.await;
        });

        let (socket, peer_addr) = Socks5QuicSocket::connect(
            DialTarget::new(
                Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                "dns.google".to_string(),
                853,
            ),
            SocketOptions::default(),
            Socks5Opt {
                username: None,
                password: None,
                socket_addr: proxy_addr,
            },
        )
        .await
        .unwrap();

        let relay_task = tokio::spawn(async move {
            let mut packet = [0u8; 1024];
            let (_len, client) = relay.recv_from(&mut packet).await.unwrap();
            let wrong = [0, 0, 0, 1, 1, 1, 1, 1, 0, 53, 1, 2, 3];
            relay.send_to(&wrong, client).await.unwrap();
        });

        socket
            .try_send(&Transmit {
                destination: peer_addr,
                contents: b"probe",
                segment_size: None,
                src_ip: None,
                ecn: None,
            })
            .unwrap();

        let mut output = [0u8; 64];
        let mut meta = [RecvMeta {
            addr: peer_addr,
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];
        let err = poll_fn(|cx| {
            Pin::new(&socket).poll_recv(cx, &mut [IoSliceMut::new(&mut output)], &mut meta)
        })
        .await
        .expect_err("wrong SOCKS5 source should be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        relay_task.await.unwrap();
        let _ = close_proxy.send(());
        proxy.await.unwrap();
    }
}
