// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::cell::RefCell;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use fast_socks5::util::target_addr::TargetAddr;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::ReadBuf;
use tokio_util::sync::WaitForCancellationFutureOwned;

use crate::infra::error::Result;
use crate::infra::network::dial::{DialTarget, SocketOptions};
use crate::infra::network::proxy::Socks5Opt;
use crate::infra::network::transport::socks5_udp::{
    SOCKS5_UDP_HEADER_MAX_SIZE, Socks5UdpAssociation, control_closed_error,
    parse_socks5_udp_packet, response_source_matches, write_socks5_udp_header,
};

const MAX_UDP_PACKET_SIZE: usize = 65_535;
const MAX_DROPPED_DATAGRAMS_PER_POLL: usize = 16;

#[derive(Debug)]
pub(crate) struct Socks5QuicSocket {
    association: Socks5UdpAssociation,
    target: TargetAddr,
    quic_peer_addr: SocketAddr,
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
        let association = Socks5UdpAssociation::connect(socket_options, socks5).await?;
        let target_addr = if let Some(remote_ip) = target.remote_ip() {
            TargetAddr::Ip(SocketAddr::new(remote_ip, target.port()))
        } else {
            TargetAddr::Domain(target.host().to_string(), target.port())
        };

        // Quinn derives its endpoint address family from local_addr(), so
        // expose the connected SOCKS5 UDP relay as the logical QUIC
        // peer. The actual upstream target is carried independently in
        // the SOCKS5 UDP header. Keeping both logical addresses on the
        // same connected UDP socket avoids Quinn rejecting or
        // IPv4-mapping a cross-family upstream address.
        let quic_peer_addr = association.get_ref().peer_addr()?;
        let socket = Arc::new(Self {
            association,
            target: target_addr,
            quic_peer_addr,
        });
        Ok((socket, quic_peer_addr))
    }
}

impl AsyncUdpSocket for Socks5QuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let control_closed = Box::pin(self.association.control_closed_token().cancelled_owned());

        Box::pin(Socks5QuicPoller {
            socket: self,
            control_closed,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SOCKS5 QUIC socket does not support UDP segmentation",
            ));
        }
        if transmit.destination != self.quic_peer_addr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC transmit destination does not match SOCKS5 relay peer",
            ));
        }
        self.association.check_control_open()?;

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
        if self.association.poll_control_closed_recv(cx).is_ready() {
            return Poll::Ready(Err(control_closed_error()));
        }

        RECV_BUF.with(|raw| {
            let Ok(mut raw) = raw.try_borrow_mut() else {
                return Poll::Ready(Err(io::Error::other(
                    "SOCKS5 QUIC receive buffer is already in use",
                )));
            };

            // Malformed, fragmented, spoofed, or oversized SOCKS5 UDP datagrams
            // are packet-level failures. Drop them instead of surfacing a
            // socket error to Quinn, which would otherwise tear
            // down the whole QUIC connection. Bound the drain loop
            // so a flood of bad datagrams cannot monopolize one
            // executor poll.
            for _ in 0..MAX_DROPPED_DATAGRAMS_PER_POLL {
                let mut read_buf = ReadBuf::new(raw.as_mut_slice());
                match self.association.get_ref().poll_recv(cx, &mut read_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => {
                        if self.association.is_control_closed() {
                            return Poll::Ready(Err(control_closed_error()));
                        }
                        let packet = read_buf.filled();
                        let Ok((source, payload_offset)) = parse_socks5_udp_packet(packet) else {
                            continue;
                        };
                        if !response_source_matches(&self.target, &source) {
                            continue;
                        }

                        let payload = &packet[payload_offset..];
                        if payload.len() > output.len() {
                            continue;
                        }

                        output[..payload.len()].copy_from_slice(payload);
                        *output_meta = RecvMeta {
                            addr: self.quic_peer_addr,
                            len: payload.len(),
                            stride: payload.len(),
                            ecn: None,
                            dst_ip: None,
                        };
                        return Poll::Ready(Ok(1));
                    }
                }
            }

            cx.waker().wake_by_ref();
            Poll::Pending
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.association.get_ref().local_addr()
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
    control_closed: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl UdpPoller for Socks5QuicPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.control_closed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(control_closed_error()));
        }

        match self.socket.association.get_ref().poll_send_ready(cx) {
            Poll::Ready(Ok(())) if self.socket.association.is_control_closed() => {
                Poll::Ready(Err(control_closed_error()))
            }
            other => other,
        }
    }
}

const SMALL_SEND_BUFFER_SIZE: usize = 2_048;

fn send_complete(socket: &Socks5QuicSocket, buf: &[u8]) -> io::Result<()> {
    let sent = socket.association.get_ref().try_send(buf)?;
    if sent != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "partial SOCKS5 QUIC UDP send",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::pin::Pin;
    use std::time::Duration;

    use futures::future::poll_fn;
    use quinn::udp::Transmit;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    use super::*;
    use crate::infra::network::proxy::Socks5Opt;

    async fn send_when_writable(
        socket: &Arc<dyn AsyncUdpSocket>,
        transmit: &Transmit<'_>,
    ) -> io::Result<()> {
        let mut poller = socket.clone().create_io_poller();
        loop {
            match socket.try_send(transmit) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    poll_fn(|cx| poller.as_mut().poll_writable(cx)).await?;
                }
                Err(error) => return Err(error),
            }
        }
    }

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
        let (source, payload_offset) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(source, TargetAddr::Ip("8.8.8.8:53".parse().unwrap()));
        assert_eq!(&packet[payload_offset..], &[1, 2, 3]);
    }

    #[test]
    fn parses_socks5_udp_ipv6_packet() {
        let mut packet = vec![0, 0, 0, 0x04];
        packet.extend_from_slice(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&853u16.to_be_bytes());
        packet.extend_from_slice(&[9, 8, 7]);
        let (source, payload_offset) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(source, TargetAddr::Ip("[2001:db8::1]:853".parse().unwrap()));
        assert_eq!(&packet[payload_offset..], &[9, 8, 7]);
    }

    #[test]
    fn parses_socks5_udp_domain_packet() {
        let packet = [
            0, 0, 0, 0x03, 11, b'd', b'n', b's', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
            53, 4, 5, 6,
        ];
        let (source, payload_offset) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(source, TargetAddr::Domain("dns.example".to_string(), 53));
        assert_eq!(&packet[payload_offset..], &[4, 5, 6]);
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
        let expected_peer = relay_addr;
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

            let mut associate = [0u8; 10];
            stream
                .read_exact(&mut associate)
                .await
                .expect("proxy should read UDP associate request");
            assert_eq!(associate, [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

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
        send_when_writable(
            &socket,
            &Transmit {
                destination: peer_addr,
                contents: &payload,
                segment_size: None,
                src_ip: None,
                ecn: None,
            },
        )
        .await
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

        assert_eq!(peer_addr, relay_addr);
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

        assert_eq!(peer_addr, relay_addr);

        let relay_task = tokio::spawn(async move {
            let mut packet = [0u8; 1024];
            let (len, client) = relay.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..4], &[0x00, 0x00, 0x00, 0x03]);
            assert_eq!(packet[4], 11);
            assert_eq!(&packet[5..16], b"dns.example");
            assert_eq!(&packet[16..18], &853u16.to_be_bytes());
            relay.send_to(&packet[..len], client).await.unwrap();
        });

        send_when_writable(
            &socket,
            &Transmit {
                destination: peer_addr,
                contents: b"domain-target",
                segment_size: None,
                src_ip: None,
                ecn: None,
            },
        )
        .await
        .unwrap();

        relay_task.await.unwrap();
        let _ = close_proxy.send(());
        proxy.await.unwrap();
    }

    async fn run_cross_family_quic_peer_test(relay: UdpSocket, upstream_ip: IpAddr) {
        let relay_addr = relay.local_addr().expect("relay should have an address");
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("IPv4 SOCKS5 listener should bind");
        let proxy_addr = listener
            .local_addr()
            .expect("SOCKS5 listener should have an address");
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

        let (socket, quic_peer_addr) = timeout(
            Duration::from_secs(2),
            Socks5QuicSocket::connect(
                DialTarget::new(Some(upstream_ip), "dns.example".to_string(), 853),
                SocketOptions::default(),
                Socks5Opt {
                    username: None,
                    password: None,
                    socket_addr: proxy_addr,
                },
            ),
        )
        .await
        .expect("cross-family SOCKS5 QUIC connect should not time out")
        .expect("cross-family SOCKS5 QUIC socket should connect");

        assert_eq!(quic_peer_addr, relay_addr);
        assert_eq!(
            socket.local_addr().unwrap().is_ipv4(),
            quic_peer_addr.is_ipv4(),
            "Quinn local and logical peer addresses must use the same family"
        );

        let expected_target = TargetAddr::Ip(SocketAddr::new(upstream_ip, 853));
        let relay_task = tokio::spawn(async move {
            let mut packet = [0u8; 1024];
            let (len, client) = relay.recv_from(&mut packet).await.unwrap();
            let (target, payload_offset) = parse_socks5_udp_packet(&packet[..len]).unwrap();
            assert_eq!(target, expected_target);
            assert_eq!(&packet[payload_offset..len], b"cross-family");
            relay.send_to(&packet[..len], client).await.unwrap();
        });

        timeout(
            Duration::from_secs(2),
            send_when_writable(
                &socket,
                &Transmit {
                    destination: quic_peer_addr,
                    contents: b"cross-family",
                    segment_size: None,
                    src_ip: None,
                    ecn: None,
                },
            ),
        )
        .await
        .expect("cross-family QUIC send should not time out")
        .expect("cross-family QUIC send should succeed");

        let mut output = [0u8; 64];
        let mut meta = [RecvMeta {
            addr: quic_peer_addr,
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];
        let received = timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                Pin::new(&socket).poll_recv(cx, &mut [IoSliceMut::new(&mut output)], &mut meta)
            }),
        )
        .await
        .expect("cross-family QUIC receive should not time out")
        .expect("cross-family QUIC receive should succeed");
        assert_eq!(received, 1);
        assert_eq!(meta[0].addr, quic_peer_addr);
        assert_eq!(&output[..meta[0].len], b"cross-family");

        relay_task.await.unwrap();
        let _ = close_proxy.send(());
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn ipv4_relay_is_quic_peer_for_ipv6_upstream() {
        let relay = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("IPv4 relay should bind");
        run_cross_family_quic_peer_test(
            relay,
            IpAddr::V6("2001:db8::53".parse::<Ipv6Addr>().unwrap()),
        )
        .await;
    }

    #[tokio::test]
    async fn ipv6_relay_is_quic_peer_for_ipv4_upstream() {
        let Ok(relay) = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).await
        else {
            return;
        };
        run_cross_family_quic_peer_test(relay, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).await;
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
        assert_eq!(peer_addr, relay_addr);

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
    async fn control_close_wakes_pending_quic_io() {
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
            // Dropping the control stream invalidates the UDP association.
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

        let recv_socket = socket.clone();
        let (poll_started, poll_started_rx) = oneshot::channel();
        let recv_task = tokio::spawn(async move {
            let mut output = [0u8; 64];
            let mut meta = [RecvMeta {
                addr: peer_addr,
                len: 0,
                stride: 0,
                ecn: None,
                dst_ip: None,
            }];
            let mut poll_started = Some(poll_started);

            poll_fn(|cx| {
                let mut bufs = [IoSliceMut::new(&mut output)];
                let poll = Pin::new(&recv_socket).poll_recv(cx, &mut bufs, &mut meta);
                if poll.is_pending() {
                    if let Some(started) = poll_started.take() {
                        let _ = started.send(());
                    }
                }
                poll
            })
            .await
        });

        poll_started_rx
            .await
            .expect("QUIC receive should register before control close");
        close_proxy
            .send(())
            .expect("proxy close signal should be delivered");

        let recv_err = timeout(Duration::from_secs(1), recv_task)
            .await
            .expect("control close should wake pending QUIC receive")
            .expect("receive task should not panic")
            .expect_err("closed SOCKS5 control channel should fail receive");
        assert_eq!(recv_err.kind(), io::ErrorKind::ConnectionAborted);

        let send_err = socket
            .try_send(&Transmit {
                destination: peer_addr,
                contents: b"after-close",
                segment_size: None,
                src_ip: None,
                ecn: None,
            })
            .expect_err("closed control channel should reject QUIC sends");
        assert_eq!(send_err.kind(), io::ErrorKind::ConnectionAborted);

        let mut poller = socket.clone().create_io_poller();
        let writable_err = poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .expect_err("closed control channel should fail writable polling");
        assert_eq!(writable_err.kind(), io::ErrorKind::ConnectionAborted);

        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn poll_recv_drops_invalid_datagrams_before_valid_response() {
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
            let wrong = [0, 0, 0, 1, 1, 1, 1, 1, 0x03, 0x55, 1, 2, 3];
            relay.send_to(&wrong, client).await.unwrap();
            let fragmented = [0, 0, 1, 1, 8, 8, 8, 8, 0x03, 0x55, 4, 5, 6];
            relay.send_to(&fragmented, client).await.unwrap();
            let valid = [0, 0, 0, 1, 8, 8, 8, 8, 0x03, 0x55, 7, 8, 9];
            relay.send_to(&valid, client).await.unwrap();
        });

        send_when_writable(
            &socket,
            &Transmit {
                destination: peer_addr,
                contents: b"probe",
                segment_size: None,
                src_ip: None,
                ecn: None,
            },
        )
        .await
        .unwrap();

        let mut output = [0u8; 64];
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
        .expect("invalid SOCKS5 datagrams should be dropped");
        assert_eq!(received, 1);
        assert_eq!(meta[0].len, 3);
        assert_eq!(&output[..3], &[7, 8, 9]);

        relay_task.await.unwrap();
        let _ = close_proxy.send(());
        proxy.await.unwrap();
    }
}
