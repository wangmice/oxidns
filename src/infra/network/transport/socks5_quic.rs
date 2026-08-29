// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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
    send_buf: Mutex<Vec<u8>>,
    recv_buf: Mutex<Vec<u8>>,
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
            send_buf: Mutex::new(Vec::with_capacity(2_048)),
            recv_buf: Mutex::new(vec![0u8; MAX_UDP_PACKET_SIZE]),
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
        let mut buf = self
            .send_buf
            .lock()
            .map_err(|_| io::Error::other("SOCKS5 QUIC send buffer lock poisoned"))?;
        write_socks5_udp_header(&mut buf, &self.target)?;
        buf.extend_from_slice(transmit.contents);
        let sent = self.datagram.get_ref().try_send(buf.as_slice())?;
        if sent != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial SOCKS5 QUIC UDP send",
            ));
        }
        Ok(())
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
        let mut raw = match self.recv_buf.lock() {
            Ok(raw) => raw,
            Err(_) => {
                return Poll::Ready(Err(io::Error::other(
                    "SOCKS5 QUIC receive buffer lock poisoned",
                )));
            }
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

fn write_socks5_udp_header(buf: &mut Vec<u8>, target: &TargetAddr) -> io::Result<()> {
    buf.clear();
    buf.extend_from_slice(&[0, 0, 0]);
    match target {
        TargetAddr::Ip(SocketAddr::V4(addr)) => {
            buf.push(0x01);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(addr)) => {
            buf.push(0x04);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            let len = u8::try_from(domain.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "SOCKS5 target domain is too long")
            })?;
            buf.extend_from_slice(&[0x03, len]);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
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
    use super::*;

    #[test]
    fn parses_socks5_udp_ipv4_packet() {
        let packet = [0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 1, 2, 3];
        let (source, payload) = parse_socks5_udp_packet(&packet).unwrap();
        assert_eq!(source, TargetAddr::Ip("8.8.8.8:53".parse().unwrap()));
        assert_eq!(payload, &[1, 2, 3]);
    }

    #[test]
    fn rejects_fragmented_socks5_udp_packet() {
        let packet = [0, 0, 1, 1, 8, 8, 8, 8, 0, 53];
        let err = parse_socks5_udp_packet(&packet).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
