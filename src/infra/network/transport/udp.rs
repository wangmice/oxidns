// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, RawFd};

use fast_socks5::util::target_addr::TargetAddr;
#[cfg(target_os = "linux")]
use socket2::SockAddr;
#[cfg(target_os = "linux")]
use tokio::io::Interest;
use tokio::net::UdpSocket;

use crate::infra::error::{DnsError, Result};
use crate::infra::network::buffer_pool::wire_buffer_pool;
use crate::infra::network::dial::{DialTarget, SocketOptions};
use crate::infra::network::proxy::Socks5Opt;
use crate::infra::network::transport::socks5_udp::{Socks5UdpAssociation, response_source_matches};
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

/// A received DNS datagram and the local address that received it.
#[derive(Debug)]
pub struct ReceivedUdpMessage {
    pub message: Message,
    pub source: SocketAddr,
    pub destination: Option<IpAddr>,
}

#[derive(Debug)]
enum UdpTransportSocket {
    Direct(UdpSocket),
    Socks5 {
        association: Socks5UdpAssociation,
        target: TargetAddr,
    },
}

#[derive(Debug)]
pub(crate) enum UdpReadError {
    Receive(DnsError),
    InvalidDatagram(DnsError),
}

impl UdpReadError {
    #[inline]
    pub(crate) fn should_backoff(&self) -> bool {
        matches!(self, Self::Receive(_))
    }

    #[inline]
    fn into_dns_error(self) -> DnsError {
        match self {
            Self::Receive(err) | Self::InvalidDatagram(err) => err,
        }
    }
}

impl std::fmt::Display for UdpReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Receive(err) | Self::InvalidDatagram(err) => write!(f, "{err}"),
        }
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
        let association = Socks5UdpAssociation::connect(socket_options, socks5).await?;
        let target = if let Some(remote_ip) = target.remote_ip() {
            TargetAddr::Ip(SocketAddr::new(remote_ip, target.port()))
        } else {
            TargetAddr::Domain(target.host().to_string(), target.port())
        };
        Ok(Self {
            socket: UdpTransportSocket::Socks5 {
                association,
                target,
            },
        })
    }

    pub(crate) fn recv_buffer_size(&self, direct_size: usize) -> usize {
        match self.socket {
            UdpTransportSocket::Direct(_) => direct_size,
            UdpTransportSocket::Socks5 { .. } => usize::from(u16::MAX),
        }
    }

    /// Completes when an underlying SOCKS5 UDP control connection dies. Direct
    /// UDP has no persistent control channel and therefore never resolves here.
    pub(crate) async fn control_closed(&self) {
        match &self.socket {
            UdpTransportSocket::Direct(_) => std::future::pending::<()>().await,
            UdpTransportSocket::Socks5 { association, .. } => association.control_closed().await,
        }
    }

    /// Receive one UDP datagram and decode it as a DNS message.
    /// Blocks until a datagram arrives or the socket errors.
    #[inline]
    #[hotpath::measure]
    pub async fn read_message(&self, buf: &mut [u8]) -> Result<Message> {
        self.read_message_classified(buf)
            .await
            .map_err(UdpReadError::into_dns_error)
    }

    /// Receive one UDP datagram while preserving whether a failure came from
    /// the receive path itself or from validating/decoding one datagram.
    ///
    /// Callers that implement receive-error backoff must only back off on
    /// [`UdpReadError::Receive`]. Invalid datagrams are packet-scoped and must
    /// not throttle the shared listener.
    #[inline]
    pub(crate) async fn read_message_classified(
        &self,
        buf: &mut [u8],
    ) -> std::result::Result<Message, UdpReadError> {
        let n = match &self.socket {
            UdpTransportSocket::Direct(socket) => socket.recv(buf).await.map_err(|e| {
                UdpReadError::Receive(DnsError::protocol(format!("UDP recv error: {e}")))
            })?,
            UdpTransportSocket::Socks5 {
                association,
                target,
            } => {
                let (n, source) = association.recv_from(buf).await.map_err(|e| {
                    let err = DnsError::protocol(format!("SOCKS5 UDP recv error: {e}"));
                    match e.kind() {
                        std::io::ErrorKind::InvalidData | std::io::ErrorKind::Unsupported => {
                            UdpReadError::InvalidDatagram(err)
                        }
                        _ => UdpReadError::Receive(err),
                    }
                })?;
                if !response_source_matches(target, &source) {
                    return Err(UdpReadError::InvalidDatagram(DnsError::protocol(format!(
                        "SOCKS5 UDP response source mismatch: expected {target}, received {source}"
                    ))));
                }
                n
            }
        };

        Message::from_bytes(&buf[..n]).map_err(|e| {
            UdpReadError::InvalidDatagram(DnsError::protocol(format!(
                "Failed to parse DNS message from UDP: {e}"
            )))
        })
    }

    /// Receive one UDP datagram from any peer and decode it as a DNS message.
    #[inline]
    #[hotpath::measure]
    pub async fn read_message_from(&self, buf: &mut [u8]) -> Result<ReceivedUdpMessage> {
        let UdpTransportSocket::Direct(socket) = &self.socket else {
            return Err(DnsError::protocol(
                "SOCKS5 UDP transport does not support unconnected receive",
            ));
        };

        #[cfg(target_os = "linux")]
        let (n, addr, destination) = loop {
            socket
                .readable()
                .await
                .map_err(|e| DnsError::protocol(format!("Failed to poll UDP socket: {e}")))?;
            match socket.try_io(Interest::READABLE, || {
                recv_from_pktinfo(socket.as_raw_fd(), buf)
            }) {
                Ok(result) => break result,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    return Err(DnsError::protocol(format!(
                        "Failed to recv_from UDP with pktinfo: {e}"
                    )));
                }
            }
        };

        #[cfg(not(target_os = "linux"))]
        let (n, addr, destination) = {
            let (n, addr) = socket
                .recv_from(buf)
                .await
                .map_err(|e| DnsError::protocol(format!("Failed to recv_from UDP: {e}")))?;
            (n, addr, None)
        };

        let msg = Message::from_bytes(&buf[..n]).map_err(|e| {
            DnsError::protocol(format!("Failed to parse DNS message from UDP: {e}"))
        })?;
        Ok(ReceivedUdpMessage {
            message: msg,
            source: addr,
            destination,
        })
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
            UdpTransportSocket::Socks5 {
                association,
                target,
            } => association
                .send_to(&bytes, target)
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

    /// Send a response while preserving the local IPv4 address that received
    /// it.
    #[cfg(target_os = "linux")]
    pub async fn write_message_to_with_source(
        &self,
        msg: &Message,
        to: SocketAddr,
        source: Option<IpAddr>,
        max_payload: u16,
    ) -> Result<()> {
        let UdpTransportSocket::Direct(socket) = &self.socket else {
            return Err(DnsError::protocol(
                "SOCKS5 UDP transport does not support unconnected send",
            ));
        };
        let mut bytes = wire_buffer_pool().acquire();
        msg.append_to_with_limit(usize::from(max_payload), &mut bytes)?;
        let Some(source) = source else {
            let n = socket
                .send_to(&bytes, to)
                .await
                .map_err(|e| DnsError::protocol(format!("Failed to send_to UDP: {e}")))?;
            return if n == bytes.len() {
                Ok(())
            } else {
                Err(DnsError::protocol(format!(
                    "Partial UDP send_to: sent {n} of {} bytes",
                    bytes.len()
                )))
            };
        };
        let n = send_to_with_source_async(socket, &bytes, to, source)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to send UDP response: {e}")))?;
        if n != bytes.len() {
            return Err(DnsError::protocol(format!(
                "Partial UDP send_to: sent {n} of {} bytes",
                bytes.len()
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[repr(align(8))]
struct AlignedControlBuffer([u8; 64]);

#[cfg(target_os = "linux")]
fn recv_from_pktinfo(
    fd: RawFd,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    use std::mem::zeroed;

    let mut peer: libc::sockaddr_storage = unsafe { zeroed() };
    let mut control = AlignedControlBuffer([0u8; 64]);
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = (&mut peer as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = control.0.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let peer = unsafe {
        match peer.ss_family as libc::c_int {
            libc::AF_INET => {
                let addr = *(&peer as *const _ as *const libc::sockaddr_in);
                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                    u16::from_be(addr.sin_port),
                ))
            }
            libc::AF_INET6 => {
                let addr = *(&peer as *const _ as *const libc::sockaddr_in6);
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr),
                    u16::from_be(addr.sin6_port),
                    addr.sin6_flowinfo,
                    addr.sin6_scope_id,
                ))
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid peer address",
                ));
            }
        }
    };
    let destination = unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        let mut destination = None;
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_PKTINFO {
                let info = libc::CMSG_DATA(cmsg).cast::<libc::in_pktinfo>();
                destination = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    (*info).ipi_addr.s_addr,
                ))));
                break;
            }
            if (*cmsg).cmsg_level == libc::IPPROTO_IPV6 && (*cmsg).cmsg_type == libc::IPV6_PKTINFO {
                let info = libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>();
                destination = Some(IpAddr::V6(std::net::Ipv6Addr::from(
                    (*info).ipi6_addr.s6_addr,
                )));
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        destination
    };
    Ok((n as usize, peer, destination))
}

#[cfg(target_os = "linux")]
async fn send_to_with_source_async(
    socket: &UdpSocket,
    buf: &[u8],
    to: SocketAddr,
    source: IpAddr,
) -> std::io::Result<usize> {
    loop {
        socket.writable().await?;
        match socket.try_io(Interest::WRITABLE, || {
            send_to_with_source(socket.as_raw_fd(), buf, to, source)
        }) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(target_os = "linux")]
fn send_to_with_source(
    fd: RawFd,
    buf: &[u8],
    to: SocketAddr,
    source: IpAddr,
) -> std::io::Result<usize> {
    use std::mem::zeroed;
    let addr = SockAddr::from(to);
    let info_len = match source {
        IpAddr::V4(_) => std::mem::size_of::<libc::in_pktinfo>(),
        IpAddr::V6(_) => std::mem::size_of::<libc::in6_pktinfo>(),
    } as u32;
    let space = unsafe { libc::CMSG_SPACE(info_len) } as usize;
    let length = unsafe { libc::CMSG_LEN(info_len) } as usize;
    let mut control = AlignedControlBuffer([0u8; 64]);
    debug_assert!(space <= control.0.len());
    let cmsg = control.0.as_mut_ptr().cast::<libc::cmsghdr>();
    unsafe {
        (*cmsg).cmsg_len = length as _;
        match source {
            IpAddr::V4(source) => {
                let mut info: libc::in_pktinfo = zeroed();
                info.ipi_spec_dst.s_addr = u32::from(source).to_be();
                (*cmsg).cmsg_level = libc::IPPROTO_IP;
                (*cmsg).cmsg_type = libc::IP_PKTINFO;
                std::ptr::copy_nonoverlapping(
                    (&info as *const libc::in_pktinfo).cast::<u8>(),
                    libc::CMSG_DATA(cmsg),
                    std::mem::size_of::<libc::in_pktinfo>(),
                );
            }
            IpAddr::V6(source) => {
                let info = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: source.octets(),
                    },
                    ipi6_ifindex: 0,
                };
                (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                std::ptr::copy_nonoverlapping(
                    (&info as *const libc::in6_pktinfo).cast::<u8>(),
                    libc::CMSG_DATA(cmsg),
                    std::mem::size_of::<libc::in6_pktinfo>(),
                );
            }
        }
    }
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr().cast_mut().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = addr.as_ptr().cast_mut().cast();
    msg.msg_namelen = addr.len();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
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

    #[tokio::test]
    async fn malformed_direct_datagram_is_packet_scoped() {
        let receiver = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("receiver should bind");
        let sender = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("sender should bind");
        sender
            .connect(
                receiver
                    .local_addr()
                    .expect("receiver should have an address"),
            )
            .await
            .expect("sender should connect");

        let transport = UdpTransport::new(receiver);
        sender
            .send(&[0x00, 0x01, 0x02])
            .await
            .expect("malformed datagram should send");

        let mut buf = [0u8; 512];
        let err = transport
            .read_message_classified(&mut buf)
            .await
            .expect_err("malformed DNS datagram should fail decoding");

        assert!(matches!(&err, UdpReadError::InvalidDatagram(_)));
        assert!(!err.should_backoff());
    }

    #[test]
    fn socks5_response_source_rejects_wrong_upstream() {
        let expected = TargetAddr::Ip("8.8.8.8:53".parse().unwrap());
        let correct = TargetAddr::Ip("8.8.8.8:53".parse().unwrap());
        let wrong_ip = TargetAddr::Ip("1.1.1.1:53".parse().unwrap());
        let wrong_port = TargetAddr::Ip("8.8.8.8:5353".parse().unwrap());

        assert!(response_source_matches(&expected, &correct));
        assert!(!response_source_matches(&expected, &wrong_ip));
        assert!(!response_source_matches(&expected, &wrong_port));

        let expected_domain = TargetAddr::Domain("dns.example".to_string(), 53);
        assert!(response_source_matches(
            &expected_domain,
            &TargetAddr::Ip("192.0.2.1:53".parse().unwrap())
        ));
        assert!(!response_source_matches(
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

    #[tokio::test]
    async fn new_socks5_authenticates_udp_associate_with_password() {
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

        let _transport = UdpTransport::new_socks5(
            DialTarget::new(
                Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                "dns.google".to_string(),
                53,
            ),
            SocketOptions::default(),
            Socks5Opt {
                username: Some("user".to_string()),
                password: Some("password".to_string()),
                socket_addr: proxy_addr,
            },
        )
        .await
        .expect("authenticated SOCKS5 UDP association should be established");

        proxy.await.expect("proxy task should complete");
    }
}
