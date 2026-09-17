// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::io;
use std::net::SocketAddr;

use fast_socks5::util::target_addr::TargetAddr;
use tokio::net::UdpSocket;

use crate::infra::error::{DnsError, Result};
use crate::infra::network::buffer_pool::wire_buffer_pool;
use crate::infra::network::dial::{DialTarget, SocketOptions};
use crate::infra::network::proxy::Socks5Opt;
use crate::infra::network::transport::socks5_udp::{Socks5UdpAssociation, response_source_matches};
use crate::infra::network::udp_socket::{UdpReplySocket, UdpReplyTarget};
use crate::proto::Message;

pub(crate) const UDP_MAX_DATAGRAM_SIZE: usize = u16::MAX as usize;

/// Connected UDP client transport for DNS messages.
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpTransportSocket,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidUdpDatagram;

#[derive(Debug)]
pub(crate) enum UdpWriteError {
    Query(DnsError),
    Connection(DnsError),
}

impl UdpWriteError {
    #[inline]
    pub(crate) fn should_close_connection(&self) -> bool {
        matches!(self, Self::Connection(_))
    }

    #[inline]
    pub(crate) fn into_dns_error(self) -> DnsError {
        match self {
            Self::Query(err) | Self::Connection(err) => err,
        }
    }
}

impl std::fmt::Display for UdpWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Query(err) | Self::Connection(err) => write!(f, "{err}"),
        }
    }
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

    /// Serialize and send a DNS message while overriding the wire ID.
    #[inline]
    pub async fn write_message_with_id(&self, msg: &Message, id: u16) -> Result<()> {
        self.write_message_with_id_classified(msg, id)
            .await
            .map_err(UdpWriteError::into_dns_error)
    }

    /// Serialize and send a DNS message while preserving whether the failure is
    /// local to this query or proves that the shared UDP connection is invalid.
    #[inline]
    #[hotpath::measure]
    pub(crate) async fn write_message_with_id_classified(
        &self,
        msg: &Message,
        id: u16,
    ) -> std::result::Result<(), UdpWriteError> {
        let mut bytes = wire_buffer_pool().acquire();
        msg.append_to_with_id(id, &mut bytes)
            .map_err(|e| UdpWriteError::Query(DnsError::from(e)))?;

        let n = match &self.socket {
            UdpTransportSocket::Direct(socket) => socket
                .send(&bytes)
                .await
                .map_err(|e| classify_udp_send_error("UDP send error", e, false))?,
            UdpTransportSocket::Socks5 {
                association,
                target,
            } => association.send_to(&bytes, target).await.map_err(|e| {
                classify_udp_send_error("SOCKS5 UDP send error", e, association.is_control_closed())
            })?,
        };

        if n != bytes.len() {
            return Err(UdpWriteError::Connection(DnsError::protocol(format!(
                "Partial UDP send: sent {} of {} bytes",
                n,
                bytes.len()
            ))));
        }
        Ok(())
    }
}

#[inline]
fn classify_udp_send_error(
    context: &'static str,
    error: io::Error,
    connection_invalid: bool,
) -> UdpWriteError {
    // Connected UDP can surface per-datagram failures (for example an
    // asynchronous ICMP error or local buffer pressure) on send. Those do not
    // prove that the shared socket is unusable and must not cancel unrelated
    // in-flight queries. Retire only when the local socket/association is
    // known to be invalid.
    let should_close = connection_invalid
        || matches!(
            error.kind(),
            io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe
        );
    let error = DnsError::protocol(format!("{context}: {error}"));
    if should_close {
        UdpWriteError::Connection(error)
    } else {
        UdpWriteError::Query(error)
    }
}

/// Server transport that preserves the destination of each incoming query.
#[derive(Debug)]
pub(crate) struct UdpServerTransport {
    socket: UdpReplySocket,
}

impl UdpServerTransport {
    pub fn new(socket: UdpSocket) -> Result<Self> {
        Ok(Self {
            socket: UdpReplySocket::new(socket)?,
        })
    }

    /// Receive one raw UDP datagram from any peer without decoding DNS.
    ///
    /// Keeping socket draining separate from DNS parsing lets the server drop
    /// datagrams at the admission boundary before paying parser CPU or
    /// temporary allocation costs while already at capacity.
    #[inline]
    #[hotpath::measure]
    pub(crate) async fn read_datagram_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, UdpReplyTarget)> {
        self.socket
            .recv_from(buf)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to recv_from UDP: {e}")))
    }

    /// Decode a previously received UDP datagram as a DNS message.
    #[inline]
    pub(crate) fn parse_datagram(buf: &[u8]) -> std::result::Result<Message, InvalidUdpDatagram> {
        Message::from_bytes(buf).map_err(|_| InvalidUdpDatagram)
    }

    #[inline]
    #[hotpath::measure]
    pub async fn write_message_to(
        &self,
        msg: &Message,
        to: UdpReplyTarget,
        max_payload: u16,
    ) -> Result<()> {
        let max_payload = usize::from(max_payload);
        let mut bytes = wire_buffer_pool().acquire();
        msg.append_to_with_limit(max_payload, &mut bytes)?;
        let n = self
            .socket
            .send_to(&bytes, to)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to send_to UDP: {}", e)))?;
        if n != bytes.len() {
            return Err(DnsError::protocol(format!(
                "Partial UDP send_to: sent {} of {} bytes",
                n,
                bytes.len()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::proto::{A, DNSClass, MessageType, Name, Question, RData, Record, RecordType};

    #[tokio::test]
    async fn udp_server_transport_classifies_malformed_dns_as_invalid_datagram() {
        let receiver = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("receiver should bind");
        let receiver_addr = receiver.local_addr().expect("receiver address");
        let transport = UdpServerTransport::new(receiver).expect("server transport");

        let sender = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("sender should bind");
        sender
            .send_to(&[0xDE, 0xAD, 0xBE, 0xEF], receiver_addr)
            .await
            .expect("malformed datagram should send");

        let mut buf = [0u8; 512];
        let (n, _) = transport
            .read_datagram_from(&mut buf)
            .await
            .expect("raw malformed datagram must still be drained from the socket");
        assert_eq!(&buf[..n], &[0xDE, 0xAD, 0xBE, 0xEF]);

        UdpServerTransport::parse_datagram(&buf[..n])
            .expect_err("malformed DNS datagram must be rejected when parsed");
    }

    #[tokio::test]
    async fn direct_udp_transport_receives_dns_datagram_larger_than_legacy_buffer() {
        let receiver = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("receiver should bind");
        let sender = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("sender should bind");
        let receiver_addr = receiver.local_addr().expect("receiver address");
        let sender_addr = sender.local_addr().expect("sender address");
        receiver
            .connect(sender_addr)
            .await
            .expect("receiver should connect");
        sender
            .connect(receiver_addr)
            .await
            .expect("sender should connect");

        let mut response = Message::new();
        response.set_id(0xCAFE);
        response.set_message_type(MessageType::Response);
        let name = Name::from_ascii("large.example.com.").unwrap();
        response.add_question(Question::new(name.clone(), RecordType::A, DNSClass::IN));
        for index in 0..700u16 {
            response.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, (index % 250 + 1) as u8))),
            ));
        }

        let wire = response.to_bytes().expect("large response should encode");
        assert!(
            wire.len() > 8_196,
            "test response must exceed legacy buffer"
        );
        assert!(wire.len() < UDP_MAX_DATAGRAM_SIZE);
        sender
            .send(&wire)
            .await
            .expect("large UDP datagram should send");

        let transport = UdpTransport::new(receiver);
        let mut buf = vec![0u8; UDP_MAX_DATAGRAM_SIZE];
        let decoded = transport
            .read_message(&mut buf)
            .await
            .expect("large DNS datagram should not be locally truncated");

        assert_eq!(decoded.id(), response.id());
        assert_eq!(decoded.answers().len(), response.answers().len());
    }

    #[test]
    fn udp_send_errors_are_query_local_unless_connection_is_known_invalid() {
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::TimedOut,
            io::ErrorKind::InvalidInput,
        ] {
            let error = classify_udp_send_error("UDP send error", io::Error::from(kind), false);
            assert!(
                !error.should_close_connection(),
                "{kind:?} must not cancel unrelated pending UDP queries"
            );
        }

        for kind in [io::ErrorKind::NotConnected, io::ErrorKind::BrokenPipe] {
            let error = classify_udp_send_error("UDP send error", io::Error::from(kind), false);
            assert!(
                error.should_close_connection(),
                "{kind:?} must retire the socket"
            );
        }

        let error = classify_udp_send_error(
            "SOCKS5 UDP send error",
            io::Error::from(io::ErrorKind::ConnectionAborted),
            true,
        );
        assert!(error.should_close_connection());
    }
}
