// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

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
                "Partial UDP send: sent {} of {} bytes",
                n,
                bytes.len()
            )));
        }
        Ok(())
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

    /// Receive one UDP datagram from any peer and decode it as DNS message.
    #[inline]
    #[hotpath::measure]
    pub async fn read_message_from(&self, buf: &mut [u8]) -> Result<(Message, UdpReplyTarget)> {
        let (n, addr) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to recv_from UDP: {}", e)))?;

        let msg = Message::from_bytes(&buf[..n]).map_err(|e| {
            DnsError::protocol(format!("Failed to parse DNS message from UDP: {}", e))
        })?;
        Ok((msg, addr))
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
