// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later
use quinn::{
    Connection, ConnectionError, ReadError, ReadExactError, RecvStream, SendStream, VarInt,
    WriteError,
};

use crate::infra::error::{DnsError, Result};
use crate::infra::network::buffer_pool::wire_buffer_pool;
use crate::proto::Message;

/// QUIC connection transport that can accept or open bidirectional streams
/// and yield reader/writer wrappers compatible with TCP transport interface.
pub struct QuicTransport {
    conn: Connection,
}

impl QuicTransport {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    /// Accept a bidirectional stream from the peer (server-side).
    /// Returns reader and writer wrappers for framed DNS messages.
    #[inline]
    pub async fn accept_bi(&self) -> Result<(QuicTransportReader, QuicTransportWriter)> {
        match self.conn.accept_bi().await {
            Ok((send, recv)) => Ok((QuicTransportReader { recv }, QuicTransportWriter { send })),
            Err(e) => Err(DnsError::protocol(format!(
                "Failed to accept QUIC bidirectional stream: {}",
                e
            ))),
        }
    }

    /// Open a bidirectional stream to the peer (client-side).
    /// Returns reader and writer wrappers for framed DNS messages.
    #[inline]
    pub async fn open_bi(&self) -> Result<(QuicTransportReader, QuicTransportWriter)> {
        match self.conn.open_bi().await {
            Ok((send, recv)) => Ok((QuicTransportReader { recv }, QuicTransportWriter { send })),
            Err(e) => Err(DnsError::protocol(format!(
                "Failed to open QUIC bidirectional stream: {}",
                e
            ))),
        }
    }

    /// Close the underlying QUIC connection gracefully.
    #[inline]
    pub fn close(&self, reason: &[u8]) {
        self.close_with_code(0, reason);
    }

    #[inline]
    pub(crate) fn close_with_code(&self, code: u32, reason: &[u8]) {
        self.conn.close(VarInt::from_u32(code), reason);
    }

    #[inline]
    pub async fn closed(&self) -> ConnectionError {
        self.conn.closed().await
    }
}

/// Writer wrapper over a QUIC SendStream that frames DNS messages
/// with 2-byte big-endian length prefix before writing.
pub struct QuicTransportWriter {
    send: SendStream,
}

impl QuicTransportWriter {
    /// Write a single DNS message as a length-prefixed frame.
    #[inline]
    #[hotpath::measure]
    pub async fn write_message(&mut self, msg: &Message) -> Result<()> {
        let mut write_buf = wire_buffer_pool().acquire();
        encode_quic_dns_frame(msg, write_buf.as_mut_vec())?;
        self.send
            .write_all(write_buf.as_slice())
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to write QUIC DNS frame: {e}")))?;
        Ok(())
    }

    /// Write one DoQ message while preserving QUIC write error semantics.
    ///
    /// In particular, RFC 9250 treats a server-to-client STOP_SENDING as a
    /// fatal DoQ protocol error, so callers must be able to distinguish
    /// `WriteError::Stopped` from ordinary stream or connection failures.
    #[inline]
    #[hotpath::measure]
    pub(crate) async fn write_message_doq(
        &mut self,
        msg: &Message,
    ) -> std::result::Result<(), QuicWriteError> {
        let mut write_buf = wire_buffer_pool().acquire();
        encode_quic_dns_frame(msg, write_buf.as_mut_vec())
            .map_err(|e| QuicWriteError::Encode(e.to_string()))?;
        self.send
            .write_all(write_buf.as_slice())
            .await
            .map_err(map_write_error)
    }

    /// Half-close the send stream (finish) to signal end of request.
    #[inline]
    pub fn finish(&mut self) -> Result<()> {
        self.send
            .finish()
            .map_err(|e| DnsError::protocol(format!("Failed to finish QUIC send stream: {}", e)))
    }

    #[inline]
    pub(crate) fn reset(&mut self, code: u32) {
        let _ = self.send.reset(VarInt::from_u32(code));
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum QuicWriteError {
    #[error("QUIC send stream stopped by peer with application code {0}")]
    Stopped(VarInt),
    #[error("QUIC connection lost: {0}")]
    ConnectionLost(ConnectionError),
    #[error("QUIC stream write error: {0}")]
    Stream(String),
    #[error("failed to encode DoQ message: {0}")]
    Encode(String),
}

fn encode_quic_dns_frame(msg: &Message, write_buf: &mut Vec<u8>) -> Result<()> {
    write_buf.extend_from_slice(&[0, 0]);

    // RFC 9250: the DNS Message ID of every DoQ message MUST be 0.
    msg.append_to_with_id(0, write_buf)?;

    let body_len = write_buf.len() - 2;
    let body_len = u16::try_from(body_len)
        .map_err(|_| DnsError::protocol("DNS message exceeds the 65535-byte QUIC framing limit"))?;
    write_buf[..2].copy_from_slice(&body_len.to_be_bytes());
    Ok(())
}

fn map_write_error(err: WriteError) -> QuicWriteError {
    match err {
        WriteError::Stopped(code) => QuicWriteError::Stopped(code),
        WriteError::ConnectionLost(err) => QuicWriteError::ConnectionLost(err),
        other => QuicWriteError::Stream(other.to_string()),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum QuicReadError {
    #[error("QUIC stream reset by peer with application code {0}")]
    StreamReset(VarInt),
    #[error("QUIC connection lost: {0}")]
    ConnectionLost(ConnectionError),
    #[error("DoQ protocol error: {0}")]
    Protocol(String),
    #[error("QUIC stream read error: {0}")]
    Stream(String),
}

/// Reader wrapper over a QUIC RecvStream that reads one framed
/// DNS message (2-byte big-endian length + body) and decodes it.
pub struct QuicTransportReader {
    recv: RecvStream,
}
impl QuicTransportReader {
    #[inline]
    #[hotpath::measure]
    pub async fn read_message(&mut self) -> Result<Message> {
        let mut len_prefix = [0u8; 2];
        self.recv
            .read_exact(&mut len_prefix)
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to read QUIC length prefix: {e}")))?;

        let msg_len = u16::from_be_bytes(len_prefix) as usize;
        if msg_len == 0 {
            return Err(DnsError::protocol(
                "Invalid zero-length DNS message over QUIC",
            ));
        }

        let mut read_buf = wire_buffer_pool().acquire();
        read_buf.resize(msg_len, 0);
        self.recv
            .read_exact(&mut read_buf[..msg_len])
            .await
            .map_err(|e| DnsError::protocol(format!("Failed to read QUIC DNS body: {e}")))?;

        Message::from_bytes(&read_buf[..msg_len])
            .map_err(|e| DnsError::protocol(format!("Invalid DNS message over QUIC: {e}")))
    }

    /// Read exactly one DoQ DNS message and require the peer to finish the
    /// stream. Preserves stream resets separately from connection/protocol
    /// failures so callers can avoid tearing down a healthy multiplexed
    /// QUIC connection.
    pub(crate) async fn read_message_doq(&mut self) -> std::result::Result<Message, QuicReadError> {
        let mut len_prefix = [0u8; 2];
        self.read_exact_doq(&mut len_prefix, "length prefix")
            .await?;

        let msg_len = u16::from_be_bytes(len_prefix) as usize;
        if msg_len == 0 {
            return Err(QuicReadError::Protocol(
                "received zero-length DNS message".to_string(),
            ));
        }

        let mut read_buf = wire_buffer_pool().acquire();
        read_buf.resize(msg_len, 0);
        self.read_exact_doq(&mut read_buf[..msg_len], "DNS body")
            .await?;

        let message = Message::from_bytes(&read_buf[..msg_len])
            .map_err(|e| QuicReadError::Protocol(format!("invalid DNS message: {e}")))?;
        drop(read_buf);
        if message.id() != 0 {
            return Err(QuicReadError::Protocol(format!(
                "received non-zero DNS message ID {}",
                message.id()
            )));
        }

        let mut extra = [0u8; 1];
        match self.recv.read(&mut extra).await {
            Ok(None) => Ok(message),
            Ok(Some(_)) => Err(QuicReadError::Protocol(
                "received more than one DNS message on a DoQ stream".to_string(),
            )),
            Err(err) => Err(map_read_error(err)),
        }
    }

    #[inline]
    pub(crate) fn stop(&mut self, code: u32) {
        let _ = self.recv.stop(VarInt::from_u32(code));
    }

    async fn read_exact_doq(
        &mut self,
        buf: &mut [u8],
        what: &str,
    ) -> std::result::Result<(), QuicReadError> {
        match self.recv.read_exact(buf).await {
            Ok(()) => Ok(()),
            Err(ReadExactError::FinishedEarly(read)) => Err(QuicReadError::Protocol(format!(
                "stream finished before complete {what} ({read} bytes read)"
            ))),
            Err(ReadExactError::ReadError(err)) => Err(map_read_error(err)),
        }
    }
}

fn map_read_error(err: ReadError) -> QuicReadError {
    match err {
        ReadError::Reset(code) => QuicReadError::StreamReset(code),
        ReadError::ConnectionLost(err) => QuicReadError::ConnectionLost(err),
        other => QuicReadError::Stream(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doq_write_error_preserves_peer_stop_sending_code() {
        let code = VarInt::from_u32(0x1234);
        let error = map_write_error(WriteError::Stopped(code));

        match error {
            QuicWriteError::Stopped(actual) => assert_eq!(actual, code),
            other => panic!("expected stopped error, got {other:?}"),
        }
    }
}
