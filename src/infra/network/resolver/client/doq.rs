// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! DNS-over-QUIC nameserver client.

use async_trait::async_trait;

use super::super::endpoint::NameserverConfig;
use super::{NameserverClient, effective_deadline};
use crate::infra::error::{DnsError, Result};
#[cfg(feature = "resolver-doq")]
use crate::infra::network::deadline::DeadlineOutcome;
use crate::infra::network::deadline::QueryDeadline;
#[cfg(feature = "resolver-doq")]
use crate::infra::network::dial::{
    QuicDialOptions, SocketOptions, UdpDialOptions, connect_quic, connect_udp,
};
#[cfg(feature = "resolver-doq")]
use crate::infra::network::transport::quic::{
    QuicReadError, QuicTransport, QuicTransportReader, QuicTransportWriter,
};
use crate::proto::Message;

#[cfg(feature = "resolver-doq")]
const DOQ_PROTOCOL_ERROR: u32 = 0x2;
#[cfg(feature = "resolver-doq")]
const DOQ_REQUEST_CANCELLED: u32 = 0x3;

#[cfg(feature = "resolver-doq")]
struct DoqQueryStream {
    reader: QuicTransportReader,
    writer: QuicTransportWriter,
    send_finished: bool,
    completed: bool,
}

#[cfg(feature = "resolver-doq")]
impl DoqQueryStream {
    fn new(reader: QuicTransportReader, writer: QuicTransportWriter) -> Self {
        Self {
            reader,
            writer,
            send_finished: false,
            completed: false,
        }
    }
}

#[cfg(feature = "resolver-doq")]
impl Drop for DoqQueryStream {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if !self.send_finished {
            self.writer.reset(DOQ_REQUEST_CANCELLED);
        }
        self.reader.stop(DOQ_REQUEST_CANCELLED);
    }
}

#[derive(Debug)]
pub(super) struct DoqNameserverClient {
    config: NameserverConfig,
}

impl DoqNameserverClient {
    pub(super) fn new(config: NameserverConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NameserverClient for DoqNameserverClient {
    async fn query(&self, request: Message, deadline: QueryDeadline) -> Result<Message> {
        query_doq_config(
            &self.config,
            request,
            effective_deadline(deadline, self.config.timeout),
        )
        .await
    }

    fn label(&self) -> &str {
        self.config.label.as_str()
    }
}

#[cfg(feature = "resolver-doq")]
async fn query_doq_config(
    config: &NameserverConfig,
    request: Message,
    deadline: QueryDeadline,
) -> Result<Message> {
    let socket = connect_udp(UdpDialOptions::new(
        config.target(),
        SocketOptions::default(),
    ))?;
    let quic_conn = connect_quic(
        socket,
        QuicDialOptions::new(
            config.target(),
            false,
            deadline
                .remaining()
                .ok_or_else(|| deadline.timeout_error())?,
            config.timeout,
            vec![b"doq".to_vec()],
        ),
    )
    .await?;
    let transport = QuicTransport::new(quic_conn);
    let (reader, writer) = match deadline.run(transport.open_bi()).await {
        DeadlineOutcome::Completed(result) => result?,
        DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
    };
    let mut stream = DoqQueryStream::new(reader, writer);
    let query_id = request.id();
    match deadline.run(stream.writer.write_message(&request)).await {
        DeadlineOutcome::Completed(result) => result?,
        DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
    }
    stream.writer.finish()?;
    stream.send_finished = true;

    let mut response = match deadline.run(stream.reader.read_message_doq()).await {
        DeadlineOutcome::Completed(Ok(response)) => response,
        DeadlineOutcome::Completed(Err(QuicReadError::Protocol(message))) => {
            transport.close_with_code(DOQ_PROTOCOL_ERROR, b"DoQ protocol error");
            return Err(DnsError::protocol(message));
        }
        DeadlineOutcome::Completed(Err(e)) => {
            return Err(DnsError::protocol(e.to_string()));
        }
        DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
    };
    stream.completed = true;
    response.set_id(query_id);
    transport.close(b"resolver query complete");
    Ok(response)
}

#[cfg(not(feature = "resolver-doq"))]
async fn query_doq_config(
    _config: &NameserverConfig,
    _request: Message,
    _deadline: QueryDeadline,
) -> Result<Message> {
    Err(DnsError::plugin(
        "nameserver DoQ is not compiled into this build; rebuild with --features resolver-doq",
    ))
}
