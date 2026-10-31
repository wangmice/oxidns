// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! UDP nameserver client.

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tracing::{debug, trace};

use super::super::endpoint::NameserverConfig;
use super::tcp::query_tcp_config;
use super::{NameserverClient, effective_deadline};
use crate::infra::error::Result;
use crate::infra::network::deadline::{DeadlineOutcome, QueryDeadline};
use crate::infra::network::dial::{SocketOptions, UdpDialOptions, connect_udp};
use crate::infra::network::response_validation::{DnsResponseIdPolicy, validate_dns_response};
use crate::infra::network::transport::udp::{UDP_MAX_DATAGRAM_SIZE, UdpReadError, UdpTransport};
use crate::proto::Message;

#[derive(Debug)]
pub(super) struct UdpNameserverClient {
    config: NameserverConfig,
}

impl UdpNameserverClient {
    pub(super) fn new(config: NameserverConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NameserverClient for UdpNameserverClient {
    async fn query(&self, request: Message, deadline: QueryDeadline) -> Result<Message> {
        query_udp_config(
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

async fn query_udp_config(
    config: &NameserverConfig,
    request: Message,
    deadline: QueryDeadline,
) -> Result<Message> {
    let socket = match deadline
        .run(connect_udp(UdpDialOptions::new(
            config.target(),
            SocketOptions::default(),
        )))
        .await
    {
        DeadlineOutcome::Completed(result) => result?,
        DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
    };
    let socket = UdpSocket::from_std(socket)?;
    let transport = UdpTransport::new(socket);
    let query_id = request.id();

    match deadline
        .run(transport.write_message_with_id(&request, query_id))
        .await
    {
        DeadlineOutcome::Completed(result) => result?,
        DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
    }

    let response =
        receive_matching_udp_response(&transport, &request, deadline, config.label.as_str())
            .await?;
    if response.truncated() {
        debug!(
            server = %config.label,
            "Nameserver UDP response truncated, falling back to TCP"
        );
        return query_tcp_config(config, request, deadline).await;
    }
    Ok(response)
}

async fn receive_matching_udp_response(
    transport: &UdpTransport,
    request: &Message,
    deadline: QueryDeadline,
    server: &str,
) -> Result<Message> {
    let mut buf = vec![0u8; UDP_MAX_DATAGRAM_SIZE];
    match deadline
        .run(async {
            loop {
                match transport.read_message_classified(&mut buf).await {
                    Ok(response) => {
                        if let Err(err) = validate_dns_response(
                            request,
                            &response,
                            DnsResponseIdPolicy::MatchRequest,
                        ) {
                            trace!(
                                server = %server,
                                err = %err,
                                "Ignoring unrelated UDP nameserver response"
                            );
                            continue;
                        }
                        return Ok(response);
                    }
                    Err(UdpReadError::InvalidDatagram(err)) => {
                        trace!(
                            server = %server,
                            err = %err,
                            "Ignoring invalid UDP nameserver response datagram"
                        );
                    }
                    Err(UdpReadError::Receive(err)) => return Err(err),
                }
            }
        })
        .await
    {
        DeadlineOutcome::Completed(result) => result,
        DeadlineOutcome::Expired => Err(deadline.timeout_error()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::net::UdpSocket;

    use super::*;
    use crate::infra::clock::AppClock;
    use crate::proto::{DNSClass, MessageType, Name, Opcode, Question, RecordType};

    fn make_query(id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.set_opcode(Opcode::Query);
        message.add_question(Question::new(
            Name::from_ascii("example.com.").expect("query name should parse"),
            RecordType::A,
            DNSClass::IN,
        ));
        message
    }

    fn response_for(request: &Message) -> Message {
        let mut response = request.clone();
        response.set_message_type(MessageType::Response);
        response
    }

    async fn connected_udp_pair() -> (UdpTransport, UdpSocket) {
        let receiver = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("receiver should bind");
        let sender = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
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
        (UdpTransport::new(receiver), sender)
    }

    #[tokio::test]
    async fn one_shot_udp_ignores_malformed_datagram_before_valid_response() {
        AppClock::start();
        let request = make_query(0x1234);
        let valid = response_for(&request)
            .to_bytes()
            .expect("valid response should encode");
        let (transport, sender) = connected_udp_pair().await;

        sender
            .send(&[0x12, 0x34, 0x80])
            .await
            .expect("malformed datagram should send");
        let valid_sender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            sender
                .send(&valid)
                .await
                .expect("valid response should send");
        });

        let response = receive_matching_udp_response(
            &transport,
            &request,
            QueryDeadline::new(Duration::from_secs(1)),
            "test",
        )
        .await
        .expect("valid response after malformed datagram should succeed");
        valid_sender
            .await
            .expect("valid response sender should finish");

        assert_eq!(response.id(), request.id());
        assert_eq!(response.questions(), request.questions());
    }

    #[tokio::test]
    async fn one_shot_udp_ignores_unrelated_responses_before_valid_response() {
        AppClock::start();
        let request = make_query(0x4321);
        let (transport, sender) = connected_udp_pair().await;

        let mut wrong_id = response_for(&request);
        wrong_id.set_id(request.id().wrapping_add(1));
        wrong_id.set_truncated(true);

        let mut wrong_question = response_for(&request);
        wrong_question.questions_mut().clear();
        wrong_question.add_question(Question::new(
            Name::from_ascii("other.example.").expect("question name should parse"),
            RecordType::A,
            DNSClass::IN,
        ));

        let mut wrong_opcode = response_for(&request);
        wrong_opcode.set_opcode(Opcode::Status);

        for response in [&wrong_id, &wrong_question, &wrong_opcode] {
            sender
                .send(&response.to_bytes().expect("test response should encode"))
                .await
                .expect("unrelated response should send");
        }
        let valid = response_for(&request)
            .to_bytes()
            .expect("valid response should encode");
        let valid_sender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            sender
                .send(&valid)
                .await
                .expect("valid response should send");
        });

        let response = receive_matching_udp_response(
            &transport,
            &request,
            QueryDeadline::new(Duration::from_secs(1)),
            "test",
        )
        .await
        .expect("matching response should survive unrelated datagrams");
        valid_sender
            .await
            .expect("valid response sender should finish");

        assert_eq!(response.id(), request.id());
        assert!(!response.truncated());
        assert_eq!(response.opcode(), request.opcode());
        assert_eq!(response.questions(), request.questions());
    }

    #[tokio::test]
    async fn one_shot_udp_invalid_datagrams_do_not_extend_deadline() {
        AppClock::start();
        let request = make_query(7);
        let (transport, sender) = connected_udp_pair().await;

        let flood = tokio::spawn(async move {
            for _ in 0..100 {
                if sender.send(&[0xDE, 0xAD, 0xBE]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let err = tokio::time::timeout(
            Duration::from_millis(250),
            receive_matching_udp_response(
                &transport,
                &request,
                QueryDeadline::new(Duration::from_millis(50)),
                "test",
            ),
        )
        .await
        .expect("invalid datagrams must not extend the absolute query deadline")
        .expect_err("invalid datagrams only should end in the original timeout");

        flood.abort();
        assert!(err.to_string().contains("DNS query timeout"));
    }
}
