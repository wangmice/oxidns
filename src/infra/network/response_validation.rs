// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared DNS request/response association validation.

use crate::infra::error::{DnsError, Result};
use crate::proto::{Message, MessageType};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsResponseIdPolicy {
    MatchRequest,
    Exact(u16),
}

#[inline]
pub(crate) fn validate_dns_response(
    request: &Message,
    response: &Message,
    id_policy: DnsResponseIdPolicy,
) -> Result<()> {
    let expected_id = match id_policy {
        DnsResponseIdPolicy::MatchRequest => request.id(),
        DnsResponseIdPolicy::Exact(id) => id,
    };

    if response.id() != expected_id {
        return Err(DnsError::protocol(format!(
            "DNS response ID mismatch: expected {}, got {}",
            expected_id,
            response.id()
        )));
    }

    if response.message_type() != MessageType::Response {
        return Err(DnsError::protocol(
            "received DNS query-shaped message as response",
        ));
    }

    if response.opcode() != request.opcode() {
        return Err(DnsError::protocol(format!(
            "DNS response opcode mismatch: expected {:?}, got {:?}",
            request.opcode(),
            response.opcode()
        )));
    }

    if response.questions() != request.questions() {
        return Err(DnsError::protocol(
            "DNS response question does not match request",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{DNSClass, Name, Opcode, Question, RecordType};

    fn query(id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.set_message_type(MessageType::Query);
        message.set_opcode(Opcode::Query);
        message.add_question(Question::new(
            Name::from_ascii("example.com.").expect("query name should parse"),
            RecordType::A,
            DNSClass::IN,
        ));
        message
    }

    fn response_for(request: &Message, id: u16) -> Message {
        let mut response = request.clone();
        response.set_id(id);
        response.set_message_type(MessageType::Response);
        response
    }

    #[test]
    fn accepts_matching_response_with_request_id() {
        let request = query(42);
        let response = response_for(&request, 42);

        validate_dns_response(&request, &response, DnsResponseIdPolicy::MatchRequest)
            .expect("matching response should be accepted");
    }

    #[test]
    fn accepts_matching_response_with_exact_wire_id() {
        let request = query(42);
        let response = response_for(&request, 0);

        validate_dns_response(&request, &response, DnsResponseIdPolicy::Exact(0))
            .expect("matching zero wire ID should be accepted");
    }

    #[test]
    fn rejects_wrong_id() {
        let request = query(42);
        let response = response_for(&request, 7);

        let err = validate_dns_response(&request, &response, DnsResponseIdPolicy::Exact(0))
            .expect_err("wrong wire ID should be rejected");

        assert!(err.to_string().contains("DNS response ID mismatch"));
    }

    #[test]
    fn rejects_query_shaped_message() {
        let request = query(42);
        let response = request.clone();

        let err = validate_dns_response(&request, &response, DnsResponseIdPolicy::MatchRequest)
            .expect_err("query-shaped response should be rejected");

        assert!(err.to_string().contains("query-shaped"));
    }

    #[test]
    fn rejects_opcode_mismatch() {
        let request = query(42);
        let mut response = response_for(&request, 42);
        response.set_opcode(Opcode::Status);

        let err = validate_dns_response(&request, &response, DnsResponseIdPolicy::MatchRequest)
            .expect_err("opcode mismatch should be rejected");

        assert!(err.to_string().contains("opcode mismatch"));
    }

    #[test]
    fn rejects_question_mismatch() {
        let request = query(42);
        let mut response = response_for(&request, 42);
        response.questions_mut().clear();
        response.add_question(Question::new(
            Name::from_ascii("other.example.").expect("response name should parse"),
            RecordType::A,
            DNSClass::IN,
        ));

        let err = validate_dns_response(&request, &response, DnsResponseIdPolicy::MatchRequest)
            .expect_err("question mismatch should be rejected");

        assert!(err.to_string().contains("question does not match"));
    }

    #[test]
    fn rejects_question_count_mismatch() {
        let request = query(42);
        let mut response = response_for(&request, 42);
        response.questions_mut().clear();

        let err = validate_dns_response(&request, &response, DnsResponseIdPolicy::MatchRequest)
            .expect_err("question count mismatch should be rejected");

        assert!(err.to_string().contains("question does not match"));
    }

    #[test]
    fn rejects_question_type_mismatch() {
        let request = query(42);
        let mut response = response_for(&request, 42);
        response.questions_mut().clear();
        response.add_question(Question::new(
            Name::from_ascii("example.com.").expect("response name should parse"),
            RecordType::AAAA,
            DNSClass::IN,
        ));

        let err = validate_dns_response(&request, &response, DnsResponseIdPolicy::MatchRequest)
            .expect_err("question type mismatch should be rejected");

        assert!(err.to_string().contains("question does not match"));
    }

    #[test]
    fn rejects_question_class_mismatch() {
        let request = query(42);
        let mut response = response_for(&request, 42);
        response.questions_mut().clear();
        response.add_question(Question::new(
            Name::from_ascii("example.com.").expect("response name should parse"),
            RecordType::A,
            DNSClass::CH,
        ));

        let err = validate_dns_response(&request, &response, DnsResponseIdPolicy::MatchRequest)
            .expect_err("question class mismatch should be rejected");

        assert!(err.to_string().contains("question does not match"));
    }
}
