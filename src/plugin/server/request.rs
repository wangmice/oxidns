// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared DNS request lifecycle for server plugins.

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{Level, debug, event_enabled, warn};

use super::metrics::ServerMetrics;
use crate::core::context::DnsContext;
pub use crate::core::context::RequestMeta;
use crate::infra::network::ip::normalize_ipv4_mapped_socket_addr;
use crate::plugin::executor::{ExecStep, Executor};
use crate::proto::wire::WireHeader;
use crate::proto::{Edns, Message, MessageType, Opcode, Rcode};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum InboundDnsRequestDisposition {
    Accept,
    Drop,
    Respond(Rcode),
}

/// Classify an inbound request using only the fixed DNS wire header.
///
/// This rejects packet classes that do not require variable-length section
/// parsing, preventing oversized response packets, unsupported opcodes, and
/// invalid question counts from consuming full DNS parser CPU or allocations.
#[inline]
pub(crate) fn classify_inbound_dns_wire_header(
    request: &WireHeader,
) -> InboundDnsRequestDisposition {
    let header = request.header();
    if header.message_type() != MessageType::Query {
        return InboundDnsRequestDisposition::Drop;
    }

    if header.opcode() != Opcode::Query {
        return if request.additional_count() == 0 {
            InboundDnsRequestDisposition::Respond(Rcode::NotImp)
        } else {
            // Additional records may contain TSIG/SIG(0). Avoid emitting an
            // unauthenticated error without paying the full signature parser
            // cost on an already-invalid request.
            InboundDnsRequestDisposition::Drop
        };
    }

    if request.question_count() != 1 {
        return if request.additional_count() == 0 {
            InboundDnsRequestDisposition::Respond(Rcode::FormErr)
        } else {
            // Preserve the signed-request silent-drop policy for malformed
            // queries whose additional section has not been authenticated.
            InboundDnsRequestDisposition::Drop
        };
    }

    InboundDnsRequestDisposition::Accept
}

/// Build a constant-cost protocol error from the fixed DNS header only.
///
/// The response deliberately omits questions and EDNS because those sections
/// have not been parsed. UDP callers therefore send it with the legacy 512-byte
/// payload ceiling.
#[inline]
pub(crate) fn build_inbound_error_response_from_wire_header(
    request: &WireHeader,
    rcode: Rcode,
) -> Message {
    let header = request.header();
    let mut response = Message::new();
    response.set_id(header.id());
    response.set_message_type(MessageType::Response);
    response.set_opcode(header.opcode());
    if header.opcode() == Opcode::Query {
        response.set_recursion_desired(header.recursion_desired());
        response.set_checking_disabled(header.checking_disabled());
    }
    response.set_rcode(rcode);
    response.set_recursion_available(true);
    response
}

/// Finish inbound validation after the fixed wire header has already been
/// accepted. Only properties that require full section decoding remain.
#[inline]
pub(crate) fn classify_inbound_dns_request_after_wire_header(
    request: &Message,
) -> InboundDnsRequestDisposition {
    debug_assert_eq!(request.message_type(), MessageType::Query);
    debug_assert_eq!(request.opcode(), Opcode::Query);
    debug_assert_eq!(request.questions().len(), 1);

    if !request.signature().is_empty() {
        InboundDnsRequestDisposition::Drop
    } else {
        InboundDnsRequestDisposition::Accept
    }
}

#[derive(Debug)]
pub struct RequestHandle {
    pub entry_executor: Arc<dyn Executor>,
    /// Shared server metrics. `None` for internal/test handles that should not
    /// emit server-level metrics.
    pub(crate) metrics: Option<Arc<ServerMetrics>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RequestExit {
    Completed,
    Controlled,
    Failed,
}

#[derive(Debug)]
#[allow(unused)]
pub struct RequestResult {
    pub request: Message,
    pub response: Message,
    pub exit: RequestExit,
}

impl RequestHandle {
    #[hotpath::measure]
    pub async fn handle_request(
        &self,
        msg: Message,
        src_addr: SocketAddr,
        meta: RequestMeta,
    ) -> RequestResult {
        let metrics_start = self.metrics.as_ref().map(|m| m.on_request_start());

        let mut context = DnsContext::new(normalize_ipv4_mapped_socket_addr(src_addr), msg);
        self.apply_request_meta(&mut context, meta);

        if event_enabled!(Level::DEBUG) {
            debug!(
                "DNS request from {}, queries: {:?}, id: {}, edns: {:?}, nameservers: {:?}",
                &src_addr,
                context.request.questions(),
                context.request.id(),
                context.request.edns(),
                context.request.authorities()
            );
        }

        let exec_outcome = self
            .entry_executor
            .execute_with_next(&mut context, None)
            .await;
        let (mut response, exit) = match exec_outcome {
            Ok(step) => {
                let exit = match step {
                    ExecStep::Next => RequestExit::Completed,
                    ExecStep::Stop | ExecStep::Return => RequestExit::Controlled,
                };
                let response = context
                    .take_response()
                    .unwrap_or_else(|| self.build_empty_response(&context));
                (response, exit)
            }
            Err(e) => {
                warn!(
                    "Entry executor '{}' failed for source {} id {}: {}",
                    self.entry_executor.tag(),
                    src_addr,
                    context.request.id(),
                    e
                );
                (self.build_servfail_response(&context), RequestExit::Failed)
            }
        };

        Self::finalize_response(&context.request, &mut response);

        if event_enabled!(Level::DEBUG) {
            debug!(
                "Sending response to {}, exit: {:?}, queries: {:?}, id: {}, edns: {:?}, answers: {:?}",
                &src_addr,
                exit,
                context.request.questions(),
                response.id(),
                response.edns(),
                response.answers()
            );
        }

        if let (Some(metrics), Some(start_ms)) = (self.metrics.as_ref(), metrics_start) {
            metrics.on_request_finish(start_ms, exit);
        }

        RequestResult {
            request: context.request,
            response,
            exit,
        }
    }

    #[inline]
    fn apply_request_meta(&self, context: &mut DnsContext, meta: RequestMeta) {
        context.set_request_meta(RequestMeta {
            server_name: meta.server_name.filter(|value| !value.is_empty()),
            url_path: meta.url_path.filter(|value| !value.is_empty()),
        });
    }

    #[inline]
    fn build_servfail_response(&self, context: &DnsContext) -> Message {
        self.build_base_response(context, Rcode::ServFail)
    }

    #[inline]
    fn build_empty_response(&self, context: &DnsContext) -> Message {
        self.build_base_response(context, Rcode::NoError)
    }

    #[inline]
    fn build_base_response(&self, context: &DnsContext, rcode: Rcode) -> Message {
        context.request().response(rcode)
    }

    /// Apply server-level RFC fixes to every outbound response.
    fn finalize_response(request: &Message, response: &mut Message) {
        response.set_recursion_available(true);

        if request.edns().is_some() && response.edns().is_none() {
            let mut edns = Edns::new();
            if let Some(req_edns) = request.edns() {
                edns.flags_mut().dnssec_ok = req_edns.flags().dnssec_ok;
            }
            response.set_edns(edns);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::continue_next;
    use crate::infra::error::Result;
    use crate::plugin::Plugin;
    use crate::proto::{Name, Question, RecordType};

    fn make_request(id: u16, qname: &str) -> Message {
        let mut request = Message::new();
        request.set_id(id);
        request.add_question(Question::new(
            Name::from_ascii(qname).expect("query name should be valid"),
            RecordType::A,
            crate::proto::DNSClass::IN,
        ));
        request
    }

    #[test]
    fn inbound_dns_post_header_classifier_only_rejects_detached_signatures() {
        let request = make_request(7, "example.com.");
        assert_eq!(
            classify_inbound_dns_request_after_wire_header(&request),
            InboundDnsRequestDisposition::Accept
        );

        use crate::proto::rdata::TXT;
        use crate::proto::{RData, Record};

        let mut signed = request;
        signed.signature_mut().push(Record::from_rdata(
            Name::from_ascii("sig.example.com.").expect("signature name should be valid"),
            0,
            RData::TXT(TXT::new(Box::from([3u8, b's', b'i', b'g']))),
        ));
        assert_eq!(
            classify_inbound_dns_request_after_wire_header(&signed),
            InboundDnsRequestDisposition::Drop
        );
    }

    fn decode_test_wire_header(
        id: u16,
        flags: u16,
        question_count: u16,
        additional_count: u16,
    ) -> crate::proto::wire::WireHeader {
        let mut packet = [0u8; 12];
        packet[0..2].copy_from_slice(&id.to_be_bytes());
        packet[2..4].copy_from_slice(&flags.to_be_bytes());
        packet[4..6].copy_from_slice(&question_count.to_be_bytes());
        packet[10..12].copy_from_slice(&additional_count.to_be_bytes());
        crate::proto::wire::decode_header(&packet).expect("test header should decode")
    }

    #[test]
    fn inbound_dns_wire_header_classifier_rejects_before_full_parse() {
        let response = decode_test_wire_header(1, 0x8000, 1, 0);
        assert_eq!(
            classify_inbound_dns_wire_header(&response),
            InboundDnsRequestDisposition::Drop
        );

        let status = decode_test_wire_header(2, 2 << 11, 1, 0);
        assert_eq!(
            classify_inbound_dns_wire_header(&status),
            InboundDnsRequestDisposition::Respond(Rcode::NotImp)
        );

        let multiple = decode_test_wire_header(3, 0, 2, 0);
        assert_eq!(
            classify_inbound_dns_wire_header(&multiple),
            InboundDnsRequestDisposition::Respond(Rcode::FormErr)
        );

        let query = decode_test_wire_header(4, 0, 1, 0);
        assert_eq!(
            classify_inbound_dns_wire_header(&query),
            InboundDnsRequestDisposition::Accept
        );

        let potentially_signed_status = decode_test_wire_header(5, 2 << 11, 1, 1);
        assert_eq!(
            classify_inbound_dns_wire_header(&potentially_signed_status),
            InboundDnsRequestDisposition::Drop
        );

        let potentially_signed_multiple = decode_test_wire_header(6, 0, 2, 1);
        assert_eq!(
            classify_inbound_dns_wire_header(&potentially_signed_multiple),
            InboundDnsRequestDisposition::Drop
        );
    }

    #[test]
    fn inbound_dns_wire_error_response_is_header_only() {
        let request = decode_test_wire_header(0x1234, 0x0110, 2, 0);
        let response = build_inbound_error_response_from_wire_header(&request, Rcode::FormErr);

        assert_eq!(response.id(), 0x1234);
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.opcode(), Opcode::Query);
        assert_eq!(response.rcode(), Rcode::FormErr);
        assert!(response.recursion_available());
        assert!(response.recursion_desired());
        assert!(response.checking_disabled());
        assert!(response.questions().is_empty());
        assert!(response.edns().is_none());
    }

    fn make_request_handle(executor: Arc<dyn Executor>) -> RequestHandle {
        RequestHandle {
            entry_executor: executor,
            metrics: None,
        }
    }

    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    struct ObservedMeta {
        server_name: Option<String>,
        url_path: Option<String>,
    }

    #[derive(Debug)]
    struct CaptureMetaExecutor {
        observed: Arc<Mutex<Option<ObservedMeta>>>,
    }

    #[async_trait]
    impl Plugin for CaptureMetaExecutor {
        fn tag(&self) -> &str {
            "capture_meta"
        }

        async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for CaptureMetaExecutor {
        async fn execute(&self, context: &mut DnsContext) -> Result<ExecStep> {
            let observed = ObservedMeta {
                server_name: context.server_name().map(str::to_string),
                url_path: context.url_path().map(str::to_string),
            };
            self.observed
                .lock()
                .expect("meta capture lock should not be poisoned")
                .replace(observed);
            Ok(ExecStep::Next)
        }
    }

    #[derive(Debug)]
    struct PostResponseExecutor;

    #[async_trait]
    impl Plugin for PostResponseExecutor {
        fn tag(&self) -> &str {
            "post_response"
        }

        async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
            Ok(())
        }

        async fn destroy(&self) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl Executor for PostResponseExecutor {
        fn with_next(&self) -> bool {
            true
        }

        async fn execute(&self, _context: &mut DnsContext) -> Result<ExecStep> {
            Ok(ExecStep::Next)
        }

        async fn execute_with_next(
            &self,
            context: &mut DnsContext,
            next: Option<crate::plugin::executor::ExecutorNext>,
        ) -> Result<ExecStep> {
            let step = continue_next!(next, context)?;
            context.set_response(context.request.response(Rcode::NXDomain));
            Ok(step)
        }
    }

    #[tokio::test]
    async fn test_handle_request_with_meta_applies_server_name_and_url_path() {
        let observed = Arc::new(Mutex::new(None));
        let request_handle = make_request_handle(Arc::new(CaptureMetaExecutor {
            observed: observed.clone(),
        }));
        let request = make_request(13, "example.com.");

        let _result = request_handle
            .handle_request(
                request,
                SocketAddr::from(([127, 0, 0, 1], 5303)),
                RequestMeta {
                    server_name: Some(Arc::from("dns.example.test")),
                    url_path: Some(Arc::from("/dns-query")),
                },
            )
            .await;

        assert_eq!(
            observed
                .lock()
                .expect("meta capture lock should not be poisoned")
                .clone(),
            Some(ObservedMeta {
                server_name: Some("dns.example.test".to_string()),
                url_path: Some("/dns-query".to_string()),
            })
        );
    }

    #[tokio::test]
    async fn test_handle_request_supports_with_next_entry_executor() {
        let request_handle = make_request_handle(Arc::new(PostResponseExecutor));
        let request = make_request(21, "example.com.");

        let result = request_handle
            .handle_request(
                request,
                SocketAddr::from(([127, 0, 0, 1], 5303)),
                RequestMeta::default(),
            )
            .await;

        assert_eq!(result.response.rcode(), Rcode::NXDomain);
        assert_eq!(result.exit, RequestExit::Completed);
    }
}
