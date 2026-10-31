// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! DNS-over-HTTPS nameserver client.

use async_trait::async_trait;
#[cfg(feature = "resolver-doh")]
use base64::Engine;
#[cfg(feature = "resolver-doh")]
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
#[cfg(feature = "resolver-doh")]
use bytes::{Buf, BufMut, Bytes, BytesMut};
#[cfg(feature = "resolver-doh")]
use http::Version;

use super::super::endpoint::NameserverConfig;
#[cfg(feature = "resolver-doh")]
use super::super::endpoint::NameserverProtocol;
use super::{NameserverClient, effective_deadline};
use crate::infra::error::{DnsError, Result};
#[cfg(feature = "resolver-doh")]
use crate::infra::network::buffer_pool::wire_buffer_pool;
#[cfg(feature = "resolver-doh")]
use crate::infra::network::deadline::DeadlineOutcome;
use crate::infra::network::deadline::QueryDeadline;
#[cfg(feature = "resolver-doh")]
use crate::infra::network::dial::{SocketOptions, TlsDialOptions, connect_tls};
#[cfg(feature = "resolver-doh")]
use crate::infra::network::proxy::connect_tcp as proxy_connect_tcp;
#[cfg(feature = "resolver-doh")]
use crate::infra::network::response_validation::{DnsResponseIdPolicy, validate_dns_response};
#[cfg(feature = "resolver-doh")]
use crate::infra::network::upstream::validate_doh_content_type;
use crate::proto::Message;

#[cfg(feature = "resolver-doh")]
const MAX_DNS_MESSAGE_LEN: usize = u16::MAX as usize;

#[derive(Debug)]
pub(super) struct DohNameserverClient {
    config: NameserverConfig,
}

impl DohNameserverClient {
    pub(super) fn new(config: NameserverConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NameserverClient for DohNameserverClient {
    async fn query(&self, request: Message, deadline: QueryDeadline) -> Result<Message> {
        query_doh_config(
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

#[cfg(feature = "resolver-doh")]
async fn query_doh_config(
    config: &NameserverConfig,
    request: Message,
    deadline: QueryDeadline,
) -> Result<Message> {
    use h2::client;

    let stream = match deadline
        .run(proxy_connect_tcp(
            config.target(),
            SocketOptions::default(),
            config.socks5.clone(),
        ))
        .await
    {
        DeadlineOutcome::Completed(result) => result?,
        DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
    };
    let tls_stream = connect_tls(
        stream,
        TlsDialOptions::new(
            config.target(),
            false,
            deadline
                .remaining()
                .ok_or_else(|| deadline.timeout_error())?,
            vec![b"h2".to_vec()],
        ),
    )
    .await?;
    let (sender, connection) = match deadline
        .run(client::Builder::new().handshake::<_, Bytes>(tls_stream))
        .await
    {
        DeadlineOutcome::Completed(Ok(value)) => value,
        DeadlineOutcome::Completed(Err(err)) => {
            return Err(DnsError::protocol(format!("H2 handshake error: {}", err)));
        }
        DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let raw_id = request.id();
    let mut body_bytes = wire_buffer_pool().acquire();
    request.append_to_with_id(0, &mut body_bytes)?;
    let http_request = build_doh_get_request(
        doh_request_uri(config),
        body_bytes.as_slice(),
        Version::HTTP_2,
    );
    // The encoded DNS message is now owned by the request URI. Return the
    // pooled wire buffer before any network wait so other concurrent
    // queries can reuse it.
    drop(body_bytes);
    let mut sender = match deadline.run(sender.ready()).await {
        DeadlineOutcome::Completed(Ok(sender)) => sender,
        DeadlineOutcome::Completed(Err(err)) => {
            return Err(DnsError::protocol(format!(
                "H2 sender readiness error: {err}"
            )));
        }
        DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
    };
    let (response_future, _send_stream) = sender
        .send_request(http_request, true)
        .map_err(|err| DnsError::protocol(format!("H2 send_request error: {err}")))?;
    let mut response = match deadline.run(response_future).await {
        DeadlineOutcome::Completed(Ok(value)) => value,
        DeadlineOutcome::Completed(Err(err)) => {
            return Err(DnsError::protocol(format!("H2 response error: {}", err)));
        }
        DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
    };
    let status_code = response.status();
    if status_code.is_success() {
        validate_doh_content_type(response.headers())?;
    }
    let response_bytes = read_h2_response_body(&mut response, deadline).await?;
    if !status_code.is_success() {
        return Err(DnsError::protocol(format!(
            "http unsuccessful code: {}",
            status_code
        )));
    }
    let mut message = Message::from_bytes(&response_bytes)?;
    validate_dns_response(&request, &message, DnsResponseIdPolicy::Exact(0))?;
    message.set_id(raw_id);
    Ok(message)
}

#[cfg(feature = "resolver-doh")]
async fn read_h2_response_body(
    response: &mut http::Response<h2::RecvStream>,
    deadline: QueryDeadline,
) -> Result<BytesMut> {
    let mut response_bytes = response_buffer(response);
    let mut flow_control = response.body_mut().flow_control().clone();

    loop {
        let partial_bytes = match deadline.run(response.body_mut().data()).await {
            DeadlineOutcome::Completed(value) => value,
            DeadlineOutcome::Expired => return Err(deadline.timeout_error()),
        };
        let Some(partial_bytes) = partial_bytes else {
            break;
        };
        let partial_bytes = partial_bytes
            .map_err(|err| DnsError::protocol(format!("H2 response body error: {err}")))?;
        let chunk_len = partial_bytes.remaining();
        let append_result = append_response_chunk(&mut response_bytes, partial_bytes);

        // h2 only replenishes the receive window when the application
        // explicitly releases capacity. Release the complete DATA frame
        // even when the DNS body limit is exceeded, because the bytes
        // have already been consumed from the stream and an error
        // return must not strand receive-window credit.
        if chunk_len != 0 {
            flow_control.release_capacity(chunk_len).map_err(|err| {
                DnsError::protocol(format!("H2 flow-control release error: {err}"))
            })?;
        }

        append_result?;
    }

    Ok(response_bytes)
}

#[cfg(not(feature = "resolver-doh"))]
async fn query_doh_config(
    _config: &NameserverConfig,
    _request: Message,
    _deadline: QueryDeadline,
) -> Result<Message> {
    Err(DnsError::plugin(
        "nameserver DoH is not compiled into this build; rebuild with --features resolver-doh",
    ))
}

#[cfg(feature = "resolver-doh")]
pub(super) fn doh_request_uri(config: &NameserverConfig) -> String {
    let path = if config.path.is_empty() {
        "/dns-query"
    } else {
        config.path.as_str()
    };
    let host = doh_uri_host(config.host.as_str());
    if config.port != NameserverProtocol::DoH.default_port() {
        format!("https://{}:{}{}?dns=", host, config.port, path)
    } else {
        format!("https://{}{}?dns=", host, path)
    }
}

#[cfg(feature = "resolver-doh")]
fn doh_uri_host(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

#[cfg(feature = "resolver-doh")]
pub(super) fn build_doh_get_request(
    mut uri: String,
    wire: &[u8],
    version: Version,
) -> http::Request<()> {
    // Append Base64 directly into the final URI instead of allocating a
    // temporary encoded String. Reserve the exact unpadded Base64 length up
    // front.
    let encoded_len = (wire.len() / 3) * 4
        + match wire.len() % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        };
    uri.reserve(encoded_len);
    BASE64_URL_SAFE_NO_PAD.encode_string(wire, &mut uri);
    http::Request::builder()
        .version(version)
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::ACCEPT, "application/dns-message")
        .method(http::Method::GET)
        .uri(uri)
        .body(())
        .expect("static DoH request should build")
}

#[cfg(feature = "resolver-doh")]
pub(super) fn response_buffer<T>(response: &http::Response<T>) -> BytesMut {
    let capacity = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.min(MAX_DNS_MESSAGE_LEN))
        .unwrap_or(4096);
    BytesMut::with_capacity(capacity)
}

#[cfg(feature = "resolver-doh")]
pub(super) fn append_response_chunk(response: &mut BytesMut, chunk: impl Buf) -> Result<()> {
    let next_len = response
        .len()
        .checked_add(chunk.remaining())
        .ok_or_else(|| DnsError::protocol("DoH response body exceeds DNS message size limit"))?;
    if next_len > MAX_DNS_MESSAGE_LEN {
        return Err(DnsError::protocol(
            "DoH response body exceeds DNS message size limit",
        ));
    }
    response.put(chunk);
    Ok(())
}

#[cfg(all(test, feature = "resolver-doh"))]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_doh_request_uri_preserves_bracketed_ipv6_literals() {
        let config = NameserverConfig::new(
            "https://[2001:4860:4860::8888]/dns-query",
            None,
            Duration::from_secs(5),
            None,
        )
        .expect("IPv6 DoH nameserver should parse");

        let uri = doh_request_uri(&config);

        assert!(uri.starts_with("https://[2001:4860:4860::8888]/dns-query?dns="));
    }

    #[test]
    fn test_doh_uri_host_brackets_ipv6_literals() {
        assert_eq!(
            doh_uri_host("2001:4860:4860::8888"),
            "[2001:4860:4860::8888]"
        );
        assert_eq!(doh_uri_host("dns.example"), "dns.example");
    }

    #[test]
    fn test_response_buffer_caps_content_length() {
        let response = http::Response::builder()
            .header(http::header::CONTENT_LENGTH, "999999999")
            .body(())
            .expect("response should build");

        let buffer = response_buffer(&response);

        assert_eq!(buffer.capacity(), MAX_DNS_MESSAGE_LEN);
    }

    #[test]
    fn test_append_response_chunk_rejects_oversized_body() {
        let mut buffer = BytesMut::new();
        buffer.resize(MAX_DNS_MESSAGE_LEN, 0);

        let err = append_response_chunk(&mut buffer, Bytes::from_static(b"x"))
            .expect_err("oversized response should fail");

        assert!(err.to_string().contains("DNS message size limit"));
    }

    #[test]
    fn test_build_doh_get_request_appends_unpadded_base64url() {
        let request = build_doh_get_request(
            "https://dns.example.test/dns-query?dns=".to_string(),
            &[0, 1, 2, 3],
            Version::HTTP_2,
        );

        assert_eq!(
            request.uri().to_string(),
            "https://dns.example.test/dns-query?dns=AAECAw"
        );
    }

    #[tokio::test]
    async fn test_read_h2_response_body_releases_flow_control_capacity() {
        use crate::infra::clock::AppClock;
        AppClock::start();

        let (client_io, server_io) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io)
                .await
                .expect("server handshake should succeed");
            let Some(Ok((_request, mut respond))) = connection.accept().await else {
                panic!("server should receive one request");
            };

            let response = http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/dns-message")
                .body(())
                .expect("response should build");
            let mut send_stream = respond
                .send_response(response, false)
                .expect("response headers should send");
            send_stream
                .send_data(Bytes::from(vec![0x5A; 128]), true)
                .expect("response body should queue");

            while let Some(result) = connection.accept().await {
                if let Err(error) = result {
                    panic!("server connection failed: {error}");
                }
            }
        });

        let mut client_builder = h2::client::Builder::new();
        client_builder.initial_window_size(16);
        let (mut sender, connection) = client_builder
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_task = tokio::spawn(async move {
            let _ = connection.await;
        });

        sender = sender
            .ready()
            .await
            .expect("client sender should become ready");
        let request = http::Request::builder()
            .method("GET")
            .uri("https://dns.example.test/dns-query")
            .body(())
            .expect("request should build");
        let (response_future, _send_stream) = sender
            .send_request(request, true)
            .expect("request should send");
        let mut response = response_future
            .await
            .expect("response headers should arrive");

        let response_bytes = tokio::time::timeout(
            Duration::from_secs(2),
            read_h2_response_body(&mut response, QueryDeadline::new(Duration::from_secs(2))),
        )
        .await
        .expect("response should not stall on the 16-byte H2 receive window")
        .expect("response body should be received successfully");

        assert_eq!(response_bytes.len(), 128);
        assert!(response_bytes.iter().all(|byte| *byte == 0x5A));

        drop(sender);
        client_task.abort();
        server_task.abort();
    }
}
