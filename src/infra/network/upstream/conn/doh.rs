// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(feature = "_http-client")]
use base64::Engine;
#[cfg(feature = "_http-client")]
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
#[cfg(feature = "_http-client")]
use bytes::BytesMut;
#[cfg(feature = "_http-client")]
use http::header::CONTENT_LENGTH;
#[cfg(feature = "_http-client")]
use http::{HeaderValue, Method, Request, Response, Version, header};

#[cfg(feature = "_http-client")]
use crate::infra::error::{DnsError, Result};
#[cfg(feature = "_http-client")]
use crate::infra::network::upstream::{ConnectionInfo, ConnectionType};

/// Content type header for DNS-over-HTTPS (RFC 8484 Section 6)
#[cfg(feature = "_http-client")]
#[allow(dead_code)]
const DNS_HEADER_VALUE: HeaderValue = HeaderValue::from_static("application/dns-message");

/// Build a DoH GET request with base64url-encoded DNS query
///
/// Constructs an HTTP GET request following RFC 8484 Section 4.1 (GET method).
/// The DNS message is base64url-encoded (without padding) and appended to the
/// URI.
///
/// # Arguments
/// * `uri` - Base URI with "?dns=" already appended (will add base64 query)
/// * `buf` - Raw DNS message bytes (wire format)
/// * `version` - HTTP version (HTTP/2 for h2, HTTP/3 for h3)
///
/// # Returns
/// HTTP Request with empty body (query is in URI parameter)
///
/// # Example URI
/// `https://dns.example.com/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB`
#[cfg(feature = "_http-client")]
#[allow(dead_code)]
#[inline]
pub fn build_dns_get_request(uri: &str, buf: &[u8], version: Version) -> Result<Request<()>> {
    // Reserve the complete GET URI once and append Base64 directly into it.
    // For unpadded Base64, every complete 3-byte group emits 4 bytes and the
    // remainder emits either 2 or 3 bytes. DNS wire messages are <= 65535
    // bytes, so this calculation cannot overflow in practice.
    let encoded_len = (buf.len() / 3) * 4
        + match buf.len() % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        };
    let mut request_uri = String::with_capacity(uri.len() + encoded_len);
    request_uri.push_str(uri);
    BASE64_URL_SAFE_NO_PAD.encode_string(buf, &mut request_uri);

    http::Request::builder()
        .version(version)
        .header(header::CONTENT_TYPE, DNS_HEADER_VALUE)
        .header(header::ACCEPT, DNS_HEADER_VALUE)
        .method(Method::GET)
        .uri(request_uri)
        .body(())
        .map_err(|e| DnsError::protocol(format!("invalid DoH request URI: {e}")))
}

/// Extract and pre-allocate response buffer from HTTP response
///
/// Reads the Content-Length header to optimize buffer allocation.
/// This avoids repeated reallocations when receiving the response body.
///
/// # Arguments
/// * `response` - HTTP response with headers
/// * `body_limit` - Maximum capacity trusted from Content-Length
///
/// # Returns
/// BytesMut buffer pre-allocated to Content-Length size (or 4KB default),
/// capped by the caller-provided body limit.
///
/// # Performance
/// Pre-allocating based on Content-Length avoids:
/// - Multiple buffer reallocations during body reception
/// - Memory copies when buffer grows
/// - Potential performance hiccups from allocator
#[cfg(feature = "_http-client")]
#[allow(dead_code)]
#[inline]
pub fn get_cap_buf_with_context_len<T>(response: &Response<T>, body_limit: usize) -> BytesMut {
    let capacity = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4096)
        .min(body_limit);

    BytesMut::with_capacity(capacity)
}

/// Maximum wire-format DNS message size carried by DoH.
pub const MAX_DOH_DNS_BODY_SIZE: usize = u16::MAX as usize;
/// Error bodies are diagnostics only; keep them bounded independently.
pub const MAX_DOH_ERROR_BODY_SIZE: usize = 8 * 1024;

/// Build DoH request URI template from connection info
///
/// Constructs the full HTTPS URI for DoH requests, handling non-standard ports.
/// The returned URI ends with "?dns=" ready for base64url-encoded query to be
/// appended.
///
/// # Arguments
/// * `connection_info` - Connection configuration with server name, port, and
///   path
///
/// # Returns
/// String containing "https://server:port/path?dns=" (port omitted if 443)
///
/// # Examples
/// - Standard port: `https://dns.example.com/dns-query?dns=`
/// - Custom port: `https://dns.example.com:8443/dns-query?dns=`
///
/// The returned value is an immutable URI template. Per-query capacity for the
/// Base64 payload is reserved by `build_dns_get_request`.
#[cfg(feature = "_http-client")]
#[allow(dead_code)]
pub fn build_doh_request_uri(connection_info: &ConnectionInfo) -> String {
    let host = doh_uri_host(&connection_info.server_name);
    if connection_info.port != ConnectionType::DoH.default_port() {
        // Include port in URI for non-standard ports. IPv6 literals must be
        // enclosed in brackets when used as an URI authority.
        format!(
            "https://{}:{}{}?dns=",
            host, connection_info.port, connection_info.path
        )
    } else {
        // Omit port 443 (standard HTTPS port) from URI.
        format!("https://{}{}?dns=", host, connection_info.path)
    }
}

#[cfg(feature = "_http-client")]
#[inline]
fn doh_uri_host(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_get_request_sets_uri_method_and_headers() {
        let request = build_dns_get_request(
            "https://dns.example.test/dns-query?dns=",
            &[0, 1, 2, 3],
            Version::HTTP_2,
        )
        .expect("valid DoH request should build");

        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.version(), Version::HTTP_2);
        assert_eq!(
            request.uri().to_string(),
            "https://dns.example.test/dns-query?dns=AAECAw"
        );
        assert_eq!(request.headers()[header::CONTENT_TYPE], DNS_HEADER_VALUE);
    }

    #[test]
    fn test_get_cap_buf_with_context_len_uses_content_length_header() {
        let response = Response::builder()
            .header(CONTENT_LENGTH, "128")
            .body(())
            .expect("response should build");

        let buf = get_cap_buf_with_context_len(&response, MAX_DOH_DNS_BODY_SIZE);

        assert_eq!(buf.capacity(), 128);
    }

    #[test]
    fn test_get_cap_buf_with_context_len_uses_default_capacity_without_header() {
        let response = Response::builder().body(()).expect("response should build");

        let buf = get_cap_buf_with_context_len(&response, MAX_DOH_DNS_BODY_SIZE);

        assert_eq!(buf.capacity(), 4096);
    }

    #[test]
    fn test_get_cap_buf_with_context_len_caps_untrusted_content_length() {
        let response = Response::builder()
            .header(CONTENT_LENGTH, "1000000")
            .body(())
            .expect("response should build");

        let buf = get_cap_buf_with_context_len(&response, 8192);

        assert_eq!(buf.capacity(), 8192);
    }

    #[test]
    fn test_build_doh_request_uri_omits_default_https_port() {
        let mut connection_info = ConnectionInfo::with_addr("https://dns.example.test/dns-query")
            .expect("connection info should parse");
        connection_info.port = 443;

        let uri = build_doh_request_uri(&connection_info);

        assert_eq!(uri, "https://dns.example.test/dns-query?dns=");
    }

    #[test]
    fn test_build_doh_request_uri_includes_custom_port() {
        let mut connection_info = ConnectionInfo::with_addr("https://dns.example.test/dns-query")
            .expect("connection info should parse");
        connection_info.port = 8443;

        let uri = build_doh_request_uri(&connection_info);

        assert_eq!(uri, "https://dns.example.test:8443/dns-query?dns=");
    }

    #[test]
    fn test_build_doh_request_uri_brackets_ipv6_literal() {
        let connection_info = ConnectionInfo::with_addr("https://[2001:db8::1]/dns-query")
            .expect("IPv6 connection info should parse");

        let uri = build_doh_request_uri(&connection_info);

        assert_eq!(uri, "https://[2001:db8::1]/dns-query?dns=");
    }

    #[test]
    fn test_build_doh_request_uri_brackets_ipv6_literal_with_custom_port() {
        let connection_info = ConnectionInfo::with_addr("https://[2001:db8::1]:8443/dns-query")
            .expect("IPv6 connection info should parse");

        let uri = build_doh_request_uri(&connection_info);

        assert_eq!(uri, "https://[2001:db8::1]:8443/dns-query?dns=");
    }

    #[test]
    fn test_build_dns_get_request_returns_error_for_invalid_uri() {
        let result = build_dns_get_request("https://[?dns=", &[0, 1, 2, 3], Version::HTTP_2);

        assert!(result.is_err());
    }
}
