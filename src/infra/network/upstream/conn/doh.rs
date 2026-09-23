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
use http::{HeaderMap, HeaderValue, Method, Request, Response, Version, header};

#[cfg(feature = "_http-client")]
use crate::infra::error::{DnsError, Result};
#[cfg(feature = "_http-client")]
use crate::infra::network::upstream::{ConnectionInfo, ConnectionType};

/// Content type header for DNS-over-HTTPS (RFC 8484 Section 6)
#[cfg(feature = "_http-client")]
#[allow(dead_code)]
const DNS_HEADER_VALUE: HeaderValue = HeaderValue::from_static("application/dns-message");

/// Validate the media type of a successful DNS-over-HTTPS response.
///
/// OxiDNS currently implements only the RFC 8484 `application/dns-message`
/// wire format. Successful responses using any other (or no) media type must
/// not be passed to the DNS message decoder.
#[cfg(feature = "_http-client")]
#[inline]
pub(crate) fn validate_doh_content_type(headers: &HeaderMap) -> Result<()> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .ok_or_else(|| DnsError::protocol("DoH response is missing Content-Type"))?;

    if !is_dns_message_media_type(content_type.as_bytes()) {
        let content_type = content_type.to_str().unwrap_or("<non-ASCII>");
        return Err(DnsError::protocol(format!(
            "unsupported or malformed DoH response Content-Type: {content_type}"
        )));
    }

    Ok(())
}

/// Parse the HTTP media type without allocating.
///
/// RFC 9110 defines media-type parameters as `token=(token / quoted-string)`
/// with no whitespace around `=`. Empty semicolon-delimited parameter slots
/// are allowed by the generic `parameters` grammar and are accepted here.
#[cfg(feature = "_http-client")]
#[inline]
fn is_dns_message_media_type(value: &[u8]) -> bool {
    let mut pos = 0;

    let type_start = pos;
    consume_token(value, &mut pos);
    if pos == type_start
        || !value[type_start..pos].eq_ignore_ascii_case(b"application")
        || value.get(pos) != Some(&b'/')
    {
        return false;
    }
    pos += 1;

    let subtype_start = pos;
    consume_token(value, &mut pos);
    if pos == subtype_start || !value[subtype_start..pos].eq_ignore_ascii_case(b"dns-message") {
        return false;
    }

    loop {
        consume_ows(value, &mut pos);
        if pos == value.len() {
            return true;
        }
        if value[pos] != b';' {
            return false;
        }
        pos += 1;
        consume_ows(value, &mut pos);

        // RFC 9110: parameters = *( OWS ";" OWS [ parameter ] )
        if pos == value.len() || value[pos] == b';' {
            continue;
        }

        let name_start = pos;
        consume_token(value, &mut pos);
        if pos == name_start || value.get(pos) != Some(&b'=') {
            return false;
        }
        pos += 1;

        match value.get(pos) {
            Some(b'"') => {
                if !consume_quoted_string(value, &mut pos) {
                    return false;
                }
            }
            Some(_) => {
                let value_start = pos;
                consume_token(value, &mut pos);
                if pos == value_start {
                    return false;
                }
            }
            None => return false,
        }
    }
}

#[cfg(feature = "_http-client")]
#[inline]
fn consume_ows(value: &[u8], pos: &mut usize) {
    while matches!(value.get(*pos), Some(b' ' | b'\t')) {
        *pos += 1;
    }
}

#[cfg(feature = "_http-client")]
#[inline]
fn consume_token(value: &[u8], pos: &mut usize) {
    while value.get(*pos).is_some_and(|byte| is_tchar(*byte)) {
        *pos += 1;
    }
}

#[cfg(feature = "_http-client")]
#[inline]
const fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(feature = "_http-client")]
#[inline]
fn consume_quoted_string(value: &[u8], pos: &mut usize) -> bool {
    debug_assert_eq!(value.get(*pos), Some(&b'"'));
    *pos += 1;

    while let Some(&byte) = value.get(*pos) {
        match byte {
            b'"' => {
                *pos += 1;
                return true;
            }
            b'\\' => {
                *pos += 1;
                let Some(&escaped) = value.get(*pos) else {
                    return false;
                };
                if !is_quoted_pair_char(escaped) {
                    return false;
                }
                *pos += 1;
            }
            _ if is_qdtext(byte) => *pos += 1,
            _ => return false,
        }
    }

    false
}

#[cfg(feature = "_http-client")]
#[inline]
const fn is_qdtext(byte: u8) -> bool {
    matches!(
        byte,
        b'\t' | b' ' | b'!' | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=u8::MAX
    )
}

#[cfg(feature = "_http-client")]
#[inline]
const fn is_quoted_pair_char(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | 0x21..=0x7e | 0x80..=u8::MAX)
}

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

/// Build a DoH POST request whose DNS wire message is sent as the HTTP body.
///
/// The returned request contains only headers and URI. H2/H3 callers stream
/// the raw DNS message separately so transport-specific flow control remains
/// owned by the protocol implementation.
#[cfg(feature = "_http-client")]
#[allow(dead_code)]
#[inline]
pub fn build_dns_post_request(uri: &str, version: Version) -> Result<Request<()>> {
    http::Request::builder()
        .version(version)
        .header(header::CONTENT_TYPE, DNS_HEADER_VALUE)
        .header(header::ACCEPT, DNS_HEADER_VALUE)
        .method(Method::POST)
        .uri(uri)
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

/// Build the DoH request URI from connection info.
///
/// Configured fixed query parameters are preserved for both HTTP methods.
/// GET returns a URI template ending in `dns=`, ready for the per-query
/// base64url payload. POST returns only the configured endpoint and fixed
/// query parameters because the DNS wire message is carried in the body.
///
/// # Arguments
/// * `connection_info` - Connection configuration with server name, port,
///   path, and optional fixed DoH query parameters
/// * `use_post` - Whether the request body carries the DNS message
///
/// # Examples
/// - GET: `https://dns.example.com/dns-query?dns=`
/// - GET with fixed query: `https://dns.example.com/dns-query?token=abc&dns=`
/// - POST: `https://dns.example.com/dns-query`
/// - POST with fixed query: `https://dns.example.com/dns-query?token=abc`
#[cfg(feature = "_http-client")]
#[allow(dead_code)]
pub fn build_doh_request_uri(connection_info: &ConnectionInfo, use_post: bool) -> String {
    let host = doh_uri_host(&connection_info.server_name);
    let mut uri = if connection_info.port != ConnectionType::DoH.default_port() {
        // Include port in URI for non-standard ports. IPv6 literals must be
        // enclosed in brackets when used as an URI authority.
        format!(
            "https://{}:{}{}",
            host, connection_info.port, connection_info.path
        )
    } else {
        // Omit port 443 (standard HTTPS port) from URI.
        format!("https://{}{}", host, connection_info.path)
    };

    match connection_info.doh_query.as_deref() {
        Some(query) if !query.is_empty() => {
            uri.reserve(query.len() + if use_post { 1 } else { "?&dns=".len() });
            uri.push('?');
            uri.push_str(query);
            if !use_post {
                uri.push_str("&dns=");
            }
        }
        _ if !use_post => uri.push_str("?dns="),
        _ => {}
    }

    uri
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
    fn test_build_dns_post_request_sets_uri_method_and_headers() {
        let request = build_dns_post_request(
            "https://dns.example.test/dns-query?token=abc",
            Version::HTTP_2,
        )
        .expect("valid DoH POST request should build");

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.version(), Version::HTTP_2);
        assert_eq!(
            request.uri().to_string(),
            "https://dns.example.test/dns-query?token=abc"
        );
        assert_eq!(request.headers()[header::CONTENT_TYPE], DNS_HEADER_VALUE);
        assert_eq!(request.headers()[header::ACCEPT], DNS_HEADER_VALUE);
    }

    #[test]
    fn test_validate_doh_content_type_accepts_dns_message() {
        let response = Response::builder()
            .header(header::CONTENT_TYPE, "application/dns-message")
            .body(())
            .expect("response should build");

        validate_doh_content_type(response.headers())
            .expect("DoH DNS media type should be accepted");
    }

    #[test]
    fn test_validate_doh_content_type_accepts_case_and_valid_parameters() {
        for content_type in [
            "Application/DNS-Message",
            "application/dns-message; foo=bar",
            "Application/DNS-Message; foo=\"bar;baz\"",
            "application/dns-message ; charset=utf-8",
            "application/dns-message; empty=\"\"",
            "application/dns-message; escaped=\"a\\\"b\\\\c\"",
            "application/dns-message; ; foo=bar;",
        ] {
            let response = Response::builder()
                .header(header::CONTENT_TYPE, content_type)
                .body(())
                .expect("response should build");

            validate_doh_content_type(response.headers())
                .expect("valid media type parameters should be accepted");
        }
    }

    #[test]
    fn test_validate_doh_content_type_rejects_missing_wrong_or_malformed_type() {
        let missing = Response::builder().body(()).expect("response should build");
        assert!(validate_doh_content_type(missing.headers()).is_err());

        for content_type in [
            "application/octet-stream",
            "application/dns-message-bogus",
            "application/dns-message garbage",
            "application/dns-message; foo",
            "application/dns-message; foo =bar",
            "application/dns-message; foo= bar",
            "application/dns-message; foo=bad/value",
            "application/dns-message; foo=\"unterminated",
            "application/dns-message; =bar",
        ] {
            let wrong = Response::builder()
                .header(header::CONTENT_TYPE, content_type)
                .body(())
                .expect("response should build");
            assert!(validate_doh_content_type(wrong.headers()).is_err());
        }
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
    fn test_build_doh_request_uri_preserves_fixed_query_parameters() {
        let connection_info =
            ConnectionInfo::with_addr("https://dns.example.test/dns-query?token=abc&profile=fast")
                .expect("connection info should parse");

        let uri = build_doh_request_uri(&connection_info);

        assert_eq!(
            uri,
            "https://dns.example.test/dns-query?token=abc&profile=fast&dns="
        );
    }

    #[test]
    fn test_build_doh_request_uri_preserves_percent_encoded_query() {
        let connection_info =
            ConnectionInfo::with_addr("https://dns.example.test/dns-query?token=a%2Fb%3Dc")
                .expect("connection info should parse");

        let uri = build_doh_request_uri(&connection_info);

        assert_eq!(
            uri,
            "https://dns.example.test/dns-query?token=a%2Fb%3Dc&dns="
        );
    }

    #[test]
    fn test_doh_upstream_rejects_preconfigured_dns_query_parameter() {
        let result =
            ConnectionInfo::with_addr("https://dns.example.test/dns-query?token=abc&dns=stale");

        assert!(result.is_err());
    }

    #[test]
    fn test_build_doh_request_uri_treats_empty_fixed_query_as_absent() {
        let mut connection_info = ConnectionInfo::with_addr("https://dns.example.test/dns-query")
            .expect("connection info should parse");
        connection_info.doh_query = Some(String::new());

        let uri = build_doh_request_uri(&connection_info);

        assert_eq!(uri, "https://dns.example.test/dns-query?dns=");
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
