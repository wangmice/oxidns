// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! DNS-over-TLS nameserver client.

use async_trait::async_trait;

use super::super::endpoint::NameserverConfig;
#[cfg(feature = "resolver-dot")]
use super::tcp::query_framed_tcp;
use super::{NameserverClient, effective_deadline};
#[cfg(not(feature = "resolver-dot"))]
use crate::infra::error::DnsError;
use crate::infra::error::Result;
#[cfg(feature = "resolver-dot")]
use crate::infra::network::deadline::DeadlineOutcome;
use crate::infra::network::deadline::QueryDeadline;
#[cfg(feature = "resolver-dot")]
use crate::infra::network::dial::{DialTarget, SocketOptions, TlsDialOptions, connect_tls};
#[cfg(feature = "resolver-dot")]
use crate::infra::network::proxy::connect_tcp as proxy_connect_tcp;
#[cfg(feature = "resolver-dot")]
use crate::infra::network::transport::tcp::TcpTransport;
use crate::proto::Message;

#[derive(Debug)]
pub(super) struct DotNameserverClient {
    config: NameserverConfig,
}

impl DotNameserverClient {
    pub(super) fn new(config: NameserverConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NameserverClient for DotNameserverClient {
    async fn query(&self, request: Message, deadline: QueryDeadline) -> Result<Message> {
        query_dot_config(
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

#[cfg(feature = "resolver-dot")]
#[inline]
fn dot_tls_dial_options(
    target: DialTarget,
    handshake_timeout: std::time::Duration,
) -> TlsDialOptions {
    TlsDialOptions::new(target, false, handshake_timeout, vec![b"dot".to_vec()])
}

#[cfg(feature = "resolver-dot")]
async fn query_dot_config(
    config: &NameserverConfig,
    request: Message,
    deadline: QueryDeadline,
) -> Result<Message> {
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
        dot_tls_dial_options(
            config.target(),
            deadline
                .remaining()
                .ok_or_else(|| deadline.timeout_error())?,
        ),
    )
    .await?;
    let transport = TcpTransport::new(tls_stream);
    let (reader, writer) = transport.into_split();
    query_framed_tcp(reader, writer, request, deadline).await
}

#[cfg(not(feature = "resolver-dot"))]
async fn query_dot_config(
    _config: &NameserverConfig,
    _request: Message,
    _deadline: QueryDeadline,
) -> Result<Message> {
    Err(DnsError::plugin(
        "nameserver DoT is not compiled into this build; rebuild with --features resolver-dot",
    ))
}

#[cfg(all(test, feature = "resolver-dot"))]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::*;

    #[test]
    fn dot_tls_options_advertise_dot_alpn() {
        let target =
            DialTarget::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 853));
        let options = dot_tls_dial_options(target, Duration::from_secs(1));

        assert_eq!(options.alpn(), &[b"dot".to_vec()]);
    }
}
