// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Server plugin category.
//!
//! Server plugins terminate inbound DNS transports and feed normalized requests
//! into the executor pipeline. Protocol implementations share request,
//! connection, and metrics support while retaining transport-specific code.

use std::time::Duration;

use crate::plugin::Plugin;

mod admission;
mod connection;
mod metrics;
mod request;

#[cfg(feature = "server-doh")]
pub(crate) use admission::DEFAULT_HTTP2_MAX_INFLIGHT_PER_CONNECTION;
#[cfg(any(feature = "server-doq", feature = "server-doh3"))]
pub(crate) use admission::DEFAULT_QUIC_MAX_BIDI_STREAMS;
pub(crate) use admission::{
    DEFAULT_SERVER_MAX_INFLIGHT_REQUESTS, DEFAULT_TCP_MAX_INFLIGHT_PER_CONNECTION,
    InboundRequestLimiter,
};
pub(crate) use connection::{ActivityTrackedIo, ConnectionActivity, ConnectionGuard};
pub(crate) use metrics::ServerMetrics;
pub use request::{RequestExit, RequestHandle, RequestMeta, RequestResult};

#[cfg(feature = "server-doh")]
pub mod http;
#[cfg(feature = "server-doq")]
pub mod quic;
/// Shared QUIC endpoint builder used by both the DoQ server and the DoH/HTTP3
/// server, so a `server-doh3`-only build still has access to it.
#[cfg(any(feature = "server-doq", feature = "server-doh3"))]
pub mod quic_endpoint;
pub mod tcp;
pub mod udp;

/// Default idle timeout applied to TCP / DoT / DoH connections.
pub(crate) const DEFAULT_SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub trait Server: Plugin {
    fn run(&self);
}
