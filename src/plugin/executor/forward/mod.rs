// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! DNS forwarding plugin.
//!
//! Forwards DNS queries to configured upstream resolvers.

mod concurrent;
mod config;
mod factory;
mod metrics;
mod selection;
mod single;

pub use config::ForwardConfig;
pub use factory::ForwardFactory;
pub use selection::ResponseSelectionMode;

use crate::infra::error::DnsError;
use crate::infra::network::upstream::ConnectionInfo;

fn is_timeout_error(err: &DnsError) -> bool {
    err.to_string().to_ascii_lowercase().contains("timeout")
}

/// Add a stable configured upstream identity to an error that is about to
/// leave the per-upstream attempt boundary. This is deliberately done only on
/// the error path so successful forwarding stays allocation-free.
fn contextualize_upstream_error(info: &ConnectionInfo, err: DnsError) -> DnsError {
    match info.tag.as_deref() {
        Some(tag) => DnsError::plugin(format!(
            "upstream '{tag}' ({}) query failed: {err}",
            info.raw_addr
        )),
        None => DnsError::plugin(format!(
            "upstream '{}' query failed: {err}",
            info.raw_addr
        )),
    }
}

#[cfg(test)]
mod tests;
