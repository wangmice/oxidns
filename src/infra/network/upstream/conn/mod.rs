// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Protocol-specific upstream connection implementations.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(any(feature = "upstream-doq", feature = "upstream-doh3"))]
use std::time::Duration;

#[cfg(feature = "_http-client")]
pub(crate) mod doh;
#[cfg(feature = "upstream-doh")]
pub(crate) mod h2;
#[cfg(feature = "upstream-doh3")]
pub(crate) mod h3;
#[cfg(feature = "upstream-doq")]
pub(crate) mod quic;
pub(crate) mod request_map;
pub(crate) mod tcp;
pub(crate) mod udp;

#[cfg(feature = "upstream-doh")]
pub(crate) use h2::{H2Connection, H2ConnectionBuilder};
#[cfg(feature = "upstream-doh3")]
pub(crate) use h3::{H3Connection, H3ConnectionBuilder};
#[cfg(feature = "upstream-doq")]
pub(crate) use quic::{QuicConnection, QuicConnectionBuilder};
pub(crate) use tcp::{TcpConnection, TcpConnectionBuilder};
pub(crate) use udp::{UdpConnection, UdpConnectionBuilder};

/// Cold-path notification bridge from a connection driver to its owning pool.
///
/// Registration happens once after a multiplexed connection is created. The
/// mutex is touched only during registration and when the connection becomes
/// unavailable, never on the query hot path.
#[derive(Default)]
pub(crate) struct PoolUnavailableNotify {
    notify: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for PoolUnavailableNotify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PoolUnavailableNotify")
    }
}

impl PoolUnavailableNotify {
    pub(crate) fn register(&self, notify: Arc<dyn Fn() + Send + Sync>) {
        *self
            .notify
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(notify);
    }

    pub(crate) fn notify_pool(&self) {
        let notify = self
            .notify
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(notify) = notify {
            notify();
        }
    }
}

/// RAII guard that decrements a connection's in-flight query counter on drop.
///
/// Ensures `using_count` is always decremented even when the query future is
/// cancelled by an outer timeout, preventing the pool from permanently
/// deadlocking due to a leaked counter.
#[allow(dead_code)]
pub(crate) struct UsingCountGuard<'a>(pub(crate) &'a AtomicU32);

impl Drop for UsingCountGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(any(feature = "upstream-doq", feature = "upstream-doh3"))]
pub(crate) fn quic_idle_timeout(query_timeout: Duration) -> Duration {
    // Keep QUIC's transport-level idle detection longer than the per-query
    // timeout. If the peer stops responding without sending CONNECTION_CLOSE,
    // the QUIC driver eventually closes and the upstream pool can replace the
    // dead connection instead of reusing it indefinitely.
    query_timeout.checked_mul(3).unwrap_or(Duration::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn using_count_guard_does_not_wrap_at_u16_boundary() {
        let count = AtomicU32::new(u32::from(u16::MAX));
        count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(count.load(Ordering::Relaxed), u32::from(u16::MAX) + 1);

        {
            let _guard = UsingCountGuard(&count);
        }

        assert_eq!(count.load(Ordering::Relaxed), u32::from(u16::MAX));
    }
}
