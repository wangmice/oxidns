// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared inbound request admission control for server transports.
//!
//! The important rule is that callers acquire a permit *before* spawning a
//! request handler. This bounds the number of handler tasks themselves instead
//! of merely bounding work after an unbounded number of tasks already exists.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Maximum number of concurrently executing request handlers per server
/// instance.
///
/// This is deliberately generous for normal DNS workloads while still placing
/// a hard ceiling on task/future retention when executors or upstreams stall.
pub(crate) const DEFAULT_SERVER_MAX_INFLIGHT_REQUESTS: usize = 4096;

/// Maximum number of concurrently executing DNS-over-TCP handlers on one
/// connection. Once reached, the reader stops consuming more frames and lets
/// TCP flow control provide backpressure to the client.
pub(crate) const DEFAULT_TCP_MAX_INFLIGHT_PER_CONNECTION: usize = 128;

/// Maximum concurrent HTTP/2 request streams admitted per connection.
/// Hyper currently defaults to 200, but the default is not stable.
#[cfg(feature = "server-doh")]
pub(crate) const DEFAULT_HTTP2_MAX_INFLIGHT_PER_CONNECTION: u32 = 128;

/// Explicit QUIC incoming bidirectional stream budget per connection.
///
/// Quinn currently defaults to 100. Set it explicitly so a dependency default
/// change cannot silently increase the server's worst-case stream/task memory.
#[cfg(any(feature = "server-doq", feature = "server-doh3"))]
pub(crate) const DEFAULT_QUIC_MAX_BIDI_STREAMS: u32 = 100;

#[derive(Clone)]
pub(crate) struct InboundRequestLimiter {
    semaphore: Arc<Semaphore>,
}

impl InboundRequestLimiter {
    pub(crate) fn new(limit: usize) -> Self {
        debug_assert!(limit != 0);
        Self {
            semaphore: Arc::new(Semaphore::new(limit)),
        }
    }

    /// Try to acquire request capacity without joining Tokio's semaphore wait queue.
    #[inline]
    pub(crate) fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.semaphore.clone().try_acquire_owned().ok()
    }

    /// Acquire request capacity before creating a handler task.
    #[inline]
    pub(crate) async fn acquire(&self) -> OwnedSemaphorePermit {
        // Keep the normal path out of Tokio's async semaphore wait queue. DNS
        // servers spend almost all of their time below the overload ceiling,
        // so this reduces admission control to a single atomic fast path.
        if let Some(permit) = self.try_acquire() {
            return permit;
        }

        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("inbound request limiter is never closed")
    }

    #[cfg(test)]
    fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_acquire_rejects_without_waiting_when_capacity_is_full() {
        let limiter = InboundRequestLimiter::new(1);
        let first = limiter
            .try_acquire()
            .expect("the first request should acquire capacity");

        assert!(
            limiter.try_acquire().is_none(),
            "overload admission must shed immediately instead of entering a semaphore wait queue"
        );

        drop(first);
        assert!(
            limiter.try_acquire().is_some(),
            "released capacity must be immediately reusable"
        );
    }

    #[tokio::test]
    async fn limiter_holds_capacity_until_permit_drop() {
        let limiter = InboundRequestLimiter::new(2);
        let first = limiter.acquire().await;
        let second = limiter.acquire().await;

        assert_eq!(limiter.available_permits(), 0);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), limiter.acquire())
                .await
                .is_err(),
            "third request must wait instead of creating additional handler capacity"
        );

        drop(first);
        let third = tokio::time::timeout(std::time::Duration::from_millis(100), limiter.acquire())
            .await
            .expect("released capacity should wake one waiter");

        assert_eq!(limiter.available_permits(), 0);
        drop(second);
        drop(third);
        assert_eq!(limiter.available_permits(), 2);
    }
}
