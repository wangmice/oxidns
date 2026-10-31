// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared connection lifecycle support for server plugins.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::infra::clock::AppClock;

pub(crate) struct ConnectionGuard {
    active_connections: Arc<AtomicU64>,
    src: SocketAddr,
    protocol: &'static str,
}

impl ConnectionGuard {
    pub(crate) fn new(
        active_connections: Arc<AtomicU64>,
        src: SocketAddr,
        protocol: &'static str,
    ) -> Self {
        Self {
            active_connections,
            src,
            protocol,
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let active = self
            .active_connections
            .fetch_sub(1, Ordering::Relaxed)
            .saturating_sub(1);
        debug!(
            "{} connection from {} closed (active: {})",
            self.protocol, self.src, active
        );
        if active > 0 && active.is_multiple_of(10) {
            debug!("Active connections: {}", active);
        }
    }
}

/// Shared transport-activity timestamp for one accepted TCP connection.
///
/// The hot I/O path only performs a relaxed atomic store when bytes actually
/// move. The watchdog sleeps independently and re-checks the timestamp when it
/// wakes, avoiding timer resets or notifications on every DNS/HTTP frame.
pub(crate) struct ConnectionActivity {
    last_activity_ms: AtomicU64,
}

impl ConnectionActivity {
    pub(crate) fn new() -> Self {
        Self {
            last_activity_ms: AtomicU64::new(AppClock::elapsed_millis()),
        }
    }

    #[inline(always)]
    fn mark_activity(&self) {
        self.last_activity_ms
            .store(AppClock::elapsed_millis(), Ordering::Relaxed);
    }

    /// Wait until the connection has had no successful transport read or write
    /// for the full configured timeout.
    pub(crate) async fn wait_until_idle(&self, idle_timeout: Duration) {
        let timeout_ms = idle_timeout
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
            .max(1);

        loop {
            let last_activity_ms = self.last_activity_ms.load(Ordering::Relaxed);
            let now_ms = AppClock::elapsed_millis();
            let idle_ms = now_ms.saturating_sub(last_activity_ms);

            if idle_ms >= timeout_ms {
                return;
            }

            tokio::time::sleep(Duration::from_millis(timeout_ms - idle_ms)).await;
        }
    }
}

/// Transparent I/O wrapper that records successful byte activity.
///
/// It deliberately contains no timer. Timeout enforcement lives in the
/// connection task, so split TCP/TLS reader and writer halves never contend on
/// a shared timer future or overwrite each other's wakers.
pub(crate) struct ActivityTrackedIo<S> {
    inner: S,
    activity: Arc<ConnectionActivity>,
}

impl<S> ActivityTrackedIo<S> {
    pub(crate) fn new(inner: S, activity: Arc<ConnectionActivity>) -> Self {
        Self { inner, activity }
    }
}

impl<S> AsyncRead for ActivityTrackedIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();

        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > filled_before {
                    this.activity.mark_activity();
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S> AsyncWrite for ActivityTrackedIo<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written != 0 {
                    this.activity.mark_activity();
                }
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(written)) => {
                if written != 0 {
                    this.activity.mark_activity();
                }
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn idle_watchdog_expires_without_activity() {
        AppClock::start();
        let activity = ConnectionActivity::new();

        tokio::time::timeout(
            Duration::from_millis(200),
            activity.wait_until_idle(Duration::from_millis(20)),
        )
        .await
        .expect("idle watchdog should expire");
    }

    #[tokio::test]
    async fn successful_io_extends_idle_deadline() {
        AppClock::start();
        let activity = Arc::new(ConnectionActivity::new());
        let (mut client, server) = duplex(64);
        let mut server = ActivityTrackedIo::new(server, activity.clone());

        let watchdog = tokio::spawn(async move {
            activity.wait_until_idle(Duration::from_millis(80)).await;
            AppClock::elapsed_millis()
        });

        tokio::time::sleep(Duration::from_millis(40)).await;
        client.write_all(b"a").await.unwrap();
        let mut byte = [0u8; 1];
        server.read_exact(&mut byte).await.unwrap();

        tokio::time::sleep(Duration::from_millis(40)).await;
        server.write_all(b"b").await.unwrap();
        let mut response = [0u8; 1];
        client.read_exact(&mut response).await.unwrap();

        assert!(
            !watchdog.is_finished(),
            "read/write activity should keep the connection alive"
        );

        tokio::time::timeout(Duration::from_millis(200), watchdog)
            .await
            .expect("watchdog should eventually expire after activity stops")
            .expect("watchdog task should not panic");
    }
}
