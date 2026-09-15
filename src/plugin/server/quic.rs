// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! QUIC DNS server plugin
//!
//! Listens for DNS queries over QUIC and processes them through a configured
//! entry plugin executor. Handles concurrent requests efficiently and manages
//! task spawning with automatic cleanup.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rustls::ServerConfig;
use serde::Deserialize;
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::config::types::PluginConfig;
use crate::infra::error::{DnsError, Result};
use crate::infra::network::listen::parse_listen_addr;
use crate::infra::network::tls_config::load_tls_config;
use crate::infra::network::transport::quic::{
    QuicReadError, QuicTransport, QuicTransportReader, QuicTransportWriter, QuicWriteError,
};
use crate::infra::observability::metrics::{register_metric_source, unregister_metric_source};
use crate::infra::system::deserialize_duration_option;
use crate::plugin::dependency::DependencySpec;
use crate::plugin::server::{
    ConnectionGuard, DEFAULT_QUIC_MAX_BIDI_STREAMS, DEFAULT_SERVER_IDLE_TIMEOUT,
    DEFAULT_SERVER_MAX_INFLIGHT_REQUESTS, InboundRequestLimiter, RequestHandle, RequestMeta,
    Server, ServerMetrics, quic_endpoint,
};
use crate::plugin::{Plugin, PluginFactory};
use crate::plugin_factory;

const DOQ_INTERNAL_ERROR: u32 = 0x1;
const DOQ_PROTOCOL_ERROR: u32 = 0x2;
const DOQ_REQUEST_CANCELLED: u32 = 0x3;

/// QUIC server configuration
#[derive(Deserialize)]
pub struct QuicServerConfig {
    /// Entry executor plugin tag to process incoming requests.
    ///
    /// - Must reference an existing executor plugin registered in
    ///   `PluginRegistry`.
    /// - All DoQ (DNS over QUIC) queries will be forwarded to this executor.
    entry: String,

    /// QUIC listen address in `ip:port` or `:port` format (e.g., "0.0.0.0:853",
    /// ":853").
    ///
    /// - `:port` binds on `[::]:port` with dual-stack sockets enabled.
    /// - Must be a valid listen address or validation will fail.
    /// - QUIC runs over UDP; ensure the port is not occupied by UDP listeners.
    listen: String,

    /// Path to TLS certificate file (PEM format).
    ///
    /// - DoQ requires TLS; both `cert` and `key` must be provided.
    /// - Certificate chain supported via `rustls-pemfile::certs`.
    cert: String,

    /// Path to TLS private key file (PEM format).
    ///
    /// - Supports common key formats (PKCS#8/RSA/EC) via `rustls-pemfile`.
    key: String,

    /// QUIC transport-level idle timeout in seconds (optional).
    ///
    /// - Applies to QUIC transport. When absent, quinn's default is used.
    #[serde(default, deserialize_with = "deserialize_duration_option")]
    idle_timeout: Option<Duration>,
}

/// QUIC DNS server plugin
#[allow(unused)]
pub struct QuicServer {
    tag: String,
    listen: SocketAddr,
    /// TLS acceptor for HTTPS support (None for plain HTTP)
    server_config: ServerConfig,
    idle_timeout: Option<Duration>,
    request_handle: Arc<RequestHandle>,
    metrics: Arc<ServerMetrics>,
    shutdown_tx: watch::Sender<bool>,
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for QuicServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicServer")
            .field("tag", &self.tag)
            .field("listen", &self.listen)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

impl QuicServer {
    fn spawn_server_task(
        &self,
        startup_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
    ) -> Result<()> {
        let mut task_slot = self
            .task_handle
            .lock()
            .map_err(|_| DnsError::runtime("QUIC server task lock poisoned"))?;

        if task_slot.is_some() {
            if let Some(startup_tx) = startup_tx {
                let _ = startup_tx.send(Ok(()));
            }
            return Ok(());
        }

        let addr = self.listen;
        let handler = self.request_handle.clone();
        let server_config = self.server_config.clone();
        let idle_timeout = self.idle_timeout;
        let shutdown_rx = self.shutdown_tx.subscribe();
        *task_slot = Some(tokio::spawn(run_server(
            addr,
            handler,
            server_config,
            idle_timeout.unwrap_or(DEFAULT_SERVER_IDLE_TIMEOUT),
            shutdown_rx,
            startup_tx,
        )));
        Ok(())
    }
}

#[async_trait]
impl Plugin for QuicServer {
    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    async fn init(&mut self, _context: &crate::plugin::PluginInitContext<'_>) -> Result<()> {
        register_metric_source(self.metrics.clone())?;
        let (startup_tx, startup_rx) = oneshot::channel();
        self.spawn_server_task(Some(startup_tx))?;
        match startup_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(DnsError::plugin(e)),
            Err(_) => Err(DnsError::plugin(
                "QUIC server startup channel closed unexpectedly",
            )),
        }
    }

    async fn destroy(&self) -> Result<()> {
        unregister_metric_source(&self.tag);
        let _ = self.shutdown_tx.send(true);
        let handle = self
            .task_handle
            .lock()
            .map_err(|_| DnsError::runtime("QUIC server task lock poisoned"))?
            .take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        Ok(())
    }
}

impl Server for QuicServer {
    fn run(&self) {
        // Spawn the QUIC server loop. This call is non-blocking and returns
        // immediately. The event loop will accept incoming QUIC connections and
        // process DoQ streams.
        debug!(listen = %self.listen, "Spawning QUIC server task");
        if let Err(e) = self.spawn_server_task(None) {
            error!(plugin = %self.tag, error = %e, "Failed to spawn QUIC server task");
        }
    }
}

#[hotpath::measure]
async fn run_server(
    addr: SocketAddr,
    handler: Arc<RequestHandle>,
    server_config: ServerConfig,
    idle_timeout: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
    startup_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
) {
    let mut startup_tx = startup_tx;
    let endpoint = match quic_endpoint::build_quic_endpoint(addr, server_config, idle_timeout) {
        Ok(s) => s,
        Err(e) => {
            if let Some(tx) = startup_tx.take() {
                let _ = tx.send(Err(format!(
                    "Failed to bind QUIC endpoint to {}: {}",
                    addr, e
                )));
            }
            error!("Failed to bind QUIC endpoint to {}: {}", addr, e);
            return;
        }
    };
    if let Some(tx) = startup_tx.take() {
        let _ = tx.send(Ok(()));
    }
    info!(
        listen = %addr,
        max_inflight_requests = DEFAULT_SERVER_MAX_INFLIGHT_REQUESTS,
        max_bidi_streams = DEFAULT_QUIC_MAX_BIDI_STREAMS,
        "QUIC server listening"
    );
    // QUIC endpoint created successfully; enter the accept loop.
    debug!("QUIC server event loop started on {}", addr);

    let tasks = TaskTracker::new();
    let shutdown_token = CancellationToken::new();
    let active_connections = Arc::new(AtomicU64::new(0));
    let request_limiter = InboundRequestLimiter::new(DEFAULT_SERVER_MAX_INFLIGHT_REQUESTS);

    // Accept QUIC connections and spawn a task per connection.
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    break;
                }
            }
            maybe_connecting = endpoint.accept() => {
                match maybe_connecting {
                    Some(connecting) => {
                        let active = active_connections.fetch_add(1, Ordering::Relaxed) + 1;
                        let handler_clone = handler.clone();
                        let task_shutdown = shutdown_token.clone();
                        let active_connections = active_connections.clone();
                        let request_limiter = request_limiter.clone();
                        tasks.spawn(async move {
                            let _connection_guard =
                                ConnectionGuard::new(active_connections.clone(), connecting.remote_address(), "QUIC");
                            let stream_tasks = TaskTracker::new();
                            let stream_cancel = CancellationToken::new();
                            let connection_stream_tasks = stream_tasks.clone();
                            let connection_stream_cancel = stream_cancel.clone();

                            tokio::select! {
                                _ = task_shutdown.cancelled() => {}
                                _ = handle_quic_connection(
                                    connecting,
                                    handler_clone,
                                    request_limiter,
                                    connection_stream_tasks,
                                    connection_stream_cancel,
                                ) => {}
                            }

                            stream_cancel.cancel();
                            stream_tasks.close();
                            stream_tasks.wait().await;
                        });
                        debug!("New QUIC connection started (active: {})", active);
                    }
                    None => break,
                }
            }
        }
    }

    shutdown_token.cancel();
    tasks.close();
    tasks.wait().await;
    info!(listen = %addr, "QUIC server stopped");
}

/// Accept a QUIC connection and handle all bidirectional streams (DNS over
/// QUIC). Each bi-directional stream represents a single DNS query/response
/// exchange.
#[hotpath::measure]
async fn handle_quic_connection(
    connecting: quinn::Incoming,
    handler: Arc<RequestHandle>,
    request_limiter: InboundRequestLimiter,
    stream_tasks: TaskTracker,
    stream_cancel: CancellationToken,
) {
    let remote_addr = connecting.remote_address();
    let connection = match connecting.await {
        Ok(c) => c,
        Err(e) => {
            warn!("QUIC handshake failed for {}: {}", remote_addr, e);
            return;
        }
    };
    let server_name = extract_tls_server_name(&connection);

    debug!("QUIC connection established with {}", remote_addr);

    let transport = QuicTransport::new(connection);
    // Accept bi-directional streams on this QUIC connection until it is closed.
    let server_name = server_name.map(Arc::from);

    loop {
        let (reader, writer) = tokio::select! {
            _ = stream_cancel.cancelled() => return,
            result = transport.accept_bi() => match result {
                Ok(streams) => streams,
                Err(e) => {
                    debug!("QUIC connection closed by {}: {}", remote_addr, e);
                    return;
                }
            }
        };

        // Wait for server-wide capacity before creating a stream handler task.
        // While saturated we stop accepting more streams from this connection,
        // allowing QUIC's stream limit and flow control to provide backpressure.
        let permit = tokio::select! {
            _ = stream_cancel.cancelled() => return,
            _ = transport.closed() => return,
            permit = request_limiter.acquire() => permit,
        };

        let handler = handler.clone();
        let server_name = server_name.clone();
        let task_cancel = stream_cancel.clone();
        let task_transport = transport.clone();
        stream_tasks.spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = task_cancel.cancelled() => {}
                result = handle_doq_bi_stream(
                    task_transport,
                    reader,
                    writer,
                    handler,
                    remote_addr,
                    server_name,
                ) => {
                    if let Err(e) = result {
                        warn!("DoQ stream error ({}): {}", remote_addr, e);
                    }
                }
            }
        });
    }
}

/// Handle a single DNS over QUIC (DoQ) bidirectional stream.
/// Format: 2-byte big-endian length prefix followed by the DNS message payload.
async fn handle_doq_bi_stream(
    transport: QuicTransport,
    mut reader: QuicTransportReader,
    mut writer: QuicTransportWriter,
    handler: Arc<RequestHandle>,
    remote_addr: std::net::SocketAddr,
    server_name: Option<Arc<str>>,
) -> Result<()> {
    let request_msg = match reader.read_message_doq().await {
        Ok(request_msg) => request_msg,
        Err(QuicReadError::Protocol(message)) => {
            warn!(
                client = %remote_addr,
                error = %message,
                "Fatal DoQ protocol error while reading request"
            );
            transport.close_with_code(DOQ_PROTOCOL_ERROR, b"DoQ protocol error");
            return Ok(());
        }
        Err(QuicReadError::StreamReset(code)) => {
            debug!(
                client = %remote_addr,
                %code,
                "DoQ request stream reset by client"
            );
            writer.reset(DOQ_REQUEST_CANCELLED);
            return Ok(());
        }
        Err(QuicReadError::ConnectionLost(error)) => {
            debug!(
                client = %remote_addr,
                error = ?error,
                "QUIC connection lost while reading DoQ request"
            );
            return Ok(());
        }
        Err(QuicReadError::Stream(message)) => {
            debug!(
                client = %remote_addr,
                error = %message,
                "DoQ request stream read error"
            );
            writer.reset(DOQ_INTERNAL_ERROR);
            return Ok(());
        }
    };

    // A DoQ client can abandon the response direction with STOP_SENDING after
    // it has already sent a complete request and FIN. Do not keep executing the
    // DNS transaction (and holding the global inbound-request permit) until the
    // eventual response write notices `WriteError::Stopped`.
    //
    // `SendStream::stopped()` is woken by STOP_SENDING. If this branch wins,
    // dropping the `handle_request()` future propagates cancellation through
    // the executor/upstream future chain. The surrounding stream task then
    // returns and releases its `InboundRequestLimiter` permit.
    let peer_stopped = writer.stopped();
    tokio::pin!(peer_stopped);
    let response = tokio::select! {
        biased;

        stopped = &mut peer_stopped => {
            match stopped {
                Ok(Some(code)) => {
                    debug!(
                        client = %remote_addr,
                        %code,
                        "Cancelling DoQ transaction after client STOP_SENDING"
                    );
                }
                Ok(None) => {
                    debug!(
                        client = %remote_addr,
                        "DoQ response send stream closed while request was executing"
                    );
                }
                Err(error) => {
                    debug!(
                        client = %remote_addr,
                        error = ?error,
                        "QUIC connection lost while executing DoQ request"
                    );
                }
            }
            return Ok(());
        }

        response = handler.handle_request(
            request_msg,
            remote_addr,
            RequestMeta {
                server_name,
                url_path: None,
            },
        ) => response,
    };

    match writer.write_message_doq(&response.response).await {
        Ok(()) => {}
        Err(QuicWriteError::Stopped(code)) => {
            debug!(
                client = %remote_addr,
                %code,
                "DoQ transaction cancelled by client with STOP_SENDING"
            );
            return Ok(());
        }
        Err(QuicWriteError::ConnectionLost(error)) => {
            debug!(
                client = %remote_addr,
                error = ?error,
                "QUIC connection lost while writing DoQ response"
            );
            return Ok(());
        }
        Err(QuicWriteError::Stream(message) | QuicWriteError::Encode(message)) => {
            warn!(
                client = %remote_addr,
                error = %message,
                "Failed to write DoQ response"
            );
            writer.reset(DOQ_INTERNAL_ERROR);
            return Ok(());
        }
    }

    if let Err(error) = writer.finish() {
        debug!(
            client = %remote_addr,
            error = %error,
            "Failed to finish DoQ response stream"
        );
    }
    Ok(())
}

#[inline]
fn extract_tls_server_name(connection: &quinn::Connection) -> Option<String> {
    connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.server_name)
        .map(|name| name.to_ascii_lowercase())
}

/// Factory for creating QUIC server plugin instances
#[derive(Debug)]
#[plugin_factory("quic_server")]
pub struct QuicServerFactory {}

#[async_trait]
impl PluginFactory for QuicServerFactory {
    /// Get dependencies (the entry executor plugin)
    fn get_dependency_specs(&self, plugin_config: &PluginConfig) -> Vec<DependencySpec> {
        if let Some(args) = &plugin_config.args
            && let Ok(config) = serde_yaml_ng::from_value::<QuicServerConfig>(args.clone())
        {
            return vec![DependencySpec::executor("args.entry", config.entry)];
        }
        vec![]
    }

    fn create(
        &self,
        plugin_config: &PluginConfig,
        init_context: &crate::plugin::PluginInitContext<'_>,
    ) -> Result<crate::plugin::UninitializedPlugin> {
        let quic_config = serde_yaml_ng::from_value::<QuicServerConfig>(
            plugin_config
                .args
                .clone()
                .ok_or_else(|| DnsError::plugin("QUIC Server requires configuration arguments"))?,
        )
        .map_err(|e| DnsError::plugin(format!("Failed to parse QUIC Server config: {}", e)))?;
        let listen = parse_listen_addr(&quic_config.listen).map_err(|e| {
            DnsError::plugin(format!(
                "Invalid QUIC listen address '{}': {}",
                quic_config.listen, e
            ))
        })?;

        // Resolve and type-check the entry executor using contextual
        // diagnostics.
        let entry_executor = init_context.executor("args.entry", &quic_config.entry)?;

        // Load TLS configuration if cert and key are provided
        let server_config =
            if let Some(res) = load_tls_config(&Some(quic_config.cert), &Some(quic_config.key)) {
                let mut config = res?;
                config.alpn_protocols = vec![b"doq".to_vec()];
                config
            } else {
                return Err("Failed to load TLS config".into());
            };

        let metrics = Arc::new(ServerMetrics::new(plugin_config.tag.clone(), "quic"));

        Ok(crate::plugin::UninitializedPlugin::Server(Box::new(
            QuicServer {
                tag: plugin_config.tag.clone(),
                listen,
                server_config,
                idle_timeout: quic_config.idle_timeout,
                request_handle: Arc::new(RequestHandle {
                    entry_executor,
                    metrics: Some(metrics.clone()),
                }),
                metrics,
                shutdown_tx: watch::channel(false).0,
                task_handle: Mutex::new(None),
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::test_utils::plugin_config;

    #[test]
    fn test_quic_factory_requires_args() {
        let factory = QuicServerFactory {};
        let cfg = plugin_config("quic", "quic_server", None);
        assert!(crate::plugin::test_utils::create_plugin_for_test(&factory, &cfg).is_err());
    }
}
