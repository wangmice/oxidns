// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Management API hub, route registry, and lifecycle control.

use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Mutex as StdMutex};

use ahash::AHashMap;
use http::Method;
use tokio::sync::{Mutex, oneshot, watch};

use crate::api::ApiHandler;
use crate::api::health::HealthState;
use crate::api::route::{PrefixRoute, RouteKey, build_plugin_route_path, normalize_route_path};
use crate::api::server::{ApiServerContext, build_tls_acceptor, run_api_server};
#[cfg(feature = "webui")]
use crate::api::static_files::StaticFileServer;
use crate::config::types::{ApiConfig, ResolvedApiHttpConfig, validate_plugin_tag_path_segment};
use crate::infra::error::{DnsError, Result};
use crate::infra::network::listen::parse_listen_addr;

#[derive(Clone)]
pub struct ApiRegister {
    hub: Arc<ApiHub>,
}

#[derive(Clone)]
pub struct PluginApiRegister {
    register: ApiRegister,
    tag: String,
}

#[cfg(feature = "plugin-query-recorder")]
pub(crate) struct PluginApiRouteRegistration {
    method: Method,
    subpath: String,
    handler: Arc<dyn ApiHandler>,
    prefix: bool,
}

#[cfg(feature = "plugin-query-recorder")]
impl PluginApiRouteRegistration {
    fn exact(method: Method, subpath: &str, handler: Arc<dyn ApiHandler>) -> Self {
        Self {
            method,
            subpath: subpath.to_string(),
            handler,
            prefix: false,
        }
    }

    pub(crate) fn get(subpath: &str, handler: Arc<dyn ApiHandler>) -> Self {
        Self::exact(Method::GET, subpath, handler)
    }

    pub(crate) fn delete(subpath: &str, handler: Arc<dyn ApiHandler>) -> Self {
        Self::exact(Method::DELETE, subpath, handler)
    }

    pub(crate) fn get_prefix(subpath: &str, handler: Arc<dyn ApiHandler>) -> Self {
        Self {
            method: Method::GET,
            subpath: subpath.to_string(),
            handler,
            prefix: true,
        }
    }
}

impl ApiRegister {
    pub(crate) fn new(hub: Arc<ApiHub>) -> Self {
        Self { hub }
    }

    pub(crate) fn health_state(&self) -> Arc<HealthState> {
        self.hub.health_state()
    }

    /// Register one handler under an absolute API path.
    pub fn register_route(
        &self,
        method: Method,
        path: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub.register_route(method, path, handler)
    }

    /// Register one GET handler under an absolute API path.
    pub fn register_get(&self, path: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.register_route(Method::GET, path, handler)
    }

    /// Register one POST handler under an absolute API path.
    pub fn register_post(&self, path: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.register_route(Method::POST, path, handler)
    }

    /// Register one DELETE handler under an absolute API path.
    pub fn register_delete(&self, path: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.register_route(Method::DELETE, path, handler)
    }

    /// Register one handler using path-prefix matching under an absolute API
    /// path.
    pub fn register_prefix_route(
        &self,
        method: Method,
        path_prefix: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub.register_prefix_route(method, path_prefix, handler)
    }

    /// Register one GET handler using path-prefix matching under an absolute
    /// API path.
    pub fn register_get_prefix(
        &self,
        path_prefix: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.register_prefix_route(Method::GET, path_prefix, handler)
    }

    /// Register one POST handler using path-prefix matching under an absolute
    /// API path.
    pub fn register_post_prefix(
        &self,
        path_prefix: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.register_prefix_route(Method::POST, path_prefix, handler)
    }

    /// Register one DELETE handler using path-prefix matching under an
    /// absolute API path.
    pub fn register_delete_prefix(
        &self,
        path_prefix: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.register_prefix_route(Method::DELETE, path_prefix, handler)
    }

    /// Create a plugin-scoped registrar under `/plugins/<plugin_tag>`.
    pub fn plugin(&self, plugin_tag: &str) -> Result<PluginApiRegister> {
        let tag = normalize_plugin_tag(plugin_tag)?;
        Ok(PluginApiRegister {
            register: self.clone(),
            tag,
        })
    }

    /// Register one GET handler under `/plugins/<plugin_tag>/<subpath>`.
    pub fn register_plugin_get(
        &self,
        plugin_tag: &str,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub
            .register_plugin_route(plugin_tag, Method::GET, subpath, handler)
    }

    /// Register one POST handler under `/plugins/<plugin_tag>/<subpath>`.
    pub fn register_plugin_post(
        &self,
        plugin_tag: &str,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub
            .register_plugin_route(plugin_tag, Method::POST, subpath, handler)
    }

    /// Register one DELETE handler under `/plugins/<plugin_tag>/<subpath>`.
    pub fn register_plugin_delete(
        &self,
        plugin_tag: &str,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub
            .register_plugin_route(plugin_tag, Method::DELETE, subpath, handler)
    }

    /// Register one GET handler using path-prefix matching under
    /// `/plugins/<plugin_tag>/<subpath>`.
    pub fn register_plugin_get_prefix(
        &self,
        plugin_tag: &str,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub
            .register_plugin_prefix_route(plugin_tag, Method::GET, subpath, handler)
    }

    /// Register one POST handler using path-prefix matching under
    /// `/plugins/<plugin_tag>/<subpath>`.
    pub fn register_plugin_post_prefix(
        &self,
        plugin_tag: &str,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub
            .register_plugin_prefix_route(plugin_tag, Method::POST, subpath, handler)
    }

    /// Register one DELETE handler using path-prefix matching under
    /// `/plugins/<plugin_tag>/<subpath>`.
    pub fn register_plugin_delete_prefix(
        &self,
        plugin_tag: &str,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.hub
            .register_plugin_prefix_route(plugin_tag, Method::DELETE, subpath, handler)
    }
}

impl PluginApiRegister {
    /// Build an absolute API path under this plugin namespace.
    pub fn path(&self, subpath: &str) -> Result<String> {
        build_plugin_route_path(&self.tag, subpath)
    }

    /// Register one handler under this plugin namespace.
    pub fn route(&self, method: Method, subpath: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.register
            .hub
            .register_plugin_route(&self.tag, method, subpath, handler)
    }

    /// Register one GET handler under this plugin namespace.
    pub fn get(&self, subpath: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.route(Method::GET, subpath, handler)
    }

    /// Register one POST handler under this plugin namespace.
    pub fn post(&self, subpath: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.route(Method::POST, subpath, handler)
    }

    /// Register one DELETE handler under this plugin namespace.
    pub fn delete(&self, subpath: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.route(Method::DELETE, subpath, handler)
    }

    /// Register one prefix handler under this plugin namespace.
    pub fn prefix_route(
        &self,
        method: Method,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        self.register
            .hub
            .register_plugin_prefix_route(&self.tag, method, subpath, handler)
    }

    #[cfg(feature = "plugin-query-recorder")]
    pub(crate) fn register_batch(
        &self,
        registrations: Vec<PluginApiRouteRegistration>,
    ) -> Result<()> {
        self.register
            .hub
            .register_plugin_route_batch(&self.tag, registrations)
    }

    /// Register one GET prefix handler under this plugin namespace.
    pub fn get_prefix(&self, subpath: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.prefix_route(Method::GET, subpath, handler)
    }

    /// Register one POST prefix handler under this plugin namespace.
    pub fn post_prefix(&self, subpath: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.prefix_route(Method::POST, subpath, handler)
    }

    /// Register one DELETE prefix handler under this plugin namespace.
    pub fn delete_prefix(&self, subpath: &str, handler: Arc<dyn ApiHandler>) -> Result<()> {
        self.prefix_route(Method::DELETE, subpath, handler)
    }
}

impl Debug for PluginApiRegister {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginApiRegister")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl Debug for ApiRegister {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiRegister").finish_non_exhaustive()
    }
}

pub struct ApiHub {
    config: ResolvedApiHttpConfig,
    routes: StdMutex<AHashMap<RouteKey, Arc<dyn ApiHandler>>>,
    prefix_routes: StdMutex<Vec<PrefixRoute>>,
    health: Arc<HealthState>,
    shutdown_tx: watch::Sender<bool>,
    task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Debug for ApiHub {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let route_count = self.routes.lock().map(|routes| routes.len()).unwrap_or(0);
        let prefix_route_count = self
            .prefix_routes
            .lock()
            .map(|routes| routes.len())
            .unwrap_or(0);
        f.debug_struct("ApiHub")
            .field("listen", &self.config.listen)
            .field("has_tls", &self.config.ssl.is_some())
            .field("has_auth", &self.config.auth.is_some())
            .field("route_count", &route_count)
            .field("prefix_route_count", &prefix_route_count)
            .finish()
    }
}

impl ApiHub {
    pub fn from_config(config: &ApiConfig) -> Result<Option<Arc<Self>>> {
        let Some(http) = &config.http else {
            return Ok(None);
        };

        let resolved = http.resolve();
        let listen = resolved.listen.trim();
        if listen.is_empty() {
            return Err(DnsError::config("api.http.listen cannot be empty"));
        }
        let listen_addr = parse_listen_addr(listen)?;
        let normalized_listen = listen_addr.to_string();
        let cors = Some(crate::api::cors::resolve_cors_config(
            resolved.cors,
            listen_addr,
        ));
        let webui = resolved.webui.clone();

        let (shutdown_tx, _) = watch::channel(false);
        Ok(Some(Arc::new(Self {
            config: ResolvedApiHttpConfig {
                listen: normalized_listen,
                ssl: resolved.ssl,
                auth: resolved.auth,
                cors,
                webui,
            },
            routes: StdMutex::new(AHashMap::new()),
            prefix_routes: StdMutex::new(Vec::new()),
            health: Arc::new(HealthState::new()),
            shutdown_tx,
            task_handle: Mutex::new(None),
        })))
    }

    pub fn register_plugin_route(
        &self,
        plugin_tag: &str,
        method: Method,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        let plugin_tag = normalize_plugin_tag(plugin_tag)?;
        let route_path = build_plugin_route_path(&plugin_tag, subpath)?;
        self.register_route(method, &route_path, handler)
    }

    pub fn register_plugin_prefix_route(
        &self,
        plugin_tag: &str,
        method: Method,
        subpath: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        let plugin_tag = normalize_plugin_tag(plugin_tag)?;
        let route_path = build_plugin_route_path(&plugin_tag, subpath)?;
        self.register_prefix_route(method, &route_path, handler)
    }

    pub fn register_route(
        &self,
        method: Method,
        path: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        let route_path = normalize_route_path(path)?;
        let key = RouteKey::new(method, route_path);
        let mut routes = self
            .routes
            .lock()
            .map_err(|_| DnsError::runtime("API route registry lock poisoned"))?;

        if routes.contains_key(&key) {
            return Err(DnsError::plugin(format!(
                "duplicate API route registered: {} {}",
                key.method, key.path
            )));
        }
        routes.insert(key, handler);
        Ok(())
    }

    #[cfg(feature = "plugin-query-recorder")]
    fn register_plugin_route_batch(
        &self,
        plugin_tag: &str,
        registrations: Vec<PluginApiRouteRegistration>,
    ) -> Result<()> {
        let plugin_tag = normalize_plugin_tag(plugin_tag)?;
        let mut exact_routes = Vec::new();
        let mut new_prefix_routes = Vec::new();

        for registration in registrations {
            let route_path = build_plugin_route_path(&plugin_tag, &registration.subpath)?;
            if registration.prefix {
                new_prefix_routes.push(PrefixRoute::new(
                    registration.method,
                    route_path,
                    registration.handler,
                ));
            } else {
                exact_routes.push((
                    RouteKey::new(registration.method, route_path),
                    registration.handler,
                ));
            }
        }

        // Hold both registries through validation and publication so callers
        // observe either the complete batch or none of it.
        let mut routes = self
            .routes
            .lock()
            .map_err(|_| DnsError::runtime("API route registry lock poisoned"))?;
        let mut prefix_routes = self
            .prefix_routes
            .lock()
            .map_err(|_| DnsError::runtime("API route registry lock poisoned"))?;

        for (index, (key, _)) in exact_routes.iter().enumerate() {
            if routes.contains_key(key)
                || exact_routes[..index]
                    .iter()
                    .any(|(previous, _)| previous == key)
            {
                return Err(DnsError::plugin(format!(
                    "duplicate API route registered: {} {}",
                    key.method, key.path
                )));
            }
        }

        for (index, route) in new_prefix_routes.iter().enumerate() {
            if prefix_routes.iter().any(|existing| {
                existing.method == route.method && existing.path_prefix == route.path_prefix
            }) || new_prefix_routes[..index].iter().any(|previous| {
                previous.method == route.method && previous.path_prefix == route.path_prefix
            }) {
                return Err(DnsError::plugin(format!(
                    "duplicate API prefix route registered: {} {}",
                    route.method, route.path_prefix
                )));
            }
        }

        for (key, handler) in exact_routes {
            routes.insert(key, handler);
        }
        prefix_routes.extend(new_prefix_routes);
        Ok(())
    }

    pub fn register_prefix_route(
        &self,
        method: Method,
        path_prefix: &str,
        handler: Arc<dyn ApiHandler>,
    ) -> Result<()> {
        let route_path = normalize_route_path(path_prefix)?;
        let mut routes = self
            .prefix_routes
            .lock()
            .map_err(|_| DnsError::runtime("API route registry lock poisoned"))?;

        if routes
            .iter()
            .any(|route| route.method == method && route.path_prefix == route_path)
        {
            return Err(DnsError::plugin(format!(
                "duplicate API prefix route registered: {} {}",
                method, route_path
            )));
        }

        routes.push(PrefixRoute::new(method, route_path, handler));
        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        let mut task_slot = self.task_handle.lock().await;
        if task_slot.is_some() {
            return Ok(());
        }

        let listen = parse_listen_addr(&self.config.listen)?;
        let routes = self
            .routes
            .lock()
            .map_err(|_| DnsError::runtime("API route registry lock poisoned"))?
            .clone();
        let prefix_routes = self
            .prefix_routes
            .lock()
            .map_err(|_| DnsError::runtime("API route registry lock poisoned"))?
            .clone();
        let tls_acceptor = build_tls_acceptor(&self.config)?;
        let auth = self.config.auth.clone();
        let cors = self.config.cors.clone();
        #[cfg(feature = "webui")]
        let webui = self
            .config
            .webui
            .as_ref()
            .map(StaticFileServer::from_config)
            .transpose()?
            .map(Arc::new);
        #[cfg(not(feature = "webui"))]
        if self.config.webui.is_some() {
            return Err(DnsError::config(
                "api.http.webui is set but this build was compiled without the `webui` feature; \
                 rebuild with --features webui",
            ));
        }
        let health = self.health.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let (startup_tx, startup_rx) = oneshot::channel();
        *task_slot = Some(tokio::spawn(async move {
            run_api_server(
                ApiServerContext {
                    listen,
                    routes,
                    prefix_routes,
                    tls_acceptor,
                    auth,
                    cors,
                    #[cfg(feature = "webui")]
                    webui,
                    health,
                },
                &mut shutdown_rx,
                startup_tx,
            )
            .await;
        }));
        drop(task_slot);

        match startup_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(DnsError::runtime(err)),
            Err(_) => Err(DnsError::runtime(
                "API server startup channel closed unexpectedly",
            )),
        }
    }

    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.task_handle.lock().await.take() {
            let _ = handle.await;
        }
    }

    pub fn mark_plugins_initialized(&self, total_plugins: usize, server_plugins: usize) {
        self.health
            .mark_plugins_initialized(total_plugins, server_plugins);
    }

    pub(crate) fn health_state(&self) -> Arc<HealthState> {
        self.health.clone()
    }
}

fn normalize_plugin_tag(plugin_tag: &str) -> Result<String> {
    if let Err(reason) = validate_plugin_tag_path_segment(plugin_tag) {
        return Err(DnsError::plugin(format!(
            "api route plugin tag '{}' is invalid: {}",
            plugin_tag, reason
        )));
    }
    Ok(plugin_tag.to_string())
}
