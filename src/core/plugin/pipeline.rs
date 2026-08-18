//! Request context, plugin executor, and compiled global+route pipeline.
//!
//! `ProxyContext` and `CompiledPluginPipeline` live together because each
//! request stores the pipeline on the context, and pipeline methods mutate
//! that context.

use std::{any::Any, collections::HashMap, sync::Arc, time::Instant};

use async_trait::async_trait;
use bytes::Bytes;
use once_cell::sync::Lazy;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

use crate::core::error::ProxyResult;

use super::upstream::{SelectedUpstream, UpstreamSelection, UpstreamSelector};
use super::{sort_plugins_by_priority_desc, PluginPhases, ProxyPlugin};

/// Context key for the generic "request body was replaced by a plugin" marker
/// (see [`ProxyContext::mark_request_body_replaced`]).
const REQUEST_BODY_REPLACED_KEY: &str = "core::request_body_replaced";

/// Trait for route behavior that can be used in proxy context.
///
/// Lives next to [`ProxyPluginExecutor`] because `build_plugin_executor`
/// returns that type; moving it to `upstream` would cycle the modules.
pub trait RouteContext: Send + Sync {
    /// Get the route identifier.
    fn id(&self) -> &str;

    /// Optional human-readable route name from configuration.
    fn name(&self) -> Option<&str> {
        None
    }

    /// Get the service ID if available.
    fn service_id(&self) -> Option<&str>;

    /// Optional human-readable service name from the bound service configuration.
    fn service_name(&self) -> Option<&str> {
        None
    }

    /// Return the configured URI template used to match this route.
    fn uri_template(&self) -> Option<&str>;

    /// Whether WebSocket upgrade requests are enabled for this route.
    fn enable_websocket(&self) -> bool {
        false
    }

    /// Select an upstream peer for the route, compiling the selection artifact
    /// (peer plus owning selector) used by all downstream callbacks.
    fn select_upstream(&self, session: &mut Session) -> ProxyResult<UpstreamSelection>;

    /// Return the effective host patterns used to match this route.
    ///
    /// Exposed so plugins can derive bounded labels from route configuration
    /// instead of attacker-controllable request input. Default is empty.
    fn effective_hosts(&self) -> &[String] {
        &[]
    }

    /// Fingerprint of the compiled route's cache namespace inputs (route/service
    /// identity and response-affecting plugin configuration). Combined with the
    /// live upstream isolation key at request time.
    fn cache_namespace_fingerprint(&self) -> u64 {
        0
    }

    /// Build plugin executor for this route.
    fn build_plugin_executor(&self) -> Arc<ProxyPluginExecutor>;

    /// Resolve upstream for this route.
    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamSelector>>;

    /// Route-level timeout, applied after an upstream override is selected.
    fn timeout(&self) -> Option<&crate::config::Timeout>;
}

/// Request-scoped context shared across all plugin phases.
///
/// Contains routing information, retry state, and plugin-specific data.
/// Common fields like request_start and request_id are directly accessible for better performance.
/// The vars field enables plugins to share additional data across different execution phases.
pub struct ProxyContext {
    /// The matched proxy route, if any.
    pub route: Option<Arc<dyn RouteContext>>,
    /// Parameters extracted from the route pattern.
    /// Stored as Vec for better performance with small number of params (typical case).
    pub route_params: Option<Vec<(String, String)>>,
    /// The upstream override selected by the traffic-split plugin. Consumed by
    /// cache namespacing and [`HttpService::upstream_peer`](crate::service::http::HttpService);
    /// the compiled result of that selection lives in [`Self::selected`].
    pub upstream_override: Option<Arc<dyn UpstreamSelector>>,
    /// Selected upstream after `upstream_peer` moves the peer to Pingora.
    /// Host rewrite, passive health, and metrics read this — not a cloned peer.
    pub selected: Option<SelectedUpstream>,
    /// Number of retry attempts so far.
    pub tries: usize,
    /// Compiled global-rule + route/service plugin layers for this request.
    /// Owns phase traversal and short-circuit rules; set in `early_request_filter`.
    pub pipeline: CompiledPluginPipeline,
    /// Request start timestamp for performance metrics and timeouts.
    pub request_start: Instant,
    /// Unique request identifier, set by request-id plugin if enabled.
    pub request_id: Option<String>,
    /// Whether the original downstream request contained authentication/session credentials.
    /// Captured before plugins can remove or rewrite headers (Authorization, Proxy-Authorization, Cookie).
    pub original_request_had_credentials: bool,
    /// Set when any auth plugin observes credentials (including custom headers/query).
    pub request_has_credentials: bool,
    /// Custom variables available to plugins (type-erased, thread-safe).
    /// Lazily allocated because many requests never store plugin variables.
    pub vars: Option<HashMap<String, Box<dyn Any + Send + Sync>>>,
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self {
            route: None,
            route_params: None,
            upstream_override: None,
            selected: None,
            tries: 0,
            pipeline: CompiledPluginPipeline::default(),
            request_start: Instant::now(),
            request_id: None,
            original_request_had_credentials: false,
            request_has_credentials: false,
            vars: None,
        }
    }
}

impl ProxyContext {
    /// Mark that the request carried credentials (regardless of auth success).
    pub fn mark_request_has_credentials(&mut self) {
        self.request_has_credentials = true;
        self.original_request_had_credentials = true;
    }

    /// Store a typed value into the context for inter-plugin communication.
    pub fn set<T: Any + Send + Sync>(&mut self, key: impl Into<String>, value: T) {
        self.vars
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), Box::new(value));
    }

    /// Get a typed reference from the context with type safety.
    pub fn get<T: Any>(&self, key: &str) -> Option<&T> {
        self.vars
            .as_ref()
            .and_then(|vars| vars.get(key))
            .and_then(|v| v.downcast_ref::<T>())
    }

    /// Get a typed mutable reference from the context with type safety.
    ///
    /// Mirrors [`Self::get`] for plugins that accumulate state across phase
    /// invocations (e.g. buffered request bodies).
    pub fn get_mut<T: Any>(&mut self, key: &str) -> Option<&mut T> {
        self.vars
            .as_mut()
            .and_then(|vars| vars.get_mut(key))
            .and_then(|v| v.downcast_mut::<T>())
    }

    /// Mark that a plugin has replaced the request body the client sent with
    /// a gateway-generated one (e.g. provider-format transformation).
    ///
    /// Body-buffering/-validating plugins consult this so client-format
    /// schemas are not applied to the replacement; the marker is generic so
    /// no plugin needs to know which transformer produced the body.
    pub fn mark_request_body_replaced(&mut self) {
        self.set(REQUEST_BODY_REPLACED_KEY, true);
    }

    /// Whether a plugin replaced the client request body on this context.
    pub fn request_body_replaced(&self) -> bool {
        self.get::<bool>(REQUEST_BODY_REPLACED_KEY)
            .copied()
            .unwrap_or(false)
    }

    /// Convenience method for string values to avoid repeated type annotation.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get::<String>(key).map(|s| s.as_str())
    }

    /// Get the elapsed time since request start in milliseconds.
    pub fn elapsed_ms(&self) -> u128 {
        self.request_start.elapsed().as_millis()
    }

    /// Get the elapsed time since request start as f64 milliseconds (for metrics).
    pub fn elapsed_ms_f64(&self) -> f64 {
        self.elapsed_ms() as f64
    }

    /// Get the request ID if set.
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// Set the request ID.
    pub fn set_request_id(&mut self, id: String) {
        self.request_id = Some(id);
    }
}

/// Shared empty plugin executor instance to avoid allocations for routes without plugins.
static DEFAULT_PLUGIN_EXECUTOR: Lazy<Arc<ProxyPluginExecutor>> =
    Lazy::new(|| Arc::new(ProxyPluginExecutor::default()));

/// Manages execution of multiple plugins in priority order.
///
/// Plugins are sorted by priority (higher numbers execute first) to ensure
/// critical plugins like auth and rate limiting run before others.
/// Uses Arc for efficient sharing across multiple concurrent requests.
///
/// Storage is private: construction is either [`Self::new`] (which sorts
/// deterministically) or [`Self::from_sorted`] (which asserts the caller's
/// ordering precondition), so an unordered executor can never be built by
/// accident.
#[derive(Default)]
pub struct ProxyPluginExecutor {
    /// Plugins in deterministic execution order (priority descending).
    plugins: Vec<Arc<dyn ProxyPlugin>>,
    early_request: Vec<Arc<dyn ProxyPlugin>>,
    request: Vec<Arc<dyn ProxyPlugin>>,
    upstream_request: Vec<Arc<dyn ProxyPlugin>>,
    request_body: Vec<Arc<dyn ProxyPlugin>>,
    response: Vec<Arc<dyn ProxyPlugin>>,
    response_body: Vec<Arc<dyn ProxyPlugin>>,
    logging: Vec<Arc<dyn ProxyPlugin>>,
}

/// Invokes a plugin method on each plugin in sequence (async, propagates Result).
macro_rules! for_each_plugin_async {
    ($plugins:expr, $method:ident, $($arg:expr),*) => {
        for plugin in $plugins.iter() {
            plugin.$method($($arg),*).await?;
        }
    };
}

/// Invokes a plugin method on each plugin in sequence (sync, propagates Result).
macro_rules! for_each_plugin_sync {
    ($plugins:expr, $method:ident, $($arg:expr),*) => {
        for plugin in $plugins.iter() {
            plugin.$method($($arg),*)?;
        }
    };
}

/// Invokes a plugin method on each plugin in sequence (async, no return value).
macro_rules! for_each_plugin_async_unit {
    ($plugins:expr, $method:ident, $($arg:expr),*) => {
        for plugin in $plugins.iter() {
            plugin.$method($($arg),*).await;
        }
    };
}

impl ProxyPluginExecutor {
    /// Sort plugins deterministically (priority desc, then name asc) and build.
    pub fn new(plugins: Vec<Arc<dyn ProxyPlugin>>) -> Self {
        let mut plugins = plugins;
        sort_plugins_by_priority_desc(&mut plugins);
        Self::from_sorted(plugins)
    }

    /// Build from an already-ordered plugin list.
    ///
    /// The precondition is a non-increasing priority sequence; tie order is
    /// whatever the caller produced (e.g. the route-over-service merge prefers
    /// the route side on equal priority). In debug builds this is asserted.
    pub fn from_sorted(plugins: Vec<Arc<dyn ProxyPlugin>>) -> Self {
        debug_assert!(
            plugins
                .windows(2)
                .all(|window| window[0].priority() >= window[1].priority()),
            "ProxyPluginExecutor::from_sorted requires priority-descending input"
        );
        let mut early_request = Vec::new();
        let mut request = Vec::new();
        let mut upstream_request = Vec::new();
        let mut request_body = Vec::new();
        let mut response = Vec::new();
        let mut response_body = Vec::new();
        let mut logging = Vec::new();
        for plugin in &plugins {
            let phases = plugin.phases();
            if phases.contains(PluginPhases::EARLY_REQUEST) {
                early_request.push(plugin.clone());
            }
            if phases.contains(PluginPhases::REQUEST) {
                request.push(plugin.clone());
            }
            if phases.contains(PluginPhases::UPSTREAM_REQUEST) {
                upstream_request.push(plugin.clone());
            }
            if phases.contains(PluginPhases::REQUEST_BODY) {
                request_body.push(plugin.clone());
            }
            if phases.contains(PluginPhases::RESPONSE) {
                response.push(plugin.clone());
            }
            if phases.contains(PluginPhases::RESPONSE_BODY) {
                response_body.push(plugin.clone());
            }
            if phases.contains(PluginPhases::LOGGING) {
                logging.push(plugin.clone());
            }
        }
        Self {
            plugins,
            early_request,
            request,
            upstream_request,
            request_body,
            response,
            response_body,
            logging,
        }
    }

    pub fn has_plugin(&self, name: &str) -> bool {
        self.plugins.iter().any(|plugin| plugin.name() == name)
    }

    /// Gateway-exit transformation rules contributed by a plugin in this layer.
    pub fn exit_transform(&self) -> Option<&crate::core::ExitTransform> {
        self.plugins
            .iter()
            .find_map(|plugin| plugin.exit_transform())
    }

    /// Read-only access to the ordered plugin list.
    pub fn plugins(&self) -> &[Arc<dyn ProxyPlugin>] {
        &self.plugins
    }

    /// Returns shared empty executor instance to minimize memory allocation.
    pub fn default_shared() -> Arc<Self> {
        DEFAULT_PLUGIN_EXECUTOR.clone()
    }
}

#[async_trait]
impl ProxyPlugin for ProxyPluginExecutor {
    fn name(&self) -> &str {
        "plugin-executor"
    }

    fn priority(&self) -> i32 {
        0
    }

    fn phases(&self) -> PluginPhases {
        PluginPhases::ALL
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        for plugin in self.request.iter() {
            if plugin.request_filter(session, ctx).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for_each_plugin_async!(self.early_request, early_request_filter, session, ctx);
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for_each_plugin_async!(
            self.upstream_request,
            upstream_request_filter,
            session,
            upstream_request,
            ctx
        );
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for_each_plugin_async!(
            self.response,
            response_filter,
            session,
            upstream_response,
            ctx
        );
        Ok(())
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for_each_plugin_async!(
            self.request_body,
            request_body_filter,
            session,
            body,
            end_of_stream,
            ctx
        );
        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        if !self.response_body.is_empty() {
            for_each_plugin_sync!(
                self.response_body,
                response_body_filter,
                session,
                body,
                end_of_stream,
                ctx
            );
        }
        Ok(())
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) {
        for_each_plugin_async_unit!(self.logging, logging, session, e, ctx);
    }
}

/// Shared empty pipeline used when no route matched or no plugins are configured.
static DEFAULT_PLUGIN_PIPELINE: Lazy<Arc<CompiledPluginPipeline>> =
    Lazy::new(|| Arc::new(CompiledPluginPipeline::default()));

/// Compiled per-request plugin composition: global rules then route/service.
///
/// Owns the layer-precedence policy that previously lived in `HttpService`'s
/// `run_global_then_route_*` helpers: global plugins always run first, a global
/// `request_filter` short-circuit skips the route layer, and every phase
/// traverses global → route. Both layers arrive already ordered from their
/// builders, so no per-request sorting or merge happens here.
#[derive(Clone)]
pub struct CompiledPluginPipeline {
    global: Arc<ProxyPluginExecutor>,
    route: Arc<ProxyPluginExecutor>,
}

impl Default for CompiledPluginPipeline {
    fn default() -> Self {
        Self {
            global: ProxyPluginExecutor::default_shared(),
            route: ProxyPluginExecutor::default_shared(),
        }
    }
}

impl CompiledPluginPipeline {
    pub fn new(global: Arc<ProxyPluginExecutor>, route: Arc<ProxyPluginExecutor>) -> Self {
        Self { global, route }
    }

    /// Shared empty pipeline with no plugins in either layer.
    pub fn empty() -> Arc<Self> {
        DEFAULT_PLUGIN_PIPELINE.clone()
    }

    /// Whether either layer contains a plugin named `name` (e.g. CORS preflight).
    pub fn has_plugin(&self, name: &str) -> bool {
        self.global.has_plugin(name) || self.route.has_plugin(name)
    }

    /// Gateway-exit transformation rules for this request, if any.
    ///
    /// Route/service configuration wins over global rules (more specific
    /// scope overrides the broader one), mirroring the layer-precedence policy
    /// of the phase methods below.
    pub fn exit_transform(&self) -> Option<&crate::core::ExitTransform> {
        self.route
            .exit_transform()
            .or_else(|| self.global.exit_transform())
    }

    /// Run global-rule plugins then route/service plugins for `early_request_filter`.
    pub async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.global.early_request_filter(session, ctx).await?;
        self.route.early_request_filter(session, ctx).await
    }

    /// Run global-rule plugins then route/service plugins for `request_filter`.
    ///
    /// Returns `true` when a plugin short-circuits the request. Global plugins
    /// run first; a global short-circuit skips the route layer entirely.
    pub async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<bool> {
        if self.global.request_filter(session, ctx).await? {
            return Ok(true);
        }
        self.route.request_filter(session, ctx).await
    }

    /// Run global-rule plugins then route/service plugins for `upstream_request_filter`.
    pub async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.global
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;
        self.route
            .upstream_request_filter(session, upstream_request, ctx)
            .await
    }

    /// Run global-rule plugins then route/service plugins for `response_filter`.
    pub async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.global
            .response_filter(session, upstream_response, ctx)
            .await?;
        self.route
            .response_filter(session, upstream_response, ctx)
            .await
    }

    /// Run global-rule plugins then route/service plugins for `response_body_filter`.
    pub fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.global
            .response_body_filter(session, body, end_of_stream, ctx)?;
        self.route
            .response_body_filter(session, body, end_of_stream, ctx)
    }

    /// Run global-rule plugins then route/service plugins for `request_body_filter`.
    pub async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.global
            .request_body_filter(session, body, end_of_stream, ctx)
            .await?;
        self.route
            .request_body_filter(session, body, end_of_stream, ctx)
            .await
    }

    /// Run global-rule plugins then route/service plugins for `logging`.
    pub async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) {
        self.global.logging(session, e, ctx).await;
        self.route.logging(session, e, ctx).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BodyFilterPlugin;

    #[async_trait]
    impl ProxyPlugin for BodyFilterPlugin {
        fn name(&self) -> &str {
            "body-filter"
        }

        fn priority(&self) -> i32 {
            0
        }

        fn phases(&self) -> PluginPhases {
            PluginPhases::RESPONSE_BODY
        }
    }

    struct LoggingOnlyPlugin;

    #[async_trait]
    impl ProxyPlugin for LoggingOnlyPlugin {
        fn name(&self) -> &str {
            "logging-only"
        }

        fn priority(&self) -> i32 {
            0
        }

        fn phases(&self) -> PluginPhases {
            PluginPhases::LOGGING
        }
    }

    #[test]
    fn test_executor_partitions_response_body_phase() {
        let executor = ProxyPluginExecutor::new(vec![Arc::new(BodyFilterPlugin)]);
        assert!(executor.request.is_empty());
        assert_eq!(executor.response_body.len(), 1);
    }

    #[test]
    fn logging_only_plugin_is_skipped_on_request_phase() {
        let executor = ProxyPluginExecutor::new(vec![Arc::new(LoggingOnlyPlugin)]);
        assert!(executor.request.is_empty());
        assert!(executor.early_request.is_empty());
        assert_eq!(executor.logging.len(), 1);
        assert_eq!(executor.plugins().len(), 1);
        assert!(executor.has_plugin("logging-only"));
    }

    #[test]
    fn new_sorts_plugins_by_priority_desc() {
        let low: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "low",
            priority: 10,
        });
        let high: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "high",
            priority: 100,
        });
        let executor = ProxyPluginExecutor::new(vec![low.clone(), high.clone()]);
        let names: Vec<&str> = executor.plugins().iter().map(|p| p.name()).collect();
        assert_eq!(names, vec!["high", "low"]);
    }

    #[test]
    fn new_breaks_ties_by_name() {
        let zebra: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "zebra",
            priority: 50,
        });
        let alpha: Arc<dyn ProxyPlugin> = Arc::new(DummyPlugin {
            name: "alpha",
            priority: 50,
        });
        let executor = ProxyPluginExecutor::new(vec![zebra, alpha]);
        let names: Vec<&str> = executor.plugins().iter().map(|p| p.name()).collect();
        assert_eq!(names, vec!["alpha", "zebra"]);
    }

    struct DummyPlugin {
        name: &'static str,
        priority: i32,
    }

    #[async_trait]
    impl ProxyPlugin for DummyPlugin {
        fn name(&self) -> &str {
            self.name
        }

        fn priority(&self) -> i32 {
            self.priority
        }
    }
}
