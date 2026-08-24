//! Request context, plugin executor, and compiled global+route pipeline.
//!
//! `ProxyContext` and `CompiledPluginPipeline` live together because each
//! request stores the pipeline on the context, and pipeline methods mutate
//! that context.

use std::{any::Any, collections::HashMap, sync::Arc, time::Instant};

use async_trait::async_trait;
use bytes::Bytes;
use once_cell::sync::Lazy;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

use crate::core::error::ProxyResult;

use super::upstream::{SelectedUpstream, UpstreamSelection, UpstreamSelector};
use super::{sort_plugins_by_priority_desc, FilterVerdict, PluginEntry, PluginPhases, ProxyPlugin};

/// Context key for the generic "request body was replaced by a plugin" marker
/// (see [`ProxyContext::mark_request_body_replaced`]).
const REQUEST_BODY_REPLACED_KEY: &str = "core::request_body_replaced";

/// Trait for route behavior that can be used in proxy context.
///
/// Lives next to [`ProxyPluginExecutor`] because `build_plugin_executor`
/// returns that type; moving it to `upstream` would cycle the modules.
///
/// This seam carries only what the request path provably needs (identity,
/// upstream selection, per-route peer policy, cache namespacing). Descriptive
/// metadata used to derive observability labels lives behind the optional
/// [`RouteLabels`] side trait reached via [`RouteContext::labels`].
pub trait RouteContext: Send + Sync {
    /// Get the route identifier.
    fn id(&self) -> &str;

    /// Whether WebSocket upgrade requests are enabled for this route.
    ///
    /// Read by the service's `upstream_peer` (peer timeout relaxation), so it
    /// stays on the request-path seam rather than the label side trait.
    fn enable_websocket(&self) -> bool {
        false
    }

    /// Select an upstream peer for the route, compiling the selection artifact
    /// (peer plus owning selector) used by all downstream callbacks.
    fn select_upstream(&self, session: &mut Session) -> ProxyResult<UpstreamSelection>;

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

    /// Route-level timeout; applied by the service's upstream selection to
    /// every selection path (route and traffic-split override).
    fn timeout(&self) -> Option<&crate::config::Timeout>;

    /// Optional descriptive metadata for label-deriving plugins. `None` (the
    /// default) means the implementation carries no label data; callers fall
    /// back to label-free behavior, matching the old per-method defaults.
    fn labels(&self) -> Option<&dyn RouteLabels> {
        None
    }
}

/// Optional, non-hot-path route metadata: human-readable names, matching
/// templates, and host patterns.
///
/// Kept off [`RouteContext`] so the cycle-breaker seam only pays for what the
/// request path uses. Observability plugins (e.g. prometheus) opt into this
/// trait via [`RouteContext::labels`] to derive bounded metric labels from
/// route configuration instead of attacker-controllable request input.
pub trait RouteLabels: Send + Sync {
    /// Optional human-readable route name from configuration.
    fn name(&self) -> Option<&str> {
        None
    }

    /// Get the service ID if available.
    fn service_id(&self) -> Option<&str> {
        None
    }

    /// Optional human-readable service name from the bound service configuration.
    fn service_name(&self) -> Option<&str> {
        None
    }

    /// Return the configured URI template used to match this route.
    fn uri_template(&self) -> Option<&str> {
        None
    }

    /// Return the effective host patterns used to match this route.
    fn effective_hosts(&self) -> &[String] {
        &[]
    }
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
    /// Bytes of the downstream request body streamed through the request-body
    /// pipeline so far. Unowned by any plugin and updated in place; avoids
    /// per-chunk `vars` allocation for body-size accounting (e.g.
    /// `client-control`).
    pub request_body_bytes: u64,
    /// Unique request identifier, set by request-id plugin if enabled.
    pub request_id: Option<String>,
    /// Whether the original downstream request contained authentication/session credentials.
    /// Captured before plugins can remove or rewrite headers (Authorization, Proxy-Authorization, Cookie).
    pub original_request_had_credentials: bool,
    /// Set when any auth plugin observes credentials (including custom headers/query).
    pub request_has_credentials: bool,
    /// Digest of the original request's standard credential headers
    /// (Authorization, Proxy-Authorization, Cookie), captured in
    /// `early_request_filter` before any plugin can strip or rewrite them.
    /// Consumed by shared-cache consumer isolation.
    pub original_credential_digest: Option<String>,
    /// Digest of the raw credential successfully verified by an auth plugin
    /// (covers carriers beyond the standard headers: custom headers, query
    /// params, cookies). Multiple auth plugins combine order-sensitively.
    pub noted_credential_digest: Option<String>,
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
            request_body_bytes: 0,
            request_id: None,
            original_request_had_credentials: false,
            request_has_credentials: false,
            original_credential_digest: None,
            noted_credential_digest: None,
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

    /// Record the raw credential an auth plugin just verified, hashed into a
    /// stable digest so shared-cache consumer isolation can vary the cache
    /// key per credential without retaining plaintext. Call before hiding
    /// the credential from the upstream request. Multiple auth plugins on
    /// one request combine order-sensitively.
    pub fn note_request_credential(&mut self, credential: &str) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"pingsix-request-credential-v1\0");
        if let Some(previous) = &self.noted_credential_digest {
            hasher.update(previous.as_bytes());
            hasher.update([0]);
        }
        hasher.update(credential.as_bytes());
        self.noted_credential_digest = Some(hex::encode(hasher.finalize()));
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
    /// Plugin entries (instance + declared phases) in deterministic execution
    /// order (priority descending).
    plugins: Vec<PluginEntry>,
    early_request: Vec<Arc<dyn ProxyPlugin>>,
    request: Vec<Arc<dyn ProxyPlugin>>,
    upstream_request: Vec<Arc<dyn ProxyPlugin>>,
    request_body: Vec<Arc<dyn ProxyPlugin>>,
    response: Vec<Arc<dyn ProxyPlugin>>,
    response_body: Vec<Arc<dyn ProxyPlugin>>,
    logging: Vec<Arc<dyn ProxyPlugin>>,
    upstream_peer: Vec<Arc<dyn ProxyPlugin>>,
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
    /// Sort plugin entries deterministically (priority desc, then name asc) and build.
    pub fn new(plugins: Vec<PluginEntry>) -> Self {
        let mut plugins = plugins;
        sort_plugins_by_priority_desc(&mut plugins);
        Self::from_sorted(plugins)
    }

    /// Build from an already-ordered entry list.
    ///
    /// The precondition is a non-increasing priority sequence; tie order is
    /// whatever the caller produced (e.g. the route-over-service merge prefers
    /// the route side on equal priority). In debug builds this is asserted.
    pub fn from_sorted(plugins: Vec<PluginEntry>) -> Self {
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
        let mut upstream_peer = Vec::new();
        for entry in &plugins {
            let phases = entry.phases;
            let plugin = &entry.plugin;
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
            if phases.contains(PluginPhases::UPSTREAM_PEER) {
                upstream_peer.push(plugin.clone());
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
            upstream_peer,
        }
    }

    pub fn has_plugin(&self, name: &str) -> bool {
        self.plugins.iter().any(|entry| entry.name() == name)
    }

    /// Whether the plugin named `name` was partitioned into `phase` at
    /// construction. A single-bit `PluginPhases` identifies one partition;
    /// any other input (empty, `ALL`, or a union) returns `false`.
    ///
    /// Exposed so construction wiring (builtin `PLUGIN_META` phases, embedder
    /// declarations) can be asserted through the public API instead of
    /// mirroring data; also useful for diagnostics.
    pub fn has_plugin_in_phase(&self, name: &str, phase: PluginPhases) -> bool {
        let partition: &[Arc<dyn ProxyPlugin>] = if phase == PluginPhases::EARLY_REQUEST {
            &self.early_request
        } else if phase == PluginPhases::REQUEST {
            &self.request
        } else if phase == PluginPhases::UPSTREAM_REQUEST {
            &self.upstream_request
        } else if phase == PluginPhases::REQUEST_BODY {
            &self.request_body
        } else if phase == PluginPhases::RESPONSE {
            &self.response
        } else if phase == PluginPhases::RESPONSE_BODY {
            &self.response_body
        } else if phase == PluginPhases::LOGGING {
            &self.logging
        } else if phase == PluginPhases::UPSTREAM_PEER {
            &self.upstream_peer
        } else {
            return false;
        };
        partition.iter().any(|plugin| plugin.name() == name)
    }

    /// Gateway-exit transformation rules contributed by a plugin in this layer.
    pub fn exit_transform(&self) -> Option<&crate::core::ExitTransform> {
        self.plugins
            .iter()
            .find_map(|entry| entry.plugin.exit_transform())
    }

    /// Read-only access to the ordered plugin entries.
    pub fn plugins(&self) -> &[PluginEntry] {
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

    /// Aggregate this layer's request-phase plugins into one verdict: the
    /// first non-`Continue` verdict wins; the pipeline (not this layer) owns
    /// writing the rejection to the session.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        for plugin in self.request.iter() {
            match plugin.request_filter(session, ctx).await? {
                FilterVerdict::Continue => {}
                verdict => return Ok(verdict),
            }
        }
        Ok(FilterVerdict::Continue)
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

    fn upstream_peer_filter(
        &self,
        session: &mut Session,
        peer: &mut HttpPeer,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        for_each_plugin_sync!(self.upstream_peer, upstream_peer_filter, session, peer, ctx);
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
    /// run first; a global rejection skips the route layer entirely.
    ///
    /// The single write choke point for plugin short-circuits: a returned
    /// [`FilterVerdict::Reject`] is written through the shared exit-response
    /// helper exactly once, so `exit-transformer` rules apply to every plugin
    /// rejection (T10 contract).
    pub async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<bool> {
        let verdict = match self.global.request_filter(session, ctx).await? {
            FilterVerdict::Continue => self.route.request_filter(session, ctx).await?,
            verdict => verdict,
        };
        match verdict {
            FilterVerdict::Continue => Ok(false),
            FilterVerdict::Reject(rejection) => {
                crate::utils::response::send_rejection(session, &rejection, ctx).await?;
                Ok(true)
            }
        }
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

    /// Run global-rule plugins then route/service plugins for
    /// `upstream_peer_filter`, after route-scoped peer policy (route timeout,
    /// WebSocket relaxation) has been applied by the caller.
    pub fn upstream_peer_filter(
        &self,
        session: &mut Session,
        peer: &mut HttpPeer,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        self.global.upstream_peer_filter(session, peer, ctx)?;
        self.route.upstream_peer_filter(session, peer, ctx)
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
    use crate::utils::testing::noop_session;

    struct BodyFilterPlugin;

    #[async_trait]
    impl ProxyPlugin for BodyFilterPlugin {
        fn name(&self) -> &str {
            "body-filter"
        }

        fn priority(&self) -> i32 {
            0
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
    }

    #[test]
    fn test_executor_partitions_response_body_phase() {
        let executor = ProxyPluginExecutor::new(vec![PluginEntry::new(
            Arc::new(BodyFilterPlugin),
            PluginPhases::RESPONSE_BODY,
        )]);
        assert!(executor.request.is_empty());
        assert_eq!(executor.response_body.len(), 1);
    }

    #[test]
    fn note_request_credential_hashes_and_combines_in_order() {
        let mut ctx = ProxyContext::default();
        assert!(ctx.noted_credential_digest.is_none());

        ctx.note_request_credential("key-a");
        let first = ctx.noted_credential_digest.clone().unwrap();
        // Digests are hex SHA-256 and never contain the plaintext.
        assert_eq!(first.len(), 64);
        assert!(!first.contains("key-a"));

        // Same credential digests identically on a fresh context.
        let mut again = ProxyContext::default();
        again.note_request_credential("key-a");
        assert_eq!(
            again.noted_credential_digest.as_deref(),
            Some(first.as_str())
        );

        // A second, different credential (a second auth plugin) combines
        // order-sensitively into a different digest.
        ctx.note_request_credential("key-b");
        let combined = ctx.noted_credential_digest.clone().unwrap();
        assert_ne!(combined, first);
        assert_eq!(combined.len(), 64);

        let mut reordered = ProxyContext::default();
        reordered.note_request_credential("key-b");
        reordered.note_request_credential("key-a");
        assert_ne!(
            reordered.noted_credential_digest, ctx.noted_credential_digest,
            "combination must be order-sensitive"
        );
    }

    #[test]
    fn test_executor_partitions_upstream_peer_phase() {
        struct PeerPlugin {
            name: &'static str,
            marker: &'static str,
        }

        impl ProxyPlugin for PeerPlugin {
            fn name(&self) -> &str {
                self.name
            }

            fn priority(&self) -> i32 {
                0
            }

            fn upstream_peer_filter(
                &self,
                _session: &mut Session,
                peer: &mut HttpPeer,
                ctx: &mut ProxyContext,
            ) -> Result<()> {
                let order = ctx.get_str("peer_filter_order").unwrap_or("").to_string();
                ctx.set("peer_filter_order", format!("{order}{}", self.marker));
                ctx.set("peer_filter_ran", peer.sni.clone());
                Ok(())
            }
        }

        let executor = ProxyPluginExecutor::new(vec![PluginEntry::new(
            Arc::new(PeerPlugin {
                name: "route-peer",
                marker: "r",
            }),
            PluginPhases::UPSTREAM_PEER,
        )]);
        assert!(executor.request.is_empty());
        assert_eq!(executor.upstream_peer.len(), 1);

        // Pipeline traversal: global layer runs before the route layer and
        // both partitions are consulted for the new phase.
        let mut peer = HttpPeer::new("127.0.0.1:9443", true, "provider.internal".to_string());
        let global = Arc::new(ProxyPluginExecutor::new(vec![PluginEntry::new(
            Arc::new(PeerPlugin {
                name: "global-peer",
                marker: "g",
            }),
            PluginPhases::UPSTREAM_PEER,
        )]));
        let pipeline = CompiledPluginPipeline::new(global, Arc::new(executor));
        let mut ctx = ProxyContext::default();
        let mut session = noop_session();
        pipeline
            .upstream_peer_filter(&mut session, &mut peer, &mut ctx)
            .unwrap();
        assert_eq!(ctx.get_str("peer_filter_order"), Some("gr"));
        assert_eq!(ctx.get_str("peer_filter_ran"), Some("provider.internal"));
    }

    #[test]
    fn logging_only_plugin_is_skipped_on_request_phase() {
        let executor = ProxyPluginExecutor::new(vec![PluginEntry::new(
            Arc::new(LoggingOnlyPlugin),
            PluginPhases::LOGGING,
        )]);
        assert!(executor.request.is_empty());
        assert!(executor.early_request.is_empty());
        assert_eq!(executor.logging.len(), 1);
        assert_eq!(executor.plugins().len(), 1);
        assert!(executor.has_plugin("logging-only"));
    }

    #[test]
    fn new_sorts_plugins_by_priority_desc() {
        let no_hook = PluginPhases::empty();
        let low = PluginEntry::new(
            Arc::new(DummyPlugin {
                name: "low",
                priority: 10,
            }),
            no_hook,
        );
        let high = PluginEntry::new(
            Arc::new(DummyPlugin {
                name: "high",
                priority: 100,
            }),
            no_hook,
        );
        let executor = ProxyPluginExecutor::new(vec![low, high]);
        let names: Vec<&str> = executor.plugins().iter().map(|p| p.name()).collect();
        assert_eq!(names, vec!["high", "low"]);
    }

    #[test]
    fn new_breaks_ties_by_name() {
        let zebra = PluginEntry::new(
            Arc::new(DummyPlugin {
                name: "zebra",
                priority: 50,
            }),
            PluginPhases::empty(),
        );
        let alpha = PluginEntry::new(
            Arc::new(DummyPlugin {
                name: "alpha",
                priority: 50,
            }),
            PluginPhases::empty(),
        );
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

    struct RejectingPlugin;

    #[async_trait]
    impl ProxyPlugin for RejectingPlugin {
        fn name(&self) -> &str {
            "rejecting"
        }

        fn priority(&self) -> i32 {
            100
        }

        async fn request_filter(
            &self,
            _session: &mut Session,
            _ctx: &mut ProxyContext,
        ) -> Result<FilterVerdict> {
            Ok(FilterVerdict::Reject(
                super::super::Rejection::new(http::StatusCode::IM_A_TEAPOT)
                    .with_body("short and stout")
                    .with_content_type("text/plain")
                    .with_header("X-Reject", "yes"),
            ))
        }
    }

    #[tokio::test]
    async fn pipeline_writes_a_rejection_exactly_once_and_returns_true() {
        let after_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        struct Probe(std::sync::Arc<std::sync::atomic::AtomicBool>);
        #[async_trait]
        impl ProxyPlugin for Probe {
            fn name(&self) -> &str {
                "probe"
            }
            fn priority(&self) -> i32 {
                1
            }
            async fn request_filter(
                &self,
                _session: &mut Session,
                _ctx: &mut ProxyContext,
            ) -> Result<FilterVerdict> {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(FilterVerdict::Continue)
            }
        }

        let route = Arc::new(ProxyPluginExecutor::new(vec![
            PluginEntry::new(Arc::new(RejectingPlugin), PluginPhases::REQUEST),
            PluginEntry::new(Arc::new(Probe(after_ran.clone())), PluginPhases::REQUEST),
        ]));
        let pipeline = CompiledPluginPipeline::new(ProxyPluginExecutor::default_shared(), route);
        let (mut session, written) = crate::utils::testing::session_for(
            crate::utils::testing::http_get_wire("/", &[]).as_bytes(),
        )
        .await;
        let mut ctx = ProxyContext {
            pipeline: pipeline.clone(),
            ..ProxyContext::default()
        };

        let short_circuited = pipeline
            .request_filter(&mut session, &mut ctx)
            .await
            .expect("no error");
        assert!(short_circuited);
        assert!(
            !after_ran.load(std::sync::atomic::Ordering::SeqCst),
            "a rejection stops the rest of the layer"
        );
        drop(session);
        let out = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        assert!(out.starts_with("HTTP/1.1 418 "), "got: {out}");
        assert!(
            out.matches("418").count() >= 1 && out.contains("short and stout"),
            "one response written: {out}"
        );
        assert!(out.contains("X-Reject: yes"), "got: {out}");
        assert!(
            !out.contains("405"),
            "exactly one status line, one write: {out}"
        );
        assert_eq!(out.matches("HTTP/1.1").count(), 1, "got: {out}");
    }
}
