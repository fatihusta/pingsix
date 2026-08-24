//! Plugin system for the Pingsix proxy.
//!
//! Provides the plugin trait, executor, context, and URI rewriting utilities.

mod pipeline;
mod rewrite;
mod upstream;

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use serde_json::Value as JsonValue;

use crate::core::error::ProxyResult;

pub use pipeline::{
    CompiledPluginPipeline, ProxyContext, ProxyPluginExecutor, RouteContext, RouteLabels,
};

// ---------------------------------------------------------------------------
// T10 frozen contract — the plugin request-phase rejection contract.
//
// These definitions are the single sanctioned shape plugin rejections take.
// Reshaping them requires a coordinated update of every plugin (T11 groups)
// and the docs (T12); do not change them casually. The wire behavior they
// induce (one write through `utils::response::send_exit_response`, so
// `exit-transformer` rules apply uniformly) is pinned by
// `tests/plugin_gateway_rejections.rs`.
// ---------------------------------------------------------------------------

/// Verdict returned by [`ProxyPlugin::request_filter`] (T10 frozen contract).
///
/// A plugin NEVER writes a rejection response to the session itself: it
/// returns a value, and the compiled pipeline writes it through the shared
/// exit-response helper exactly once. "The plugin remembered the transform" is
/// therefore unrepresentable — `exit-transformer` rules apply uniformly to
/// every gateway-generated rejection.
#[derive(Debug)]
pub enum FilterVerdict {
    /// The request proceeds: remaining plugins in the layer run, then routing/
    /// proxying continues.
    Continue,
    /// The request is short-circuited with a gateway-generated response. The
    /// pipeline writes it; remaining plugins in the layer do not run.
    Reject(Rejection),
}

/// A gateway-generated rejection response, as a plain value (T10 frozen
/// contract).
///
/// Carries everything the two historical write helpers
/// (`send_exit_response` / the deleted `ResponseBuilder::send_proxy_error`)
/// accepted at their call sites. The pipeline renders it through
/// `send_exit_response`, so the uniform behaviors (1xx/204/304 body strip,
/// close-delimited keep-alive fix, `$status`/`$message`/`$request_id`
/// templating, `exit-transformer` rules) apply to every plugin equally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// HTTP status of the rejection (`exit-transformer` matches on this code).
    pub status: StatusCode,
    /// Optional response body. `exit-transformer` templates it as `$message`.
    pub body: Option<String>,
    /// Content-Type for the body. Only emitted when a non-empty body is sent.
    pub content_type: Option<String>,
    /// Extra response headers (appended verbatim, in order).
    pub headers: Vec<(String, String)>,
    /// `true` drops downstream keep-alive after the response (Pingora closes
    /// the connection). Mirrors limit-count's historical
    /// `session.set_keepalive(None)` on 429s; the pipeline applies it because
    /// it owns the session at write time, not the plugin.
    pub close_connection: bool,
}

impl Rejection {
    /// A bodyless rejection with the given status.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            body: None,
            content_type: None,
            headers: Vec::new(),
            close_connection: false,
        }
    }

    /// Attach a response body.
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set the body's content type (only emitted when a body is sent).
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Append one response header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Append response headers, preserving order.
    pub fn with_headers(mut self, headers: impl IntoIterator<Item = (String, String)>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Mark the downstream connection for closure after the response.
    pub fn with_close_connection(mut self) -> Self {
        self.close_connection = true;
        self
    }
}

/// A plugin instance paired with the lifecycle phases it declares (T10 frozen
/// contract).
///
/// This is the external-plugin escape hatch for phases: [`ProxyPlugin`] is a
/// public trait implementable outside the crate, so hook-phase declarations
/// are construction data rather than a trait method (which would let the
/// declaration silently disagree with the implemented hooks). Builtin plugins
/// get their phases from `PLUGIN_META`; embedders constructing a
/// [`ProxyPluginExecutor`] with their own plugins pass
/// `PluginEntry::new(plugin, PHASES)` per plugin.
#[derive(Clone)]
pub struct PluginEntry {
    /// The plugin instance.
    pub plugin: Arc<dyn ProxyPlugin>,
    /// The lifecycle phases the executor must partition this plugin into.
    pub phases: PluginPhases,
}

impl PluginEntry {
    pub fn new(plugin: Arc<dyn ProxyPlugin>, phases: PluginPhases) -> Self {
        Self { plugin, phases }
    }

    /// Plugin name (forwarded for ordering and lookup).
    pub fn name(&self) -> &str {
        self.plugin.name()
    }

    /// Plugin priority (forwarded for ordering).
    pub fn priority(&self) -> i32 {
        self.plugin.priority()
    }
}
pub use rewrite::apply_regex_uri_template;
pub use upstream::{
    HealthCheckFingerprint, HealthCheckSpec, PassiveOutcome, SelectedUpstream, UpstreamSelection,
    UpstreamSelector,
};

/// One declarative rewrite rule for gateway-generated error responses
/// (APISIX `exit-transformer` semantics, expressed declaratively instead of
/// Lua callbacks).
///
/// A rule matches when the gateway is about to send `codes` as an error
/// status; it may then remap the status, replace the body, and add headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitTransformRule {
    /// Gateway exit statuses this rule matches (e.g. 401, 502).
    pub codes: Vec<u16>,
    /// Replacement status code; the matched status is kept when `None`.
    pub status_code: Option<u16>,
    /// Replacement body with `$status`/`$message`/`$request_id` variables.
    pub body: Option<String>,
    /// Headers to add or override on the transformed response. A
    /// `Content-Type` entry (case-insensitive) sets the transformed body's
    /// content type instead of being inserted twice.
    pub headers: Vec<(String, String)>,
}

/// Compiled configuration of the `exit-transformer` plugin: an ordered rule
/// list evaluated first-match-wins against gateway exit statuses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitTransform {
    pub rules: Vec<ExitTransformRule>,
}

impl ExitTransform {
    /// First rule matching `status`, if any.
    pub fn matching(&self, status: u16) -> Option<&ExitTransformRule> {
        self.rules.iter().find(|rule| rule.codes.contains(&status))
    }
}

/// Bitmask of plugin lifecycle phases a plugin actually implements.
///
/// Executors partition their plugin lists with this so hot-path phases skip
/// default no-op hooks. Combine constants with [`BitOr`](std::ops::BitOr).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PluginPhases(u8);

impl PluginPhases {
    pub const EARLY_REQUEST: Self = Self(1 << 0);
    pub const REQUEST: Self = Self(1 << 1);
    pub const UPSTREAM_REQUEST: Self = Self(1 << 2);
    pub const REQUEST_BODY: Self = Self(1 << 3);
    pub const RESPONSE: Self = Self(1 << 4);
    pub const RESPONSE_BODY: Self = Self(1 << 5);
    pub const LOGGING: Self = Self(1 << 6);
    pub const UPSTREAM_PEER: Self = Self(1 << 7);

    pub const ALL: Self = Self(
        Self::EARLY_REQUEST.0
            | Self::REQUEST.0
            | Self::UPSTREAM_REQUEST.0
            | Self::REQUEST_BODY.0
            | Self::RESPONSE.0
            | Self::RESPONSE_BODY.0
            | Self::LOGGING.0
            | Self::UPSTREAM_PEER.0,
    );

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for PluginPhases {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// Type alias for plugin initialization functions.
///
/// `defaults` carries the owning gateway instance's effective
/// `pingsix.defaults` (resolved at startup) so plugin construction can honor
/// instance-scoped fallbacks (e.g. cache capacity).
pub type PluginCreateFn =
    fn(JsonValue, &crate::config::EffectiveDefaults) -> ProxyResult<Arc<dyn ProxyPlugin>>;

/// The core plugin trait that defines the lifecycle hooks for proxy plugins.
///
/// Plugin execution follows APISIX's phase model for consistency with existing ecosystems.
///
/// # Phase declaration (T10)
///
/// The executor invokes a plugin's hook only if the phase was declared at
/// construction time, so a plugin whose declaration disagrees with its hooks
/// cannot be wired accidentally: builtin plugins declare phases once in
/// `PLUGIN_META` (`src/plugins/mod.rs`); embedders implementing this trait
/// outside the crate declare phases per plugin when building a
/// [`ProxyPluginExecutor`], via [`PluginEntry::new`]. There is deliberately no
/// `phases()` method on this trait.
///
/// # Request-phase rejection (T10)
///
/// `request_filter` returns a [`FilterVerdict`]: [`FilterVerdict::Continue`]
/// to proceed, [`FilterVerdict::Reject`] to short-circuit with a
/// gateway-generated response the pipeline writes on the plugin's behalf.
/// Plugins must never write rejection responses to the session from
/// `request_filter` themselves.
#[async_trait]
pub trait ProxyPlugin: Send + Sync {
    /// Return the name of this plugin.
    fn name(&self) -> &str;

    /// Return the priority of this plugin.
    fn priority(&self) -> i32;

    /// Typed health-check specs with stable fingerprints for incremental
    /// reconcile. Only plugins that own background maintenance register here;
    /// the default is no specs.
    fn health_check_specs(&self) -> Vec<HealthCheckSpec> {
        Vec::new()
    }

    /// Gateway-exit transformation rules contributed by this plugin.
    ///
    /// Only the `exit-transformer` plugin overrides this; the shared exit
    /// response helper (`utils::response::send_exit_response`) consults it so
    /// every gateway-generated rejection flows through one configurable path.
    /// The default is no transformation.
    fn exit_transform(&self) -> Option<&ExitTransform> {
        None
    }

    /// Handle the incoming request in the access phase.
    ///
    /// Use this phase for: request validation, authentication, rate limiting,
    /// access control, and early response generation.
    /// Corresponds to APISIX's rewrite/access phase.
    ///
    /// Return [`FilterVerdict::Reject`] to short-circuit the request with a
    /// gateway-generated response; the pipeline writes it through the shared
    /// exit-response helper exactly once (so `exit-transformer` applies
    /// uniformly) and skips the remaining plugins in the layer.
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        Ok(FilterVerdict::Continue)
    }

    /// Handle the incoming request before any downstream processing.
    ///
    /// Use this for early request inspection and modification before
    /// core proxy logic executes.
    async fn early_request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Modify the request before it is sent to the upstream.
    ///
    /// Use this for: adding authentication headers, request transformation,
    /// and upstream-specific modifications.
    /// Corresponds to APISIX's before_proxy phase.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Modify the response header before it is sent to the downstream.
    ///
    /// Use this for: adding security headers, CORS handling, and response transformation.
    /// Corresponds to APISIX's header_filter phase.
    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Handle request body chunks as they stream from the downstream.
    ///
    /// Use this for: WAF inspection, upload size limits, and body validation.
    /// Return an error to abort the request (mapped by the service's
    /// `fail_to_proxy`, e.g. `PayloadTooLarge` -> 413). Corresponds to
    /// APISIX's body inspection during the request phase.
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Handle the response body chunks.
    ///
    /// Use this for: content compression, body transformation, and filtering.
    /// Corresponds to APISIX's body_filter phase.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Adjust the selected upstream peer after route/upstream selection and
    /// before the peer is handed to Pingora.
    ///
    /// Use this for request-scoped peer policy the plugin owns (timeout
    /// floors, TLS verification overrides). Route-scoped policy (route
    /// timeout, WebSocket relaxation) has already been applied by the
    /// caller, so plugin adjustments run last in the precedence chain.
    /// Invoked only when [`Self::phases`] declares
    /// [`PluginPhases::UPSTREAM_PEER`].
    fn upstream_peer_filter(
        &self,
        _session: &mut Session,
        _peer: &mut HttpPeer,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Called after the complete response is sent or on fatal error.
    ///
    /// Use this for: metrics collection, access logging, cleanup operations.
    /// Error logging is already handled by the framework.
    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, _ctx: &mut ProxyContext) {}
}

/// Sort plugin entries deterministically by:
/// - higher priority first
/// - for ties, sort by plugin name
pub fn sort_plugins_by_priority_desc(entries: &mut [PluginEntry]) {
    entries.sort_by(|a, b| {
        b.priority()
            .cmp(&a.priority())
            .then_with(|| a.name().cmp(b.name()))
    });
}
