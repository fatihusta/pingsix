//! Plugin system for the Pingsix proxy.
//!
//! Provides the plugin trait, executor, context, and URI rewriting utilities.

mod pipeline;
mod rewrite;
mod upstream;

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use pingora_error::{Error, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use serde_json::Value as JsonValue;

use crate::core::error::ProxyResult;

pub use pipeline::{CompiledPluginPipeline, ProxyContext, ProxyPluginExecutor, RouteContext};
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

    pub const ALL: Self = Self(
        Self::EARLY_REQUEST.0
            | Self::REQUEST.0
            | Self::UPSTREAM_REQUEST.0
            | Self::REQUEST_BODY.0
            | Self::RESPONSE.0
            | Self::RESPONSE_BODY.0
            | Self::LOGGING.0,
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
#[async_trait]
pub trait ProxyPlugin: Send + Sync {
    /// Return the name of this plugin.
    fn name(&self) -> &str;

    /// Return the priority of this plugin.
    fn priority(&self) -> i32;

    /// Phases this plugin implements. The executor only invokes hooks listed
    /// here. Default is empty so a plugin that forgets to declare phases is a
    /// silent no-op — built-ins and tests must override this.
    fn phases(&self) -> PluginPhases {
        PluginPhases::empty()
    }

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
    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<bool> {
        Ok(false)
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

    /// Called after the complete response is sent or on fatal error.
    ///
    /// Use this for: metrics collection, access logging, cleanup operations.
    /// Error logging is already handled by the framework.
    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, _ctx: &mut ProxyContext) {}
}

/// Sort proxy plugins deterministically by:
/// - higher priority first
/// - for ties, sort by plugin name
pub fn sort_plugins_by_priority_desc(plugins: &mut [Arc<dyn ProxyPlugin>]) {
    plugins.sort_by(|a, b| {
        b.priority()
            .cmp(&a.priority())
            .then_with(|| a.name().cmp(b.name()))
    });
}
