//! Core components for the Pingsix proxy.
//!
//! This module provides the essential building blocks for the proxy system:
//! - Error handling and result types
//! - Plugin system infrastructure
//! - Request context management
//! - Plugin execution framework
//! - Service readiness tracking

pub mod error;
pub mod plugin;
pub mod secret;
pub mod status;

// Re-export all public items so external modules can use `crate::core::*`
pub use error::{ErrorContext, ProxyError, ProxyResult};
pub use plugin::{
    apply_regex_uri_template, sort_plugins_by_priority_desc, CompiledPluginPipeline, ExitTransform,
    ExitTransformRule, FilterVerdict, HealthCheckFingerprint, HealthCheckSpec, PassiveOutcome,
    PluginCreateFn, PluginEntry, PluginPhases, ProxyContext, ProxyPlugin, ProxyPluginExecutor,
    Rejection, RouteContext, RouteLabels, SelectedUpstream, UpstreamSelection, UpstreamSelector,
};
pub use secret::{constant_time_digest_eq, constant_time_eq, secret_digest};
