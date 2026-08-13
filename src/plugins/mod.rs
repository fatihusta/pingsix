pub mod api_breaker;
pub mod basic_auth;
pub mod brotli;
pub mod cache;
pub mod client_control;
pub mod compression;
pub mod cors;
pub mod csrf;
pub mod echo;
pub mod fault_injection;
pub mod file_logger;
pub mod grpc_web;
pub mod gzip;
pub mod ip_restriction;
pub mod jwt_auth;
pub mod key_auth;
pub mod limit_conn;
pub mod limit_count;
pub mod limit_req;
pub mod prometheus;
pub mod proxy_mirror;
pub mod proxy_rewrite;
pub mod redirect;
pub mod request_id;
pub mod response_rewrite;
pub mod traffic_split;

use std::{collections::HashMap, sync::Arc};

use once_cell::sync::Lazy;
use serde_json::Value as JsonValue;

use crate::{
    config::Upstream,
    core::{PluginCreateFn, ProxyError, ProxyPlugin, ProxyResult},
    proxy::upstream::{PreparedUpstreams, ProxyUpstream, TrafficSplitOwner, UpstreamOccurrence},
};

/// Global registry mapping plugin names to their factory functions.
///
/// Plugins are listed in descending priority order (higher priority = executes first).
/// The priority value determines execution order in the plugin chain.
static PLUGIN_BUILDER_REGISTRY: Lazy<HashMap<&'static str, PluginCreateFn>> = Lazy::new(|| {
    let arr: Vec<(&str, PluginCreateFn)> = vec![
        (
            client_control::PLUGIN_NAME,
            client_control::create_client_control_plugin,
        ), // 22000
        (
            request_id::PLUGIN_NAME,
            request_id::create_request_id_plugin,
        ), // 12015
        (
            fault_injection::PLUGIN_NAME,
            fault_injection::create_fault_injection_plugin,
        ), // 11000
        (cors::PLUGIN_NAME, cors::create_cors_plugin), // 4000
        (
            ip_restriction::PLUGIN_NAME,
            ip_restriction::create_ip_restriction_plugin,
        ), // 3000
        (csrf::PLUGIN_NAME, csrf::create_csrf_plugin), // 2980
        (
            basic_auth::PLUGIN_NAME,
            basic_auth::create_basic_auth_plugin,
        ), // 2520
        (jwt_auth::PLUGIN_NAME, jwt_auth::create_jwt_auth_plugin), // 2510
        (key_auth::PLUGIN_NAME, key_auth::create_key_auth_plugin), // 2500
        (cache::PLUGIN_NAME, cache::create_cache_plugin), // 1085
        (
            proxy_rewrite::PLUGIN_NAME,
            proxy_rewrite::create_proxy_rewrite_plugin,
        ), // 1008
        (
            api_breaker::PLUGIN_NAME,
            api_breaker::create_api_breaker_plugin,
        ), // 1005
        (
            proxy_mirror::PLUGIN_NAME,
            proxy_mirror::create_proxy_mirror_plugin,
        ), // 1010
        (
            limit_conn::PLUGIN_NAME,
            limit_conn::create_limit_conn_plugin,
        ), // 1003
        (
            limit_count::PLUGIN_NAME,
            limit_count::create_limit_count_plugin,
        ), // 1002
        (limit_req::PLUGIN_NAME, limit_req::create_limit_req_plugin), // 1001
        (brotli::PLUGIN_NAME, brotli::create_brotli_plugin), // 996
        (gzip::PLUGIN_NAME, gzip::create_gzip_plugin), // 995
        (redirect::PLUGIN_NAME, redirect::create_redirect_plugin), // 900
        (
            response_rewrite::PLUGIN_NAME,
            response_rewrite::create_response_rewrite_plugin,
        ), // 899
        (grpc_web::PLUGIN_NAME, grpc_web::create_grpc_web_plugin), // 505
        (
            prometheus::PLUGIN_NAME,
            prometheus::create_prometheus_plugin,
        ), // 500
        (echo::PLUGIN_NAME, echo::create_echo_plugin), // 412
        (
            file_logger::PLUGIN_NAME,
            file_logger::create_file_logger_plugin,
        ), // 399
    ];
    arr.into_iter().collect()
});

/// Build-time dependency context for plugins that resolve other resources.
///
/// Carries the owning scope plus the same-version named upstreams and prepared
/// material so dependency-aware plugins (currently traffic-split) no longer
/// need to be special-cased by name in the factory path.
pub(crate) struct PluginBuildContext<'a> {
    pub upstreams: &'a HashMap<String, Arc<ProxyUpstream>>,
    pub prepared: &'a PreparedUpstreams,
    pub owner: &'a TrafficSplitOwner,
    /// Effective `pingsix.defaults` of the owning gateway instance.
    pub defaults: &'a crate::config::EffectiveDefaults,
    /// DNS resolver of the owning gateway instance.
    pub resolver: &'a Arc<hickory_resolver::TokioResolver>,
}

/// Factories that resolve upstream references at build time.
///
/// A plugin registers here instead of the plain registry when it needs
/// [`PluginBuildContext`]; registration is declarative, so adding a future
/// dependency-aware plugin needs no name check anywhere.
type UpstreamPluginFactory =
    fn(JsonValue, &PluginBuildContext<'_>) -> ProxyResult<Arc<dyn ProxyPlugin>>;

/// Deterministic structural validation of a plugin config (no graph context).
type ValidatePluginFn = fn(&JsonValue) -> ProxyResult<()>;

/// Named upstream id extraction for whole-graph reference checks.
type PluginUpstreamRefsFn = fn(&JsonValue) -> ProxyResult<Vec<String>>;

/// Inline upstream occurrence extraction for candidate preparation.
type PluginUpstreamJobsFn =
    fn(TrafficSplitOwner, &JsonValue) -> ProxyResult<Vec<(UpstreamOccurrence, Upstream)>>;

/// Control-plane capabilities of a plugin that resolves other resources.
///
/// One registry entry replaces the former name-based special cases in graph
/// validation and candidate preparation; a future dependency-aware plugin
/// declares the capabilities it needs here and every consumer picks them up
/// generically.
pub(crate) struct PluginUpstreamCapabilities {
    pub factory: UpstreamPluginFactory,
    /// Deterministic structural validation (Admin pre-check, no graph context).
    pub validate: Option<ValidatePluginFn>,
    /// Named upstream ids referenced by the config (whole-graph reference check).
    pub upstream_refs: Option<PluginUpstreamRefsFn>,
    /// Inline upstream occurrences to prepare when the owning scope is rebuilt.
    pub upstream_jobs: Option<PluginUpstreamJobsFn>,
}

static PLUGIN_UPSTREAM_CAPABILITIES: Lazy<HashMap<&'static str, PluginUpstreamCapabilities>> =
    Lazy::new(|| {
        HashMap::from([(
            traffic_split::PLUGIN_NAME,
            PluginUpstreamCapabilities {
                factory: traffic_split::create_traffic_split_plugin_with_context,
                validate: Some(traffic_split::validate_traffic_split_config),
                upstream_refs: Some(traffic_split::named_upstream_ids),
                upstream_jobs: Some(traffic_split::inline_upstream_jobs),
            },
        )])
    });

/// Deterministic Admin pre-check for one plugin config.
///
/// Dependency-aware plugins (registered in [`PLUGIN_UPSTREAM_CAPABILITIES`])
/// validate structurally through their declared `validate` capability — they
/// cannot be built without upstream context. Plain plugins are built, which
/// parses their typed config and surfaces configuration errors.
pub(crate) fn validate_plugin_config(name: &str, cfg: &JsonValue) -> ProxyResult<()> {
    match PLUGIN_UPSTREAM_CAPABILITIES.get(name) {
        Some(cap) => match cap.validate {
            Some(validate) => validate(cfg),
            None => Ok(()),
        },
        None => {
            // Validation builds the plugin to surface config errors; defaults
            // only affect fallback resolution (identical validation outcome).
            build_plugin(
                name,
                cfg.clone(),
                // Admin validation only checks whether a plugin config can be
                // parsed and built. It must not inherit another gateway
                // instance's process-global defaults.
                &crate::config::EffectiveDefaults::default(),
            )?;
            Ok(())
        }
    }
}

/// Named upstream ids referenced by a plugin config, when the plugin declares
/// any. Empty for plugins without graph references.
pub(crate) fn plugin_upstream_refs(name: &str, cfg: &JsonValue) -> ProxyResult<Vec<String>> {
    match PLUGIN_UPSTREAM_CAPABILITIES
        .get(name)
        .and_then(|cap| cap.upstream_refs)
    {
        Some(extract) => extract(cfg),
        None => Ok(Vec::new()),
    }
}

/// Inline upstream occurrences declared across a resource's plugin configs.
///
/// Only plugins registered with an `upstream_jobs` capability contribute;
/// the owning scope's reuse decision is made by the caller.
pub(crate) fn plugin_upstream_jobs(
    owner: TrafficSplitOwner,
    plugins: &HashMap<String, JsonValue>,
) -> ProxyResult<Vec<(UpstreamOccurrence, Upstream)>> {
    let mut jobs = Vec::new();
    for (name, cfg) in plugins {
        if let Some(collect) = PLUGIN_UPSTREAM_CAPABILITIES
            .get(name.as_str())
            .and_then(|cap| cap.upstream_jobs)
        {
            jobs.extend(collect(owner.clone(), cfg)?);
        }
    }
    Ok(jobs)
}

/// Creates plugin instances from configuration using a factory pattern.
///
/// Looks up the plugin builder function in the global registry and invokes it
/// with the provided configuration. Fails fast for unknown plugin types.
///
/// # Arguments
/// - `name`: Plugin identifier (must match registry keys)
/// - `cfg`: Plugin configuration as JSON
///
/// # Returns
/// Arc-wrapped plugin instance for thread-safe sharing across requests
///
/// # Errors
/// Returns `ReadError` for unknown plugin names or configuration parsing failures
pub(crate) fn build_plugin_with_upstreams(
    name: &str,
    cfg: JsonValue,
    upstreams: &HashMap<String, Arc<ProxyUpstream>>,
    prepared: &PreparedUpstreams,
    owner: &TrafficSplitOwner,
    defaults: &crate::config::EffectiveDefaults,
    resolver: &Arc<hickory_resolver::TokioResolver>,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    // Dependency-aware plugins register here; the lookup replaces the former
    // `name == traffic-split` special case with a declarative registry entry.
    if let Some(capabilities) = PLUGIN_UPSTREAM_CAPABILITIES.get(name) {
        let context = PluginBuildContext {
            upstreams,
            prepared,
            owner,
            defaults,
            resolver,
        };
        return (capabilities.factory)(cfg, &context);
    }
    build_plugin(name, cfg, defaults)
}

/// Plugin name → secret-field transform derived from `#[encrypt]` markers.
///
/// Used by admin (encrypt before etcd write) and control-plane (decrypt on load).
pub(crate) static PLUGIN_ENCRYPT_FIELDS: Lazy<
    HashMap<&'static str, crate::utils::encryption::PluginSecretsTransform>,
> = Lazy::new(|| {
    HashMap::from([
        (basic_auth::PLUGIN_NAME, basic_auth::SECRETS_TRANSFORM),
        (csrf::PLUGIN_NAME, csrf::SECRETS_TRANSFORM),
        (key_auth::PLUGIN_NAME, key_auth::SECRETS_TRANSFORM),
        (jwt_auth::PLUGIN_NAME, jwt_auth::SECRETS_TRANSFORM),
    ])
});

pub fn build_plugin(
    name: &str,
    cfg: JsonValue,
    defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let builder = PLUGIN_BUILDER_REGISTRY
        .get(name)
        .ok_or_else(|| ProxyError::Plugin(format!("Unknown plugin type: {name}")))?;
    builder(cfg, defaults)
}
