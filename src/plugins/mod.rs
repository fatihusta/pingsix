pub mod ai_proxy;
pub mod api_breaker;
pub mod basic_auth;
pub mod brotli;
pub mod cache;
pub mod client_control;
pub mod compression;
pub(crate) mod config;
pub mod cors;
pub mod csrf;
pub mod echo;
pub mod exit_transformer;
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
pub(crate) mod limiter_shards;
pub mod prometheus;
pub mod proxy_mirror;
pub mod proxy_rewrite;
pub mod redirect;
pub mod request_id;
pub mod request_validation;
pub mod response_rewrite;
pub mod traffic_split;
pub mod uri_blocker;

use std::{collections::HashMap, sync::Arc};

use serde_json::Value as JsonValue;

use crate::{
    config::Upstream,
    core::{PluginCreateFn, ProxyError, ProxyPlugin, ProxyResult},
    proxy::upstream::{PreparedUpstreams, ProxyUpstream, TrafficSplitOwner, UpstreamOccurrence},
};

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

/// Construction strategy for one builtin plugin.
pub(crate) enum PluginFactory {
    Plain(PluginCreateFn),
    WithUpstreams(UpstreamPluginFactory),
}

/// Complete compile-time metadata for one builtin plugin.
///
/// This is deliberately an explicit closed inventory rather than a distributed
/// registration mechanism: adding a plugin makes all of its construction,
/// graph, and secret-handling choices visible in one entry.
pub(crate) struct PluginMeta {
    pub name: &'static str,
    pub factory: PluginFactory,
    pub secrets_transform: Option<crate::utils::encryption::PluginSecretsTransform>,
    /// Deterministic structural validation (Admin pre-check, no graph context).
    pub validate: Option<ValidatePluginFn>,
    /// Named upstream ids referenced by the config (whole-graph reference check).
    pub upstream_refs: Option<PluginUpstreamRefsFn>,
    /// Inline upstream occurrences to prepare when the owning scope is rebuilt.
    pub upstream_jobs: Option<PluginUpstreamJobsFn>,
}

/// The single inventory for every builtin plugin. Entries remain in descending
/// priority order to preserve the previous registry's documentation order.
static PLUGIN_META: &[PluginMeta] = &[
    PluginMeta {
        name: client_control::PLUGIN_NAME,
        factory: PluginFactory::Plain(client_control::create_client_control_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: exit_transformer::PLUGIN_NAME,
        factory: PluginFactory::Plain(exit_transformer::create_exit_transformer_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: request_id::PLUGIN_NAME,
        factory: PluginFactory::Plain(request_id::create_request_id_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: fault_injection::PLUGIN_NAME,
        factory: PluginFactory::Plain(fault_injection::create_fault_injection_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: cors::PLUGIN_NAME,
        factory: PluginFactory::Plain(cors::create_cors_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: ip_restriction::PLUGIN_NAME,
        factory: PluginFactory::Plain(ip_restriction::create_ip_restriction_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: uri_blocker::PLUGIN_NAME,
        factory: PluginFactory::Plain(uri_blocker::create_uri_blocker_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: ai_proxy::PLUGIN_NAME,
        factory: PluginFactory::WithUpstreams(ai_proxy::create_ai_proxy_plugin_with_context),
        secrets_transform: Some(ai_proxy::SECRETS_TRANSFORM),
        validate: Some(ai_proxy::validate_ai_proxy_config),
        upstream_refs: None,
        upstream_jobs: Some(ai_proxy::inline_upstream_jobs),
    },
    PluginMeta {
        name: request_validation::PLUGIN_NAME,
        factory: PluginFactory::Plain(request_validation::create_request_validation_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: csrf::PLUGIN_NAME,
        factory: PluginFactory::Plain(csrf::create_csrf_plugin),
        secrets_transform: Some(csrf::SECRETS_TRANSFORM),
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: basic_auth::PLUGIN_NAME,
        factory: PluginFactory::Plain(basic_auth::create_basic_auth_plugin),
        secrets_transform: Some(basic_auth::SECRETS_TRANSFORM),
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: jwt_auth::PLUGIN_NAME,
        factory: PluginFactory::Plain(jwt_auth::create_jwt_auth_plugin),
        secrets_transform: Some(jwt_auth::SECRETS_TRANSFORM),
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: key_auth::PLUGIN_NAME,
        factory: PluginFactory::Plain(key_auth::create_key_auth_plugin),
        secrets_transform: Some(key_auth::SECRETS_TRANSFORM),
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: cache::PLUGIN_NAME,
        factory: PluginFactory::Plain(cache::create_cache_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: proxy_rewrite::PLUGIN_NAME,
        factory: PluginFactory::Plain(proxy_rewrite::create_proxy_rewrite_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: api_breaker::PLUGIN_NAME,
        factory: PluginFactory::Plain(api_breaker::create_api_breaker_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: proxy_mirror::PLUGIN_NAME,
        factory: PluginFactory::Plain(proxy_mirror::create_proxy_mirror_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: limit_conn::PLUGIN_NAME,
        factory: PluginFactory::Plain(limit_conn::create_limit_conn_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: limit_count::PLUGIN_NAME,
        factory: PluginFactory::Plain(limit_count::create_limit_count_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: limit_req::PLUGIN_NAME,
        factory: PluginFactory::Plain(limit_req::create_limit_req_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: brotli::PLUGIN_NAME,
        factory: PluginFactory::Plain(brotli::create_brotli_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: gzip::PLUGIN_NAME,
        factory: PluginFactory::Plain(gzip::create_gzip_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: redirect::PLUGIN_NAME,
        factory: PluginFactory::Plain(redirect::create_redirect_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: response_rewrite::PLUGIN_NAME,
        factory: PluginFactory::Plain(response_rewrite::create_response_rewrite_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: grpc_web::PLUGIN_NAME,
        factory: PluginFactory::Plain(grpc_web::create_grpc_web_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: prometheus::PLUGIN_NAME,
        factory: PluginFactory::Plain(prometheus::create_prometheus_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: echo::PLUGIN_NAME,
        factory: PluginFactory::Plain(echo::create_echo_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: file_logger::PLUGIN_NAME,
        factory: PluginFactory::Plain(file_logger::create_file_logger_plugin),
        secrets_transform: None,
        validate: None,
        upstream_refs: None,
        upstream_jobs: None,
    },
    PluginMeta {
        name: traffic_split::PLUGIN_NAME,
        factory: PluginFactory::WithUpstreams(
            traffic_split::create_traffic_split_plugin_with_context,
        ),
        secrets_transform: None,
        validate: Some(traffic_split::validate_traffic_split_config),
        upstream_refs: Some(traffic_split::named_upstream_ids),
        upstream_jobs: Some(traffic_split::inline_upstream_jobs),
    },
];

fn plugin_meta(name: &str) -> Option<&'static PluginMeta> {
    PLUGIN_META.iter().find(|meta| meta.name == name)
}

/// Deterministic Admin pre-check for one plugin config.
///
/// Plain plugins validate by construction: building parses the typed config
/// and surfaces errors. Dependency-aware plugins (`WithUpstreams`) cannot be
/// built without upstream context, so they validate structurally through their
/// declared `validate` capability. Defaults only affect fallback resolution
/// (identical validation outcome), and the Admin path always uses a neutral
/// default so it never inherits another gateway instance's state.
///
/// Validation by construction also runs plain builders' side effects on the
/// config write path: for file-logger, validating a config opens (or creates)
/// the log file — accepted behavior.
pub(crate) fn validate_plugin_config(name: &str, cfg: &JsonValue) -> ProxyResult<()> {
    let meta = plugin_meta(name)
        .ok_or_else(|| ProxyError::Plugin(format!("Unknown plugin type: {name}")))?;
    match meta.factory {
        PluginFactory::Plain(factory) => {
            factory(cfg.clone(), &crate::config::EffectiveDefaults::default())?;
            Ok(())
        }
        PluginFactory::WithUpstreams(_) => match meta.validate {
            Some(validate) => validate(cfg),
            None => Ok(()),
        },
    }
}

/// Named upstream ids referenced by a plugin config, when the plugin declares
/// any. Empty for plugins without graph references.
pub(crate) fn plugin_upstream_refs(name: &str, cfg: &JsonValue) -> ProxyResult<Vec<String>> {
    match plugin_meta(name).and_then(|meta| meta.upstream_refs) {
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
        if let Some(collect) = plugin_meta(name).and_then(|meta| meta.upstream_jobs) {
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
    let meta = plugin_meta(name)
        .ok_or_else(|| ProxyError::Plugin(format!("Unknown plugin type: {name}")))?;
    match meta.factory {
        PluginFactory::Plain(factory) => factory(cfg, defaults),
        PluginFactory::WithUpstreams(factory) => {
            let context = PluginBuildContext {
                upstreams,
                prepared,
                owner,
                defaults,
                resolver,
            };
            factory(cfg, &context)
        }
    }
}

/// Transform a plugin config's declared secret fields, if any.
pub(crate) fn transform_plugin_secrets(
    name: &str,
    config: &mut JsonValue,
    op: crate::utils::encryption::SecretOp,
    keyring: &crate::utils::encryption::KeyringService,
) -> ProxyResult<()> {
    if let Some(transform) = plugin_meta(name).and_then(|meta| meta.secrets_transform) {
        transform(config, op, keyring)?;
    }
    Ok(())
}

pub fn build_plugin(
    name: &str,
    cfg: JsonValue,
    defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let meta = plugin_meta(name)
        .ok_or_else(|| ProxyError::Plugin(format!("Unknown plugin type: {name}")))?;
    match meta.factory {
        PluginFactory::Plain(factory) => factory(cfg, defaults),
        PluginFactory::WithUpstreams(_) => Err(ProxyError::Plugin(format!(
            "Plugin type '{name}' requires upstream build context"
        ))),
    }
}

/// Public plugin construction by name for embedders and integration tests.
///
/// Mirrors the internal registry lookup: unknown plugins and invalid
/// configurations fail loudly.
pub fn build_plugin_by_name(name: &str, cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    build_plugin(name, cfg, &crate::config::EffectiveDefaults::default())
}

#[cfg(test)]
mod builtin_phases_tests {
    use super::*;
    use serde_json::json;

    use crate::core::PluginPhases;
    use crate::proxy::upstream::discovery::build_resolver_for_state;

    fn expected_phases() -> HashMap<&'static str, PluginPhases> {
        let request = PluginPhases::REQUEST;
        let early = PluginPhases::EARLY_REQUEST;
        let logging = PluginPhases::LOGGING;
        HashMap::from([
            (
                client_control::PLUGIN_NAME,
                request | PluginPhases::REQUEST_BODY,
            ),
            (exit_transformer::PLUGIN_NAME, PluginPhases::empty()),
            (request_id::PLUGIN_NAME, request | PluginPhases::RESPONSE),
            (fault_injection::PLUGIN_NAME, request),
            (cors::PLUGIN_NAME, request | PluginPhases::RESPONSE),
            (ip_restriction::PLUGIN_NAME, request),
            (uri_blocker::PLUGIN_NAME, request),
            (
                ai_proxy::PLUGIN_NAME,
                request
                    | PluginPhases::UPSTREAM_REQUEST
                    | PluginPhases::REQUEST_BODY
                    | PluginPhases::UPSTREAM_PEER,
            ),
            (
                request_validation::PLUGIN_NAME,
                request | PluginPhases::REQUEST_BODY,
            ),
            (csrf::PLUGIN_NAME, request | PluginPhases::RESPONSE),
            (basic_auth::PLUGIN_NAME, request),
            (jwt_auth::PLUGIN_NAME, request | PluginPhases::RESPONSE),
            (key_auth::PLUGIN_NAME, request),
            (cache::PLUGIN_NAME, request),
            (proxy_rewrite::PLUGIN_NAME, PluginPhases::UPSTREAM_REQUEST),
            (
                proxy_mirror::PLUGIN_NAME,
                request | PluginPhases::UPSTREAM_REQUEST | PluginPhases::REQUEST_BODY,
            ),
            (api_breaker::PLUGIN_NAME, request | PluginPhases::RESPONSE),
            (limit_conn::PLUGIN_NAME, request | logging),
            (limit_count::PLUGIN_NAME, request | PluginPhases::RESPONSE),
            (limit_req::PLUGIN_NAME, request),
            (gzip::PLUGIN_NAME, early),
            (brotli::PLUGIN_NAME, early),
            (redirect::PLUGIN_NAME, request),
            (
                echo::PLUGIN_NAME,
                PluginPhases::RESPONSE | PluginPhases::RESPONSE_BODY,
            ),
            (
                response_rewrite::PLUGIN_NAME,
                PluginPhases::RESPONSE | PluginPhases::RESPONSE_BODY,
            ),
            (
                grpc_web::PLUGIN_NAME,
                early | PluginPhases::REQUEST | PluginPhases::REQUEST_BODY | PluginPhases::RESPONSE,
            ),
            (prometheus::PLUGIN_NAME, logging),
            (
                file_logger::PLUGIN_NAME,
                logging | PluginPhases::REQUEST_BODY | PluginPhases::RESPONSE_BODY,
            ),
            (traffic_split::PLUGIN_NAME, request),
        ])
    }

    fn minimal_config(name: &str) -> JsonValue {
        match name {
            "fault-injection" => json!({"abort": {"http_status": 503}}),
            "basic-auth" => json!({"username": "user", "password": "pass"}),
            "jwt-auth" => json!({"secret": "test-secret"}),
            "key-auth" => json!({"key": "test-key"}),
            "csrf" => json!({"key": "csrf-secret"}),
            "proxy-cache" => json!({"ttl": 60}),
            "limit-req" => json!({"rate": 1.0, "key": "remote_addr"}),
            "limit-conn" => json!({
                "conn": 2,
                "default_conn_delay": 0.1,
                "key": "remote_addr"
            }),
            "limit-count" => json!({"time_window": 1, "count": 10}),
            "api-breaker" => json!({"break_response_code": 502}),
            "proxy-mirror" => json!({"host": "http://127.0.0.1:9797"}),
            "echo" => json!({"body": "ok"}),
            "redirect" => json!({"uri": "/next", "regex_uri": []}),
            "uri-blocker" => json!({"block_rules": ["/blocked"]}),
            "request-validation" => json!({"header_schema": {"type": "object"}}),
            "ip-restriction" => json!({"whitelist": ["127.0.0.1/32"]}),
            "ai-proxy" => json!({
                "provider": "openai-compatible",
                "auth": {"header": {"Authorization": "Bearer test"}},
                "override": {"endpoint": "http://127.0.0.1:9"}
            }),
            "exit-transformer" => json!({"rules": [{"codes": [404]}]}),
            _ => json!({}),
        }
    }

    #[test]
    fn plugin_meta_inventory_is_complete_and_unique() {
        let expected_names: std::collections::HashSet<_> = expected_phases().into_keys().collect();
        let inventory_names: std::collections::HashSet<_> =
            PLUGIN_META.iter().map(|meta| meta.name).collect();
        assert_eq!(
            inventory_names.len(),
            PLUGIN_META.len(),
            "duplicate plugin metadata"
        );
        assert_eq!(
            inventory_names, expected_names,
            "plugin metadata is incomplete"
        );

        let traffic_split =
            plugin_meta(traffic_split::PLUGIN_NAME).expect("traffic-split metadata");
        assert!(matches!(
            traffic_split.factory,
            PluginFactory::WithUpstreams(_)
        ));
        assert!(traffic_split.validate.is_some());
        assert!(traffic_split.upstream_refs.is_some());
        assert!(traffic_split.upstream_jobs.is_some());

        let ai_proxy_meta = plugin_meta(ai_proxy::PLUGIN_NAME).expect("ai-proxy metadata");
        assert!(matches!(
            ai_proxy_meta.factory,
            PluginFactory::WithUpstreams(_)
        ));
        assert!(ai_proxy_meta.validate.is_some());
        assert!(ai_proxy_meta.upstream_jobs.is_some());
        assert!(ai_proxy_meta.secrets_transform.is_some());

        for name in [
            basic_auth::PLUGIN_NAME,
            csrf::PLUGIN_NAME,
            jwt_auth::PLUGIN_NAME,
            key_auth::PLUGIN_NAME,
        ] {
            assert!(plugin_meta(name).unwrap().secrets_transform.is_some());
        }
        assert!(plugin_meta(cache::PLUGIN_NAME)
            .unwrap()
            .secrets_transform
            .is_none());
    }

    #[test]
    fn builtin_plugin_phases_match_table() {
        let defaults = crate::config::EffectiveDefaults::default();
        let expected = expected_phases();

        for meta in PLUGIN_META {
            assert!(
                expected.contains_key(meta.name),
                "builtin phase table is missing {}",
                meta.name
            );
        }

        for (name, phases) in &expected {
            if *name == traffic_split::PLUGIN_NAME || *name == ai_proxy::PLUGIN_NAME {
                continue;
            }
            let plugin = build_plugin(name, minimal_config(name), &defaults)
                .unwrap_or_else(|err| panic!("build {name}: {err}"));
            assert_eq!(plugin.phases(), *phases, "phases mismatch for {name}");
        }

        let split = traffic_split::create_traffic_split_plugin_with_upstreams(
            json!({"rules":[{"weighted_upstreams":[{"weight": 1}]}]}),
            &HashMap::new(),
            &HashMap::new(),
            TrafficSplitOwner::Route("phase-table".into()),
            &defaults,
            &build_resolver_for_state().expect("resolver"),
        )
        .expect("traffic-split");
        assert_eq!(
            split.phases(),
            expected[traffic_split::PLUGIN_NAME],
            "phases mismatch for traffic-split"
        );

        // ai-proxy is also WithUpstreams: build through its sync embedder
        // constructor (IP-literal endpoint, no DNS needed).
        let ai = ai_proxy::build_ai_proxy_plugin(minimal_config("ai-proxy")).expect("ai-proxy");
        assert_eq!(
            ai.phases(),
            expected[ai_proxy::PLUGIN_NAME],
            "phases mismatch for ai-proxy"
        );
    }
}
