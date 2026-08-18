//! Provider upstream construction: endpoint URL → [`config::Upstream`] →
//! prepared [`ProxyUpstream`].
//!
//! Follows the traffic-split precedent: the provider endpoint is declared
//! through the plugin's `upstream_jobs` capability so the async control-plane
//! worker resolves DNS at build time (`prepare_upstream`), and the plugin
//! factory then consumes the prepared material keyed by
//! [`UpstreamOccurrence::AiProxy`].

use std::sync::Arc;

use serde_json::Value as JsonValue;

use crate::config::{self, EffectiveDefaults, Node, Nodes};
use crate::core::{ProxyError, ProxyPlugin, ProxyResult};
use crate::proxy::upstream::{
    PreparedUpstreams, ProxyUpstream, TrafficSplitOwner, UpstreamOccurrence,
};

use super::config::AiProxyConfig;
use super::provider::provider_spec;
use super::PluginAiProxy;

/// The effective provider endpoint after config resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedEndpoint {
    /// Dial scheme: HTTP or HTTPS (providers are HTTPS by default).
    pub(crate) scheme: config::UpstreamScheme,
    /// Bare host (no brackets, no port) as it goes into an upstream node.
    pub(crate) host: String,
    /// Effective port (scheme default when the URL omits one).
    pub(crate) port: u16,
    /// Target request path (endpoint path, or the provider's default chat
    /// path when the endpoint URL carries none).
    pub(crate) path: String,
    /// Query parameters contributed by the endpoint URL (rare).
    pub(crate) query: Vec<(String, String)>,
}

/// Resolve the effective endpoint: `override.endpoint` wins over the
/// provider default; an endpoint path wins over the provider default chat
/// path (APISIX: "endpoint path wins over the capability path").
pub(crate) fn resolve_endpoint(cfg: &AiProxyConfig) -> ProxyResult<ResolvedEndpoint> {
    let spec = provider_spec(cfg.provider);
    let raw = cfg
        .r#override
        .endpoint
        .as_deref()
        .or(spec.default_endpoint)
        .ok_or_else(|| {
            ProxyError::Configuration(format!(
                "provider '{}' has no default endpoint; override.endpoint is required",
                cfg.provider.as_str()
            ))
        })?;

    let url = url::Url::parse(raw)
        .map_err(|e| ProxyError::Configuration(format!("invalid endpoint URL '{raw}': {e}")))?;
    let scheme = match url.scheme() {
        "https" => config::UpstreamScheme::HTTPS,
        "http" => config::UpstreamScheme::HTTP,
        other => {
            return Err(ProxyError::Configuration(format!(
                "endpoint URL scheme must be http or https, got '{other}'"
            )))
        }
    };

    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| {
            ProxyError::Configuration(format!("endpoint URL '{raw}' is missing a host"))
        })?
        .to_string();
    let port = url.port_or_known_default().ok_or_else(|| {
        ProxyError::Configuration(format!("endpoint URL '{raw}' is missing a port"))
    })?;

    // An endpoint of scheme://host keeps the provider's default chat path.
    let raw_path = url.path();
    let path = if raw_path.is_empty() || raw_path == "/" {
        spec.chat_path.to_string()
    } else {
        raw_path.to_string()
    };

    let query = url
        .query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default();

    Ok(ResolvedEndpoint {
        scheme,
        host,
        port,
        path,
        query,
    })
}

/// Node host as expected by [`config::Node`]: IPv6 literals need brackets.
fn node_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// ai-proxy timeout is milliseconds; upstream timeouts are seconds with a
/// minimum of one second (sub-second timeouts round up).
fn milliseconds_to_seconds(ms: u64) -> u64 {
    ms.div_ceil(1000).clamp(1, 86_400)
}

/// Build the single-node upstream config for a provider endpoint.
///
/// `pass_host: node` so the Host header and TLS SNI are the provider host;
/// `keepalive: false` maps to a zero idle timeout (connections are used once
/// and never pooled). TLS verification cannot be expressed here (UpstreamTls
/// carries only client certificates); `ssl_verify: false` travels on the
/// request context instead and is applied to the selected peer by
/// [`HttpService`](crate::service::http::HttpService).
pub(crate) fn build_provider_upstream_config(
    cfg: &AiProxyConfig,
    endpoint: &ResolvedEndpoint,
) -> ProxyResult<config::Upstream> {
    let seconds = milliseconds_to_seconds(cfg.timeout);
    Ok(config::Upstream {
        id: format!("ai-proxy-{}", cfg.provider.as_str()),
        name: None,
        // No blind retries: LLM completions are expensive and non-idempotent;
        // retry policy belongs to the caller or ai-proxy-multi (v2+).
        retries: None,
        retry_timeout: None,
        timeout: Some(config::Timeout {
            connect: seconds,
            send: seconds,
            read: seconds,
        }),
        nodes: Nodes(vec![Node {
            host: node_host(&endpoint.host),
            port: Some(endpoint.port),
            weight: 1,
            priority: 0,
        }]),
        r#type: config::SelectionType::RoundRobin,
        checks: None,
        hash_on: config::UpstreamHashOn::VARS,
        key: "uri".to_string(),
        scheme: endpoint.scheme,
        pass_host: config::UpstreamPassHost::NODE,
        upstream_host: None,
        tls: None,
        keepalive_pool: Some(config::KeepalivePool {
            size: cfg.keepalive_pool,
            // keepalive:false → zero idle timeout → connections are never
            // reused (Pingora expires pooled connections immediately).
            idle_timeout_ms: if cfg.keepalive {
                cfg.keepalive_timeout
            } else {
                0
            },
            requests: config::KeepalivePool::default_requests(),
        }),
    })
}

/// Deterministic Admin pre-check: parse and validate the plugin config
/// without resolving DNS or building the upstream.
pub fn validate_ai_proxy_config(cfg: &JsonValue) -> ProxyResult<()> {
    AiProxyConfig::parse(cfg.clone()).map(|_| ())
}

/// Declare the provider upstream embedded in an ai-proxy config so the
/// control-plane preparation pipeline resolves it (DNS at build time),
/// exactly like traffic-split's inline upstreams.
pub(crate) fn inline_upstream_jobs(
    owner: TrafficSplitOwner,
    cfg: &JsonValue,
) -> ProxyResult<Vec<(UpstreamOccurrence, config::Upstream)>> {
    let config = AiProxyConfig::parse(cfg.clone())?;
    let endpoint = resolve_endpoint(&config)?;
    let upstream = build_provider_upstream_config(&config, &endpoint)?;
    Ok(vec![(UpstreamOccurrence::AiProxy(owner), upstream)])
}

/// Registry entry for the dependency-aware plugin build.
pub(crate) fn create_ai_proxy_plugin_with_context(
    cfg: JsonValue,
    context: &crate::plugins::PluginBuildContext<'_>,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    create_ai_proxy_plugin_with_upstreams(
        cfg,
        context.prepared,
        context.owner.clone(),
        context.defaults,
        context.resolver,
    )
}

/// Build the plugin from material prepared by the control plane.
pub(crate) fn create_ai_proxy_plugin_with_upstreams(
    cfg: JsonValue,
    prepared: &PreparedUpstreams,
    owner: TrafficSplitOwner,
    defaults: &EffectiveDefaults,
    resolver: &Arc<hickory_resolver::TokioResolver>,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = AiProxyConfig::parse(cfg)?;
    let endpoint = resolve_endpoint(&config)?;
    let upstream_config = build_provider_upstream_config(&config, &endpoint)?;
    let prepared_material = prepared
        .get(&UpstreamOccurrence::AiProxy(owner.clone()))
        .cloned()
        .ok_or_else(|| {
            ProxyError::Configuration(format!(
                "ai-proxy provider upstream for {} was not prepared (DNS preparation missing)",
                owner_id(&owner)
            ))
        })?;
    let upstream = Arc::new(ProxyUpstream::build(
        upstream_config,
        prepared_material,
        defaults,
        resolver,
    )?);
    Ok(Arc::new(PluginAiProxy::new(config, endpoint, upstream)))
}

fn owner_id(owner: &TrafficSplitOwner) -> String {
    match owner {
        TrafficSplitOwner::Route(id) => format!("route '{id}'"),
        TrafficSplitOwner::Service(id) => format!("service '{id}'"),
        TrafficSplitOwner::GlobalRule(id) => format!("global-rule '{id}'"),
    }
}

/// Embedder/integration-test constructor: builds the plugin with
/// synchronously prepared material.
///
/// Only endpoints whose host is an IP literal can be prepared this way —
/// hostname endpoints need the async DNS preparation pipeline and are
/// rejected here with that explanation. Production construction always goes
/// through [`create_ai_proxy_plugin_with_upstreams`].
pub fn build_ai_proxy_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = AiProxyConfig::parse(cfg)?;
    let endpoint = resolve_endpoint(&config)?;
    let upstream_config = build_provider_upstream_config(&config, &endpoint)?;

    let resolver = crate::proxy::upstream::discovery::build_resolver_for_state()?;
    let prepared_material =
        crate::proxy::upstream::discovery::prepare_static_upstream(&upstream_config, &resolver)?;

    let upstream = Arc::new(ProxyUpstream::build(
        upstream_config,
        prepared_material,
        &EffectiveDefaults::default(),
        &resolver,
    )?);
    Ok(Arc::new(PluginAiProxy::new(config, endpoint, upstream)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_config(provider: &str, endpoint: Option<&str>) -> AiProxyConfig {
        let mut value = json!({
            "provider": provider,
            "auth": { "header": { "Authorization": "Bearer sk-test" } }
        });
        if let Some(endpoint) = endpoint {
            value["override"] = json!({ "endpoint": endpoint });
        }
        AiProxyConfig::parse(value).unwrap()
    }

    #[test]
    fn endpoint_resolution_prefers_override_and_keeps_default_paths() {
        // Default endpoints (override absent).
        let openai = resolve_endpoint(&test_config("openai", None)).unwrap();
        assert_eq!(openai.host, "api.openai.com");
        assert_eq!(openai.port, 443);
        assert_eq!(openai.path, "/v1/chat/completions");
        assert_eq!(openai.scheme, config::UpstreamScheme::HTTPS);

        let deepseek = resolve_endpoint(&test_config("deepseek", None)).unwrap();
        assert_eq!(deepseek.host, "api.deepseek.com");
        assert_eq!(deepseek.path, "/chat/completions");

        let anthropic = resolve_endpoint(&test_config("anthropic", None)).unwrap();
        assert_eq!(anthropic.host, "api.anthropic.com");
        assert_eq!(anthropic.path, "/v1/messages");

        // Override with full path: endpoint path wins.
        let overridden = resolve_endpoint(&test_config(
            "openai",
            Some("https://llm.internal:8443/v2/chat"),
        ))
        .unwrap();
        assert_eq!(overridden.host, "llm.internal");
        assert_eq!(overridden.port, 8443);
        assert_eq!(overridden.path, "/v2/chat");

        // Override without a path: provider default chat path applies.
        let bare_host = resolve_endpoint(&test_config(
            "openai-compatible",
            Some("http://127.0.0.1:9099"),
        ))
        .unwrap();
        assert_eq!(bare_host.scheme, config::UpstreamScheme::HTTP);
        assert_eq!(bare_host.port, 9099);
        assert_eq!(bare_host.path, "/v1/chat/completions");

        // Endpoint query parameters are carried through.
        let with_query = resolve_endpoint(&test_config(
            "openai-compatible",
            Some("https://gateway.internal/api?key=abc&x=1"),
        ))
        .unwrap();
        assert_eq!(with_query.path, "/api");
        assert_eq!(
            with_query.query,
            vec![
                ("key".to_string(), "abc".to_string()),
                ("x".to_string(), "1".to_string())
            ]
        );
    }

    #[test]
    fn upstream_config_carries_scheme_tls_defaults_and_timeouts() {
        let cfg = test_config("openai", None);
        let endpoint = resolve_endpoint(&cfg).unwrap();
        let upstream = build_provider_upstream_config(&cfg, &endpoint).unwrap();

        assert_eq!(upstream.scheme, config::UpstreamScheme::HTTPS);
        assert_eq!(upstream.pass_host, config::UpstreamPassHost::NODE);
        assert_eq!(upstream.retries, None);
        assert_eq!(
            upstream.timeout,
            Some(config::Timeout {
                connect: 30,
                send: 30,
                read: 30
            })
        );
        assert_eq!(
            upstream.nodes.iter().next().unwrap().bare_host(),
            "api.openai.com"
        );
        assert_eq!(
            upstream.keepalive_pool,
            Some(config::KeepalivePool {
                size: 30,
                idle_timeout_ms: 60_000,
                requests: 1000,
            })
        );
    }

    #[test]
    fn timeout_milliseconds_round_up_to_seconds() {
        let mut cfg = test_config("openai", None);
        cfg.timeout = 500; // sub-second: rounds up, minimum 1s
        let endpoint = resolve_endpoint(&cfg).unwrap();
        let upstream = build_provider_upstream_config(&cfg, &endpoint).unwrap();
        assert_eq!(
            upstream.timeout,
            Some(config::Timeout {
                connect: 1,
                send: 1,
                read: 1
            })
        );

        cfg.timeout = 90_001; // 90.001s → 91s
        let upstream = build_provider_upstream_config(&cfg, &endpoint).unwrap();
        assert_eq!(upstream.timeout.unwrap().read, 91);
    }

    #[test]
    fn keepalive_false_disables_pooling_and_http_endpoints_dial_plain() {
        let mut cfg = test_config("openai-compatible", Some("http://127.0.0.1:9099"));
        cfg.keepalive = false;
        let endpoint = resolve_endpoint(&cfg).unwrap();
        let upstream = build_provider_upstream_config(&cfg, &endpoint).unwrap();
        assert_eq!(upstream.scheme, config::UpstreamScheme::HTTP);
        assert_eq!(upstream.keepalive_pool.unwrap().idle_timeout_ms, 0);
    }

    #[test]
    fn inline_upstream_jobs_key_is_stable_per_owner() {
        let cfg = json!({
            "provider": "openai-compatible",
            "auth": { "header": { "Authorization": "Bearer k" } },
            "override": { "endpoint": "http://127.0.0.1:9099/v1" }
        });
        let owner = TrafficSplitOwner::Route("r1".into());
        let jobs = inline_upstream_jobs(owner.clone(), &cfg).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].0, UpstreamOccurrence::AiProxy(owner.clone()));
        // Same config + owner → same occurrence identity.
        let again = inline_upstream_jobs(owner, &cfg).unwrap();
        assert_eq!(again[0].0, jobs[0].0);

        // Invalid configs are rejected here too.
        let bad = json!({ "provider": "openai", "auth": {} });
        assert!(inline_upstream_jobs(TrafficSplitOwner::Route("r2".into()), &bad).is_err());
    }

    #[test]
    fn admin_precheck_validates_structurally() {
        assert!(validate_ai_proxy_config(&json!({
            "provider": "deepseek",
            "auth": { "header": { "Authorization": "Bearer k" } }
        }))
        .is_ok());
        assert!(validate_ai_proxy_config(&json!({
            "provider": "nope",
            "auth": { "header": { "Authorization": "Bearer k" } }
        }))
        .is_err());
    }

    #[test]
    fn sync_constructor_builds_ip_literal_endpoints() {
        let plugin = build_ai_proxy_plugin(json!({
            "provider": "openai-compatible",
            "auth": { "header": { "Authorization": "Bearer k" } },
            "override": { "endpoint": "http://127.0.0.1:19099/v1" }
        }))
        .expect("IP-literal endpoint prepares synchronously");
        assert_eq!(plugin.name(), "ai-proxy");
    }

    #[tokio::test]
    async fn sync_constructor_rejects_hostname_endpoints() {
        // Hostname endpoints need the async DNS preparation pipeline; polling
        // them synchronously yields no immediate result.
        let err = match build_ai_proxy_plugin(json!({
            "provider": "openai",
            "auth": { "header": { "Authorization": "Bearer k" } }
        })) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("hostname endpoint must not prepare synchronously"),
        };
        assert!(
            err.contains("asynchronous DNS") || err.contains("discovery"),
            "{err}"
        );
    }
}
