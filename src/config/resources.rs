use std::collections::{HashMap, HashSet};

use http::Method;
use pingsix_macros::EncryptFields;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::{serde_as, DisplayFromStr};
use validator::{Validate, ValidationError};

use crate::config::node::Nodes;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate, EncryptFields)]
pub struct UpstreamTls {
    #[validate(length(min = 1))]
    pub client_cert: String,
    #[encrypt]
    #[validate(length(min = 1))]
    pub client_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct Timeout {
    #[validate(range(min = 1, max = 86400))]
    pub connect: u64,
    #[validate(range(min = 1, max = 86400))]
    pub send: u64,
    #[validate(range(min = 1, max = 86400))]
    pub read: u64,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate, EncryptFields)]
#[validate(schema(function = "Route::validate"))]
pub struct Route {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,

    pub uri: Option<String>,
    #[serde(default)]
    pub uris: Vec<String>,
    #[serde(default)]
    #[serde_as(as = "Vec<DisplayFromStr>")]
    pub methods: Vec<Method>,
    pub host: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default = "Route::default_priority")]
    pub priority: u32,

    #[serde(default)]
    #[encrypt(plugins)]
    pub plugins: HashMap<String, JsonValue>,
    #[validate(nested)]
    #[encrypt(nested)]
    pub upstream: Option<Upstream>,
    pub upstream_id: Option<String>,
    pub service_id: Option<String>,
    #[validate(nested)]
    pub timeout: Option<Timeout>,
    /// Enable WebSocket upgrade proxying for this route (APISIX `enable_websocket`).
    /// When enabled (or when a request carries an `Upgrade` header), upstream
    /// read/write timeouts are disabled so long-lived bidirectional streams are
    /// not killed while idle.
    #[serde(default)]
    pub enable_websocket: bool,
}

impl Route {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.uri.is_none() && self.uris.is_empty() {
            return Err(ValidationError::new("uri_or_uris_required"));
        }

        // APISIX semantics treat these as alternative forms; silently preferring
        // the singular hides configuration mistakes, so reject both-at-once.
        if self.uri.is_some() && !self.uris.is_empty() {
            return Err(ValidationError::new("uri_and_uris_mutually_exclusive"));
        }
        if self.host.is_some() && !self.hosts.is_empty() {
            return Err(ValidationError::new("host_and_hosts_mutually_exclusive"));
        }

        if self.upstream_id.is_none() && self.service_id.is_none() && self.upstream.is_none() {
            let mut err = ValidationError::new("upstream_or_service_required");
            err.message = Some(
                "route requires an upstream or service; locally short-circuiting plugins \
                 (redirect/echo/fault-injection) must still bind a placeholder upstream, or \
                 be configured on a global rule"
                    .into(),
            );
            return Err(err);
        }

        // APISIX semantics treat inline `upstream` and `upstream_id` as
        // alternative forms of the same upstream slot; silently preferring one
        // hides configuration mistakes and leaves a shadowed reference that
        // still participates in whole-graph validation, so reject both-at-once.
        if self.upstream.is_some() && self.upstream_id.is_some() {
            return Err(ValidationError::new(
                "upstream_and_upstream_id_mutually_exclusive",
            ));
        }

        Ok(())
    }

    pub fn get_hosts(&self) -> Vec<&str> {
        if let Some(ref host) = self.host {
            vec![host.as_str()]
        } else {
            self.hosts.iter().map(|s| s.as_str()).collect()
        }
    }

    pub fn get_uris(&self) -> Vec<&str> {
        if let Some(ref uri) = self.uri {
            vec![uri.as_str()]
        } else {
            self.uris.iter().map(|s| s.as_str()).collect()
        }
    }

    fn default_priority() -> u32 {
        0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate, EncryptFields)]
#[validate(schema(function = "Upstream::validate_scheme_dependent_fields"))]
pub struct Upstream {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub retries: Option<u32>,
    pub retry_timeout: Option<u64>,
    #[validate(nested)]
    pub timeout: Option<Timeout>,
    #[validate(nested)]
    pub nodes: Nodes,
    #[serde(default)]
    pub r#type: SelectionType,
    #[validate(nested)]
    pub checks: Option<HealthCheck>,
    #[serde(default)]
    pub hash_on: UpstreamHashOn,
    #[serde(default = "Upstream::default_key")]
    pub key: String,
    #[serde(default)]
    pub scheme: UpstreamScheme,
    #[serde(default)]
    pub pass_host: UpstreamPassHost,
    pub upstream_host: Option<String>,
    #[encrypt(nested)]
    #[validate(nested)]
    pub tls: Option<UpstreamTls>,
    /// Per-upstream connection-pool tuning (APISIX `keepalive_pool`).
    #[serde(default)]
    #[validate(nested)]
    pub keepalive_pool: Option<KeepalivePool>,
}

impl Upstream {
    fn default_key() -> String {
        "uri".to_string()
    }

    /// Checks that need fields validated together, including the scheme, which
    /// decides the default port of nodes that omit one.
    fn validate_scheme_dependent_fields(&self) -> Result<(), ValidationError> {
        if self.pass_host == UpstreamPassHost::REWRITE && self.upstream_host.is_none() {
            return Err(ValidationError::new("upstream_host_required_for_rewrite"));
        }

        self.validate_unique_node_addresses()
    }

    /// Pingora backend identity is `addr` + `weight`, so two enabled nodes that
    /// dial the same address cannot be represented separately at runtime. The
    /// scheme default port makes `example.com` and `example.com:80` collide over
    /// HTTP, so compare effective addresses rather than the configured ones.
    fn validate_unique_node_addresses(&self) -> Result<(), ValidationError> {
        let mut seen = HashSet::with_capacity(self.nodes.len());
        for node in self.nodes.iter().filter(|node| node.is_enabled()) {
            let addr = node.effective_addr_key(&self.scheme);
            if !seen.insert(addr) {
                let mut err = ValidationError::new("nodes_duplicate_address");
                err.add_param("address".into(), &node.effective_addr_key(&self.scheme));
                return Err(err);
            }
        }

        Ok(())
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SelectionType {
    #[default]
    RoundRobin,
    Random,
    Fnv,
    Ketama,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[validate(schema(function = "HealthCheck::validate"))]
pub struct HealthCheck {
    /// Active health probing. Optional so a passive-only `checks` block is
    /// valid (APISIX allows `checks` with only `passive`). At least one of
    /// `active`/`passive` must be present.
    #[serde(default)]
    #[validate(nested)]
    pub active: Option<ActiveCheck>,
    /// Passive health checking driven by real request outcomes
    /// (APISIX `checks.passive`). Nodes are pulled from rotation after
    /// `unhealthy.*` consecutive failures and restored after
    /// `healthy.successes` consecutive healthy responses.
    #[serde(default)]
    #[validate(nested)]
    pub passive: Option<PassiveCheck>,
}

impl HealthCheck {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.active.is_none() && self.passive.is_none() {
            return Err(ValidationError::new(
                "health_check_requires_active_or_passive",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
#[validate(schema(function = "PassiveCheck::validate"))]
#[serde(rename_all = "lowercase")]
pub struct PassiveCheck {
    /// Check type. Accepted for APISIX schema compatibility; counters are
    /// driven by real traffic outcomes regardless of this value.
    #[serde(default)]
    pub r#type: PassiveCheckType,
    #[serde(default)]
    #[validate(nested)]
    pub healthy: PassiveHealthy,
    #[serde(default)]
    #[validate(nested)]
    pub unhealthy: PassiveUnhealthy,
}

impl PassiveCheck {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_passive_statuses(&self.healthy.http_statuses)?;
        validate_passive_statuses(&self.unhealthy.http_statuses)?;
        if self.healthy.successes > 254
            || self.unhealthy.tcp_failures > 254
            || self.unhealthy.timeouts > 254
            || self.unhealthy.http_failures > 254
        {
            return Err(ValidationError::new("invalid_passive_threshold"));
        }
        Ok(())
    }
}

fn validate_passive_statuses(statuses: &[u32]) -> Result<(), ValidationError> {
    if statuses.is_empty()
        || statuses.iter().any(|status| !(200..=599).contains(status))
        || statuses.iter().collect::<HashSet<_>>().len() != statuses.len()
    {
        return Err(ValidationError::new("invalid_passive_http_statuses"));
    }
    Ok(())
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(clippy::upper_case_acronyms)]
pub enum PassiveCheckType {
    TCP,
    #[default]
    HTTP,
    HTTPS,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct PassiveHealthy {
    /// Status codes that count as a successful real-traffic outcome.
    #[serde(default = "PassiveHealthy::default_http_statuses")]
    pub http_statuses: Vec<u32>,
    /// Consecutive healthy outcomes required to restore a tripped node. Zero disables recovery.
    #[serde(default = "PassiveHealthy::default_successes")]
    #[validate(range(min = 0, max = 254))]
    pub successes: u32,
}

impl PassiveHealthy {
    fn default_http_statuses() -> Vec<u32> {
        vec![
            200, 201, 202, 203, 204, 205, 206, 207, 208, 226, 300, 301, 302, 303, 304, 305, 306,
            307, 308,
        ]
    }

    fn default_successes() -> u32 {
        5
    }
}

impl Default for PassiveHealthy {
    fn default() -> Self {
        Self {
            http_statuses: Self::default_http_statuses(),
            successes: Self::default_successes(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct PassiveUnhealthy {
    /// Status codes that count as an unhealthy real-traffic outcome.
    #[serde(default = "PassiveUnhealthy::default_http_statuses")]
    pub http_statuses: Vec<u32>,
    /// Consecutive TCP failures before the node is tripped. Zero disables this category.
    #[serde(default = "PassiveUnhealthy::default_tcp_failures")]
    #[validate(range(min = 0, max = 254))]
    pub tcp_failures: u32,
    /// Consecutive timeouts before the node is tripped. Zero disables this category.
    #[serde(default = "PassiveUnhealthy::default_timeouts")]
    #[validate(range(min = 0, max = 254))]
    pub timeouts: u32,
    /// Consecutive unhealthy HTTP statuses before the node is tripped. Zero disables this category.
    #[serde(default = "PassiveUnhealthy::default_http_failures")]
    #[validate(range(min = 0, max = 254))]
    pub http_failures: u32,
}

impl PassiveUnhealthy {
    fn default_http_statuses() -> Vec<u32> {
        vec![429, 500, 503]
    }

    fn default_tcp_failures() -> u32 {
        2
    }

    fn default_timeouts() -> u32 {
        7
    }

    fn default_http_failures() -> u32 {
        5
    }
}

impl Default for PassiveUnhealthy {
    fn default() -> Self {
        Self {
            http_statuses: Self::default_http_statuses(),
            tcp_failures: Self::default_tcp_failures(),
            timeouts: Self::default_timeouts(),
            http_failures: Self::default_http_failures(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct ActiveCheck {
    #[serde(default)]
    pub r#type: ActiveCheckType,
    #[serde(default = "ActiveCheck::default_timeout")]
    #[validate(range(min = 1))]
    pub timeout: u32,
    #[serde(default = "ActiveCheck::default_http_path")]
    pub http_path: String,
    pub host: Option<String>,
    #[validate(range(min = 1, max = 65535))]
    pub port: Option<u32>,
    #[serde(default = "ActiveCheck::default_https_verify_certificate")]
    pub https_verify_certificate: bool,
    #[serde(default)]
    pub req_headers: Vec<String>,
    #[validate(nested)]
    pub healthy: Option<Health>,
    #[validate(nested)]
    pub unhealthy: Option<Unhealthy>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(clippy::upper_case_acronyms)]
pub enum ActiveCheckType {
    TCP,
    #[default]
    HTTP,
    HTTPS,
}

impl ActiveCheck {
    fn default_timeout() -> u32 {
        1
    }

    fn default_http_path() -> String {
        "/".to_string()
    }

    fn default_https_verify_certificate() -> bool {
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct Health {
    #[serde(default = "Health::default_interval")]
    #[validate(range(min = 1))]
    pub interval: u32,
    #[serde(default = "Health::default_http_statuses")]
    pub http_statuses: Vec<u32>,
    #[serde(default = "Health::default_successes")]
    #[validate(range(min = 1))]
    pub successes: u32,
}

impl Health {
    fn default_interval() -> u32 {
        1
    }

    fn default_http_statuses() -> Vec<u32> {
        vec![200, 302]
    }

    fn default_successes() -> u32 {
        2
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct Unhealthy {
    #[serde(default = "Unhealthy::default_http_failures")]
    #[validate(range(min = 1))]
    pub http_failures: u32,
    #[serde(default = "Unhealthy::default_tcp_failures")]
    #[validate(range(min = 1))]
    pub tcp_failures: u32,
}

impl Unhealthy {
    fn default_http_failures() -> u32 {
        5
    }

    fn default_tcp_failures() -> u32 {
        2
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(clippy::upper_case_acronyms)]
pub enum UpstreamHashOn {
    #[default]
    VARS,
    HEAD,
    COOKIE,
}

#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(clippy::upper_case_acronyms)]
pub enum UpstreamScheme {
    #[default]
    HTTP,
    HTTPS,
    GRPC,
    GRPCS,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(clippy::upper_case_acronyms)]
pub enum UpstreamPassHost {
    #[default]
    PASS,
    REWRITE,
    NODE,
}

/// Serde bridge mapping APISIX's fractional `idle_timeout` seconds onto an
/// integer millisecond field so [`Upstream`] can keep deriving `Eq`.
mod secs_f64_as_ms {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = f64::deserialize(deserializer)?;
        if !secs.is_finite() || secs < 0.0 {
            return Err(serde::de::Error::custom(
                "keepalive_pool.idle_timeout must be a non-negative number",
            ));
        }
        Ok((secs * 1000.0).round() as u64)
    }

    pub(crate) fn serialize<S>(millis: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(*millis as f64 / 1000.0)
    }
}

/// Per-upstream keepalive connection-pool settings, APISIX
/// `keepalive_pool` schema compatible.
///
/// * `idle_timeout` (seconds, fractional allowed, default 60) maps onto
///   Pingora's per-peer idle timeout: how long an idle upstream connection
///   stays in the pool before it is closed.
/// * `size` (default 320) and `requests` (default 1000) are accepted for
///   APISIX schema compatibility. Pingora 0.8 does not expose per-upstream
///   pool size or per-connection request caps, so non-default values log a
///   warning at build time and the process-global
///   `pingora.upstream_keepalive_pool_size` applies instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct KeepalivePool {
    /// Idle connections to keep per upstream (accepted, not enforced).
    #[serde(default = "KeepalivePool::default_size")]
    #[validate(range(min = 1))]
    pub size: u32,
    /// Seconds an idle connection is kept before closing.
    #[serde(
        default = "KeepalivePool::default_idle_timeout_ms",
        rename = "idle_timeout",
        with = "secs_f64_as_ms"
    )]
    #[validate(range(min = 0))]
    pub idle_timeout_ms: u64,
    /// Requests per connection before recycling (accepted, not enforced).
    #[serde(default = "KeepalivePool::default_requests")]
    #[validate(range(min = 1))]
    pub requests: u32,
}

impl KeepalivePool {
    pub(crate) fn default_size() -> u32 {
        320
    }

    pub(crate) fn default_idle_timeout_ms() -> u64 {
        60_000
    }

    pub(crate) fn default_requests() -> u32 {
        1000
    }

    /// Whether any accepted-but-unenforced knob deviates from its default.
    pub(crate) fn has_unsupported_overrides(&self) -> bool {
        self.size != Self::default_size() || self.requests != Self::default_requests()
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize, Validate, EncryptFields)]
#[validate(schema(function = "Service::validate_upstream"))]
pub struct Service {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    #[encrypt(plugins)]
    pub plugins: HashMap<String, JsonValue>,
    #[encrypt(nested)]
    pub upstream: Option<Upstream>,
    pub upstream_id: Option<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
}

impl Service {
    fn validate_upstream(&self) -> Result<(), ValidationError> {
        if self.upstream_id.is_none() && self.upstream.is_none() {
            return Err(ValidationError::new("upstream_required"));
        }
        // Same alternative-form rule as [`Route::validate`]: both inline
        // `upstream` and `upstream_id` together are ambiguous and rejected.
        if self.upstream.is_some() && self.upstream_id.is_some() {
            return Err(ValidationError::new(
                "upstream_and_upstream_id_mutually_exclusive",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize, Validate, EncryptFields)]
pub struct GlobalRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    #[encrypt(plugins)]
    pub plugins: HashMap<String, JsonValue>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize, Validate, EncryptFields)]
#[allow(clippy::upper_case_acronyms)]
pub struct SSL {
    #[serde(default)]
    pub id: String,
    pub cert: String,
    #[encrypt]
    pub key: String,
    #[validate(length(min = 1))]
    pub snis: Vec<String>,
}
