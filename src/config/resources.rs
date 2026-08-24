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

/// Per-upstream keepalive connection-pool tuning (APISIX `keepalive_pool`).
///
/// `idle_timeout` (seconds, fractional allowed, default 60) maps onto
/// Pingora's per-peer idle timeout: how long an idle upstream connection
/// stays in the pool before it is closed. APISIX `size`/`requests` are not
/// enforced by Pingora and are deliberately not part of the schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Validate)]
pub struct KeepalivePool {
    /// Seconds an idle connection is kept before closing.
    #[serde(
        default = "KeepalivePool::default_idle_timeout_ms",
        rename = "idle_timeout",
        with = "secs_f64_as_ms"
    )]
    #[validate(range(min = 0))]
    pub idle_timeout_ms: u64,
}

impl KeepalivePool {
    pub(crate) fn default_idle_timeout_ms() -> u64 {
        60_000
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

// ---------------------------------------------------------------------------
// Config-field fingerprints
// ---------------------------------------------------------------------------

/// Which fields of [`Upstream`] a fingerprint covers. Call sites name a
/// profile instead of walking fields by hand; the policy lives here, declared
/// next to the config type it describes.
///
/// INVARIANT — read before adding or renaming an [`Upstream`] field:
/// every field enters **every** profile's fingerprint *by default*, because
/// the fingerprint hashes a whole-struct serialization and only the fields
/// named in a profile's exclusion list are left out. A new field therefore
/// must receive an explicit per-profile decision *at this definition site*:
/// either leave it included, or add its serialized name to the profile's
/// exclusion list below — in the same commit. The drift-guard test
/// (`fingerprint_tests::upstream_field_classification_drift_guard`) fails
/// while any field lacks a classification, so the decision cannot be skipped
/// silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamFingerprintProfile {
    /// Identity for health-check reconciliation. Covers only what changes
    /// probe behavior — scheme, effective node addresses, and `checks` — so
    /// LB-only edits (weights, retries, timeouts, host headers, …) never
    /// restart health-check tasks.
    HealthCheck,
    /// Cache-namespace identity: every field that can change which origin is
    /// contacted, or which virtual host / TLS client identity is used to
    /// reach it.
    CacheOrigin,
}

/// [`UpstreamFingerprintProfile::HealthCheck`] field exclusions, decided
/// field by field. Node weight/priority are excluded in the node projection
/// itself (they change load balancing, not probe behavior). See the
/// INVARIANT on [`UpstreamFingerprintProfile`].
const UPSTREAM_HEALTH_CHECK_EXCLUDED: &[&str] = &[
    "id",
    "retries",
    "retry_timeout",
    "timeout",
    "type",
    "hash_on",
    "key",
    "pass_host",
    "upstream_host",
    "tls",
    "keepalive_pool",
];

/// [`UpstreamFingerprintProfile::CacheOrigin`] field exclusions: probe
/// configuration and connection-pool tuning do not change which origin is
/// contacted. See the INVARIANT on [`UpstreamFingerprintProfile`].
const UPSTREAM_CACHE_ORIGIN_EXCLUDED: &[&str] = &["checks", "keepalive_pool"];

impl Upstream {
    /// Stable fingerprint of this upstream under `profile`.
    ///
    /// Properties every profile guarantees:
    /// - node insertion order / wire form (map vs. list) never changes the
    ///   value — nodes are sorted before hashing;
    /// - an omitted port and an explicit scheme-default port name the same
    ///   origin (`example.com` ≡ `example.com:80` over HTTP) — nodes hash
    ///   their *effective* port.
    pub fn fingerprint(&self, profile: UpstreamFingerprintProfile) -> u64 {
        use std::hash::Hasher;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        // Whole-struct projection: every serialized field enters the
        // fingerprint unless the profile explicitly excludes it above.
        let mut projection =
            serde_json::to_value(self).expect("Upstream serialization is infallible");
        let object = projection
            .as_object_mut()
            .expect("Upstream serializes to a JSON object");
        let excluded: &[&str] = match profile {
            UpstreamFingerprintProfile::HealthCheck => UPSTREAM_HEALTH_CHECK_EXCLUDED,
            UpstreamFingerprintProfile::CacheOrigin => UPSTREAM_CACHE_ORIGIN_EXCLUDED,
        };
        for key in excluded {
            object.remove(*key);
        }

        // Canonical node projection (both profiles): sorted, bare host, and
        // effective (scheme-default-resolved) port. Weight and priority only
        // matter to the cache origin; health-check identity must survive
        // their retuning.
        let mut nodes: Vec<_> = self.nodes.iter().collect();
        nodes.sort_by_key(|node| node.sort_key());
        let projected_nodes: Vec<JsonValue> = nodes
            .into_iter()
            .map(|node| {
                let mut fields = vec![
                    JsonValue::from(node.bare_host()),
                    JsonValue::from(node.effective_port(&self.scheme)),
                ];
                if profile == UpstreamFingerprintProfile::CacheOrigin {
                    fields.push(JsonValue::from(node.weight));
                    fields.push(JsonValue::from(node.priority));
                }
                JsonValue::Array(fields)
            })
            .collect();
        object.insert("nodes".to_string(), JsonValue::Array(projected_nodes));

        if profile == UpstreamFingerprintProfile::CacheOrigin {
            // The client-certificate identity changes which TLS client the
            // origin sees, so it belongs in the namespace — but key material
            // must never enter the fingerprint in cleartext. Digests stand in
            // for the PEM material.
            object.insert(
                "tls".to_string(),
                match &self.tls {
                    Some(tls) => JsonValue::Array(vec![
                        JsonValue::from(hex_digest(&tls.client_cert)),
                        JsonValue::from(hex_digest(&tls.client_key)),
                    ]),
                    None => JsonValue::Null,
                },
            );
        }

        hash_canonical_json(&projection, &mut hasher);
        hasher.finish()
    }
}

/// [`Route::cache_namespace_fingerprint`] field exclusions, decided field by
/// field: labels, method lists, and upstream *bindings* do not change
/// response content (the bound upstream contributes its own fingerprint where
/// cache isolation is keyed). The same INVARIANT as
/// [`UpstreamFingerprintProfile`] applies: adding a `Route` field includes it
/// in the fingerprint by default; excluding it requires an explicit entry
/// here plus a classification in
/// `fingerprint_tests::route_cache_namespace_classification_drift_guard`.
const ROUTE_CACHE_NAMESPACE_EXCLUDED: &[&str] = &[
    "name",
    "methods",
    "upstream",
    "upstream_id",
    "enable_websocket",
];

/// Within a service bound to a route, only identity and plugin configuration
/// can affect responses; hosts and upstream bindings cannot.
const SERVICE_CACHE_NAMESPACE_EXCLUDED: &[&str] = &["name", "hosts", "upstream", "upstream_id"];

impl Route {
    /// Cache-namespace fingerprint: route identity, match shape
    /// (URIs/hosts/priority), route timeout, and the response-affecting
    /// plugin configuration of the route and its bound service.
    ///
    /// Any configuration that can change a cached response must change this
    /// value. Plugin maps hash canonically (keys sorted recursively), so map
    /// insertion/wire order never changes the value.
    pub fn cache_namespace_fingerprint(&self, service: Option<&Service>) -> u64 {
        use std::hash::Hasher;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        // Whole-struct projection; see ROUTE_CACHE_NAMESPACE_EXCLUDED for the
        // per-field exclusion decisions.
        let mut projection = serde_json::to_value(self).expect("Route serialization is infallible");
        let object = projection
            .as_object_mut()
            .expect("Route serializes to a JSON object");
        for key in ROUTE_CACHE_NAMESPACE_EXCLUDED {
            object.remove(*key);
        }

        object.insert(
            "bound_service".to_string(),
            match service {
                Some(service) => {
                    let mut service_projection =
                        serde_json::to_value(service).expect("Service serialization is infallible");
                    let service_object = service_projection
                        .as_object_mut()
                        .expect("Service serializes to a JSON object");
                    for key in SERVICE_CACHE_NAMESPACE_EXCLUDED {
                        service_object.remove(*key);
                    }
                    service_projection
                }
                None => JsonValue::Null,
            },
        );

        hash_canonical_json(&projection, &mut hasher);
        hasher.finish()
    }
}

/// Hex-encoded secret digest, so client-identity material can participate in
/// a fingerprint without appearing in cleartext.
fn hex_digest(value: &str) -> String {
    use std::fmt::Write;
    crate::core::secret_digest(value)
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Hash a JSON projection deterministically: object keys sort recursively,
/// arrays keep order, numbers hash by their canonical `serde_json` rendering.
/// This makes fingerprints independent of `HashMap` iteration order and of
/// serde_json map implementation details.
fn hash_canonical_json(value: &JsonValue, hasher: &mut impl std::hash::Hasher) {
    use std::hash::Hash;
    match value {
        JsonValue::Null => 0u8.hash(hasher),
        JsonValue::Bool(b) => {
            1u8.hash(hasher);
            b.hash(hasher);
        }
        JsonValue::Number(n) => {
            2u8.hash(hasher);
            n.to_string().hash(hasher);
        }
        JsonValue::String(s) => {
            3u8.hash(hasher);
            s.hash(hasher);
        }
        JsonValue::Array(items) => {
            4u8.hash(hasher);
            items.len().hash(hasher);
            for item in items {
                hash_canonical_json(item, hasher);
            }
        }
        JsonValue::Object(map) => {
            5u8.hash(hasher);
            map.len().hash(hasher);
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for key in keys {
                key.hash(hasher);
                hash_canonical_json(&map[key], hasher);
            }
        }
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;
    use crate::config::Node;
    use std::collections::BTreeSet;

    fn node(host: &str, port: u16, weight: u32, priority: i8) -> Node {
        Node {
            host: host.into(),
            // Test convenience: 0 means "port omitted" (scheme default).
            port: (port != 0).then_some(port),
            weight,
            priority,
        }
    }

    /// Upstream with every field populated, so the drift guard observes every
    /// serialized key.
    fn populated_upstream() -> Upstream {
        Upstream {
            id: "u-drift".into(),
            retries: Some(2),
            retry_timeout: Some(5),
            timeout: Some(Timeout {
                connect: 1,
                send: 2,
                read: 3,
            }),
            nodes: Nodes(vec![
                node("10.0.0.1", 8080, 1, 1),
                node("10.0.0.2", 8080, 2, 0),
            ]),
            r#type: SelectionType::RoundRobin,
            checks: Some(HealthCheck {
                active: Some(ActiveCheck {
                    r#type: ActiveCheckType::HTTP,
                    timeout: 1,
                    http_path: "/healthz".into(),
                    host: Some("probe.internal".into()),
                    port: Some(8080),
                    https_verify_certificate: true,
                    req_headers: vec!["X-Probe: 1".into()],
                    healthy: Some(Health {
                        interval: 1,
                        http_statuses: vec![200],
                        successes: 1,
                    }),
                    unhealthy: Some(Unhealthy {
                        http_failures: 1,
                        tcp_failures: 1,
                    }),
                }),
                passive: None,
            }),
            hash_on: UpstreamHashOn::VARS,
            key: "uri".into(),
            scheme: UpstreamScheme::HTTP,
            pass_host: UpstreamPassHost::PASS,
            upstream_host: Some("tenant.internal".into()),
            tls: Some(UpstreamTls {
                client_cert: "CERT-PEM".into(),
                client_key: "KEY-PEM".into(),
            }),
            keepalive_pool: Some(KeepalivePool {
                idle_timeout_ms: 60_000,
            }),
        }
    }

    fn populated_route() -> Route {
        Route {
            id: "r-drift".into(),
            name: Some("drift".into()),
            uri: Some("/v1/*".into()),
            uris: vec![],
            methods: vec![http::Method::GET],
            host: Some("api.example.com".into()),
            hosts: vec![],
            priority: 7,
            plugins: HashMap::from([(
                "proxy-rewrite".to_string(),
                serde_json::json!({"uri": "/v2"}),
            )]),
            upstream: None,
            upstream_id: Some("u-drift".into()),
            service_id: Some("s-drift".into()),
            timeout: Some(Timeout {
                connect: 1,
                send: 1,
                read: 1,
            }),
            enable_websocket: false,
        }
    }

    fn populated_service() -> Service {
        Service {
            id: "s-drift".into(),
            name: Some("svc".into()),
            plugins: HashMap::from([("limit-count".to_string(), serde_json::json!({"count": 10}))]),
            upstream: None,
            upstream_id: Some("u-drift".into()),
            hosts: vec!["svc.example.com".into()],
        }
    }

    fn serialized_keys<T: serde::Serialize>(value: &T) -> BTreeSet<String> {
        serde_json::to_value(value)
            .expect("serialization is infallible")
            .as_object()
            .expect("struct serializes to a JSON object")
            .keys()
            .cloned()
            .collect()
    }

    /// DRIFT GUARD: every serialized `Upstream` field must appear exactly once
    /// in the classification table below. Adding or renaming a field fails
    /// this test loudly until the field gets an explicit per-profile decision
    /// here and in the profile exclusion lists in this file.
    #[test]
    fn upstream_field_classification_drift_guard() {
        type Mutate = fn(&mut Upstream);
        // (field, mutation, changes HealthCheck, changes CacheOrigin)
        let table: &[(&str, Mutate, bool, bool)] = &[
            ("id", |u: &mut Upstream| u.id = "other".into(), false, true),
            ("retries", |u| u.retries = Some(9), false, true),
            ("retry_timeout", |u| u.retry_timeout = Some(9), false, true),
            (
                "timeout",
                |u| u.timeout.as_mut().unwrap().connect = 42,
                false,
                true,
            ),
            (
                "nodes",
                |u| u.nodes.push(node("10.0.0.9", 9090, 1, 0)),
                true,
                true,
            ),
            ("type", |u| u.r#type = SelectionType::Ketama, false, true),
            (
                "checks",
                |u| {
                    u.checks
                        .as_mut()
                        .unwrap()
                        .active
                        .as_mut()
                        .unwrap()
                        .http_path = "/other".into();
                },
                true,
                false,
            ),
            (
                "hash_on",
                |u| u.hash_on = UpstreamHashOn::COOKIE,
                false,
                true,
            ),
            ("key", |u| u.key = "other".into(), false, true),
            ("scheme", |u| u.scheme = UpstreamScheme::HTTPS, true, true),
            (
                "pass_host",
                |u| u.pass_host = UpstreamPassHost::REWRITE,
                false,
                true,
            ),
            (
                "upstream_host",
                |u| u.upstream_host = Some("other.internal".into()),
                false,
                true,
            ),
            (
                "tls",
                |u| u.tls.as_mut().unwrap().client_key = "OTHER-KEY".into(),
                false,
                true,
            ),
            (
                "keepalive_pool",
                |u| u.keepalive_pool.as_mut().unwrap().idle_timeout_ms = 1,
                false,
                false,
            ),
        ];

        let serialized = serialized_keys(&populated_upstream());
        let classified: BTreeSet<String> =
            table.iter().map(|(name, ..)| (*name).to_string()).collect();
        assert_eq!(
            serialized, classified,
            "an Upstream field lacks a fingerprint-profile classification; \
             decide HealthCheck/CacheOrigin sensitivity here and in the \
             profile exclusion lists in this file"
        );

        let base = populated_upstream();
        let base_hc = base.fingerprint(UpstreamFingerprintProfile::HealthCheck);
        let base_cache = base.fingerprint(UpstreamFingerprintProfile::CacheOrigin);
        for (name, mutate, hc_changes, cache_changes) in table {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_ne!(
                &base, &changed,
                "mutation for field '{name}' must actually change the upstream"
            );
            assert_eq!(
                changed.fingerprint(UpstreamFingerprintProfile::HealthCheck) != base_hc,
                *hc_changes,
                "HealthCheck sensitivity mismatch for field '{name}'"
            );
            assert_eq!(
                changed.fingerprint(UpstreamFingerprintProfile::CacheOrigin) != base_cache,
                *cache_changes,
                "CacheOrigin sensitivity mismatch for field '{name}'"
            );
        }
    }

    /// DRIFT GUARD: same contract for `Route`'s cache-namespace profile.
    #[test]
    fn route_cache_namespace_classification_drift_guard() {
        type Mutate = fn(&mut Route);
        // (field, mutation, changes cache-namespace fingerprint)
        let table: &[(&str, Mutate, bool)] = &[
            ("id", |r: &mut Route| r.id = "other".into(), true),
            ("name", |r| r.name = Some("other".into()), false),
            ("uri", |r| r.uri = Some("/other".into()), true),
            ("uris", |r| r.uris = vec!["/alt".into()], true),
            ("methods", |r| r.methods = vec![http::Method::POST], false),
            ("host", |r| r.host = Some("other.example.com".into()), true),
            ("hosts", |r| r.hosts = vec!["alt.example.com".into()], true),
            ("priority", |r| r.priority = 42, true),
            (
                "plugins",
                |r| {
                    r.plugins.insert(
                        "proxy-rewrite".to_string(),
                        serde_json::json!({"uri": "/v3"}),
                    );
                },
                true,
            ),
            (
                "upstream",
                |r| r.upstream = Some(populated_upstream()),
                false,
            ),
            (
                "upstream_id",
                |r| r.upstream_id = Some("other".into()),
                false,
            ),
            ("service_id", |r| r.service_id = Some("other".into()), true),
            ("timeout", |r| r.timeout.as_mut().unwrap().read = 99, true),
            ("enable_websocket", |r| r.enable_websocket = true, false),
        ];

        let serialized = serialized_keys(&populated_route());
        let classified: BTreeSet<String> =
            table.iter().map(|(name, ..)| (*name).to_string()).collect();
        assert_eq!(
            serialized, classified,
            "a Route field lacks a cache-namespace classification; decide its \
             sensitivity here and in ROUTE_CACHE_NAMESPACE_EXCLUDED"
        );

        let base = populated_route();
        let base_fp = base.cache_namespace_fingerprint(None);
        for (name, mutate, changes) in table {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_ne!(
                &base, &changed,
                "mutation for field '{name}' must actually change the route"
            );
            assert_eq!(
                changed.cache_namespace_fingerprint(None) != base_fp,
                *changes,
                "cache-namespace sensitivity mismatch for field '{name}'"
            );
        }
    }

    #[test]
    fn upstream_fingerprint_stable_across_node_order() {
        let a = Upstream {
            nodes: Nodes(vec![node("10.0.0.2", 80, 2, 0), node("10.0.0.1", 80, 1, 0)]),
            ..populated_upstream()
        };
        let b = Upstream {
            nodes: Nodes(vec![node("10.0.0.1", 80, 1, 0), node("10.0.0.2", 80, 2, 0)]),
            ..populated_upstream()
        };
        for profile in [
            UpstreamFingerprintProfile::HealthCheck,
            UpstreamFingerprintProfile::CacheOrigin,
        ] {
            assert_eq!(
                a.fingerprint(profile),
                b.fingerprint(profile),
                "node insertion order must not change {profile:?}"
            );
        }
    }

    #[test]
    fn upstream_fingerprint_canonicalizes_scheme_default_port() {
        // An omitted port and an explicit scheme-default port dial the same
        // origin, so both profiles must treat them identically.
        let omitted = Upstream {
            nodes: Nodes(vec![node("example.com", 0, 1, 0)]),
            ..populated_upstream()
        };
        let explicit = Upstream {
            nodes: Nodes(vec![node("example.com", 80, 1, 0)]),
            ..populated_upstream()
        };
        for profile in [
            UpstreamFingerprintProfile::HealthCheck,
            UpstreamFingerprintProfile::CacheOrigin,
        ] {
            assert_eq!(
                omitted.fingerprint(profile),
                explicit.fingerprint(profile),
                "omitted port and explicit scheme default must agree for {profile:?}"
            );
        }

        // A genuinely different effective port must differ in both profiles.
        let other = Upstream {
            nodes: Nodes(vec![node("example.com", 8080, 1, 0)]),
            ..populated_upstream()
        };
        for profile in [
            UpstreamFingerprintProfile::HealthCheck,
            UpstreamFingerprintProfile::CacheOrigin,
        ] {
            assert_ne!(
                omitted.fingerprint(profile),
                other.fingerprint(profile),
                "different effective ports must differ for {profile:?}"
            );
        }
    }

    #[test]
    fn health_check_profile_ignores_node_weight_priority_and_lb_knobs() {
        let base = populated_upstream();
        let base_hc = base.fingerprint(UpstreamFingerprintProfile::HealthCheck);

        let mut reweighted = base.clone();
        reweighted.nodes.0[0].weight = 99;
        assert_eq!(
            base_hc,
            reweighted.fingerprint(UpstreamFingerprintProfile::HealthCheck)
        );
        assert_ne!(
            base.fingerprint(UpstreamFingerprintProfile::CacheOrigin),
            reweighted.fingerprint(UpstreamFingerprintProfile::CacheOrigin),
            "weights must still matter to the cache-origin profile"
        );

        let mut reprioritized = base.clone();
        reprioritized.nodes.0[0].priority = -5;
        assert_eq!(
            base_hc,
            reprioritized.fingerprint(UpstreamFingerprintProfile::HealthCheck)
        );
        assert_ne!(
            base.fingerprint(UpstreamFingerprintProfile::CacheOrigin),
            reprioritized.fingerprint(UpstreamFingerprintProfile::CacheOrigin),
            "priorities must still matter to the cache-origin profile"
        );
    }

    #[test]
    fn route_cache_namespace_plugin_map_order_insensitive_but_value_sensitive() {
        let plugins_a: HashMap<String, JsonValue> = [
            (
                "proxy-rewrite".to_string(),
                serde_json::json!({"uri": "/v2"}),
            ),
            (
                "response-rewrite".to_string(),
                serde_json::json!({"body": "x"}),
            ),
        ]
        .into_iter()
        .collect();
        // Same entries, opposite insertion order.
        let plugins_b: HashMap<String, JsonValue> = [
            (
                "response-rewrite".to_string(),
                serde_json::json!({"body": "x"}),
            ),
            (
                "proxy-rewrite".to_string(),
                serde_json::json!({"uri": "/v2"}),
            ),
        ]
        .into_iter()
        .collect();

        let route_a = Route {
            plugins: plugins_a,
            ..populated_route()
        };
        let route_b = Route {
            plugins: plugins_b,
            ..populated_route()
        };
        assert_eq!(
            route_a.cache_namespace_fingerprint(None),
            route_b.cache_namespace_fingerprint(None),
            "plugin map insertion order must not change the fingerprint"
        );

        let mut route_c = route_a.clone();
        route_c.plugins.insert(
            "proxy-rewrite".to_string(),
            serde_json::json!({"uri": "/v3"}),
        );
        assert_ne!(
            route_a.cache_namespace_fingerprint(None),
            route_c.cache_namespace_fingerprint(None),
            "a changed plugin value must change the fingerprint"
        );
        assert_ne!(
            route_a.cache_namespace_fingerprint(None),
            Route {
                plugins: HashMap::new(),
                ..populated_route()
            }
            .cache_namespace_fingerprint(None),
            "removing plugins must change the fingerprint"
        );
    }

    #[test]
    fn route_cache_namespace_service_contributions() {
        let route = populated_route();
        let service = populated_service();
        let base = route.cache_namespace_fingerprint(Some(&service));
        assert_ne!(
            base,
            route.cache_namespace_fingerprint(None),
            "binding a service must change the namespace"
        );

        // Only the service's identity and plugins may affect the namespace.
        let mut renamed = service.clone();
        renamed.name = Some("other".into());
        assert_eq!(base, route.cache_namespace_fingerprint(Some(&renamed)));

        let mut rehosted = service.clone();
        rehosted.hosts = vec!["other.example.com".into()];
        assert_eq!(base, route.cache_namespace_fingerprint(Some(&rehosted)));

        let mut rewired = service.clone();
        rewired.upstream_id = Some("other-upstream".into());
        assert_eq!(base, route.cache_namespace_fingerprint(Some(&rewired)));

        let mut renamed_id = service.clone();
        renamed_id.id = "other-service".into();
        assert_ne!(base, route.cache_namespace_fingerprint(Some(&renamed_id)));

        let mut replugged = service.clone();
        replugged.plugins.insert(
            "cors".to_string(),
            serde_json::json!({"allow_origins": "*"}),
        );
        assert_ne!(base, route.cache_namespace_fingerprint(Some(&replugged)));

        let mut revalued = service.clone();
        revalued
            .plugins
            .insert("limit-count".to_string(), serde_json::json!({"count": 11}));
        assert_ne!(base, route.cache_namespace_fingerprint(Some(&revalued)));

        // A same-id service with identical plugins is the same namespace even
        // when constructed separately (already covered above by clones, stated
        // explicitly for the equality direction).
        assert_eq!(
            base,
            route.cache_namespace_fingerprint(Some(&service.clone()))
        );
    }
}
