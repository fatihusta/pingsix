pub mod etcd;
mod node;

use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
};

use http::Method;
use pingora::server::configuration::{Opt, ServerConf};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use pingsix_macros::EncryptFields;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::{serde_as, DisplayFromStr};
use validator::{Validate, ValidationError};

pub use node::{Node, Nodes};

/// Re-export so external callers (integration tests, other crates) can name the
/// argument types of [`transform_resource_secrets`].
pub use crate::utils::encryption::{KeyringService, SecretOp};

/// Enables uniform ID handling across configuration entities for validation.
pub trait Identifiable {
    fn id(&self) -> &str;
    fn set_id(&mut self, id: String);
}

macro_rules! impl_identifiable {
    ($type:ty) => {
        impl Identifiable for $type {
            fn id(&self) -> &str {
                &self.id
            }

            fn set_id(&mut self, id: String) {
                self.id = id;
            }
        }
    };
}

impl_identifiable!(Route);
impl_identifiable!(Upstream);
impl_identifiable!(Service);
impl_identifiable!(GlobalRule);
impl_identifiable!(SSL);

/// Root configuration structure combining Pingora framework config with Pingsix-specific settings.
#[serde_as]
#[derive(Default, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Config::validate_resource_id"))]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Pingora framework configuration (workers, logging, etc.)
    #[serde(default)]
    pub pingora: ServerConf,

    /// Pingsix-specific configuration (listeners, etcd, plugins, etc.)
    #[validate(nested)]
    pub pingsix: Pingsix,

    // Static resource definitions - used when etcd is not configured
    #[validate(nested)]
    #[serde(default)]
    pub routes: Vec<Route>,
    #[validate(nested)]
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[validate(nested)]
    #[serde(default)]
    pub services: Vec<Service>,
    #[validate(nested)]
    #[serde(default)]
    pub global_rules: Vec<GlobalRule>,
    #[validate(nested)]
    #[serde(default)]
    pub ssls: Vec<SSL>,
}

// Configuration loading and validation methods
impl Config {
    /// Loads configuration from YAML file with comprehensive validation.
    ///
    /// Synchronous loading is intentional - configuration should be validated
    /// at startup before any async operations begin.
    pub fn load_from_yaml<P>(path: P) -> Result<Self>
    where
        P: AsRef<std::path::Path> + std::fmt::Display,
    {
        let conf_str = fs::read_to_string(&path).or_err_with(ReadError, || {
            format!("Unable to read conf file from {path}")
        })?;
        log::debug!("Conf file read from {path}");
        Self::from_yaml(&conf_str)
    }

    /// Main configuration loading entry point that combines file config with CLI overrides.
    pub fn load_yaml_with_opt_override(opt: &Opt) -> Result<Self> {
        if let Some(path) = &opt.conf {
            let mut conf = Self::load_from_yaml(path)?;
            conf.merge_with_opt(opt);
            Ok(conf)
        } else {
            Error::e_explain(ReadError, "No path specified")
        }
    }

    /// Parses YAML configuration string with comprehensive validation.
    pub fn from_yaml(conf_str: &str) -> Result<Self> {
        let conf: Config = serde_yml::from_str(conf_str)
            .or_err_with(ReadError, || "Unable to parse yaml configuration")?;

        log::debug!(
            "Loaded configuration with {} routes, {} upstreams, {} services, {} global rules, and {} SSL entries",
            conf.routes.len(),
            conf.upstreams.len(),
            conf.services.len(),
            conf.global_rules.len(),
            conf.ssls.len(),
        );

        // Validate configuration structure and constraints
        conf.validate()
            .or_err_with(FileReadError, || "Conf file validation failed")?;

        // Ensure all resource IDs are unique within their respective types
        Self::validate_unique_ids(&conf.routes, "route")
            .or_err_with(FileReadError, || "Route ID validation failed")?;
        Self::validate_unique_ids(&conf.upstreams, "upstream")
            .or_err_with(FileReadError, || "Upstream ID validation failed")?;
        Self::validate_unique_ids(&conf.services, "service")
            .or_err_with(FileReadError, || "Service ID validation failed")?;
        Self::validate_unique_ids(&conf.global_rules, "global_rule")
            .or_err_with(FileReadError, || "Global rule ID validation failed")?;
        Self::validate_unique_ids(&conf.ssls, "ssl")
            .or_err_with(FileReadError, || "SSL ID validation failed")?;

        // Best-effort unrecognized-field warnings for static YAML resources.
        // Unknown fields are still accepted (ingress metadata compatibility);
        // this only logs likely typos of behavior fields.
        if let Ok(graph) = serde_yml::from_str::<JsonValue>(conf_str) {
            warn_static_resources(&graph);
        }

        Ok(conf)
    }

    /// Serializes configuration back to YAML format for debugging or export.
    #[cfg(test)]
    pub fn to_yaml(&self) -> String {
        serde_yml::to_string(self).unwrap_or_else(|e| {
            log::error!("Failed to serialize config to YAML: {e}");
            String::new()
        })
    }

    /// Applies CLI option overrides to loaded configuration.
    pub fn merge_with_opt(&mut self, opt: &Opt) {
        if opt.daemon {
            self.pingora.daemon = true;
        }
    }

    fn validate_resource_id(&self) -> Result<(), ValidationError> {
        Self::validate_non_empty_ids(&self.upstreams, "upstream")?;
        Self::validate_non_empty_ids(&self.routes, "route")?;
        Self::validate_non_empty_ids(&self.services, "service")?;
        Self::validate_non_empty_ids(&self.global_rules, "global_rule")?;
        Self::validate_non_empty_ids(&self.ssls, "ssl")?;
        Ok(())
    }

    /// Validates that all resources in the slice have non-empty IDs.
    ///
    /// Uses generic constraint on `Identifiable` trait to work with any resource type.
    fn validate_non_empty_ids<T: Identifiable>(
        items: &[T],
        resource_name: &str,
    ) -> Result<(), ValidationError> {
        if items.iter().any(|item| item.id().is_empty()) {
            let mut err = ValidationError::new("id_required");
            err.add_param("resource".into(), &resource_name);
            return Err(err);
        }
        Ok(())
    }

    fn validate_unique_ids<T: Identifiable>(items: &[T], resource_name: &str) -> Result<()> {
        let mut ids = HashSet::new();
        for item in items {
            if !ids.insert(item.id().to_string()) {
                return Error::e_explain(
                    FileReadError,
                    format!("Duplicate {} ID found: {}", resource_name, item.id()),
                );
            }
        }
        Ok(())
    }
}

/// Schema of a dynamic configuration resource for unrecognized-field warnings.
///
/// Only typed object fields appear in `nested`. Deliberately free-form objects
/// (`plugins`, `nodes`, and compatibility metadata) remain leaves: their
/// contents belong to another schema or external producer and must not be
/// diagnosed here.
struct ResourceSchema {
    fields: &'static [&'static str],
    nested: &'static [(&'static str, &'static str)],
}

fn schema_for(id: &str) -> Option<&'static ResourceSchema> {
    const ROUTE: ResourceSchema = ResourceSchema {
        fields: &[
            "id",
            "name",
            "uri",
            "uris",
            "methods",
            "host",
            "hosts",
            "priority",
            "plugins",
            "upstream",
            "upstream_id",
            "service_id",
            "timeout",
            "enable_websocket",
            "metadata",
        ],
        nested: &[("upstream", "upstream"), ("timeout", "timeout")],
    };
    const UPSTREAM: ResourceSchema = ResourceSchema {
        fields: &[
            "id",
            "name",
            "retries",
            "retry_timeout",
            "timeout",
            "nodes",
            "plugins",
            "type",
            "checks",
            "hash_on",
            "key",
            "scheme",
            "pass_host",
            "upstream_host",
            "tls",
            "metadata",
        ],
        nested: &[
            ("timeout", "timeout"),
            ("checks", "health_check"),
            ("tls", "upstream_tls"),
        ],
    };
    const SERVICE: ResourceSchema = ResourceSchema {
        fields: &[
            "id",
            "name",
            "plugins",
            "upstream",
            "upstream_id",
            "hosts",
            "metadata",
        ],
        nested: &[("upstream", "upstream")],
    };
    const GLOBAL_RULE: ResourceSchema = ResourceSchema {
        fields: &["id", "plugins", "metadata"],
        nested: &[],
    };
    const SSL: ResourceSchema = ResourceSchema {
        fields: &["id", "cert", "key", "snis", "metadata"],
        nested: &[],
    };
    const TIMEOUT: ResourceSchema = ResourceSchema {
        fields: &["connect", "send", "read"],
        nested: &[],
    };
    const UPSTREAM_TLS: ResourceSchema = ResourceSchema {
        fields: &["client_cert", "client_key"],
        nested: &[],
    };
    const HEALTH_CHECK: ResourceSchema = ResourceSchema {
        fields: &["active", "passive"],
        nested: &[("active", "active_check"), ("passive", "passive_check")],
    };
    const ACTIVE_CHECK: ResourceSchema = ResourceSchema {
        fields: &[
            "type",
            "timeout",
            "http_path",
            "host",
            "port",
            "https_verify_certificate",
            "req_headers",
            "healthy",
            "unhealthy",
        ],
        nested: &[("healthy", "health"), ("unhealthy", "unhealthy")],
    };
    const HEALTH: ResourceSchema = ResourceSchema {
        fields: &["interval", "http_statuses", "successes"],
        nested: &[],
    };
    const UNHEALTHY: ResourceSchema = ResourceSchema {
        fields: &["http_failures", "tcp_failures"],
        nested: &[],
    };
    const PASSIVE_CHECK: ResourceSchema = ResourceSchema {
        fields: &["type", "healthy", "unhealthy"],
        nested: &[
            ("healthy", "passive_healthy"),
            ("unhealthy", "passive_unhealthy"),
        ],
    };
    const PASSIVE_HEALTHY: ResourceSchema = ResourceSchema {
        fields: &["http_statuses", "successes"],
        nested: &[],
    };
    const PASSIVE_UNHEALTHY: ResourceSchema = ResourceSchema {
        fields: &["http_statuses", "tcp_failures", "timeouts", "http_failures"],
        nested: &[],
    };
    match id {
        "route" => Some(&ROUTE),
        "upstream" => Some(&UPSTREAM),
        "service" => Some(&SERVICE),
        "global_rule" => Some(&GLOBAL_RULE),
        "ssl" => Some(&SSL),
        "timeout" => Some(&TIMEOUT),
        "upstream_tls" => Some(&UPSTREAM_TLS),
        "health_check" => Some(&HEALTH_CHECK),
        "active_check" => Some(&ACTIVE_CHECK),
        "health" => Some(&HEALTH),
        "unhealthy" => Some(&UNHEALTHY),
        "passive_check" => Some(&PASSIVE_CHECK),
        "passive_healthy" => Some(&PASSIVE_HEALTHY),
        "passive_unhealthy" => Some(&PASSIVE_UNHEALTHY),
        _ => None,
    }
}

/// Edit distance between two short field names for typo suggestions.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for (i, ac) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, bc) in b.iter().enumerate() {
            let cost = if ac == bc { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Warn about unrecognized fields on a resource object, suggesting likely
/// typos of known behavior fields. Unknown fields are still accepted (ingress
/// metadata compatibility); this only logs, so a typo like `retry_timout` does
/// not fail silently while the operator believes it took effect.
///
/// `resource_type` is the plural store segment (e.g. `"upstreams"`).
pub(crate) fn warn_unrecognized_fields(resource_type: &str, value: &JsonValue) {
    for warning in unrecognized_fields(resource_type, value) {
        if let Some(suggestion) = warning.suggestion {
            log::warn!(
                "Configuration: field '{}' is not recognized; did you mean '{}'? It will be ignored.",
                warning.path,
                suggestion,
            );
        } else {
            log::warn!(
                "Configuration: field '{}' is not recognized and will be ignored.",
                warning.path,
            );
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FieldWarning {
    path: String,
    suggestion: Option<&'static str>,
}

/// Find warnings without emitting them, keeping warning traversal testable.
fn unrecognized_fields(resource_type: &str, value: &JsonValue) -> Vec<FieldWarning> {
    let schema_id = match resource_type {
        "routes" => "route",
        "upstreams" => "upstream",
        "services" => "service",
        "global_rules" => "global_rule",
        "ssls" => "ssl",
        _ => return Vec::new(),
    };
    let mut warnings = Vec::new();
    collect_schema_warnings(schema_id, resource_type, value, &mut warnings);
    warnings
}

fn collect_schema_warnings(
    schema_id: &str,
    path: &str,
    value: &JsonValue,
    warnings: &mut Vec<FieldWarning>,
) {
    let (Some(schema), Some(obj)) = (schema_for(schema_id), value.as_object()) else {
        return;
    };
    for (key, val) in obj {
        let field_path = format!("{path}.{key}");
        if schema.fields.contains(&key.as_str()) {
            if let Some(nested_id) = schema
                .nested
                .iter()
                .find_map(|(field, id)| (*field == key.as_str()).then_some(*id))
            {
                collect_schema_warnings(nested_id, &field_path, val, warnings);
            }
            continue;
        }
        warnings.push(FieldWarning {
            path: field_path,
            suggestion: suggest_field(schema, key, key.chars().count()),
        });
    }
}

/// Closest known field to `key` within edit distance 1..=2, else `None`.
fn suggest_field(schema: &ResourceSchema, key: &str, key_len: usize) -> Option<&'static str> {
    schema
        .fields
        .iter()
        .copied()
        .filter(|known| known.chars().count().abs_diff(key_len) <= 2)
        .map(|known| (known, edit_distance(key, known)))
        .filter(|(_, d)| *d > 0 && *d <= 2)
        .min_by_key(|(_, d)| *d)
        .map(|(k, _)| k)
}

/// Best-effort unrecognized-field warnings for the top-level resource arrays of
/// a static YAML document (etcd/Admin resources are checked at decode time).
fn warn_static_resources(graph: &JsonValue) {
    for key in ["routes", "upstreams", "services", "global_rules", "ssls"] {
        if let Some(arr) = graph.get(key).and_then(|v| v.as_array()) {
            for elem in arr {
                warn_unrecognized_fields(key, elem);
            }
        }
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Pingsix {
    #[validate(length(min = 1))]
    #[validate(nested)]
    pub listeners: Vec<Listener>,

    #[validate(nested)]
    pub etcd: Option<Etcd>,

    #[validate(nested)]
    pub admin: Option<Admin>,

    #[validate(nested)]
    pub status: Option<Status>,

    #[validate(nested)]
    pub prometheus: Option<Prometheus>,

    #[validate(nested)]
    pub sentry: Option<Sentry>,

    #[validate(nested)]
    pub log: Option<Log>,

    #[validate(nested)]
    pub defaults: Option<Defaults>,

    /// Encrypt sensitive fields (e.g. SSL private keys) when storing them in etcd.
    #[validate(nested)]
    pub data_encryption: Option<DataEncryption>,
}

/// Keyring used to encrypt/decrypt sensitive configuration fields in etcd.
///
/// The first keyring entry encrypts new values. On read, every entry is tried
/// in order so rotated keys can still decrypt older ciphertext.
#[derive(Clone, Default, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "DataEncryption::validate_keyring"))]
#[serde(deny_unknown_fields)]
pub struct DataEncryption {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub keyring: Vec<String>,
}

impl DataEncryption {
    fn validate_keyring(&self) -> Result<(), ValidationError> {
        if !self.enable {
            return Ok(());
        }
        if self.keyring.is_empty() {
            return Err(ValidationError::new("data_encryption_keyring_required"));
        }
        if self.keyring.iter().any(|k| k.is_empty()) {
            return Err(ValidationError::new("data_encryption_keyring_entry_empty"));
        }
        Ok(())
    }
}

/// Global default settings applied when a route/upstream does not override them.
#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Fallback upstream connect/read/send timeout used when a route or
    /// upstream does not set its own `timeout`.
    #[validate(nested)]
    pub upstream_timeout: Option<Timeout>,
    /// Maximum time spent resolving an upstream DNS name before the candidate
    /// is rejected. Defaults to five seconds.
    #[serde(default = "Defaults::default_dns_resolution_timeout")]
    #[validate(range(min = 1, max = 60))]
    pub dns_resolution_timeout: u64,
    /// Optional interval for refreshing DNS-based upstream backends after publish.
    /// `None` disables periodic DNS refresh.
    #[serde(default)]
    #[validate(range(min = 1, max = 3600))]
    pub dns_refresh_interval: Option<u64>,
    #[validate(nested)]
    pub cache: Option<CacheDefaults>,
}

/// Default capacity knobs for the response cache.
#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct CacheDefaults {
    #[serde(default = "CacheDefaults::default_max_memory_bytes")]
    pub max_memory_bytes: usize,
    #[serde(default = "CacheDefaults::default_max_object_bytes")]
    pub default_max_object_bytes: usize,
}

impl Defaults {
    fn default_dns_resolution_timeout() -> u64 {
        5
    }
}

impl CacheDefaults {
    /// 512 MB.
    fn default_max_memory_bytes() -> usize {
        512 * 1024 * 1024
    }

    /// 1 MB.
    fn default_max_object_bytes() -> usize {
        1024 * 1024
    }
}

impl Default for CacheDefaults {
    fn default() -> Self {
        Self {
            max_memory_bytes: Self::default_max_memory_bytes(),
            default_max_object_bytes: Self::default_max_object_bytes(),
        }
    }
}

/// Instance-owned effective defaults resolved once at startup from
/// `pingsix.defaults` (plus built-in fallbacks for unset knobs).
///
/// The process-global `init_*`/getter facade remains for migration; new code
/// resolves its fallbacks from an injected `EffectiveDefaults` at construction
/// time so two gateway runtimes in one process can use different defaults.
#[derive(Clone, Debug)]
pub struct EffectiveDefaults {
    /// Fallback upstream timeout used when neither route nor upstream sets one.
    pub upstream_timeout: Option<Timeout>,
    /// Maximum time spent resolving an upstream DNS name (seconds).
    pub dns_resolution_timeout: u64,
    /// Optional DNS refresh interval for published upstream load balancers.
    pub dns_refresh_interval: Option<u64>,
    /// Response-cache capacity knobs.
    pub cache: CacheDefaults,
}

impl EffectiveDefaults {
    /// Resolve effective defaults from `pingsix.defaults`, applying the same
    /// built-in fallbacks the deserializer would use for absent fields.
    pub fn from_pingsix(cfg: &Pingsix) -> Self {
        let defaults = cfg.defaults.as_ref();
        Self {
            upstream_timeout: defaults.and_then(|d| d.upstream_timeout.clone()),
            dns_resolution_timeout: defaults
                .map(|d| d.dns_resolution_timeout)
                .unwrap_or_else(Defaults::default_dns_resolution_timeout),
            dns_refresh_interval: defaults.and_then(|d| d.dns_refresh_interval),
            cache: defaults.and_then(|d| d.cache.clone()).unwrap_or_default(),
        }
    }

    /// The migration-period process-global defaults, read from the legacy
    /// `init_*` OnceCells so the facade and injected paths agree.
    pub fn global() -> Self {
        Self {
            upstream_timeout: default_upstream_timeout(),
            dns_resolution_timeout: dns_resolution_timeout(),
            dns_refresh_interval: dns_refresh_interval(),
            cache: CacheDefaults {
                max_memory_bytes: crate::service::http::configured_max_memory_bytes(),
                default_max_object_bytes: crate::plugins::cache::default_max_object_bytes(),
            },
        }
    }
}

impl Default for EffectiveDefaults {
    fn default() -> Self {
        Self {
            upstream_timeout: None,
            dns_resolution_timeout: Defaults::default_dns_resolution_timeout(),
            dns_refresh_interval: None,
            cache: CacheDefaults::default(),
        }
    }
}

/// Global default upstream timeout, populated once at startup from
/// `pingsix.defaults.upstream_timeout`. Used as a fallback when a route or
/// upstream does not configure its own `timeout`.
///
/// Migration facade retained as test scaffolding: production resolves
/// [`EffectiveDefaults`] per gateway build; these OnceCells back
/// [`EffectiveDefaults::global`] and the legacy getters used by unit tests.
static DEFAULT_UPSTREAM_TIMEOUT: once_cell::sync::OnceCell<Option<Timeout>> =
    once_cell::sync::OnceCell::new();
static DNS_RESOLUTION_TIMEOUT: once_cell::sync::OnceCell<u64> = once_cell::sync::OnceCell::new();
static DNS_REFRESH_INTERVAL: once_cell::sync::OnceCell<Option<u64>> =
    once_cell::sync::OnceCell::new();

/// Populate the global default upstream timeout from configuration. Called once
/// at startup. Subsequent calls are no-ops (first value wins), which keeps
/// parallel test initialization safe.
pub fn init_default_upstream_timeout(timeout: Option<Timeout>) {
    let _ = DEFAULT_UPSTREAM_TIMEOUT.set(timeout);
}

/// Returns the configured global default upstream timeout, if any.
pub fn default_upstream_timeout() -> Option<Timeout> {
    DEFAULT_UPSTREAM_TIMEOUT.get().cloned().flatten()
}

/// Populate the finite DNS resolution deadline from configuration.
pub fn init_dns_resolution_timeout(timeout: u64) {
    let _ = DNS_RESOLUTION_TIMEOUT.set(timeout);
}

/// DNS deadline used by discovery when no startup configuration has initialized it.
pub fn dns_resolution_timeout() -> u64 {
    *DNS_RESOLUTION_TIMEOUT.get_or_init(Defaults::default_dns_resolution_timeout)
}

/// Populate the optional DNS refresh interval from configuration.
pub fn init_dns_refresh_interval(interval: Option<u64>) {
    let _ = DNS_REFRESH_INTERVAL.set(interval);
}

/// Optional DNS refresh interval for published upstream load balancers.
pub fn dns_refresh_interval() -> Option<u64> {
    DNS_REFRESH_INTERVAL.get().cloned().flatten()
}

/// Install the process-wide data-encryption keyring used when reading/writing
/// sensitive fields in etcd. First call wins.
pub fn init_data_encryption(enable: bool, keyring: &[String]) -> crate::core::ProxyResult<()> {
    crate::utils::encryption::init(enable, keyring)
}

/// Apply `op` (encrypt / decrypt / redact) to sensitive fields of a resource's
/// JSON representation, dispatched by etcd resource type.
///
/// This is the single wiring point shared by the admin write path (encrypt),
/// the control-plane load path (decrypt) and the admin read API (redact). Each
/// resource type delegates to its own `#[derive(EncryptFields)]` implementation,
/// so marking a new secret field with `#[encrypt]` on the struct wires up all
/// three paths at once — no changes here, and no separate redaction list.
/// Unknown resource types pass through unchanged.
pub fn transform_resource_secrets(
    keyring: &crate::utils::encryption::KeyringService,
    resource_type: &str,
    value: &mut JsonValue,
    op: SecretOp,
) -> crate::core::ProxyResult<()> {
    use crate::utils::encryption::EncryptFields;
    match resource_type {
        "ssls" => SSL::transform_secrets(value, op, keyring),
        "upstreams" => Upstream::transform_secrets(value, op, keyring),
        "routes" => Route::transform_secrets(value, op, keyring),
        "services" => Service::transform_secrets(value, op, keyring),
        "global_rules" => GlobalRule::transform_secrets(value, op, keyring),
        _ => Ok(()),
    }
}

/// Finite peer-I/O fallback used whenever neither a route nor upstream nor
/// global defaults provide a timeout.
pub const BUILTIN_UPSTREAM_TIMEOUT: Timeout = Timeout {
    connect: 5,
    send: 30,
    read: 30,
};

/// Resolve the effective timeout for a route/upstream: explicit > configured
/// global > built-in fallback. This always produces finite peer timeouts.
pub fn resolve_upstream_timeout(explicit: Option<Timeout>, global: Option<Timeout>) -> Timeout {
    explicit.or(global).unwrap_or(BUILTIN_UPSTREAM_TIMEOUT)
}

/// TLS/mTLS configuration for connecting to etcd.
#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "EtcdTls::validate_mtls_pair"))]
#[serde(deny_unknown_fields)]
pub struct EtcdTls {
    #[validate(length(min = 1))]
    pub ca_cert: String,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub domain: Option<String>,
}

impl EtcdTls {
    /// mTLS requires both a client cert and a client key, or neither. A partial
    /// pair would silently skip mTLS, so reject it at config-validation time.
    fn validate_mtls_pair(&self) -> Result<(), ValidationError> {
        match (&self.client_cert, &self.client_key) {
            (Some(_), Some(_)) | (None, None) => Ok(()),
            _ => Err(ValidationError::new("mtls_cert_and_key_required_together")),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Listener::validate_tls_for_offer_h2"))]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub address: SocketAddr,
    pub tls: Option<Tls>,
    #[serde(default)]
    pub offer_h2: bool,
    #[serde(default)]
    pub offer_h2c: bool,
}

impl Listener {
    fn validate_tls_for_offer_h2(&self) -> Result<(), ValidationError> {
        if self.offer_h2 && self.tls.is_none() {
            Err(ValidationError::new("tls_required_for_h2"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "Etcd::validate_connection"))]
#[serde(deny_unknown_fields)]
pub struct Etcd {
    #[validate(length(min = 1))]
    pub host: Vec<String>,
    #[validate(length(min = 1))]
    pub prefix: String,
    pub timeout: Option<u32>,
    pub connect_timeout: Option<u32>,
    pub user: Option<String>,
    pub password: Option<String>,
    #[validate(nested)]
    pub tls: Option<EtcdTls>,
}

impl Etcd {
    fn validate_connection(&self) -> Result<(), ValidationError> {
        match (&self.user, &self.password) {
            (None, None) => {}
            (Some(user), Some(password))
                if !user.trim().is_empty() && !password.trim().is_empty() => {}
            _ => {
                return Err(ValidationError::new(
                    "etcd_user_and_password_required_together",
                ))
            }
        }
        crate::config::etcd::validate_etcd_endpoints(&self.host, self.tls.is_some())
            .map(|_| ())
            .map_err(|_| ValidationError::new("invalid_etcd_endpoint"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    pub address: SocketAddr,
    #[validate(length(min = 1), custom(function = "Admin::validate_api_key"))]
    pub api_key: String,
    /// Allow binding Admin to a non-loopback address without TLS (default: false).
    #[serde(default)]
    pub allow_insecure_remote: bool,
}

impl Admin {
    fn validate_api_key(api_key: &str) -> Result<(), ValidationError> {
        if api_key.trim().is_empty() {
            return Err(ValidationError::new("api_key_required"));
        }
        Ok(())
    }

    /// Admin has no TLS listener today: non-loopback binds require an explicit insecure opt-in.
    pub fn validate_bind_safety(&self) -> Result<(), String> {
        if self.address.ip().is_loopback() {
            return Ok(());
        }
        if self.allow_insecure_remote {
            log::warn!(
                "Admin API is bound to non-loopback address {} with allow_insecure_remote=true. \
                 API key may be transmitted in cleartext. Admin TLS binding is not supported.",
                self.address
            );
            return Ok(());
        }
        Err(format!(
            "Admin API refuses non-loopback plaintext bind at {}. \
             Use a loopback address (recommended) or set allow_insecure_remote: true. \
             Admin TLS binding is not supported.",
            self.address
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub address: SocketAddr,
    /// Seconds after which an etcd sync is considered stale (default: 300).
    #[serde(default)]
    pub config_stale_after: Option<u64>,
    /// Readiness fails when etcd has remained disconnected past the threshold.
    #[serde(default = "Status::default_fail_readiness_when_stale")]
    pub fail_readiness_when_stale: bool,
    /// Required to expose detailed diagnostics on a non-loopback plaintext listener.
    #[serde(default)]
    pub diagnostics_api_key: Option<String>,
    /// Explicitly allow protected diagnostics on a non-loopback plaintext listener.
    #[serde(default)]
    pub allow_insecure_remote: bool,
}

impl Status {
    fn default_fail_readiness_when_stale() -> bool {
        true
    }

    pub fn diagnostics_enabled(&self) -> bool {
        self.address.ip().is_loopback()
            || (self.allow_insecure_remote
                && self
                    .diagnostics_api_key
                    .as_deref()
                    .is_some_and(|key| !key.trim().is_empty()))
    }

    /// Warn about non-loopback binds. Unlike `Admin`, the status endpoint
    /// exposes no sensitive data without authenticated diagnostics, so an
    /// insecure bind is warned rather than refused.
    pub fn log_bind_safety(&self) {
        if self.diagnostics_enabled() && !self.address.ip().is_loopback() {
            log::warn!(
                "Status diagnostics are enabled on non-loopback plaintext address {}. API keys are transmitted in cleartext.",
                self.address
            );
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Prometheus {
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Sentry {
    pub dsn: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Log {
    #[validate(length(min = 1), custom(function = "Log::validate_path"))]
    pub path: String,
    #[serde(default = "Log::default_max_size_bytes")]
    #[validate(range(min = 1))]
    pub max_size_bytes: u64,
    #[serde(default = "Log::default_max_backups")]
    pub max_backups: u32,
    /// Internal size-based rotation is the bounded production default. External
    /// and disabled modes must be selected explicitly.
    #[serde(default)]
    pub rotation: LogRotation,

    /// Bounded capacity of the async log channel (buffered log lines pending the
    /// writer). Defaults to 4096; larger values smooth bursts at the cost of
    /// memory under a stalled sink.
    #[serde(default = "Log::default_channel_capacity")]
    #[validate(range(min = 64))]
    pub channel_capacity: usize,
}

/// Log file rotation strategy.
///
/// Only `Internal` rotates in-process. `External` and `Disabled` never reopen
/// the file: the writer keeps its descriptor open, so an external rotator must
/// use copytruncate semantics (or the process must be restarted) after a
/// rename-based rotation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    #[default]
    Internal,
    /// No in-process rotation; rely on an external rotator (copytruncate).
    External,
    /// No rotation at all; the file grows unbounded.
    Disabled,
}

impl Log {
    fn default_max_size_bytes() -> u64 {
        100 * 1024 * 1024
    }

    fn default_max_backups() -> u32 {
        5
    }

    fn default_channel_capacity() -> usize {
        4096
    }

    fn validate_path(path: &str) -> Result<(), ValidationError> {
        if path.contains('\0') || path.trim().is_empty() {
            return Err(ValidationError::new("Invalid log file path"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert_path: String,
    pub key_path: String,
}

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
            return Err(ValidationError::new("upstream_or_service_required"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::encryption::EncryptFields;
    use crate::utils::encryption::KeyringService;
    use http::Method;

    fn init_log() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn passive_schema_accepts_disabled_thresholds_and_rejects_bad_statuses() {
        let valid = PassiveCheck {
            r#type: PassiveCheckType::HTTP,
            healthy: PassiveHealthy {
                http_statuses: vec![200],
                successes: 0,
            },
            unhealthy: PassiveUnhealthy {
                http_statuses: vec![500],
                tcp_failures: 0,
                timeouts: 0,
                http_failures: 0,
            },
        };
        assert!(valid.validate().is_ok());

        for statuses in [vec![], vec![199], vec![600], vec![500, 500]] {
            let mut invalid = valid.clone();
            invalid.unhealthy.http_statuses = statuses;
            assert!(invalid.validate().is_err());
        }
        let mut too_large = valid;
        too_large.healthy.successes = 255;
        assert!(too_large.validate().is_err());
    }

    #[test]
    fn health_check_requires_active_or_passive() {
        // Passive-only is valid (APISIX allows a `checks` block with only passive).
        let passive_only = HealthCheck {
            active: None,
            passive: Some(PassiveCheck {
                r#type: PassiveCheckType::HTTP,
                healthy: PassiveHealthy::default(),
                unhealthy: PassiveUnhealthy::default(),
            }),
        };
        assert!(passive_only.validate().is_ok());

        // Neither active nor passive is rejected.
        let neither = HealthCheck {
            active: None,
            passive: None,
        };
        assert!(neither.validate().is_err());
    }

    #[test]
    fn test_print_default_yaml() {
        init_log();
        let conf = Config::default();
        println!("{}", conf.to_yaml());
    }

    #[test]
    fn test_load_file() {
        init_log();
        let conf_str = r#"
---
pingora:
  version: 1
  client_bind_to_ipv4:
      - 1.2.3.4
      - 5.6.7.8
  client_bind_to_ipv6: []

pingsix:
  listeners:
    - address: 0.0.0.0:8080
    - address: "[::1]:8080"
      tls:
        cert_path: /etc/ssl/server.crt
        key_path: /etc/ssl/server.key
      offer_h2: true

routes:
  - id: "1"
    uri: /
    methods: [GET, POST]
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http

upstreams:
  - nodes:
      "127.0.0.1:1980": 1
    id: "1"
    checks:
      active:
        type: http

services:
  - id: "1"
    upstream_id: "1"
    hosts: ["example.com"]
        "#;
        let conf = Config::from_yaml(conf_str).unwrap();
        assert_eq!(2, conf.pingora.client_bind_to_ipv4.len());
        assert_eq!(0, conf.pingora.client_bind_to_ipv6.len());
        assert_eq!(1, conf.pingora.version);
        assert_eq!(2, conf.pingsix.listeners.len());
        assert_eq!(1, conf.routes.len());
        assert_eq!(1, conf.upstreams.len());
        assert_eq!(1, conf.services.len());
        assert_eq!(vec![Method::GET, Method::POST], conf.routes[0].methods);
        print!("{}", conf.to_yaml());
    }

    #[test]
    fn test_load_file_upstream_id() {
        init_log();
        let conf_str = r#"
---
pingora:
  version: 1
  client_bind_to_ipv4:
      - 1.2.3.4
      - 5.6.7.8
  client_bind_to_ipv6: []

pingsix:
  listeners:
    - address: 0.0.0.0:8080
      offer_h2c: true
    - address: "[::1]:8080"
      tls:
        cert_path: /etc/ssl/server.crt
        key_path: /etc/ssl/server.key
      offer_h2: true

routes:
  - id: "1"
    uri: /
    methods: [GET]
    upstream_id: "1"

upstreams:
  - nodes:
      "127.0.0.1:1980": 1
    id: "1"
    checks:
      active:
        type: http
  - nodes:
      "127.0.0.1:1981": 1
    id: "2"
    checks:
      active:
        type: http

services:
  - id: "1"
    upstream_id: "1"
    hosts: ["example.com"]
        "#;
        let conf = Config::from_yaml(conf_str).unwrap();
        assert_eq!(2, conf.pingora.client_bind_to_ipv4.len());
        assert_eq!(0, conf.pingora.client_bind_to_ipv6.len());
        assert_eq!(1, conf.pingora.version);
        assert_eq!(2, conf.pingsix.listeners.len());
        assert_eq!(1, conf.routes.len());
        assert_eq!(2, conf.upstreams.len());
        assert_eq!(1, conf.services.len());
        assert_eq!(vec![Method::GET], conf.routes[0].methods);
        print!("{}", conf.to_yaml());
    }

    #[test]
    fn test_valid_listeners_length() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners: []

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {e:?}");
                // Test passes if we get an error
            }
        }
    }

    #[test]
    fn test_valid_listeners_tls_for_offer_h2() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
      offer_h2: true

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {e:?}");
                // Test passes if we get an error
            }
        }
    }

    #[test]
    fn test_valid_routes_uri_and_uris() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {e:?}");
                // Test passes if we get an error
            }
        }
    }

    #[test]
    fn route_rejects_uri_and_uris_together() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    uris: ["/other"]
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
        assert!(
            Config::from_yaml(conf_str).is_err(),
            "uri and uris are mutually exclusive forms"
        );
    }

    #[test]
    fn route_rejects_host_and_hosts_together() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    host: api.example.com
    hosts: ["other.example.com"]
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
        assert!(
            Config::from_yaml(conf_str).is_err(),
            "host and hosts are mutually exclusive forms"
        );
    }

    #[test]
    fn route_rejects_upstream_and_upstream_id_together() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
    upstream_id: "named-upstream"
        "#;
        assert!(
            Config::from_yaml(conf_str).is_err(),
            "inline upstream and upstream_id are mutually exclusive forms"
        );
    }

    #[test]
    fn route_allows_upstream_id_with_service_id() {
        init_log();
        // Route-level upstream_id overriding a service's upstream is a valid
        // APISIX pattern and must remain accepted.
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

services:
  - id: "s1"
    upstream:
      nodes:
        "127.0.0.1:1981": 1

routes:
  - id: "1"
    uri: /
    upstream_id: "u1"
    service_id: "s1"

upstreams:
  - id: "u1"
    nodes:
      "127.0.0.1:1982": 1
        "#;
        assert!(
            Config::from_yaml(conf_str).is_ok(),
            "upstream_id + service_id must remain valid"
        );
    }

    #[test]
    fn service_rejects_upstream_and_upstream_id_together() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

services:
  - id: "s1"
    upstream:
      nodes:
        "127.0.0.1:1981": 1
    upstream_id: "u1"
        "#;
        assert!(
            Config::from_yaml(conf_str).is_err(),
            "service inline upstream and upstream_id are mutually exclusive"
        );
    }

    #[test]
    fn test_valid_routes_upstream_host() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      pass_host: rewrite
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {e:?}");
                // Test passes if we get an error
            }
        }
    }

    #[test]
    fn test_valid_config_upstream_id() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http

upstreams:
  - nodes:
      "127.0.0.1:1980": 1
    checks:
      active:
        type: http
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {e:?}");
                // Test passes if we get an error
            }
        }
    }

    #[test]
    fn test_valid_route_upstream() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {e:?}");
                // Test passes if we get an error
            }
        }
    }

    #[test]
    fn test_valid_service_upstream() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http

services:
  - id: "1"
    hosts: ["example.com"]
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {e:?}");
                // Test passes if we get an error
            }
        }
    }

    #[test]
    fn test_admin_api_key_must_not_be_empty() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
  admin:
    address: "127.0.0.1:9180"
    api_key: "   "

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;

        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {e:?}");
            }
        }
    }

    #[test]
    fn test_duplicate_ids() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
  - id: "1"
    uri: /other
    upstream:
      nodes:
        "127.0.0.1:1981": 1

upstreams:
  - id: "1"
    nodes:
      "127.0.0.1:1980": 1
  - id: "1"
    nodes:
      "127.0.0.1:1981": 1
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {e:?}");
                // Test passes if we get an error
            }
        }
    }

    #[test]
    fn test_invalid_node_key() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "-invalid.com:8080": 1
        "#;
        let conf = Config::from_yaml(conf_str);
        match conf {
            Ok(_) => panic!("Expected error, but got a valid config"),
            Err(e) => {
                eprintln!("Error: {e:?}");
                // Test passes if we get an error
            }
        }
    }

    #[test]
    fn test_upstream_with_tls() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      scheme: https
      tls:
        client_cert: |
          -----BEGIN CERTIFICATE-----
          MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
          A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
          aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
          ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
          CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
          dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
          dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
          BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
          uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
          DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
          SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
          l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
          -----END CERTIFICATE-----
        client_key: |
          -----BEGIN EC PRIVATE KEY-----
          MHcCAQEEIIrYSSNdykVHguvz6t+tCg4EBdAy/pQjf4qwl3VhfhBloAoGCCqGSM49
          AwEHoUQDQgAEUtiNI4rjZ9eGNrEgCwl9yMm6oiCVL8VKY/qDX854L4/zYsr9t/eA
          Vp1uF7kOEUxIssCvO1kXFjBoCQeZF/7dp6A==
          -----END EC PRIVATE KEY-----

upstreams:
  - id: "1"
    nodes:
      "192.168.1.100:8443": 1
    scheme: https
    tls:
      client_cert: |
        -----BEGIN CERTIFICATE-----
        MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
        A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
        aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
        ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
        CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
        dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
        dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
        BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
        uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
        DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
        SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
        l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
        -----END CERTIFICATE-----
      client_key: |
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIIrYSSNdykVHguvz6t+tCg4EBdAy/pQjf4qwl3VhfhBloAoGCCqGSM49
        AwEHoUQDQgAEUtiNI4rjZ9eGNrEgCwl9yMm6oiCVL8VKY/qDX854L4/zYsr9t/eA
        Vp1uF7kOEUxIssCvO1kXFjBoCQeZF/7dp6A==
        -----END EC PRIVATE KEY-----
        "#;
        let conf = Config::from_yaml(conf_str).unwrap();
        assert_eq!(1, conf.routes.len());
        assert_eq!(1, conf.upstreams.len());

        // Check route upstream TLS config
        let route_upstream = conf.routes[0].upstream.as_ref().unwrap();
        assert!(route_upstream.tls.is_some());
        let route_tls = route_upstream.tls.as_ref().unwrap();
        assert!(route_tls.client_cert.contains("BEGIN CERTIFICATE"));
        assert!(route_tls.client_key.contains("BEGIN EC PRIVATE KEY"));

        // Check upstream TLS config
        let upstream = &conf.upstreams[0];
        assert!(upstream.tls.is_some());
        let upstream_tls = upstream.tls.as_ref().unwrap();
        assert!(upstream_tls.client_cert.contains("BEGIN CERTIFICATE"));
        assert!(upstream_tls.client_key.contains("BEGIN EC PRIVATE KEY"));
    }

    #[test]
    fn upstream_tls_encrypt_fields_visits_client_key_not_cert() {
        use crate::utils::encryption::CIPHERTEXT_PREFIX;

        let mut cfg = serde_json::json!({
            "nodes": { "127.0.0.1:443": 1 },
            "tls": {
                "client_cert": "cert-pem",
                "client_key": format!("{CIPHERTEXT_PREFIX}deadbeef"),
            }
        });
        let err =
            Upstream::transform_secrets(&mut cfg, SecretOp::Decrypt, &KeyringService::global())
                .unwrap_err();
        assert!(
            err.to_string().contains("data_encryption is disabled")
                || err.to_string().contains("Encrypted value"),
            "{err}"
        );
        assert_eq!(cfg["tls"]["client_cert"], "cert-pem");
    }

    /// A resource's derived `EncryptFields` must descend into its `plugins`
    /// map (via `#[encrypt(plugins)]`) and its inline `upstream`, so wiring a
    /// new secret only requires marking the plugin/struct field.
    #[test]
    fn route_transform_secrets_walks_plugins_and_inline_upstream() {
        use crate::utils::encryption::CIPHERTEXT_PREFIX;

        // Ciphertext with encryption disabled surfaces an error, proving the
        // walk reached the plugin secret field.
        let mut route = serde_json::json!({
            "uri": "/",
            "plugins": {
                "basic-auth": {
                    "username": "demo",
                    "password": format!("{CIPHERTEXT_PREFIX}deadbeef"),
                }
            }
        });
        let err = transform_resource_secrets(
            &KeyringService::global(),
            "routes",
            &mut route,
            SecretOp::Decrypt,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("data_encryption is disabled")
                || err.to_string().contains("Encrypted value"),
            "{err}"
        );

        // Same for an inline upstream TLS private key.
        let mut route = serde_json::json!({
            "uri": "/",
            "upstream": {
                "nodes": { "127.0.0.1:443": 1 },
                "tls": {
                    "client_cert": "cert-pem",
                    "client_key": format!("{CIPHERTEXT_PREFIX}deadbeef"),
                }
            }
        });
        let err = transform_resource_secrets(
            &KeyringService::global(),
            "routes",
            &mut route,
            SecretOp::Decrypt,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("data_encryption is disabled")
                || err.to_string().contains("Encrypted value"),
            "{err}"
        );

        // Unknown resource types are a no-op pass-through.
        let mut other = serde_json::json!({ "foo": "bar" });
        transform_resource_secrets(
            &KeyringService::global(),
            "unknown",
            &mut other,
            SecretOp::Decrypt,
        )
        .unwrap();
        assert_eq!(other["foo"], "bar");
    }

    #[test]
    fn admin_bind_rejects_non_loopback_without_insecure_flag() {
        let admin = Admin {
            address: "0.0.0.0:9181".parse().unwrap(),
            api_key: "secret".into(),
            allow_insecure_remote: false,
        };
        assert!(admin.validate_bind_safety().is_err());
    }

    #[test]
    fn admin_bind_allows_loopback_and_explicit_insecure_remote() {
        let loopback = Admin {
            address: "127.0.0.1:9181".parse().unwrap(),
            api_key: "secret".into(),
            allow_insecure_remote: false,
        };
        assert!(loopback.validate_bind_safety().is_ok());

        let remote = Admin {
            address: "0.0.0.0:9181".parse().unwrap(),
            api_key: "secret".into(),
            allow_insecure_remote: true,
        };
        assert!(remote.validate_bind_safety().is_ok());
    }

    #[test]
    fn data_encryption_requires_keyring_when_enabled() {
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "127.0.0.1:8080"
  data_encryption:
    enable: true
    keyring: []
"#;
        assert!(Config::from_yaml(conf_str).is_err());
    }

    #[test]
    fn data_encryption_accepts_keyring() {
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "127.0.0.1:8080"
  data_encryption:
    enable: true
    keyring:
      - "12387412834"
      - "89731823413"
"#;
        let conf = Config::from_yaml(conf_str).unwrap();
        let enc = conf.pingsix.data_encryption.unwrap();
        assert!(enc.enable);
        assert_eq!(enc.keyring.len(), 2);
    }

    #[test]
    fn test_unknown_fields_in_resources_accepted() {
        init_log();
        // Resource types (Route, Upstream, Service, SSL) must tolerate unknown fields
        // for compatibility with ingress-controller which embeds metadata fields
        // (name, description, labels) in the serialized JSON/YAML.
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    name: "my-route"
    labels:
      managed-by: apisix-ingress-controller
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      retry_timout: 10
"#;
        let conf = Config::from_yaml(conf_str);
        assert!(
            conf.is_ok(),
            "Expected unknown fields in resources to be accepted, got error: {:?}",
            conf.err()
        );
    }

    #[test]
    fn unrecognized_field_warnings_include_full_typed_paths_and_skip_free_objects() {
        let resource = serde_json::json!({
            "nodes": { "backend:80": { "weigth": 1 } },
            "plugins": { "example": { "config_typo": true } },
            "metadata": { "annotation_typo": true },
            "checks": {
                "active": {
                    "healthy": { "sucesses": 2 },
                },
                "passive": {
                    "unhealthy": { "http_failuers": 3 },
                },
            },
            "tls": { "client_kay": "private" },
        });

        let warnings = unrecognized_fields("upstreams", &resource);
        assert_eq!(
            warnings,
            vec![
                FieldWarning {
                    path: "upstreams.checks.active.healthy.sucesses".into(),
                    suggestion: Some("successes"),
                },
                FieldWarning {
                    path: "upstreams.checks.passive.unhealthy.http_failuers".into(),
                    suggestion: Some("http_failures"),
                },
                FieldWarning {
                    path: "upstreams.tls.client_kay".into(),
                    suggestion: Some("client_key"),
                },
            ]
        );
    }

    #[test]
    fn unknown_field_typos_suggest_the_closest_known_field() {
        let upstream = schema_for("upstream").expect("upstream schema exists");
        // `retry_timout` is one deletion away from `retry_timeout`.
        assert_eq!(
            suggest_field(upstream, "retry_timout", "retry_timout".chars().count()),
            Some("retry_timeout")
        );
        // A completely unrelated field gets no suggestion.
        assert_eq!(
            suggest_field(
                upstream,
                "totally_unrelated",
                "totally_unrelated".chars().count()
            ),
            None
        );
        // A known field is not a typo of itself; suggestion is for *other* fields only.
        assert_eq!(
            suggest_field(
                schema_for("route").unwrap(),
                "upstream",
                "upstream".chars().count()
            ),
            None
        );
    }

    #[test]
    fn resolve_upstream_timeout_prefers_explicit() {
        init_log();
        let explicit = Timeout {
            connect: 1,
            send: 2,
            read: 3,
        };
        let global = Timeout {
            connect: 9,
            send: 9,
            read: 9,
        };
        let t = resolve_upstream_timeout(Some(explicit), Some(global));
        assert_eq!(t.connect, 1);
        assert_eq!(t.read, 3);
    }

    #[test]
    fn resolve_upstream_timeout_uses_global_when_explicit_none() {
        init_log();
        let global = Timeout {
            connect: 9,
            send: 9,
            read: 9,
        };
        let t = resolve_upstream_timeout(None, Some(global));
        assert_eq!(t.connect, 9);
    }

    #[test]
    fn resolve_upstream_timeout_uses_built_in_when_both_absent() {
        init_log();
        assert_eq!(
            resolve_upstream_timeout(None, None),
            BUILTIN_UPSTREAM_TIMEOUT
        );
    }

    #[test]
    fn log_rotation_defaults_internal_and_accepts_explicit_modes() {
        let internal: Log = serde_yml::from_str("path: /tmp/pingsix.log").unwrap();
        assert_eq!(internal.rotation, LogRotation::Internal);
        let external: Log =
            serde_yml::from_str("path: /tmp/pingsix.log\nrotation: external").unwrap();
        assert_eq!(external.rotation, LogRotation::External);
        let disabled: Log =
            serde_yml::from_str("path: /tmp/pingsix.log\nrotation: disabled").unwrap();
        assert_eq!(disabled.rotation, LogRotation::Disabled);
    }

    #[test]
    fn status_defaults_to_fail_closed_and_protects_remote_diagnostics() {
        let status: Status = serde_yml::from_str("address: 127.0.0.1:9000").unwrap();
        assert!(status.fail_readiness_when_stale);
        assert!(status.diagnostics_enabled());
        let remote: Status = serde_yml::from_str("address: 0.0.0.0:9000").unwrap();
        assert!(!remote.diagnostics_enabled());
    }

    #[test]
    fn test_health_check_port_out_of_range() {
        init_log();
        for port in [0u32, 70000] {
            let conf_str = format!(
                r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          port: {port}
"#
            );
            let conf = Config::from_yaml(&conf_str);
            assert!(
                conf.is_err(),
                "Expected health check port {port} to be rejected"
            );
        }
    }

    #[test]
    fn test_health_check_zero_interval_rejected() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          healthy:
            interval: 0
"#;
        assert!(Config::from_yaml(conf_str).is_err());
    }

    #[test]
    fn test_health_check_zero_timeout_rejected() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          timeout: 0
"#;
        assert!(Config::from_yaml(conf_str).is_err());
    }

    #[test]
    fn test_health_check_zero_successes_rejected() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          healthy:
            successes: 0
"#;
        assert!(Config::from_yaml(conf_str).is_err());
    }

    #[test]
    fn test_health_check_zero_failures_rejected() {
        init_log();
        for (field, yaml) in [
            (
                "http_failures",
                r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          unhealthy:
            http_failures: 0
"#,
            ),
            (
                "tcp_failures",
                r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          unhealthy:
            tcp_failures: 0
"#,
            ),
        ] {
            let conf = Config::from_yaml(yaml);
            assert!(
                conf.is_err(),
                "Expected health check {field}=0 to be rejected"
            );
        }
    }

    #[test]
    fn test_defaults_cache_parsed() {
        init_log();
        // Explicit values.
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
  defaults:
    cache:
      max_memory_bytes: 1048576
      default_max_object_bytes: 2048
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
"#;
        let conf = Config::from_yaml(conf_str).unwrap();
        let cache = conf
            .pingsix
            .defaults
            .expect("defaults present")
            .cache
            .expect("cache present");
        assert_eq!(cache.max_memory_bytes, 1048576);
        assert_eq!(cache.default_max_object_bytes, 2048);

        // Empty cache -> defaults 512MB / 1MB.
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
  defaults:
    cache: {}
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
"#;
        let conf = Config::from_yaml(conf_str).unwrap();
        let cache = conf
            .pingsix
            .defaults
            .expect("defaults present")
            .cache
            .expect("cache present");
        assert_eq!(cache.max_memory_bytes, 512 * 1024 * 1024);
        assert_eq!(cache.default_max_object_bytes, 1024 * 1024);
    }

    #[test]
    fn test_defaults_upstream_timeout_parsed() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
  defaults:
    upstream_timeout:
      connect: 1
      send: 2
      read: 3
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
"#;
        let conf = Config::from_yaml(conf_str).unwrap();
        let t = conf
            .pingsix
            .defaults
            .expect("defaults present")
            .upstream_timeout
            .expect("upstream_timeout present");
        assert_eq!(t.connect, 1);
        assert_eq!(t.send, 2);
        assert_eq!(t.read, 3);
    }

    #[test]
    fn test_etcd_tls_parsed() {
        init_log();
        let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
  etcd:
    host:
      - "https://127.0.0.1:2379"
    prefix: "/pingsix"
    tls:
      ca_cert: /a.pem
      client_cert: /c.pem
      client_key: /k.pem
      domain: etcd.x
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
"#;
        let conf = Config::from_yaml(conf_str).unwrap();
        let tls = conf
            .pingsix
            .etcd
            .expect("etcd present")
            .tls
            .expect("tls present");
        assert_eq!(tls.ca_cert, "/a.pem");
        assert_eq!(tls.client_cert.as_deref(), Some("/c.pem"));
        assert_eq!(tls.client_key.as_deref(), Some("/k.pem"));
        assert_eq!(tls.domain.as_deref(), Some("etcd.x"));
    }

    #[test]
    fn etcd_tls_rejects_partial_mtls() {
        use validator::Validate;
        // client_cert present without client_key must fail validation rather
        // than silently skip mTLS.
        let tls = EtcdTls {
            ca_cert: "/a.pem".to_string(),
            client_cert: Some("/c.pem".to_string()),
            client_key: None,
            domain: None,
        };
        assert!(tls.validate().is_err());

        // Symmetric: key without cert also fails.
        let tls = EtcdTls {
            ca_cert: "/a.pem".to_string(),
            client_cert: None,
            client_key: Some("/k.pem".to_string()),
            domain: None,
        };
        assert!(tls.validate().is_err());

        // Both present (or both absent) is valid.
        let tls = EtcdTls {
            ca_cert: "/a.pem".to_string(),
            client_cert: Some("/c.pem".to_string()),
            client_key: Some("/k.pem".to_string()),
            domain: None,
        };
        assert!(tls.validate().is_ok());

        let tls = EtcdTls {
            ca_cert: "/a.pem".to_string(),
            client_cert: None,
            client_key: None,
            domain: None,
        };
        assert!(tls.validate().is_ok());
    }

    #[test]
    fn upstream_yaml_accepts_both_map_and_list_nodes() {
        let map_yaml = r#"
id: u1
nodes:
  "127.0.0.1:1980": 1
"#;
        let list_yaml = r#"
id: u2
nodes:
  - host: 127.0.0.1
    port: 1980
    weight: 1
"#;
        let from_map: Upstream = serde_yml::from_str(map_yaml).unwrap();
        let from_list: Upstream = serde_yml::from_str(list_yaml).unwrap();
        assert!(from_map.nodes.contains_addr("127.0.0.1:1980"));
        assert!(from_list.nodes.contains_addr("127.0.0.1:1980"));
        assert!(from_map.validate().is_ok());
        assert!(from_list.validate().is_ok());
    }

    #[test]
    fn upstream_rejects_mixed_map_and_list_node_forms() {
        // YAML cannot express map entries and sequence items in the same
        // mapping value; the document itself is invalid.
        let mixed_yaml = r#"
id: u1
nodes:
  "127.0.0.1:1980": 1
  - host: 10.0.0.2
    port: 1980
    weight: 1
"#;
        assert!(
            serde_yml::from_str::<Upstream>(mixed_yaml).is_err(),
            "mixed map/list under nodes must not parse"
        );
    }

    fn upstream_with_nodes(nodes: &str, scheme: &str) -> Upstream {
        let yaml = format!("id: u1\nscheme: {scheme}\nnodes:\n{nodes}");
        serde_yml::from_str(&yaml).expect("valid upstream yaml")
    }

    #[test]
    fn upstream_rejects_duplicate_node_addresses() {
        let dup = upstream_with_nodes(
            "  - host: 127.0.0.1\n    port: 443\n    priority: -1\n  \
             - host: 127.0.0.1\n    port: 443\n    priority: 10\n",
            "https",
        );
        let err = dup.validate().expect_err("duplicate host:port must fail");
        assert!(
            err.to_string().contains("nodes_duplicate_address"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn upstream_rejects_omitted_port_colliding_with_scheme_default() {
        // Over HTTP the portless node dials :80, so these are one endpoint and
        // Pingora would collapse them into a single backend.
        let http = upstream_with_nodes(
            "  - host: example.com\n  - host: example.com\n    port: 80\n",
            "http",
        );
        let err = http
            .validate()
            .expect_err("omitted port must collide with explicit :80 over http");
        assert!(
            err.to_string().contains("nodes_duplicate_address"),
            "unexpected error: {err}"
        );

        // Over HTTPS the same pair dials :443 and :80, so they are distinct.
        let https = upstream_with_nodes(
            "  - host: example.com\n  - host: example.com\n    port: 80\n",
            "https",
        );
        assert!(
            https.validate().is_ok(),
            "explicit :80 must not collide with the https default :443"
        );

        let grpcs = upstream_with_nodes(
            "  - host: example.com\n  - host: example.com\n    port: 443\n",
            "grpcs",
        );
        assert!(
            grpcs.validate().is_err(),
            "omitted port must collide with explicit :443 over grpcs"
        );
    }

    #[test]
    fn upstream_duplicate_check_ignores_disabled_nodes() {
        let with_disabled = upstream_with_nodes(
            "  - host: example.com\n    port: 80\n  - host: example.com\n    port: 80\n    weight: 0\n",
            "http",
        );
        assert!(
            with_disabled.validate().is_ok(),
            "a weight 0 node never becomes a backend, so it cannot collide"
        );
    }

    #[test]
    fn upstream_nested_nodes_validation_reports_invalid_host_without_panicking() {
        // `#[validate(nested)]` wraps the manual `Nodes::validate` errors; the
        // merged path must surface the specific error instead of panicking on
        // duplicate field entries.
        let up = upstream_with_nodes(
            "  - host: 'not a host'\n    port: 80\n  - host: 'also bad'\n    port: 80\n",
            "http",
        );
        let err = up
            .validate()
            .expect_err("invalid node hosts must fail upstream validation");
        assert!(
            err.to_string().contains("invalid_host"),
            "nested error must name the real cause: {err}"
        );
    }

    #[test]
    fn upstream_rejects_explicit_zero_port_in_list_form() {
        // An explicit `port: 0` must be a parse error (like `"host:0"` in the
        // map form), never a silent remap to the scheme default.
        let yaml = "id: u1\nscheme: http\nnodes:\n  - host: example.com\n    port: 0\n";
        let err =
            serde_yml::from_str::<Upstream>(yaml).expect_err("explicit port 0 must not parse");
        assert!(
            err.to_string().contains("1..=65535"),
            "parse error must explain the port rule: {err}"
        );
    }
}
