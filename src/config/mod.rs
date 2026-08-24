pub mod etcd;
mod node;

use std::{fs, net::SocketAddr};

use pingora::server::configuration::{Opt, ServerConf};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::proxy::control_plane::ResourceConfigSet;

pub use node::{Node, Nodes};

/// Re-export so external callers (integration tests, other crates) can name the
/// argument types of [`transform_resource_secrets`].
pub use crate::utils::encryption::{KeyringService, SecretOp};

mod defaults;
mod resources;
mod schema;

pub use defaults::*;
pub use resources::*;

pub(crate) use schema::warn_unrecognized_fields;

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
///
/// Static resources are carried in control-plane vocabulary
/// ([`ResourceConfigSet`], id-keyed) from the start: [`Config::from_yaml`]
/// converts the on-disk sequence sections directly into it, so there is no
/// intermediate Vec-of-resources layer and duplicate ids fail at map
/// construction. User-facing YAML schema is unchanged.
#[derive(Default, Debug, Serialize, Validate)]
pub struct Config {
    /// Pingora framework configuration (workers, logging, etc.)
    pub pingora: ServerConf,

    /// Pingsix-specific configuration (listeners, etcd, plugins, etc.)
    #[validate(nested)]
    pub pingsix: Pingsix,

    /// Static resource definitions, keyed by id — used only when etcd is not
    /// configured. Parsed from the YAML `routes`/`upstreams`/`services`/
    /// `global_rules`/`ssls` sequence sections.
    pub resources: ResourceConfigSet,
}

/// On-disk YAML shape of [`Config`]: deserialization-only adapter so the
/// resource sections keep their sequence form for users (zero schema change,
/// including `deny_unknown_fields` behavior) while the loader converts them
/// into the id-keyed [`ResourceConfigSet`] in one pass.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    pingora: ServerConf,
    pingsix: Pingsix,
    #[serde(default)]
    routes: Vec<Route>,
    #[serde(default)]
    upstreams: Vec<Upstream>,
    #[serde(default)]
    services: Vec<Service>,
    #[serde(default)]
    global_rules: Vec<GlobalRule>,
    #[serde(default)]
    ssls: Vec<SSL>,
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
        let file: ConfigFile = serde_yml::from_str(conf_str)
            .or_err_with(ReadError, || "Unable to parse yaml configuration")?;

        // Static resource sections: schema-validate each entry, require
        // non-empty ids, and reject duplicate ids at map construction. The
        // error wording stays machine-testable (e.g. names the duplicated id).
        let resources = ResourceConfigSet::from_yaml_sections(
            file.routes,
            file.upstreams,
            file.services,
            file.global_rules,
            file.ssls,
        )
        .map_err(|e| Error::explain(FileReadError, e.to_string()))?;

        let conf = Config {
            pingora: file.pingora,
            pingsix: file.pingsix,
            resources,
        };

        log::debug!(
            "Loaded configuration with {} routes, {} upstreams, {} services, {} global rules, and {} SSL entries",
            conf.resources.routes.len(),
            conf.resources.upstreams.len(),
            conf.resources.services.len(),
            conf.resources.global_rules.len(),
            conf.resources.ssls.len(),
        );

        // Validate server-settings structure and constraints (pingora, pingsix).
        conf.validate()
            .or_err_with(FileReadError, || "Conf file validation failed")?;

        // Best-effort unrecognized-field warnings for static YAML resources.
        // Unknown fields are still accepted (ingress metadata compatibility);
        // this only logs likely typos of behavior fields.
        if let Ok(graph) = serde_yml::from_str::<JsonValue>(conf_str) {
            schema::warn_static_resources(&graph);
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

#[cfg(test)]
mod tests;
