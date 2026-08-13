use serde::{Deserialize, Serialize};
use validator::Validate;

use super::resources::Timeout;
use super::Pingsix;

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
/// Each [`crate::service::GatewayState`] holds its own copy so two gateway
/// runtimes in one process can use different defaults.
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
