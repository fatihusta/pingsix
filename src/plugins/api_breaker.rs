//! API circuit breaker plugin, APISIX `api-breaker` compatible.
//!
//! Trips per-route when the upstream returns an unhealthy status
//! (`unhealthy.http_statuses`) a configured number of times (`unhealthy.failures`).
//! While tripped, requests are answered with `break_response_code` for an
//! exponentially backed-off window (2, 4, 8, ... seconds, capped at
//! `max_breaker_sec`) measured from the latest failure batch. Once the window
//! lapses, requests flow again; `healthy.successes` consecutive healthy
//! responses reset the breaker (APISIX `_M.access` / `_M.log` semantics).
//!
//! Connection-level failures (no upstream response) are not counted, matching
//! APISIX, which only observes `upstream_status`.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Instant,
};

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::{
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult, Rejection},
    plugins::{
        config::parse_and_validate_plugin_config,
        limiting::{rejection, Shard},
    },
    utils::request::render_apisix_request_template,
};

pub const PLUGIN_NAME: &str = "api-breaker";

/// APISIX `api-breaker` runs at priority 1005.
const PRIORITY: i32 = 1005;

/// Cap on the exponential factor so `2^failure_times` cannot overflow.
const MAX_EXPONENT: u32 = 30;

/// Fixed bitset over HTTP status codes (0..640), so per-response membership
/// tests are O(1) and allocation-free. Built once at plugin construction from
/// the configured `http_statuses` lists.
#[derive(Clone)]
struct StatusCodeSet([u64; 10]);

impl StatusCodeSet {
    fn from_statuses(statuses: &[u16]) -> Self {
        let mut bits = [0u64; 10];
        for &status in statuses {
            let idx = status as usize;
            if idx < 640 {
                bits[idx / 64] |= 1u64 << (idx % 64);
            }
        }
        Self(bits)
    }

    fn contains(&self, status: u16) -> bool {
        let idx = status as usize;
        idx < 640 && (self.0[idx / 64] & (1u64 << (idx % 64))) != 0
    }
}

/// Creates an `api-breaker` plugin instance from JSON configuration.
pub fn create_api_breaker_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginApiBreaker {
        unhealthy_set: StatusCodeSet::from_statuses(&config.unhealthy.http_statuses),
        healthy_set: StatusCodeSet::from_statuses(&config.healthy.http_statuses),
        config,
        state: Mutex::new(BreakerStates::default()),
    }))
}

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators WITHOUT constructing the plugin (no breaker state allocated).
pub fn validate_api_breaker_config(cfg: &JsonValue) -> ProxyResult<()> {
    PluginConfig::try_from(cfg.clone())?;
    Ok(())
}

/// Bounded breaker state keyed by stable route identity (or one fixed key for
/// a global-rule instance). Client-controlled Host/path values are excluded so
/// high-cardinality inputs cannot bypass the breaker or evict hot state.
const MAX_BREAKER_KEYS: usize = 1024;

/// Fixed-capacity LRU over the shared [`Shard`] recency machinery: a new key
/// at capacity evicts the least recently used state (no predicate — breaker
/// state has no notion of "idle"), while an existing key only refreshes its
/// recency. Eviction is O(log n), never a request-time map scan.
#[derive(Default)]
struct BreakerStates {
    shard: Shard<BreakerState>,
}

impl BreakerStates {
    fn entry(&mut self, key: String) -> &mut BreakerState {
        if !self.shard.contains_key(&key) && self.shard.len() >= MAX_BREAKER_KEYS {
            self.shard.evict_oldest();
        }
        self.shard.touch(&key);
        self.shard.entry(key).or_default()
    }
}

#[derive(Default)]
struct BreakerState {
    /// Cumulative unhealthy responses since the last reset.
    unhealthy_count: u32,
    /// Consecutive healthy responses while recovering from a trip.
    healthy_count: u32,
    /// When the current trip started (None when closed).
    lasttime: Option<Instant>,
}

/// Breaker window duration in seconds: `2^failure_times` capped at
/// `max_breaker_sec` (APISIX `breaker_time`).
fn breaker_secs(unhealthy_count: u32, failures: u32, max_breaker_sec: u64) -> u64 {
    let failure_times = (unhealthy_count / failures.max(1)).clamp(1, MAX_EXPONENT);
    let exp = 1u64.checked_shl(failure_times).unwrap_or(u64::MAX);
    exp.min(max_breaker_sec)
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
struct BreakHeader {
    #[validate(custom(function = "validate_header_key"))]
    key: String,
    #[validate(length(min = 1))]
    value: String,
}

fn validate_header_key(key: &str) -> Result<(), ValidationError> {
    if key.trim().is_empty() || key.parse::<http::HeaderName>().is_err() {
        return Err(ValidationError::new("invalid header key"));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
struct UnhealthyConf {
    #[serde(default = "UnhealthyConf::default_unhealthy_statuses")]
    http_statuses: Vec<u16>,
    #[serde(default = "UnhealthyConf::default_failures")]
    failures: u32,
}

impl Default for UnhealthyConf {
    fn default() -> Self {
        Self {
            http_statuses: Self::default_unhealthy_statuses(),
            failures: Self::default_failures(),
        }
    }
}

impl UnhealthyConf {
    fn default_unhealthy_statuses() -> Vec<u16> {
        vec![500]
    }
    fn default_failures() -> u32 {
        3
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
struct HealthyConf {
    #[serde(default = "HealthyConf::default_healthy_statuses")]
    http_statuses: Vec<u16>,
    #[serde(default = "HealthyConf::default_successes")]
    successes: u32,
}

impl Default for HealthyConf {
    fn default() -> Self {
        Self {
            http_statuses: Self::default_healthy_statuses(),
            successes: Self::default_successes(),
        }
    }
}

impl HealthyConf {
    fn default_healthy_statuses() -> Vec<u16> {
        vec![200]
    }
    fn default_successes() -> u32 {
        3
    }
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// HTTP status code returned while the circuit is open.
    #[validate(range(min = 200, max = 599))]
    break_response_code: u16,

    #[serde(default)]
    break_response_body: Option<String>,

    #[serde(default)]
    #[validate(nested)]
    break_response_headers: Vec<BreakHeader>,

    /// Upper bound (seconds) of the exponential breaker window.
    #[serde(default = "PluginConfig::default_max_breaker_sec")]
    #[validate(range(min = 3))]
    max_breaker_sec: u64,

    #[serde(default)]
    unhealthy: UnhealthyConf,

    #[serde(default)]
    healthy: HealthyConf,
}

impl PluginConfig {
    fn default_max_breaker_sec() -> u64 {
        300
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid api-breaker plugin config")?;
        // APISIX requires non-empty, unique status lists in their respective ranges.
        if config.unhealthy.http_statuses.is_empty()
            || config.healthy.http_statuses.is_empty()
            || config
                .unhealthy
                .http_statuses
                .iter()
                .collect::<HashSet<_>>()
                .len()
                != config.unhealthy.http_statuses.len()
            || config
                .healthy
                .http_statuses
                .iter()
                .collect::<HashSet<_>>()
                .len()
                != config.healthy.http_statuses.len()
        {
            return Err(ProxyError::validation_error(
                "api-breaker http_statuses must be non-empty and unique",
            ));
        }
        // Status-code sets must fall in the same ranges APISIX enforces.
        if config
            .unhealthy
            .http_statuses
            .iter()
            .any(|s| !(500..=599).contains(s))
        {
            return Err(ProxyError::validation_error(
                "api-breaker unhealthy.http_statuses must be in [500, 599]",
            ));
        }
        if config
            .healthy
            .http_statuses
            .iter()
            .any(|s| !(200..=499).contains(s))
        {
            return Err(ProxyError::validation_error(
                "api-breaker healthy.http_statuses must be in [200, 499]",
            ));
        }
        if config.unhealthy.failures < 1 {
            return Err(ProxyError::validation_error(
                "api-breaker unhealthy.failures must be >= 1",
            ));
        }
        if config.healthy.successes < 1 {
            return Err(ProxyError::validation_error(
                "api-breaker healthy.successes must be >= 1",
            ));
        }
        Ok(config)
    }
}

pub struct PluginApiBreaker {
    config: PluginConfig,
    unhealthy_set: StatusCodeSet,
    healthy_set: StatusCodeSet,
    state: Mutex<BreakerStates>,
}

impl PluginApiBreaker {
    /// Stable, bounded breaker state key.
    ///
    /// Uses route identity when a route is bound, falling back to the request
    /// path for global-rule instances. The raw `Host` header is deliberately
    /// **not** part of the key: under wildcard/multi-host routes it is
    /// attacker-controllable and would let a client rotate subdomains to keep
    /// failure counts from accumulating (bypassing the breaker) or to evict
    /// hot state under LRU pressure.
    fn state_key(session: &Session, ctx: &ProxyContext) -> String {
        let _ = session;
        match ctx.route.as_ref().map(|route| route.id()) {
            Some(route_id) if !route_id.is_empty() => route_id.into(),
            _ => "__global__".to_string(),
        }
    }

    fn is_open(&self, key: String, now: Instant) -> bool {
        let mut states = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = states.entry(key);
        match state.lasttime {
            Some(lasttime) => {
                let window = breaker_secs(
                    state.unhealthy_count,
                    self.config.unhealthy.failures,
                    self.config.max_breaker_sec,
                );
                lasttime + std::time::Duration::from_secs(window) >= now
            }
            None => false,
        }
    }

    /// Build the breaker-open rejection (T10: a returned value; the pipeline
    /// writes it). Header templates render against the request session.
    fn reject(&self, session: &mut Session) -> Rejection {
        let mut headers: Vec<(String, String)> = Vec::new();
        for h in &self.config.break_response_headers {
            let value = render_apisix_request_template(session, &h.value);
            headers.push((h.key.clone(), value));
        }
        rejection(
            StatusCode::from_u16(self.config.break_response_code)
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            self.config.break_response_body.as_deref(),
            &headers,
        )
    }
}

#[async_trait]
impl ProxyPlugin for PluginApiBreaker {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        if self.is_open(Self::state_key(session, ctx), Instant::now()) {
            log::debug!("api-breaker: circuit open, rejecting request");
            return Ok(FilterVerdict::Reject(self.reject(session)));
        }
        Ok(FilterVerdict::Continue)
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        let status = upstream_response.status.as_u16();
        // Pre-compiled bitsets: no per-response HashSet allocation.
        let is_unhealthy = self.unhealthy_set.contains(status);
        let is_healthy = self.healthy_set.contains(status);

        let mut states = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = states.entry(Self::state_key(session, ctx));

        if is_unhealthy {
            // Unhealthy process (APISIX `_M.log`).
            state.healthy_count = 0;
            state.unhealthy_count += 1;
            if state.unhealthy_count % self.config.unhealthy.failures.max(1) == 0 {
                state.lasttime = Some(Instant::now());
                log::debug!(
                    "api-breaker: tripped after {} unhealthy responses (status {status})",
                    state.unhealthy_count
                );
            }
        } else if is_healthy && state.lasttime.is_some() {
            // Health process: recovery only tracked while previously tripped.
            state.healthy_count += 1;
            if state.healthy_count >= self.config.healthy.successes.max(1) {
                log::debug!(
                    "api-breaker: recovered after {} healthy responses",
                    state.healthy_count
                );
                state.lasttime = None;
                state.unhealthy_count = 0;
                state.healthy_count = 0;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::request::render_apisix_template;

    #[test]
    fn breaker_state_capacity_evicts_oldest_without_scan() {
        let mut states = BreakerStates::default();
        for i in 0..MAX_BREAKER_KEYS {
            states.entry(i.to_string());
        }
        states.entry("new".to_string());
        assert_eq!(states.shard.len(), MAX_BREAKER_KEYS);
        assert!(!states.shard.contains_key("0"));
        assert!(states.shard.contains_key("new"));
    }

    #[test]
    fn breaker_window_grows_exponentially_and_caps() {
        // failures=3: unhealthy_count 3 -> factor 1 -> 2s; 6 -> factor 2 -> 4s.
        assert_eq!(breaker_secs(3, 3, 300), 2);
        assert_eq!(breaker_secs(6, 3, 300), 4);
        assert_eq!(breaker_secs(9, 3, 300), 8);
        // Cap at max_breaker_sec.
        assert_eq!(breaker_secs(9, 3, 5), 5);
        // Failure count below one batch still uses a 2s window.
        assert_eq!(breaker_secs(1, 3, 300), 2);
        // Exponent overflow is clamped.
        assert_eq!(breaker_secs(10_000, 1, 300), 300);
    }

    #[test]
    fn config_defaults_match_apisix() {
        let config = PluginConfig::try_from(serde_json::json!({
            "break_response_code": 502
        }))
        .unwrap();
        assert_eq!(config.max_breaker_sec, 300);
        assert_eq!(config.unhealthy.http_statuses, vec![500]);
        assert_eq!(config.unhealthy.failures, 3);
        assert_eq!(config.healthy.http_statuses, vec![200]);
        assert_eq!(config.healthy.successes, 3);
        assert!(config.break_response_body.is_none());
    }

    #[test]
    fn config_validates_status_ranges() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "break_response_code": 502,
            "unhealthy": { "http_statuses": [400] }
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "break_response_code": 502,
            "healthy": { "http_statuses": [500] }
        }))
        .is_err());
    }

    #[test]
    fn header_template_literals_and_variables_are_parsed() {
        // Pure-template rendering (no request) confirms the parser preserves
        // literals, resolves variables, and keeps separators next to missing
        // variables. Request-bound resolution is exercised via render_apisix_*
        // in utils::request tests.
        assert_eq!(render_apisix_template("30", |_| String::new()), "30");
        assert_eq!(
            render_apisix_template("$name:${missing}/${name}", |name| match name {
                "name" => "alice".to_string(),
                _ => String::new(),
            }),
            "alice:/alice"
        );
    }

    #[test]
    fn status_code_set_membership_is_precomputed() {
        let set = StatusCodeSet::from_statuses(&[200, 302, 503]);
        assert!(set.contains(200));
        assert!(set.contains(302));
        assert!(set.contains(503));
        assert!(!set.contains(201));
        assert!(!set.contains(500));
        // Out of bitset range is safely ignored.
        assert!(!StatusCodeSet::from_statuses(&[700]).contains(700));
    }

    #[test]
    fn config_requires_break_code() {
        assert!(PluginConfig::try_from(serde_json::json!({})).is_err());
    }

    #[test]
    fn config_rejects_empty_or_duplicate_statuses_and_headers() {
        for invalid in [serde_json::json!([]), serde_json::json!([500, 500])] {
            assert!(PluginConfig::try_from(serde_json::json!({
                "break_response_code": 502,
                "unhealthy": { "http_statuses": invalid }
            }))
            .is_err());
        }
        assert!(PluginConfig::try_from(serde_json::json!({
            "break_response_code": 502,
            "break_response_headers": [{ "key": "X-Test", "value": "" }]
        }))
        .is_err());
    }

    #[test]
    fn config_rejects_bad_header_key() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "break_response_code": 502,
            "break_response_body": "down",
            "break_response_headers": [{ "key": "bad key!", "value": "x" }]
        }))
        .is_err());
    }
}
