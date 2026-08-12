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
    collections::{HashMap, HashSet},
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
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::{request::render_apisix_request_template, response::ResponseBuilder},
};

pub const PLUGIN_NAME: &str = "api-breaker";

/// APISIX `api-breaker` runs at priority 1005.
const PRIORITY: i32 = 1005;

/// Cap on the exponential factor so `2^failure_times` cannot overflow.
const MAX_EXPONENT: u32 = 30;

/// Creates an `api-breaker` plugin instance from JSON configuration.
pub fn create_api_breaker_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginApiBreaker {
        config,
        state: Mutex::new(BreakerStates::default()),
    }))
}

/// Bounded, per route identity + host breaker state. The state key excludes
/// the raw request URI (query/parameters) so high-cardinality inputs cannot
/// bypass the breaker or evict hot state.
const MAX_BREAKER_KEYS: usize = 1024;

#[derive(Default)]
struct BreakerStates {
    entries: HashMap<String, BreakerState>,
}

impl BreakerStates {
    fn entry(&mut self, key: String) -> &mut BreakerState {
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_BREAKER_KEYS {
            // Evict only the least-recently-used key; never clear all hot state.
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, state)| state.last_touch)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        let state = self.entries.entry(key).or_default();
        state.last_touch = Instant::now();
        state
    }
}

struct BreakerState {
    /// Cumulative unhealthy responses since the last reset.
    unhealthy_count: u32,
    /// Consecutive healthy responses while recovering from a trip.
    healthy_count: u32,
    /// When the current trip started (None when closed).
    lasttime: Option<Instant>,
    last_touch: Instant,
}

impl Default for BreakerState {
    fn default() -> Self {
        Self {
            unhealthy_count: 0,
            healthy_count: 0,
            lasttime: None,
            last_touch: Instant::now(),
        }
    }
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
        let config: PluginConfig = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid api-breaker plugin config", e))?;
        config.validate()?;
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
    state: Mutex<BreakerStates>,
}

impl PluginApiBreaker {
    /// Is the circuit currently open (within the breaker window)?
    fn state_key(session: &Session, ctx: &ProxyContext) -> String {
        let host = session
            .req_header()
            .headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        // Scope by route identity so a service-level plugin instance shared
        // across routes does not leak failures between them, and so high-cardinality
        // query strings or path parameters cannot bypass the breaker. Falls back
        // to the request path only when no route is bound (global rule).
        match ctx.route.as_ref().map(|route| route.id()) {
            Some(route_id) if !route_id.is_empty() => format!("{route_id}\n{host}"),
            _ => format!("{host}\n{}", session.req_header().uri.path()),
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

    async fn reject(&self, session: &mut Session) -> Result<bool> {
        let mut headers: Vec<(&str, String)> = Vec::new();
        for h in &self.config.break_response_headers {
            let value = render_apisix_request_template(session, &h.value);
            headers.push((h.key.as_str(), value));
        }
        let headers_ref: Vec<(&str, &str)> =
            headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        ResponseBuilder::send_proxy_error(
            session,
            StatusCode::from_u16(self.config.break_response_code)
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            self.config.break_response_body.as_deref(),
            if headers_ref.is_empty() {
                None
            } else {
                Some(&headers_ref)
            },
        )
        .await?;
        Ok(true)
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

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        if self.is_open(Self::state_key(session, ctx), Instant::now()) {
            log::debug!("api-breaker: circuit open, rejecting request");
            return self.reject(session).await;
        }
        Ok(false)
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        let status = upstream_response.status.as_u16();
        let mut states = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = states.entry(Self::state_key(session, ctx));

        let unhealthy: HashSet<u16> = self
            .config
            .unhealthy
            .http_statuses
            .iter()
            .copied()
            .collect();
        let healthy: HashSet<u16> = self.config.healthy.http_statuses.iter().copied().collect();

        if unhealthy.contains(&status) {
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
        } else if healthy.contains(&status) && state.lasttime.is_some() {
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
        assert_eq!(
            render_apisix_template("30", |_| String::new()),
            "30"
        );
        assert_eq!(
            render_apisix_template("$name:${missing}/${name}", |name| match name {
                "name" => "alice".to_string(),
                _ => String::new(),
            }),
            "alice:/alice"
        );
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
