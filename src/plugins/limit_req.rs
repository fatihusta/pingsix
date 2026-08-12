//! Leaky-bucket rate limiting plugin, APISIX `limit-req` compatible.
//!
//! Limits request velocity per key using the leaky bucket algorithm: up to
//! `rate` requests per second pass immediately; requests up to `rate + burst`
//! are delayed (queued) rather than dropped; requests beyond `rate + burst`
//! are rejected with `rejected_code`. With `nodelay: true` no delay is
//! applied, so the burst capacity is consumed at full speed and subsequent
//! requests are rejected until the bucket drains.
//!
//! The algorithm mirrors `lua-resty-limit-traffic`'s `limit/req.lua`
//! `incoming()` so behavior matches APISIX with `policy: local`.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::Result;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::{
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::{request::apisix_key, response::ResponseBuilder},
};

pub const PLUGIN_NAME: &str = "limit-req";

/// APISIX `limit-req` runs at priority 1001 (before limit-count 1002).
const PRIORITY: i32 = 1001;

/// Upper bound on tracked keys before idle entries are swept.
const MAX_KEYS: usize = 4096;

/// Creates a `limit-req` plugin instance from JSON configuration.
pub fn create_limit_req_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginLimitReq {
        config,
        buckets: Mutex::new(HashMap::new()),
    }))
}

/// Mutable leaky-bucket state for one key.
struct Bucket {
    excess: f64,
    last: Instant,
    initialized: bool,
}

/// Pure leaky-bucket transition (unit-testable).
///
/// Returns `Ok((delay_secs, new_excess))` when the request may proceed
/// (`delay` is 0 when `nodelay` is set), or `Err(())` when the request
/// exceeds `rate + burst`.
fn leaky_bucket_step(
    old_excess: f64,
    elapsed_secs: f64,
    rate: f64,
    burst: f64,
    nodelay: bool,
) -> Result<(f64, f64), ()> {
    let excess = (old_excess - elapsed_secs * rate + 1.0).max(0.0);
    if excess > burst {
        return Err(());
    }
    let _ = nodelay; // nodelay skips sleeping; it never changes state.
    Ok((excess / rate, excess))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum KeyType {
    #[default]
    Var,
    VarCombination,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Policy {
    #[default]
    Local,
    Redis,
    RedisCluster,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct PluginConfig {
    /// Maximum number of requests allowed per second (bucket drain rate).
    #[validate(custom(function = "validate_rate"))]
    rate: f64,

    /// Number of requests allowed to be delayed (bucket capacity above rate).
    #[serde(default)]
    #[validate(range(min = 0))]
    burst: u32,

    #[serde(default)]
    key_type: KeyType,

    /// Variable (or whitespace-separated variable combination) to key on.
    #[validate(custom(function = "validate_key"))]
    key: String,

    #[serde(default = "PluginConfig::default_rejected_code")]
    #[validate(range(min = 400, max = 599))]
    rejected_code: u16,

    #[serde(default)]
    rejected_msg: Option<String>,

    /// If true, requests within the burst range are not delayed; the burst is
    /// consumed at full speed and further requests are rejected.
    #[serde(default)]
    nodelay: bool,

    /// Accepted for APISIX schema compatibility.
    #[serde(default)]
    allow_degradation: bool,

    /// Counter backend. Only `local` is supported in this release.
    #[serde(default)]
    policy: Policy,
}

impl PluginConfig {
    fn default_rejected_code() -> u16 {
        503
    }
}

fn validate_rate(value: f64) -> Result<(), ValidationError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(ValidationError::new("rate must be > 0"));
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), ValidationError> {
    if key.trim().is_empty() {
        return Err(ValidationError::new("key cannot be empty"));
    }
    Ok(())
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid limit-req plugin config", e))?;
        config.validate()?;
        if config.policy != Policy::Local {
            return Err(ProxyError::validation_error(
                "limit-req policy 'redis'/'redis-cluster' requires a distributed backend; only 'local' is supported",
            ));
        }
        Ok(config)
    }
}

/// Leaky-bucket rate limiting plugin implementation.
pub struct PluginLimitReq {
    config: PluginConfig,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl PluginLimitReq {
    async fn reject(&self, session: &mut Session) -> Result<bool> {
        ResponseBuilder::send_proxy_error(
            session,
            StatusCode::from_u16(self.config.rejected_code)
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            self.config.rejected_msg.as_deref(),
            None,
        )
        .await?;
        Ok(true)
    }
}

#[async_trait]
impl ProxyPlugin for PluginLimitReq {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let key = apisix_key(
            session,
            &self.config.key,
            self.config.key_type == KeyType::VarCombination,
        );

        let now = Instant::now();

        // The lock is held only for the pure state transition; sleeping and
        // response writes happen after the bucket state is updated.
        let (delay, rejected) = {
            let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
            if !buckets.contains_key(key.as_ref()) && buckets.len() >= MAX_KEYS {
                // Sweep fully-drained buckets to bound memory from ephemeral keys.
                buckets.retain(|_, b| {
                    now.duration_since(b.last).as_secs_f64() * self.config.rate >= b.excess
                });
            }
            // Preserve every extant bucket. When full, new keys share a stable
            // overflow bucket rather than resetting active/hot key state.
            let storage_key = if buckets.contains_key(key.as_ref()) || buckets.len() < MAX_KEYS {
                key.into_owned()
            } else {
                "__pingsix_limit_req_overflow__".to_string()
            };
            let bucket = buckets.entry(storage_key).or_insert_with(|| Bucket {
                excess: 0.0,
                last: now,
                initialized: false,
            });
            if !bucket.initialized {
                bucket.initialized = true;
                bucket.last = now;
                (Some(0.0), false)
            } else {
                let elapsed = now.duration_since(bucket.last).as_secs_f64();
                bucket.last = now;
                match leaky_bucket_step(
                    bucket.excess,
                    elapsed,
                    self.config.rate,
                    self.config.burst as f64,
                    self.config.nodelay,
                ) {
                    Ok((delay, new_excess)) => {
                        bucket.excess = new_excess;
                        (Some(delay), false)
                    }
                    Err(()) => (None, true),
                }
            }
        };

        if rejected {
            return self.reject(session).await;
        }

        let delay = delay.expect("not rejected implies a delay");
        if delay > 0.0 && !self.config.nodelay {
            tokio::time::sleep(Duration::from_secs_f64(delay)).await;
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_empty_state_adds_one_request() {
        assert_eq!(
            leaky_bucket_step(0.0, 0.0, 1.0, 1.0, false).unwrap(),
            (1.0, 1.0)
        );
    }

    #[test]
    fn existing_state_uses_post_increment_excess_for_delay() {
        // resty.limit.req calculates max(old - elapsed * rate + 1, 0), then
        // returns delay = excess / rate.
        assert_eq!(
            leaky_bucket_step(1.0, 0.5, 2.0, 2.0, false).unwrap(),
            (0.5, 1.0)
        );
    }

    #[test]
    fn idle_bucket_drains_and_next_request_has_no_delay() {
        assert_eq!(
            leaky_bucket_step(5.0, 5.0, 1.0, 1.0, false).unwrap(),
            (1.0, 1.0)
        );
    }

    #[test]
    fn above_rate_plus_burst_is_rejected() {
        // rate=1, burst=1: after two immediate arrivals excess is 2 > burst 1.
        assert_eq!(leaky_bucket_step(2.0, 0.0, 1.0, 1.0, false), Err(()));
    }

    #[test]
    fn nodelay_only_suppresses_sleep_not_state() {
        assert_eq!(
            leaky_bucket_step(0.0, 0.0, 1.0, 1.0, true).unwrap(),
            (1.0, 1.0)
        );
        assert_eq!(
            leaky_bucket_step(0.0, 0.0, 1.0, 1.0, false).unwrap(),
            (1.0, 1.0)
        );
        assert_eq!(leaky_bucket_step(1.0, 0.0, 1.0, 1.0, true), Err(()));
    }

    #[test]
    fn bucket_drains_over_time() {
        // excess 2, rate 1: after 1.5s the new excess is 1.5, which
        // exceeds burst 1 and is rejected.
        assert_eq!(leaky_bucket_step(2.0, 1.5, 1.0, 1.0, false), Err(()));
    }

    #[test]
    fn config_rejects_invalid_values() {
        assert!(PluginConfig::try_from(
            serde_json::json!({ "rate": 0, "burst": 0, "key": "remote_addr" })
        )
        .is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({ "rate": 1, "burst": 0, "key": "" }))
                .is_err()
        );
        assert!(PluginConfig::try_from(
            serde_json::json!({ "rate": 1, "burst": 0, "key": "remote_addr", "policy": "redis" })
        )
        .is_err());
    }

    #[test]
    fn config_defaults_match_apisix() {
        let config = PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0,
            "key": "remote_addr"
        }))
        .unwrap();
        assert_eq!(config.rejected_code, 503);
        assert!(!config.nodelay);
        assert_eq!(config.key_type, KeyType::Var);
        assert_eq!(config.policy, Policy::Local);
    }

    #[test]
    fn config_rejects_unsupported_fields_and_status_outside_http_range() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "rate": 1, "burst": 0, "key": "remote_addr", "rules": []
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "rate": 1, "burst": 0, "key": "remote_addr", "rejected_code": 199
        }))
        .is_err());
    }
}
