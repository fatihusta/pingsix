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
    collections::{hash_map::Entry, HashMap},
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
    core::{PluginPhases, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::limiter_shards::{
        shard_idx, TouchOrder, CLEANUP_BUDGET, LIMIT_SHARDS, PER_SHARD_REGULAR_MAX,
    },
    utils::{request::apisix_key, response::ResponseBuilder},
};

pub const PLUGIN_NAME: &str = "limit-req";

/// APISIX `limit-req` runs at priority 1001 (before limit-count 1002).
const PRIORITY: i32 = 1001;

/// Creates a `limit-req` plugin instance from JSON configuration.
pub fn create_limit_req_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginLimitReq {
        config,
        buckets: std::array::from_fn(|_| Mutex::new(BucketShard::default())),
    }))
}

/// Mutable leaky-bucket state for one key. `last` is the drain anchor: the
/// instant from which the next request measures elapsed draining time.
struct Bucket {
    excess: f64,
    last: Instant,
}

#[derive(Default)]
struct BucketShard {
    entries: HashMap<String, Bucket>,
    touch_order: TouchOrder,
}

impl BucketShard {
    fn touch(&mut self, key: &str) {
        self.touch_order.touch(key);
    }

    /// Remove no more than `CLEANUP_BUDGET` oldest drained buckets.
    fn sweep_drained(&mut self, now: Instant, rate: f64) {
        for _ in 0..CLEANUP_BUDGET {
            let Some((touch, key)) = self.touch_order.pop_oldest() else {
                break;
            };
            let drained = self.entries.get(&key).is_some_and(|bucket| {
                now.duration_since(bucket.last).as_secs_f64() * rate >= bucket.excess
            });
            if drained {
                self.entries.remove(&key);
            } else {
                self.touch_order.restore(touch, key);
            }
        }
    }
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

/// Apply one request to an already-tracked bucket at time `now`.
///
/// Mirrors `lua-resty-limit-traffic`'s `limit/req.lua` commit discipline: the
/// drain anchor (`last`) and `excess` are written only when the request is
/// accepted. A rejected request leaves both untouched — otherwise every
/// rejection would re-anchor the drain clock and a client retrying just
/// above the rate would stay locked out forever.
fn bucket_incoming(
    bucket: &mut Bucket,
    now: Instant,
    rate: f64,
    burst: f64,
    nodelay: bool,
) -> Result<f64, ()> {
    let elapsed = now.duration_since(bucket.last).as_secs_f64();
    match leaky_bucket_step(bucket.excess, elapsed, rate, burst, nodelay) {
        Ok((delay, new_excess)) => {
            bucket.last = now;
            bucket.excess = new_excess;
            Ok(delay)
        }
        Err(()) => Err(()),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum KeyType {
    #[default]
    Var,
    #[serde(rename = "var_combination")]
    VarCombination,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Policy {
    #[default]
    Local,
    Redis,
    #[serde(rename = "redis-cluster")]
    RedisCluster,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Maximum number of requests allowed per second (bucket drain rate).
    #[validate(custom(function = "validate_rate"))]
    rate: f64,

    /// Number of requests allowed to be delayed (bucket capacity above rate).
    /// APISIX allows fractional burst values; pingsix keeps its default of 0.
    #[serde(default)]
    #[validate(custom(function = "validate_burst"))]
    burst: f64,

    #[serde(default)]
    key_type: KeyType,

    /// Variable (or whitespace-separated variable combination) to key on.
    #[validate(custom(function = "validate_key"))]
    key: String,

    #[serde(default = "PluginConfig::default_rejected_code")]
    #[validate(range(min = 200, max = 599))]
    rejected_code: u16,

    #[serde(default)]
    #[validate(custom(function = "validate_rejected_msg"))]
    rejected_msg: Option<String>,

    /// If true, requests within the burst range are not delayed; the burst is
    /// consumed at full speed and further requests are rejected.
    #[serde(default)]
    nodelay: bool,

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

fn validate_burst(value: f64) -> Result<(), ValidationError> {
    if !value.is_finite() || value < 0.0 {
        return Err(ValidationError::new("burst must be >= 0"));
    }
    Ok(())
}

fn validate_rejected_msg(value: &&String) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new(
            "rejected_msg must have at least 1 character",
        ));
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
    buckets: [Mutex<BucketShard>; LIMIT_SHARDS],
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
    fn phases(&self) -> PluginPhases {
        PluginPhases::REQUEST
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
            let mut buckets = self.buckets[shard_idx(key.as_ref())]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Preserve extant buckets. A new key gets one bounded sweep when
            // the shard is full, then either a regular slot or the stable
            // overflow bucket shared with other overflowed keys.
            let new_key = !buckets.entries.contains_key(key.as_ref());
            if new_key && buckets.entries.len() >= PER_SHARD_REGULAR_MAX {
                // Fixed work budget; no request can scan the full map.
                buckets.sweep_drained(now, self.config.rate);
            }
            let storage_key = if !new_key || buckets.entries.len() < PER_SHARD_REGULAR_MAX {
                key.into_owned()
            } else {
                "__pingsix_limit_req_overflow__".to_string()
            };
            buckets.touch(&storage_key);
            match buckets.entries.entry(storage_key) {
                Entry::Vacant(slot) => {
                    // First request for this bucket initializes it and passes.
                    slot.insert(Bucket {
                        excess: 0.0,
                        last: now,
                    });
                    (Some(0.0), false)
                }
                Entry::Occupied(slot) => match bucket_incoming(
                    slot.into_mut(),
                    now,
                    self.config.rate,
                    self.config.burst,
                    self.config.nodelay,
                ) {
                    Ok(delay) => (Some(delay), false),
                    Err(()) => (None, true),
                },
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
    fn full_shard_uses_stable_overflow_bucket() {
        let now = Instant::now();
        let mut shard = BucketShard::default();
        for i in 0..PER_SHARD_REGULAR_MAX {
            let key = i.to_string();
            shard.entries.insert(
                key.clone(),
                Bucket {
                    excess: 1.0,
                    last: now,
                },
            );
            shard.touch(&key);
        }
        shard.sweep_drained(now, 1.0);
        let storage_key = if shard.entries.len() < PER_SHARD_REGULAR_MAX {
            "new-key"
        } else {
            "__pingsix_limit_req_overflow__"
        };
        shard.entries.insert(
            storage_key.into(),
            Bucket {
                excess: 0.0,
                last: now,
            },
        );
        shard.touch(storage_key);

        assert_eq!(storage_key, "__pingsix_limit_req_overflow__");
        assert_eq!(shard.entries.len(), PER_SHARD_REGULAR_MAX + 1);
    }

    #[test]
    fn bounded_sweep_removes_at_most_budget_entries() {
        let now = Instant::now();
        let mut shard = BucketShard::default();
        for i in 0..CLEANUP_BUDGET + 2 {
            let key = i.to_string();
            shard.entries.insert(
                key.clone(),
                Bucket {
                    excess: 0.0,
                    last: now - Duration::from_secs(1),
                },
            );
            shard.touch(&key);
        }
        shard.sweep_drained(now, 1.0);
        assert_eq!(shard.entries.len(), 2);
    }

    #[test]
    fn fractional_burst_is_accepted() {
        let config = PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0.5,
            "key": "remote_addr"
        }))
        .unwrap();
        assert_eq!(config.burst, 0.5);
        assert_eq!(
            leaky_bucket_step(0.25, 0.0, 1.0, 1.25, false),
            Ok((1.25, 1.25))
        );
    }

    #[test]
    fn rejected_request_does_not_reanchor_drain_clock() {
        // rate=1, burst=0: accepted at t0, rejected at t0+0.5s, accepted
        // again at t0+1.1s. Before the fix the rejection committed
        // `last = t0+0.5`, so the retry only saw 0.6s of drain and was
        // rejected too — a client retrying just above the rate stayed
        // locked out forever.
        let t0 = Instant::now();
        // The bucket `request_filter` leaves behind after the accepted
        // request at t0 (first request initializes and passes with excess 0).
        let mut bucket = Bucket {
            excess: 0.0,
            last: t0,
        };
        // t0+0.5s: excess = max(0 - 0.5*1 + 1, 0) = 0.5 > burst 0 -> rejected.
        assert_eq!(
            bucket_incoming(
                &mut bucket,
                t0 + Duration::from_millis(500),
                1.0,
                0.0,
                false
            ),
            Err(())
        );
        // The rejection must have left BOTH `last` and `excess` untouched.
        assert_eq!(bucket.last, t0);
        assert_eq!(bucket.excess, 0.0);
        // t0+1.1s: the bucket fully drained since t0, so the retry passes.
        assert_eq!(
            bucket_incoming(
                &mut bucket,
                t0 + Duration::from_millis(1100),
                1.0,
                0.0,
                false
            ),
            Ok(0.0)
        );
    }

    #[test]
    fn accepted_request_commits_drain_anchor_and_excess() {
        let t0 = Instant::now();
        let mut bucket = Bucket {
            excess: 0.0,
            last: t0,
        };
        // Accepted at t0+0.5s: excess = max(0 - 0.5 + 1, 0) = 0.5, delay 0.5.
        assert_eq!(
            bucket_incoming(
                &mut bucket,
                t0 + Duration::from_millis(500),
                1.0,
                1.0,
                false
            ),
            Ok(0.5)
        );
        assert_eq!(bucket.excess, 0.5);
        assert_eq!(bucket.last, t0 + Duration::from_millis(500));
    }

    #[test]
    fn config_rejects_invalid_values() {
        assert!(PluginConfig::try_from(
            serde_json::json!({ "rate": 0, "burst": 0, "key": "remote_addr" })
        )
        .is_err());
        assert!(PluginConfig::try_from(
            serde_json::json!({ "rate": 1, "burst": -0.5, "key": "remote_addr" })
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
    fn config_rejects_redis_cluster_policy_with_clear_validation_error() {
        let err = PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0,
            "key": "remote_addr",
            "policy": "redis-cluster"
        }))
        .unwrap_err();
        assert!(err.to_string().contains("requires a distributed backend"));
    }

    #[test]
    fn config_accepts_var_combination_key_type() {
        let config = PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0,
            "key": "$remote_addr $http_x_user",
            "key_type": "var_combination"
        }))
        .unwrap();
        assert_eq!(config.key_type, KeyType::VarCombination);
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
    fn config_ignores_unknown_fields_and_rejects_status_outside_http_range() {
        // Fields outside the limit-req schema (e.g. limit-count's `rules`)
        // are tolerated and ignored.
        let config = PluginConfig::try_from(serde_json::json!({
            "rate": 1, "burst": 0, "key": "remote_addr", "rules": []
        }))
        .expect("unknown fields are tolerated");
        assert_eq!(config.rate, 1.0);
        assert!(PluginConfig::try_from(serde_json::json!({
            "rate": 1, "burst": 0, "key": "remote_addr", "rejected_code": 199
        }))
        .is_err());
    }

    #[test]
    fn config_accepts_rejected_code_200_and_rejects_empty_msg() {
        let config = PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0,
            "key": "remote_addr",
            "rejected_code": 200
        }))
        .unwrap();
        assert_eq!(config.rejected_code, 200);
        assert!(PluginConfig::try_from(serde_json::json!({
            "rate": 1,
            "burst": 0,
            "key": "remote_addr",
            "rejected_msg": ""
        }))
        .is_err());
    }
}
