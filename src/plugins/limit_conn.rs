//! Concurrency limiting plugin, APISIX `limit-conn` compatible.
//!
//! Limits the number of concurrent in-flight requests per key (default:
//! `remote_addr`). Requests up to `conn` pass immediately; requests between
//! `conn` and `conn + burst` are delayed (per `default_conn_delay`) before
//! being allowed; requests above `conn + burst` are rejected with
//! `rejected_code`.
//!
//! The counter is exact and process-local (APISIX `policy: local`). Redis
//! policies are rejected at configuration time because this release ships no
//! distributed counter backend.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
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

pub const PLUGIN_NAME: &str = "limit-conn";

/// APISIX `limit-conn` runs at priority 1003 (after limit-count 1002).
const PRIORITY: i32 = 1003;

/// Context key holding the concurrency guard while the request is in flight.
const CTX_KEY_CONN_GUARD: &str = "pingsix_limit_conn_guard";

/// Upper bound on tracked keys before idle entries are swept.
const MAX_KEYS: usize = 4096;

/// Creates a `limit-conn` plugin instance from JSON configuration.
pub fn create_limit_conn_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginLimitConn {
        config,
        counters: Mutex::new(HashMap::new()),
    }))
}

/// Outcome of the concurrency decision for one request.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Decision {
    Pass,
    Delay(f64),
    Reject,
}

/// Pure decision function (unit-testable): maps an observed in-flight count
/// to the action APISIX `limit-conn` would take.
fn decide(count: usize, conn: u32, burst: u32, unit_delay: f64) -> Decision {
    let conn = conn as usize;
    if count > conn + burst as usize {
        Decision::Reject
    } else if count > conn {
        Decision::Delay(unit_delay * ((count - 1) / conn) as f64)
    } else {
        Decision::Pass
    }
}

/// RAII guard: decrements the per-key in-flight count when dropped.
///
/// Stored in [`ProxyContext`] vars so the slot is released when the request
/// finishes (success or failure), mirroring Guide L38's `Guard` pattern.
struct ConnState {
    count: AtomicUsize,
    unit_delay: Mutex<f64>,
}

/// Request-scoped state released by the reliable `logging` lifecycle hook.
/// If the request future is cancelled before `logging` runs, `Drop` still
/// decrements the in-flight counter so the slot is never leaked.
struct ConnGuard {
    state: Arc<ConnState>,
    started: Instant,
    released: bool,
}

impl ConnGuard {
    fn new(state: Arc<ConnState>) -> Self {
        Self {
            state,
            started: Instant::now(),
            released: false,
        }
    }

    fn release(&mut self, update_delay: bool) {
        if self.released {
            return;
        }
        self.released = true;
        self.state.count.fetch_sub(1, Ordering::Relaxed);
        if update_delay {
            let mut unit_delay = self
                .state
                .unit_delay
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *unit_delay = (self.started.elapsed().as_secs_f64() + *unit_delay) / 2.0;
        }
    }

    fn leave(mut self, update_delay: bool) {
        self.release(update_delay);
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        // Cancellation path: release the slot without a latency update.
        self.release(false);
    }
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
    /// Maximum number of concurrent requests allowed to pass immediately.
    #[validate(range(min = 1))]
    conn: u32,

    /// Number of excessive concurrent requests allowed to be delayed.
    #[serde(default)]
    #[validate(range(min = 0))]
    burst: u32,

    /// Delay in seconds applied to requests within the burst range.
    #[validate(custom(function = "validate_conn_delay"))]
    default_conn_delay: f64,

    /// If true, retain the configured delay on request completion; otherwise
    /// update the per-key unit delay from observed request latency.
    #[serde(default)]
    only_use_default_delay: bool,

    #[serde(default)]
    key_type: KeyType,

    /// Variable or variable-combination template to key on.
    key: String,

    #[serde(default = "PluginConfig::default_rejected_code")]
    #[validate(range(min = 400, max = 599))]
    rejected_code: u16,

    #[serde(default)]
    rejected_msg: Option<String>,

    /// Accepted for APISIX schema compatibility; this local implementation has
    /// no external dependencies that could degrade.
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

fn validate_conn_delay(value: f64) -> Result<(), ValidationError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(ValidationError::new("default_conn_delay must be > 0"));
    }
    Ok(())
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid limit-conn plugin config", e))?;
        config.validate()?;
        if config.policy != Policy::Local {
            return Err(ProxyError::validation_error(
                "limit-conn policy 'redis'/'redis-cluster' requires a distributed backend; only 'local' is supported",
            ));
        }
        Ok(config)
    }
}

/// Concurrency limiting plugin implementation.
pub struct PluginLimitConn {
    config: PluginConfig,
    /// Exact per-key in-flight counters. Entries are swept when the map grows
    /// past [`MAX_KEYS`] to avoid unbounded memory from ephemeral keys.
    counters: Mutex<HashMap<String, Arc<ConnState>>>,
}

impl PluginLimitConn {
    fn get_or_insert_counter(&self, key: &str) -> Arc<ConnState> {
        let mut counters = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = counters.get(key) {
            return state.clone();
        }
        if counters.len() >= MAX_KEYS {
            counters.retain(|_, state| state.count.load(Ordering::Relaxed) > 0);
        }
        // Never evict active entries. New keys use one stable overflow state
        // once all entries are active, avoiding split concurrency guards.
        let storage_key = if counters.len() < MAX_KEYS {
            key
        } else {
            "__pingsix_limit_conn_overflow__"
        };
        counters
            .entry(storage_key.to_string())
            .or_insert_with(|| {
                Arc::new(ConnState {
                    count: AtomicUsize::new(0),
                    unit_delay: Mutex::new(self.config.default_conn_delay),
                })
            })
            .clone()
    }

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
impl ProxyPlugin for PluginLimitConn {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        let key = apisix_key(
            session,
            &self.config.key,
            self.config.key_type == KeyType::VarCombination,
        );
        let state = self.get_or_insert_counter(key.as_ref());
        let count = state.count.fetch_add(1, Ordering::Relaxed) + 1;
        let unit_delay = *state.unit_delay.lock().unwrap_or_else(|e| e.into_inner());

        match decide(count, self.config.conn, self.config.burst, unit_delay) {
            Decision::Pass => {
                ctx.set(CTX_KEY_CONN_GUARD, ConnGuard::new(state));
                Ok(false)
            }
            Decision::Delay(secs) => {
                // Hold the guard locally so a cancellation during sleep still
                // decrements via Drop; transfer ownership only after success.
                let guard = ConnGuard::new(state);
                tokio::time::sleep(Duration::from_secs_f64(secs)).await;
                ctx.set(CTX_KEY_CONN_GUARD, guard);
                Ok(false)
            }
            Decision::Reject => {
                // Release the slot immediately; no guard is stored.
                state.count.fetch_sub(1, Ordering::Relaxed);
                log::debug!(
                    "limit-conn: rejected request for key {:?} (in-flight {count}, conn {} burst {})",
                    key,
                    self.config.conn,
                    self.config.burst
                );
                self.reject(session).await
            }
        }
    }

    async fn logging(
        &self,
        _session: &mut Session,
        _e: Option<&pingora_error::Error>,
        ctx: &mut ProxyContext,
    ) {
        if let Some(vars) = ctx.vars.as_mut() {
            if let Some(guard) = vars
                .remove(CTX_KEY_CONN_GUARD)
                .and_then(|guard| guard.downcast::<ConnGuard>().ok())
            {
                guard.leave(!self.config.only_use_default_delay);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_within_conn_pass_immediately() {
        assert_eq!(decide(1, 2, 1, 0.1), Decision::Pass);
        assert_eq!(decide(2, 2, 1, 0.1), Decision::Pass);
    }

    #[test]
    fn burst_range_uses_resty_limit_conn_formula() {
        assert_eq!(decide(3, 2, 3, 0.5), Decision::Delay(0.5));
        assert_eq!(decide(4, 2, 3, 0.5), Decision::Delay(0.5));
        assert_eq!(decide(5, 2, 3, 0.5), Decision::Delay(1.0));
    }

    #[test]
    fn only_use_default_delay_does_not_change_incoming_formula() {
        assert_eq!(decide(5, 2, 3, 0.7), Decision::Delay(1.4));
    }

    #[test]
    fn above_conn_plus_burst_is_rejected() {
        assert_eq!(decide(4, 2, 1, 0.1), Decision::Reject);
        assert_eq!(decide(6, 2, 3, 0.1), Decision::Reject);
    }

    #[test]
    fn guard_decrements_counter_on_drop() {
        let state = Arc::new(ConnState {
            count: AtomicUsize::new(1),
            unit_delay: Mutex::new(0.1),
        });
        ConnGuard::new(state.clone()).leave(false);
        assert_eq!(state.count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn guard_releases_slot_when_dropped_without_leave() {
        // Models a request future cancelled mid-delay: the guard is dropped
        // without `leave()`, but the in-flight slot must still be released.
        let state = Arc::new(ConnState {
            count: AtomicUsize::new(1),
            unit_delay: Mutex::new(0.1),
        });
        drop(ConnGuard::new(state.clone()));
        assert_eq!(state.count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn guard_release_is_idempotent() {
        let state = Arc::new(ConnState {
            count: AtomicUsize::new(1),
            unit_delay: Mutex::new(0.1),
        });
        let guard = ConnGuard::new(state.clone());
        guard.leave(false);
        assert_eq!(state.count.load(Ordering::Relaxed), 0);
        // A second release via Drop must not double-decrement.
    }

    #[test]
    fn config_rejects_redis_policy() {
        let err = PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 1,
            "default_conn_delay": 0.1,
            "policy": "redis"
        }));
        assert!(err.is_err());
    }

    #[test]
    fn config_rejects_invalid_conn_delay() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 0,
            "default_conn_delay": 0
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 0,
            "default_conn_delay": -1.0
        }))
        .is_err());
    }

    #[test]
    fn config_defaults_match_apisix() {
        let config = PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 1,
            "default_conn_delay": 0.1,
            "key": "remote_addr"
        }))
        .unwrap();
        assert_eq!(config.rejected_code, 503);
        assert_eq!(config.key_type, KeyType::Var);
        assert!(!config.only_use_default_delay);
        assert_eq!(config.policy, Policy::Local);
    }

    #[test]
    fn config_requires_key_and_rejects_unsupported_rules() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "conn": 2, "burst": 1, "default_conn_delay": 0.1
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "conn": 2, "burst": 1, "default_conn_delay": 0.1,
            "key": "remote_addr", "rules": []
        }))
        .is_err());
    }
}
