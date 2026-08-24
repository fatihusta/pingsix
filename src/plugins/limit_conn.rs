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
    borrow::Cow,
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
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
    core::{PluginPhases, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::limiter_shards::{
        shard_idx, TouchOrder, CLEANUP_BUDGET, LIMIT_SHARDS, PER_SHARD_REGULAR_MAX,
    },
    utils::{
        request::{apisix_key, render_apisix_request_template},
        response::ResponseBuilder,
    },
};

pub const PLUGIN_NAME: &str = "limit-conn";

/// APISIX `limit-conn` runs at priority 1003 (after limit-count 1002).
const PRIORITY: i32 = 1003;

/// Context key holding the concurrency guard while the request is in flight.
/// Keyed per instance so a global and a route limit-conn instance never
/// overwrite each other's guard slot.
static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

fn conn_guard_key(instance_id: u64) -> String {
    format!("pingsix_limit_conn_guard_{instance_id}")
}

/// Creates a `limit-conn` plugin instance from JSON configuration.
pub fn create_limit_conn_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginLimitConn {
        config,
        counters: std::array::from_fn(|_| Mutex::new(CounterShard::default())),
        guard_key: conn_guard_key(NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed)),
    }))
}

/// Outcome of the concurrency decision for one request.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Decision {
    Pass,
    Delay(f64),
    Reject,
}

/// One request-scoped concurrency limit: either a matching rule or the
/// plugin-level `conn`/`burst`/`key` fallback.
struct LimitSelection {
    key: Cow<'static, str>,
    conn: u32,
    burst: u32,
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

#[derive(Default)]
struct CounterShard {
    entries: HashMap<String, Arc<ConnState>>,
    touch_order: TouchOrder,
}

impl CounterShard {
    fn touch(&mut self, key: &str) {
        self.touch_order.touch(key);
    }

    /// Remove at most `CLEANUP_BUDGET` inactive states; active states remain.
    fn sweep_inactive(&mut self) {
        for _ in 0..CLEANUP_BUDGET {
            let Some((_touch, key)) = self.touch_order.pop_oldest() else {
                break;
            };
            if self
                .entries
                .get(&key)
                .is_some_and(|state| state.count.load(Ordering::Relaxed) == 0)
            {
                self.entries.remove(&key);
            } else {
                // Move active entries to the back so one active oldest entry
                // cannot consume every cleanup slot.
                self.touch(&key);
            }
        }
    }
}

/// Request-scoped state released by the reliable `logging` lifecycle hook.
/// If the request future is cancelled before `logging` runs, `Drop` still
/// decrements the in-flight counter so the slot is never leaked.
struct ConnGuard {
    state: Arc<ConnState>,
    started: Instant,
    /// Artificial burst-range delay this request slept through. APISIX feeds
    /// `request_time - delay` into its unit-delay estimate, so the delay we
    /// imposed ourselves is excluded from the latency feedback.
    slept_delay: Duration,
    released: bool,
}

impl ConnGuard {
    fn new(state: Arc<ConnState>) -> Self {
        Self {
            state,
            started: Instant::now(),
            slept_delay: Duration::ZERO,
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
            // `saturating_sub` clamps at zero so a guard released before its
            // full delay elapsed never feeds a negative latency.
            let latency = self
                .started
                .elapsed()
                .saturating_sub(self.slept_delay)
                .as_secs_f64();
            let mut unit_delay = self
                .state
                .unit_delay
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *unit_delay = (latency + *unit_delay) / 2.0;
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

/// One rule from APISIX `limit-conn`'s `rules` array.
#[derive(Debug, Serialize, Deserialize, Validate)]
struct ConnRule {
    /// Maximum number of concurrent requests allowed to pass immediately.
    #[validate(range(min = 1))]
    conn: u32,

    /// Number of excessive concurrent requests allowed to be delayed.
    #[validate(range(min = 0))]
    burst: u32,

    /// Variable template selecting the requests this rule applies to.
    #[validate(custom(function = "validate_key"))]
    key: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_limit_conn_shape"))]
struct PluginConfig {
    /// Maximum number of concurrent requests allowed to pass immediately.
    /// Required together with `key` when `rules` is not configured.
    #[validate(custom(function = "validate_optional_conn"))]
    conn: Option<u32>,

    /// Number of excessive concurrent requests allowed to be delayed.
    /// Defaults to 0 for backwards compatibility with pingsix configs that
    /// omit it; APISIX requires it in the main configuration branch.
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

    /// Variable or variable-combination template to key on. Required together
    /// with `conn` when `rules` is not configured.
    #[validate(custom(function = "validate_optional_key"))]
    key: Option<String>,

    /// Per-rule limits; every matching rule is enforced (APISIX semantics).
    /// Mutually exclusive with the plugin-level `conn`/`key` branch.
    #[serde(default)]
    #[validate(custom(function = "validate_conn_rules"))]
    rules: Vec<ConnRule>,

    #[serde(default = "PluginConfig::default_rejected_code")]
    #[validate(range(min = 200, max = 599))]
    rejected_code: u16,

    #[serde(default)]
    #[validate(custom(function = "validate_rejected_msg"))]
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

fn validate_optional_conn(value: u32) -> Result<(), ValidationError> {
    if value < 1 {
        return Err(ValidationError::new("conn must be > 0"));
    }
    Ok(())
}

fn validate_optional_key(value: &&String) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::new("key cannot be empty"));
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), ValidationError> {
    if key.trim().is_empty() {
        return Err(ValidationError::new("key cannot be empty"));
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

// The validator derive invokes custom validators with the exact field type;
// accepting `&Vec` keeps the generated call arity-free.
#[allow(clippy::ptr_arg)]
fn validate_conn_rules(rules: &Vec<ConnRule>) -> Result<(), ValidationError> {
    for (index, rule) in rules.iter().enumerate() {
        if let Err(error) = rule.validate() {
            return Err(ValidationError::new("invalid rules entry")
                .with_message(format!("rules[{index}] is invalid: {error}").into()));
        }
    }
    Ok(())
}

/// APISIX oneOf: either the plugin-level `conn`/`burst`/`key` branch or the
/// `rules` branch, with `default_conn_delay` shared by both. Pingsix keeps its
/// existing default of `burst = 0` for the plugin-level branch.
fn validate_limit_conn_shape(config: &PluginConfig) -> Result<(), ValidationError> {
    let main_configured = config.conn.is_some() || config.key.is_some();
    let rules_configured = !config.rules.is_empty();
    if main_configured && rules_configured {
        return Err(ValidationError::new(
            "configure either conn/burst/key or rules, not both",
        ));
    }
    if !main_configured && !rules_configured {
        return Err(ValidationError::new(
            "either conn, burst and key or rules must be configured",
        ));
    }
    if main_configured && (config.conn.is_none() || config.key.is_none()) {
        return Err(ValidationError::new(
            "conn and key must be configured together",
        ));
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
    /// Sharded in-flight counters. Entries are swept when a shard grows past
    /// the per-shard capacity to avoid unbounded memory from ephemeral keys.
    /// Sharding keeps requests with different keys off the same mutex and
    /// bounds any cleanup sweep to one shard (1/`LIMIT_SHARDS` of keys).
    counters: [Mutex<CounterShard>; LIMIT_SHARDS],
    /// Per-instance context key for the request guard.
    guard_key: String,
}

/// Evaluate a `rules` entry's key template. APISIX skips a rule only when
/// the template contains no placeholders; a placeholder whose variable is
/// absent renders empty and is still enforced as the empty-key bucket.
fn resolve_rule_key(session: &mut Session, rule_key: &str) -> Option<Cow<'static, str>> {
    if !rule_key.contains('$') {
        return None;
    }
    Some(Cow::Owned(render_apisix_request_template(
        session, rule_key,
    )))
}

impl PluginLimitConn {
    /// Select every matching rule (APISIX enforces all of them), then fall
    /// back to the plugin-level `conn`/`burst`/`key` when rules are not
    /// configured. Returns `None` when the rules branch is configured but no
    /// rule applies; the caller turns that into 500 or `allow_degradation`
    /// pass, mirroring APISIX.
    fn select_limits(&self, session: &mut Session) -> Option<Vec<LimitSelection>> {
        if !self.config.rules.is_empty() {
            let mut limits = Vec::new();
            for rule in &self.config.rules {
                if let Some(key) = resolve_rule_key(session, &rule.key) {
                    limits.push(LimitSelection {
                        key,
                        conn: rule.conn,
                        burst: rule.burst,
                    });
                }
            }
            return if limits.is_empty() {
                None
            } else {
                Some(limits)
            };
        }

        let (Some(conn), Some(key)) = (&self.config.conn, &self.config.key) else {
            return None;
        };
        Some(vec![LimitSelection {
            key: apisix_key(
                session,
                key,
                self.config.key_type == KeyType::VarCombination,
            ),
            conn: *conn,
            burst: self.config.burst,
        }])
    }

    fn get_or_insert_counter(&self, key: &str) -> Arc<ConnState> {
        let mut shard = self.counters[shard_idx(key)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(state) = shard.entries.get(key).cloned() {
            shard.touch(key);
            return state;
        }
        if shard.entries.len() >= PER_SHARD_REGULAR_MAX {
            // A fixed, small cleanup budget prevents a request-time full scan.
            shard.sweep_inactive();
        }
        // Never evict active entries. New keys use one stable overflow state
        // once all regular entries are active, avoiding split guards.
        let storage_key = if shard.entries.len() < PER_SHARD_REGULAR_MAX {
            key
        } else {
            "__pingsix_limit_conn_overflow__"
        };
        let state = shard
            .entries
            .entry(storage_key.to_string())
            .or_insert_with(|| {
                Arc::new(ConnState {
                    count: AtomicUsize::new(0),
                    unit_delay: Mutex::new(self.config.default_conn_delay),
                })
            })
            .clone();
        shard.touch(storage_key);
        state
    }

    async fn reject(&self, session: &mut Session) -> Result<bool> {
        self.reject_with(
            session,
            StatusCode::from_u16(self.config.rejected_code)
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            self.config.rejected_msg.as_deref(),
        )
        .await
    }

    async fn reject_with(
        &self,
        session: &mut Session,
        status: StatusCode,
        body: Option<&str>,
    ) -> Result<bool> {
        ResponseBuilder::send_proxy_error(session, status, body, None).await?;
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
    fn phases(&self) -> PluginPhases {
        PluginPhases::REQUEST | PluginPhases::LOGGING
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        let Some(limits) = self.select_limits(session) else {
            // APISIX returns 500 when a rules-branch config matches no rule,
            // unless allow_degradation explicitly permits the request.
            if self.config.allow_degradation {
                return Ok(false);
            }
            return self
                .reject_with(
                    session,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Some("failed to get limit conn rules"),
                )
                .await;
        };

        let mut guards = Vec::with_capacity(limits.len());
        for limit in limits {
            let state = self.get_or_insert_counter(limit.key.as_ref());
            let count = state.count.fetch_add(1, Ordering::Relaxed) + 1;
            let unit_delay = *state.unit_delay.lock().unwrap_or_else(|e| e.into_inner());

            match decide(count, limit.conn, limit.burst, unit_delay) {
                Decision::Pass => {
                    guards.push(ConnGuard::new(state));
                }
                Decision::Delay(secs) => {
                    // Hold the guard locally so a cancellation during sleep
                    // still decrements via Drop; transfer ownership only after
                    // success. Record the artificial delay so `leave()` can
                    // exclude it from the latency feedback (APISIX computes
                    // `request_time - delay`).
                    let mut guard = ConnGuard::new(state);
                    guard.slept_delay = Duration::from_secs_f64(secs);
                    tokio::time::sleep(Duration::from_secs_f64(secs)).await;
                    guards.push(guard);
                }
                Decision::Reject => {
                    // Release the current slot immediately; previously admitted
                    // guards are dropped with the local vector.
                    state.count.fetch_sub(1, Ordering::Relaxed);
                    log::debug!(
                        "limit-conn: rejected request for key {:?} (in-flight {count}, conn {} burst {})",
                        limit.key,
                        limit.conn,
                        limit.burst
                    );
                    return self.reject(session).await;
                }
            }
        }

        ctx.set(self.guard_key.clone(), guards);
        Ok(false)
    }

    async fn logging(
        &self,
        _session: &mut Session,
        _e: Option<&pingora_error::Error>,
        ctx: &mut ProxyContext,
    ) {
        if let Some(vars) = ctx.vars.as_mut() {
            if let Some(guards) = vars
                .remove(&self.guard_key)
                .and_then(|guards| guards.downcast::<Vec<ConnGuard>>().ok())
            {
                for guard in *guards {
                    guard.leave(!self.config.only_use_default_delay);
                }
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
    fn burst_delay_is_excluded_from_latency_feedback() {
        // Two guards with the same wall-clock service time: the one that
        // slept through a burst delay feeds a smaller latency into the
        // unit-delay EMA (APISIX uses `request_time - delay`), so our own
        // throttling never inflates the estimated service latency.
        let plain_state = Arc::new(ConnState {
            count: AtomicUsize::new(1),
            unit_delay: Mutex::new(1.0),
        });
        let delayed_state = Arc::new(ConnState {
            count: AtomicUsize::new(1),
            unit_delay: Mutex::new(1.0),
        });

        let mut delayed = ConnGuard::new(delayed_state.clone());
        // A delay longer than the test's own runtime clamps the latency at
        // zero, making the expected EMA exact.
        delayed.slept_delay = Duration::from_secs(600);
        let plain = ConnGuard::new(plain_state.clone());
        std::thread::sleep(Duration::from_millis(10));

        delayed.leave(true);
        plain.leave(true);

        // Delayed guard: latency clamps to 0 -> EMA = (0 + 1.0) / 2.
        assert_eq!(*delayed_state.unit_delay.lock().unwrap(), 0.5);
        // Plain guard: real service time elapsed -> EMA strictly larger.
        // (Before the fix both guards fed the same inflated latency.)
        assert!(*plain_state.unit_delay.lock().unwrap() > 0.5);
    }

    #[test]
    fn full_active_shard_uses_one_stable_overflow_state() {
        let plugin = PluginLimitConn {
            config: PluginConfig::try_from(serde_json::json!({
                "conn": 2,
                "default_conn_delay": 0.1,
                "key": "remote_addr"
            }))
            .unwrap(),
            counters: std::array::from_fn(|_| Mutex::new(CounterShard::default())),
            guard_key: conn_guard_key(99),
        };
        let shard = shard_idx("regular-0");
        let regular_keys: Vec<_> = (0..100_000)
            .map(|i| format!("regular-{i}"))
            .filter(|key| shard_idx(key) == shard)
            .take(PER_SHARD_REGULAR_MAX)
            .collect();
        assert_eq!(regular_keys.len(), PER_SHARD_REGULAR_MAX);
        for key in &regular_keys {
            plugin
                .get_or_insert_counter(key)
                .count
                .fetch_add(1, Ordering::Relaxed);
        }
        let overflow_keys: Vec<_> = (100_000..200_000)
            .map(|i| format!("overflow-{i}"))
            .filter(|key| shard_idx(key) == shard)
            .take(2)
            .collect();
        let first = plugin.get_or_insert_counter(&overflow_keys[0]);
        let second = plugin.get_or_insert_counter(&overflow_keys[1]);

        assert!(Arc::ptr_eq(&first, &second));
        let shard = plugin.counters[shard].lock().unwrap();
        assert_eq!(shard.entries.len(), PER_SHARD_REGULAR_MAX + 1);
        assert!(shard
            .entries
            .contains_key("__pingsix_limit_conn_overflow__"));
    }

    #[test]
    fn bounded_sweep_keeps_active_state_and_removes_only_budget() {
        let mut shard = CounterShard::default();
        let active = "active".to_string();
        shard.entries.insert(
            active.clone(),
            Arc::new(ConnState {
                count: AtomicUsize::new(1),
                unit_delay: Mutex::new(0.1),
            }),
        );
        shard.touch(&active);
        for i in 0..CLEANUP_BUDGET + 2 {
            let key = i.to_string();
            shard.entries.insert(
                key.clone(),
                Arc::new(ConnState {
                    count: AtomicUsize::new(0),
                    unit_delay: Mutex::new(0.1),
                }),
            );
            shard.touch(&key);
        }
        shard.sweep_inactive();
        assert!(shard.entries.contains_key(&active));
        assert_eq!(
            shard.entries.len(),
            4,
            "the active entry plus two inactive entries remain after an 8-item bounded sweep"
        );
    }

    #[test]
    fn config_tolerates_unknown_fields() {
        // Unknown fields (typos or fields from other APISIX versions) are
        // ignored; only declared fields take effect.
        let config = PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 1,
            "default_conn_delay": 0.1,
            "key": "remote_addr",
            "typo_field": true
        }))
        .expect("unknown fields are tolerated");
        assert_eq!(config.conn, Some(2));
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
    fn config_rejects_redis_cluster_policy_with_clear_validation_error() {
        let err = PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 1,
            "default_conn_delay": 0.1,
            "key": "remote_addr",
            "policy": "redis-cluster"
        }))
        .unwrap_err();
        assert!(err.to_string().contains("requires a distributed backend"));
    }

    #[test]
    fn config_accepts_var_combination_key_type() {
        let config = PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 1,
            "default_conn_delay": 0.1,
            "key": "$remote_addr $http_x_user",
            "key_type": "var_combination"
        }))
        .unwrap();
        assert_eq!(config.key_type, KeyType::VarCombination);
    }

    #[test]
    fn config_accepts_rejected_code_200() {
        let config = PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 1,
            "default_conn_delay": 0.1,
            "key": "remote_addr",
            "rejected_code": 200
        }))
        .unwrap();
        assert_eq!(config.rejected_code, 200);
    }

    #[test]
    fn config_rejects_rejected_code_below_200() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 1,
            "default_conn_delay": 0.1,
            "key": "remote_addr",
            "rejected_code": 199
        }))
        .is_err());
    }

    #[test]
    fn config_rejects_empty_rejected_msg() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 1,
            "default_conn_delay": 0.1,
            "key": "remote_addr",
            "rejected_msg": ""
        }))
        .is_err());
    }

    #[test]
    fn config_parses_rules_branch() {
        let config = PluginConfig::try_from(serde_json::json!({
            "default_conn_delay": 0.1,
            "rules": [
                {"conn": 3, "burst": 1, "key": "$http_x_user"},
                {"conn": 10, "burst": 0, "key": "$remote_addr"}
            ]
        }))
        .unwrap();
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].conn, 3);
        assert!(config.conn.is_none());
        assert!(config.key.is_none());
    }

    #[test]
    fn config_rules_branch_still_requires_default_conn_delay() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "rules": [{"conn": 3, "burst": 1, "key": "$remote_addr"}]
        }))
        .is_err());
    }

    #[test]
    fn config_rejects_both_main_and_rules_branches() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "burst": 1,
            "default_conn_delay": 0.1,
            "key": "remote_addr",
            "rules": [{"conn": 3, "burst": 1, "key": "$remote_addr"}]
        }))
        .is_err());
    }

    async fn session_with_header(name: &'static str, value: &'static str) -> Session {
        use tokio::io::AsyncWriteExt;

        let (client, mut server) = tokio::io::duplex(1024);
        server
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: example.com\r\n{name}: {value}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("write canned request");
        drop(server);
        let mut session = Session::new_h1(Box::new(client));
        session
            .downstream_session
            .read_request()
            .await
            .expect("canned request parses");
        session
    }

    /// A session whose canned request is written up front, keeping the peer
    /// end alive so plugin responses can be read back.
    async fn session_with_raw_request(raw: &'static str) -> (Session, tokio::io::DuplexStream) {
        use tokio::io::AsyncWriteExt;

        let (client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(raw.as_bytes())
            .await
            .expect("write canned request");
        let mut session = Session::new_h1(Box::new(client));
        session
            .downstream_session
            .read_request()
            .await
            .expect("canned request parses");
        (session, server)
    }

    /// Read everything the plugin wrote back to the client (the session must
    /// already be dropped so the stream reaches EOF).
    async fn drain_response(server: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt;

        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), server.read_to_end(&mut buf))
            .await
            .expect("response completes")
            .expect("response reads cleanly");
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn rejects_at_conn_plus_burst_with_configured_code_and_frees_slot() {
        let plugin = PluginLimitConn {
            config: PluginConfig::try_from(serde_json::json!({
                "conn": 1,
                "burst": 0,
                "default_conn_delay": 0.1,
                "key": "remote_addr",
                "rejected_code": 429
            }))
            .unwrap(),
            counters: std::array::from_fn(|_| Mutex::new(CounterShard::default())),
            guard_key: conn_guard_key(96),
        };
        let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        // First in-flight request occupies the single slot.
        let (mut first_session, _first_server) = session_with_raw_request(request).await;
        let mut first_ctx = ProxyContext::default();
        assert!(!plugin
            .request_filter(&mut first_session, &mut first_ctx)
            .await
            .unwrap());

        // A concurrent request exceeds conn + burst and is rejected with the
        // configured status code.
        let (mut second_session, mut second_server) = session_with_raw_request(request).await;
        let mut second_ctx = ProxyContext::default();
        assert!(plugin
            .request_filter(&mut second_session, &mut second_ctx)
            .await
            .unwrap());
        drop(second_session);
        let response = drain_response(&mut second_server).await;
        assert!(
            response.starts_with("HTTP/1.1 429 "),
            "expected the configured rejected_code, got: {response}"
        );

        // Completing the first request frees the slot, so a subsequent
        // request passes again.
        plugin
            .logging(&mut first_session, None, &mut first_ctx)
            .await;
        let (mut third_session, _third_server) = session_with_raw_request(request).await;
        let mut third_ctx = ProxyContext::default();
        assert!(!plugin
            .request_filter(&mut third_session, &mut third_ctx)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn rules_select_every_matching_rule_and_skip_unresolved() {
        let plugin = PluginLimitConn {
            config: PluginConfig::try_from(serde_json::json!({
                "default_conn_delay": 0.1,
                "rules": [
                    {"conn": 3, "burst": 1, "key": "$http_x_user"},
                    {"conn": 10, "burst": 0, "key": "$http_x_role"}
                ]
            }))
            .unwrap(),
            counters: std::array::from_fn(|_| Mutex::new(CounterShard::default())),
            guard_key: conn_guard_key(98),
        };

        let mut session = session_with_header("x-user", "alice").await;
        session
            .req_header_mut()
            .insert_header("x-role", "admin")
            .unwrap();
        let limits = plugin.select_limits(&mut session).expect("rules match");
        assert_eq!(limits.len(), 2);
        assert_eq!(limits[0].conn, 3);
        assert_eq!(limits[1].conn, 10);

        // Absent variable -> APISIX still enforces the rule under the
        // empty-key bucket.
        let mut empty = session_with_header("x-other", "v").await;
        let limits = plugin
            .select_limits(&mut empty)
            .expect("empty-key rule applies");
        assert_eq!(limits.len(), 2);
        assert!(limits.iter().all(|limit| limit.key.is_empty()));

        // Bare rule keys resolve no variables and are skipped, like APISIX.
        let bare = PluginLimitConn {
            config: PluginConfig::try_from(serde_json::json!({
                "default_conn_delay": 0.1,
                "rules": [{"conn": 3, "burst": 1, "key": "remote_addr"}]
            }))
            .unwrap(),
            counters: std::array::from_fn(|_| Mutex::new(CounterShard::default())),
            guard_key: conn_guard_key(97),
        };
        let mut session = session_with_header("host", "example.com").await;
        assert!(bare.select_limits(&mut session).is_none());
    }

    #[test]
    fn config_rejects_rules_with_invalid_values() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "default_conn_delay": 0.1,
            "rules": [{"conn": 0, "burst": 1, "key": "$remote_addr"}]
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "default_conn_delay": 0.1,
            "rules": [{"conn": 3, "burst": 1, "key": ""}]
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "default_conn_delay": 0.1,
            "rules": [{"conn": 3, "burst": 1}]
        }))
        .is_err());
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
    fn config_requires_key_and_rejects_main_without_conn() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "conn": 2, "burst": 1, "default_conn_delay": 0.1
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "burst": 1, "default_conn_delay": 0.1, "key": "remote_addr"
        }))
        .is_err());
    }

    #[test]
    fn config_keeps_pingsix_default_burst() {
        let config = PluginConfig::try_from(serde_json::json!({
            "conn": 2,
            "default_conn_delay": 0.1,
            "key": "remote_addr"
        }))
        .unwrap();
        assert_eq!(config.burst, 0);
        assert_eq!(config.conn, Some(2));
    }
}
