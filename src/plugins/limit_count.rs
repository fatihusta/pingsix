use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, RwLock, Weak},
    time::{Duration, Instant},
};

use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, IntCounterVec};

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::Result;
use pingora_limits::rate::Rate;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::{
    config::UpstreamHashOn,
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::{
        config::parse_and_validate_plugin_config,
        limiting::{
            default_rejected_code, next_instance_ctx_key, rejection, select_rules, validate_key,
            validate_rejected_msg, BoundedShardMap, CountKeyType as KeyType, CountPolicy as Policy,
            RejectPolicy, Shard, SweepMiss, LIMIT_COUNT_OVERFLOW,
        },
    },
    utils::request::{apisix_key, request_selector_key},
};

pub const PLUGIN_NAME: &str = "limit-count";
const PRIORITY: i32 = 1002;

/// Context key holding the request's rate-limit quota as one typed value.
/// Keeping a single `vars` entry (instead of three string entries) avoids
/// three key allocations per request on the hot path. Keyed per instance so a
/// global and a route limit-count instance never overwrite each other's quota.
#[cfg(test)]
fn rate_limit_quota_key(instance_id: u64) -> String {
    crate::plugins::limiting::instance_ctx_key("pingsix_rate_limit_quota_", instance_id)
}

/// Hard cap on timestamp history per sliding-window key. Older entries are
/// dropped first, so memory stays bounded even under sustained overload.
const MAX_SLIDING_ENTRIES_PER_KEY: usize = 4096;

/// Schema maximum time window; also the age after which an untouched sliding
/// window entry is unconditionally stale for any configured window.
const MAX_WINDOW_SECS: u32 = 86400;

/// Typed rate-limit quota stored in the request context and expanded into
/// response headers by [`PluginRateLimit::response_filter`].
struct RateLimitQuota {
    limit: u32,
    remaining: isize,
    reset: u32,
    current_count: isize,
    header_prefix: String,
}

/// One request-scoped rate limit: either a matching rule or the plugin-level
/// `count`/`time_window` fallback.
struct LimitSelection {
    count: u32,
    time_window: u32,
    header_prefix: String,
    /// `true` when this selection comes from an APISIX `rules` entry. Rule
    /// keys use APISIX semantics: an absent variable renders an empty key and
    /// is still limited, while the pingsix `key_missing_policy` only applies
    /// to the plugin-level key.
    from_rule: bool,
}

/// Outcome of observing one request against a limit.
struct LimitOutcome {
    limited: bool,
    current_count: isize,
    remaining: isize,
}

static RATE_LIMIT_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "pingsix_rate_limit_requests_total",
        "Rate-limit decisions by local outcome",
        &["outcome", "scope"]
    )
    .expect("rate-limit metric registration must succeed")
});

/// Creates a Limit Count plugin instance with the given configuration.
/// This plugin enforces rate limiting on requests based on a key derived from the request
/// (e.g., client IP, header, or custom variable). Exceeding the limit results in a configurable
/// response (default: `503 Service Unavailable`).
pub fn create_limit_count_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;

    if let Some(group) = config.group.as_deref().filter(|group| !group.is_empty()) {
        log::debug!("limit-count: local counters are namespaced by group {group:?}");
    }

    let group_state = config
        .group
        .as_deref()
        .filter(|group| !group.is_empty())
        .map(group_state);
    if let Some(state) = group_state.as_deref() {
        let mut rates = state.fixed_rates.write().unwrap_or_else(|e| e.into_inner());
        for (window, rate) in build_fixed_rates(&config) {
            rates.entry(window).or_insert(Arc::new(rate));
        }
    }

    Ok(Arc::new(PluginRateLimit {
        reject: RejectPolicy::new(config.rejected_code, config.rejected_msg.clone()),
        fixed_rates: build_fixed_rates(&config),
        config,
        sliding: BoundedShardMap::new(),
        quota_key: next_instance_ctx_key("pingsix_rate_limit_quota_"),
        group_state,
    }))
}

/// Process-wide registry of shared counters for APISIX `group` semantics.
/// `Weak` entries let retired plugin snapshots drop their state while any
/// live instance keeps the shared limiter alive.
static GROUP_STATES: Lazy<Mutex<HashMap<String, Weak<GroupState>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Counters shared by every plugin instance that configures the same `group`.
struct GroupState {
    /// One shared fixed-window [`Rate`] per time window. Readers clone the
    /// `Arc` under the read lock and observe lock-free, so group traffic is
    /// never serialized on this registry; the write lock is taken only to
    /// register a window for the first time.
    fixed_rates: RwLock<HashMap<u32, Arc<Rate>>>,
    sliding: BoundedShardMap<SlidingWindow>,
}

impl GroupState {
    /// Record one request for `key` and return the window occupancy.
    fn observe(&self, window_type: WindowType, time_window: u32, key: &str) -> isize {
        match window_type {
            WindowType::Fixed => {
                // Fast path: read-lock, clone the shared counter, and observe
                // outside the guard (`Rate` is atomic and lock-free).
                let rate = self
                    .fixed_rates
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&time_window)
                    .cloned();
                let rate = rate.unwrap_or_else(|| {
                    // First registration of this window (double-checked: it
                    // may have appeared between dropping the read lock and
                    // acquiring the write lock).
                    let mut rates = self.fixed_rates.write().unwrap_or_else(|e| e.into_inner());
                    rates
                        .entry(time_window)
                        .or_insert_with(|| {
                            Arc::new(Rate::new(Duration::from_secs(time_window as u64)))
                        })
                        .clone()
                });
                rate.observe(&key, 1)
            }
            WindowType::Sliding => {
                let now = Instant::now();
                let mut shard = self.sliding.lock(key);
                sliding_window_for(&mut shard, key, now).observe(now, time_window) as isize
            }
        }
    }
}

/// Get (or lazily create) the shared limiter for `group`.
fn group_state(group: &str) -> Arc<GroupState> {
    let mut registry = GROUP_STATES.lock().unwrap_or_else(|e| e.into_inner());
    // Opportunistically reclaim dead tombstones so long-lived processes with
    // rotating group names cannot grow this registry without bound.
    if registry.len() >= 128 {
        registry.retain(|_, state| state.upgrade().is_some());
    }
    if let Some(state) = registry.get(group).and_then(Weak::upgrade) {
        return state;
    }
    let state = Arc::new(GroupState {
        fixed_rates: RwLock::new(HashMap::new()),
        sliding: BoundedShardMap::new(),
    });
    registry.insert(group.to_string(), Arc::downgrade(&state));
    state
}

/// Register one fixed-window [`Rate`] per distinct configured time window.
/// Rules may select different windows per request; instances with equal
/// window lengths are interchangeable, so one shared instance per window
/// suffices.
///
/// pingora-limits `Rate` is a count-min estimator (4 hashes over a fixed slot
/// array), not an exact per-key counter: under high key cardinality distinct
/// keys can collide and counts overestimate, so very low `count` limits may
/// reject slightly early. The error is bounded by design (never an
/// undercount) and matches the trade APISIX's `local` policy makes.
fn build_fixed_rates(config: &PluginConfig) -> HashMap<u32, Rate> {
    let mut rates = HashMap::new();
    if let Some(time_window) = config.time_window {
        rates
            .entry(time_window)
            .or_insert_with(|| Rate::new(Duration::from_secs(time_window as u64)));
    }
    for rule in &config.rules {
        rates
            .entry(rule.time_window)
            .or_insert_with(|| Rate::new(Duration::from_secs(rule.time_window as u64)));
    }
    rates
}

/// One rule from APISIX `limit-count`'s `rules` array.
#[derive(Debug, Serialize, Deserialize, Validate)]
struct CountRule {
    /// Maximum number of requests allowed in `time_window`.
    #[validate(range(min = 1))]
    count: u32,

    /// Time window in seconds.
    #[validate(range(min = 1, max = 86400))]
    time_window: u32,

    /// Variable template selecting the requests this rule applies to.
    #[validate(custom(function = "validate_key"))]
    key: String,

    /// Prefix applied to the four `X-Rate-Limit-*` quota headers.
    #[serde(default)]
    #[validate(custom(function = "validate_header_prefix"))]
    header_prefix: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_limit_count_shape"))]
struct PluginConfig {
    /// Type of key to use for rate limiting. APISIX values plus pingsix's
    /// legacy `head`/`cookie` selectors.
    #[serde(default)]
    key_type: KeyType,

    /// Key name or value to use for rate limiting (e.g., header name for `HEAD`, variable name for `VARS`).
    /// Defaults to `remote_addr` for APISIX compatibility.
    /// Must be non-empty.
    #[validate(custom(function = "validate_key"))]
    #[serde(default = "PluginConfig::default_key")]
    key: String,

    /// Time window for rate limiting, in seconds. Mutually exclusive with `rules`.
    #[validate(custom(function = "validate_optional_time_window"))]
    time_window: Option<u32>,

    /// Maximum number of requests allowed in the time window. Mutually
    /// exclusive with `rules`.
    #[validate(custom(function = "validate_optional_count"))]
    count: Option<u32>,

    /// Fixed (existing `Rate` path) or sliding (local bounded history).
    #[serde(default)]
    window_type: WindowType,

    /// HTTP status code for rejected requests (default: 503).
    #[serde(default = "default_rejected_code")]
    #[validate(range(min = 200, max = 599))]
    rejected_code: u16,

    /// Optional custom message for rejected requests. If not set, no response body is sent.
    #[serde(default)]
    #[validate(custom(function = "validate_rejected_msg"))]
    rejected_msg: Option<String>,

    /// Prefix applied to the three `X-RateLimit-*` quota headers (rules
    /// entries carry their own `header_prefix`).
    #[serde(default)]
    #[validate(custom(function = "validate_header_prefix"))]
    header_prefix: Option<String>,

    /// Whether to include `X-Rate-Limit-*` headers in the response (default: true).
    #[serde(default = "PluginConfig::default_show_limit_quota_header")]
    show_limit_quota_header: bool,

    /// Policy for handling requests when key extraction fails (default: allow).
    #[serde(default = "PluginConfig::default_key_missing_policy")]
    key_missing_policy: KeyMissingPolicy,

    /// Rate limiting is process-local in this release; cluster scope needs a shared backend.
    #[serde(default)]
    scope: Scope,

    /// Per-rule limits, evaluated first-match-wins. Mutually exclusive with
    /// the plugin-level `count`/`time_window` branch.
    #[serde(default)]
    #[validate(custom(function = "validate_count_rules"))]
    rules: Vec<CountRule>,

    /// Optional namespace prefixed to every local counter key as `<group>|`.
    #[serde(default)]
    group: Option<String>,

    /// Counter backend. Only `local` is supported in this release.
    #[serde(default)]
    policy: Policy,

    /// Accepted for APISIX schema compatibility; this local implementation has
    /// no external dependencies that could degrade.
    #[serde(default)]
    allow_degradation: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum WindowType {
    #[default]
    Fixed,
    Sliding,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default)]
#[serde(rename_all = "lowercase")]
enum KeyMissingPolicy {
    /// Allow requests when key cannot be extracted
    #[default]
    Allow,
    /// Deny requests when key cannot be extracted
    Deny,
    /// Use a default key for all requests with missing keys
    Default,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Scope {
    #[default]
    Local,
    Cluster,
}

impl PluginConfig {
    fn default_key() -> String {
        "remote_addr".to_string()
    }

    fn default_show_limit_quota_header() -> bool {
        true
    }

    fn default_key_missing_policy() -> KeyMissingPolicy {
        KeyMissingPolicy::Allow
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid limit count plugin config")?;
        config.policy.ensure_local("limit-count")?;
        if config.scope == Scope::Cluster {
            return Err(ProxyError::validation_error(
                "limit-count scope 'cluster' requires a distributed backend",
            ));
        }
        if config.window_type == WindowType::Sliding {
            let configured_counts = config
                .count
                .iter()
                .chain(config.rules.iter().map(|rule| &rule.count));
            if configured_counts
                .clone()
                .any(|count| *count >= MAX_SLIDING_ENTRIES_PER_KEY as u32)
            {
                return Err(ProxyError::validation_error(format!(
                    "limit-count sliding window count must be below {MAX_SLIDING_ENTRIES_PER_KEY} (bounded per-key history)"
                )));
            }
        }
        if config.group.is_some() && !config.rules.is_empty() {
            return Err(ProxyError::validation_error(
                "limit-count group and rules cannot be configured together",
            ));
        }
        let mut rule_keys = std::collections::HashSet::new();
        for rule in &config.rules {
            if !rule_keys.insert(rule.key.as_str()) {
                return Err(ProxyError::validation_error(format!(
                    "limit-count rules contain duplicate key '{}'",
                    rule.key
                )));
            }
        }

        Ok(config)
    }
}

fn validate_optional_count(value: u32) -> Result<(), ValidationError> {
    if value < 1 {
        return Err(ValidationError::new("count must be > 0"));
    }
    Ok(())
}

fn validate_optional_time_window(value: u32) -> Result<(), ValidationError> {
    if !(1..=86400).contains(&value) {
        return Err(ValidationError::new(
            "time_window must be between 1 and 86400 seconds",
        ));
    }
    Ok(())
}

/// `header_prefix` becomes part of response header names, so it must be a
/// non-empty HTTP-token-safe subset of `[A-Za-z0-9_-]`; anything else is
/// rejected at config validation so a bad prefix fails the config write
/// instead of failing header insertion (and the response) on every request.
fn validate_header_prefix(value: &&String) -> Result<(), ValidationError> {
    if value.is_empty()
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ValidationError::new(
            "header_prefix must be non-empty and contain only [A-Za-z0-9_-]",
        ));
    }
    Ok(())
}

// The validator derive invokes custom validators with the exact field type;
// accepting `&Vec` keeps the generated call arity-free.
#[allow(clippy::ptr_arg)]
fn validate_count_rules(rules: &Vec<CountRule>) -> Result<(), ValidationError> {
    for (index, rule) in rules.iter().enumerate() {
        if let Err(error) = rule.validate() {
            return Err(ValidationError::new("invalid rules entry")
                .with_message(format!("rules[{index}] is invalid: {error}").into()));
        }
    }
    Ok(())
}

/// APISIX oneOf: either the plugin-level `count`/`time_window` branch or the
/// `rules` branch, never both and never neither.
fn validate_limit_count_shape(config: &PluginConfig) -> Result<(), ValidationError> {
    let main_configured = config.count.is_some() || config.time_window.is_some();
    let rules_configured = !config.rules.is_empty();
    if main_configured && rules_configured {
        return Err(ValidationError::new(
            "configure either count/time_window or rules, not both",
        ));
    }
    if !main_configured && !rules_configured {
        return Err(ValidationError::new(
            "either count and time_window or rules must be configured",
        ));
    }
    if main_configured && (config.count.is_none() || config.time_window.is_none()) {
        return Err(ValidationError::new(
            "count and time_window must be configured together",
        ));
    }
    Ok(())
}

/// Per-key sliding-window event history. The deque only grows to
/// [`MAX_SLIDING_ENTRIES_PER_KEY`]; older timestamps are evicted first.
#[derive(Default)]
struct SlidingWindow {
    events: VecDeque<Instant>,
}

impl SlidingWindow {
    /// Drop events older than `time_window` seconds.
    fn prune(&mut self, now: Instant, time_window: u32) {
        let window = Duration::from_secs(time_window as u64);
        while self
            .events
            .front()
            .is_some_and(|event| now.checked_duration_since(*event).unwrap_or_default() >= window)
        {
            self.events.pop_front();
        }
    }

    /// Record one event at `now` and return the current window occupancy.
    fn observe(&mut self, now: Instant, time_window: u32) -> usize {
        self.prune(now, time_window);
        if self.events.len() >= MAX_SLIDING_ENTRIES_PER_KEY {
            self.events.pop_front();
        }
        self.events.push_back(now);
        self.events.len()
    }
}

/// True when the window's newest event is older than any configured window
/// can possibly be ([`MAX_WINDOW_SECS`]), or the window holds no events — the
/// sweep predicate for the shared budgeted stale-sweep.
fn sliding_stale(window: &SlidingWindow, now: Instant) -> bool {
    match window.events.back() {
        Some(last) => now
            .checked_duration_since(*last)
            .is_some_and(|age| age >= Duration::from_secs(MAX_WINDOW_SECS as u64)),
        None => true,
    }
}

/// Get (or create) the window for `key` within one shard, applying the shared
/// bounded-shard admission rules (one stable overflow entry per shard once
/// regular capacity fills) first.
fn sliding_window_for<'a>(
    shard: &'a mut Shard<SlidingWindow>,
    key: &str,
    now: Instant,
) -> &'a mut SlidingWindow {
    shard
        .admit(key, LIMIT_COUNT_OVERFLOW, |shard| {
            shard.sweep(|window| sliding_stale(window, now), SweepMiss::Restore)
        })
        .or_default()
}

/// Rate Limit plugin implementation.
///
/// This is a per-instance in-memory rate limiter. In a multi-replica deployment,
/// the effective limit is approximately `config.count * replica_count`.
pub struct PluginRateLimit {
    config: PluginConfig,
    /// One fixed-window [`Rate`] per configured time window.
    fixed_rates: HashMap<u32, Rate>,
    /// Sharded sliding-window histories, used only when `window_type: sliding`.
    sliding: BoundedShardMap<SlidingWindow>,
    /// Per-instance context key for the quota shared with `response_filter`.
    quota_key: String,
    /// Shared counters for APISIX `group` semantics, when configured.
    group_state: Option<Arc<GroupState>>,
    reject: RejectPolicy,
}

#[async_trait]
impl ProxyPlugin for PluginRateLimit {
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
        let Some(limits) = self.select_limits(session) else {
            // APISIX returns 500 when a rules-branch config matches no rule,
            // unless allow_degradation explicitly permits the request.
            if self.config.allow_degradation {
                RATE_LIMIT_REQUESTS
                    .with_label_values(&["allowed", "local"])
                    .inc();
                return Ok(FilterVerdict::Continue);
            }
            RATE_LIMIT_REQUESTS
                .with_label_values(&["rejected", "local"])
                .inc();
            return Ok(FilterVerdict::Reject(rejection(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("failed to get rate limit rules"),
                &[],
            )));
        };

        let mut quotas = Vec::new();
        for (key, selection) in limits {
            // Handle empty key based on policy (plugin-level keys only;
            // empty rule keys are limited under the empty-key bucket like
            // APISIX).
            if key.is_empty() && !selection.from_rule {
                return Ok(self.handle_missing_key(session, ctx));
            }

            // Check rate limit without forcing borrowed selector keys to allocate.
            let outcome = self.check_rate_limit(&selection, key.as_ref());

            if outcome.limited {
                RATE_LIMIT_REQUESTS
                    .with_label_values(&["rejected", "local"])
                    .inc();
                return Ok(self.handle_rate_limit(&selection, outcome.current_count));
            }
            RATE_LIMIT_REQUESTS
                .with_label_values(&["allowed", "local"])
                .inc();

            // Store rate limit info in context for potential use by other plugins
            if self.config.show_limit_quota_header {
                quotas.push(RateLimitQuota {
                    limit: selection.count,
                    remaining: outcome.remaining,
                    reset: selection.time_window,
                    current_count: outcome.current_count,
                    header_prefix: selection.header_prefix.clone(),
                });
            }
        }

        if self.config.show_limit_quota_header {
            ctx.set(self.quota_key.clone(), quotas);
        }

        Ok(FilterVerdict::Continue)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        if self.config.show_limit_quota_header {
            if let Some(quotas) = ctx.get::<Vec<RateLimitQuota>>(&self.quota_key) {
                for quota in quotas {
                    let headers = build_rate_limit_headers(
                        quota.limit,
                        quota.remaining,
                        quota.reset,
                        quota.current_count,
                        true,
                        &quota.header_prefix,
                        HeaderPath::Success,
                    );
                    for (name, value) in headers {
                        upstream_response.insert_header(name, value)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl PluginRateLimit {
    /// The plugin-level branch, when the oneOf validation guarantees it.
    fn main_selection(&self) -> Option<LimitSelection> {
        let (Some(count), Some(time_window)) = (self.config.count, self.config.time_window) else {
            return None;
        };
        Some(LimitSelection {
            count,
            time_window,
            header_prefix: self.config.header_prefix.clone().unwrap_or_default(),
            from_rule: false,
        })
    }

    /// Resolve the plugin-level key according to `key_type`.
    fn resolve_main_key(&self, session: &mut Session) -> Cow<'static, str> {
        match self.config.key_type {
            KeyType::Var => apisix_key(session, &self.config.key, false),
            KeyType::VarCombination => apisix_key(session, &self.config.key, true),
            KeyType::Constant => Cow::Owned(self.config.key.clone()),
            KeyType::Head => request_selector_key(session, &UpstreamHashOn::HEAD, &self.config.key)
                .into_owned()
                .into(),
            KeyType::Cookie => {
                request_selector_key(session, &UpstreamHashOn::COOKIE, &self.config.key)
                    .into_owned()
                    .into()
            }
        }
    }

    /// Select every matching rule (APISIX enforces all of them), then fall
    /// back to the plugin-level `count`/`time_window` branch. Returns `None`
    /// when the rules branch is configured but no rule applies; the caller
    /// turns that into 500 or `allow_degradation` pass, mirroring APISIX.
    fn select_limits(
        &self,
        session: &mut Session,
    ) -> Option<Vec<(Cow<'static, str>, LimitSelection)>> {
        if !self.config.rules.is_empty() {
            return select_rules(
                session,
                &self.config.rules,
                |rule| rule.key.as_str(),
                |index, rule, key| {
                    (
                        key,
                        LimitSelection {
                            count: rule.count,
                            time_window: rule.time_window,
                            // APISIX defaults each rule's header prefix to its
                            // 1-based index when `header_prefix` is omitted.
                            header_prefix: rule
                                .header_prefix
                                .clone()
                                .unwrap_or_else(|| (index + 1).to_string()),
                            from_rule: true,
                        },
                    )
                },
            );
        }

        let selection = self.main_selection()?;
        let key = self.resolve_main_key(session);
        Some(vec![(key, selection)])
    }

    /// Prefix a raw counter key with the configured `group` namespace. When a
    /// shared group limiter is used the group already namespaces the whole
    /// store, so the raw key is returned unchanged.
    fn storage_key<'a>(&self, key: &'a str) -> Cow<'a, str> {
        if self.group_state.is_some() {
            return Cow::Borrowed(key);
        }
        match self
            .config
            .group
            .as_deref()
            .filter(|group| !group.is_empty())
        {
            Some(group) => Cow::Owned(format!("{group}|{key}")),
            None => Cow::Borrowed(key),
        }
    }

    /// Handle requests with missing keys based on configured policy
    fn handle_missing_key(&self, _session: &mut Session, ctx: &mut ProxyContext) -> FilterVerdict {
        match self.config.key_missing_policy {
            KeyMissingPolicy::Allow => {
                RATE_LIMIT_REQUESTS
                    .with_label_values(&["allowed", "local"])
                    .inc();
                FilterVerdict::Continue
            }
            KeyMissingPolicy::Deny => {
                RATE_LIMIT_REQUESTS
                    .with_label_values(&["rejected", "local"])
                    .inc();
                FilterVerdict::Reject(rejection(
                    StatusCode::BAD_REQUEST,
                    Some("Missing required key for rate limiting"),
                    &[],
                ))
            }
            KeyMissingPolicy::Default => {
                // Use a default key for all requests with missing keys
                let Some(selection) = self.main_selection() else {
                    return FilterVerdict::Continue;
                };
                let outcome = self.check_rate_limit(&selection, "_default_rate_limit_key");

                if outcome.limited {
                    RATE_LIMIT_REQUESTS
                        .with_label_values(&["rejected", "local"])
                        .inc();
                    self.handle_rate_limit(&selection, outcome.current_count)
                } else {
                    RATE_LIMIT_REQUESTS
                        .with_label_values(&["allowed", "local"])
                        .inc();
                    if self.config.show_limit_quota_header {
                        ctx.set(
                            self.quota_key.clone(),
                            vec![RateLimitQuota {
                                limit: selection.count,
                                remaining: outcome.remaining,
                                reset: selection.time_window,
                                current_count: outcome.current_count,
                                header_prefix: selection.header_prefix.clone(),
                            }],
                        );
                    }
                    FilterVerdict::Continue
                }
            }
        }
    }

    /// Check if the request exceeds the rate limit and return detailed information
    fn check_rate_limit(&self, selection: &LimitSelection, key: &str) -> LimitOutcome {
        let namespaced = self.storage_key(key);
        let current_count = match (self.group_state.as_ref(), self.config.window_type) {
            (Some(group), WindowType::Fixed) => group.observe(
                WindowType::Fixed,
                selection.time_window,
                namespaced.as_ref(),
            ),
            (Some(group), WindowType::Sliding) => group.observe(
                WindowType::Sliding,
                selection.time_window,
                namespaced.as_ref(),
            ),
            (None, WindowType::Fixed) => {
                // Rate::observe requires a sized hash key. Passing &Cow keeps this
                // allocation-free for keys without a group namespace.
                let rate = self
                    .fixed_rates
                    .get(&selection.time_window)
                    .expect("factory pre-registers every configured time window");
                rate.observe(&namespaced, 1)
            }
            (None, WindowType::Sliding) => {
                let now = Instant::now();
                let mut shard = self.sliding.lock(namespaced.as_ref());
                sliding_window_for(&mut shard, namespaced.as_ref(), now)
                    .observe(now, selection.time_window) as isize
            }
        };
        let remaining = (selection.count as isize) - current_count;
        let limited = current_count > selection.count as isize;

        LimitOutcome {
            limited,
            current_count,
            remaining: remaining.max(0),
        }
    }

    /// Build the rejection for a rate-limited request, including detailed
    /// quota headers. The downstream connection is marked for closure
    /// (`close_connection`, applied by the pipeline's single write — the
    /// historical `session.set_keepalive(None)` on 429s).
    fn handle_rate_limit(&self, selection: &LimitSelection, current_count: isize) -> FilterVerdict {
        let headers = build_rate_limit_headers(
            selection.count,
            (selection.count as isize - current_count).max(0),
            selection.time_window,
            current_count,
            self.config.show_limit_quota_header,
            &selection.header_prefix,
            HeaderPath::Rejection,
        );

        FilterVerdict::Reject(
            rejection(
                self.reject.status(),
                self.config.rejected_msg.as_deref(),
                &headers,
            )
            .with_close_connection(),
        )
    }
}

/// Apply the APISIX `header_prefix` to the three quota header names.
///
/// APISIX inserts the prefix before the `RateLimit-` marker: prefix `"1"` on
/// `X-RateLimit-Limit` yields `X-1-RateLimit-Limit`.
fn rate_limit_header_name(prefix: &str, base: &'static str) -> String {
    if prefix.is_empty() {
        base.to_string()
    } else {
        base.replacen("RateLimit-", &format!("{prefix}-RateLimit-"), 1)
    }
}

/// Which response the quota headers are attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderPath {
    /// Successful (proxied) response: only the three quota headers plus the
    /// scope header. RFC 9110 assigns `Retry-After` meaning only on 3xx/503
    /// responses, and APISIX never sends `Used`/`Retry-After` on success.
    Success,
    /// Rate-limit rejection: additionally emits `X-RateLimit-Used` and
    /// `Retry-After` so the client can see how many requests it consumed
    /// and when to retry.
    Rejection,
}

/// Build the rate-limit response headers.
///
/// `X-RateLimit-Scope: local` advertises that this limiter is per-instance/in-memory,
/// so operators know the effective limit scales with replica count.
fn build_rate_limit_headers(
    count: u32,
    remaining: isize,
    time_window: u32,
    current_count: isize,
    show: bool,
    header_prefix: &str,
    path: HeaderPath,
) -> Vec<(String, String)> {
    if !show {
        return Vec::new();
    }

    let mut headers = vec![
        (
            rate_limit_header_name(header_prefix, "X-RateLimit-Limit"),
            count.to_string(),
        ),
        (
            rate_limit_header_name(header_prefix, "X-RateLimit-Remaining"),
            remaining.to_string(),
        ),
        (
            rate_limit_header_name(header_prefix, "X-RateLimit-Reset"),
            time_window.to_string(),
        ),
        ("X-RateLimit-Scope".to_string(), "local".to_string()),
    ];
    if path == HeaderPath::Rejection {
        headers.push((
            rate_limit_header_name(header_prefix, "X-RateLimit-Used"),
            current_count.to_string(),
        ));
        headers.push(("Retry-After".to_string(), time_window.to_string()));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::Entry;

    fn make_plugin(cfg: JsonValue) -> PluginRateLimit {
        let config = PluginConfig::try_from(cfg).unwrap();
        let fixed_rates = build_fixed_rates(&config);
        PluginRateLimit {
            reject: RejectPolicy::new(config.rejected_code, config.rejected_msg.clone()),
            fixed_rates,
            config,
            sliding: BoundedShardMap::new(),
            quota_key: rate_limit_quota_key(99),
            group_state: None,
        }
    }

    #[test]
    fn rate_limit_response_includes_local_scope() {
        for path in [HeaderPath::Success, HeaderPath::Rejection] {
            let headers = build_rate_limit_headers(10, 3, 60, 7, true, "", path);
            let scope = headers
                .iter()
                .find(|(name, _)| name == "X-RateLimit-Scope")
                .map(|(_, value)| value.as_str());
            assert_eq!(scope, Some("local"));
        }
    }

    #[test]
    fn build_rate_limit_headers_respects_show_flag() {
        let headers = build_rate_limit_headers(10, 3, 60, 7, false, "", HeaderPath::Rejection);
        assert!(headers.is_empty());
    }

    #[test]
    fn header_prefix_is_applied_to_quota_headers_only() {
        let headers = build_rate_limit_headers(10, 3, 60, 7, true, "api", HeaderPath::Rejection);
        assert!(headers
            .iter()
            .any(|(name, value)| name == "X-api-RateLimit-Limit" && value == "10"));
        assert!(headers
            .iter()
            .any(|(name, value)| name == "X-api-RateLimit-Used" && value == "7"));
        assert!(headers.iter().any(|(name, _)| name == "Retry-After"));
        assert!(headers.iter().any(|(name, _)| name == "X-RateLimit-Scope"));
        assert!(!headers.iter().any(|(name, _)| name == "X-api-Retry-After"));
    }

    #[test]
    fn success_headers_omit_used_and_retry_after() {
        // RFC 9110 gives `Retry-After` meaning only on 3xx/503 responses,
        // and APISIX sends only Limit/Remaining/Reset on success.
        let headers = build_rate_limit_headers(10, 3, 60, 7, true, "api", HeaderPath::Success);
        let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "X-api-RateLimit-Limit",
                "X-api-RateLimit-Remaining",
                "X-api-RateLimit-Reset",
                "X-RateLimit-Scope",
            ]
        );
    }

    #[test]
    fn rejection_headers_add_used_and_retry_after() {
        let headers = build_rate_limit_headers(10, 0, 60, 11, true, "", HeaderPath::Rejection);
        let value = |base: &str| {
            headers
                .iter()
                .find(|(name, _)| name == base)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value("X-RateLimit-Used"), Some("11"));
        assert_eq!(value("Retry-After"), Some("60"));
    }

    #[test]
    fn config_defaults_match_apisix() {
        let config = PluginConfig::try_from(serde_json::json!({
            "count": 10,
            "time_window": 60
        }))
        .unwrap();
        assert_eq!(config.key, "remote_addr");
        assert_eq!(config.key_type, KeyType::Var);
        assert_eq!(config.window_type, WindowType::Fixed);
        assert_eq!(config.rejected_code, 503);
        assert_eq!(config.policy, Policy::Local);
        assert!(config.show_limit_quota_header);
        assert!(!config.allow_degradation);
    }

    #[test]
    fn config_accepts_rejected_code_200_and_rejects_below() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "count": 1, "time_window": 1, "rejected_code": 200
        }))
        .is_ok());
        assert!(PluginConfig::try_from(serde_json::json!({
            "count": 1, "time_window": 1, "rejected_code": 199
        }))
        .is_err());
    }

    #[test]
    fn config_rejects_empty_rejected_msg() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "count": 1, "time_window": 1, "rejected_msg": ""
        }))
        .is_err());
    }

    #[test]
    fn config_accepts_var_combination_key() {
        let config = PluginConfig::try_from(serde_json::json!({
            "count": 1,
            "time_window": 1,
            "key": "$remote_addr $http_x_user",
            "key_type": "var_combination"
        }))
        .unwrap();
        assert_eq!(config.key_type, KeyType::VarCombination);
        assert_eq!(config.key, "$remote_addr $http_x_user");
    }

    #[test]
    fn config_keeps_legacy_head_key_type() {
        let config = PluginConfig::try_from(serde_json::json!({
            "count": 1,
            "time_window": 1,
            "key": "Host",
            "key_type": "head"
        }))
        .unwrap();
        assert_eq!(config.key_type, KeyType::Head);
    }

    #[test]
    fn config_accepts_valid_header_prefixes() {
        let main = PluginConfig::try_from(serde_json::json!({
            "count": 1,
            "time_window": 1,
            "header_prefix": "X-Foo_1"
        }))
        .unwrap();
        assert_eq!(main.header_prefix.as_deref(), Some("X-Foo_1"));

        let rules = PluginConfig::try_from(serde_json::json!({
            "rules": [
                {"count": 1, "time_window": 1, "key": "$remote_addr", "header_prefix": "ip"}
            ]
        }))
        .unwrap();
        assert_eq!(rules.rules[0].header_prefix.as_deref(), Some("ip"));

        // No prefix configured stays the unprefixed default.
        let bare = PluginConfig::try_from(serde_json::json!({
            "count": 1, "time_window": 1
        }))
        .unwrap();
        assert_eq!(bare.header_prefix, None);
    }

    #[test]
    fn config_rejects_invalid_header_prefixes() {
        // Empty or non-token characters would corrupt the header names the
        // plugin emits, so they fail config validation instead of breaking
        // every rate-limited response.
        for bad in ["", "a b", "a:b", "a.b", "a,b", "caf\u{e9}"] {
            assert!(
                PluginConfig::try_from(serde_json::json!({
                    "count": 1, "time_window": 1, "header_prefix": bad
                }))
                .is_err(),
                "top-level header_prefix {bad:?} must be rejected"
            );
            assert!(
                PluginConfig::try_from(serde_json::json!({
                    "rules": [
                        {"count": 1, "time_window": 1, "key": "$remote_addr", "header_prefix": bad}
                    ]
                }))
                .is_err(),
                "rule header_prefix {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn main_selection_uses_configured_header_prefix() {
        let plugin = make_plugin(serde_json::json!({
            "count": 1,
            "time_window": 60,
            "header_prefix": "tenant"
        }));
        let selection = plugin.main_selection().unwrap();
        assert_eq!(selection.header_prefix, "tenant");
    }

    #[test]
    fn config_parses_rules_branch() {
        let config = PluginConfig::try_from(serde_json::json!({
            "rules": [
                {"count": 3, "time_window": 10, "key": "$http_x_user"},
                {"count": 20, "time_window": 60, "key": "$remote_addr", "header_prefix": "ip"}
            ]
        }))
        .unwrap();
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].count, 3);
        assert_eq!(config.rules[1].header_prefix.as_deref(), Some("ip"));
        assert!(config.count.is_none());
        assert!(config.time_window.is_none());
    }

    #[test]
    fn config_rejects_both_main_and_rules_branches() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "count": 1,
            "time_window": 1,
            "rules": [{"count": 2, "time_window": 2, "key": "$remote_addr"}]
        }))
        .is_err());
    }

    #[test]
    fn config_rejects_unenforceable_sliding_counts() {
        let ok = PluginConfig::try_from(serde_json::json!({
            "count": 4095,
            "time_window": 1,
            "window_type": "sliding"
        }));
        assert!(ok.is_ok());

        for invalid in [
            serde_json::json!({
                "count": 4096,
                "time_window": 1,
                "window_type": "sliding"
            }),
            serde_json::json!({
                "rules": [{ "count": 5000, "time_window": 1, "key": "$remote_addr" }],
                "window_type": "sliding"
            }),
        ] {
            assert!(PluginConfig::try_from(invalid).is_err());
        }
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

    #[tokio::test]
    async fn rules_select_every_matching_rule_and_skip_unresolved() {
        let plugin = make_plugin(serde_json::json!({
            "rules": [
                {"count": 3, "time_window": 10, "key": "$http_x_user"},
                {"count": 20, "time_window": 60, "key": "$http_x_role"}
            ]
        }));

        let mut session = session_with_header("x-user", "alice").await;
        session
            .req_header_mut()
            .insert_header("x-role", "admin")
            .unwrap();
        let limits = plugin
            .select_limits(&mut session)
            .expect("both rules match");
        assert_eq!(limits.len(), 2);
        assert_eq!(limits[0].1.count, 3);
        assert_eq!(limits[1].1.count, 20);
        assert_eq!(limits[1].1.header_prefix, "2");

        // Absent variable -> APISIX still enforces the rule under the
        // empty-key bucket.
        let mut empty = session_with_header("x-other", "v").await;
        let limits = plugin
            .select_limits(&mut empty)
            .expect("empty-key rules apply");
        assert_eq!(limits.len(), 2);
        assert!(limits.iter().all(|(key, _)| key.is_empty()));

        // Bare rule keys resolve no variables and are skipped, like APISIX.
        let bare = make_plugin(serde_json::json!({
            "rules": [{"count": 3, "time_window": 10, "key": "remote_addr"}]
        }));
        let mut session = session_with_header("host", "example.com").await;
        assert!(bare.select_limits(&mut session).is_none());
    }

    #[test]
    fn config_rejects_group_with_rules_and_duplicate_rule_keys() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "group": "tenant-a",
            "rules": [{ "count": 1, "time_window": 1, "key": "$remote_addr" }]
        }))
        .is_err());

        assert!(PluginConfig::try_from(serde_json::json!({
            "rules": [
                { "count": 1, "time_window": 1, "key": "$remote_addr" },
                { "count": 2, "time_window": 2, "key": "$remote_addr" }
            ]
        }))
        .is_err());
    }

    #[test]
    fn config_rejects_partial_main_branch() {
        assert!(PluginConfig::try_from(serde_json::json!({"count": 1})).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({"time_window": 1})).is_err());
    }

    #[test]
    fn config_rejects_invalid_rules() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "rules": [{"count": 0, "time_window": 10, "key": "$remote_addr"}]
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "rules": [{"count": 2, "time_window": 0, "key": "$remote_addr"}]
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "rules": [{"count": 2, "time_window": 10, "key": ""}]
        }))
        .is_err());
    }

    #[test]
    fn config_tolerates_unknown_fields() {
        // Unknown fields (typos or fields from other APISIX versions) are
        // ignored; only declared fields take effect.
        let config = PluginConfig::try_from(serde_json::json!({
            "count": 10,
            "time_window": 60,
            "typo_field": true
        }))
        .expect("unknown fields are tolerated");
        assert_eq!(config.count, Some(10));
        assert_eq!(config.time_window, Some(60));
    }

    #[test]
    fn config_rejects_non_local_policies() {
        for policy in ["redis", "redis-cluster", "redis-sentinel"] {
            let err = PluginConfig::try_from(serde_json::json!({
                "count": 1,
                "time_window": 1,
                "policy": policy
            }));
            assert!(err.is_err(), "policy {policy} must be rejected");
        }
    }

    #[test]
    fn config_parses_group() {
        let config = PluginConfig::try_from(serde_json::json!({
            "count": 1,
            "time_window": 1,
            "group": "tenant-a"
        }))
        .unwrap();
        assert_eq!(config.group.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn fixed_window_rejects_after_count() {
        let plugin = make_plugin(serde_json::json!({"count": 2, "time_window": 60}));
        let selection = plugin.main_selection().unwrap();

        let first = plugin.check_rate_limit(&selection, "1.2.3.4");
        let second = plugin.check_rate_limit(&selection, "1.2.3.4");
        let third = plugin.check_rate_limit(&selection, "1.2.3.4");
        assert!(!first.limited);
        assert!(!second.limited);
        assert!(third.limited);
        assert_eq!(third.current_count, 3);
        assert_eq!(third.remaining, 0);
    }

    #[test]
    fn sliding_window_rejects_after_count() {
        let plugin = make_plugin(serde_json::json!({
            "count": 2,
            "time_window": 10,
            "window_type": "sliding"
        }));
        let selection = plugin.main_selection().unwrap();

        assert!(!plugin.check_rate_limit(&selection, "1.2.3.4").limited);
        assert!(!plugin.check_rate_limit(&selection, "1.2.3.4").limited);
        let third = plugin.check_rate_limit(&selection, "1.2.3.4");
        assert!(third.limited);
        assert_eq!(third.current_count, 3);
    }

    #[test]
    fn sliding_window_drops_events_older_than_window() {
        let mut shard = Shard::<SlidingWindow>::default();
        let start = Instant::now();

        assert_eq!(
            sliding_window_for(&mut shard, "key", start).observe(start, 10),
            1
        );
        assert_eq!(
            sliding_window_for(&mut shard, "key", start).observe(start, 10),
            2
        );

        let later = start + Duration::from_secs(10);
        assert_eq!(
            sliding_window_for(&mut shard, "key", later).observe(later, 10),
            1
        );
    }

    #[test]
    fn sliding_window_history_is_bounded_per_key() {
        let mut shard = Shard::<SlidingWindow>::default();
        let now = Instant::now();
        for _ in 0..MAX_SLIDING_ENTRIES_PER_KEY + 10 {
            sliding_window_for(&mut shard, "key", now).observe(now, MAX_WINDOW_SECS);
        }
        let Entry::Occupied(window) = shard.entry("key".into()) else {
            panic!("the observed window exists")
        };
        assert_eq!(window.get().events.len(), MAX_SLIDING_ENTRIES_PER_KEY);
    }

    #[test]
    fn group_fixed_window_registered_by_another_instance_is_usable() {
        let first = group_state("cross-instance-window");
        let second = group_state("cross-instance-window");
        // Instance B's factory registers window 120 into the shared map.
        second
            .fixed_rates
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .entry(120)
            .or_insert_with(|| Arc::new(Rate::new(Duration::from_secs(120))));
        // Instance A observing that window takes the read fast path and
        // shares B's counter rather than failing.
        assert_eq!(first.observe(WindowType::Fixed, 120, "1.2.3.4"), 1);
        assert_eq!(second.observe(WindowType::Fixed, 120, "1.2.3.4"), 2);
    }

    #[test]
    fn group_fixed_window_registers_unknown_window_on_first_use() {
        let state = group_state("late-window-registration");
        // A window no factory pre-registered is registered on first observe
        // (double-checked) instead of panicking.
        assert_eq!(state.observe(WindowType::Fixed, 30, "1.2.3.4"), 1);
        assert_eq!(state.observe(WindowType::Fixed, 30, "1.2.3.4"), 2);
        assert!(state
            .fixed_rates
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&30));
    }

    #[test]
    fn group_state_registry_prunes_dead_tombstones() {
        for index in 0..130 {
            drop(group_state(&format!("rotating-{index}")));
        }
        let registry = GROUP_STATES.lock().unwrap();
        assert!(
            registry.len() < 128,
            "dead tombstones must be pruned once the registry reaches 128 entries, got {}",
            registry.len()
        );
    }

    #[test]
    fn group_state_registry_is_shared_while_any_instance_lives() {
        let first = group_state("tenant-a");
        let second = group_state("tenant-a");
        assert!(Arc::ptr_eq(&first, &second));

        // The shared limiter observes both plugin instances' requests.
        first
            .fixed_rates
            .write()
            .unwrap()
            .entry(60)
            .or_insert_with(|| Arc::new(Rate::new(Duration::from_secs(60))));
        assert_eq!(first.observe(WindowType::Fixed, 60, "1.2.3.4"), 1);
        assert_eq!(second.observe(WindowType::Fixed, 60, "1.2.3.4"), 2);

        // Retiring one instance keeps the shared limiter alive.
        drop(first);
        let still = group_state("tenant-a");
        assert!(Arc::ptr_eq(&second, &still));

        // Once every instance retires the registry entry can be rebuilt.
        drop(second);
        drop(still);
        let fresh = group_state("tenant-a");
        assert!(!Arc::ptr_eq(&fresh, &group_state("tenant-b")));
    }

    #[test]
    fn group_namespaces_isolate_local_counters() {
        let first = make_plugin(serde_json::json!({
            "count": 1,
            "time_window": 60,
            "group": "first"
        }));
        let second = make_plugin(serde_json::json!({
            "count": 1,
            "time_window": 60,
            "group": "second"
        }));
        let first_selection = first.main_selection().unwrap();
        let second_selection = second.main_selection().unwrap();

        assert!(!first.check_rate_limit(&first_selection, "1.2.3.4").limited);
        assert!(first.check_rate_limit(&first_selection, "1.2.3.4").limited);
        // A different group sees an independent counter for the same raw key.
        assert!(
            !second
                .check_rate_limit(&second_selection, "1.2.3.4")
                .limited
        );
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

    const CANNED_REQUEST: &str = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    /// Same request keyed by a header so two sessions share one limiter key
    /// (duplex sessions have no client address, so `remote_addr` resolves
    /// empty and would take the missing-key policy instead).
    const KEYED_REQUEST: &str = "GET / HTTP/1.1\r\nHost: example.com\r\nx-user: alice\r\n\r\n";

    #[tokio::test]
    async fn group_shares_counters_across_plugin_instances() {
        let first = create_limit_count_plugin(
            serde_json::json!({
                "count": 1,
                "time_window": 60,
                "key": "http_x_user",
                "group": "shared-group-test"
            }),
            &crate::config::EffectiveDefaults::default(),
        )
        .unwrap();
        let second = create_limit_count_plugin(
            serde_json::json!({
                "count": 1,
                "time_window": 60,
                "key": "http_x_user",
                "group": "shared-group-test"
            }),
            &crate::config::EffectiveDefaults::default(),
        )
        .unwrap();

        // One request through instance A ...
        let (mut first_session, _first_server) = session_with_raw_request(KEYED_REQUEST).await;
        let mut first_ctx = ProxyContext::default();
        assert!(!crate::utils::testing::run_request_filter(
            first.as_ref(),
            &mut first_session,
            &mut first_ctx
        )
        .await
        .unwrap());

        // ... and the next request through instance B is limited: the group
        // shares one counter across instances.
        let (mut second_session, mut second_server) = session_with_raw_request(KEYED_REQUEST).await;
        let mut second_ctx = ProxyContext::default();
        assert!(crate::utils::testing::run_request_filter(
            second.as_ref(),
            &mut second_session,
            &mut second_ctx
        )
        .await
        .unwrap());
        drop(second_session);
        let response = drain_response(&mut second_server).await;
        assert!(
            response.starts_with("HTTP/1.1 503 "),
            "expected group-limited 503, got: {response}"
        );
    }

    #[tokio::test]
    async fn rules_no_match_yields_500_and_degradation_passes() {
        // A rule whose key contains no variables never matches, so the
        // rules branch selects no limit at all.
        let strict = make_plugin(serde_json::json!({
            "rules": [{"count": 1, "time_window": 60, "key": "remote_addr"}]
        }));
        let (mut session, mut server) = session_with_raw_request(CANNED_REQUEST).await;
        let mut ctx = ProxyContext::default();
        assert!(
            crate::utils::testing::run_request_filter(&strict, &mut session, &mut ctx)
                .await
                .unwrap()
        );
        drop(session);
        let response = drain_response(&mut server).await;
        assert!(
            response.starts_with("HTTP/1.1 500 "),
            "expected rules-no-match 500, got: {response}"
        );
        assert!(response.contains("failed to get rate limit rules"));

        // allow_degradation explicitly permits the request instead.
        let tolerant = make_plugin(serde_json::json!({
            "rules": [{"count": 1, "time_window": 60, "key": "remote_addr"}],
            "allow_degradation": true
        }));
        let (mut session, _server) = session_with_raw_request(CANNED_REQUEST).await;
        let mut ctx = ProxyContext::default();
        assert!(
            !crate::utils::testing::run_request_filter(&tolerant, &mut session, &mut ctx)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn limited_response_carries_prefixed_rate_limit_headers() {
        let plugin = make_plugin(serde_json::json!({
            "count": 1,
            "time_window": 60,
            "key": "http_x_user",
            "header_prefix": "api",
            "rejected_code": 429
        }));

        // First request passes and consumes the single allowed request.
        let (mut first, _first_server) = session_with_raw_request(KEYED_REQUEST).await;
        let mut first_ctx = ProxyContext::default();
        assert!(
            !crate::utils::testing::run_request_filter(&plugin, &mut first, &mut first_ctx)
                .await
                .unwrap()
        );

        // The second is limited with the configured code and the prefixed
        // rate-limit headers on the rejection.
        let (mut second, mut second_server) = session_with_raw_request(KEYED_REQUEST).await;
        let mut second_ctx = ProxyContext::default();
        assert!(
            crate::utils::testing::run_request_filter(&plugin, &mut second, &mut second_ctx)
                .await
                .unwrap()
        );
        drop(second);
        let response = drain_response(&mut second_server).await;
        assert!(
            response.starts_with("HTTP/1.1 429 "),
            "expected the configured rejected_code, got: {response}"
        );
        for header in [
            "X-api-RateLimit-Limit: 1",
            "X-api-RateLimit-Remaining: 0",
            "X-api-RateLimit-Reset: 60",
            "X-api-RateLimit-Used: 2",
            "Retry-After: 60",
            "X-RateLimit-Scope: local",
        ] {
            assert!(
                response.contains(header),
                "missing header {header:?} in: {response}"
            );
        }
    }

    #[tokio::test]
    async fn success_response_omits_used_and_retry_after() {
        let plugin = make_plugin(serde_json::json!({
            "count": 5,
            "time_window": 60,
            "key": "http_x_user",
            "header_prefix": "api"
        }));
        let (mut session, _server) = session_with_raw_request(KEYED_REQUEST).await;
        let mut ctx = ProxyContext::default();
        assert!(
            !crate::utils::testing::run_request_filter(&plugin, &mut session, &mut ctx)
                .await
                .unwrap()
        );

        let mut upstream_response =
            pingora_http::ResponseHeader::build(StatusCode::OK, None).unwrap();
        plugin
            .response_filter(&mut session, &mut upstream_response, &mut ctx)
            .await
            .unwrap();

        let header = |name: &str| {
            upstream_response
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
        };
        assert_eq!(header("X-api-RateLimit-Limit"), Some("5"));
        assert_eq!(header("X-api-RateLimit-Remaining"), Some("4"));
        assert_eq!(header("X-api-RateLimit-Reset"), Some("60"));
        assert_eq!(header("X-RateLimit-Scope"), Some("local"));
        // Successful proxied responses carry no `Retry-After` (RFC 9110
        // assigns it meaning only on 3xx/503) and no `Used` header.
        assert_eq!(header("Retry-After"), None);
        assert_eq!(header("X-api-RateLimit-Used"), None);
        assert_eq!(header("X-RateLimit-Used"), None);
    }
}
