use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ::http::{HeaderName, Method};
use async_trait::async_trait;
use pingora_error::Result;
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::{
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::config::parse_and_validate_plugin_config,
};

pub(crate) mod http;

pub const PLUGIN_NAME: &str = "proxy-cache";
const PRIORITY: i32 = 1085;

/// 1MB fallback used when a cache plugin inherits instance defaults.
#[cfg(test)]
const FALLBACK_MAX_OBJECT_BYTES: usize = 1024 * 1024;

/// Resolves the final `max_file_size_bytes` a cache plugin would embed for `cfg`.
pub fn resolved_max_file_size_bytes(cfg: JsonValue, default_max: usize) -> ProxyResult<usize> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(resolve_max_file_size(
        effective_max_file_size_bytes(&config),
        default_max,
    ))
}

/// The APISIX alias `max_resp_body_size` maps to pingsix's
/// `max_file_size_bytes` only when it is explicitly present and the pingsix
/// field is not. The APISIX default (64 MiB) is parsed for schema visibility,
/// but it is not applied implicitly so existing pingsix configs keep inheriting
/// the instance's `default_max_object_bytes` (1 MiB by default).
fn effective_max_file_size_bytes(config: &PluginConfig) -> Option<usize> {
    if config.max_file_size_bytes.is_some() {
        config.max_file_size_bytes
    } else if config.max_resp_body_size_explicit {
        config.max_resp_body_size
    } else {
        None
    }
}

/// Resolves the final `max_file_size_bytes` for `CacheSettings`.
/// `None` (unconfigured) -> use the instance default; `Some(0)` -> 0 (unlimited);
/// `Some(n)` -> n.
fn resolve_max_file_size(configured: Option<usize>, global_default: usize) -> usize {
    configured.unwrap_or(global_default)
}

// Context key for sharing cache settings between plugin and HttpService
pub const CTX_KEY_CACHE_SETTINGS: &str = "pingsix_cache_settings";

/// Uniquely names each proxy-cache instance's per-request no-cache decision.
static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

/// Lightweight cache configuration passed to HttpService.
///
/// This serves as a communication contract between the cache plugin and the HTTP service,
/// containing only the essential information needed for caching decisions during request processing.
#[derive(Clone)]
pub struct CacheSettings {
    pub ttl: Duration,
    pub statuses: Arc<HashSet<u16>>,
    /// Lowercase, trimmed Vary header names from config, pre-normalized at plugin creation.
    pub vary: Arc<Vec<String>>,
    pub hide_cache_headers: bool,
    /// Whether `PURGE` requests are wired to remove matching cache entries.
    pub enable_purge: bool,
    pub max_file_size_bytes: usize,
    /// Enable Stale-While-Revalidate: serve stale content while fetching fresh content in background
    pub stale_while_revalidate: Option<Duration>,
    /// Enable s-maxage support: respect Cache-Control s-maxage directive for shared caches
    pub respect_s_maxage: bool,
    /// Cache authenticated or cookie-bearing requests. Disabled by default because a shared
    /// cache must not reuse user-specific responses without an explicit cache key strategy.
    pub cache_authenticated_requests: bool,
    /// Cache responses that set cookies. Disabled independently because replaying Set-Cookie from
    /// a shared cache can leak or overwrite sessions even for otherwise anonymous requests.
    pub cache_set_cookie_responses: bool,
    /// APISIX `cache_key` templates. `None` keeps pingsix's
    /// `METHOD host uri` key; `Some(templates)` renders each template and
    /// joins the results with a newline.
    pub cache_key: Option<Arc<Vec<String>>>,
    /// APISIX `cache_bypass` templates. Any request whose rendered template
    /// is non-empty and not `"0"` skips cache lookup for that request
    /// (existing entries are not consulted).
    pub cache_bypass: Arc<Vec<String>>,
    /// APISIX `no_cache` templates. Any request whose rendered template is
    /// non-empty and not `"0"` suppresses STORING the response; existing
    /// entries are still eligible for a cache hit (response-side semantics).
    pub no_cache: Arc<Vec<String>>,
    /// Per-instance context key storing this request's `no_cache` decision
    /// for the response-side store check.
    pub no_cache_flag_key: String,
    /// APISIX `cache_control` (see [`PluginConfig::cache_control`]): `None`
    /// keeps pingsix legacy behavior, `Some(false)` pins storage freshness to
    /// `ttl` and disables the request-side `no-cache` bypass.
    pub cache_control: Option<bool>,
    /// Add a digest of Authorization/Cookie headers to the cache key when
    /// authenticated requests are cached.
    pub consumer_isolation: bool,
    /// Fingerprint of the effective cache policy for cache-key namespacing.
    pub policy_fingerprint: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PluginConfig {
    /// Response TTL in seconds. APISIX `cache_ttl` overrides this value when
    /// both are present; the APISIX default (300) applies when neither is set.
    #[serde(default = "PluginConfig::default_ttl")]
    #[validate(range(min = 1))]
    pub ttl: u64,

    /// APISIX alias for `ttl`. When present it replaces the effective TTL.
    #[serde(default)]
    pub cache_ttl: Option<u64>,

    #[serde(default = "PluginConfig::default_cache_http_methods")]
    #[validate(custom(function = "validate_methods"))]
    pub cache_http_methods: Vec<String>,

    /// APISIX alias for `cache_http_methods`. When present it replaces the
    /// pingsix field (APISIX restricts entries to GET/POST/HEAD).
    #[serde(default)]
    pub cache_method: Option<Vec<String>>,

    #[serde(default = "PluginConfig::default_cache_http_statuses")]
    #[validate(custom(function = "validate_statuses"))]
    pub cache_http_statuses: Vec<u16>,

    /// APISIX alias for `cache_http_statuses`. When present it replaces the
    /// pingsix field; the pingsix default `[200]` is kept when neither is set.
    #[serde(default)]
    pub cache_http_status: Option<Vec<u16>>,

    #[serde(default)]
    #[validate(custom(function = "validate_regexes"))]
    pub no_cache_str: Vec<String>,

    /// APISIX alias for `no_cache_str`. When present it does NOT replace the
    /// pingsix field: entries are APISIX variable templates evaluated per
    /// request, and a non-empty rendered value other than `"0"` skips caching.
    #[serde(default)]
    pub no_cache: Option<Vec<String>>,

    #[serde(default)]
    #[validate(custom(function = "validate_vary_headers"))]
    pub vary: Vec<String>,

    /// APISIX `cache_strategy`. Absent (APISIX's implicit `disk` default) is
    /// treated as the local memory backend; explicit `disk` is rejected.
    #[serde(default)]
    pub cache_strategy: Option<CacheStrategy>,

    /// APISIX `cache_key` templates. Rendered per request and joined with
    /// newlines; `None` keeps pingsix's `METHOD host uri` key (the preserved
    /// pingsix default — set the field explicitly for APISIX semantics).
    #[serde(default)]
    pub cache_key: Option<Vec<String>>,

    /// APISIX `cache_bypass` templates. If any rendered template is non-empty
    /// the request bypasses the cache.
    #[serde(default)]
    pub cache_bypass: Option<Vec<String>>,

    #[serde(default)]
    pub hide_cache_headers: bool,

    /// APISIX `cache_control`. `Some(true)`: honor request-side
    /// `Cache-Control` (`no-cache`/`no-store` bypass) and let origin freshness
    /// (`max-age`/`s-maxage`) override `ttl`. `Some(false)`: the configured
    /// `ttl` governs storage freshness and request `Cache-Control` does not
    /// bypass. Absent: pingsix legacy behavior (request `no-cache` bypasses;
    /// origin freshness honored per `respect_s_maxage`). Origin
    /// `private`/`no-store`/`no-cache` always reject storage regardless of
    /// this flag.
    #[serde(default)]
    pub cache_control: Option<bool>,

    /// Add a credential-derived digest to the cache key when authenticated
    /// requests are cached. APISIX default: true.
    #[serde(default = "PluginConfig::default_consumer_isolation")]
    pub consumer_isolation: bool,

    /// APISIX alias for `cache_set_cookie_responses`: when true, responses
    /// containing Set-Cookie may enter the shared cache. The pingsix field
    /// still works independently; the two are OR-ed together.
    #[serde(default)]
    pub cache_set_cookie: bool,

    /// Accept `PURGE` requests that delete the matching cache entry.
    ///
    /// Defaults to `false`: in a shared/edge deployment an unauthenticated
    /// `PURGE` would let any client force cache misses (stampede DoS). This is
    /// an opt-in for deployments that front PURGE with their own auth/ACL layer.
    #[serde(default)]
    pub enable_purge: bool,

    /// Cache entries, locks and SWR state are local to this process.
    #[serde(default)]
    pub scope: Scope,

    /// Maximum cacheable response size in bytes.
    /// `None` (default) inherits the instance's `default_max_object_bytes`
    /// (`pingsix.defaults.cache.default_max_object_bytes`, 1MB by default).
    /// `Some(0)` means no limit. `Some(n)` enforces an explicit byte limit.
    #[serde(default)]
    pub max_file_size_bytes: Option<usize>,

    /// APISIX alias for `max_file_size_bytes`. Parsed with APISIX's default
    /// (64 MiB) for schema visibility; the alias is mapped to
    /// `max_file_size_bytes` only when it is explicitly present and the
    /// pingsix field is not, so `Some(0)` keeps its pingsix meaning (no limit)
    /// and omitted configs keep inheriting the instance default.
    #[serde(default = "PluginConfig::default_max_resp_body_size")]
    pub max_resp_body_size: Option<usize>,

    /// Whether `max_resp_body_size` appeared in the input JSON. Serde cannot
    /// distinguish an applied default from an explicit value otherwise.
    #[serde(skip)]
    pub max_resp_body_size_explicit: bool,

    /// Stale-While-Revalidate duration in seconds.
    /// When set, stale cached responses can be served while a background revalidation occurs.
    /// This improves performance by reducing wait times for fresh content.
    #[serde(default)]
    pub stale_while_revalidate_secs: Option<u64>,

    /// Respect Cache-Control s-maxage directive for shared caches.
    /// When enabled, s-maxage overrides the configured TTL for shared cache scenarios.
    /// Default: true (recommended for CDN/proxy scenarios)
    #[serde(default = "PluginConfig::default_respect_s_maxage")]
    pub respect_s_maxage: bool,

    /// Allow shared caching for requests that include Authorization or Cookie headers.
    /// Defaults to false to prevent accidental cross-user response reuse.
    #[serde(default)]
    pub cache_authenticated_requests: bool,

    /// Allow responses containing Set-Cookie to enter the shared cache.
    /// This is a separate, high-risk opt-in and defaults to false.
    #[serde(default)]
    pub cache_set_cookie_responses: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    #[default]
    Local,
    Cluster,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CacheStrategy {
    Disk,
    Memory,
}

impl PluginConfig {
    fn default_ttl() -> u64 {
        300
    }
    fn default_cache_http_methods() -> Vec<String> {
        vec!["GET".to_string(), "HEAD".to_string()]
    }
    fn default_cache_http_statuses() -> Vec<u16> {
        vec![200]
    }
    fn default_consumer_isolation() -> bool {
        true
    }
    fn default_max_resp_body_size() -> Option<usize> {
        // APISIX default: 64 MiB.
        Some(64 * 1024 * 1024)
    }
    fn default_respect_s_maxage() -> bool {
        true
    }
}

fn validate_methods(methods: &[String]) -> Result<(), ValidationError> {
    for m in methods {
        if m.parse::<Method>().is_err() {
            return Err(ValidationError::new("invalid_http_method"));
        }
    }
    Ok(())
}

fn validate_statuses(statuses: &[u16]) -> Result<(), ValidationError> {
    for &status in statuses {
        if !(100..=599).contains(&status) {
            return Err(ValidationError::new("invalid_http_status"));
        }
    }
    Ok(())
}

fn validate_regexes(patterns: &[String]) -> Result<(), ValidationError> {
    for pattern in patterns {
        if Regex::new(pattern).is_err() {
            return Err(ValidationError::new("invalid_regex_pattern"));
        }
    }
    Ok(())
}

fn validate_vary_headers(headers: &[String]) -> Result<(), ValidationError> {
    for header in headers {
        let header = header.trim();
        if header == "*" || header.parse::<HeaderName>().is_err() {
            return Err(ValidationError::new("invalid_vary_header"));
        }
    }
    Ok(())
}

fn validate_apisix_methods(methods: &[String]) -> Result<(), ValidationError> {
    if methods.is_empty() {
        return Err(ValidationError::new(
            "cache_method must have at least 1 item",
        ));
    }
    let mut seen = HashSet::new();
    for method in methods {
        if !matches!(method.as_str(), "GET" | "POST" | "HEAD") {
            return Err(ValidationError::new(
                "cache_method entries must be GET, POST or HEAD",
            ));
        }
        if !seen.insert(method.as_str()) {
            return Err(ValidationError::new("cache_method entries must be unique"));
        }
    }
    Ok(())
}

fn validate_apisix_statuses(statuses: &[u16]) -> Result<(), ValidationError> {
    if statuses.is_empty() {
        return Err(ValidationError::new(
            "cache_http_status must have at least 1 item",
        ));
    }
    let mut seen = HashSet::new();
    for &status in statuses {
        if !(200..=599).contains(&status) {
            return Err(ValidationError::new(
                "cache_http_status entries must be between 200 and 599",
            ));
        }
        if !seen.insert(status) {
            return Err(ValidationError::new(
                "cache_http_status entries must be unique",
            ));
        }
    }
    Ok(())
}

fn validate_optional_templates(templates: Option<&[String]>) -> Result<(), ValidationError> {
    if let Some(templates) = templates {
        if templates.is_empty() {
            return Err(ValidationError::new(
                "template list must have at least 1 item",
            ));
        }
    }
    Ok(())
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let max_resp_body_size_explicit = value.get("max_resp_body_size").is_some();
        let mut config: PluginConfig =
            parse_and_validate_plugin_config(value, "Failed to parse cache plugin config")?;
        config.max_resp_body_size_explicit = max_resp_body_size_explicit;

        if let Some(ttl) = config.cache_ttl {
            if ttl < 1 {
                return Err(ValidationError::new("cache_ttl must be at least 1").into());
            }
        }
        if let Some(methods) = config.cache_method.as_deref() {
            validate_apisix_methods(methods)?;
        }
        if let Some(statuses) = config.cache_http_status.as_deref() {
            validate_apisix_statuses(statuses)?;
        }
        validate_optional_templates(config.cache_key.as_deref())?;
        validate_optional_templates(config.cache_bypass.as_deref())?;
        validate_optional_templates(config.no_cache.as_deref())?;
        // APISIX check_schema rejects `$request_method` in cache_key: the
        // method is not part of the cache identity (and would break the
        // PURGE→GET key alias).
        if config
            .cache_key
            .as_ref()
            .is_some_and(|templates| templates.iter().any(|t| t == "$request_method"))
        {
            return Err(ProxyError::validation_error(
                "cache_key variable $request_method unsupported",
            ));
        }
        if let Some(size) = config.max_resp_body_size {
            if size < 1 {
                return Err(ValidationError::new("max_resp_body_size must be at least 1").into());
            }
        }
        if config.cache_strategy == Some(CacheStrategy::Disk) {
            return Err(ProxyError::validation_error(
                "cache_strategy 'disk' requires a disk cache zone, only 'memory' is supported",
            ));
        }
        if config.scope == Scope::Cluster {
            return Err(ProxyError::validation_error(
                "cache scope 'cluster' requires a distributed backend",
            ));
        }

        // Apply APISIX aliases. Aliases win over the pingsix fields when both
        // are present; `cache_set_cookie` ORs into its pingsix counterpart.
        if let Some(ttl) = config.cache_ttl {
            config.ttl = ttl;
        }
        if let Some(methods) = config.cache_method.take() {
            config.cache_http_methods = methods;
        }
        if let Some(statuses) = config.cache_http_status.take() {
            config.cache_http_statuses = statuses;
        }
        if config.cache_set_cookie {
            config.cache_set_cookie_responses = true;
        }

        Ok(config)
    }
}

pub struct PluginCache {
    methods: HashSet<Method>,
    no_cache_regex: Vec<Regex>,
    // Pre-compiled shared settings to avoid recreation on each request
    cache_settings: Arc<CacheSettings>,
}

pub fn create_cache_plugin(
    cfg: JsonValue,
    defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;

    if config.cache_strategy == Some(CacheStrategy::Memory) {
        log::debug!("proxy-cache: explicit cache_strategy 'memory' maps to scope Local");
    }

    let methods = config
        .cache_http_methods
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let statuses = Arc::new(config.cache_http_statuses.iter().cloned().collect());
    let no_cache_regex = config
        .no_cache_str
        .iter()
        .map(|s| {
            Regex::new(s).map_err(|e| -> Box<pingora_error::Error> {
                ProxyError::validation_error(format!("Invalid regex in no_cache_str '{s}': {e}"))
                    .into()
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut vary: Vec<String> = config
        .vary
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    vary.sort_unstable();
    vary.dedup();
    let vary = Arc::new(vary);

    // Resolve the final max object size: None inherits the instance's
    // effective default, Some(0) means unlimited, Some(n) is an explicit limit.
    let max_file_size_bytes = resolve_max_file_size(
        effective_max_file_size_bytes(&config),
        defaults.cache.default_max_object_bytes,
    );

    let policy_fingerprint = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        config.ttl.hash(&mut hasher);
        max_file_size_bytes.hash(&mut hasher);
        config.hide_cache_headers.hash(&mut hasher);
        config.respect_s_maxage.hash(&mut hasher);
        config.cache_authenticated_requests.hash(&mut hasher);
        config.cache_set_cookie_responses.hash(&mut hasher);
        config.cache_control.hash(&mut hasher);
        config.consumer_isolation.hash(&mut hasher);
        config.stale_while_revalidate_secs.hash(&mut hasher);
        config.cache_key.hash(&mut hasher);
        config.cache_bypass.hash(&mut hasher);
        config.no_cache.hash(&mut hasher);
        let mut statuses: Vec<_> = config.cache_http_statuses.clone();
        statuses.sort_unstable();
        statuses.dedup();
        for status in statuses {
            status.hash(&mut hasher);
        }
        for h in vary.iter() {
            h.hash(&mut hasher);
        }
        hasher.finish()
    };

    // Pre-build cache settings at plugin creation to avoid per-request overhead
    let no_cache_flag_key = format!(
        "pingsix_proxy_cache_no_cache_{}",
        NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed)
    );
    let cache_settings = Arc::new(CacheSettings {
        ttl: Duration::from_secs(config.ttl),
        statuses,
        vary,
        hide_cache_headers: config.hide_cache_headers,
        enable_purge: config.enable_purge,
        max_file_size_bytes,
        stale_while_revalidate: config.stale_while_revalidate_secs.map(Duration::from_secs),
        respect_s_maxage: config.respect_s_maxage,
        cache_authenticated_requests: config.cache_authenticated_requests,
        cache_set_cookie_responses: config.cache_set_cookie_responses,
        cache_key: config.cache_key.clone().map(Arc::new),
        cache_bypass: Arc::new(config.cache_bypass.clone().unwrap_or_default()),
        no_cache: Arc::new(config.no_cache.clone().unwrap_or_default()),
        no_cache_flag_key,
        cache_control: config.cache_control,
        consumer_isolation: config.consumer_isolation,
        policy_fingerprint,
    });

    Ok(Arc::new(PluginCache {
        methods,
        no_cache_regex,
        cache_settings,
    }))
}

pub(crate) fn should_bypass_authenticated_request(
    settings: &CacheSettings,
    ctx: &ProxyContext,
) -> bool {
    !settings.cache_authenticated_requests
        && (ctx.original_request_had_credentials || ctx.request_has_credentials)
}

#[cfg(test)]
fn should_bypass_set_cookie_response(settings: &CacheSettings, has_set_cookie: bool) -> bool {
    has_set_cookie && !settings.cache_set_cookie_responses
}

#[async_trait]
impl ProxyPlugin for PluginCache {
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
        let method = &session.req_header().method;
        let path = session.req_header().uri.path();

        // 1. PURGE requests must enable the cache too: `is_purge` needs the
        //    cache enabled with a matching key to delete the entry (Guide L46).
        //    PURGE is opt-in (`enable_purge`) because it is unauthenticated:
        //    with it disabled a PURGE is proxied like any other method.
        if method.as_str() == "PURGE" && self.cache_settings.enable_purge {
            ctx.set(self.cache_settings.no_cache_flag_key.clone(), false);
            ctx.set(CTX_KEY_CACHE_SETTINGS, self.cache_settings.clone());
            log::trace!("Cache enabled for PURGE {path}");
            return Ok(FilterVerdict::Continue);
        }

        // 2. Check if method is cacheable
        if !self.methods.contains(method) {
            log::trace!("Method {method} not cacheable, skipping cache");
            return Ok(FilterVerdict::Continue);
        }

        // 3. APISIX cache_bypass: any template that renders non-empty and not
        //    "0" disables cache lookup for this request.
        if !self.cache_settings.cache_bypass.is_empty()
            && http::cache_bypass_requested(&self.cache_settings.cache_bypass, session.req_header())
        {
            log::trace!("Cache bypass requested via cache_bypass template");
            return Ok(FilterVerdict::Continue);
        }

        // 4. APISIX no_cache: any template that renders non-empty and not
        //    "0" suppresses storing this response, but existing entries are
        //    still eligible for a cache hit (APISIX response-side semantics).
        let no_cache = !self.cache_settings.no_cache.is_empty()
            && http::no_cache_requested(&self.cache_settings.no_cache, session.req_header());
        ctx.set(self.cache_settings.no_cache_flag_key.clone(), no_cache);
        if no_cache {
            log::trace!("Cache store disabled via no_cache template");
        }

        // 5. Shared caching of authenticated or cookie-bearing requests is opt-in.
        if should_bypass_authenticated_request(&self.cache_settings, ctx) {
            log::trace!("Request contains credentials, skipping shared cache");
            return Ok(FilterVerdict::Continue);
        }

        // 6. Check if URI matches a no-cache pattern
        for re in &self.no_cache_regex {
            if re.is_match(path) {
                log::trace!("Path {path} matches no-cache pattern, skipping cache");
                return Ok(FilterVerdict::Continue);
            }
        }

        // 7. All checks passed. Put the lightweight CacheSettings into context.
        ctx.set(CTX_KEY_CACHE_SETTINGS, self.cache_settings.clone());
        log::trace!("Cache enabled for {method} {path}");

        Ok(FilterVerdict::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::cache::http::response_cacheability;
    use pingora_cache::{NoCacheReason, RespCacheable};

    fn settings_from_json_with_default(
        value: serde_json::Value,
        global_default: usize,
    ) -> CacheSettings {
        let config = PluginConfig::try_from(value).unwrap();
        CacheSettings {
            ttl: Duration::from_secs(config.ttl),
            statuses: Arc::new(config.cache_http_statuses.iter().cloned().collect()),
            vary: Arc::new(vec![]),
            hide_cache_headers: config.hide_cache_headers,
            enable_purge: config.enable_purge,
            max_file_size_bytes: resolve_max_file_size(
                effective_max_file_size_bytes(&config),
                global_default,
            ),
            stale_while_revalidate: config.stale_while_revalidate_secs.map(Duration::from_secs),
            respect_s_maxage: config.respect_s_maxage,
            cache_authenticated_requests: config.cache_authenticated_requests,
            cache_set_cookie_responses: config.cache_set_cookie_responses,
            cache_key: config.cache_key.clone().map(Arc::new),
            cache_bypass: Arc::new(config.cache_bypass.clone().unwrap_or_default()),
            no_cache: Arc::new(config.no_cache.clone().unwrap_or_default()),
            no_cache_flag_key: "test-no-cache-flag".to_string(),
            cache_control: config.cache_control,
            consumer_isolation: config.consumer_isolation,
            policy_fingerprint: 0,
        }
    }

    fn settings_from_json(value: serde_json::Value) -> CacheSettings {
        settings_from_json_with_default(value, FALLBACK_MAX_OBJECT_BYTES)
    }

    #[test]
    fn purge_uses_get_cache_key_method() {
        assert_eq!(http::cache_key_method("PURGE"), "GET");
        assert_eq!(http::cache_key_method("HEAD"), "HEAD");
    }

    #[test]
    fn purge_is_disabled_by_default() {
        let config = PluginConfig::try_from(serde_json::json!({ "ttl": 60 })).unwrap();
        assert!(!config.enable_purge);
        let settings = settings_from_json(serde_json::json!({ "ttl": 60 }));
        assert!(!settings.enable_purge);
    }

    #[test]
    fn purge_can_be_opted_in() {
        let config = PluginConfig::try_from(serde_json::json!({
            "ttl": 60,
            "enable_purge": true
        }))
        .unwrap();
        assert!(config.enable_purge);
        let settings = settings_from_json(serde_json::json!({
            "ttl": 60,
            "enable_purge": true
        }));
        assert!(settings.enable_purge);
    }

    #[test]
    fn purge_policy_requires_opt_in() {
        let disabled = Arc::new(settings_from_json(serde_json::json!({ "ttl": 60 })));
        let enabled = Arc::new(settings_from_json(serde_json::json!({
            "ttl": 60,
            "enable_purge": true
        })));
        assert!(http::should_enable_purge(Some(&enabled)));
        assert!(!http::should_enable_purge(Some(&disabled)));
        assert!(!http::should_enable_purge(None));
    }

    #[test]
    fn vary_rejects_wildcard_and_invalid_header_names() {
        assert!(PluginConfig::try_from(serde_json::json!({ "ttl": 1, "vary": ["*"] })).is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({ "ttl": 1, "vary": ["bad header"] }))
                .is_err()
        );
    }

    #[test]
    fn authenticated_requests_are_not_cacheable_by_default() {
        let config = PluginConfig::try_from(serde_json::json!({ "ttl": 60 })).unwrap();

        assert!(!config.cache_authenticated_requests);
    }

    #[test]
    fn authenticated_request_caching_requires_explicit_opt_in() {
        let config = PluginConfig::try_from(serde_json::json!({
            "ttl": 60,
            "cache_authenticated_requests": true
        }))
        .unwrap();

        assert!(config.cache_authenticated_requests);
        assert!(!config.cache_set_cookie_responses);
    }

    #[test]
    fn set_cookie_response_caching_requires_separate_opt_in() {
        let config = PluginConfig::try_from(serde_json::json!({
            "ttl": 60,
            "cache_authenticated_requests": true,
            "cache_set_cookie_responses": true
        }))
        .unwrap();

        assert!(config.cache_set_cookie_responses);
    }

    #[test]
    fn credential_flags_bypass_shared_cache_by_default() {
        let settings = settings_from_json(serde_json::json!({ "ttl": 60 }));

        let from_headers = ProxyContext {
            original_request_had_credentials: true,
            ..Default::default()
        };
        assert!(should_bypass_authenticated_request(
            &settings,
            &from_headers
        ));

        let mut from_plugin = ProxyContext::default();
        from_plugin.mark_request_has_credentials();
        assert!(should_bypass_authenticated_request(&settings, &from_plugin));

        let opt_in = settings_from_json(serde_json::json!({
            "ttl": 60,
            "cache_authenticated_requests": true
        }));
        assert!(!should_bypass_authenticated_request(&opt_in, &from_plugin));
    }

    #[test]
    fn late_auth_mark_still_bypasses_when_checked_at_enable_time() {
        // Simulates global cache setting CacheSettings before route key-auth marks credentials.
        let settings = settings_from_json(serde_json::json!({ "ttl": 60 }));
        let mut ctx = ProxyContext::default();
        assert!(!should_bypass_authenticated_request(&settings, &ctx));
        ctx.mark_request_has_credentials();
        assert!(should_bypass_authenticated_request(&settings, &ctx));
    }

    #[test]
    fn set_cookie_responses_bypass_unless_explicitly_enabled() {
        let defaults = settings_from_json(serde_json::json!({ "ttl": 60 }));
        assert!(should_bypass_set_cookie_response(&defaults, true));
        assert!(!should_bypass_set_cookie_response(&defaults, false));

        let opt_in = settings_from_json(serde_json::json!({
            "ttl": 60,
            "cache_set_cookie_responses": true
        }));
        assert!(!should_bypass_set_cookie_response(&opt_in, true));
    }

    #[test]
    fn max_file_size_none_uses_global_default() {
        // None (unconfigured) inherits the global default, whatever it is.
        let s = settings_from_json_with_default(serde_json::json!({ "ttl": 60 }), 999_999);
        assert_eq!(s.max_file_size_bytes, 999_999);
    }

    #[test]
    fn max_file_size_some_zero_means_unlimited() {
        let s = settings_from_json_with_default(
            serde_json::json!({ "ttl": 60, "max_file_size_bytes": 0 }),
            999_999,
        );
        assert_eq!(s.max_file_size_bytes, 0);
    }

    #[test]
    fn max_file_size_some_value() {
        let s = settings_from_json_with_default(
            serde_json::json!({ "ttl": 60, "max_file_size_bytes": 5_000_000 }),
            999_999,
        );
        assert_eq!(s.max_file_size_bytes, 5_000_000);
    }

    #[test]
    fn plugin_name_is_apisix_proxy_cache() {
        assert_eq!(PLUGIN_NAME, "proxy-cache");
    }

    #[test]
    fn ttl_defaults_to_apisix_default_and_cache_ttl_overrides() {
        let defaulted = PluginConfig::try_from(serde_json::json!({})).unwrap();
        assert_eq!(defaulted.ttl, 300);

        let overridden = PluginConfig::try_from(serde_json::json!({
            "ttl": 60,
            "cache_ttl": 90
        }))
        .unwrap();
        assert_eq!(overridden.ttl, 90);

        assert!(PluginConfig::try_from(serde_json::json!({ "cache_ttl": 0 })).is_err());
    }

    #[test]
    fn apisix_cache_method_overrides_pingsix_methods() {
        let config = PluginConfig::try_from(serde_json::json!({
            "cache_http_methods": ["OPTIONS"],
            "cache_method": ["GET", "POST", "HEAD"]
        }))
        .unwrap();
        assert_eq!(config.cache_http_methods, ["GET", "POST", "HEAD"]);

        assert!(PluginConfig::try_from(serde_json::json!({ "cache_method": ["DELETE"] })).is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({ "cache_method": ["GET", "GET"] })).is_err()
        );
        assert!(PluginConfig::try_from(serde_json::json!({ "cache_method": [] })).is_err());
    }

    #[test]
    fn apisix_cache_http_status_overrides_pingsix_statuses() {
        let config = PluginConfig::try_from(serde_json::json!({
            "cache_http_statuses": [204],
            "cache_http_status": [200, 301, 404]
        }))
        .unwrap();
        assert_eq!(config.cache_http_statuses, [200, 301, 404]);

        // The pingsix default stays `[200]` when only the alias is absent.
        let defaulted = PluginConfig::try_from(serde_json::json!({})).unwrap();
        assert_eq!(defaulted.cache_http_statuses, [200]);

        assert!(PluginConfig::try_from(serde_json::json!({ "cache_http_status": [199] })).is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({ "cache_http_status": [200, 200] })).is_err()
        );
        assert!(PluginConfig::try_from(serde_json::json!({ "cache_http_status": [] })).is_err());
    }

    #[test]
    fn apisix_no_cache_keeps_pingsix_regex_list_independent() {
        let config = PluginConfig::try_from(serde_json::json!({
            "no_cache_str": ["^/legacy"],
            "no_cache": ["$http_x_private"]
        }))
        .unwrap();
        assert_eq!(config.no_cache_str, ["^/legacy"]);
        assert_eq!(
            config.no_cache.as_deref(),
            Some(&["$http_x_private".to_string()][..])
        );

        assert!(PluginConfig::try_from(serde_json::json!({ "no_cache": [] })).is_err());
    }

    #[test]
    fn disk_strategy_is_rejected() {
        assert!(PluginConfig::try_from(serde_json::json!({})).is_ok());
        assert!(PluginConfig::try_from(serde_json::json!({ "cache_strategy": "memory" })).is_ok());

        let disk = PluginConfig::try_from(serde_json::json!({ "cache_strategy": "disk" }));
        assert!(disk.is_err());
        assert!(disk
            .unwrap_err()
            .to_string()
            .contains("only 'memory' is supported"));
    }

    #[test]
    fn apisix_max_resp_body_size_maps_only_when_pingsix_field_is_absent() {
        let config =
            PluginConfig::try_from(serde_json::json!({ "max_resp_body_size": 4096 })).unwrap();
        assert_eq!(config.max_resp_body_size, Some(4096));
        let settings = settings_from_json_with_default(
            serde_json::json!({ "max_resp_body_size": 4096 }),
            999_999,
        );
        assert_eq!(settings.max_file_size_bytes, 4096);

        // An explicit pingsix field (including 0 = unlimited) wins.
        let settings = settings_from_json_with_default(
            serde_json::json!({ "max_resp_body_size": 4096, "max_file_size_bytes": 0 }),
            999_999,
        );
        assert_eq!(settings.max_file_size_bytes, 0);

        // The parsed APISIX default is not applied implicitly: absent configs
        // keep inheriting the pingsix instance default.
        let defaulted = PluginConfig::try_from(serde_json::json!({})).unwrap();
        assert_eq!(defaulted.max_resp_body_size, Some(64 * 1024 * 1024));
        let settings = settings_from_json_with_default(serde_json::json!({}), 999_999);
        assert_eq!(settings.max_file_size_bytes, 999_999);

        assert!(PluginConfig::try_from(serde_json::json!({ "max_resp_body_size": 0 })).is_err());
    }

    #[test]
    fn apisix_cache_set_cookie_ors_into_pingsix_field() {
        let config =
            PluginConfig::try_from(serde_json::json!({ "cache_set_cookie": true })).unwrap();
        assert!(config.cache_set_cookie_responses);

        let existing =
            PluginConfig::try_from(serde_json::json!({ "cache_set_cookie": true })).unwrap();
        assert!(existing.cache_set_cookie_responses);
    }

    #[test]
    fn apisix_cache_key_and_bypass_defaults() {
        let config = PluginConfig::try_from(serde_json::json!({})).unwrap();
        // Existing pingsix configs keep the legacy METHOD-host-uri key unless
        // `cache_key` is set explicitly (APISIX default would be
        // ["$host", "$request_uri"]).
        assert_eq!(config.cache_key, None);
        assert_eq!(config.cache_bypass, None);
        assert_eq!(
            config.cache_control, None,
            "absent flag keeps pingsix legacy behavior"
        );
        assert!(config.consumer_isolation);
    }

    #[test]
    fn cache_control_flag_accepts_explicit_values() {
        let config = PluginConfig::try_from(serde_json::json!({ "cache_control": true })).unwrap();
        assert_eq!(config.cache_control, Some(true));
        let config = PluginConfig::try_from(serde_json::json!({ "cache_control": false })).unwrap();
        assert_eq!(config.cache_control, Some(false));
    }

    #[test]
    fn cache_key_request_method_is_rejected() {
        // APISIX check_schema rejects $request_method: the method is not part
        // of the cache identity and would break the PURGE→GET key alias.
        let err = PluginConfig::try_from(serde_json::json!({
            "cache_key": ["$host", "$request_method"]
        }))
        .unwrap_err();
        assert!(err.to_string().contains("$request_method"), "{err}");
        assert!(PluginConfig::try_from(serde_json::json!({
            "cache_key": ["$host", "$request_uri"]
        }))
        .is_ok());
    }

    async fn cache_session(headers: &[(&str, &str)]) -> Session {
        use tokio::io::AsyncWriteExt;

        let (client, mut server) = tokio::io::duplex(1024);
        let mut request = "GET /api/users?q=1 HTTP/1.1\r\nHost: example.com\r\n".to_string();
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        server.write_all(request.as_bytes()).await.unwrap();
        drop(server);
        let mut session = Session::new_h1(Box::new(client));
        session.downstream_session.read_request().await.unwrap();
        session
    }

    fn cacheable_response() -> pingora_http::ResponseHeader {
        pingora_http::ResponseHeader::build(200, None).unwrap()
    }

    #[tokio::test]
    async fn no_cache_template_suppresses_store_but_keeps_lookup_eligible() {
        let plugin = create_cache_plugin(
            serde_json::json!({ "ttl": 60, "no_cache": ["$http_x_private"] }),
            &crate::config::EffectiveDefaults::default(),
        )
        .unwrap();
        let mut ctx = ProxyContext::default();

        // Template renders truthy: the response must not be STORED, but the
        // request stays eligible for cache LOOKUP (settings are in ctx).
        let mut session = cache_session(&[("X-Private", "1")]).await;
        plugin.request_filter(&mut session, &mut ctx).await.unwrap();
        assert!(
            ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)
                .is_some(),
            "no_cache must keep the request eligible for cache LOOKUP (hits)"
        );
        let settings = ctx
            .get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)
            .unwrap();
        assert!(ctx
            .get::<bool>(&settings.no_cache_flag_key)
            .copied()
            .unwrap_or(false));
        assert!(matches!(
            response_cacheability(&cacheable_response(), &ctx).unwrap(),
            RespCacheable::Uncacheable(_)
        ));

        // Template renders falsy: storing stays enabled.
        let mut ctx = ProxyContext::default();
        let mut session = cache_session(&[]).await;
        plugin.request_filter(&mut session, &mut ctx).await.unwrap();
        let settings = ctx
            .get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)
            .unwrap();
        assert!(!ctx
            .get::<bool>(&settings.no_cache_flag_key)
            .copied()
            .unwrap_or(false));
        assert!(matches!(
            response_cacheability(&cacheable_response(), &ctx).unwrap(),
            RespCacheable::Cacheable(_)
        ));
    }

    #[tokio::test]
    async fn cache_bypass_template_disables_lookup_entirely() {
        let plugin = create_cache_plugin(
            serde_json::json!({ "ttl": 60, "cache_bypass": ["$http_x_bypass"] }),
            &crate::config::EffectiveDefaults::default(),
        )
        .unwrap();
        let mut ctx = ProxyContext::default();

        let mut session = cache_session(&[("X-Bypass", "1")]).await;
        plugin.request_filter(&mut session, &mut ctx).await.unwrap();
        assert!(
            ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)
                .is_none(),
            "cache_bypass must disable the cache for this request"
        );
        assert!(matches!(
            response_cacheability(&cacheable_response(), &ctx).unwrap(),
            RespCacheable::Uncacheable(NoCacheReason::NeverEnabled)
        ));
    }
}
