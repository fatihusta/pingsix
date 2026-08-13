use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use http::{
    header::{SET_COOKIE, VARY},
    StatusCode,
};
use once_cell::sync::{Lazy, OnceCell};
use pingora::modules::http::{
    HttpModules,
    {compression::ResponseCompressionBuilder, grpc_web::GrpcWeb},
};
use pingora_cache::{
    cache_control::{CacheControl, DirectiveMap, DirectiveValue},
    eviction::simple_lru::Manager,
    filters::resp_cacheable,
    key::{CacheKey, HashBinary},
    lock::{CacheKeyLockImpl, CacheLock},
    CacheMeta, CacheMetaDefaults, CachePhase, MemCache, NoCacheReason, RespCacheable,
    VarianceBuilder,
};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorSource, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use prometheus::{register_int_counter_vec, IntCounterVec};

use crate::{
    config::{self, CacheDefaults},
    core::{
        CompiledPluginPipeline, PassiveOutcome, ProxyContext, ProxyError, ProxyPluginExecutor,
        RouteContext, UpstreamSelection,
    },
    plugins::cache::{self, CacheSettings, CTX_KEY_CACHE_SETTINGS},
    proxy::runtime::RuntimeStore,
};

/// Headers that imply credentials for shared-cache safety (checked before plugins mutate them).
pub(crate) fn headers_indicate_shared_cache_credentials(headers: &http::HeaderMap) -> bool {
    headers.contains_key("authorization")
        || headers.contains_key("proxy-authorization")
        || headers.contains_key("cookie")
}

/// A WebSocket upgrade is trusted only when both RFC 7230/6455 handshake
/// headers are present. In particular, an arbitrary `Upgrade` header must not
/// alter upstream timeout behavior.
fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    let connection_has_upgrade = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    let upgrade_is_websocket = headers
        .get_all(http::header::UPGRADE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.trim().eq_ignore_ascii_case("websocket"));
    connection_has_upgrade && upgrade_is_websocket
}

static CACHE_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "pingsix_cache_requests_total",
        "Local response-cache outcomes",
        &["outcome", "scope"]
    )
    .expect("cache metric registration must succeed")
});

/// Whether any `Vary` field contains the wildcard token. RFC semantics make
/// such a response unsuitable for reuse by a shared cache.
fn response_has_vary_star(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("*"))
}

// Default cache metadata: No caching by default unless explicitly configured
const CACHE_DEFAULT: CacheMetaDefaults = CacheMetaDefaults::new(|_| None, 0, 0);

/// Configured eviction memory budget, populated once at startup from
/// `pingsix.defaults.cache.max_memory_bytes`. Falls back to 512MB when unset.
static CACHE_MAX_MEMORY_BYTES: OnceCell<usize> = OnceCell::new();

/// 512MB fallback used when no memory budget has been initialized.
const FALLBACK_MAX_MEMORY_BYTES: usize = 512 * 1024 * 1024;

/// Populates global cache capacity defaults from configuration. Must be called once
/// at startup before the proxy serves traffic. Subsequent calls are no-ops (first
/// value wins), keeping parallel test initialization safe.
///
/// Migration facade: the composition root now builds a per-instance
/// [`CacheRuntime`] from [`config::EffectiveDefaults`]; this global remains for
/// the legacy getter until every consumer is instance-wired.
pub fn init_cache_defaults(cache: &CacheDefaults) {
    let _ = CACHE_MAX_MEMORY_BYTES.set(cache.max_memory_bytes);
    cache::init_default_max_object_bytes(cache.default_max_object_bytes);
}

/// Returns the effective cache memory budget, falling back to 512MB when unset.
///
/// Migration facade for [`EffectiveDefaults::global`].
pub fn configured_max_memory_bytes() -> usize {
    CACHE_MAX_MEMORY_BYTES
        .get()
        .copied()
        .unwrap_or(FALLBACK_MAX_MEMORY_BYTES)
}

/// Instance-owned response-cache infrastructure.
///
/// Pingora 0.8's `session.cache.enable` retains `'static` references for the
/// storage backend, eviction manager, and cache lock. Those references can
/// escape a request through Pingora-managed eviction and stale-revalidation
/// tasks, so reclaiming these allocations after a `GatewayRuntime` drops would
/// be unsound. They intentionally live until process exit.
///
/// A `GatewayState` still owns the *selection* of a distinct cache runtime:
/// every build receives independent backing objects and therefore an isolated
/// cache namespace. Repeated in-process builds should be reserved for testing
/// or controlled orchestration; process restart is required to reclaim their
/// Pingora cache allocations. This is the sole unavoidable Pingora `'static`
/// boundary, not a general ambient-state facade.
pub struct CacheRuntime {
    backend: &'static MemCache,
    eviction: &'static (dyn pingora_cache::eviction::EvictionManager + Sync),
    lock: &'static CacheKeyLockImpl,
}

impl CacheRuntime {
    /// Build an isolated cache runtime sized from the instance's effective
    /// cache defaults.
    pub fn new(defaults: &CacheDefaults) -> Self {
        let backend: &'static MemCache = Box::leak(Box::new(MemCache::new()));
        let eviction: &'static Manager =
            Box::leak(Box::new(Manager::new(defaults.max_memory_bytes)));
        let lock: &'static CacheKeyLockImpl =
            Box::leak(CacheLock::new_boxed(Duration::from_secs(5)));
        Self {
            backend,
            eviction,
            lock,
        }
    }
}

/// Proxy service.
///
/// Manages the proxying of requests to upstream servers. Plugin composition,
/// ordering, and phase traversal live in [`CompiledPluginPipeline`]; this type
/// only adapts Pingora callbacks to it.
pub struct HttpService {
    runtime: Arc<RuntimeStore>,
    cache: Arc<CacheRuntime>,
}

impl HttpService {
    pub fn new(runtime: Arc<RuntimeStore>, cache: Arc<CacheRuntime>) -> Self {
        Self { runtime, cache }
    }
}

#[async_trait]
impl ProxyHttp for HttpService {
    type CTX = ProxyContext;

    /// Creates a new context for each request
    fn new_ctx(&self) -> Self::CTX {
        Self::CTX::default()
    }

    /// Set up downstream modules.
    ///
    /// set up [ResponseCompressionBuilder] for gzip and brotli compression.
    /// set up [GrpcWeb] for grpc-web protocol.
    fn init_downstream_modules(&self, modules: &mut HttpModules) {
        // Add disabled downstream compression module by default
        modules.add_module(ResponseCompressionBuilder::enable(0));
        // Add the gRPC web module
        modules.add_module(Box::new(GrpcWeb));
    }

    /// Handle the incoming request before any downstream module is executed.
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        let original_headers = &session.req_header().headers;
        ctx.original_request_had_credentials =
            headers_indicate_shared_cache_credentials(original_headers);
        if ctx.original_request_had_credentials {
            ctx.request_has_credentials = true;
        }

        // Load one immutable runtime snapshot for all data-plane configuration used here.
        let runtime = self.runtime.load();
        let global_plugins = runtime.global_plugins.clone();
        let (route_match, is_fallback_preflight) =
            match runtime.route_matcher.match_request(session) {
                Some(route_match) => (Some(route_match), false),
                None => (
                    runtime
                        .route_matcher
                        .match_preflight(session, global_plugins.has_plugin("cors")),
                    true,
                ),
            };
        if let Some((route_params, route)) = route_match {
            // The preflight matcher itself filters fallback candidates to routes
            // whose effective route/service/global configuration contains CORS.
            let executor = route.build_plugin_executor();
            debug_assert!(
                !is_fallback_preflight
                    || executor.has_plugin("cors")
                    || global_plugins.has_plugin("cors")
            );
            ctx.route_params = Some(route_params);
            ctx.pipeline = CompiledPluginPipeline::new(global_plugins, executor);
            ctx.route = Some(route);
        } else {
            ctx.pipeline =
                CompiledPluginPipeline::new(global_plugins, ProxyPluginExecutor::default_shared());
        }

        // Execute global rule plugins, then route/service plugins.
        let pipeline = ctx.pipeline.clone();
        pipeline.early_request_filter(session, ctx).await
    }

    /// Filters incoming requests
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        if ctx.route.is_none() {
            session
                .respond_error(StatusCode::NOT_FOUND.as_u16())
                .await?;
            return Ok(true);
        }

        // Execute global rule plugins, then route/service plugins. The pipeline
        // is cloned out of `ctx` so its phase methods can borrow `ctx` mutably.
        let pipeline = ctx.pipeline.clone();
        pipeline.request_filter(session, ctx).await
    }

    /// Selects an upstream peer for the request
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Both selection paths compile the same artifact: peer + owning
        // selector. Route timeouts apply to override selections too.
        let selection = if let Some(upstream) = ctx.upstream_override.clone() {
            let mut backend = upstream.select_backend(session).ok_or_else(|| {
                ProxyError::UpstreamSelection("Traffic-split selected no backend".to_string())
            })?;
            let mut peer = backend
                .ext
                .get_mut::<HttpPeer>()
                .ok_or_else(|| ProxyError::Internal("Peer missing".into()))?
                .clone();
            if let Some(route) = ctx.route.as_ref() {
                crate::proxy::route::apply_route_timeout(route.timeout(), &mut peer);
            }
            let selected_backend = backend.clone();
            UpstreamSelection {
                peer: Box::new(peer),
                upstream,
                backend: selected_backend,
            }
        } else {
            let route = ctx
                .route
                .as_ref()
                .ok_or_else(|| ProxyError::Internal("Route not found".into()))?;
            route.select_upstream(session)?
        };

        let mut peer = selection.peer.clone();
        ctx.selected = Some(selection);

        // Long-lived WebSocket streams may legitimately be idle. Only relax
        // upstream timeouts for an explicitly enabled route and a complete,
        // trusted WebSocket upgrade handshake.
        let websocket_enabled = ctx
            .route
            .as_ref()
            .map(|route| route.enable_websocket())
            .unwrap_or(false);
        if websocket_enabled && is_websocket_upgrade(&session.req_header().headers) {
            peer.options.read_timeout = None;
            peer.options.write_timeout = None;
            log::debug!("WebSocket request: disabled upstream read/write timeouts");
        }

        Ok(peer)
    }

    /// Modify the request before it is sent to the upstream
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let pipeline = ctx.pipeline.clone();
        pipeline
            .upstream_request_filter(session, upstream_request, ctx)
            .await?;

        // Rewrite host header
        // Priority: upstream_override > route upstream
        if let Some(selected) = ctx.selected.as_ref() {
            match selected.upstream.get_pass_host() {
                config::UpstreamPassHost::PASS => {
                    // Do nothing, preserve original host
                }
                config::UpstreamPassHost::REWRITE => {
                    selected.upstream.upstream_host_rewrite(upstream_request);
                }
                config::UpstreamPassHost::NODE => {
                    if let Err(e) = upstream_request
                        .insert_header(http::header::HOST, selected.peer.sni.as_str())
                    {
                        log::error!("Failed to rewrite upstream host header: {e}");
                    }
                }
            }
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Passive health check: observe the real-traffic response status
        // (APISIX `checks.passive` unhealthy/healthy counters).
        if let Some(selected) = ctx.selected.as_ref() {
            selected.upstream.observe_passive(
                &selected.backend,
                PassiveOutcome::Http(upstream_response.status.as_u16()),
            );
        }

        // Add X-Cache-Status header logic
        if let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) {
            let cache_phase = session.cache.phase();
            let status_str = match cache_phase {
                CachePhase::Hit => "HIT",
                CachePhase::Miss => "MISS",
                CachePhase::Stale => "STALE",
                CachePhase::Expired => "EXPIRED",
                CachePhase::Revalidated => "REVALIDATED",
                _ => "BYPASS",
            };
            CACHE_REQUESTS
                .with_label_values(&[&status_str.to_ascii_lowercase(), "local"])
                .inc();
            if !settings.hide_cache_headers {
                upstream_response.insert_header("X-Cache-Status", status_str)?;
                upstream_response.insert_header("X-Cache-Scope", "local")?;
            }
        }

        let pipeline = ctx.pipeline.clone();
        pipeline
            .response_filter(session, upstream_response, ctx)
            .await
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        let pipeline = ctx.pipeline.clone();
        pipeline.response_body_filter(session, body, end_of_stream, ctx)?;
        Ok(None)
    }

    /// Stream request body chunks through plugin request-body filters
    /// (e.g. client-control size enforcement).
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let pipeline = ctx.pipeline.clone();
        pipeline
            .request_body_filter(session, body, end_of_stream, ctx)
            .await
    }

    /// Map plugin-raised body errors to client-facing status codes; otherwise
    /// mirror Pingora's default error-code derivation.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        _ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let code = match e.etype() {
            ErrorType::Custom(custom)
                if *custom == crate::plugins::client_control::ERROR_PAYLOAD_TOO_LARGE =>
            {
                StatusCode::PAYLOAD_TOO_LARGE.as_u16()
            }
            _ => {
                if let ErrorType::HTTPStatus(code) = e.etype() {
                    *code
                } else {
                    match e.esource() {
                        ErrorSource::Upstream => 502,
                        ErrorSource::Downstream => match e.etype() {
                            ErrorType::WriteError
                            | ErrorType::ReadError
                            | ErrorType::ConnectionClosed => {
                                // connection already dead
                                0
                            }
                            _ => 400,
                        },
                        ErrorSource::Internal | ErrorSource::Unset => 500,
                    }
                }
            }
        };
        if code > 0 {
            session.respond_error(code).await.unwrap_or_else(|err| {
                log::error!("failed to send error response to downstream: {err}");
            });
        }

        FailToProxy {
            error_code: code,
            // default to no reuse, which is safest
            can_reuse_downstream: false,
        }
    }

    /// Intercept `PURGE` requests to delete the matching cache entry
    /// (Guide L46 / APISIX proxy-cache purge semantics). The cache plugin
    /// enables the cache for PURGE requests and the key callback maps PURGE
    /// onto the GET key, so this short-circuits before any upstream fetch.
    fn is_purge(&self, session: &Session, ctx: &Self::CTX) -> bool {
        session.req_header().method.as_str() == "PURGE"
            && ctx
                .get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)
                .is_some()
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        let headers = &session.req_header().headers;

        if headers.contains_key("x-bypass-cache") {
            log::debug!("Cache bypass requested via x-bypass-cache header");
            return Ok(());
        }

        if let Some(cache_control) = headers.get("cache-control") {
            if let Ok(cc_str) = cache_control.to_str() {
                if cc_str.contains("no-cache") {
                    log::debug!("Cache bypass requested via cache-control: no-cache");
                    return Ok(());
                }
            }
        }

        // Check for cache settings from plugin configuration.
        // Re-check credentials here: global cache may run before route auth plugins mark them.
        if let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) {
            if crate::plugins::cache::should_bypass_authenticated_request(settings, ctx) {
                log::debug!("Skipping shared cache: request has credentials");
                return Ok(());
            }

            log::debug!("Cache settings found, enabling Pingora cache.");

            // Enable caching with configured backend and eviction manager
            session.cache.enable(
                self.cache.backend,
                Some(self.cache.eviction),
                None,
                Some(self.cache.lock),
                None,
            );

            // Set maximum file size if configured
            if settings.max_file_size_bytes > 0 {
                session
                    .cache
                    .set_max_file_size_bytes(settings.max_file_size_bytes);
                log::debug!(
                    "Set max cache file size to {} bytes",
                    settings.max_file_size_bytes
                );
            }
        }
        Ok(())
    }

    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
        let req = session.req_header();
        let host = req
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // PURGE requests must compute the same key as the cached GET/HEAD so
        // the delete hits the entry (APISIX proxy-cache keys exclude the method).
        let method = if req.method.as_str() == "PURGE" {
            "GET"
        } else {
            req.method.as_str()
        };
        let primary = format!("{method} {} {}", host, req.uri);

        let route_fp = ctx
            .route
            .as_ref()
            .map(|r| r.cache_namespace_fingerprint())
            .unwrap_or(0);
        let policy_fp = ctx
            .get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)
            .map(|s| s.policy_fingerprint)
            .unwrap_or(0);
        let upstream_key = if let Some(override_up) = ctx.upstream_override.as_ref() {
            override_up.cache_isolation_key()
        } else {
            ctx.route
                .as_ref()
                .and_then(|r| r.resolve_upstream())
                .map(|u| u.cache_isolation_key())
                .unwrap_or_default()
        };
        let scheme = if session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some()
        {
            "https"
        } else {
            "http"
        };
        // Route fingerprint covers identity + response-affecting plugins;
        // upstream isolation covers origin selection (nodes, Host rewrite, TLS).
        // `upstream_key` is a u64 fingerprint directly, avoiding a per-request
        // hex `String` allocation.
        let namespace = format!("rf={route_fp:x}|c={policy_fp:x}|u={upstream_key:x}|sch={scheme}");
        Ok(CacheKey::new(namespace, primary, ""))
    }

    fn cache_vary_filter(
        &self,
        meta: &CacheMeta,
        ctx: &mut Self::CTX,
        req: &RequestHeader,
    ) -> Option<HashBinary> {
        // Only process Vary headers when cache settings are present
        let settings = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)?;

        // `Vary: *` responses must never enter a shared cache. The response
        // filter enforces that rule; this is a defensive guard against ever
        // constructing a stable variance for the literal `*` header name.
        if response_has_vary_star(meta.headers()) {
            return None;
        }

        // Collect Vary header names into a small Vec instead of a HashSet:
        // typical responses carry 0-3 names, where sort+dedup on a Vec is
        // cheaper than a hashed container, and we avoid cloning already-
        // lowercase configured names.
        let mut vary_headers: Vec<String> = Vec::new();
        // 1. Headers from the origin's `Vary` response header (arbitrary case).
        meta.headers()
            .get_all(VARY)
            .iter()
            .flat_map(|v| v.to_str().unwrap_or("").split(','))
            .for_each(|h| {
                let trimmed = h.trim().to_ascii_lowercase();
                if !trimmed.is_empty() {
                    vary_headers.push(trimmed);
                }
            });
        // 2. Headers from the plugin's pre-normalized (lowercase, sorted,
        //    deduped) `vary` configuration.
        vary_headers.extend(settings.vary.iter().cloned());

        // 3. Build the variance key.
        if vary_headers.is_empty() {
            return None;
        }
        vary_headers.sort_unstable();
        vary_headers.dedup();
        let mut key = VarianceBuilder::new();
        for header_name in &vary_headers {
            key.add_value(
                header_name,
                req.headers
                    .get(header_name)
                    .map(|v| v.as_bytes())
                    .unwrap_or(&[]),
            );
        }
        key.finalize()
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) else {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::NeverEnabled));
        };

        // These reasons may run after `session.cache.enable()`; NeverEnabled panics there.
        if crate::plugins::cache::should_bypass_authenticated_request(settings, ctx) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        if !settings.statuses.contains(&resp.status.as_u16()) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        if !settings.cache_set_cookie_responses && resp.headers.contains_key(SET_COOKIE) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        if response_has_vary_star(&resp.headers) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        let cc = CacheControl::from_resp_headers(resp);
        let final_cc = ensure_max_age(cc, settings);

        // Only treat the request as authorized when credentials were actually
        // present; the previous hard-coded `true` made every response require
        // `public`/`s-maxage` and prevented the default TTL path from caching.
        let authorization_present =
            ctx.original_request_had_credentials || ctx.request_has_credentials;

        Ok(resp_cacheable(
            final_cc.as_ref(),
            resp.clone(),
            authorization_present,
            &CACHE_DEFAULT,
        ))
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Self::CTX) {
        let pipeline = ctx.pipeline.clone();
        pipeline.logging(session, e, ctx).await;
    }

    /// Observe only genuine post-connect upstream transport failures. Connection
    /// failures are observed in `fail_to_connect`, avoiding double counting.
    fn error_while_proxy(
        &self,
        _peer: &HttpPeer,
        _session: &mut Session,
        e: Box<Error>,
        ctx: &mut Self::CTX,
        _client_reused: bool,
    ) -> Box<Error> {
        if *e.esource() == ErrorSource::Upstream {
            if let Some(selected) = ctx.selected.as_ref() {
                let outcome = match e.etype() {
                    ErrorType::ReadTimedout | ErrorType::WriteTimedout => PassiveOutcome::Timeout,
                    ErrorType::ReadError | ErrorType::WriteError | ErrorType::ConnectionClosed => {
                        PassiveOutcome::TcpFailure
                    }
                    _ => return e,
                };
                selected
                    .upstream
                    .observe_passive(&selected.backend, outcome);
            }
        }
        e
    }

    /// This filter is called when there is an error in the process of establishing a connection to the upstream.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if let Some(selected) = ctx.selected.as_ref() {
            let outcome = match e.etype() {
                ErrorType::ConnectTimedout | ErrorType::TLSHandshakeTimedout => {
                    Some(PassiveOutcome::Timeout)
                }
                ErrorType::ConnectRefused
                | ErrorType::ConnectNoRoute
                | ErrorType::ConnectError
                | ErrorType::TLSHandshakeFailure
                | ErrorType::HandshakeError => Some(PassiveOutcome::TcpFailure),
                _ => None,
            };
            if let Some(outcome) = outcome {
                selected
                    .upstream
                    .observe_passive(&selected.backend, outcome);
            }
            if let Some(retries) = selected.upstream.get_retries() {
                if retries > 0 && ctx.tries < retries {
                    let within_timeout = match selected.upstream.get_retry_timeout() {
                        Some(timeout) => ctx.elapsed_ms() <= (timeout * 1000) as u128,
                        None => true,
                    };
                    if within_timeout {
                        ctx.tries += 1;
                        e.set_retry(true);
                    }
                }
            }
        }
        e
    }
}

/// Ensures CacheControl has max-age set, adding default TTL if missing.
/// Also handles s-maxage and stale-while-revalidate directives based on settings.
fn ensure_max_age(cc: Option<CacheControl>, settings: &CacheSettings) -> Option<CacheControl> {
    match cc {
        Some(existing_cc) => {
            let has_max_age_existing = existing_cc.directives.contains_key("max-age");
            let needs_smaxage_rewrite =
                settings.respect_s_maxage && existing_cc.directives.contains_key("s-maxage");
            let needs_stale_while_revalidate = settings.stale_while_revalidate.is_some_and(|_| {
                !existing_cc
                    .directives
                    .contains_key("stale-while-revalidate")
            });

            if has_max_age_existing && !needs_smaxage_rewrite && !needs_stale_while_revalidate {
                return Some(existing_cc);
            }

            let mut directives = DirectiveMap::with_capacity(existing_cc.directives.len() + 3);
            let mut has_max_age = false;

            // Copy existing directives and check for max-age
            for (key, value) in &existing_cc.directives {
                // If respect_s_maxage is enabled and s-maxage is present, use it as max-age for shared cache
                if settings.respect_s_maxage && key == "s-maxage" {
                    if let Some(s_maxage_value) = value {
                        // Use s-maxage value as max-age for shared cache scenario
                        let max_age_from_s_maxage = DirectiveValue(s_maxage_value.0.clone());
                        directives.insert("max-age".to_string(), Some(max_age_from_s_maxage));
                        has_max_age = true;
                    }
                    // Also keep the original s-maxage
                    let cloned_value = value.as_ref().map(|val| DirectiveValue(val.0.clone()));
                    directives.insert(key.clone(), cloned_value);
                } else if key == "max-age" {
                    has_max_age = true;
                    let cloned_value = value.as_ref().map(|val| DirectiveValue(val.0.clone()));
                    directives.insert(key.clone(), cloned_value);
                } else {
                    let cloned_value = value.as_ref().map(|val| DirectiveValue(val.0.clone()));
                    directives.insert(key.clone(), cloned_value);
                }
            }

            // Add max-age if not present (and not set from s-maxage)
            if !has_max_age {
                let max_age_value = DirectiveValue(settings.ttl.as_secs().to_string().into_bytes());
                directives.insert("max-age".to_string(), Some(max_age_value));
            }

            // Add stale-while-revalidate if configured and not already present
            if let Some(swr_duration) = settings.stale_while_revalidate {
                if !directives.contains_key("stale-while-revalidate") {
                    let swr_value = DirectiveValue(swr_duration.as_secs().to_string().into_bytes());
                    directives.insert("stale-while-revalidate".to_string(), Some(swr_value));
                }
            }

            Some(CacheControl { directives })
        }
        None => {
            // No Cache-Control header, create new instance
            let capacity = 1 + settings.stale_while_revalidate.is_some() as usize;
            let mut directives = DirectiveMap::with_capacity(capacity);

            // Add max-age directive
            let max_age_value = DirectiveValue(settings.ttl.as_secs().to_string().into_bytes());
            directives.insert("max-age".to_string(), Some(max_age_value));

            // Add stale-while-revalidate if configured
            if let Some(swr_duration) = settings.stale_while_revalidate {
                let swr_value = DirectiveValue(swr_duration.as_secs().to_string().into_bytes());
                directives.insert("stale-while-revalidate".to_string(), Some(swr_value));
            }

            Some(CacheControl { directives })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_runtime_instances_are_isolated() {
        // Two gateway instances must own distinct cache backends/evictors so
        // cached responses never leak across instances in one process.
        let a = CacheRuntime::new(&CacheDefaults {
            max_memory_bytes: 100,
            default_max_object_bytes: 50,
        });
        let b = CacheRuntime::new(&CacheDefaults {
            max_memory_bytes: 200,
            default_max_object_bytes: 60,
        });
        assert!(!std::ptr::eq(a.backend, b.backend));
        assert!(!std::ptr::eq(a.eviction, b.eviction));
        assert!(!std::ptr::eq(a.lock, b.lock));
    }

    #[test]
    fn vary_star_is_detected_across_all_header_lines() {
        let mut headers = http::HeaderMap::new();
        headers.append(VARY, "Accept-Encoding".parse().unwrap());
        headers.append(VARY, "Origin, *".parse().unwrap());
        assert!(response_has_vary_star(&headers));
        headers.clear();
        headers.insert(VARY, "Origin, Accept-Encoding".parse().unwrap());
        assert!(!response_has_vary_star(&headers));
    }

    #[test]
    fn shared_cache_credential_headers_include_proxy_authorization() {
        let mut headers = http::HeaderMap::new();
        assert!(!headers_indicate_shared_cache_credentials(&headers));

        headers.insert("authorization", "Basic x".parse().unwrap());
        assert!(headers_indicate_shared_cache_credentials(&headers));

        headers.clear();
        headers.insert("proxy-authorization", "Basic x".parse().unwrap());
        assert!(headers_indicate_shared_cache_credentials(&headers));

        headers.clear();
        headers.insert("cookie", "a=b".parse().unwrap());
        assert!(headers_indicate_shared_cache_credentials(&headers));
    }

    #[test]
    fn websocket_upgrade_requires_both_handshake_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));

        headers.insert(
            http::header::CONNECTION,
            "keep-alive, Upgrade".parse().unwrap(),
        );
        assert!(is_websocket_upgrade(&headers));

        headers.insert(http::header::UPGRADE, "h2c".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn eviction_manager_uses_configured_memory() {
        // init_cache_defaults is idempotent (first call wins); in a fresh test binary this
        // is the only setter, so the configured value is observable via the getter.
        let cache = CacheDefaults {
            max_memory_bytes: 777_777,
            default_max_object_bytes: 888,
        };
        init_cache_defaults(&cache);
        assert_eq!(configured_max_memory_bytes(), 777_777);
        assert_eq!(cache::default_max_object_bytes(), 888);
    }
}
