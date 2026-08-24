use std::{sync::Arc, time::Duration};

#[cfg(test)]
use crate::plugins::cache::http::response_has_vary_star;
use async_trait::async_trait;
use bytes::Bytes;
#[cfg(test)]
use http::header::VARY;
use http::StatusCode;
use once_cell::sync::Lazy;
use pingora::modules::http::{
    HttpModules,
    {compression::ResponseCompressionBuilder, grpc_web::GrpcWeb},
};
use pingora_cache::{
    eviction::simple_lru::Manager,
    key::{CacheKey, HashBinary},
    lock::{CacheKeyLockImpl, CacheLock},
    CacheMeta, CachePhase, MemCache, RespCacheable,
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
    plugins::cache::{
        http::{
            cache_key, cache_vary, credential_cache_key_component, error_status,
            headers_indicate_shared_cache_credentials, response_cacheability, should_enable_purge,
            should_enable_request_cache,
        },
        CacheSettings, CTX_KEY_CACHE_SETTINGS,
    },
    proxy::{route::apply_route_timeout, runtime::RuntimeStore},
};

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
            // Capture the credential digest from the ORIGINAL headers before
            // any plugin (auth plugin `hide_credentials`, proxy-rewrite header
            // removal) can strip them; shared-cache consumer isolation reads
            // it later when the cache key is built.
            ctx.original_credential_digest =
                Some(credential_cache_key_component(session.req_header()));
        }

        // Load one immutable runtime snapshot for all data-plane configuration used here.
        let runtime = self.runtime.load();
        let global_plugins = runtime.global_plugins.clone();
        // Preflight fallback eligibility (route/service/global CORS) is
        // compiled into the route matcher at snapshot build time.
        let route_match = match runtime.route_matcher.match_request(session) {
            Some(route_match) => Some(route_match),
            None => runtime.route_matcher.match_preflight(session),
        };
        if let Some((route_params, route)) = route_match {
            let executor = route.build_plugin_executor();
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
            crate::utils::response::send_exit_response(
                session,
                StatusCode::NOT_FOUND.as_u16(),
                None,
                None,
                &[],
                ctx,
            )
            .await?;
            return Ok(true);
        }

        // Execute global rule plugins, then route/service plugins. The pipeline
        // is cloned out of `ctx` so its phase methods can borrow `ctx` mutably.
        let pipeline = ctx.pipeline.clone();
        pipeline.request_filter(session, ctx).await
    }

    /// Selects an upstream peer for the request.
    ///
    /// Peer-option precedence — this is the single home of the chain:
    /// 1. upstream defaults (compiled upstream / provider configuration,
    ///    including upstream-level timeouts),
    /// 2. route timeout override (`route.timeout`, applied to traffic-split
    ///    override selections too),
    /// 3. WebSocket relaxation (route-enabled plus a complete, trusted
    ///    upgrade handshake) — after the route timeout so long-lived streams
    ///    may idle,
    /// 4. plugin `upstream_peer_filter` phase (e.g. ai-proxy read-timeout
    ///    floor, `ssl_verify`) — plugin policy runs last.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Both selection paths compile the same artifact: peer + owning
        // selector.
        let selection = if let Some(upstream) = ctx.upstream_override.clone() {
            let mut backend = upstream.select_backend(session).ok_or_else(|| {
                ProxyError::UpstreamSelection("Traffic-split selected no backend".to_string())
            })?;
            let peer = backend
                .ext
                .get_mut::<HttpPeer>()
                .ok_or_else(|| ProxyError::Internal("Peer missing".into()))?
                .clone();
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

        let (mut peer, selected) = selection.into_peer();
        ctx.selected = Some(selected);

        // (2) Route timeout applies to every selection path.
        if let Some(route) = ctx.route.as_ref() {
            apply_route_timeout(route.timeout(), &mut peer);
        }

        // (3) Long-lived WebSocket streams may legitimately be idle. Only
        // relax upstream timeouts for an explicitly enabled route and a
        // complete, trusted WebSocket upgrade handshake.
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

        // (4) Plugin-owned peer policy.
        let pipeline = ctx.pipeline.clone();
        pipeline.upstream_peer_filter(session, &mut peer, ctx)?;

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
                    if let Err(e) =
                        upstream_request.insert_header(http::header::HOST, selected.sni.as_str())
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

    /// Map plugin-raised errors to client-facing status codes; otherwise
    /// mirror Pingora's default error-code derivation. Every status-bearing
    /// error flows through the shared exit helper so a configured
    /// `exit-transformer` can rewrite the response.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let code = error_status(e);
        if code > 0 {
            crate::utils::response::send_exit_response(session, code, None, None, &[], ctx)
                .await
                .unwrap_or_else(|err| {
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
    /// enables the cache for PURGE requests only when `enable_purge` is on,
    /// and the key callback maps PURGE onto the GET key, so this short-circuits
    /// before any upstream fetch.
    fn is_purge(&self, session: &Session, ctx: &Self::CTX) -> bool {
        session.req_header().method.as_str() == "PURGE"
            && should_enable_purge(ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS))
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        let settings = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS);
        if should_enable_request_cache(&session.req_header().headers, settings, ctx) {
            let settings = settings.expect("cache settings checked above");
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
        Ok(cache_key(session, ctx))
    }

    fn cache_vary_filter(
        &self,
        meta: &CacheMeta,
        ctx: &mut Self::CTX,
        req: &RequestHeader,
    ) -> Option<HashBinary> {
        cache_vary(meta, ctx, req)
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        response_cacheability(resp, ctx)
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
}
