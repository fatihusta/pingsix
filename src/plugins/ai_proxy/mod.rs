//! ai-proxy plugin (APISIX-compatible LLM proxy, v1).
//!
//! Clients send OpenAI Chat-format requests; the plugin injects provider
//! authentication, transforms the request body (options deep-merge,
//! `max_tokens` protocol mapping, Anthropic format conversion), switches the
//! request to the provider upstream (per-upstream keepalive/timeout), and
//! passes responses through untouched — including SSE streams.
//!
//! Execution model (chunked streaming rewrite — see the note below):
//!
//! ```text
//! request_filter          header-only checks (content-type, body declared),
//!                         claim the request (single-instance ownership,
//!                         see below), switch to the provider upstream
//! upstream_request_filter provider path/query, auth headers, and replace
//!                         Content-Length with `Transfer-Encoding: chunked`
//!                         (the upstream writer becomes length-agnostic)
//! request_body_filter     buffer client chunks (bounded), transform at end
//!                         of stream, inject the transformed body as one
//!                         chunk, mark the body as gateway-replaced
//! upstream_peer_filter    owning-instance peer policy (read-timeout floor,
//!                         `ssl_verify`) applied to the selected peer
//! ```
//!
//! The response side is pure passthrough (APISIX ai-proxy semantics).
//!
//! # Single-instance ownership
//!
//! The pipeline may compose a global-rule and a route/service plugin layer,
//! and several scopes can configure `ai-proxy` at once. At most ONE instance
//! may own a request; everything else (peer options, auth injection, body
//! transform) is derived from the owning instance alone, so provider
//! credentials, TLS flags, and transformations can never mix:
//!
//! * APISIX merge semantics: a route/service-scoped `ai-proxy` overrides a
//!   global-rule one — the global instance yields before claiming whenever
//!   the matched route carries its own instance (the check is an `Arc`
//!   clone, not a rebuild).
//! * The first remaining instance to run `request_filter` claims the request
//!   by recording its identity token in [`AiProxyRequestState`]; any later
//!   instance (e.g. a second global rule) becomes a no-op.
//! * Every other hook re-checks the token, so a yielded instance never
//!   touches the upstream request or the body stream.
//!
//! # Why chunked framing (and not rewrite Content-Length)
//!
//! The upstream request header is finalized (and sent) before the proxy
//! loop streams the request body, so a rewritten `Content-Length` would
//! have to be exact before the body has even been read. Worse: a plugin
//! that fully drains the downstream body in `request_filter` deadlocks
//! pingora 0.8's h1 proxy loop — the loop only invokes body filters while
//! the downstream reader has data, and `read_body_or_idle` pends forever
//! once `is_body_done()` is true with a non-empty declared body (the
//! initial flush requires `is_body_empty()`). Chunked framing avoids both
//! problems: the transformed body can take any length and is emitted at
//! end of stream, exactly like `request-validation` releases its buffered
//! body. Found by the process-level e2e test
//! (`tests/ai_proxy_e2e.rs::smoke2`); the earlier session-level probe only
//! proved the hook primitives, not the loop integration.

mod config;
mod provider;
mod transform;
mod upstream;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorType, Result};
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::core::{
    FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, Rejection, UpstreamSelector,
};

use crate::proxy::upstream::ProxyUpstream;

use config::AiProxyConfig;
use provider::{provider_spec, Provider};

use upstream::ResolvedEndpoint;

pub(crate) use config::SECRETS_TRANSFORM;
pub use upstream::{build_ai_proxy_plugin, validate_ai_proxy_config};
pub(crate) use upstream::{create_ai_proxy_plugin_with_context, inline_upstream_jobs};

pub(crate) const PLUGIN_NAME: &str = "ai-proxy";

/// pingsix priority scale. ai-proxy must read the request body before
/// request-validation (2800) so the two plugins cannot fight over the body
/// stream; sharing the uri-blocker level (2900) is safe — they share no
/// request state. Ties break by name, putting ai-proxy first.
const PRIORITY: i32 = 2900;

/// ctx key holding the per-request [`AiProxyRequestState`]; written exactly
/// once by the owning instance in `request_filter` and read by every later
/// hook (including this plugin's `upstream_peer_filter`).
pub(crate) const CTX_KEY_STATE: &str = "ai_proxy::state";

/// Floor for the upstream read timeout on ai-proxy requests (seconds).
///
/// LLM upstreams legitimately go silent between reads — non-streaming
/// completions before their first byte ("thinking"), SSE streams between
/// chunks — and pingora's `read_timeout` bounds the gap *between* reads, not
/// the total duration, so the configured value (often 30s) would kill live
/// requests. The relaxation is therefore bounded by this generous floor: a
/// stalled provider connection is dropped after at most this long, while
/// `timeout` keeps bounding connect and write. A total-duration bound
/// (`max_stream_duration_ms`) is v2.
pub(crate) const PROVIDER_READ_TIMEOUT_FLOOR_SECS: u64 = 600;

/// Apply this plugin's request-scoped peer policy onto the selected peer.
///
/// Both settings travel on the ai-proxy request state (written once by the
/// owning plugin instance) because peer options cannot be expressed on the
/// upstream resource (its TLS block carries only client certificates) and
/// must reflect the owning instance's configuration:
///
/// * read-timeout floor (every ai-proxy request): the configured value is
///   lifted to [`PROVIDER_READ_TIMEOUT_FLOOR_SECS`] instead of being removed —
///   a stalled provider can no longer hold a connection forever. The write
///   timeout stays untouched as client-side abuse protection.
/// * `ssl_verify: false`: disable certificate verification for the selected
///   provider peer.
fn apply_request_peer_options(ctx: &ProxyContext, peer: &mut HttpPeer) {
    let Some(state) = ctx.get::<AiProxyRequestState>(CTX_KEY_STATE) else {
        return;
    };
    let floor = Duration::from_secs(PROVIDER_READ_TIMEOUT_FLOOR_SECS);
    if peer
        .options
        .read_timeout
        .is_none_or(|current| current < floor)
    {
        peer.options.read_timeout = Some(floor);
        log::debug!(
            "ai-proxy request: upstream read_timeout floored at {}s",
            floor.as_secs()
        );
    }
    if state.insecure_tls {
        peer.options.verify_cert = false;
        peer.options.verify_hostname = false;
        log::debug!(
            "ai-proxy request: disabled upstream certificate verification (ssl_verify=false)"
        );
    }
}

/// Identity tokens for plugin instances (see [`AiProxyRequestState::token`]).
fn next_instance_token() -> u64 {
    static TOKENS: AtomicU64 = AtomicU64::new(1);
    TOKENS.fetch_add(1, Ordering::Relaxed)
}

/// Which configuration layer an instance was built from.
///
/// Route and service plugins share the route layer (services are merged into
/// routes before execution), so only the global-rule layer needs separate
/// treatment: it runs first and yields to a route-scoped instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PluginScope {
    /// Built from a global rule (runs before the route layer).
    Global,
    /// Built from a route or service (the route plugin layer).
    Route,
}

/// Per-request ai-proxy state, owned by exactly one plugin instance.
///
/// Consolidating what used to be independent boolean/string ctx entries keeps
/// ownership, TLS, streaming, and the body buffer consistent: a non-owning
/// instance can never observe or mutate another instance's flags, and the
/// claiming instance overwrites the whole state atomically.
#[derive(Debug, Default)]
pub(crate) struct AiProxyRequestState {
    /// Identity token of the owning [`PluginAiProxy`] instance; every hook
    /// compares it against its own token before acting.
    pub(crate) token: u64,
    /// `ssl_verify: false` of the owning instance — disables provider
    /// certificate verification (not expressible on the upstream resource,
    /// whose TLS block carries only client certificates).
    pub(crate) insecure_tls: bool,
    /// The final body carried `"stream": true`. Set at end of the body
    /// transform; observational in v1.
    pub(crate) streaming: bool,
    /// Buffered (pre-transform) client body; taken out at end of stream.
    pub(crate) body: BytesMut,
}

/// Anthropic Messages API version header value (APISIX docs' canonical).
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The ai-proxy plugin.
pub struct PluginAiProxy {
    config: AiProxyConfig,
    provider: Provider,
    endpoint: ResolvedEndpoint,
    upstream: Arc<ProxyUpstream>,
    scope: PluginScope,
    /// Unique identity of this instance; recorded in
    /// [`AiProxyRequestState`] by the claiming instance.
    token: u64,
}

impl PluginAiProxy {
    pub(crate) fn new(
        config: AiProxyConfig,
        endpoint: ResolvedEndpoint,
        upstream: Arc<ProxyUpstream>,
        scope: PluginScope,
    ) -> Self {
        let provider = config.provider;
        Self {
            config,
            provider,
            endpoint,
            upstream,
            scope,
            token: next_instance_token(),
        }
    }

    /// Whether this instance owns the request: the state recorded at claim
    /// time carries this instance's token. Non-owning instances (a global
    /// instance that yielded, or a later duplicate) never touch the request.
    fn owns_request(&self, ctx: &ProxyContext) -> bool {
        ctx.get::<AiProxyRequestState>(CTX_KEY_STATE)
            .is_some_and(|state| state.token == self.token)
    }

    /// Build the rejection value (the pipeline writes it through the shared
    /// exit helper, so exit-transformer applies). JSON error body, mirroring
    /// the gateway's other rejections.
    fn reject(status: http::StatusCode, message: &str) -> Rejection {
        let body = serde_json::json!({ "error": message }).to_string();
        Rejection::new(status)
            .with_body(body)
            .with_content_type("application/json")
    }
}

/// Whether the request declares a body at all (chunked or Content-Length).
/// Bodyless requests fail closed — there is nothing to transform.
fn request_declares_body(headers: &HeaderMap) -> bool {
    let chunked = headers
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let content_length = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    chunked || content_length > 0
}

/// Validate the request Content-Type: `None` accepts, `Some(message)`
/// rejects with a 400.
///
/// APISIX parity: an absent Content-Type defaults to JSON. A present one
/// must be exactly `application/json` (case-insensitive; parameters such as
/// `charset=utf-8` are allowed) — prefix look-alikes like `application/jsonp`
/// are rejected, and a duplicated Content-Type is ambiguous, so the gateway
/// and the provider could otherwise disagree about the body format.
fn content_type_error(headers: &HeaderMap) -> Option<&'static str> {
    let mut values = headers.get_all(http::header::CONTENT_TYPE).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return Some("ambiguous content-type: exactly one application/json value is required");
    }
    let is_json = first
        .to_str()
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
        .unwrap_or(false);
    if is_json {
        None
    } else {
        Some("unsupported content-type: only application/json is supported")
    }
}

/// Merge query-parameter sources: client query (already on the upstream
/// request), endpoint query, then auth.query — later sources win on
/// duplicate keys (auth credentials are non-overridable, APISIX semantics).
fn merged_query(
    existing: Option<&str>,
    endpoint_query: &[(String, String)],
    auth_query: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    let mut pairs: Vec<(String, String)> = existing
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default();
    pairs.extend(
        endpoint_query
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    pairs.extend(
        auth_query
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );

    if pairs.is_empty() {
        return None;
    }
    // Keep the first-appearance order, last value per key. Positions map makes
    // dedup O(n) instead of a linear `find` per pair.
    use std::collections::HashMap;
    let mut positions: HashMap<String, usize> = HashMap::with_capacity(pairs.len());
    let mut deduped: Vec<(String, String)> = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        if let Some(&position) = positions.get(&key) {
            deduped[position].1 = value;
        } else {
            positions.insert(key.clone(), deduped.len());
            deduped.push((key, value));
        }
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in deduped {
        serializer.append_pair(&key, &value);
    }
    Some(serializer.finish())
}

#[async_trait]
impl ProxyPlugin for PluginAiProxy {
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
        // Single-instance ownership: at most one ai-proxy instance handles a
        // request. An instance that already claimed makes this one a no-op,
        // so credentials, TLS flags, and the body transform never mix.
        if ctx.get::<AiProxyRequestState>(CTX_KEY_STATE).is_some() {
            return Ok(FilterVerdict::Continue);
        }
        // APISIX merge semantics: a route-scoped ai-proxy overrides a
        // global-rule one. When the matched route carries its own instance,
        // the global instance yields before claiming (the check is an `Arc`
        // clone, not a rebuild).
        if self.scope == PluginScope::Global
            && ctx
                .route
                .as_ref()
                .is_some_and(|route| route.build_plugin_executor().has_plugin(PLUGIN_NAME))
        {
            log::debug!("ai-proxy: global instance yields to the route-scoped instance");
            return Ok(FilterVerdict::Continue);
        }

        if let Some(message) = content_type_error(&session.req_header().headers) {
            return Ok(FilterVerdict::Reject(Self::reject(
                http::StatusCode::BAD_REQUEST,
                message,
            )));
        }

        if !request_declares_body(&session.req_header().headers) {
            return Ok(FilterVerdict::Reject(Self::reject(
                http::StatusCode::BAD_REQUEST,
                "request body required",
            )));
        }

        // Header-only decisions. The body is intentionally NOT read here:
        // fully draining it would deadlock pingora 0.8's h1 proxy loop (see
        // the module docs); the body is buffered and transformed in
        // `request_body_filter` instead.
        ctx.set(
            CTX_KEY_STATE,
            AiProxyRequestState {
                token: self.token,
                insecure_tls: !self.config.ssl_verify,
                streaming: false,
                body: BytesMut::new(),
            },
        );

        // Switch this request onto the provider upstream.
        ctx.upstream_override = Some(self.upstream.clone() as Arc<dyn UpstreamSelector>);
        Ok(FilterVerdict::Continue)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Only rewrite when this plugin owns the request (request_filter
        // yields/no-ops otherwise).
        if !self.owns_request(ctx) {
            return Ok(());
        }

        // Provider path + merged query.
        let query = merged_query(
            upstream_request.uri.query(),
            &self.endpoint.query,
            &self.config.auth.query,
        );
        let path_query = match query {
            Some(query) => format!("{}?{}", self.endpoint.path, query),
            None => self.endpoint.path.clone(),
        };
        let uri: http::Uri = path_query.parse().map_err(|error| {
            ProxyError::Configuration(format!(
                "ai-proxy: invalid target URI '{path_query}': {error}"
            ))
        })?;
        upstream_request.set_uri(uri);

        // The upstream request header is finalized before the body streams,
        // and the transformed body length is unknown until end of stream, so
        // switch to chunked framing (pingora's h1 writer honors
        // Transfer-Encoding over Content-Length). The transformed body is
        // emitted as a single chunk at end of stream.
        upstream_request.remove_header("content-length");
        upstream_request.remove_header("transfer-encoding");
        upstream_request.insert_header("Transfer-Encoding", "chunked")?;
        let content_type = provider_spec(self.provider).content_type;
        upstream_request.insert_header("Content-Type", content_type)?;

        // Prevent upstream compression: the response must reach the client
        // unchanged (SSE passthrough, no re-compression).
        upstream_request.remove_header("Accept-Encoding");
        // Do not forward client credentials to the LLM provider; provider
        // auth comes from auth.header below (documented APISIX difference —
        // APISIX forwards client headers and overlays auth on top).
        upstream_request.remove_header("Authorization");

        if self.provider == Provider::Anthropic
            && !self
                .config
                .auth
                .header
                .keys()
                .any(|name| name.eq_ignore_ascii_case("anthropic-version"))
        {
            upstream_request.insert_header("anthropic-version", ANTHROPIC_VERSION)?;
        }

        for (name, value) in &self.config.auth.header {
            // insert_header takes an owned header name (IntoCaseHeaderName).
            upstream_request.insert_header(name.clone(), value.as_str())?;
        }
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        if !self.owns_request(ctx) {
            return Ok(());
        }

        // Swallow client chunks into the per-request buffer; nothing reaches
        // the provider before the transform (request-validation pattern).
        if let Some(chunk) = body.take() {
            let state = ctx
                .get_mut::<AiProxyRequestState>(CTX_KEY_STATE)
                .expect("ai-proxy state present (ownership checked above)");
            state.body.extend_from_slice(&chunk);
            if state.body.len() as u64 > self.config.max_req_body_size {
                log::debug!(
                    "ai-proxy: body exceeded max_req_body_size {}",
                    self.config.max_req_body_size
                );
                return Err(Error::explain(
                    ErrorType::HTTPStatus(413),
                    "request body too large",
                ));
            }
        }

        if !end_of_stream {
            // Keep the upstream stream open. Returning `None` here would be
            // read as "body finished" by pingora's request-body pipeline
            // (h1 sends the terminating chunk, h2 sets END_STREAM), so the
            // swallowed chunk must leave an empty-but-present placeholder;
            // pingora skips writing 0-byte chunks mid-stream. Without this,
            // chunked client requests would reach the provider as an empty
            // body after the very first chunk.
            *body = Some(Bytes::new());
            return Ok(());
        }

        // End of body: take the buffered bytes back out and transform.
        let buffer = std::mem::take(
            &mut ctx
                .get_mut::<AiProxyRequestState>(CTX_KEY_STATE)
                .expect("ai-proxy state present (ownership checked above)")
                .body,
        );

        let transformed = match transform::transform_request(
            &buffer,
            self.config.options.as_ref(),
            self.config
                .r#override
                .llm_options
                .as_ref()
                .map(|llm| llm.max_tokens),
            self.provider,
        ) {
            Ok(transformed) => transformed,
            Err(error) => {
                log::debug!("ai-proxy: request transform rejected: {}", error.detail());
                // The body phase has no short-circuit channel; the status
                // travels on the error (mapped by fail_to_proxy). The
                // response body is empty unless exit-transformer fills it.
                return Err(Error::explain(ErrorType::HTTPStatus(400), error.detail()));
            }
        };

        let state = ctx
            .get_mut::<AiProxyRequestState>(CTX_KEY_STATE)
            .expect("ai-proxy state present (ownership checked above)");
        state.streaming = transformed.streaming;
        // Generic marker: the client-format body has been replaced with the
        // provider-format one; client-format body schemas no longer apply
        // (read by request-validation, which stays decoupled from ai-proxy).
        ctx.mark_request_body_replaced();

        *body = Some(transformed.body);
        Ok(())
    }

    fn upstream_peer_filter(
        &self,
        _session: &mut Session,
        peer: &mut HttpPeer,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Only the instance that claimed this request applies its peer
        // policy; yielded or duplicate instances never touch the peer.
        if !self.owns_request(ctx) {
            return Ok(());
        }
        apply_request_peer_options(ctx, peer);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        PluginEntry, ProxyPluginExecutor, ProxyResult, RouteContext, UpstreamSelection,
    };
    use crate::utils::testing::session_from_request as session_for;
    use serde_json::{json, Value as JsonValue};

    fn json_request(content_type: Option<&str>, extra: &str) -> String {
        let body = r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
        let mut wire = String::from("POST /llm HTTP/1.1\r\nHost: t\r\n");
        if let Some(content_type) = content_type {
            wire.push_str(&format!("Content-Type: {content_type}\r\n"));
        }
        wire.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        wire.push_str(extra);
        wire
    }

    // ------------------------------------------------------------------
    // Plugin construction helpers (direct, so tests can pick the scope)
    // ------------------------------------------------------------------

    fn instance_config(port: u16, key: &str, ssl_verify: bool) -> JsonValue {
        json!({
            "provider": "openai-compatible",
            "auth": { "header": { "Authorization": format!("Bearer {key}") } },
            "override": { "endpoint": format!("http://127.0.0.1:{port}") },
            "ssl_verify": ssl_verify
        })
    }

    fn build_with_scope(cfg: JsonValue, scope: PluginScope) -> Arc<PluginAiProxy> {
        use crate::config::EffectiveDefaults;
        use crate::proxy::upstream::discovery;
        use upstream::{build_provider_upstream_config, resolve_endpoint};
        let config = config::AiProxyConfig::parse(cfg).expect("config parses");
        let endpoint = resolve_endpoint(&config).expect("endpoint resolves");
        let upstream_config = build_provider_upstream_config(&config, &endpoint).unwrap();
        let resolver = discovery::build_resolver_for_state().unwrap();
        let prepared = discovery::prepare_static_upstream(&upstream_config, &resolver).unwrap();
        Arc::new(PluginAiProxy::new(
            config,
            endpoint,
            Arc::new(
                ProxyUpstream::build(
                    upstream_config,
                    prepared,
                    &EffectiveDefaults::default(),
                    &resolver,
                )
                .unwrap(),
            ),
            scope,
        ))
    }

    struct MockRoute {
        executor: Arc<ProxyPluginExecutor>,
    }

    impl RouteContext for MockRoute {
        fn id(&self) -> &str {
            "mock-route"
        }

        fn select_upstream(&self, _session: &mut Session) -> ProxyResult<UpstreamSelection> {
            unimplemented!("not needed for ownership tests")
        }

        fn build_plugin_executor(&self) -> Arc<ProxyPluginExecutor> {
            self.executor.clone()
        }

        fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamSelector>> {
            None
        }

        fn timeout(&self) -> Option<&crate::config::Timeout> {
            None
        }
    }

    fn owner_token(ctx: &ProxyContext) -> Option<u64> {
        ctx.get::<AiProxyRequestState>(CTX_KEY_STATE)
            .map(|state| state.token)
    }

    /// Whether the plugin lets the request through (T10 verdict form of the
    /// old `Ok(false)` assertions).
    fn continues(verdict: FilterVerdict) -> bool {
        matches!(verdict, FilterVerdict::Continue)
    }

    // ------------------------------------------------------------------
    // Content-Type gate
    // ------------------------------------------------------------------

    #[test]
    fn content_type_check_accepts_exact_json_only() {
        let headers = |values: &[&str]| {
            let mut map = HeaderMap::new();
            for value in values {
                map.append(http::header::CONTENT_TYPE, value.parse().unwrap());
            }
            map
        };

        // Exact match (any case) and parameters are fine.
        assert!(content_type_error(&headers(&[])).is_none());
        assert!(content_type_error(&headers(&["application/json"])).is_none());
        assert!(content_type_error(&headers(&["APPLICATION/JSON"])).is_none());
        assert!(content_type_error(&headers(&["application/json; charset=utf-8"])).is_none());

        // Prefix look-alikes are not application/json.
        let error = content_type_error(&headers(&["application/jsonp"])).unwrap();
        assert!(error.contains("unsupported"));
        assert!(content_type_error(&headers(&["application/json-foo"])).is_some());

        // Duplicated Content-Type is ambiguous.
        let error = content_type_error(&headers(&["application/json", "text/plain"])).unwrap();
        assert!(error.contains("ambiguous"));
    }

    #[tokio::test]
    async fn request_filter_rejects_bad_content_type() {
        for content_type in [Some("application/jsonp"), Some("text/plain")] {
            let mut session = session_for(&json_request(content_type, "")).await;
            let mut ctx = ProxyContext::default();
            let plugin = build_with_scope(instance_config(19099, "k", true), PluginScope::Route);
            let verdict = plugin
                .request_filter(&mut session, &mut ctx)
                .await
                .expect("no error");
            assert!(
                matches!(verdict, FilterVerdict::Reject(ref r) if r.status == 400),
                "{content_type:?} must short-circuit with a 400 rejection"
            );
            assert!(owner_token(&ctx).is_none(), "no claim on rejection");
        }
    }

    // ------------------------------------------------------------------
    // Single-instance ownership
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn first_instance_claims_and_later_instances_noop() {
        // The claiming instance disables provider TLS verification
        // (ssl_verify=false); the later instance keeps it on.
        let first = build_with_scope(
            instance_config(19099, "first-key", false),
            PluginScope::Route,
        );
        let second = build_with_scope(
            instance_config(19098, "second-key", true),
            PluginScope::Route,
        );

        let mut session = session_for(&json_request(Some("application/json"), "")).await;
        let mut ctx = ProxyContext::default();

        // First instance claims.
        assert!(continues(
            first.request_filter(&mut session, &mut ctx).await.unwrap()
        ));
        let first_token = owner_token(&ctx).expect("first instance claimed");
        assert_eq!(first_token, first.token);
        let first_upstream = ctx
            .upstream_override
            .as_ref()
            .map(|o| Arc::as_ptr(o) as *const ());
        assert!(first_upstream.is_some());

        // A second instance never re-claims: the state, upstream override,
        // and TLS flag all stay derived from the first instance.
        assert!(continues(
            second.request_filter(&mut session, &mut ctx).await.unwrap()
        ));
        assert_eq!(owner_token(&ctx), Some(first_token));
        assert_eq!(
            ctx.upstream_override
                .as_ref()
                .map(|o| Arc::as_ptr(o) as *const ()),
            first_upstream
        );

        // The non-owner also leaves the upstream request untouched, while
        // the owner rewrites path, framing, and auth.
        let mut upstream_request = session.req_header().clone();
        second
            .upstream_request_filter(&mut session, &mut upstream_request, &mut ctx)
            .await
            .unwrap();
        assert_eq!(upstream_request.uri.path(), "/llm");
        assert!(upstream_request.headers.get("Authorization").is_none());

        // ...and does not apply its peer policy onto the selected peer
        // (only the owning instance may; a non-owner's stricter or looser
        // TLS/timeout settings must never leak onto the peer).
        let mut peer = configured_peer(60);
        second
            .upstream_peer_filter(&mut session, &mut peer, &mut ctx)
            .unwrap();
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(60)));
        assert!(
            peer.options.verify_cert,
            "non-owner must not touch the peer"
        );

        // The owning instance does apply its policy: read-timeout floor and
        // ssl_verify=false disabling provider certificate verification.
        first
            .upstream_peer_filter(&mut session, &mut peer, &mut ctx)
            .unwrap();
        assert_eq!(
            peer.options.read_timeout,
            Some(Duration::from_secs(PROVIDER_READ_TIMEOUT_FLOOR_SECS))
        );
        assert!(!peer.options.verify_cert);

        first
            .upstream_request_filter(&mut session, &mut upstream_request, &mut ctx)
            .await
            .unwrap();
        assert_eq!(upstream_request.uri.path(), "/v1/chat/completions");
        assert_eq!(
            upstream_request.headers.get("Authorization").unwrap(),
            "Bearer first-key"
        );

        // ...and does not touch the body stream.
        let mut chunk = Some(Bytes::from_static(b"{\"partial\""));
        second
            .request_body_filter(&mut session, &mut chunk, false, &mut ctx)
            .await
            .unwrap();
        assert!(chunk.is_some(), "non-owner must pass chunks through");
        assert!(ctx
            .get::<AiProxyRequestState>(CTX_KEY_STATE)
            .unwrap()
            .body
            .is_empty());
    }

    #[tokio::test]
    async fn global_instance_yields_to_route_scoped_instance() {
        let global = build_with_scope(
            instance_config(19099, "global-key", false),
            PluginScope::Global,
        );
        let route = build_with_scope(
            instance_config(19098, "route-key", true),
            PluginScope::Route,
        );

        let mut session = session_for(&json_request(Some("application/json"), "")).await;
        let mut ctx = ProxyContext {
            route: Some(Arc::new(MockRoute {
                executor: Arc::new(ProxyPluginExecutor::new(vec![PluginEntry::new(
                    route.clone() as Arc<dyn ProxyPlugin>,
                    crate::plugins::plugin_meta(PLUGIN_NAME).unwrap().phases,
                )])),
            })),
            ..ProxyContext::default()
        };

        // The global instance (even running first) does not claim...
        assert!(continues(
            global.request_filter(&mut session, &mut ctx).await.unwrap()
        ));
        assert!(owner_token(&ctx).is_none(), "global must yield");
        assert!(ctx.upstream_override.is_none());

        // ...so its credentials and ssl_verify:false never reach the request;
        // the route-scoped instance owns it alone.
        assert!(continues(
            route.request_filter(&mut session, &mut ctx).await.unwrap()
        ));
        assert_eq!(owner_token(&ctx), Some(route.token));

        let mut upstream_request = session.req_header().clone();
        global
            .upstream_request_filter(&mut session, &mut upstream_request, &mut ctx)
            .await
            .unwrap();
        assert_eq!(upstream_request.uri.path(), "/llm");

        route
            .upstream_request_filter(&mut session, &mut upstream_request, &mut ctx)
            .await
            .unwrap();
        assert_eq!(upstream_request.uri.path(), "/v1/chat/completions");
        assert_eq!(
            upstream_request.headers.get("Authorization").unwrap(),
            "Bearer route-key"
        );
        assert!(
            !ctx.get::<AiProxyRequestState>(CTX_KEY_STATE)
                .unwrap()
                .insecure_tls,
            "route's ssl_verify=true must not be poisoned by the global instance"
        );
    }

    #[tokio::test]
    async fn global_instance_claims_when_route_has_no_ai_proxy() {
        let global = build_with_scope(
            instance_config(19099, "global-key", false),
            PluginScope::Global,
        );

        let mut session = session_for(&json_request(Some("application/json"), "")).await;
        let mut ctx = ProxyContext {
            route: Some(Arc::new(MockRoute {
                executor: ProxyPluginExecutor::default_shared(),
            })),
            ..ProxyContext::default()
        };

        assert!(continues(
            global.request_filter(&mut session, &mut ctx).await.unwrap()
        ));
        assert_eq!(owner_token(&ctx), Some(global.token));
        assert!(
            ctx.get::<AiProxyRequestState>(CTX_KEY_STATE)
                .unwrap()
                .insecure_tls
        );
    }

    fn configured_peer(read_secs: u64) -> HttpPeer {
        let mut peer = HttpPeer::new("127.0.0.1:9443", true, "provider.internal".to_string());
        peer.options.read_timeout = Some(Duration::from_secs(read_secs));
        peer.options.write_timeout = Some(Duration::from_secs(60));
        peer.options.verify_cert = true;
        peer.options.verify_hostname = true;
        peer
    }

    fn request_state(insecure_tls: bool) -> AiProxyRequestState {
        AiProxyRequestState {
            token: 1,
            insecure_tls,
            streaming: false,
            body: BytesMut::new(),
        }
    }

    #[test]
    fn peer_options_floor_read_timeout_without_touching_write_or_tls() {
        let floor = Duration::from_secs(PROVIDER_READ_TIMEOUT_FLOOR_SECS);

        // Without ai-proxy state the peer is untouched.
        let mut ctx = ProxyContext::default();
        let mut peer = configured_peer(60);
        apply_request_peer_options(&ctx, &mut peer);
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(60)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(60)));
        assert!(peer.options.verify_cert);

        // With state, a short read timeout is lifted to the generous floor:
        // ai-proxy requests must not be killed between upstream reads, but a
        // stalled provider is still dropped after the floor.
        ctx.set(CTX_KEY_STATE, request_state(false));
        apply_request_peer_options(&ctx, &mut peer);
        assert_eq!(peer.options.read_timeout, Some(floor));
        assert_eq!(
            peer.options.write_timeout,
            Some(Duration::from_secs(60)),
            "write timeout stays as abuse protection"
        );
        assert!(
            peer.options.verify_cert,
            "the read floor alone must not touch TLS"
        );

        // A peer with no configured read timeout is floored too (the
        // `is_none_or` None branch): an ai-proxy request never inherits an
        // unbounded read.
        let mut peer = configured_peer(60);
        peer.options.read_timeout = None;
        apply_request_peer_options(&ctx, &mut peer);
        assert_eq!(peer.options.read_timeout, Some(floor));

        // A configured read timeout above the floor is preserved.
        let mut peer = configured_peer(3600);
        apply_request_peer_options(&ctx, &mut peer);
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn peer_options_insecure_state_disables_cert_verification_only() {
        let mut ctx = ProxyContext::default();
        ctx.set(CTX_KEY_STATE, request_state(true));
        let mut peer = configured_peer(3600);
        apply_request_peer_options(&ctx, &mut peer);
        assert!(!peer.options.verify_cert);
        assert!(!peer.options.verify_hostname);
        assert_eq!(
            peer.options.read_timeout,
            Some(Duration::from_secs(3600)),
            "insecure TLS alone must not touch timeouts"
        );
        assert_eq!(
            peer.options.write_timeout,
            Some(Duration::from_secs(60)),
            "insecure TLS alone must not touch the write timeout"
        );
    }

    #[tokio::test]
    async fn body_transform_marks_replaced_body_and_streaming() {
        let plugin = build_with_scope(instance_config(19099, "k", true), PluginScope::Route);
        let mut session = session_for(
            "POST /llm HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .await;
        let mut ctx = ProxyContext::default();
        assert!(continues(
            plugin.request_filter(&mut session, &mut ctx).await.unwrap()
        ));

        let body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        let mut chunk = Some(Bytes::from_static(body));
        plugin
            .request_body_filter(&mut session, &mut chunk, false, &mut ctx)
            .await
            .unwrap();
        // The client chunk is swallowed, but an empty-but-present placeholder
        // must remain: a None body would tell pingora the upstream body is
        // finished (terminating chunk / END_STREAM) mid-stream.
        let swallowed = chunk.expect("stream kept open with a placeholder chunk");
        assert!(
            swallowed.is_empty(),
            "chunk content must be swallowed, got {swallowed:?}"
        );
        assert!(
            !ctx.get::<AiProxyRequestState>(CTX_KEY_STATE)
                .unwrap()
                .body
                .is_empty(),
            "swallowed bytes are buffered in the request state"
        );

        let mut chunk = None;
        plugin
            .request_body_filter(&mut session, &mut chunk, true, &mut ctx)
            .await
            .unwrap();
        let transformed = chunk.expect("transformed body injected at end of stream");
        let parsed: JsonValue = serde_json::from_slice(&transformed).unwrap();
        assert_eq!(parsed["stream"], json!(true));
        assert!(
            ctx.request_body_replaced(),
            "generic body-replaced marker must be set for request-validation"
        );
        assert!(
            ctx.get::<AiProxyRequestState>(CTX_KEY_STATE)
                .unwrap()
                .streaming
        );
    }
}
