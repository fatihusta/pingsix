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
//!                         ctx flags, switch to the provider upstream
//! upstream_request_filter provider path/query, auth headers, and replace
//!                         Content-Length with `Transfer-Encoding: chunked`
//!                         (the upstream writer becomes length-agnostic)
//! request_body_filter     buffer client chunks (bounded), transform at end
//!                         of stream, inject the transformed body as one
//!                         chunk
//! ```
//!
//! The response side is pure passthrough (APISIX ai-proxy semantics).
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
use pingora_error::{Error, ErrorType, Result};
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use std::sync::Arc;

use crate::core::{PluginPhases, ProxyContext, ProxyError, ProxyPlugin, UpstreamSelector};
use crate::utils::response::send_exit_response;

use crate::proxy::upstream::ProxyUpstream;

use config::AiProxyConfig;
use provider::{provider_spec, Provider};

pub(crate) use transform::TransformedRequest;

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

/// ctx flag marking this request as ai-proxy-owned; set in `request_filter`
/// and consumed by `upstream_request_filter` (skip guard) and
/// [`HttpService::upstream_peer`](crate::service::http::HttpService).
pub const CTX_KEY_ACTIVE: &str = "ai_proxy::active";

/// ctx key holding the [`TransformedRequest`] once the body has been
/// transformed (set in the body filter at end of stream).
///
/// Also consulted by request-validation (lower priority, same phase): when
/// present, the body the client sent has been replaced, so client-format
/// body schemas are skipped. The entry stays for the whole request because
/// body-phase plugins run after injection.
pub const CTX_KEY_TRANSFORMED: &str = "ai_proxy::transformed";

/// ctx flag marking a streaming (`"stream": true`) request. Set at end of
/// the body transform; observational in v1 (the read timeout is relaxed for
/// every ai-proxy request — see [`CTX_KEY_RELAX_READ_TIMEOUT`]).
pub const CTX_KEY_STREAMING: &str = "ai_proxy::streaming";

/// ctx flag relaxing the upstream read timeout for this request.
///
/// Set for EVERY ai-proxy request: LLM upstreams legitimately go silent for
/// long stretches — non-streaming completions before their first byte
/// ("thinking"), streaming responses between SSE chunks — and pingora's
/// `read_timeout` bounds the gap *between* reads, not the total duration.
/// Connect/write timeouts still apply per `timeout`. A total-duration bound
/// (`max_stream_duration_ms`) is v2.
pub const CTX_KEY_RELAX_READ_TIMEOUT: &str = "ai_proxy::relax_read_timeout";

/// ctx key holding the buffered (pre-transform) request body.
const CTX_KEY_BODY_BUFFER: &str = "ai_proxy::body_buffer";

/// ctx flag marking `ssl_verify: false`; consumed by
/// [`HttpService::upstream_peer`](crate::service::http::HttpService) to
/// disable peer certificate verification (not expressible on the upstream
/// resource, whose TLS block carries only client certificates).
pub const CTX_KEY_INSECURE_TLS: &str = "ai_proxy::insecure_tls";

/// Anthropic Messages API version header value (APISIX docs' canonical).
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The ai-proxy plugin.
pub struct PluginAiProxy {
    config: AiProxyConfig,
    provider: Provider,
    endpoint: ResolvedEndpoint,
    upstream: Arc<ProxyUpstream>,
}

impl PluginAiProxy {
    pub(crate) fn new(
        config: AiProxyConfig,
        endpoint: ResolvedEndpoint,
        upstream: Arc<ProxyUpstream>,
    ) -> Self {
        let provider = config.provider;
        Self {
            config,
            provider,
            endpoint,
            upstream,
        }
    }

    /// Reject through the shared exit helper (exit-transformer applies).
    /// JSON error body, mirroring the gateway's other rejections.
    async fn reject(
        session: &mut Session,
        ctx: &mut ProxyContext,
        status: u16,
        message: &str,
    ) -> Result<bool> {
        let body = serde_json::json!({ "error": message }).to_string();
        send_exit_response(
            session,
            status,
            Some(body.as_str()),
            Some("application/json"),
            &[],
            ctx,
        )
        .await?;
        Ok(true)
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
    // Keep the first-appearance order, last value per key.
    let mut deduped: Vec<(String, String)> = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        if let Some(existing) = deduped.iter_mut().find(|(k, _)| k == &key) {
            existing.1 = value;
        } else {
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

    fn phases(&self) -> PluginPhases {
        PluginPhases::REQUEST | PluginPhases::UPSTREAM_REQUEST | PluginPhases::REQUEST_BODY
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        // APISIX parity: absent Content-Type defaults to JSON; a present one
        // must be application/json.
        let content_type_json = session
            .req_header()
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("application/json")
            })
            .unwrap_or(true);
        if !content_type_json {
            return Self::reject(
                session,
                ctx,
                400,
                "unsupported content-type: only application/json is supported",
            )
            .await;
        }

        if !request_declares_body(&session.req_header().headers) {
            return Self::reject(session, ctx, 400, "request body required").await;
        }

        // Header-only decisions. The body is intentionally NOT read here:
        // fully draining it would deadlock pingora 0.8's h1 proxy loop (see
        // the module docs); the body is buffered and transformed in
        // `request_body_filter` instead.
        ctx.set(CTX_KEY_ACTIVE, true);
        ctx.set(CTX_KEY_RELAX_READ_TIMEOUT, true);
        if !self.config.ssl_verify {
            ctx.set(CTX_KEY_INSECURE_TLS, true);
        }

        // Switch this request onto the provider upstream.
        ctx.upstream_override = Some(self.upstream.clone() as Arc<dyn UpstreamSelector>);
        Ok(false)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Only rewrite when this plugin owns the request (request_filter
        // short-circuited otherwise).
        if ctx.get::<bool>(CTX_KEY_ACTIVE).copied() != Some(true) {
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
        if ctx.get::<bool>(CTX_KEY_ACTIVE).copied() != Some(true) {
            return Ok(());
        }

        // Swallow client chunks into the per-request buffer; nothing reaches
        // the provider before the transform (request-validation pattern).
        if let Some(chunk) = body.take() {
            let buffer = ctx
                .vars
                .get_or_insert_with(Default::default)
                .entry(CTX_KEY_BODY_BUFFER.to_string())
                .or_insert_with(|| Box::new(BytesMut::new()));
            let buffer = buffer
                .downcast_mut::<BytesMut>()
                .expect("ai-proxy body buffer");
            buffer.extend_from_slice(&chunk);
            if buffer.len() as u64 > self.config.max_req_body_size {
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
            return Ok(());
        }

        // End of body: take the buffer back out and transform.
        let buffer = ctx
            .vars
            .as_mut()
            .and_then(|vars| vars.remove(CTX_KEY_BODY_BUFFER))
            .and_then(|boxed| boxed.downcast::<BytesMut>().ok())
            .map(|boxed| *boxed)
            .unwrap_or_default();

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

        if transformed.streaming {
            ctx.set(CTX_KEY_STREAMING, true);
        }
        // Marker for request-validation (same phase, lower priority): the
        // client-format body schema no longer applies.
        ctx.set(CTX_KEY_TRANSFORMED, transformed.clone());

        *body = Some(transformed.body);
        Ok(())
    }
}

/// Whether an ai-proxy-transformed request is on this context.
pub(crate) fn transformed_request_present(ctx: &ProxyContext) -> bool {
    ctx.get::<TransformedRequest>(CTX_KEY_TRANSFORMED).is_some()
}
