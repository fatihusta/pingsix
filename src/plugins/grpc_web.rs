use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::header;
use pingora::modules::http::grpc_web::GrpcWebBridge;
use pingora_error::{Error, ErrorType, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult, Rejection},
    plugins::{config::parse_and_validate_plugin_config, ctx_keys::next_instance_ctx_key},
    utils::response::content_type,
};

pub const PLUGIN_NAME: &str = "grpc-web";
const PRIORITY: i32 = 505;

/// APISIX default maximum gRPC-Web request body size (64 MiB).
const DEFAULT_MAX_REQ_BODY_SIZE: u64 = 64 * 1024 * 1024;
/// APISIX default CORS allow-headers list for gRPC-Web responses.
const DEFAULT_CORS_ALLOW_HEADERS: &str = "content-type,x-grpc-web,x-user-agent";
/// Headers APISIX exposes on gRPC-Web responses.
const GRPC_WEB_EXPOSE_HEADERS: &str = "grpc-message,grpc-status";
const GRPC_WEB_ALLOW_METHODS: &str = "POST";

/// Creates a gRPC-Web plugin instance.
///
/// The plugin initializes Pingora's `GrpcWebBridge` for each request, enforces
/// the configured maximum request body size while the body streams, and adds
/// the APISIX-compatible CORS headers to gRPC-Web responses.
pub fn create_grpc_web_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginGrpcWeb {
        config,
        body_bytes_key: next_instance_ctx_key("pingsix_grpc_web_body_bytes_"),
        request_marker_key: next_instance_ctx_key("pingsix_grpc_web_request_"),
        request_marker_text_key: next_instance_ctx_key("pingsix_grpc_web_request_text_"),
    }))
}

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators WITHOUT constructing the plugin.
pub fn validate_grpc_web_config(cfg: &JsonValue) -> ProxyResult<()> {
    PluginConfig::try_from(cfg.clone())?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    #[serde(default = "PluginConfig::default_max_req_body_size")]
    #[validate(range(min = 1))]
    max_req_body_size: u64,
    #[serde(default = "PluginConfig::default_cors_allow_headers")]
    #[validate(length(min = 1))]
    cors_allow_headers: String,
}

impl PluginConfig {
    fn default_max_req_body_size() -> u64 {
        DEFAULT_MAX_REQ_BODY_SIZE
    }

    fn default_cors_allow_headers() -> String {
        DEFAULT_CORS_ALLOW_HEADERS.to_string()
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        parse_and_validate_plugin_config(value, "Invalid grpc-web plugin config")
    }
}

/// gRPC-Web plugin implementation.
pub struct PluginGrpcWeb {
    config: PluginConfig,
    /// Per-instance context key for the body counter. Separate from the shared
    /// `ctx.request_body_bytes` so a route that also enables client-control
    /// does not count every chunk twice.
    body_bytes_key: String,
    /// Records whether the original header was gRPC-Web before Pingora's
    /// downstream module rewrites it to `application/grpc*`.
    request_marker_key: String,
    /// Records whether the original content type was the base64
    /// `application/grpc-web-text*` variant, which must be rejected (see
    /// [`PluginGrpcWeb::request_filter`]).
    request_marker_text_key: String,
}

#[cfg(test)]
fn body_bytes_key(instance_id: u64) -> String {
    crate::plugins::ctx_keys::instance_ctx_key("pingsix_grpc_web_body_bytes_", instance_id)
}

#[cfg(test)]
fn request_marker_key(instance_id: u64) -> String {
    crate::plugins::ctx_keys::instance_ctx_key("pingsix_grpc_web_request_", instance_id)
}

#[cfg(test)]
fn request_marker_text_key(instance_id: u64) -> String {
    crate::plugins::ctx_keys::instance_ctx_key("pingsix_grpc_web_request_text_", instance_id)
}

fn has_grpc_web_content_type(session: &Session) -> bool {
    grpc_web_content_type_prefix(session)
        .is_some_and(|value| value.starts_with("application/grpc-web"))
}

fn has_grpc_web_text_content_type(session: &Session) -> bool {
    grpc_web_content_type_prefix(session)
        .is_some_and(|value| value.starts_with("application/grpc-web-text"))
}

/// Lowercased, trimmed original request Content-Type (before Pingora's
/// downstream module can rewrite it to `application/grpc`).
fn grpc_web_content_type_prefix(session: &Session) -> Option<String> {
    session
        .req_header()
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim_start().to_ascii_lowercase())
}

impl PluginGrpcWeb {
    /// Whether adding `chunk_len` bytes to `accumulated` exceeds `limit`.
    fn exceeds_after_chunk(limit: u64, accumulated: u64, chunk_len: usize) -> bool {
        accumulated.saturating_add(chunk_len as u64) > limit
    }
}

#[async_trait]
impl ProxyPlugin for PluginGrpcWeb {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        let is_grpc_web = has_grpc_web_content_type(session);
        ctx.set(self.request_marker_key.clone(), is_grpc_web);
        ctx.set(
            self.request_marker_text_key.clone(),
            has_grpc_web_text_content_type(session),
        );

        let Some(grpc) = session.downstream_modules_ctx.get_mut::<GrpcWebBridge>() else {
            return Ok(());
        };

        // Initialize gRPC module for this request. The module itself only
        // transitions to Upgrade for the marked gRPC-Web content types.
        grpc.init();
        Ok(())
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        // CORS/expose headers are attached to every local grpc-web answer.
        let cors_headers = |r: Rejection| {
            r.with_header("Access-Control-Allow-Origin", "*")
                .with_header("Access-Control-Expose-Headers", GRPC_WEB_EXPOSE_HEADERS)
        };

        // APISIX grpc-web is strict: OPTIONS is answered locally as a CORS
        // preflight, POST is the only proxied method, and every proxied
        // request must carry a gRPC-Web content type.
        if session.req_header().method == http::Method::OPTIONS {
            return Ok(FilterVerdict::Reject(
                Rejection::new(http::StatusCode::NO_CONTENT)
                    .with_header("Access-Control-Allow-Methods", GRPC_WEB_ALLOW_METHODS)
                    .with_header(
                        "Access-Control-Allow-Headers",
                        self.config.cors_allow_headers.clone(),
                    )
                    .with_header("Access-Control-Allow-Origin", "*")
                    .with_header("Access-Control-Expose-Headers", GRPC_WEB_EXPOSE_HEADERS),
            ));
        }

        if session.req_header().method != http::Method::POST {
            return Ok(FilterVerdict::Reject(cors_headers(Rejection::new(
                http::StatusCode::METHOD_NOT_ALLOWED,
            ))));
        }

        // `application/grpc-web-text*` carries base64-framed bodies. APISIX
        // transcodes them; Pingora's bridge accepts the content type but
        // passes the base64 bytes through unconverted, corrupting the gRPC
        // upstream stream. Fail closed with a clear error instead.
        if ctx
            .get::<bool>(&self.request_marker_text_key)
            .copied()
            .unwrap_or(false)
        {
            return Ok(FilterVerdict::Reject(cors_headers(
                Rejection::new(http::StatusCode::BAD_REQUEST)
                    .with_body("grpc-web-text (base64) content type is not supported")
                    .with_content_type(content_type::TEXT_PLAIN),
            )));
        }

        if !ctx
            .get::<bool>(&self.request_marker_key)
            .copied()
            .unwrap_or(false)
        {
            return Ok(FilterVerdict::Reject(cors_headers(Rejection::new(
                http::StatusCode::BAD_REQUEST,
            ))));
        }

        Ok(FilterVerdict::Continue)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Use the pre-module marker rather than the rewritten Content-Type;
        // native application/grpc requests must not be mistaken for gRPC-Web.
        if !ctx
            .get::<bool>(&self.request_marker_key)
            .copied()
            .unwrap_or(false)
        {
            return Ok(());
        }
        let limit = self.config.max_req_body_size;
        if let Some(bytes) = body {
            let accumulated = ctx.get::<u64>(&self.body_bytes_key).copied().unwrap_or(0);
            if Self::exceeds_after_chunk(limit, accumulated, bytes.len()) {
                let total = accumulated.saturating_add(bytes.len() as u64);
                ctx.set(self.body_bytes_key.clone(), total);
                log::debug!("grpc-web: streamed {total} bytes exceeds limit {limit}");
                return Err(Error::explain(
                    ErrorType::HTTPStatus(413),
                    format!("request body exceeded max_req_body_size {limit}"),
                ));
            }
            ctx.set(
                self.body_bytes_key.clone(),
                accumulated.saturating_add(bytes.len() as u64),
            );
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Gate on the request marker, not the response Content-Type: a gRPC
        // upstream answers `application/grpc`, and Pingora's GrpcWebBridge
        // only converts it to `application/grpc-web` later (inside
        // `write_response_tasks`, after plugin filters run). Every request
        // that reached the upstream through this plugin is a gRPC-Web request
        // (all others were rejected in `request_filter`), so APISIX's
        // unconditional header emission is mirrored here.
        if ctx
            .get::<bool>(&self.request_marker_key)
            .copied()
            .unwrap_or(false)
        {
            apply_grpc_web_cors_headers(upstream_response, &self.config.cors_allow_headers)?;
        }
        Ok(())
    }
}

/// Insert APISIX-compatible CORS headers on the response of a handled
/// gRPC-Web request. The caller is responsible for gating on the request
/// marker (see [`PluginGrpcWeb::response_filter`]).
fn apply_grpc_web_cors_headers(resp: &mut ResponseHeader, allow_headers: &str) -> Result<()> {
    resp.insert_header(header::ACCESS_CONTROL_ALLOW_HEADERS, allow_headers)?;
    resp.insert_header(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        GRPC_WEB_EXPOSE_HEADERS,
    )?;
    if resp
        .headers
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none()
    {
        resp.insert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_match_apisix() {
        let config = PluginConfig::try_from(serde_json::json!({})).unwrap();
        assert_eq!(config.max_req_body_size, 64 * 1024 * 1024);
        assert_eq!(
            config.cors_allow_headers,
            "content-type,x-grpc-web,x-user-agent"
        );
    }

    #[test]
    fn config_accepts_explicit_values() {
        let config = PluginConfig::try_from(serde_json::json!({
            "max_req_body_size": 1024,
            "cors_allow_headers": "x-custom"
        }))
        .unwrap();
        assert_eq!(config.max_req_body_size, 1024);
        assert_eq!(config.cors_allow_headers, "x-custom");
    }

    #[test]
    fn config_rejects_invalid_values() {
        assert!(PluginConfig::try_from(serde_json::json!({ "max_req_body_size": 0 })).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "cors_allow_headers": "" })).is_err());
    }

    #[test]
    fn body_limit_helper_reports_exceeding_chunks() {
        assert!(!PluginGrpcWeb::exceeds_after_chunk(10, 0, 10));
        assert!(PluginGrpcWeb::exceeds_after_chunk(10, 0, 11));
        assert!(PluginGrpcWeb::exceeds_after_chunk(10, 8, 3));
        assert!(!PluginGrpcWeb::exceeds_after_chunk(10, 8, 2));
    }

    fn response_with_content_type(content_type: &str) -> ResponseHeader {
        let mut resp = ResponseHeader::build(http::StatusCode::OK, None).unwrap();
        resp.insert_header(header::CONTENT_TYPE, content_type)
            .unwrap();
        resp
    }

    async fn session_with_content_type(content_type: &str) -> Session {
        use tokio::io::AsyncWriteExt;

        let (client, mut server) = tokio::io::duplex(1024);
        server
            .write_all(
                format!("POST /rpc HTTP/1.1\r\nHost: t\r\nContent-Type: {content_type}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        drop(server);
        let mut session = Session::new_h1(Box::new(client));
        session.downstream_session.read_request().await.unwrap();
        session
    }

    #[test]
    fn cors_headers_are_inserted_for_handled_grpc_web_responses() {
        // The gate is the request marker (set from the ORIGINAL request
        // Content-Type); the upstream content type at response-filter time is
        // `application/grpc` because the bridge converts it later.
        let mut resp = response_with_content_type("application/grpc");
        apply_grpc_web_cors_headers(&mut resp, "content-type,x-grpc-web,x-user-agent").unwrap();
        assert_eq!(
            resp.headers
                .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                .unwrap()
                .to_str()
                .unwrap(),
            "content-type,x-grpc-web,x-user-agent"
        );
        assert_eq!(
            resp.headers
                .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                .unwrap()
                .to_str()
                .unwrap(),
            GRPC_WEB_EXPOSE_HEADERS
        );
        assert_eq!(
            resp.headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            "*"
        );
    }

    #[test]
    fn existing_allow_origin_is_preserved() {
        let mut resp = response_with_content_type("application/grpc-web");
        resp.insert_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "https://app.example")
            .unwrap();
        apply_grpc_web_cors_headers(&mut resp, "x-custom").unwrap();
        assert_eq!(
            resp.headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .to_str()
                .unwrap(),
            "https://app.example"
        );
    }

    fn plugin() -> PluginGrpcWeb {
        PluginGrpcWeb {
            config: PluginConfig::try_from(serde_json::json!({})).unwrap(),
            body_bytes_key: body_bytes_key(9901),
            request_marker_key: request_marker_key(9901),
            request_marker_text_key: request_marker_text_key(9901),
        }
    }

    #[tokio::test]
    async fn response_filter_applies_cors_headers_for_marked_grpc_requests() {
        // A gRPC upstream answering `application/grpc`: with the old
        // response-Content-Type gate these headers were never inserted
        // (the bridge converts the content type only after plugin filters).
        let mut resp = response_with_content_type("application/grpc");
        let mut session = session_with_content_type("application/grpc-web+proto").await;
        let mut ctx = ProxyContext::default();
        ctx.set(plugin().request_marker_key.clone(), true);
        plugin()
            .response_filter(&mut session, &mut resp, &mut ctx)
            .await
            .unwrap();
        assert!(resp
            .headers
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .is_some());
        assert!(resp
            .headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_some());
    }

    #[tokio::test]
    async fn response_filter_skips_unmarked_requests() {
        let mut resp = response_with_content_type("application/grpc-web");
        let mut session = session_with_content_type("application/grpc-web+proto").await;
        let mut ctx = ProxyContext::default();
        ctx.set(plugin().request_marker_key.clone(), false);
        plugin()
            .response_filter(&mut session, &mut resp, &mut ctx)
            .await
            .unwrap();
        assert!(resp
            .headers
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .is_none());
    }

    #[tokio::test]
    async fn grpc_web_text_content_type_is_detected_for_rejection() {
        for content_type in [
            "application/grpc-web-text",
            "application/grpc-web-text+proto",
            "Application/GRPC-Web-Text; charset=utf-8",
        ] {
            assert!(
                has_grpc_web_text_content_type(&session_with_content_type(content_type).await),
                "{content_type} must be detected as grpc-web-text"
            );
        }
        for content_type in ["application/grpc-web", "application/grpc-web+proto"] {
            assert!(!has_grpc_web_text_content_type(
                &session_with_content_type(content_type).await
            ));
        }
    }

    #[tokio::test]
    async fn request_content_type_gating_is_case_insensitive() {
        for content_type in [
            "application/grpc-web",
            "application/grpc-web+proto; charset=utf-8",
            "Application/GRPC-Web-Text",
        ] {
            assert!(has_grpc_web_content_type(
                &session_with_content_type(content_type).await
            ));
        }
        for content_type in [
            "application/grpc",
            "application/grpc+proto",
            "application/json",
        ] {
            assert!(!has_grpc_web_content_type(
                &session_with_content_type(content_type).await
            ));
        }
    }
}
