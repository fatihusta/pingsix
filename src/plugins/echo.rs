use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{
    core::{PluginPhases, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::config::HeaderValue,
    plugins::response_rewrite::{
        clear_body_modified_headers, is_informational_response, is_upgraded_session,
    },
};

pub const PLUGIN_NAME: &str = "echo";
const PRIORITY: i32 = 412;

/// Uniquely names every echo instance's context markers so a global and a
/// route instance never share request state.
static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

struct EchoContextKeys {
    skip_body: String,
    before_emitted: String,
}

fn echo_context_keys(instance_id: u64) -> EchoContextKeys {
    EchoContextKeys {
        skip_body: format!("pingsix_echo_skip_body_{instance_id}"),
        before_emitted: format!("pingsix_echo_before_emitted_{instance_id}"),
    }
}

/// Creates an Echo plugin instance with the given configuration.
pub fn create_echo_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    let keys = echo_context_keys(NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed));
    Ok(Arc::new(PluginEcho { config, keys }))
}

/// Configuration for the Echo plugin.
///
/// APISIX semantics: the upstream response is proxied and its body is wrapped
/// (`before_body` prefix, `after_body` suffix) or replaced (`body`) in the
/// response body phase.
#[derive(Default, Debug, Serialize, Deserialize)]
struct PluginConfig {
    /// Text prepended to the first upstream response body chunk.
    #[serde(default)]
    before_body: Option<String>,

    /// Text replacing the upstream response body (emitted at end of stream).
    #[serde(default)]
    body: Option<String>,

    /// Text appended to the last upstream response body chunk.
    #[serde(default)]
    after_body: Option<String>,

    /// Additional HTTP headers to include in the response.
    /// Keys are header names; values are strings or numbers (rendered the
    /// way APISIX assigns Lua values to headers).
    #[serde(default)]
    headers: HashMap<String, HeaderValue>,
}

impl PluginConfig {
    fn modifies_body(&self) -> bool {
        self.before_body.is_some() || self.body.is_some() || self.after_body.is_some()
    }

    fn replacement_body(&self) -> String {
        format!(
            "{}{}{}",
            self.before_body.as_deref().unwrap_or(""),
            self.body.as_deref().unwrap_or(""),
            self.after_body.as_deref().unwrap_or("")
        )
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid echo plugin config", e))?;

        if config.before_body.is_none() && config.body.is_none() && config.after_body.is_none() {
            return Err(ProxyError::validation_error(
                "at least one of 'before_body', 'body', or 'after_body' must be configured",
            ));
        }

        Ok(config)
    }
}

/// Echo plugin implementation.
pub struct PluginEcho {
    config: PluginConfig,
    keys: EchoContextKeys,
}

impl PluginEcho {
    /// Body-phase entry point, factored away from `Session` for unit tests.
    fn process_body_chunk(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) {
        if ctx
            .get::<bool>(&self.keys.skip_body)
            .copied()
            .unwrap_or(false)
        {
            return;
        }

        // APISIX `body` replaces the upstream body and is emitted once, at end
        // of stream. Intermediate upstream chunks are swallowed with an
        // empty-but-present placeholder to keep the downstream stream open.
        if self.config.body.is_some() {
            let _ = body.take();
            if end_of_stream {
                *body = Some(Bytes::from(self.config.replacement_body()));
            } else {
                *body = Some(Bytes::new());
            }
            return;
        }

        let before_emitted = ctx
            .get::<bool>(&self.keys.before_emitted)
            .copied()
            .unwrap_or(false);

        match body.take() {
            Some(mut chunk) => {
                if let Some(prefix) = self.config.before_body.as_deref() {
                    if !before_emitted {
                        let mut combined = BytesMut::with_capacity(prefix.len() + chunk.len());
                        combined.extend_from_slice(prefix.as_bytes());
                        combined.extend_from_slice(&chunk);
                        chunk = combined.freeze();
                        ctx.set(self.keys.before_emitted.clone(), true);
                    }
                }
                if end_of_stream {
                    if let Some(suffix) = self.config.after_body.as_deref() {
                        let mut combined = BytesMut::with_capacity(chunk.len() + suffix.len());
                        combined.extend_from_slice(&chunk);
                        combined.extend_from_slice(suffix.as_bytes());
                        chunk = combined.freeze();
                    }
                }
                *body = Some(chunk);
            }
            None => {
                if end_of_stream {
                    let mut out = BytesMut::new();
                    if let Some(prefix) = self.config.before_body.as_deref() {
                        if !before_emitted {
                            out.extend_from_slice(prefix.as_bytes());
                            ctx.set(self.keys.before_emitted.clone(), true);
                        }
                    }
                    if let Some(suffix) = self.config.after_body.as_deref() {
                        out.extend_from_slice(suffix.as_bytes());
                    }
                    *body = Some(out.freeze());
                } else {
                    // Keep the stream open when Pingora reports no chunk
                    // mid-stream.
                    *body = Some(Bytes::new());
                }
            }
        }
    }
}

#[async_trait]
impl ProxyPlugin for PluginEcho {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    fn phases(&self) -> PluginPhases {
        PluginPhases::RESPONSE | PluginPhases::RESPONSE_BODY
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Informational responses (e.g. 103 Early Hints, or the 101 upgrade
        // handshake) are forwarded verbatim: clearing their headers or
        // forcing chunked framing onto them would corrupt the stream.
        if is_informational_response(upstream_response) {
            return Ok(());
        }

        if self.config.modifies_body() {
            // Compressed or bodyless responses cannot be wrapped safely.
            // `Content-Encoding: identity` explicitly means "no encoding",
            // so such bodies stay plain bytes and are still wrapped
            // (mirrors response-rewrite).
            let bodyless = session.req_header().method == http::Method::HEAD
                || matches!(upstream_response.status.as_u16(), 204 | 304);
            let content_encoding = upstream_response
                .headers
                .get("Content-Encoding")
                .and_then(|value| value.to_str().ok());
            let compressed = content_encoding
                .is_some_and(|encoding| !encoding.trim().eq_ignore_ascii_case("identity"));
            if compressed || bodyless {
                log::debug!("echo: skipping body wrap for compressed/bodyless response");
                ctx.set(self.keys.skip_body.clone(), true);
            } else {
                clear_body_modified_headers(session.is_http2(), upstream_response)?;
            }
        }

        for (name, value) in &self.config.headers {
            upstream_response.insert_header(name.clone(), value.render())?;
        }

        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // An upgraded connection (101) tunnels protocol bytes (e.g.
        // WebSocket frames) through this hook as UpgradedBody tasks; they
        // are not an HTTP body and must pass through unchanged.
        if is_upgraded_session(session) {
            return Ok(());
        }
        self.process_body_chunk(body, end_of_stream, ctx);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_only_still_works() {
        let config = PluginConfig::try_from(serde_json::json!({ "body": "ok" })).unwrap();
        assert_eq!(config.replacement_body(), "ok");
    }

    #[test]
    fn before_and_after_are_concatenated_for_replacement() {
        let config = PluginConfig::try_from(serde_json::json!({
            "before_body": "before-",
            "body": "middle",
            "after_body": "-after"
        }))
        .unwrap();
        assert_eq!(config.replacement_body(), "before-middle-after");
    }

    #[test]
    fn before_or_after_alone_satisfies_anyof() {
        assert!(PluginConfig::try_from(serde_json::json!({ "before_body": "prefix" })).is_ok());
        assert!(PluginConfig::try_from(serde_json::json!({ "after_body": "suffix" })).is_ok());
        assert_eq!(
            PluginConfig::try_from(serde_json::json!({ "body": "" }))
                .unwrap()
                .replacement_body(),
            ""
        );
    }

    #[test]
    fn empty_config_is_rejected() {
        assert!(PluginConfig::try_from(serde_json::json!({})).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "headers": { "X": "y" } })).is_err());
    }

    fn plugin(cfg: JsonValue) -> PluginEcho {
        PluginEcho {
            config: PluginConfig::try_from(cfg).unwrap(),
            keys: echo_context_keys(1),
        }
    }

    #[test]
    fn body_replacement_emits_at_end_of_stream() {
        let plugin = plugin(serde_json::json!({ "body": "replacement" }));
        let mut ctx = ProxyContext::default();

        let mut chunk = Some(Bytes::from_static(b"origin"));
        plugin.process_body_chunk(&mut chunk, false, &mut ctx);
        assert_eq!(chunk, Some(Bytes::new()));

        let mut chunk = Some(Bytes::from_static(b"ignored"));
        plugin.process_body_chunk(&mut chunk, true, &mut ctx);
        assert_eq!(chunk, Some(Bytes::from_static(b"replacement")));
    }

    #[test]
    fn before_and_after_wrap_streamed_upstream_chunks() {
        let plugin = plugin(serde_json::json!({
            "before_body": "[",
            "after_body": "]"
        }));
        let mut ctx = ProxyContext::default();

        let mut chunk = Some(Bytes::from_static(b"one"));
        plugin.process_body_chunk(&mut chunk, false, &mut ctx);
        assert_eq!(chunk, Some(Bytes::from_static(b"[one")));

        let mut chunk = Some(Bytes::from_static(b"two"));
        plugin.process_body_chunk(&mut chunk, true, &mut ctx);
        assert_eq!(chunk, Some(Bytes::from_static(b"two]")));

        // The prefix is emitted exactly once.
        let mut chunk = Some(Bytes::from_static(b"second"));
        plugin.process_body_chunk(&mut chunk, true, &mut ctx);
        assert_eq!(chunk, Some(Bytes::from_static(b"second]")));
    }

    #[test]
    fn compressed_responses_are_passed_through() {
        let plugin = plugin(serde_json::json!({ "before_body": "[" }));
        let mut ctx = ProxyContext::default();
        ctx.set(plugin.keys.skip_body.clone(), true);

        let mut chunk = Some(Bytes::from_static(b"gzip-bytes"));
        plugin.process_body_chunk(&mut chunk, true, &mut ctx);
        assert_eq!(chunk, Some(Bytes::from_static(b"gzip-bytes")));
    }

    #[test]
    fn header_application_is_independent_of_body_wrap() {
        let plugin = plugin(serde_json::json!({
            "body": "x",
            "headers": {"X-Echo": "true"}
        }));
        assert!(plugin.config.headers.contains_key("X-Echo"));
    }

    // ------------------------------------------------------------------
    // Pingora session helpers (same pattern as the other plugin suites)
    // ------------------------------------------------------------------

    async fn session_for(wire: &str) -> Session {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(wire.as_bytes())
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

    /// A session whose H1 layer completed a 101 upgrade handshake, the same
    /// way Pingora's proxy loop marks a session upgraded before tunneling
    /// `HttpTask::UpgradedBody` chunks through `response_body_filter`.
    async fn upgraded_websocket_session() -> Session {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(b"GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\n\r\n")
            .await
            .expect("write upgrade request");
        let mut session = Session::new_h1(Box::new(client));
        session
            .downstream_session
            .read_request()
            .await
            .expect("upgrade request parses");

        let mut switching =
            ResponseHeader::build(http::StatusCode::SWITCHING_PROTOCOLS, None).expect("build 101");
        switching
            .insert_header("Upgrade", "websocket")
            .expect("insert upgrade header");
        session
            .downstream_session
            .write_response_header(Box::new(switching))
            .await
            .expect("finish 101 handshake");
        assert!(is_upgraded_session(&session));
        drop(server);
        session
    }

    #[tokio::test]
    async fn numeric_header_values_are_accepted_and_applied() {
        let plugin = plugin(serde_json::json!({
            "before_body": "x",
            "headers": {"X-Count": 42, "X-Ratio": 1.5}
        }));
        let mut session = session_for("GET / HTTP/1.1\r\nHost: t\r\n\r\n").await;
        let mut resp = ResponseHeader::build(http::StatusCode::OK, None).expect("build 200");
        let mut ctx = ProxyContext::default();

        plugin
            .response_filter(&mut session, &mut resp, &mut ctx)
            .await
            .expect("filter runs");

        assert_eq!(resp.headers.get("X-Count").unwrap().to_str().unwrap(), "42");
        assert_eq!(
            resp.headers.get("X-Ratio").unwrap().to_str().unwrap(),
            "1.5"
        );
    }

    #[tokio::test]
    async fn identity_encoded_bodies_are_wrapped() {
        let plugin = plugin(serde_json::json!({
            "before_body": "[",
            "after_body": "]"
        }));
        let mut session = session_for("GET / HTTP/1.1\r\nHost: t\r\n\r\n").await;
        let mut resp = ResponseHeader::build(http::StatusCode::OK, None).expect("build 200");
        resp.insert_header("Content-Encoding", "identity")
            .expect("insert encoding");
        let mut ctx = ProxyContext::default();

        plugin
            .response_filter(&mut session, &mut resp, &mut ctx)
            .await
            .expect("filter runs");

        let mut body = Some(Bytes::from_static(b"plain"));
        plugin
            .response_body_filter(&mut session, &mut body, true, &mut ctx)
            .expect("body filter runs");
        assert_eq!(body, Some(Bytes::from_static(b"[plain]")));
    }

    #[tokio::test]
    async fn informational_response_passes_through_verbatim() {
        let plugin = plugin(serde_json::json!({
            "before_body": "[",
            "after_body": "]",
            "headers": {"X-Echo": "yes"}
        }));
        let mut session = session_for("GET / HTTP/1.1\r\nHost: t\r\n\r\n").await;
        let mut hints = ResponseHeader::build(http::StatusCode::from_u16(103).unwrap(), None)
            .expect("build 103");
        hints
            .insert_header("Link", "</style.css>; rel=preload")
            .expect("insert link");
        hints
            .insert_header("Content-Length", "0")
            .expect("insert content length");
        let mut ctx = ProxyContext::default();

        plugin
            .response_filter(&mut session, &mut hints, &mut ctx)
            .await
            .expect("filter runs");

        // No header insertion, no framing rewrite: the 103 is forwarded
        // exactly as the upstream sent it.
        assert_eq!(hints.status.as_u16(), 103);
        assert_eq!(
            hints.headers.get("Link").unwrap().to_str().unwrap(),
            "</style.css>; rel=preload"
        );
        assert_eq!(hints.headers.get("Content-Length").unwrap(), "0");
        assert!(hints.headers.get("X-Echo").is_none());
        assert!(hints.headers.get("Transfer-Encoding").is_none());
    }

    #[tokio::test]
    async fn upgraded_body_frames_pass_through_unchanged() {
        let plugin = plugin(serde_json::json!({
            "before_body": "[",
            "after_body": "]"
        }));
        let mut session = upgraded_websocket_session().await;
        let mut ctx = ProxyContext::default();

        // The 101 handshake response itself is informational and passes
        // through response_filter verbatim (no forced chunked framing).
        let mut switching =
            ResponseHeader::build(http::StatusCode::SWITCHING_PROTOCOLS, None).expect("build 101");
        switching
            .insert_header("Upgrade", "websocket")
            .expect("insert upgrade header");
        plugin
            .response_filter(&mut session, &mut switching, &mut ctx)
            .await
            .expect("filter runs");
        assert_eq!(switching.status.as_u16(), 101);
        assert!(switching.headers.get("Transfer-Encoding").is_none());

        // WebSocket frames tunneled as UpgradedBody must not be wrapped,
        // buffered, or split.
        let mut frame = Some(Bytes::from_static(&[0x81, 0x02, 0x68, 0x69]));
        plugin
            .response_body_filter(&mut session, &mut frame, false, &mut ctx)
            .expect("body filter runs");
        assert_eq!(frame, Some(Bytes::from_static(&[0x81, 0x02, 0x68, 0x69])));

        let mut close_frame = Some(Bytes::from_static(&[0x88, 0x00]));
        plugin
            .response_body_filter(&mut session, &mut close_frame, true, &mut ctx)
            .expect("body filter runs");
        assert_eq!(close_frame, Some(Bytes::from_static(&[0x88, 0x00])));
    }
}
