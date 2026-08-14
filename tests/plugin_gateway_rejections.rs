//! Behavioral tests for the gateway-rejection plugin family:
//! `uri-blocker`, `request-validation`, and `exit-transformer`.
//!
//! Each test drives a real `pingora_proxy::Session` with a canned HTTP/1.1
//! request (parsed through `read_request`) and captures the raw response
//! bytes the plugin writes, so status lines, headers, and bodies are asserted
//! exactly as a client would see them.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::protocols::raw_connect::ProxyDigest;
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType, IO,
};
use pingora_error::ErrorType;
use pingora_proxy::Session;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use pingsix::core::{PluginPhases, ProxyContext, ProxyPlugin, ProxyPluginExecutor};

// ---------------------------------------------------------------------------
// Mock stream: yields a canned request, then EOF; captures all writes.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct MockStream {
    to_read: Vec<u8>,
    read_offset: usize,
    written: Arc<Mutex<Vec<u8>>>,
}

impl MockStream {
    fn new(request: &[u8], written: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            to_read: request.to_vec(),
            read_offset: 0,
            written,
        }
    }
}

impl AsyncRead for MockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_offset >= self.to_read.len() {
            // EOF
            return Poll::Ready(Ok(()));
        }
        let remaining = &self.to_read[self.read_offset..];
        let n = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..n]);
        self.read_offset += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.written.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl Shutdown for MockStream {
    async fn shutdown(&mut self) {}
}

impl UniqueID for MockStream {
    fn id(&self) -> UniqueIDType {
        0
    }
}

impl Ssl for MockStream {}

impl GetTimingDigest for MockStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        Vec::new()
    }
}

impl GetProxyDigest for MockStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        None
    }
}

impl GetSocketDigest for MockStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        None
    }
}

#[async_trait]
impl Peek for MockStream {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a session whose downstream yields `request` and whose writes are
/// captured into the returned buffer.
async fn session_for(request: &[u8]) -> (Session, Arc<Mutex<Vec<u8>>>) {
    let written = Arc::new(Mutex::new(Vec::new()));
    let stream: Box<dyn IO> = Box::new(MockStream::new(request, written.clone()));
    let mut session = Session::new_h1(stream);
    session
        .downstream_session
        .read_request()
        .await
        .expect("canned request parses");
    (session, written)
}

fn status_and_body(raw: &[u8]) -> (u16, String) {
    let text = String::from_utf8_lossy(raw);
    let mut parts = text.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or_default();
    let body = parts.next().unwrap_or_default().to_string();

    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status line present");
    (status, body)
}

fn header_value(raw: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let head = text.split("\r\n\r\n").next().unwrap_or_default();
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

async fn build_plugin(name: &str, config: serde_json::Value) -> Arc<dyn ProxyPlugin> {
    pingsix::plugins::build_plugin_by_name(name, config).expect("plugin builds")
}

// ---------------------------------------------------------------------------
// uri-blocker
// ---------------------------------------------------------------------------

#[tokio::test]
async fn uri_blocker_blocks_matching_uri_with_default_403() {
    let plugin = build_plugin(
        "uri-blocker",
        serde_json::json!({ "block_rules": ["^/admin"] }),
    )
    .await;
    let (mut session, written) =
        session_for(b"GET /admin/console HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    let mut ctx = ProxyContext::default();

    let short_circuited = plugin
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error");
    assert!(short_circuited);

    let (status, body) = {
        let raw = written.lock().unwrap().clone();
        status_and_body(&raw)
    };
    assert_eq!(status, 403);
    assert!(body.is_empty(), "no rejected_msg means empty body");
}

#[tokio::test]
async fn uri_blocker_matches_query_string_and_message_is_json() {
    let plugin = build_plugin(
        "uri-blocker",
        serde_json::json!({
            "block_rules": ["token=[0-9]+"],
            "rejected_code": 418,
            "rejected_msg": "sensitive parameter"
        }),
    )
    .await;
    let (mut session, written) =
        session_for(b"GET /search?q=1&token=12345 HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    let mut ctx = ProxyContext::default();

    assert!(plugin
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error"));

    let raw = written.lock().unwrap().clone();
    let (status, body) = status_and_body(&raw);
    assert_eq!(status, 418);
    assert_eq!(body, r#"{"error_msg":"sensitive parameter"}"#);
    assert_eq!(
        header_value(&raw, "Content-Type").as_deref(),
        Some("application/json")
    );
}

#[tokio::test]
async fn uri_blocker_allows_non_matching_uri() {
    let plugin = build_plugin(
        "uri-blocker",
        serde_json::json!({ "block_rules": ["^/admin"] }),
    )
    .await;
    let (mut session, _written) =
        session_for(b"GET /public/data HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    let mut ctx = ProxyContext::default();

    assert!(!plugin
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error"));
}

// ---------------------------------------------------------------------------
// request-validation: headers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn request_validation_accepts_conforming_headers() {
    let plugin = build_plugin(
        "request-validation",
        serde_json::json!({
            "header_schema": {
                "type": "object",
                "required": ["X-Api-Version"],
                "properties": {
                    "X-Api-Version": {"type": "string", "pattern": "^v[0-9]+$"}
                }
            }
        }),
    )
    .await;
    let (mut session, _written) =
        session_for(b"GET /anything HTTP/1.1\r\nHost: example.com\r\nX-Api-Version: v2\r\n\r\n")
            .await;
    let mut ctx = ProxyContext::default();

    assert!(!plugin
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error"));
}

#[tokio::test]
async fn request_validation_rejects_bad_header_value_with_message() {
    let plugin = build_plugin(
        "request-validation",
        serde_json::json!({
            "header_schema": {
                "type": "object",
                "required": ["X-Api-Version"],
                "properties": {
                    "X-Api-Version": {"type": "string", "pattern": "^v[0-9]+$"}
                }
            },
            "rejected_code": 400,
            "rejected_msg": "invalid api version"
        }),
    )
    .await;
    let (mut session, written) =
        session_for(b"GET /anything HTTP/1.1\r\nHost: example.com\r\nX-Api-Version: 2\r\n\r\n")
            .await;
    let mut ctx = ProxyContext::default();

    assert!(plugin
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error"));

    let raw = written.lock().unwrap().clone();
    let (status, body) = status_and_body(&raw);
    assert_eq!(status, 400);
    assert_eq!(body, "invalid api version");
}

#[tokio::test]
async fn request_validation_defaults_body_to_first_schema_error() {
    let plugin = build_plugin(
        "request-validation",
        serde_json::json!({
            "header_schema": {
                "type": "object",
                "required": ["X-Mandatory"]
            }
        }),
    )
    .await;
    let (mut session, written) =
        session_for(b"GET /anything HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    let mut ctx = ProxyContext::default();

    assert!(plugin
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error"));

    let raw = written.lock().unwrap().clone();
    let (status, body) = status_and_body(&raw);
    assert_eq!(status, 400);
    assert!(
        body.contains("X-Mandatory"),
        "default body carries the schema violation, got: {body}"
    );
}

// ---------------------------------------------------------------------------
// request-validation: body
// ---------------------------------------------------------------------------

fn body_plugin(schema: serde_json::Value) -> Arc<dyn ProxyPlugin> {
    // Synchronous wrapper: the factory is sync under the hood, but tests call
    // it through the async helper for uniformity.
    futures::executor::block_on(build_plugin("request-validation", schema))
}

#[tokio::test]
async fn request_validation_passes_valid_json_body_through_whole() {
    let plugin = body_plugin(serde_json::json!({
        "body_schema": {
            "type": "object",
            "required": ["quantity"],
            "properties": {"quantity": {"type": "integer", "minimum": 1}}
        }
    }));
    let (mut session, _written) = session_for(
        b"POST /order HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"quantity\": 3, \"sku\": \"a\"}",
    )
    .await;
    let mut ctx = ProxyContext::default();

    assert!(
        !plugin
            .request_filter(&mut session, &mut ctx)
            .await
            .expect("no error"),
        "headers conform and a body is declared"
    );

    // Stream the body in two chunks, ending with end_of_stream.
    let mut first = Some(Bytes::from_static(b"{\"quantity\": 3, "));
    plugin
        .request_body_filter(&mut session, &mut first, false, &mut ctx)
        .await
        .expect("chunk accepted");
    assert!(first.is_none(), "chunk is withheld until validation");

    let mut second = Some(Bytes::from_static(b"\"sku\": \"a\"}"));
    plugin
        .request_body_filter(&mut session, &mut second, true, &mut ctx)
        .await
        .expect("body validates");

    let released = second.expect("validated body released upstream");
    assert_eq!(
        released,
        Bytes::from_static(b"{\"quantity\": 3, \"sku\": \"a\"}")
    );
}

#[tokio::test]
async fn request_validation_rejects_invalid_json_body_with_rejected_code() {
    let plugin = body_plugin(serde_json::json!({
        "body_schema": {
            "type": "object",
            "properties": {"quantity": {"type": "integer", "minimum": 1}}
        },
        "rejected_code": 422
    }));
    let (mut session, _written) = session_for(
        b"POST /order HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"quantity\": 0}",
    )
    .await;
    let mut ctx = ProxyContext::default();

    assert!(!plugin
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error"));

    let mut chunk = Some(Bytes::from_static(b"{\"quantity\": 0}"));
    let err = plugin
        .request_body_filter(&mut session, &mut chunk, true, &mut ctx)
        .await
        .expect_err("schema violation fails the request");
    assert_eq!(
        err.etype(),
        &ErrorType::HTTPStatus(422),
        "rejected_code travels on the error for fail_to_proxy mapping"
    );
}

#[tokio::test]
async fn request_validation_rejects_bodyless_request_when_body_schema_set() {
    let plugin = body_plugin(serde_json::json!({
        "body_schema": {"type": "object"}
    }));
    let (mut session, written) =
        session_for(b"GET /anything HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    let mut ctx = ProxyContext::default();

    assert!(
        plugin
            .request_filter(&mut session, &mut ctx)
            .await
            .expect("no error"),
        "GET without a body is rejected (APISIX fail-closed parity)"
    );

    let raw = written.lock().unwrap().clone();
    assert_eq!(status_and_body(&raw).0, 400);
}

#[tokio::test]
async fn request_validation_validates_form_urlencoded_bodies() {
    let plugin = body_plugin(serde_json::json!({
        "body_schema": {
            "type": "object",
            "required": ["grant_type"],
            "properties": {"grant_type": {"type": "string", "enum": ["client_credentials"]}}
        }
    }));
    let (mut session, _written) = session_for(
        b"POST /token HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 43\r\n\r\ngrant_type=client_credentials&scope=read",
    )
    .await;
    let mut ctx = ProxyContext::default();
    assert!(!plugin
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error"));

    let mut chunk = Some(Bytes::from_static(
        b"grant_type=client_credentials&scope=read",
    ));
    plugin
        .request_body_filter(&mut session, &mut chunk, true, &mut ctx)
        .await
        .expect("form body validates against the schema");
    assert!(chunk.is_some(), "valid form body released upstream");
}

#[tokio::test]
async fn request_validation_oversized_body_is_rejected() {
    let plugin = body_plugin(serde_json::json!({
        "body_schema": {"type": "object"},
        "max_req_body_size": 8
    }));
    let (mut session, _written) = session_for(
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 32\r\n\r\n{\"a\":\"0123456789ABCDEF\"}",
    )
    .await;
    let mut ctx = ProxyContext::default();
    assert!(!plugin
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error"));

    let mut chunk = Some(Bytes::from_static(b"{\"a\":\"0123456789ABCDEF\"}"));
    let err = plugin
        .request_body_filter(&mut session, &mut chunk, false, &mut ctx)
        .await
        .expect_err("body exceeds max_req_body_size");
    assert_eq!(err.etype(), &ErrorType::HTTPStatus(400));
}

// ---------------------------------------------------------------------------
// exit-transformer integration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exit_transformer_rewrites_plugin_rejection() {
    let transformer = build_plugin(
        "exit-transformer",
        serde_json::json!({
            "rules": [
                {
                    "codes": [400],
                    "status_code": 422,
                    "body": "{\"error\":true,\"origin_status\":$status,\"detail\":\"$message\"}",
                    "headers": {
                        "Content-Type": "application/json",
                        "X-Blocked": "yes"
                    }
                }
            ]
        }),
    )
    .await;
    let validation = build_plugin(
        "request-validation",
        serde_json::json!({
            "header_schema": {"type": "object", "required": ["X-Mandatory"]},
            "rejected_msg": "mandatory header missing"
        }),
    )
    .await;

    // Compose both in one route executor so the shared helper can find the
    // transform through the pipeline, exactly like production.
    let route = Arc::new(ProxyPluginExecutor::new(vec![
        validation.clone(),
        transformer.clone(),
    ]));
    let pipeline = pingsix::core::CompiledPluginPipeline::new(
        pingsix::core::ProxyPluginExecutor::default_shared(),
        route,
    );

    let (mut session, written) =
        session_for(b"GET /anything HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    let mut ctx = ProxyContext {
        pipeline,
        ..ProxyContext::default()
    };

    assert!(ctx
        .pipeline
        .clone()
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error"));

    let raw = written.lock().unwrap().clone();
    let (status, body) = status_and_body(&raw);
    assert_eq!(status, 422, "rule remaps the original 400");
    assert_eq!(
        body, r#"{"error":true,"origin_status":422,"detail":"mandatory header missing"}"#,
        "body carries the remapped status and the original rejection message"
    );
    assert_eq!(
        header_value(&raw, "Content-Type").as_deref(),
        Some("application/json"),
        "rule content type replaces the default"
    );
    assert_eq!(
        header_value(&raw, "X-Blocked").as_deref(),
        Some("yes"),
        "rule headers are appended"
    );
}

#[tokio::test]
async fn exit_transformer_route_level_overrides_global_level() {
    let blocker = build_plugin(
        "uri-blocker",
        serde_json::json!({ "block_rules": ["/forbidden"] }),
    )
    .await;
    let global_transformer = build_plugin(
        "exit-transformer",
        serde_json::json!({
            "rules": [{"codes": [403], "body": "global"}]
        }),
    )
    .await;
    let route_transformer = build_plugin(
        "exit-transformer",
        serde_json::json!({
            "rules": [{"codes": [403], "body": "route"}]
        }),
    )
    .await;

    let global = Arc::new(ProxyPluginExecutor::new(vec![
        blocker.clone(),
        global_transformer,
    ]));
    let route = Arc::new(ProxyPluginExecutor::new(vec![route_transformer]));
    let pipeline = pingsix::core::CompiledPluginPipeline::new(global, route);

    let (mut session, written) =
        session_for(b"GET /forbidden HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    let mut ctx = ProxyContext {
        pipeline,
        ..ProxyContext::default()
    };

    // Drive the global layer (where the blocker lives) through the pipeline's
    // request phase, mirroring HttpService::request_filter.
    assert!(ctx
        .pipeline
        .clone()
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("no error"));

    let raw = written.lock().unwrap().clone();
    let (status, body) = status_and_body(&raw);
    assert_eq!(status, 403);
    assert_eq!(body, "route", "more specific scope wins");
}

// ---------------------------------------------------------------------------
// Phase gating
// ---------------------------------------------------------------------------

#[test]
fn new_plugins_declare_their_phases() {
    let blocker = futures::executor::block_on(build_plugin(
        "uri-blocker",
        serde_json::json!({ "block_rules": ["x"] }),
    ));
    assert_eq!(blocker.phases(), PluginPhases::REQUEST);

    let validation = futures::executor::block_on(build_plugin(
        "request-validation",
        serde_json::json!({ "header_schema": {"type": "object"} }),
    ));
    assert_eq!(
        validation.phases(),
        PluginPhases::REQUEST | PluginPhases::REQUEST_BODY
    );

    let transformer = futures::executor::block_on(build_plugin(
        "exit-transformer",
        serde_json::json!({ "rules": [{"codes": [404]}] }),
    ));
    assert_eq!(transformer.phases(), PluginPhases::empty());
}

#[tokio::test]
async fn rejection_framing_content_length_matches_body() {
    let plugin = build_plugin(
        "uri-blocker",
        serde_json::json!({
            "block_rules": ["/x"],
            "rejected_msg": "blocked by policy"
        }),
    )
    .await;
    let (mut session, written) = session_for(b"GET /x HTTP/1.1\r\nHost: e.com\r\n\r\n").await;
    let mut ctx = ProxyContext::default();
    assert!(plugin.request_filter(&mut session, &mut ctx).await.unwrap());
    let raw = written.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&raw);
    println!("--- with body ---\n{text}");
    let body_len = status_and_body(&raw).1.len();
    assert_eq!(
        header_value(&raw, "Content-Length"),
        Some(body_len.to_string()),
        "C-L must equal actual body length"
    );
}

#[tokio::test]
async fn empty_rejection_framing_is_documented() {
    let plugin = build_plugin("uri-blocker", serde_json::json!({"block_rules": ["/x"]})).await;
    let (mut session, written) = session_for(b"GET /x HTTP/1.1\r\nHost: e.com\r\n\r\n").await;
    let mut ctx = ProxyContext::default();
    assert!(plugin.request_filter(&mut session, &mut ctx).await.unwrap());
    let raw = written.lock().unwrap().clone();
    println!("--- empty body ---\n{}", String::from_utf8_lossy(&raw));
}

#[tokio::test]
async fn empty_rejection_sets_content_length_zero_for_safe_framing() {
    let plugin = build_plugin("uri-blocker", serde_json::json!({"block_rules": ["/x"]})).await;
    let (mut session, written) = session_for(b"GET /x HTTP/1.1\r\nHost: e.com\r\n\r\n").await;
    let mut ctx = ProxyContext::default();
    assert!(plugin.request_filter(&mut session, &mut ctx).await.unwrap());
    let raw = written.lock().unwrap().clone();
    assert_eq!(
        header_value(&raw, "Content-Length").as_deref(),
        Some("0"),
        "bodyless rejection must self-describe its empty body so keep-alive framing is unambiguous"
    );
    let (status, body) = status_and_body(&raw);
    assert_eq!(status, 403);
    assert!(body.is_empty());
}

#[tokio::test]
async fn exit_transformer_body_replacement_recomputes_content_length() {
    let transformer = build_plugin(
        "exit-transformer",
        serde_json::json!({
            "rules": [{"codes": [403], "body": "{\"error\":true}", "headers": {"Content-Type": "application/json"}}]
        }),
    )
    .await;
    let blocker = build_plugin(
        "uri-blocker",
        serde_json::json!({"block_rules": ["/x"], "rejected_msg": "a-much-longer-original-rejection-message"}),
    )
    .await;
    let route = Arc::new(ProxyPluginExecutor::new(vec![blocker, transformer]));
    let pipeline = pingsix::core::CompiledPluginPipeline::new(
        pingsix::core::ProxyPluginExecutor::default_shared(),
        route,
    );
    let (mut session, written) = session_for(b"GET /x HTTP/1.1\r\nHost: e.com\r\n\r\n").await;
    let mut ctx = ProxyContext {
        pipeline,
        ..ProxyContext::default()
    };
    assert!(ctx
        .pipeline
        .clone()
        .request_filter(&mut session, &mut ctx)
        .await
        .unwrap());
    let raw = written.lock().unwrap().clone();
    let (status, body) = status_and_body(&raw);
    assert_eq!(status, 403);
    assert_eq!(body, "{\"error\":true}");
    assert_eq!(
        header_value(&raw, "Content-Length").as_deref(),
        Some("14"),
        "C-L must match the REPLACED body, not the original rejection body"
    );
}

// ---------------------------------------------------------------------------
// Pingora 响应体帧模式实证:为什么"改 body 必须前置 chunked"
// ---------------------------------------------------------------------------

#[tokio::test]
async fn content_length_mode_silently_truncates_longer_body() {
    // Pingora 在写响应头时按头选择 body 帧模式(init_body_writer):
    // 带 Content-Length 的头 -> ContentLength 模式,写满 N 字节后丢弃剩余。
    // 这就是"改了 body 不改头"的下场之一:静默截断。
    use pingora_http::ResponseHeader;
    let (mut session, written) = session_for(b"GET /x HTTP/1.1\r\nHost: e.com\r\n\r\n").await;

    let mut resp = ResponseHeader::build(http::StatusCode::OK, None).unwrap();
    resp.insert_header("Content-Length", "5").unwrap();
    session
        .write_response_header(Box::new(resp), false)
        .await
        .unwrap();
    // 实际写出 10 字节,但头声明 5
    session
        .write_response_body(Some(Bytes::from_static(b"0123456789")), true)
        .await
        .unwrap();

    let raw = written.lock().unwrap().clone();
    let split_at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator")
        + 4;
    let body = &raw[split_at..];
    assert_eq!(body, b"01234", "超出 C-L 的字节被静默截断,客户端永远收不到");
}

#[tokio::test]
async fn chunked_mode_carries_modified_body_faithfully() {
    // 同样改长 body,先在头阶段删 C-L、设 Transfer-Encoding: chunked
    // (Pingora compression 模块 set_stream_headers 的同款姿势),
    // body 以帧编码,长度变化无损传输。
    use pingora_http::ResponseHeader;
    let (mut session, written) = session_for(b"GET /x HTTP/1.1\r\nHost: e.com\r\n\r\n").await;

    let mut resp = ResponseHeader::build(http::StatusCode::OK, None).unwrap();
    resp.remove_header(&http::header::CONTENT_LENGTH);
    resp.insert_header("Transfer-Encoding", "chunked").unwrap();
    session
        .write_response_header(Box::new(resp), false)
        .await
        .unwrap();
    session
        .write_response_body(Some(Bytes::from_static(b"0123456789")), true)
        .await
        .unwrap();

    let raw = written.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&raw);
    let body_part = text.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("");
    assert!(
        body_part.starts_with("A\r\n0123456789\r\n0\r\n"),
        "chunked 帧无损携带全部 10 字节(帧长 0xA),实际: {body_part:?}"
    );
}

// ---------------------------------------------------------------------------
// 请求体改写模式实证:提前读 → 改写 → 定长放行(方案 A,ai-proxy 地基)
// ---------------------------------------------------------------------------

/// 模拟 ai-proxy 式请求体转换的探针插件:
/// request_filter 提前读完 body → 转换 → ctx 暂存;
/// upstream_request_filter 重算 C-L(发头前,帧模式按新长度初始化);
/// request_body_filter 把转换后 body 注入转发流。
use pingora_error::Result as PResult;

struct BodyRewriteProbe {
    replaced: Bytes,
    seen_original: Arc<Mutex<Option<Bytes>>>,
    injected: Arc<Mutex<Option<Bytes>>>,
}

#[async_trait]
impl ProxyPlugin for BodyRewriteProbe {
    fn name(&self) -> &str {
        "body-rewrite-probe"
    }
    fn priority(&self) -> i32 {
        100
    }
    fn phases(&self) -> PluginPhases {
        PluginPhases::REQUEST | PluginPhases::UPSTREAM_REQUEST | PluginPhases::REQUEST_BODY
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> PResult<bool> {
        // 提前把整个请求体从下游读空(APISIX ngx.req.read_body 等价物)
        let mut buf = bytes::BytesMut::new();
        while let Some(chunk) = session.downstream_session.read_request_body().await? {
            buf.extend_from_slice(&chunk);
        }
        *self.seen_original.lock().unwrap() = Some(buf.freeze());
        ctx.set("probe::replacement", self.replaced.clone());
        Ok(false)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut ProxyContext,
    ) -> PResult<()> {
        // 发头前重算 Content-Length:上游 body writer 按此初始化帧模式
        let replacement: Bytes = ctx
            .get::<Bytes>("probe::replacement")
            .cloned()
            .expect("stored in request_filter");
        upstream_request.insert_header("Content-Length", replacement.len().to_string())?;
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> PResult<()> {
        // 转发循环读到 None+end(原始流已被提前读空),注入改写后的完整 body
        if end_of_stream && body.is_none() {
            let replacement = ctx
                .vars
                .as_mut()
                .and_then(|vars| vars.remove("probe::replacement"))
                .and_then(|boxed| boxed.downcast::<Bytes>().ok())
                .map(|boxed| *boxed)
                .expect("replacement present");
            *self.injected.lock().unwrap() = Some(replacement.clone());
            *body = Some(replacement);
        }
        Ok(())
    }
}

#[tokio::test]
async fn early_read_rewrite_inject_replaces_request_body_whole() {
    use pingora_http::RequestHeader;

    let seen_original = Arc::new(Mutex::new(None));
    let injected = Arc::new(Mutex::new(None));
    let replacement = Bytes::from_static(
        b"{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"model\":\"test-model\"}",
    );

    let probe = Arc::new(BodyRewriteProbe {
        replaced: replacement.clone(),
        seen_original: seen_original.clone(),
        injected: injected.clone(),
    });

    let original = b"{\"prompt\":\"hi\"}";
    let (mut session, _w) = {
        let mut req = format!(
            "POST /v1/chat HTTP/1.1\r\nHost: gw.local\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            original.len()
        )
        .into_bytes();
        req.extend_from_slice(original);
        session_for(&req).await
    };

    let mut ctx = ProxyContext::default();
    assert!(!probe.request_filter(&mut session, &mut ctx).await.unwrap());

    // 1. 提前读到了完整原始 body
    assert_eq!(
        seen_original.lock().unwrap().as_deref(),
        Some(original.as_ref()),
        "request_filter 阶段拿到完整原始请求体"
    );

    // 2. 下游 body 已读完(转发循环随后的读取会立刻得到结束信号)
    assert!(
        session.downstream_session.is_body_done(),
        "提前读空后 Pingora 视 body 为完成,转发循环不会阻塞"
    );

    // 3. upstream_request_filter 重算 C-L 生效
    let mut upstream_req = RequestHeader::build("POST", b"/v1/chat", None).unwrap();
    probe
        .upstream_request_filter(&mut session, &mut upstream_req, &mut ctx)
        .await
        .unwrap();
    assert_eq!(
        upstream_req
            .headers
            .get("Content-Length")
            .unwrap()
            .to_str()
            .unwrap(),
        replacement.len().to_string(),
        "上游请求头携带改写后长度,上游帧模式按新长度初始化"
    );

    // 4. 转发循环到达:None+end 触发注入,改写后的完整 body 进入转发流
    let mut body = None;
    probe
        .request_body_filter(&mut session, &mut body, true, &mut ctx)
        .await
        .unwrap();
    assert_eq!(body.as_deref(), Some(replacement.as_ref()));
    assert_eq!(
        injected.lock().unwrap().as_deref(),
        Some(replacement.as_ref())
    );
}
