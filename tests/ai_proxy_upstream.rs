//! End-to-end ai-proxy tests: a real gateway (static YAML config, no etcd)
//! against a local mock LLM provider.
//!
//! These tests assert what the provider actually receives on the wire —
//! request line, headers (auth injection, chunked framing, Content-Type),
//! and the exact transformed JSON body — plus the client-visible error
//! paths (400 content-type, 400 transform failures, 413 body cap) and the
//! global-rule/route ownership precedence across a real pipeline.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use common::*;

// ---------------------------------------------------------------------------
// Mock LLM provider: captures complete HTTP/1.1 requests (decoding chunked
// bodies) and answers with a canned chat completion.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CapturedRequest {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn method(&self) -> &str {
        self.request_line.split_whitespace().next().unwrap_or("")
    }

    fn path(&self) -> &str {
        self.request_line.split_whitespace().nth(1).unwrap_or("")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct MockProvider {
    port: u16,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockProvider {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let captured_c = captured.clone();
        let stop_c = stop.clone();
        let handle = std::thread::spawn(move || {
            while !stop_c.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if let Some(request) = read_complete_request(&mut stream) {
                            captured_c.lock().unwrap().push(request);
                            write_completion_response(&mut stream);
                        }
                        // Incomplete requests (e.g. the gateway aborting after
                        // a body-phase rejection) are dropped without a
                        // response; they never count as "reached".
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            captured,
            stop,
            handle: Some(handle),
        }
    }

    /// Complete requests captured so far, in arrival order.
    fn requests(&self) -> Vec<CapturedRequest> {
        self.captured.lock().unwrap().clone()
    }
}

impl Drop for MockProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Read one full HTTP/1.1 request (headers + body per framing) from `stream`.
/// Returns `None` on EOF/timeout/incomplete framing.
fn read_complete_request(stream: &mut TcpStream) -> Option<CapturedRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];

    // Phase 1: read until the end of the header block.
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator found above");
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let mut rest = buf[split + 4..].to_vec();

    let mut lines = head.lines();
    let request_line = lines.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    let is_chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    let content_length: Option<usize> = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok());

    // Phase 2: read the body to completion.
    let body = if is_chunked {
        loop {
            if let Some(decoded) = decode_chunked(&rest) {
                break decoded;
            }
            match stream.read(&mut chunk) {
                Ok(0) => return None,
                Ok(n) => rest.extend_from_slice(&chunk[..n]),
                Err(_) => return None,
            }
        }
    } else if let Some(length) = content_length {
        while rest.len() < length {
            match stream.read(&mut chunk) {
                Ok(0) => return None,
                Ok(n) => rest.extend_from_slice(&chunk[..n]),
                Err(_) => return None,
            }
        }
        rest.truncate(length);
        rest
    } else {
        Vec::new()
    };

    Some(CapturedRequest {
        request_line,
        headers,
        body,
    })
}

/// Decode a complete chunked body; `None` while framing is still incomplete.
fn decode_chunked(raw: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut pos = 0;
    loop {
        let line_end = raw[pos..].windows(2).position(|w| w == b"\r\n")? + pos;
        let size_line = std::str::from_utf8(&raw[pos..line_end]).ok()?;
        let size_hex = size_line.split(';').next()?.trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        pos = line_end + 2;
        if size == 0 {
            return Some(decoded); // terminal chunk (trailers not expected)
        }
        if raw.len() < pos + size + 2 {
            return None;
        }
        decoded.extend_from_slice(&raw[pos..pos + size]);
        pos += size + 2; // data + trailing CRLF
    }
}

fn write_completion_response(stream: &mut TcpStream) {
    let body = r#"{"id":"chatcmpl-mock","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"mock-reply"},"finish_reason":"stop"}]}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

// ---------------------------------------------------------------------------
// Gateway boot helpers (static YAML, mirroring protocol_defaults.rs).
// ---------------------------------------------------------------------------

fn spawn_gateway(listen_port: u16, status_port: u16, resources_yaml: &str) -> (String, Child) {
    let yaml = format!(
        r#"{}
pingsix:
  listeners:
    - address: "127.0.0.1:{listen_port}"
  status:
    address: "127.0.0.1:{status_port}"

{resources_yaml}
"#,
        pingora_header(listen_port)
    );
    let config_path = write_config(listen_port, &yaml);
    let child = spawn_pingsix(&config_path);
    assert!(
        wait_until_ready(status_port, Duration::from_secs(15)),
        "static ai-proxy config should become ready"
    );
    (config_path, child)
}

fn shutdown_gateway(listen_port: u16, config_path: &str, child: &mut Child) {
    sigterm(child);
    let _ = wait_exit(child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, config_path);
}

/// An ai-proxy plugin config (JSON; YAML accepts it inline) pointing at the
/// mock provider with a bearer key and optional extra fields merged in.
fn ai_proxy_json(provider_port: u16, key: &str, extra: serde_json::Value) -> String {
    let mut config = serde_json::json!({
        "provider": "openai-compatible",
        "auth": { "header": { "Authorization": format!("Bearer {key}") } },
        "override": { "endpoint": format!("http://127.0.0.1:{provider_port}") },
    });
    if let (Some(base), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
        for (field, value) in extra {
            base.insert(field.clone(), value.clone());
        }
    }
    config.to_string()
}

fn route_with_ai_proxy(uri: &str, plugin_json: &str, provider_port: u16) -> String {
    format!(
        r#"
routes:
  - id: "1"
    uri: {uri}
    plugins:
      ai-proxy: {plugin_json}
    upstream:
      nodes:
        "127.0.0.1:{provider_port}": 1
      type: roundrobin
"#
    )
}

const CLIENT_BODY: &str =
    r#"{"model":"client-model","messages":[{"role":"user","content":"hi"}],"max_tokens":8}"#;

/// POST with a Content-Length body through the gateway.
fn post_json(addr: &str, path: &str, body: &str) -> HttpResponse {
    http_exchange(
        addr,
        "POST",
        path,
        &[("Content-Type", "application/json")],
        Some(body),
    )
    .expect("gateway reachable")
}

// ---------------------------------------------------------------------------
// Happy path: what the provider receives on the wire.
// ---------------------------------------------------------------------------

#[test]
fn upstream_receives_transformed_request_with_auth_and_chunked_framing() {
    let provider = MockProvider::start();
    let listen_port = random_port();
    let status_port = random_port();

    let plugin = ai_proxy_json(
        provider.port,
        "route-key",
        serde_json::json!({
            "options": { "temperature": 0.2 },
            "override": { "endpoint": format!("http://127.0.0.1:{}", provider.port), "llm_options": { "max_tokens": 2048 } }
        }),
    );
    let (config_path, mut child) = spawn_gateway(
        listen_port,
        status_port,
        &route_with_ai_proxy("/llm", &plugin, provider.port),
    );
    let addr = format!("127.0.0.1:{listen_port}");

    // The client's own Authorization must not survive: provider auth wins.
    let response = http_exchange(
        &addr,
        "POST",
        "/llm",
        &[
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer client-should-be-dropped"),
        ],
        Some(CLIENT_BODY),
    )
    .expect("gateway reachable");

    assert_eq!(response.status, 200, "{}", response.body);
    assert!(response.body.contains("mock-reply"));

    let requests = provider.requests();
    assert_eq!(requests.len(), 1, "exactly one upstream request");
    let upstream = &requests[0];
    assert_eq!(upstream.method(), "POST");
    assert_eq!(upstream.path(), "/v1/chat/completions");
    assert_eq!(upstream.header("Authorization"), Some("Bearer route-key"));
    assert_eq!(upstream.header("Content-Type"), Some("application/json"));

    // Chunked framing: the transformed length is unknown until end of body.
    assert!(
        upstream
            .header("Transfer-Encoding")
            .is_some_and(|v| v.contains("chunked")),
        "upstream request must be chunked: {:?}",
        upstream.headers
    );
    assert!(upstream.header("Content-Length").is_none());

    let body: serde_json::Value = serde_json::from_slice(&upstream.body).expect("valid JSON");
    assert_eq!(body["model"], "client-model");
    assert_eq!(body["temperature"], 0.2, "options must deep-merge");
    assert_eq!(
        body["max_tokens"], 2048,
        "forced llm_options.max_tokens must win"
    );

    shutdown_gateway(listen_port, &config_path, &mut child);
}

// ---------------------------------------------------------------------------
// Multi-chunk downstream bodies are buffered and transformed as a whole.
// ---------------------------------------------------------------------------

#[test]
fn client_chunked_body_is_buffered_and_transformed_as_a_whole() {
    let provider = MockProvider::start();
    let listen_port = random_port();
    let status_port = random_port();

    let plugin = ai_proxy_json(provider.port, "chunked-key", serde_json::json!({}));
    let (config_path, mut child) = spawn_gateway(
        listen_port,
        status_port,
        &route_with_ai_proxy("/llm", &plugin, provider.port),
    );

    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect gateway");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let head = "POST /llm HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    stream.write_all(head.as_bytes()).unwrap();

    // Split the client body across several chunked frames, with pauses so
    // the gateway's body filter observes multiple partial reads.
    let bytes = CLIENT_BODY.as_bytes();
    for piece in [
        (&bytes[..13], 30u64),
        (&bytes[13..40], 30),
        (&bytes[40..], 0),
    ] {
        std::thread::sleep(Duration::from_millis(piece.1.max(1)));
        stream
            .write_all(format!("{:x}\r\n", piece.0.len()).as_bytes())
            .unwrap();
        stream.write_all(piece.0).unwrap();
        stream.write_all(b"\r\n").unwrap();
    }
    stream.write_all(b"0\r\n\r\n").unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let (status, body) = status_and_body(&raw);
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("mock-reply"));

    let requests = provider.requests();
    assert_eq!(requests.len(), 1);
    let upstream = &requests[0];
    let parsed: serde_json::Value =
        serde_json::from_slice(&upstream.body).expect("full transformed body");
    assert_eq!(parsed["model"], "client-model");
    assert_eq!(
        parsed["messages"][0]["content"], "hi",
        "all client chunks must be reassembled before the transform"
    );

    shutdown_gateway(listen_port, &config_path, &mut child);
}

// ---------------------------------------------------------------------------
// Error paths: client-visible status and "provider never fully reached".
// ---------------------------------------------------------------------------

#[test]
fn bad_content_type_is_rejected_before_reaching_the_provider() {
    let provider = MockProvider::start();
    let listen_port = random_port();
    let status_port = random_port();

    let plugin = ai_proxy_json(provider.port, "k", serde_json::json!({}));
    let (config_path, mut child) = spawn_gateway(
        listen_port,
        status_port,
        &route_with_ai_proxy("/llm", &plugin, provider.port),
    );

    for content_type in ["text/plain", "application/jsonp"] {
        let response = http_exchange(
            &format!("127.0.0.1:{listen_port}"),
            "POST",
            "/llm",
            &[("Content-Type", content_type)],
            Some(CLIENT_BODY),
        )
        .expect("gateway reachable");
        assert_eq!(response.status, 400, "{content_type}: {}", response.body);
    }

    assert!(
        provider.requests().is_empty(),
        "no upstream request may complete for a rejected content type"
    );
    shutdown_gateway(listen_port, &config_path, &mut child);
}

#[test]
fn invalid_json_body_is_rejected_with_400_not_forwarded() {
    let provider = MockProvider::start();
    let listen_port = random_port();
    let status_port = random_port();

    let plugin = ai_proxy_json(provider.port, "k", serde_json::json!({}));
    let (config_path, mut child) = spawn_gateway(
        listen_port,
        status_port,
        &route_with_ai_proxy("/llm", &plugin, provider.port),
    );

    let response = post_json(&format!("127.0.0.1:{listen_port}"), "/llm", "{not json");
    assert_eq!(response.status, 400, "{}", response.body);
    assert!(
        provider.requests().is_empty(),
        "an untransformable body must never fully reach the provider"
    );
    shutdown_gateway(listen_port, &config_path, &mut child);
}

#[test]
fn oversized_body_is_rejected_with_413() {
    let provider = MockProvider::start();
    let listen_port = random_port();
    let status_port = random_port();

    let plugin = ai_proxy_json(
        provider.port,
        "k",
        serde_json::json!({ "max_req_body_size": 32 }),
    );
    let (config_path, mut child) = spawn_gateway(
        listen_port,
        status_port,
        &route_with_ai_proxy("/llm", &plugin, provider.port),
    );

    let response = post_json(&format!("127.0.0.1:{listen_port}"), "/llm", CLIENT_BODY);
    assert_eq!(response.status, 413, "{}", response.body);
    assert!(
        provider.requests().is_empty(),
        "an oversized body must never fully reach the provider"
    );
    shutdown_gateway(listen_port, &config_path, &mut child);
}

// ---------------------------------------------------------------------------
// Scope precedence across a real global+route pipeline.
// ---------------------------------------------------------------------------

#[test]
fn route_scoped_ai_proxy_overrides_the_global_rule() {
    let provider = MockProvider::start();
    let listen_port = random_port();
    let status_port = random_port();

    let global = ai_proxy_json(provider.port, "global-key", serde_json::json!({}));
    let route = ai_proxy_json(provider.port, "route-key", serde_json::json!({}));
    let resources = format!(
        r#"
global_rules:
  - id: "g1"
    plugins:
      ai-proxy: {global}
{}
"#,
        route_with_ai_proxy("/llm", &route, provider.port)
    );
    let (config_path, mut child) = spawn_gateway(listen_port, status_port, &resources);

    let response = post_json(&format!("127.0.0.1:{listen_port}"), "/llm", CLIENT_BODY);
    assert_eq!(response.status, 200, "{}", response.body);

    let requests = provider.requests();
    assert_eq!(
        requests.len(),
        1,
        "exactly one instance may claim a request"
    );
    assert_eq!(
        requests[0].header("Authorization"),
        Some("Bearer route-key"),
        "the route-scoped instance must win; credentials must never mix"
    );
    shutdown_gateway(listen_port, &config_path, &mut child);
}

#[test]
fn global_ai_proxy_handles_a_route_without_its_own_instance() {
    let provider = MockProvider::start();
    let listen_port = random_port();
    let status_port = random_port();

    let global = ai_proxy_json(provider.port, "global-key", serde_json::json!({}));
    let resources = format!(
        r#"
global_rules:
  - id: "g1"
    plugins:
      ai-proxy: {global}

routes:
  - id: "1"
    uri: /plain
    upstream:
      nodes:
        "127.0.0.1:{}": 1
      type: roundrobin
"#,
        provider.port
    );
    let (config_path, mut child) = spawn_gateway(listen_port, status_port, &resources);

    let response = post_json(&format!("127.0.0.1:{listen_port}"), "/plain", CLIENT_BODY);
    assert_eq!(response.status, 200, "{}", response.body);

    let requests = provider.requests();
    assert_eq!(requests.len(), 1);
    let upstream = &requests[0];
    assert_eq!(upstream.header("Authorization"), Some("Bearer global-key"));
    assert_eq!(
        upstream.path(),
        "/v1/chat/completions",
        "the global instance must rewrite path and auth on a plain route"
    );
    shutdown_gateway(listen_port, &config_path, &mut child);
}

// ---------------------------------------------------------------------------
// Anthropic conversion on the wire.
// ---------------------------------------------------------------------------

#[test]
fn anthropic_requests_are_converted_on_the_wire() {
    let provider = MockProvider::start();
    let listen_port = random_port();
    let status_port = random_port();

    let plugin = ai_proxy_json(
        provider.port,
        "anthropic-key",
        serde_json::json!({
            "provider": "anthropic",
            "auth": { "header": { "x-api-key": "anthropic-key" } }
        }),
    );
    let (config_path, mut child) = spawn_gateway(
        listen_port,
        status_port,
        &route_with_ai_proxy("/llm", &plugin, provider.port),
    );

    let client_body = r#"{"model":"claude-3","max_tokens":64,"messages":[{"role":"system","content":"be brief"},{"role":"user","content":"hi"}]}"#;
    let response = post_json(&format!("127.0.0.1:{listen_port}"), "/llm", client_body);
    assert_eq!(response.status, 200, "{}", response.body);

    let requests = provider.requests();
    assert_eq!(requests.len(), 1);
    let upstream = &requests[0];
    assert_eq!(upstream.path(), "/v1/messages");
    assert_eq!(upstream.header("x-api-key"), Some("anthropic-key"));
    assert_eq!(upstream.header("anthropic-version"), Some("2023-06-01"));

    let body: serde_json::Value = serde_json::from_slice(&upstream.body).expect("valid JSON");
    assert_eq!(body["system"], "be brief", "system role is extracted");
    assert_eq!(
        body["messages"]
            .as_array()
            .map(|m| m.len())
            .unwrap_or_default(),
        1,
        "only the non-system message remains"
    );
    assert_eq!(body["max_tokens"], 64);

    shutdown_gateway(listen_port, &config_path, &mut child);
}

// ---------------------------------------------------------------------------
// Regression: body-buffering plugins must not terminate the upstream body
// early on chunked client requests (pingora reads a None chunk as "body
// finished"; request-validation shares the buffering pattern with ai-proxy).
// ---------------------------------------------------------------------------

#[test]
fn request_validation_forwards_chunked_client_body_after_validation() {
    let provider = MockProvider::start();
    let listen_port = random_port();
    let status_port = random_port();

    let validation = serde_json::json!({
        "body_schema": {
            "type": "object",
            "required": ["model"],
            "properties": { "model": { "type": "string" } }
        }
    })
    .to_string();
    let resources = format!(
        r#"
routes:
  - id: "1"
    uri: /validate
    plugins:
      request-validation: {validation}
    upstream:
      nodes:
        "127.0.0.1:{}": 1
      type: roundrobin
"#,
        provider.port
    );
    let (config_path, mut child) = spawn_gateway(listen_port, status_port, &resources);

    // Send the body as several chunked frames; the buffered body may only be
    // released upstream once, complete, after validation.
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect gateway");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let head = "POST /validate HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    stream.write_all(head.as_bytes()).unwrap();
    let bytes = CLIENT_BODY.as_bytes();
    for piece in [&bytes[..15], &bytes[15..45], &bytes[45..]] {
        std::thread::sleep(Duration::from_millis(20));
        stream
            .write_all(format!("{:x}\r\n", piece.len()).as_bytes())
            .unwrap();
        stream.write_all(piece).unwrap();
        stream.write_all(b"\r\n").unwrap();
    }
    stream.write_all(b"0\r\n\r\n").unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let (status, body) = status_and_body(&raw);
    assert_eq!(status, 200, "{body}");

    let requests = provider.requests();
    assert_eq!(requests.len(), 1);
    let upstream_request = &requests[0];
    let forwarded: serde_json::Value =
        serde_json::from_slice(&upstream_request.body).expect("complete body forwarded");
    assert_eq!(
        forwarded,
        serde_json::from_str::<serde_json::Value>(CLIENT_BODY).unwrap(),
        "the original body must arrive intact after validation"
    );

    shutdown_gateway(listen_port, &config_path, &mut child);
}
