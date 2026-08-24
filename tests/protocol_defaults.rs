//! Protocol security defaults: auth, CORS, cache (static YAML, no etcd).

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::*;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

fn make_jwt(secret: &str) -> String {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 3600;
    encode(
        &Header::new(Algorithm::HS256),
        &Claims {
            sub: "user".into(),
            exp,
        },
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn static_config(listen_port: u16, status_port: u16, routes_yaml: &str) -> String {
    format!(
        r#"{}
pingsix:
  listeners:
    - address: "127.0.0.1:{listen_port}"
  status:
    address: "127.0.0.1:{status_port}"

{routes_yaml}
"#,
        pingora_header(listen_port)
    )
}

fn spawn_static(
    listen_port: u16,
    status_port: u16,
    routes_yaml: &str,
) -> (String, std::process::Child) {
    let yaml = static_config(listen_port, status_port, routes_yaml);
    let config_path = write_config(listen_port, &yaml);
    let child = spawn_pingsix(&config_path);
    assert!(
        wait_until_ready(status_port, Duration::from_secs(15)),
        "static config should become ready"
    );
    (config_path, child)
}

#[test]
fn auth1_jwt_query_disabled_by_default() {
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    let secret = "jwt-test-secret";
    let token = make_jwt(secret);

    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      jwt-auth:
        secret: "{secret}"
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let via_query = http_get(&addr, &format!("/?jwt={token}")).unwrap();
    assert_eq!(
        via_query.status, 401,
        "query jwt must be ignored by default: {}",
        via_query.body
    );

    let via_header = http_exchange(
        &addr,
        "GET",
        "/",
        &[("Authorization", &format!("Bearer {token}"))],
        None,
    )
    .unwrap();
    assert_eq!(via_header.status, 200, "{}", via_header.body);

    // Explicit query enable.
    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);

    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      jwt-auth:
        secret: "{secret}"
        query: jwt
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");
    let via_query = http_get(&addr, &format!("/?jwt={token}")).unwrap();
    assert_eq!(
        via_query.status, 200,
        "enabled query jwt: {}",
        via_query.body
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn auth2_key_auth_query_disabled_by_default() {
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      key-auth:
        keys: ["my-api-key"]
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let via_query = http_get(&addr, "/?apikey=my-api-key").unwrap();
    assert_eq!(via_query.status, 401, "query key-auth disabled by default");

    let via_header = http_exchange(&addr, "GET", "/", &[("apikey", "my-api-key")], None).unwrap();
    assert_eq!(via_header.status, 200, "{}", via_header.body);

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cors1_bare_options_is_not_preflight() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "options-app".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    methods: ["GET", "OPTIONS"]
    plugins:
      cors:
        allow_origins: "*"
        allow_methods: "**"
        allow_headers: "*"
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let resp = http_exchange(
        &addr,
        "OPTIONS",
        "/",
        &[("Origin", "https://example.com")],
        None,
    )
    .unwrap();
    // Not a CORS preflight short-circuit (204); should reach upstream or normal handling.
    assert_ne!(
        resp.status, 204,
        "bare OPTIONS must not be treated as preflight"
    );
    assert!(
        !resp
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"))
            || resp.body.contains("options-app"),
        "unexpected preflight-style response: status={} headers={:?}",
        resp.status,
        resp.headers
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cors2_real_preflight_returns_acao() {
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    methods: ["GET"]
    plugins:
      cors:
        allow_origins: "**"
        allow_methods: "**"
        allow_headers: "**"
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    upstream.reset_hits();
    let resp = http_exchange(
        &addr,
        "OPTIONS",
        "/",
        &[
            ("Origin", "https://example.com"),
            ("Access-Control-Request-Method", "GET"),
            ("Access-Control-Request-Headers", "X-Custom"),
        ],
        None,
    )
    .unwrap();
    assert_eq!(resp.status, 204, "preflight status: {}", resp.body);
    let acao = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"));
    assert!(acao.is_some(), "missing ACAO in {:?}", resp.headers);
    let vary = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("vary"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert!(
        vary.to_ascii_lowercase().contains("origin")
            || vary
                .to_ascii_lowercase()
                .contains("access-control-request-headers"),
        "expected Vary merge, got {vary:?}"
    );
    assert_eq!(upstream.hits(), 0, "preflight must not hit upstream");

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cors3_global_rule_enables_preflight_fallback() {
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    // The route itself carries no CORS plugin and does not accept OPTIONS, so
    // only the global CORS rule can make it a preflight fallback candidate.
    let routes = format!(
        r#"
global_rules:
  - id: "g1"
    plugins:
      cors:
        allow_origins: "**"
        allow_methods: "**"
        allow_headers: "**"
routes:
  - id: "1"
    uri: /
    methods: ["GET"]
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    upstream.reset_hits();
    let resp = http_exchange(
        &addr,
        "OPTIONS",
        "/",
        &[
            ("Origin", "https://example.com"),
            ("Access-Control-Request-Method", "GET"),
        ],
        None,
    )
    .unwrap();
    assert_eq!(resp.status, 204, "preflight status: {}", resp.body);
    let acao = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("access-control-allow-origin"));
    assert!(acao.is_some(), "missing ACAO in {:?}", resp.headers);
    assert_eq!(upstream.hits(), 0, "preflight must not hit upstream");

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cache1_vary_star_not_cached() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "vary-star".into(),
        headers: vec![("Vary".into(), "*".into())],
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      proxy-cache:
        ttl: 60
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    assert_eq!(http_get(&addr, "/").unwrap().status, 200);
    let after_first = upstream.hits();
    assert_eq!(http_get(&addr, "/").unwrap().status, 200);
    assert!(
        upstream.hits() > after_first,
        "Vary: * response must not be served from shared cache"
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cache2_authorization_bypasses_cache() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "auth-body".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      proxy-cache:
        ttl: 60
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let _ = http_exchange(&addr, "GET", "/", &[("Authorization", "Bearer x")], None).unwrap();
    let after_first = upstream.hits();
    let _ = http_exchange(&addr, "GET", "/", &[("Authorization", "Bearer x")], None).unwrap();
    assert!(
        upstream.hits() > after_first,
        "authenticated requests must bypass cache by default"
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cache3_set_cookie_not_cached() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "cookie-body".into(),
        headers: vec![("Set-Cookie".into(), "sid=1".into())],
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      proxy-cache:
        ttl: 60
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    assert_eq!(http_get(&addr, "/").unwrap().status, 200);
    let after_first = upstream.hits();
    assert_eq!(http_get(&addr, "/").unwrap().status, 200);
    assert!(
        upstream.hits() > after_first,
        "Set-Cookie responses must not be cached by default"
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn cache4_consumer_isolation_partitions_despite_hidden_credentials() {
    // key-auth credentials travel on a custom header that the plugin strips
    // (hide_credentials) before the cache key is built; consumer isolation
    // must still partition the shared cache per verified credential.
    let upstream = MockUpstream::start(MockUpstreamConfig {
        // Authorized responses are only stored when the origin marks them
        // public (RFC 7234 via pingora-cache).
        headers: vec![("Cache-Control".into(), "public, max-age=60".into())],
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /data
    plugins:
      key-auth:
        keys: ["key-a", "key-b"]
        hide_credentials: true
      proxy-cache:
        ttl: 60
        cache_authenticated_requests: true
        consumer_isolation: true
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let get_with_key = |key: &str| {
        http_exchange(&addr, "GET", "/data", &[("apikey", key)], None).expect("request")
    };

    // Same consumer: first request misses upstream, second is served from
    // cache (no new upstream hit).
    assert_eq!(get_with_key("key-a").status, 200);
    assert_eq!(upstream.hits(), 1);
    assert_eq!(get_with_key("key-a").status, 200);
    assert_eq!(upstream.hits(), 1, "same key must be a cache HIT");

    // Different consumer: isolated bucket, so the entry must MISS and go
    // upstream even though the URL and (stripped) headers are identical.
    assert_eq!(get_with_key("key-b").status, 200);
    assert_eq!(
        upstream.hits(),
        2,
        "different key must not reuse key-a's entry"
    );
    assert_eq!(get_with_key("key-b").status, 200);
    assert_eq!(upstream.hits(), 2, "key-b entry must now be a HIT");

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn rewrite1_response_body_is_replaced() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "origin-body".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      response-rewrite:
        body: "replacement-body"
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let first = http_get(&addr, "/").expect("request");
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(first.body, "replacement-body");
    assert_eq!(upstream.hits(), 1);

    let second = http_get(&addr, "/").expect("second request");
    assert_eq!(second.body, "replacement-body");

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn rewrite2_final_bodyless_status_suppresses_body_and_chunking() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "origin-body".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      response-rewrite:
        status_code: 204
        body: "must-not-be-sent"
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let response = http_get(&format!("127.0.0.1:{listen_port}"), "/").expect("request");
    assert_eq!(response.status, 204);
    assert!(response.body.is_empty(), "bodyless response leaked bytes");
    assert!(!response
        .headers
        .iter()
        .any(|(name, _)| { name.eq_ignore_ascii_case("transfer-encoding") }));

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn limit1_rules_use_empty_key_bucket_and_header_rule_is_enforced() {
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      limit-count:
        rules:
          - key: "$http_x_user"
            count: 1
            time_window: 60
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    // Missing variable -> APISIX enforces the empty-key bucket: the first
    // headerless request passes, the next one is limited (count: 1).
    let first_no_header = http_get(&addr, "/").expect("headerless request");
    assert_eq!(first_no_header.status, 200, "{}", first_no_header.body);
    let second_no_header = http_get(&addr, "/").expect("second headerless request");
    assert_eq!(second_no_header.status, 503, "{}", second_no_header.body);

    let first = http_exchange(&addr, "GET", "/", &[("X-User", "alice")], None)
        .expect("first matching request");
    assert_eq!(first.status, 200, "{}", first.body);
    let second = http_exchange(&addr, "GET", "/", &[("X-User", "alice")], None)
        .expect("second matching request");
    assert_eq!(second.status, 503, "{}", second.body);
    assert_eq!(upstream.hits(), 2);

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn echo1_wraps_upstream_response_body() {
    let upstream = MockUpstream::start(MockUpstreamConfig {
        body: "core".into(),
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      echo:
        before_body: "["
        after_body: "]"
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let response = http_get(&addr, "/").expect("request");
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body, "[core]");
    assert_eq!(upstream.hits(), 1);

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn grpc1_preflight_and_content_type_gating() {
    let upstream = MockUpstream::start(MockUpstreamConfig::default());
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      grpc-web: {{}}
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let preflight = http_exchange(&addr, "OPTIONS", "/", &[], None).expect("preflight");
    assert_eq!(preflight.status, 204, "{}", preflight.body);
    assert!(preflight.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("access-control-allow-methods") && value == "POST"
    }));

    let wrong_method = http_exchange(&addr, "GET", "/", &[], None).expect("GET");
    assert_eq!(wrong_method.status, 405, "{}", wrong_method.body);

    for content_type in [
        "application/json",
        "application/grpc",
        "application/grpc+proto",
    ] {
        let wrong_type = http_exchange(
            &addr,
            "POST",
            "/",
            &[("Content-Type", content_type)],
            Some("payload"),
        )
        .expect("wrong content type");
        assert_eq!(
            wrong_type.status, 400,
            "{content_type}: {}",
            wrong_type.body
        );
    }

    let grpc = http_exchange(
        &addr,
        "POST",
        "/",
        &[("Content-Type", "application/grpc-web+proto")],
        Some("grpc-frame"),
    )
    .expect("grpc-web request");
    assert_eq!(grpc.status, 200, "{}", grpc.body);
    assert_eq!(upstream.hits(), 1);

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn grpc2_bridged_response_carries_cors_headers_and_text_is_rejected() {
    // The upstream answers application/grpc; Pingora's bridge converts it to
    // grpc-web only after plugin filters run, so the CORS/expose headers must
    // be applied based on the request marker — a browser needs
    // Access-Control-Expose-Headers to read grpc-status on Trailers-Only
    // responses.
    let upstream = MockUpstream::start(MockUpstreamConfig {
        headers: vec![
            ("Content-Type".into(), "application/grpc".into()),
            ("grpc-status".into(), "0".into()),
        ],
        ..Default::default()
    });
    let listen_port = random_port();
    let status_port = random_port();
    let routes = format!(
        r#"
routes:
  - id: "1"
    uri: /
    plugins:
      grpc-web: {{}}
    upstream:
      nodes:
        "127.0.0.1:{up}": 1
      type: roundrobin
"#,
        up = upstream.port
    );
    let (config_path, mut child) = spawn_static(listen_port, status_port, &routes);
    let addr = format!("127.0.0.1:{listen_port}");

    let bridged = http_exchange(
        &addr,
        "POST",
        "/",
        &[("Content-Type", "application/grpc-web+proto")],
        Some("grpc-frame"),
    )
    .expect("bridged grpc-web request");
    assert_eq!(bridged.status, 200, "{}", bridged.body);
    assert!(
        bridged.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("access-control-expose-headers")
                && value == "grpc-message,grpc-status"
        }),
        "expose headers missing on bridged response: {:?}",
        bridged.headers
    );
    assert!(bridged.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("access-control-allow-origin") && value == "*"
    }));

    // base64-framed grpc-web-text is not transcoded by Pingora's bridge and
    // must fail closed instead of corrupting the upstream gRPC stream.
    let text = http_exchange(
        &addr,
        "POST",
        "/",
        &[("Content-Type", "application/grpc-web-text+proto")],
        Some("YmFzZTY0"),
    )
    .expect("grpc-web-text request");
    assert_eq!(text.status, 400, "{}", text.body);
    assert!(text.body.contains("grpc-web-text"));
    assert_eq!(
        upstream.hits(),
        1,
        "rejected -text request must not go upstream"
    );

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}

#[test]
fn status1_config_diagnostics_on_loopback() {
    let listen_port = random_port();
    let status_port = random_port();
    let routes = r#"
routes: []
"#;
    let (config_path, mut child) = spawn_static(listen_port, status_port, routes);

    let live = http_get(&format!("127.0.0.1:{status_port}"), "/status/live").unwrap();
    assert_eq!(live.status, 200);
    let cfg = http_get(&format!("127.0.0.1:{status_port}"), "/status/config").unwrap();
    assert_eq!(cfg.status, 200, "{}", cfg.body);
    let view: serde_json::Value = serde_json::from_str(&cfg.body).unwrap();
    assert_eq!(view["ready"], true);
    assert_eq!(view["config_source"], "yaml");

    sigterm(&child);
    let _ = wait_exit(&mut child, Duration::from_secs(20));
    cleanup_runtime_files(listen_port, &config_path);
}
