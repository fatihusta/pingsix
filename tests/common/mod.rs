//! Shared helpers for process-level integration tests.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use etcd_client::Client;
use std::collections::HashSet;
use std::sync::LazyLock;

pub const ADMIN_API_KEY: &str = "integration-test-key";
pub const ETCD_IMAGE: &str = "quay.io/coreos/etcd:v3.5.21";

/// Returns `true` when Docker is available, `false` otherwise.
pub fn docker_available() -> bool {
    Command::new("docker")
        .args(["info"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

static DOCKER_SKIP_NOTICE_PRINTED: AtomicBool = AtomicBool::new(false);
static ETCD_CONTAINER_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Guard for Docker-backed tests.
///
/// Returns `true` when Docker is available. Otherwise prints one prominent
/// skip notice per test binary and returns `false`, so a green `cargo test`
/// shows an explicit notice instead of silently dropping the etcd/control-plane
/// coverage. (CI runners provision Docker; a local run without Docker still
/// exits green, but visibly.)
pub fn require_docker(test_name: &str) -> bool {
    if docker_available() {
        return true;
    }
    if !DOCKER_SKIP_NOTICE_PRINTED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "\nNOTE: Docker is unavailable — skipping Docker-backed integration tests\n\
             ({test_name} and others in this binary). Run with Docker available to\n\
             actually exercise etcd/control-plane coverage.\n"
        );
    }
    false
}

/// Ports already handed out by [`random_port`] in this test process.
///
/// The probe socket is dropped before the caller can bind the port for real,
/// so the kernel is free to hand the same port to the very next `bind(:0)` —
/// observed in CI as a config whose listener and status address collided,
/// making the status app win the bind race and tests talk HTTP to it
/// (`BrokenPipe`/`ConnectionRefused`). The registry makes every port handed
/// out in this process single-use.
static HANDED_OUT_PORTS: LazyLock<Mutex<HashSet<u16>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Pick a random unused port, never returning the same port twice within
/// this test process.
///
/// The probe socket is held open while the port is registered below: a
/// concurrent `random_port()` on another test thread cannot bind a port that
/// is currently bound, so duplicates are impossible even under parallel test
/// execution. The remaining window (some other process grabbing the freed
/// port before our child binds it) is not preventable from the test side.
pub fn random_port() -> u16 {
    loop {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let fresh = HANDED_OUT_PORTS.lock().unwrap().insert(port);
        drop(listener); // keep the socket open until the port is registered
        if fresh {
            return port;
        }
        // Handed out earlier in this process: try again.
    }
}

pub fn write_config(listen_port: u16, contents: &str) -> String {
    let path = format!("/tmp/pingsix-it-config-{listen_port}.yaml");
    std::fs::write(&path, contents).unwrap();
    path
}

pub fn cleanup_runtime_files(listen_port: u16, config_path: &str) {
    let _ = std::fs::remove_file(config_path);
    let _ = std::fs::remove_file(format!("/tmp/pingsix-it-{listen_port}.pid"));
    let _ = std::fs::remove_file(format!("/tmp/pingsix-it-{listen_port}.sock"));
    // Also remove the spawned child's redirected log so passed runs do not
    // accumulate .child.log files in /tmp (PingsixGuard removes it too; the
    // double remove is harmless).
    let _ = std::fs::remove_file(child_log_path(config_path));
}

/// Minimal pingora + pingsix header shared by etcd-mode configs.
pub fn pingora_header(listen_port: u16) -> String {
    format!(
        r#"
pingora:
  version: 1
  threads: 1
  pid_file: /tmp/pingsix-it-{listen_port}.pid
  upgrade_sock: /tmp/pingsix-it-{listen_port}.sock
  grace_period_seconds: 1
  graceful_shutdown_timeout_seconds: 1
"#
    )
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub fn http_exchange(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Option<HttpResponse> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .ok()?;

    let body_bytes = body.unwrap_or("").as_bytes();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if body.is_some() {
        req.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes).ok()?;
    }

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let (header_part, body_part) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = header_part.lines();
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let mut resp_headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            resp_headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some(HttpResponse {
        status,
        headers: resp_headers,
        body: body_part.to_string(),
    })
}

pub fn http_status(addr: &str, path: &str) -> Option<u16> {
    http_exchange(addr, "GET", path, &[], None).map(|r| r.status)
}

pub fn http_get(addr: &str, path: &str) -> Option<HttpResponse> {
    http_exchange(addr, "GET", path, &[], None)
}

pub fn wait_until_ready(status_port: u16, timeout: Duration) -> bool {
    wait_until_status(status_port, "/status/ready", 200, timeout)
}

pub fn wait_until_status(status_port: u16, path: &str, want: u16, timeout: Duration) -> bool {
    let addr = format!("127.0.0.1:{status_port}");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if http_status(&addr, path) == Some(want) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

pub fn wait_until_ready_reason(
    status_port: u16,
    reason: &str,
    timeout: Duration,
) -> Option<HttpResponse> {
    let addr = format!("127.0.0.1:{status_port}");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(resp) = http_get(&addr, "/status/ready") {
            if resp.status == 503 && resp.body.contains(reason) {
                return Some(resp);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    None
}

pub fn wait_until_proxy_body(
    listen_port: u16,
    path: &str,
    needle: &str,
    timeout: Duration,
) -> bool {
    let addr = format!("127.0.0.1:{listen_port}");
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(resp) = http_get(&addr, path) {
            if resp.status == 200 && resp.body.contains(needle) {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

pub fn wait_until_admin_ready(admin_port: u16, timeout: Duration) -> bool {
    let addr = format!("127.0.0.1:{admin_port}");
    let start = Instant::now();
    while start.elapsed() < timeout {
        // Any HTTP response means the Admin listener accepted connections.
        if http_exchange(
            &addr,
            "GET",
            "/apisix/admin/routes/__ready__",
            &[("x-api-key", ADMIN_API_KEY)],
            None,
        )
        .is_some()
        {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

pub fn child_log_path(config_path: &str) -> String {
    format!("{config_path}.child.log")
}

pub fn spawn_pingsix(config_path: &str) -> Child {
    let bin_path = env!("CARGO_BIN_EXE_pingsix");
    let log_path = child_log_path(config_path);
    // Redirect to a file so a busy child cannot block on a full OS pipe.
    let log_file = std::fs::File::create(&log_path).expect("create child log file");
    let log_err = log_file.try_clone().expect("clone child log file");
    Command::new(bin_path)
        .arg("-c")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("failed to spawn pingsix binary")
}

/// RAII guard: kills the child and cleans pid/sock/config/log on drop or panic.
pub struct PingsixGuard {
    child: Option<Child>,
    listen_port: u16,
    config_path: String,
}

impl PingsixGuard {
    pub fn new(listen_port: u16, config_path: String, child: Child) -> Self {
        Self {
            child: Some(child),
            listen_port,
            config_path,
        }
    }

    pub fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("pingsix child already taken")
    }

    pub fn config_path(&self) -> &str {
        &self.config_path
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub fn child_logs(&self) -> String {
        std::fs::read_to_string(child_log_path(&self.config_path)).unwrap_or_default()
    }
}

impl Drop for PingsixGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        cleanup_runtime_files(self.listen_port, &self.config_path);
        let _ = std::fs::remove_file(child_log_path(&self.config_path));
    }
}

pub fn child_stdio_snapshot(child: &mut Child) -> String {
    // Prefer the on-disk log when spawn redirected there; fall back to pipes.
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        if !buf.is_empty() {
            out.push_str("--- stdout ---\n");
            out.push_str(&String::from_utf8_lossy(&buf));
        }
    }
    if let Some(mut stderr) = child.stderr.take() {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        if !buf.is_empty() {
            out.push_str("--- stderr ---\n");
            out.push_str(&String::from_utf8_lossy(&buf));
        }
    }
    out
}

pub fn sigterm(child: &Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
}

pub fn wait_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("pingsix did not exit within {timeout:?}");
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("error waiting for child: {e}"),
        }
    }
}

/// RAII wrapper that stops/removes a docker etcd container on drop.
pub struct EtcdFixture {
    container_name: String,
    pub port: u16,
    pub endpoint: String,
}

impl EtcdFixture {
    pub fn start() -> Self {
        if !docker_available() {
            panic!(
                "Docker is required for etcd integration tests (image {ETCD_IMAGE}). \
                 `docker info` failed."
            );
        }
        let port = random_port();
        // The port alone is not unique across repeated local runs: a stopped
        // container from a previous run keeps its name but releases the port,
        // so `random_port()` can collide with it. Add a per-process sequence
        // number, and on a name conflict remove the stale container and retry
        // once instead of failing the whole test binary.
        let container_name = format!(
            "pingsix-it-etcd-{}-{}-{}",
            std::process::id(),
            port,
            ETCD_CONTAINER_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let run_container = || {
            Command::new("docker")
                .args([
                    "run",
                    "-d",
                    "--name",
                    &container_name,
                    "-p",
                    &format!("{port}:2379"),
                    ETCD_IMAGE,
                    "/usr/local/bin/etcd",
                    "--name",
                    "s1",
                    "--data-dir",
                    "/etcd-data",
                    "--listen-client-urls",
                    "http://0.0.0.0:2379",
                    "--advertise-client-urls",
                    "http://0.0.0.0:2379",
                    "--listen-peer-urls",
                    "http://0.0.0.0:2380",
                    "--initial-advertise-peer-urls",
                    "http://0.0.0.0:2380",
                    "--initial-cluster",
                    "s1=http://0.0.0.0:2380",
                    "--initial-cluster-token",
                    "pingsix-it",
                    "--initial-cluster-state",
                    "new",
                ])
                .output()
                .expect("failed to run docker")
        };
        let mut output = run_container();
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("already in use") {
                let _ = Command::new("docker")
                    .args(["rm", "-f", &container_name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                output = run_container();
            }
        }
        if !output.status.success() {
            panic!(
                "docker run etcd failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let endpoint = format!("http://127.0.0.1:{port}");
        let fixture = Self {
            container_name,
            port,
            endpoint: endpoint.clone(),
        };
        fixture.wait_healthy(Duration::from_secs(15));
        fixture
    }

    fn wait_healthy(&self, timeout: Duration) {
        let start = Instant::now();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let probe_key = format!("/pingsix-it-health-{}", self.port);
        while start.elapsed() < timeout {
            let ok = rt.block_on(async {
                let client = Client::connect([&self.endpoint], None).await.ok()?;
                client
                    .kv_client()
                    .put(probe_key.as_str(), b"ok", None)
                    .await
                    .ok()?;
                Some(())
            });
            if ok.is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("etcd at {} did not become healthy", self.endpoint);
    }

    pub fn stop(&self) {
        let _ = Command::new("docker")
            .args(["stop", "-t", "1", &self.container_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    pub fn start_again(&self) {
        let status = Command::new("docker")
            .args(["start", &self.container_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("docker start");
        assert!(status.success(), "docker start failed");
        self.wait_healthy(Duration::from_secs(15));
    }

    pub fn unique_prefix(&self) -> String {
        format!("/pingsix-it-{}-{}", std::process::id(), self.port)
    }

    pub fn put_json(&self, prefix: &str, resource_type: &str, id: &str, value: &serde_json::Value) {
        let key = format!("{prefix}/{resource_type}/{id}");
        let body = serde_json::to_vec(value).unwrap();
        let endpoint = self.endpoint.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut last_err = None;
        for attempt in 0..10 {
            let result = rt.block_on(async {
                let client = Client::connect([endpoint.as_str()], None).await?;
                client
                    .kv_client()
                    .put(key.as_str(), body.clone(), None)
                    .await?;
                Ok::<(), etcd_client::Error>(())
            });
            match result {
                Ok(()) => return,
                Err(e) => {
                    last_err = Some(e);
                    thread::sleep(Duration::from_millis(75 * (attempt + 1)));
                }
            }
        }
        panic!("etcd put {key} failed after retries: {last_err:?}");
    }
}

impl Drop for EtcdFixture {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[derive(Clone)]
pub struct MockUpstreamConfig {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
    /// When true, response body is the request `Host` header value.
    pub echo_host: bool,
}

impl Default for MockUpstreamConfig {
    fn default() -> Self {
        Self {
            status: 200,
            body: "upstream-ok".into(),
            headers: vec![],
            echo_host: false,
        }
    }
}

/// Tiny threaded HTTP/1.1 upstream for proxy tests.
pub struct MockUpstream {
    pub port: u16,
    hits: Arc<AtomicUsize>,
    config: Arc<Mutex<MockUpstreamConfig>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockUpstream {
    pub fn start(config: MockUpstreamConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let shared = Arc::new(Mutex::new(config));
        let stop = Arc::new(AtomicBool::new(false));

        let hits_c = hits.clone();
        let shared_c = shared.clone();
        let stop_c = stop.clone();
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            while !stop_c.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        hits_c.fetch_add(1, Ordering::SeqCst);
                        let mut buf = [0u8; 4096];
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let host = req
                            .lines()
                            .find_map(|line| {
                                let lower = line.to_ascii_lowercase();
                                lower.strip_prefix("host:").map(|v| v.trim().to_string())
                            })
                            .unwrap_or_default();
                        let cfg = shared_c.lock().unwrap().clone();
                        let body = if cfg.echo_host {
                            host
                        } else {
                            cfg.body.clone()
                        };
                        let mut resp = format!(
                            "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nConnection: close\r\n",
                            cfg.status,
                            body.len()
                        );
                        for (k, v) in &cfg.headers {
                            resp.push_str(&format!("{k}: {v}\r\n"));
                        }
                        resp.push_str("\r\n");
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.write_all(body.as_bytes());
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            hits,
            config: shared,
            stop,
            handle: Some(handle),
        }
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    pub fn set_config(&self, config: MockUpstreamConfig) {
        *self.config.lock().unwrap() = config;
    }

    pub fn reset_hits(&self) {
        self.hits.store(0, Ordering::SeqCst);
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub struct EtcdModeConfig {
    pub listen_port: u16,
    pub status_port: u16,
    pub admin_port: u16,
    pub etcd_endpoint: String,
    pub prefix: String,
    pub stale_after: u64,
    pub dns_timeout: u64,
    pub prometheus_port: Option<u16>,
}

pub fn etcd_config_yaml(cfg: &EtcdModeConfig) -> String {
    let mut yaml = format!(
        r#"{}
pingsix:
  defaults:
    dns_resolution_timeout: {dns_timeout}
  listeners:
    - address: "127.0.0.1:{listen_port}"
  etcd:
    host:
      - "{etcd_endpoint}"
    prefix: "{prefix}"
    timeout: 5
    connect_timeout: 3
  admin:
    address: "127.0.0.1:{admin_port}"
    api_key: "{ADMIN_API_KEY}"
  status:
    address: "127.0.0.1:{status_port}"
    config_stale_after: {stale_after}
    fail_readiness_when_stale: true
"#,
        pingora_header(cfg.listen_port),
        dns_timeout = cfg.dns_timeout,
        listen_port = cfg.listen_port,
        etcd_endpoint = cfg.etcd_endpoint,
        prefix = cfg.prefix,
        admin_port = cfg.admin_port,
        status_port = cfg.status_port,
        stale_after = cfg.stale_after,
    );
    if let Some(prom) = cfg.prometheus_port {
        yaml.push_str(&format!(
            "  prometheus:\n    address: \"127.0.0.1:{prom}\"\n"
        ));
    }
    yaml
}

fn admin_exchange_with_retry(
    admin_port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> HttpResponse {
    let addr = format!("127.0.0.1:{admin_port}");
    let start = Instant::now();
    let timeout = Duration::from_secs(15);
    loop {
        if let Some(resp) = http_exchange(&addr, method, path, headers, body) {
            return resp;
        }
        if start.elapsed() >= timeout {
            panic!(
                "admin {method} failed to connect to {addr}{path} within {timeout:?} \
                 (Admin listener not ready or process exited)"
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn admin_put(
    admin_port: u16,
    resource: &str,
    id: &str,
    body: &serde_json::Value,
) -> HttpResponse {
    let path = format!("/apisix/admin/{resource}/{id}");
    let raw = serde_json::to_string(body).unwrap();
    admin_exchange_with_retry(
        admin_port,
        "PUT",
        &path,
        &[
            ("x-api-key", ADMIN_API_KEY),
            ("Content-Type", "application/json"),
        ],
        Some(&raw),
    )
}

pub fn admin_get(admin_port: u16, resource: &str, id: &str) -> HttpResponse {
    let path = format!("/apisix/admin/{resource}/{id}");
    admin_exchange_with_retry(
        admin_port,
        "GET",
        &path,
        &[("x-api-key", ADMIN_API_KEY)],
        None,
    )
}

pub fn admin_delete(admin_port: u16, resource: &str, id: &str) -> HttpResponse {
    let path = format!("/apisix/admin/{resource}/{id}");
    admin_exchange_with_retry(
        admin_port,
        "DELETE",
        &path,
        &[("x-api-key", ADMIN_API_KEY)],
        None,
    )
}

pub fn status_config(status_port: u16) -> serde_json::Value {
    let addr = format!("127.0.0.1:{status_port}");
    let resp = http_get(&addr, "/status/config").expect("status/config");
    assert_eq!(resp.status, 200, "status/config body={}", resp.body);
    serde_json::from_str(&resp.body).expect("parse status/config json")
}

pub fn upstream_nodes(addr: &str) -> serde_json::Value {
    serde_json::json!({
        "nodes": { addr: 1 },
        "type": "roundrobin"
    })
}

pub fn route_to_upstream(uri: &str, upstream_id: &str) -> serde_json::Value {
    serde_json::json!({
        "uri": uri,
        "upstream_id": upstream_id
    })
}

// ---------------------------------------------------------------------------
// Session-level mock: yields a canned HTTP/1.1 request, then EOF; captures
// all response bytes. For plugin-pipeline integration tests.
// ---------------------------------------------------------------------------

use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use pingora_core::protocols::raw_connect::ProxyDigest;
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType, IO,
};
use pingora_proxy::Session;
use tokio::io::ReadBuf;

#[derive(Debug)]
pub struct MockStream {
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

impl tokio::io::AsyncRead for MockStream {
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

impl tokio::io::AsyncWrite for MockStream {
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

/// Build a session whose downstream yields `request` and whose writes are
/// captured into the returned buffer.
pub async fn session_for(request: &[u8]) -> (Session, Arc<Mutex<Vec<u8>>>) {
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

/// Split a raw HTTP/1.1 response into (status, body).
pub fn status_and_body(raw: &[u8]) -> (u16, String) {
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

/// First value of a response header, case-insensitive.
pub fn header_value(raw: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let head = text.split("\r\n\r\n").next().unwrap_or_default();
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}
