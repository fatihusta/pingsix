//! Request mirroring plugin, APISIX `proxy-mirror` compatible.
//!
//! Asynchronously duplicates a sampled portion of requests to a shadow
//! upstream (`host`) without waiting for or influencing the real response.
//! The original request's headers and body are streamed to the mirror while
//! the primary proxy flow is unaffected; mirror connection failures are logged
//! and never fail the main request (Guide L6-style forwarding to a shadow peer,
//! APISIX `enable_mirror` semantics).
//!
//! Only `http://`/`https://` mirror targets are supported in this release.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use once_cell::sync::Lazy;
use pingora_core::{connectors::http::Connector, upstreams::peer::HttpPeer};
use pingora_error::Result;
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use prometheus::{register_int_counter_vec, IntCounterVec};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::{
    sync::{mpsc, Notify, Semaphore},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use validator::{Validate, ValidationError};

use crate::{
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::config::parse_and_validate_plugin_config,
};

pub const PLUGIN_NAME: &str = "proxy-mirror";

/// APISIX `proxy-mirror` runs at priority 1010.
const PRIORITY: i32 = 1010;

/// Context key: whether this request is sampled for mirroring.
const CTX_KEY_MIRROR: &str = "pingsix_proxy_mirror";
/// Context key: bounded producer for the background mirror task.
const CTX_KEY_MIRROR_SENDER: &str = "pingsix_proxy_mirror_sender";

/// A small, fixed queue keeps a slow shadow upstream from accumulating request
/// bodies in process memory.
const MIRROR_QUEUE_CAPACITY: usize = 32;
const MIRROR_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const MIRROR_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Hard cap on the number of mirror tasks running concurrently across the
/// whole process. Each sampled request previously spawned a detached task
/// that resolved DNS and opened a connection on its own; without a global
/// bound a high sample rate against a slow/unreachable mirror could fan out
/// to ~RPS concurrent tasks, DNS lookups and sockets.
const MAX_CONCURRENT_MIRRORS: usize = 64;

/// Reuse a resolved mirror address without re-querying DNS for this long.
const MIRROR_DNS_CACHE_TTL: Duration = Duration::from_secs(60);
/// After a DNS failure, keep serving the last known address for this grace
/// window so transient resolver errors drop only mirrors, not the cached peer.
const MIRROR_DNS_STALE_GRACE: Duration = Duration::from_secs(300);

static MIRROR_PERMITS: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_MIRRORS)));

static MIRROR_DROPPED: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "pingsix_proxy_mirror_dropped_total",
        "Mirror requests dropped before or during shadowing",
        &["reason"]
    )
    .expect("mirror metric registration must succeed")
});

fn mirror_dropped(reason: &'static str) {
    MIRROR_DROPPED.with_label_values(&[reason]).inc();
}

/// Shared, cached DNS resolution for one mirror target. The plugin instance is
/// reused across requests, so every sampled request for the same target shares
/// one resolver: a fresh address is reused for [`MIRROR_DNS_CACHE_TTL`] and a
/// stale address is served for [`MIRROR_DNS_STALE_GRACE`] after a lookup
/// failure, instead of issuing one lookup per request.
struct MirrorResolver {
    target: MirrorTarget,
    state: StdMutex<MirrorDnsState>,
    /// Elected with CAS so the only mutex in this type is never held across
    /// DNS I/O. `lookup_done` wakes every cache-miss follower.
    lookup_in_flight: AtomicBool,
    lookup_done: Notify,
}

#[derive(Default)]
struct MirrorDnsState {
    addr: Option<SocketAddr>,
    resolved_at: Option<Instant>,
    /// Published before waking followers so all waiters receive the outcome
    /// of a failed flight instead of immediately stampeding into another one.
    last_error: Option<&'static str>,
}

/// Clears an elected DNS flight even if its task is aborted. This is essential
/// because mirror work is cancelled when its plugin snapshot is retired.
struct LookupFlight<'a> {
    resolver: &'a MirrorResolver,
}

impl Drop for LookupFlight<'_> {
    fn drop(&mut self) {
        self.resolver
            .lookup_in_flight
            .store(false, Ordering::Release);
        self.resolver.lookup_done.notify_waiters();
    }
}

impl MirrorResolver {
    fn new(target: MirrorTarget) -> Self {
        Self {
            target,
            state: StdMutex::new(MirrorDnsState::default()),
            lookup_in_flight: AtomicBool::new(false),
            lookup_done: Notify::new(),
        }
    }

    /// Resolve the target to a connectable peer. A cache miss elects exactly
    /// one lookup leader; followers wait for its result then consume the cache
    /// or attempt the next flight. No `std::sync::Mutex` is held over await.
    async fn resolve(&self) -> Result<HttpPeer, &'static str> {
        self.resolve_with(|| async {
            match tokio::net::lookup_host((self.target.host.as_str(), self.target.port)).await {
                Ok(mut addresses) => addresses
                    .next()
                    .ok_or("mirror target resolved to no address"),
                Err(_) => Err("mirror target DNS lookup failed"),
            }
        })
        .await
    }

    async fn resolve_with<F, Fut>(&self, lookup: F) -> Result<HttpPeer, &'static str>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<SocketAddr, &'static str>>,
    {
        let mut lookup = Some(lookup);
        loop {
            if let Some(peer) = self.cached_fresh() {
                return Ok(peer);
            }

            if self
                .lookup_in_flight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let _flight = LookupFlight { resolver: self };
                match lookup.take().expect("lookup leader is elected once")().await {
                    Ok(addr) => {
                        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                        state.addr = Some(addr);
                        state.resolved_at = Some(Instant::now());
                        state.last_error = None;
                        return Ok(HttpPeer::new(
                            addr,
                            self.target.tls,
                            self.target.sni.clone(),
                        ));
                    }
                    Err(error) => {
                        self.state
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .last_error = Some(error);
                        return self.stale_reuse().ok_or(error);
                    }
                }
            }

            // Register before checking the flag so a leader cannot finish in
            // the gap and strand this waiter. If it already finished, loop.
            let notified = self.lookup_done.notified();
            if self.lookup_in_flight.load(Ordering::Acquire) {
                notified.await;
                if let Some(peer) = self.stale_reuse() {
                    return Ok(peer);
                }
                if let Some(error) = self.last_error() {
                    return Err(error);
                }
            }
        }
    }

    fn cached_fresh(&self) -> Option<HttpPeer> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = state
            .resolved_at
            .is_some_and(|t| t.elapsed() < MIRROR_DNS_CACHE_TTL);
        if fresh {
            state
                .addr
                .map(|addr| HttpPeer::new(addr, self.target.tls, self.target.sni.clone()))
        } else {
            None
        }
    }

    fn last_error(&self) -> Option<&'static str> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_error
    }

    /// Serve the last known address for a short grace window after a DNS
    /// failure so transient resolver errors do not evict a still-good peer.
    fn stale_reuse(&self) -> Option<HttpPeer> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let within_grace = state.resolved_at.is_some_and(|resolved_at| {
            resolved_at.elapsed() < MIRROR_DNS_CACHE_TTL + MIRROR_DNS_STALE_GRACE
        });
        if !within_grace {
            return None;
        }
        state
            .addr
            .map(|addr| HttpPeer::new(addr, self.target.tls, self.target.sni.clone()))
    }
}

/// Creates a `proxy-mirror` plugin instance from JSON configuration.
pub fn create_proxy_mirror_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    let target = parse_mirror_target(&config.host)?;
    let resolver = Arc::new(MirrorResolver::new(target));
    Ok(Arc::new(PluginProxyMirror {
        config,
        resolver,
        connector: Arc::new(Connector::new(None)),
        tasks: MirrorTaskTracker::new(),
    }))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PathConcatMode {
    /// Replace the original path with the configured one (keep query).
    #[default]
    Replace,
    /// Prefix the configured path onto the original path.
    Prefix,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Mirror target base URL, e.g. `http://127.0.0.1:9797`.
    #[validate(custom(function = "validate_host"))]
    host: String,

    /// Custom path applied per `path_concat_mode`.
    #[serde(default)]
    path: Option<String>,

    #[serde(default)]
    path_concat_mode: PathConcatMode,

    /// Proportion of requests to mirror (0.00001..=1).
    #[serde(default = "PluginConfig::default_sample_ratio")]
    #[validate(range(min = 0.00001, max = 1.0))]
    sample_ratio: f64,
}

impl PluginConfig {
    fn default_sample_ratio() -> f64 {
        1.0
    }
}

fn validate_host(host: &str) -> Result<(), ValidationError> {
    if parse_mirror_target(host).is_err() {
        return Err(ValidationError::new(
            "host must be an http(s) scheme and authority only, e.g. http://127.0.0.1:9797",
        ));
    }
    Ok(())
}

fn validate_path(path: Option<&str>) -> ProxyResult<()> {
    if path.is_some_and(|path| {
        !path.starts_with('/') || path.len() == 1 || path.contains('?') || path.contains('&')
    }) {
        return Err(ProxyError::validation_error(
            "mirror path must match ^/[^?&]+$",
        ));
    }
    Ok(())
}

/// Parsed mirror target. Kept free of any I/O: name resolution happens per
/// request inside the mirror task, so config validation never blocks on DNS
/// and an unresolvable target can only drop a mirror, never panic the proxy.
#[derive(Debug, Clone)]
struct MirrorTarget {
    host: String,
    port: u16,
    tls: bool,
    sni: String,
}

/// Parse `host` into a [`MirrorTarget`]. Returns a validation error for
/// unsupported schemes or malformed URLs.
fn parse_mirror_target(host: &str) -> ProxyResult<MirrorTarget> {
    let uri: http::Uri = host
        .parse()
        .map_err(|e| ProxyError::validation_error(format!("invalid mirror host '{host}': {e}")))?;

    // `http::Uri` normalizes an authority-only URL to path `/`; accept that
    // representation but reject every explicit non-root path.
    if uri.authority().is_none()
        || uri.path() != "/"
        || uri.query().is_some()
        || host.contains('#')
        || host.ends_with('/')
    {
        return Err(ProxyError::validation_error(
            "mirror host must contain only scheme and authority (no path or query)",
        ));
    }

    let (tls, default_port) = match uri.scheme_str() {
        Some("http") => (false, 80),
        Some("https") => (true, 443),
        Some(other) => {
            return Err(ProxyError::validation_error(format!(
                "unsupported mirror scheme '{other}'; only http/https are supported"
            )))
        }
        None => {
            return Err(ProxyError::validation_error(
                "mirror host must include a scheme (http:// or https://)",
            ))
        }
    };

    let host_str = uri
        .host()
        .ok_or_else(|| ProxyError::validation_error("mirror host is missing a hostname"))?;

    Ok(MirrorTarget {
        host: host_str.to_string(),
        port: uri.port_u16().unwrap_or(default_port),
        tls,
        sni: host_str.to_string(),
    })
}

/// Resolve a [`MirrorTarget`] to a connectable [`HttpPeer`] via the shared
/// [`MirrorResolver`] (cached, stale-reusing). Used by the mirror task so a
/// DNS failure only drops the mirror, never the request.
async fn resolve_mirror_peer(resolver: &MirrorResolver) -> Result<HttpPeer, &'static str> {
    resolver.resolve().await
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid proxy-mirror plugin config")?;
        validate_path(config.path.as_deref())?;
        Ok(config)
    }
}

/// Plugin-local ownership for detached mirror work. Handles are pruned on
/// admission and capped by the same global permit limit, so retirement never
/// leaves an unbounded task registry. Dropping a plugin snapshot cancels and
/// aborts all currently registered work; this cannot join tasks synchronously,
/// so runtime shutdown remains responsible for draining Tokio itself.
struct MirrorTaskTracker {
    cancel: CancellationToken,
    tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl MirrorTaskTracker {
    fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
            tasks: StdMutex::new(Vec::new()),
        }
    }

    fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    fn track(&self, task: JoinHandle<()>) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }
}

impl Drop for MirrorTaskTracker {
    fn drop(&mut self) {
        self.cancel.cancel();
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        for task in tasks.drain(..) {
            task.abort();
        }
    }
}

pub struct PluginProxyMirror {
    config: PluginConfig,
    resolver: Arc<MirrorResolver>,
    connector: Arc<Connector>,
    tasks: MirrorTaskTracker,
}

#[derive(Clone)]
struct MirrorSender {
    sender: mpsc::Sender<MirrorBody>,
    active: Arc<AtomicBool>,
}

enum MirrorBody {
    Chunk(Bytes, bool),
    Finish,
}

impl MirrorSender {
    fn try_send(&self, body: MirrorBody) {
        if !self.active.load(Ordering::Relaxed) {
            return;
        }
        if let Err(error) = self.sender.try_send(body) {
            self.active.store(false, Ordering::Relaxed);
            match error {
                mpsc::error::TrySendError::Full(_) => {
                    mirror_dropped("queue_full");
                    log::warn!("proxy-mirror: mirror queue is full; dropping mirror request");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    log::debug!("proxy-mirror: mirror task is no longer available");
                }
            }
        }
    }
}

impl PluginProxyMirror {
    /// Build the mirrored request header: cloned original with an optional
    /// path rewrite per `path_concat_mode`.
    fn build_mirror_request(&self, original: &RequestHeader) -> ProxyResult<RequestHeader> {
        let mut mirror = original.clone();

        if let Some(conf_path) = &self.config.path {
            let query = original
                .uri
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            let new_path = match self.config.path_concat_mode {
                PathConcatMode::Replace => format!("{conf_path}{query}"),
                PathConcatMode::Prefix => {
                    format!("{conf_path}{}{query}", original.uri.path())
                }
            };
            let new_uri: http::Uri = new_path.parse().map_err(|e| {
                ProxyError::validation_error(format!("failed to build mirror URI: {e}"))
            })?;
            mirror.set_uri(new_uri);
        }

        Ok(mirror)
    }
}

#[async_trait]
impl ProxyPlugin for PluginProxyMirror {
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
        // Sample independently per request (APISIX `sample_ratio`).
        let sampled = rand::random::<f64>() < self.config.sample_ratio;
        ctx.set(CTX_KEY_MIRROR, sampled);
        if sampled {
            log::trace!(
                "proxy-mirror: mirroring request {} {}",
                session.req_header().method,
                session.req_header().uri
            );
        }
        Ok(FilterVerdict::Continue)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        if !ctx.get::<bool>(CTX_KEY_MIRROR).copied().unwrap_or(false) {
            return Ok(());
        }

        // Bound global mirror concurrency before spawning: if the process is
        // already mirroring MAX_CONCURRENT_MIRRORS requests, drop this mirror
        // instead of adding to an unbounded fan-out of tasks, DNS lookups and
        // sockets.
        let Some(permit) = MIRROR_PERMITS.clone().try_acquire_owned().ok() else {
            mirror_dropped("concurrency_limit");
            log::debug!("proxy-mirror: concurrency limit reached, dropping mirror");
            return Ok(());
        };

        let mirror_req = match self.build_mirror_request(upstream_request) {
            Ok(req) => req,
            Err(e) => {
                log::warn!("proxy-mirror: failed to build mirror request: {e}");
                return Ok(());
            }
        };

        let (sender, mut receiver) = mpsc::channel(MIRROR_QUEUE_CAPACITY);
        let active = Arc::new(AtomicBool::new(true));
        ctx.set(
            CTX_KEY_MIRROR_SENDER,
            MirrorSender {
                sender,
                active: active.clone(),
            },
        );
        let connector = self.connector.clone();
        let resolver = self.resolver.clone();
        let cancelled = self.tasks.cancellation_token();
        let task = tokio::spawn(async move {
            // `_permit` releases the global mirror slot when the task ends.
            let _permit = permit;
            let result = tokio::select! {
                _ = cancelled.cancelled() => Err("mirror task cancelled"),
                result = async {
                // Resolve via the shared, cached resolver: an unresolvable or
                // slow DNS target only drops the mirror, never the request.
                let peer =
                    tokio::time::timeout(MIRROR_CONNECT_TIMEOUT, resolve_mirror_peer(&resolver))
                        .await
                        .map_err(|_| "mirror target DNS lookup timed out")??;
                let (mut session, _) =
                    tokio::time::timeout(MIRROR_CONNECT_TIMEOUT, connector.get_http_session(&peer))
                        .await
                        .map_err(|_| "connection timed out")?
                        .map_err(|_| "connection failed")?;
                tokio::time::timeout(
                    MIRROR_WRITE_TIMEOUT,
                    session.write_request_header(Box::new(mirror_req)),
                )
                .await
                .map_err(|_| "header write timed out")?
                .map_err(|_| "header write failed")?;
                // Always wait for the body stream from `request_body_filter`.
                // Inferring body presence from Content-Length/Transfer-Encoding
                // would drop HTTP/2 streaming bodies that carry neither header;
                // bodyless requests signal end-of-stream immediately.
                while let Some(body) = receiver.recv().await {
                    match body {
                        MirrorBody::Chunk(bytes, end) => {
                            tokio::time::timeout(
                                MIRROR_WRITE_TIMEOUT,
                                session.write_request_body(bytes, end),
                            )
                            .await
                            .map_err(|_| "body write timed out")?
                            .map_err(|_| "body write failed")?;
                            if end {
                                return Ok::<(), &str>(());
                            }
                        }
                        MirrorBody::Finish => {
                            tokio::time::timeout(
                                MIRROR_WRITE_TIMEOUT,
                                session.finish_request_body(),
                            )
                            .await
                            .map_err(|_| "body completion timed out")?
                            .map_err(|_| "body completion failed")?;
                            return Ok(());
                        }
                    }
                }
                Err("request body ended without completion")
                } => result,
            };
            active.store(false, Ordering::Relaxed);
            if let Err(error) = result {
                let reason = match error {
                    "mirror target DNS lookup timed out" => "dns_timeout",
                    "mirror target DNS lookup failed" | "mirror target resolved to no address" => {
                        "dns"
                    }
                    "connection timed out" | "connection failed" => "connect",
                    "header write timed out" | "header write failed" => "write_header",
                    "body write timed out" | "body write failed" => "write_body",
                    "body completion timed out" | "body completion failed" => "write_body",
                    _ => "other",
                };
                mirror_dropped(reason);
                log::warn!("proxy-mirror: dropping mirror request: {error}");
            }
        });
        self.tasks.track(task);
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        let Some(sender) = ctx.get::<MirrorSender>(CTX_KEY_MIRROR_SENDER) else {
            return Ok(());
        };
        match body {
            Some(bytes) => sender.try_send(MirrorBody::Chunk(bytes.clone(), end_of_stream)),
            None if end_of_stream => sender.try_send(MirrorBody::Finish),
            None => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_http::RequestHeader;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn test_target() -> MirrorTarget {
        parse_mirror_target("http://127.0.0.1:9797").unwrap()
    }

    #[tokio::test]
    async fn dns_cache_miss_is_singleflight_and_wakes_waiters() {
        let resolver = Arc::new(MirrorResolver::new(test_target()));
        let calls = Arc::new(AtomicUsize::new(0));
        // Signal the leader has entered the lookup without blocking the runtime
        // thread: a std::sync::Barrier::wait() inside a spawned task deadlocks
        // on the default current-thread test runtime.
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let leader = {
            let resolver = resolver.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                resolver
                    .resolve_with(|| async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let _ = entered_tx.send(());
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok("127.0.0.1:9797".parse().unwrap())
                    })
                    .await
            })
        };
        // Wait until the leader is inside the lookup closure and sleeping, so
        // the follower below arrives while the flight is still in progress.
        entered_rx.await.unwrap();
        let follower = {
            let resolver = resolver.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                resolver
                    .resolve_with(|| async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok("127.0.0.2:9797".parse().unwrap())
                    })
                    .await
            })
        };

        assert!(leader.await.unwrap().is_ok());
        assert!(follower.await.unwrap().is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dns_failure_reuses_stale_address_only_within_grace() {
        let resolver = MirrorResolver::new(test_target());
        let address = "127.0.0.1:9797".parse().unwrap();
        {
            let mut state = resolver.state.lock().unwrap();
            state.addr = Some(address);
            state.resolved_at =
                Some(Instant::now() - MIRROR_DNS_CACHE_TTL - Duration::from_secs(1));
        }
        assert!(resolver
            .resolve_with(|| async { Err("lookup failed") })
            .await
            .is_ok());

        {
            let mut state = resolver.state.lock().unwrap();
            state.resolved_at = Some(
                Instant::now()
                    - MIRROR_DNS_CACHE_TTL
                    - MIRROR_DNS_STALE_GRACE
                    - Duration::from_secs(1),
            );
        }
        assert!(matches!(
            resolver
                .resolve_with(|| async { Err("lookup failed") })
                .await,
            Err("lookup failed")
        ));
    }

    #[tokio::test]
    async fn tracker_cancels_detached_task_when_plugin_snapshot_drops() {
        let tracker = MirrorTaskTracker::new();
        let cancellation = tracker.cancellation_token();
        let task_cancellation = cancellation.clone();
        tracker.track(tokio::spawn(async move {
            task_cancellation.cancelled().await;
        }));
        drop(tracker);
        assert!(cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn semaphore_permit_is_released_when_mirror_work_is_cancelled() {
        let permits = Arc::new(Semaphore::new(1));
        let held = permits.clone().try_acquire_owned().unwrap();
        assert!(permits.clone().try_acquire_owned().is_err());
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            let _permit = held;
            worker_cancellation.cancelled().await;
        });
        cancellation.cancel();
        task.await.unwrap();
        assert!(permits.try_acquire_owned().is_ok());
    }

    #[test]
    fn config_requires_http_url_host() {
        assert!(PluginConfig::try_from(serde_json::json!({})).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "host": "ftp://x" })).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "host": "127.0.0.1:9797" })).is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({ "host": "http://127.0.0.1:9797" })).is_ok()
        );
        assert!(PluginConfig::try_from(
            serde_json::json!({ "host": "https://mirror.example.com" })
        )
        .is_ok());
        for invalid in [
            "grpc://mirror.example.com",
            "grpcs://mirror.example.com",
            "http://mirror.example.com/path",
            "http://mirror.example.com?query=1",
            "http://mirror.example.com/#fragment",
        ] {
            assert!(PluginConfig::try_from(serde_json::json!({ "host": invalid })).is_err());
        }
    }

    #[test]
    fn config_defaults() {
        let config =
            PluginConfig::try_from(serde_json::json!({ "host": "http://127.0.0.1:9797" })).unwrap();
        assert_eq!(config.sample_ratio, 1.0);
        assert_eq!(config.path_concat_mode, PathConcatMode::Replace);
        assert!(config.path.is_none());
    }

    #[test]
    fn config_requires_apisix_subset_path() {
        for invalid in ["shadow", "/", "/shadow?x=1", "/shadow&x=1"] {
            assert!(PluginConfig::try_from(serde_json::json!({
                "host": "http://127.0.0.1:9797",
                "path": invalid,
            }))
            .is_err());
        }
        assert!(PluginConfig::try_from(serde_json::json!({
            "host": "http://127.0.0.1:9797",
            "path": "/shadow/path",
        }))
        .is_ok());
    }

    #[test]
    fn config_rejects_bad_sample_ratio() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "host": "http://127.0.0.1:9797",
            "sample_ratio": 2.0
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "host": "http://127.0.0.1:9797",
            "sample_ratio": 0.0
        }))
        .is_err());
    }

    #[test]
    fn bounded_queue_drops_mirror_when_full() {
        let (sender, _receiver) = mpsc::channel(1);
        let active = Arc::new(AtomicBool::new(true));
        let mirror = MirrorSender {
            sender,
            active: active.clone(),
        };
        mirror.try_send(MirrorBody::Finish);
        mirror.try_send(MirrorBody::Finish);
        assert!(!active.load(Ordering::Relaxed));
    }

    #[test]
    fn mirror_target_parses_scheme_and_default_port() {
        let target = parse_mirror_target("https://mirror.example.com").unwrap();
        assert_eq!(target.sni, "mirror.example.com");
        assert_eq!(target.port, 443);
        assert!(target.tls);
    }

    #[test]
    fn mirror_request_replace_path_keeps_query() {
        let plugin = PluginProxyMirror {
            config: PluginConfig {
                host: "http://127.0.0.1:9797".into(),
                path: Some("/shadow".into()),
                path_concat_mode: PathConcatMode::Replace,
                sample_ratio: 1.0,
            },
            resolver: Arc::new(MirrorResolver::new(
                parse_mirror_target("http://127.0.0.1:9797").unwrap(),
            )),
            connector: Arc::new(Connector::new(None)),
            tasks: MirrorTaskTracker::new(),
        };
        let mut req = RequestHeader::build("GET", b"/original?a=1", None).unwrap();
        req.insert_header("Host", "example.com").unwrap();
        let mirror = plugin.build_mirror_request(&req).unwrap();
        assert_eq!(mirror.uri.to_string(), "/shadow?a=1");
    }

    #[test]
    fn mirror_request_prefix_mode() {
        let plugin = PluginProxyMirror {
            config: PluginConfig {
                host: "http://127.0.0.1:9797".into(),
                path: Some("/pre".into()),
                path_concat_mode: PathConcatMode::Prefix,
                sample_ratio: 1.0,
            },
            resolver: Arc::new(MirrorResolver::new(
                parse_mirror_target("http://127.0.0.1:9797").unwrap(),
            )),
            connector: Arc::new(Connector::new(None)),
            tasks: MirrorTaskTracker::new(),
        };
        let req = RequestHeader::build("GET", b"/api/x", None).unwrap();
        let mirror = plugin.build_mirror_request(&req).unwrap();
        assert_eq!(mirror.uri.to_string(), "/pre/api/x");
    }

    #[test]
    fn mirror_request_without_path_keeps_uri() {
        let plugin = PluginProxyMirror {
            config: PluginConfig {
                host: "http://127.0.0.1:9797".into(),
                path: None,
                path_concat_mode: PathConcatMode::Replace,
                sample_ratio: 1.0,
            },
            resolver: Arc::new(MirrorResolver::new(
                parse_mirror_target("http://127.0.0.1:9797").unwrap(),
            )),
            connector: Arc::new(Connector::new(None)),
            tasks: MirrorTaskTracker::new(),
        };
        let req = RequestHeader::build("GET", b"/api/x?b=2", None).unwrap();
        let mirror = plugin.build_mirror_request(&req).unwrap();
        assert_eq!(mirror.uri.to_string(), "/api/x?b=2");
    }
}
