use std::{borrow::Cow, sync::Arc, time::Duration};

use futures::FutureExt;
use http::Uri;
use pingora::services::background::background_service;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::Error;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_load_balancing::{
    health_check::{HealthCheck as HealthCheckTrait, HttpHealthCheck, TcpHealthCheck},
    selection::{
        consistent::KetamaHashing, BackendIter, BackendSelection, FVNHash, Random, RoundRobin,
    },
    Backend, Backends, LoadBalancer,
};
use pingora_proxy::Session;

use crate::{
    config::{self, Identifiable},
    core::{ProxyError, ProxyResult, UpstreamSelector},
    proxy::upstream::selection,
    utils::request::request_selector_key,
};

#[cfg(test)]
use super::discovery::prepare_static_upstream;
use super::discovery::{HybridDiscovery, PreparedUpstream, SeededDiscovery};

/// Upper bound on backends probed per selection attempt, as required by
/// [`LoadBalancer::select_with`].
const MAX_LB_ITERATIONS: usize = 256;

/// Runs a closure over the inner LB for any SelectionLB variant, eliminating repetitive match arms.
macro_rules! with_lb {
    ($lb:expr, |$lb_var:ident| $body:expr) => {
        match $lb {
            SelectionLB::RoundRobin($lb_var) => $body,
            SelectionLB::Random($lb_var) => $body,
            SelectionLB::Fnv($lb_var) => $body,
            SelectionLB::Ketama($lb_var) => $body,
        }
    };
}

/// Proxy load balancer.
///
/// Manages the load balancing of requests to upstream servers.
pub struct ProxyUpstream {
    pub inner: config::Upstream,
    lb: SelectionLB,
    /// Stable fingerprint of origin-identity fields used for cache namespacing.
    cache_origin_fingerprint: u64,
}

/// Fingerprint of every upstream field that can change which origin is contacted
/// or which virtual host / TLS identity is used. Private key material is hashed
/// via `secret_digest` and never placed in the cache key in cleartext.
pub(crate) fn cache_origin_fingerprint(upstream: &config::Upstream) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    upstream.id.hash(&mut hasher);
    upstream.scheme.hash(&mut hasher);
    upstream.r#type.hash(&mut hasher);
    upstream.hash_on.hash(&mut hasher);
    upstream.key.hash(&mut hasher);
    upstream.pass_host.hash(&mut hasher);
    upstream.upstream_host.hash(&mut hasher);
    upstream.retries.hash(&mut hasher);
    upstream.retry_timeout.hash(&mut hasher);
    if let Some(timeout) = &upstream.timeout {
        timeout.connect.hash(&mut hasher);
        timeout.send.hash(&mut hasher);
        timeout.read.hash(&mut hasher);
    }
    // HashMap wire order / list insertion order must not change the fingerprint
    // for an otherwise identical node set. Sort by the canonical node key, and
    // hash the *effective* port so "no port" and an explicit scheme-default
    // port (e.g. `example.com` vs `example.com:80` over http) are the same
    // origin.
    let mut nodes: Vec<_> = upstream.nodes.iter().collect();
    nodes.sort_by_key(|n| n.sort_key());
    for node in nodes {
        node.bare_host().hash(&mut hasher);
        node.effective_port(&upstream.scheme).hash(&mut hasher);
        node.weight.hash(&mut hasher);
        node.priority.hash(&mut hasher);
    }
    if let Some(tls) = &upstream.tls {
        // Digest PEM material so client identity changes invalidate cache without
        // embedding secrets in the key.
        crate::core::secret_digest(&tls.client_cert).hash(&mut hasher);
        crate::core::secret_digest(&tls.client_key).hash(&mut hasher);
    } else {
        0u8.hash(&mut hasher);
    }
    hasher.finish()
}

impl Identifiable for ProxyUpstream {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl ProxyUpstream {
    /// Test-only static-IP constructor. Production candidates must supply
    /// explicitly prepared material to [`Self::build`].
    #[cfg(test)]
    pub(crate) fn build_static(upstream: config::Upstream) -> ProxyResult<Self> {
        let prepared = prepare_static_upstream(&upstream)?;
        Self::build(upstream, prepared)
    }

    /// Build an upstream from material prepared before candidate compilation.
    /// This constructor never performs discovery I/O.
    pub(crate) fn build(
        mut upstream: config::Upstream,
        prepared: PreparedUpstream,
    ) -> ProxyResult<Self> {
        // Auto-generate upstream ID if empty (for inline upstreams in route, service, traffic-split)
        if upstream.id.is_empty() {
            upstream.id = format!("inline_{}", uuid::Uuid::new_v4());
            log::debug!("Generated ID for inline upstream: {}", upstream.id);
        }

        let cache_origin_fingerprint = cache_origin_fingerprint(&upstream);
        let lb = SelectionLB::from_prepared(upstream.clone(), prepared).map_err(|e| {
            ProxyError::Configuration(format!("Failed to create load balancer: {e}"))
        })?;

        Ok(ProxyUpstream {
            inner: upstream,
            lb,
            cache_origin_fingerprint,
        })
    }

    pub(crate) fn health_check_service(
        &self,
    ) -> Arc<dyn pingora_core::services::background::BackgroundService + Send + Sync> {
        with_lb!(&self.lb, |lb| lb.upstreams.clone())
    }

    /// Test helper: select a backend without a full proxy session.
    #[cfg(test)]
    pub(crate) fn select_backend_for_test(&self) -> Option<Backend> {
        let mut backend = with_lb!(&self.lb, |lb| lb.select(b""));
        if let Some(backend) = backend.as_mut() {
            if let Some(peer) = backend.ext.get_mut::<HttpPeer>() {
                self.set_timeout(peer);
            }
        }
        backend
    }

    /// Sets the finite upstream/global/built-in timeout for an `HttpPeer`.
    fn set_timeout(&self, p: &mut HttpPeer) {
        let config::Timeout {
            connect,
            read,
            send,
        } = config::resolve_upstream_timeout(
            self.inner.timeout.clone(),
            config::default_upstream_timeout(),
        );
        p.options.connection_timeout = Some(Duration::from_secs(connect));
        p.options.read_timeout = Some(Duration::from_secs(read));
        p.options.write_timeout = Some(Duration::from_secs(send));
    }

    /// Hash key for the session-aware selection algorithms.
    fn hash_key<'a>(&self, session: &'a mut Session) -> Cow<'a, str> {
        let key = request_selector_key(session, &self.inner.hash_on, self.inner.key.as_str());
        log::debug!("proxy lb key: {key}");
        key
    }
}

// Implementation of UpstreamSelector trait for decoupling from core module
impl UpstreamSelector for ProxyUpstream {
    fn select_backend(&self, session: &mut Session) -> Option<Backend> {
        let mut backend = match &self.lb {
            SelectionLB::RoundRobin(lb) => lb.select(b""),
            SelectionLB::Random(lb) => lb.select(b""),
            SelectionLB::Fnv(lb) => lb.select(self.hash_key(session).as_bytes()),
            SelectionLB::Ketama(lb) => lb.select(self.hash_key(session).as_bytes()),
        };

        if let Some(backend) = backend.as_mut() {
            if let Some(peer) = backend.ext.get_mut::<HttpPeer>() {
                self.set_timeout(peer);
            }
        }

        backend
    }

    fn get_retries(&self) -> Option<usize> {
        self.inner.retries.map(|r| r as _)
    }

    fn get_retry_timeout(&self) -> Option<u64> {
        self.inner.retry_timeout
    }

    fn get_pass_host(&self) -> &config::UpstreamPassHost {
        &self.inner.pass_host
    }

    fn upstream_host_rewrite(&self, upstream_request: &mut RequestHeader) {
        if self.inner.pass_host == config::UpstreamPassHost::REWRITE {
            if let Some(host) = &self.inner.upstream_host {
                if let Err(e) = upstream_request.insert_header(http::header::HOST, host) {
                    log::error!("Failed to rewrite upstream host header: {e}");
                }
            }
        }
    }

    fn cache_isolation_key(&self) -> String {
        format!("{:x}", self.cache_origin_fingerprint)
    }
}

enum SelectionLB {
    RoundRobin(LB<RoundRobin>),
    Random(LB<Random>),
    Fnv(LB<FVNHash>),
    Ketama(LB<KetamaHashing>),
}

impl SelectionLB {
    fn from_prepared(value: config::Upstream, prepared: PreparedUpstream) -> ProxyResult<Self> {
        match value.r#type {
            config::SelectionType::RoundRobin => Ok(SelectionLB::RoundRobin(
                LB::<RoundRobin>::from_prepared(value, prepared)?,
            )),
            config::SelectionType::Random => Ok(SelectionLB::Random(LB::<Random>::from_prepared(
                value, prepared,
            )?)),
            config::SelectionType::Fnv => Ok(SelectionLB::Fnv(LB::<FVNHash>::from_prepared(
                value, prepared,
            )?)),
            config::SelectionType::Ketama => Ok(SelectionLB::Ketama(
                LB::<KetamaHashing>::from_prepared(value, prepared)?,
            )),
        }
    }
}

/// `BS` is the configured algorithm; it is applied per priority group by
/// [`selection::PriorityGrouped`].
struct LB<BS: BackendSelection>
where
    BS::Iter: BackendIter,
{
    upstreams: Arc<LoadBalancer<selection::PriorityGrouped<BS>>>,
}

impl<BS> LB<BS>
where
    BS: BackendSelection + Send + Sync + 'static,
    BS::Iter: BackendIter,
{
    /// Select a backend honouring node priority, then health.
    fn select(&self, key: &[u8]) -> Option<Backend> {
        selection::select_backend(&self.upstreams, key, MAX_LB_ITERATIONS)
    }

    fn from_prepared(upstream: config::Upstream, prepared: PreparedUpstream) -> ProxyResult<Self> {
        let refresh: HybridDiscovery = upstream.clone().try_into()?;
        let discovery = SeededDiscovery::new(prepared, refresh);
        let mut upstreams = LoadBalancer::<selection::PriorityGrouped<BS>>::from_backends(
            Backends::new(Box::new(discovery)),
        );

        if let Some(check) = upstream.checks {
            let health_check: Box<dyn HealthCheckTrait + Send + Sync + 'static> =
                check.clone().try_into().map_err(|e| {
                    ProxyError::Configuration(format!(
                        "Upstream '{}' has an invalid health check configuration: {e}",
                        upstream.id
                    ))
                })?;
            upstreams.set_health_check(health_check);

            let health_check_frequency = check
                .active
                .healthy
                .map(|healthy| Duration::from_secs(healthy.interval as _))
                .unwrap_or(Duration::from_secs(1));

            upstreams.health_check_frequency = Some(health_check_frequency);
        }

        if let Some(interval) = config::dns_refresh_interval() {
            upstreams.update_frequency = Some(Duration::from_secs(interval));
        }

        // Extract the Arc<LoadBalancer> via background_service().task().
        // The wrapper is intentionally dropped — health checks are driven by
        // SHARED_HEALTH_CHECK_SERVICE, not by Pingora's background service mechanism.
        let background =
            background_service(&format!("health check for {}", upstream.id), upstreams);
        let upstreams = background.task();

        // The seeded discovery result is immediately ready and never performs
        // I/O, so populate selection before this LB can be published.
        let update_result = upstreams.update().now_or_never().ok_or_else(|| {
            ProxyError::Configuration(format!(
                "Upstream '{}' seeded discovery was not immediately ready",
                upstream.id
            ))
        })?;
        update_result.map_err(|e| {
            ProxyError::Configuration(format!(
                "Upstream '{}' failed to install prepared backends: {e}",
                upstream.id
            ))
        })?;

        Ok(Self { upstreams })
    }
}

impl TryFrom<config::HealthCheck> for Box<dyn HealthCheckTrait + Send + Sync + 'static> {
    type Error = ProxyError;

    fn try_from(value: config::HealthCheck) -> Result<Self, Self::Error> {
        match value.active.r#type {
            config::ActiveCheckType::TCP => Ok(Into::<Box<TcpHealthCheck>>::into(value)),
            config::ActiveCheckType::HTTP | config::ActiveCheckType::HTTPS => {
                Ok(Box::new(HttpHealthCheck::try_from(value)?))
            }
        }
    }
}

impl From<config::HealthCheck> for Box<TcpHealthCheck> {
    fn from(value: config::HealthCheck) -> Self {
        let mut health_check = TcpHealthCheck::new();
        health_check.peer_template.options.total_connection_timeout =
            Some(Duration::from_secs(value.active.timeout as _));

        if let Some(healthy) = value.active.healthy {
            health_check.consecutive_success = healthy.successes as _;
        }

        if let Some(unhealthy) = value.active.unhealthy {
            health_check.consecutive_failure = unhealthy.tcp_failures as _;
        }

        health_check
    }
}

impl TryFrom<config::HealthCheck> for HttpHealthCheck {
    type Error = ProxyError;

    fn try_from(value: config::HealthCheck) -> Result<Self, Self::Error> {
        let host = value.active.host.unwrap_or_default();
        let tls = value.active.r#type == config::ActiveCheckType::HTTPS;
        let mut health_check = HttpHealthCheck::new(host.as_str(), tls);

        // Set total connection timeout if provided
        health_check.peer_template.options.total_connection_timeout =
            Some(Duration::from_secs(value.active.timeout as _));

        // Set certificate verification if TLS is enabled
        health_check.peer_template.options.verify_cert = value.active.https_verify_certificate;

        // Build URI for HTTP health check path. A malformed path must fail
        // candidate publication rather than silently disabling the probe.
        let uri = Uri::builder()
            .path_and_query(&value.active.http_path)
            .build()
            .map_err(|e| {
                ProxyError::Configuration(format!(
                    "Invalid health check path '{}': {e}",
                    value.active.http_path
                ))
            })?;
        health_check.req.set_uri(uri);

        // Insert headers; malformed entries must fail closed instead of being
        // silently dropped, otherwise probes run with a different request than
        // the operator configured.
        for header in value.active.req_headers.iter() {
            let mut parts = header.splitn(2, ':');
            let (key, val) = match (parts.next(), parts.next()) {
                (Some(key), Some(val)) => (key.trim().to_string(), val.trim().to_string()),
                _ => {
                    return Err(ProxyError::Configuration(format!(
                        "Invalid health check header {header:?}: expected 'Name: value'"
                    )))
                }
            };
            if key.is_empty() {
                return Err(ProxyError::Configuration(format!(
                    "Invalid health check header {header:?}: empty header name"
                )));
            }
            health_check.req.insert_header(key, &val).map_err(|e| {
                ProxyError::Configuration(format!("Invalid health check header {header:?}: {e}"))
            })?;
        }

        // Handle port override
        if let Some(port) = value.active.port {
            health_check.port_override = Some(port as _);
        }

        // Set the success conditions
        if let Some(healthy) = value.active.healthy {
            health_check.consecutive_success = healthy.successes as _;

            // Validator for HTTP status codes
            if !healthy.http_statuses.is_empty() {
                let http_statuses = healthy.http_statuses.clone(); // Clone to move into closure
                health_check.validator = Some(Box::new(move |header: &ResponseHeader| {
                    if http_statuses.contains(&(header.status.as_u16() as _)) {
                        Ok(())
                    } else {
                        Err(Error::new_str("Invalid response"))
                    }
                }));
            }
        }

        // Set the failure conditions
        if let Some(unhealthy) = value.active.unhealthy {
            health_check.consecutive_failure = unhealthy.http_failures as _;
        }

        // Return the Boxed health check
        Ok(health_check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        init_default_upstream_timeout, Nodes, SelectionType, Timeout, UpstreamHashOn,
        UpstreamPassHost, UpstreamScheme,
    };
    use std::collections::HashMap;

    fn node(host: &str, port: u16, priority: i8) -> config::Node {
        config::Node {
            host: host.into(),
            // Test convenience: 0 means "port omitted" (scheme default).
            port: (port != 0).then_some(port),
            weight: 1,
            priority,
        }
    }

    fn sample_upstream(id: &str, timeout: Option<Timeout>) -> config::Upstream {
        let mut nodes = HashMap::new();
        nodes.insert("127.0.0.1:18080".to_string(), 1);
        config::Upstream {
            id: id.to_string(),
            name: None,
            retries: None,
            retry_timeout: None,
            timeout,
            nodes: Nodes::from_map(nodes),
            r#type: SelectionType::RoundRobin,
            checks: None,
            hash_on: UpstreamHashOn::VARS,
            key: "uri".into(),
            scheme: UpstreamScheme::HTTP,
            pass_host: UpstreamPassHost::PASS,
            upstream_host: None,
            tls: None,
        }
    }

    #[test]
    fn explicit_upstream_timeout_applied_to_peer() {
        init_default_upstream_timeout(Some(Timeout {
            connect: 5,
            send: 5,
            read: 5,
        }));
        let upstream = ProxyUpstream::build_static(sample_upstream(
            "payments",
            Some(Timeout {
                connect: 30,
                send: 30,
                read: 30,
            }),
        ))
        .unwrap();
        let backend = upstream.select_backend_for_test().unwrap();
        let peer = backend.ext.get::<HttpPeer>().unwrap();
        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(30))
        );
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn missing_upstream_timeout_uses_global_default() {
        init_default_upstream_timeout(Some(Timeout {
            connect: 5,
            send: 5,
            read: 5,
        }));
        // First-wins OnceCell: if a prior test already set a different value,
        // resolve via whatever is currently configured.
        let global = crate::config::default_upstream_timeout();
        let upstream = ProxyUpstream::build_static(sample_upstream("plain", None)).unwrap();
        let backend = upstream.select_backend_for_test().unwrap();
        let peer = backend.ext.get::<HttpPeer>().unwrap();
        if let Some(g) = global {
            assert_eq!(
                peer.options.connection_timeout,
                Some(Duration::from_secs(g.connect))
            );
            assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(g.read)));
            assert_eq!(
                peer.options.write_timeout,
                Some(Duration::from_secs(g.send))
            );
        } else {
            assert!(peer.options.connection_timeout.is_none());
        }
    }

    #[test]
    fn cache_origin_fingerprint_changes_with_host_rewrite() {
        let base = sample_upstream("u1", None);
        let fp1 = cache_origin_fingerprint(&base);
        let mut rewritten = base.clone();
        rewritten.pass_host = UpstreamPassHost::REWRITE;
        rewritten.upstream_host = Some("tenant-b.internal".into());
        let fp2 = cache_origin_fingerprint(&rewritten);
        assert_ne!(
            fp1, fp2,
            "pass_host/upstream_host must change cache origin fingerprint"
        );
        let mut nodes_changed = base;
        nodes_changed
            .nodes
            .push("10.0.0.2:80".parse().expect("valid node address"));
        assert_ne!(
            fp1,
            cache_origin_fingerprint(&nodes_changed),
            "node set must change cache origin fingerprint"
        );
    }

    #[test]
    fn cache_origin_fingerprint_is_stable_across_node_order() {
        let mut a_nodes = HashMap::new();
        a_nodes.insert("10.0.0.2:80".into(), 1);
        a_nodes.insert("10.0.0.1:80".into(), 2);
        let mut b_nodes = HashMap::new();
        b_nodes.insert("10.0.0.1:80".into(), 2);
        b_nodes.insert("10.0.0.2:80".into(), 1);

        let a = config::Upstream {
            nodes: Nodes::from_map(a_nodes),
            ..sample_upstream("u1", None)
        };
        let b = config::Upstream {
            nodes: Nodes::from_map(b_nodes),
            ..sample_upstream("u1", None)
        };
        assert_eq!(cache_origin_fingerprint(&a), cache_origin_fingerprint(&b));
    }

    #[test]
    fn negative_priority_is_lower_than_zero() {
        let upstream = ProxyUpstream::build_static(config::Upstream {
            nodes: Nodes(vec![
                node("127.0.0.1", 18301, 0),
                node("127.0.0.1", 18302, -1),
            ]),
            ..sample_upstream("neg", None)
        })
        .unwrap();

        let backend = upstream.select_backend_for_test().unwrap();
        assert_eq!(backend.addr.to_string(), "127.0.0.1:18301");
        assert_eq!(selection::backend_priority(&backend), 0);
    }

    #[test]
    fn duplicate_addr_keeps_higher_priority() {
        // Pingora Backend identity ignores ext; same addr+weight collapses.
        // We keep the higher priority so negative cannot "stick" over 0/10.
        let prepared = prepare_static_upstream(&config::Upstream {
            nodes: Nodes(vec![node("127.0.0.1", 443, -1), node("127.0.0.1", 443, 10)]),
            ..sample_upstream("dup", None)
        })
        .unwrap();

        assert_eq!(prepared.backends.len(), 1);
        let only = prepared.backends.iter().next().unwrap();
        assert_eq!(selection::backend_priority(only), 10);
    }

    #[test]
    fn cache_origin_fingerprint_canonicalizes_scheme_default_port() {
        // An omitted port and an explicit scheme-default port dial the same
        // origin, so they must share a cache namespace.
        let no_port = config::Upstream {
            nodes: Nodes(vec![node("example.com", 0, 0)]),
            ..sample_upstream("u1", None)
        };
        let explicit = config::Upstream {
            nodes: Nodes(vec![node("example.com", 80, 0)]),
            ..sample_upstream("u1", None)
        };
        assert_eq!(
            cache_origin_fingerprint(&no_port),
            cache_origin_fingerprint(&explicit),
            "omitted port and explicit scheme default are the same origin"
        );

        // But a genuinely different effective port must differ.
        let other = config::Upstream {
            nodes: Nodes(vec![node("example.com", 8080, 0)]),
            ..sample_upstream("u1", None)
        };
        assert_ne!(
            cache_origin_fingerprint(&no_port),
            cache_origin_fingerprint(&other),
            "different effective ports must not share a cache namespace"
        );
    }

    /// A malformed health-check path or header must fail candidate build
    /// instead of silently disabling/altering the probe.
    #[test]
    fn invalid_health_check_config_fails_candidate_build() {
        use crate::config::{ActiveCheck, ActiveCheckType, HealthCheck as HealthCheckConfig};

        fn upstream_with_http_path(path: &str) -> config::Upstream {
            let mut upstream = sample_upstream("hc", None);
            upstream.checks = Some(HealthCheckConfig {
                active: ActiveCheck {
                    r#type: ActiveCheckType::HTTP,
                    timeout: 1,
                    http_path: path.to_string(),
                    host: None,
                    port: None,
                    https_verify_certificate: true,
                    req_headers: vec![],
                    healthy: None,
                    unhealthy: None,
                },
            });
            upstream
        }

        let invalid_path = upstream_with_http_path("not a uri path");
        let err = ProxyUpstream::build_static(invalid_path)
            .err()
            .expect("malformed health check path must fail build")
            .to_string();
        assert!(
            err.contains("health check") || err.contains("Invalid health check path"),
            "malformed health check path must fail build, got: {err}"
        );

        let mut malformed_header = upstream_with_http_path("/");
        if let Some(check) = malformed_header.checks.as_mut() {
            check.active.req_headers = vec!["HeaderWithoutColon".into()];
        }
        let err = ProxyUpstream::build_static(malformed_header)
            .err()
            .expect("malformed health check header must fail build")
            .to_string();
        assert!(
            err.contains("Invalid health check header"),
            "malformed health check header must fail build, got: {err}"
        );

        // A well-formed configuration still builds.
        let mut ok = upstream_with_http_path("/healthz");
        if let Some(check) = ok.checks.as_mut() {
            check.active.req_headers = vec!["X-Probe: healthz".into()];
        }
        ProxyUpstream::build_static(ok).expect("valid health check must build");
    }

    // ---------------------------------------------------------------------
    // Real active health-check failure/recovery
    // ---------------------------------------------------------------------

    fn upstream_with_active_check(addr: &str) -> config::Upstream {
        use crate::config::{ActiveCheck, ActiveCheckType, Health, HealthCheck as HC, Unhealthy};
        let mut upstream = sample_upstream("hc-live", None);
        // Probe the test backend, not the sample upstream's hard-coded node.
        upstream.nodes = Nodes::from_map(HashMap::from([(addr.to_string(), 1)]));
        upstream.checks = Some(HC {
            active: ActiveCheck {
                r#type: ActiveCheckType::HTTP,
                timeout: 1,
                http_path: "/".into(),
                host: None,
                port: None,
                https_verify_certificate: true,
                req_headers: vec![],
                // Fast transitions: one probe decides each way.
                healthy: Some(Health {
                    interval: 1,
                    http_statuses: vec![200],
                    successes: 1,
                }),
                unhealthy: Some(Unhealthy {
                    http_failures: 1,
                    tcp_failures: 1,
                }),
            },
        });
        upstream
    }

    /// Serve minimal HTTP/1.1 200 responses for every accepted connection.
    async fn serve_http(listener: tokio::net::TcpListener) {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
            });
        }
    }

    /// Bind a listener that can immediately reuse the same port after a close.
    fn bind_reusable(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        socket.listen(1024)
    }

    fn any_backend_ready(upstream: &ProxyUpstream) -> bool {
        with_lb!(&upstream.lb, |lb| {
            lb.upstreams
                .backends()
                .get_backend()
                .iter()
                .any(|b| lb.upstreams.backends().ready(b))
        })
    }

    async fn wait_for_ready(upstream: &ProxyUpstream, expect_ready: bool, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if any_backend_ready(upstream) == expect_ready {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "backend readiness did not become {expect_ready} within {timeout:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Real Pingora health probes against a live local backend: readiness must
    /// follow healthy → unhealthy (backend stopped) → healthy (backend back).
    /// Selection itself still returns a backend when nothing is ready, via the
    /// APISIX-compatible all-unready fallback.
    #[tokio::test]
    async fn active_health_check_failure_and_recovery() {
        let _ = env_logger::builder().is_test(true).try_init();
        let listener = bind_reusable("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut backend = tokio::spawn(serve_http(listener));

        let upstream = ProxyUpstream::build_static(upstream_with_active_check(&addr.to_string()))
            .expect("upstream with active check must build");
        let service = upstream.health_check_service();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let health_task = tokio::spawn(async move {
            service.start(shutdown_rx).await;
        });

        // Backend up → probe succeeds → ready and selectable.
        wait_for_ready(&upstream, true, Duration::from_secs(10)).await;
        assert!(upstream.select_backend_for_test().is_some());

        // Backend down → consecutive probe failure → not ready, but the
        // all-unready fallback still yields an enabled backend.
        backend.abort();
        wait_for_ready(&upstream, false, Duration::from_secs(15)).await;
        assert!(
            upstream.select_backend_for_test().is_some(),
            "all-unready fallback must still select an enabled backend"
        );

        // Backend restored on the same port → probe recovers → ready again.
        let listener2 = bind_reusable(addr).expect("same port must be reusable");
        backend = tokio::spawn(serve_http(listener2));
        wait_for_ready(&upstream, true, Duration::from_secs(15)).await;
        assert!(upstream.select_backend_for_test().is_some());

        health_task.abort();
        backend.abort();
    }
}
