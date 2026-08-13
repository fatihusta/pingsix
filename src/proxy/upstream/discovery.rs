use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::{future::join_all, FutureExt};
use hickory_resolver::TokioResolver;
use once_cell::sync::OnceCell;
use pingora::{protocols::ALPN, upstreams::peer::HttpPeer};
use pingora_core::utils::tls::CertKey;
use pingora_error::{BError, Error, ErrorType::InternalError, OrErr, Result};
use pingora_load_balancing::{
    discovery::{ServiceDiscovery, Static},
    Backend,
};

use crate::proxy::upstream::selection::{insert_backend, set_backend_id, set_backend_priority};
use crate::{
    config::{self, Upstream, UpstreamPassHost, UpstreamScheme, UpstreamTls},
    core::{ProxyError, ProxyResult},
};

static GLOBAL_RESOLVER: OnceCell<Arc<TokioResolver>> = OnceCell::new();

/// Construct a DNS resolver for one gateway instance.
pub(crate) fn build_resolver_for_state() -> ProxyResult<Arc<TokioResolver>> {
    build_resolver()
}

fn build_resolver() -> ProxyResult<Arc<TokioResolver>> {
    let builder = TokioResolver::builder_tokio().map_err(|e| {
        ProxyError::Configuration(format!("Failed to create DNS resolver builder: {e}"))
    })?;
    let resolver = builder
        .build()
        .map_err(|e| ProxyError::Configuration(format!("Failed to build DNS resolver: {e}")))?;
    Ok(Arc::new(resolver))
}

/// The migration-period process-global resolver (first construction wins).
fn get_global_resolver() -> ProxyResult<Arc<TokioResolver>> {
    GLOBAL_RESOLVER.get_or_try_init(build_resolver).cloned()
}

/// [`get_global_resolver`] exposed to the upstream builder for the migration
/// facade; the composition root constructs per-instance resolvers directly.
pub(crate) fn get_global_resolver_for_build() -> ProxyResult<Arc<TokioResolver>> {
    get_global_resolver()
}

/// Loads a client certificate and key from PEM format strings.
///
/// This function parses the certificate chain and private key from PEM encoded strings
/// and creates a CertKey object that can be used for mTLS authentication.
fn load_client_cert_key(tls_config: &UpstreamTls) -> ProxyResult<Arc<CertKey>> {
    use pingora_core::tls::pkey::PKey;
    use pingora_core::tls::x509::X509;

    // Parse the certificate chain
    let cert_pem = tls_config.client_cert.as_bytes();
    let certificates = X509::stack_from_pem(cert_pem)
        .or_err_with(pingora_error::ErrorType::InternalError, || {
            "Failed to parse client certificate PEM"
        })?;

    if certificates.is_empty() {
        return Err(ProxyError::Configuration(
            "No certificates found in client_cert".to_string(),
        ));
    }

    // Parse the private key
    let key_pem = tls_config.client_key.as_bytes();
    let private_key = PKey::private_key_from_pem(key_pem)
        .or_err_with(pingora_error::ErrorType::InternalError, || {
            "Failed to parse client private key PEM"
        })?;

    // The leaf certificate and the private key must belong to the same key
    // pair. Detecting this here (instead of at the first TLS handshake) makes
    // a mismatched mTLS identity a deterministic configuration error.
    let leaf_public = certificates
        .first()
        .ok_or_else(|| {
            ProxyError::Configuration("No certificates found in client_cert".to_string())
        })?
        .public_key()
        .map_err(|e| {
            ProxyError::Configuration(format!("Failed to read client certificate public key: {e}"))
        })?;
    if !leaf_public.public_eq(&private_key) {
        return Err(ProxyError::Configuration(
            "Upstream client certificate and private key do not match".to_string(),
        ));
    }

    // Create CertKey using the new method
    let cert_key = CertKey::new(certificates, private_key);

    Ok(Arc::new(cert_key))
}

/// Deterministically validate upstream mTLS material without building a
/// discovery. Shared by the Admin write path (reject before commit) and the
/// discovery builders (reject the candidate), so invalid client certificate
/// or key material can never be stored yet permanently fail to publish.
pub(crate) fn validate_client_tls_material(tls_config: &UpstreamTls) -> ProxyResult<()> {
    load_client_cert_key(tls_config).map(|_| ())
}

/// One DNS-backed upstream node: address, load-balancing metadata, and TLS SNI.
///
/// Separated from shared discovery infrastructure (`resolver`, client cert) so
/// [`DnsDiscovery::new`] stays under Clippy's argument limit.
struct DnsNode {
    domain: String,
    port: u16,
    scheme: UpstreamScheme,
    weight: u32,
    priority: i8,
    /// TLS SNI, computed with the same pass-host rule as literal-IP backends.
    sni: String,
}

/// A DNS refresh can fail in only these expected, recoverable ways. Keeping
/// this finite makes LKG decisions explicit rather than conflating an empty
/// answer with a resolver failure.
#[derive(Debug, Clone, Copy)]
enum DnsRefreshFailure {
    Lookup,
    Empty,
}

/// Last-known-good state for a DNS node. A successful non-empty answer is
/// retained only for [`DNS_STALE_TTL`] after its resolution time; repeated
/// failures must not extend this deadline indefinitely.
#[derive(Default)]
struct DnsLkgState {
    addresses: Option<Vec<IpAddr>>,
    last_success_at: Option<Instant>,
}

/// Maximum age for a DNS node's last-known-good addresses after lookup errors
/// or empty answers. This preserves availability for transient resolver faults
/// without continuing to send mirrored traffic to a reassigned old address.
const DNS_STALE_TTL: Duration = Duration::from_secs(300);

/// DNS-based service discovery.
///
/// Resolves DNS names to IP addresses and creates backends for each resolved IP.
/// A per-node last-known-good state is reused after a lookup fails or returns
/// empty, but only inside [`DNS_STALE_TTL`].
pub struct DnsDiscovery {
    resolver: Arc<TokioResolver>,
    node: DnsNode,
    client_cert_key: Option<Arc<CertKey>>,
    lkg: Mutex<DnsLkgState>,
}

impl DnsDiscovery {
    fn new(
        node: DnsNode,
        resolver: Arc<TokioResolver>,
        client_cert_key: Option<Arc<CertKey>>,
    ) -> Self {
        Self {
            resolver,
            node,
            client_cert_key,
            lkg: Mutex::new(DnsLkgState::default()),
        }
    }

    /// Build the backend set for a resolved IP list.
    fn build_backends(&self, ips: &[IpAddr]) -> BTreeSet<Backend> {
        let mut backends = BTreeSet::new();
        for ip in ips {
            let addr = SocketAddr::new(*ip, self.node.port).to_string();
            let mut backend = match Backend::new_with_weight(&addr, self.node.weight as _) {
                Ok(b) => b,
                Err(e) => {
                    log::error!("Failed to create backend for {addr}: {e}");
                    continue;
                }
            };
            let peer = build_peer(
                &addr,
                self.node.scheme,
                self.node.sni.clone(),
                self.client_cert_key.as_ref(),
            );
            if backend.ext.insert::<HttpPeer>(peer).is_some() {
                log::error!("Backend {addr} already had HttpPeer metadata");
                continue;
            }
            set_backend_priority(&mut backend, self.node.priority);
            set_backend_id(&mut backend);
            backends.insert(backend);
        }
        backends
    }

    /// Rebuild from the last non-empty DNS answer while it remains inside the
    /// stale TTL. Failures never update `last_success_at`, so they cannot extend
    /// the LKG lifetime.
    fn lkg_backends(&self, failure: DnsRefreshFailure) -> Option<BTreeSet<Backend>> {
        let lkg = self.lkg.lock().unwrap_or_else(|e| e.into_inner());
        let (Some(ips), Some(last_success_at)) = (&lkg.addresses, lkg.last_success_at) else {
            return None;
        };
        if last_success_at.elapsed() > DNS_STALE_TTL {
            log::warn!(
                "DNS refresh for {} yielded {:?}, but its LKG is older than {}s",
                self.node.domain,
                failure,
                DNS_STALE_TTL.as_secs()
            );
            return None;
        }
        log::warn!(
            "DNS refresh for {} yielded {:?}; serving {} LKG backend address(es)",
            self.node.domain,
            failure,
            ips.len()
        );
        Some(self.build_backends(ips))
    }
}

#[async_trait]
impl ServiceDiscovery for DnsDiscovery {
    /// Discovers backends by resolving DNS names to IP addresses.
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let domain = self.node.domain.as_str();
        log::debug!("Resolving DNS for domain: {domain}");

        match self.resolver.lookup_ip(domain).await {
            Ok(ips) => {
                let resolved: Vec<IpAddr> = ips.iter().collect();
                if resolved.is_empty() {
                    if let Some(lkg) = self.lkg_backends(DnsRefreshFailure::Empty) {
                        return Ok((lkg, HashMap::new()));
                    }
                    return Err(Error::explain(
                        InternalError,
                        format!("DNS discovery for domain {domain} returned no addresses"),
                    ));
                }
                *self.lkg.lock().unwrap_or_else(|e| e.into_inner()) = DnsLkgState {
                    addresses: Some(resolved.clone()),
                    last_success_at: Some(Instant::now()),
                };
                Ok((self.build_backends(&resolved), HashMap::new()))
            }
            Err(e) => {
                if let Some(lkg) = self.lkg_backends(DnsRefreshFailure::Lookup) {
                    return Ok((lkg, HashMap::new()));
                }
                log::warn!("DNS discovery failed for domain: {domain}: {e}");
                Err(Error::because(
                    InternalError,
                    format!("DNS discovery failed for domain: {domain}: {e}"),
                    e,
                ))
            }
        }
    }
}

/// DNS and static backend material resolved before a runtime candidate is built.
#[derive(Clone)]
pub(crate) struct PreparedUpstream {
    pub backends: BTreeSet<Backend>,
    pub health_checks: HashMap<u64, bool>,
}

/// Resolve an upstream before candidate compilation. The timeout bounds all DNS
/// lookups in this upstream; a DNS-only upstream with no result is not publishable.
pub(crate) fn prepare_static_upstream(
    upstream: &Upstream,
    resolver: &Arc<TokioResolver>,
) -> ProxyResult<PreparedUpstream> {
    let discovery: HybridDiscovery = HybridDiscovery::build(upstream.clone(), resolver.clone())?;
    match discovery.discover().now_or_never() {
        Some(Ok((backends, health_checks))) if !backends.is_empty() => Ok(PreparedUpstream {
            backends,
            health_checks,
        }),
        Some(Ok(_)) => Err(ProxyError::Configuration(format!(
            "Upstream '{}' discovery returned no backends",
            upstream.id
        ))),
        Some(Err(e)) => Err(ProxyError::Configuration(format!(
            "Upstream '{}' discovery failed: {e}",
            upstream.id
        ))),
        None => Err(ProxyError::Configuration(format!(
            "Upstream '{}' requires asynchronous DNS preparation",
            upstream.id
        ))),
    }
}

/// Used by the asynchronous control-plane preparation worker. Kept separate
/// from runtime construction so DNS I/O cannot be introduced into a writer.
pub(crate) async fn prepare_upstream(
    upstream: &Upstream,
    defaults: &config::EffectiveDefaults,
    resolver: &Arc<TokioResolver>,
) -> ProxyResult<PreparedUpstream> {
    let timeout = Duration::from_secs(defaults.dns_resolution_timeout);
    let discovery: HybridDiscovery = HybridDiscovery::build(upstream.clone(), resolver.clone())?;
    let (backends, health_checks) = tokio::time::timeout(timeout, discovery.discover())
        .await
        .map_err(|_| {
            ProxyError::Configuration(format!(
                "Upstream '{}' DNS resolution timed out after {}s",
                upstream.id,
                timeout.as_secs()
            ))
        })?
        .map_err(|e| {
            ProxyError::Configuration(format!("Upstream '{}' discovery failed: {e}", upstream.id))
        })?;
    if backends.is_empty() {
        return Err(ProxyError::Configuration(format!(
            "Upstream '{}' discovery returned no backends",
            upstream.id
        )));
    }
    Ok(PreparedUpstream {
        backends,
        health_checks,
    })
}

/// Returns prepared backends once, then delegates subsequent refreshes to the
/// normal discovery implementation.
pub(crate) struct SeededDiscovery {
    initial: Mutex<Option<PreparedUpstream>>,
    refresh: HybridDiscovery,
}

impl SeededDiscovery {
    pub(crate) fn new(initial: PreparedUpstream, refresh: HybridDiscovery) -> Self {
        Self {
            initial: Mutex::new(Some(initial)),
            refresh,
        }
    }
}

#[async_trait]
impl ServiceDiscovery for SeededDiscovery {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        if let Some(prepared) = self
            .initial
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            return Ok((prepared.backends, prepared.health_checks));
        }
        self.refresh.discover().await
    }
}

/// Hybrid service discovery.
///
/// Combines static and DNS-based service discovery.
#[derive(Default)]
pub struct HybridDiscovery {
    discoveries: Vec<Box<dyn ServiceDiscovery + Send + Sync>>,
}

#[async_trait]
impl ServiceDiscovery for HybridDiscovery {
    /// Discovers backends by combining static and DNS-based service discovery.
    ///
    /// If every sub-discovery that yields backends fails (or all succeed with
    /// none and at least one errored), the first error is surfaced so an empty
    /// backend set is never silently published. When some backends are
    /// recovered despite failures, the failed sub-discoveries are logged as
    /// warnings and the successful backends are returned.
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let mut backends = BTreeSet::new();
        let mut health_checks = HashMap::new();

        let futures = self
            .discoveries
            .iter()
            .map(|discovery| async move { discovery.discover().await });

        let results = join_all(futures).await;

        let mut first_err: Option<BError> = None;
        for result in results.into_iter() {
            match result {
                Ok((part_backends, part_health_checks)) => {
                    for backend in part_backends {
                        insert_backend(&mut backends, backend);
                    }
                    health_checks.extend(part_health_checks);
                }
                Err(e) => {
                    log::warn!("Hybrid discovery sub-task failed: {e}");
                    first_err.get_or_insert(e);
                }
            }
        }

        if backends.is_empty() {
            if let Some(err) = first_err {
                return Err(Error::because(
                    InternalError,
                    "Hybrid discovery yielded no backends and at least one sub-discovery failed",
                    err,
                ));
            }
        }

        Ok((backends, health_checks))
    }
}

impl TryFrom<Upstream> for HybridDiscovery {
    type Error = ProxyError;

    /// Migration facade: resolve through the process-global resolver.
    fn try_from(upstream: Upstream) -> ProxyResult<Self> {
        Self::build(upstream, get_global_resolver()?)
    }
}

impl HybridDiscovery {
    /// Build hybrid discovery for one upstream using the owning gateway
    /// instance's resolver (per-instance DNS isolation).
    pub(crate) fn build(upstream: Upstream, resolver: Arc<TokioResolver>) -> ProxyResult<Self> {
        let mut this = Self::default();
        let mut backends = BTreeSet::new();

        // Load client certificate if configured
        let client_cert_key = if let Some(ref tls) = upstream.tls {
            Some(load_client_cert_key(tls)?)
        } else {
            None
        };

        // Process each node in upstream
        // SNI / pass-host policy is shared with the DNS branch below; clone
        // once so both the IP peer and DnsDiscovery see the same values.
        let pass_host = upstream.pass_host.clone();
        let upstream_host = upstream.upstream_host.clone();
        for node in upstream.nodes.iter() {
            // Weight 0 means the node is configured but disabled for selection.
            if !node.is_enabled() {
                continue;
            }
            let port = node.effective_port(&upstream.scheme);
            let weight = node.weight;
            let host = node.bare_host();

            if let Ok(ip_addr) = host.parse::<IpAddr>() {
                // It's an IP address
                // Handle backend creation for IP addresses - add brackets for IPv6
                let addr_str = if ip_addr.is_ipv6() {
                    format!("[{ip_addr}]:{port}")
                } else {
                    format!("{ip_addr}:{port}")
                };
                let mut backend =
                    Backend::new_with_weight(&addr_str, weight as usize).map_err(|e| {
                        ProxyError::Configuration(format!(
                            "Failed to create backend for {addr_str}: {e}"
                        ))
                    })?;

                let sni = compute_peer_sni(host, &pass_host, upstream_host.as_deref());
                let peer = build_peer(&addr_str, upstream.scheme, sni, client_cert_key.as_ref());

                // A metadata collision is an invariant violation: reject the
                // candidate instead of panicking so the control plane can
                // classify it as a permanent configuration error.
                if backend.ext.insert::<HttpPeer>(peer).is_some() {
                    return Err(ProxyError::Configuration(format!(
                        "Backend {addr_str} already had HttpPeer metadata"
                    )));
                }

                set_backend_priority(&mut backend, node.priority);
                set_backend_id(&mut backend);
                insert_backend(&mut backends, backend);
            } else {
                // It's a domain name
                // Handle DNS discovery for domain names
                let sni = compute_peer_sni(host, &pass_host, upstream_host.as_deref());
                let discovery = DnsDiscovery::new(
                    DnsNode {
                        domain: host.to_string(),
                        port,
                        scheme: upstream.scheme,
                        weight,
                        priority: node.priority,
                        sni,
                    },
                    resolver.clone(),
                    client_cert_key.clone(),
                );
                this.discoveries.push(Box::new(discovery));
            }
        }

        if !backends.is_empty() {
            this.discoveries.push(Static::new(backends));
        }

        Ok(this)
    }
}

/// Compute the TLS SNI for a peer from the node host and pass-host policy.
///
/// Shared by DNS and literal-IP backend construction so both paths apply the
/// same rule: `pass_host: rewrite` targets `upstream_host` (falling back to the
/// node host), everything else uses the node host itself.
fn compute_peer_sni(
    host: &str,
    pass_host: &UpstreamPassHost,
    upstream_host: Option<&str>,
) -> String {
    if *pass_host == UpstreamPassHost::REWRITE {
        upstream_host.unwrap_or(host).to_string()
    } else {
        host.to_string()
    }
}

/// Build an `HttpPeer` for one backend address with a unified TLS policy.
///
/// Both DNS-resolved and literal-IP backends flow through here so scheme,
/// ALPN, mTLS, and SNI stay consistent across discovery modes.
fn build_peer(
    addr: &str,
    scheme: UpstreamScheme,
    sni: String,
    client_cert_key: Option<&Arc<CertKey>>,
) -> HttpPeer {
    let tls = matches!(scheme, UpstreamScheme::HTTPS | UpstreamScheme::GRPCS);
    let mut peer = HttpPeer::new(addr, tls, sni);
    if matches!(scheme, UpstreamScheme::GRPC | UpstreamScheme::GRPCS) {
        peer.options.alpn = ALPN::H2;
    }
    if let Some(cert_key) = client_cert_key {
        peer.client_cert_key = Some(cert_key.clone());
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub `ServiceDiscovery` that returns a fixed set of backends or an error.
    struct StubDiscovery {
        backends: Vec<Backend>,
        fail: bool,
    }

    impl StubDiscovery {
        fn ok(addrs: &[&str]) -> Self {
            let backends = addrs
                .iter()
                .map(|addr| Backend::new_with_weight(addr, 1).unwrap())
                .collect();
            Self {
                backends,
                fail: false,
            }
        }

        fn fail() -> Self {
            Self {
                backends: vec![],
                fail: true,
            }
        }
    }

    #[async_trait]
    impl ServiceDiscovery for StubDiscovery {
        async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
            if self.fail {
                return Err(Error::because(
                    InternalError,
                    "stub discovery failure",
                    std::io::Error::other("stub"),
                ));
            }
            Ok((self.backends.iter().cloned().collect(), HashMap::new()))
        }
    }

    fn hybrid(discs: Vec<StubDiscovery>) -> HybridDiscovery {
        let discoveries: Vec<Box<dyn ServiceDiscovery + Send + Sync>> = discs
            .into_iter()
            .map(|d| Box::new(d) as Box<dyn ServiceDiscovery + Send + Sync>)
            .collect();
        HybridDiscovery { discoveries }
    }

    #[tokio::test]
    async fn test_all_discoveries_fail_returns_error() {
        let hd = hybrid(vec![StubDiscovery::fail(), StubDiscovery::fail()]);
        let result = hd.discover().await;
        assert!(result.is_err(), "expected Err when all discoveries fail");
    }

    #[test]
    fn dns_discovery_serves_lkg_backends_within_stale_ttl() {
        // A transient resolver failure must not evict a recently-good node.
        let resolver = get_global_resolver().unwrap();
        let discovery = DnsDiscovery::new(
            DnsNode {
                domain: "does-not-resolve.example.test".into(),
                port: 8080,
                scheme: UpstreamScheme::HTTP,
                weight: 1,
                priority: 0,
                sni: "does-not-resolve.example.test".into(),
            },
            resolver,
            None,
        );
        assert!(
            discovery.lkg_backends(DnsRefreshFailure::Lookup).is_none(),
            "no LKG yet -> no backends"
        );
        *discovery.lkg.lock().unwrap() = DnsLkgState {
            addresses: Some(vec!["127.0.0.1".parse().unwrap()]),
            last_success_at: Some(Instant::now()),
        };
        let lkg = discovery
            .lkg_backends(DnsRefreshFailure::Empty)
            .expect("LKG backends served within TTL");
        assert_eq!(lkg.len(), 1, "one LKG backend should be rebuilt");

        discovery.lkg.lock().unwrap().last_success_at =
            Some(Instant::now() - DNS_STALE_TTL - Duration::from_secs(1));
        assert!(
            discovery.lkg_backends(DnsRefreshFailure::Lookup).is_none(),
            "expired LKG must not be reused"
        );
    }

    #[tokio::test]
    async fn test_partial_failure_returns_successful_backends() {
        let hd = hybrid(vec![
            StubDiscovery::ok(&["127.0.0.1:80"]),
            StubDiscovery::fail(),
        ]);
        let (backends, _) = hd
            .discover()
            .await
            .expect("expected Ok with successful backends on partial failure");
        assert_eq!(backends.len(), 1);
        assert!(backends
            .iter()
            .any(|b| b.addr.to_string() == "127.0.0.1:80"));
    }

    #[tokio::test]
    async fn test_all_success_returns_all() {
        let hd = hybrid(vec![
            StubDiscovery::ok(&["127.0.0.1:80"]),
            StubDiscovery::ok(&["127.0.0.2:80"]),
        ]);
        let (backends, _) = hd
            .discover()
            .await
            .expect("expected Ok when all discoveries succeed");
        assert_eq!(backends.len(), 2);
    }

    #[test]
    fn compute_peer_sni_follows_pass_host_policy() {
        assert_eq!(
            compute_peer_sni("api.example.com", &UpstreamPassHost::PASS, None),
            "api.example.com"
        );
        assert_eq!(
            compute_peer_sni("10.0.0.1", &UpstreamPassHost::NODE, None),
            "10.0.0.1"
        );
        assert_eq!(
            compute_peer_sni(
                "10.0.0.1",
                &UpstreamPassHost::REWRITE,
                Some("tenant.internal")
            ),
            "tenant.internal"
        );
        // rewrite falls back to the node host when no upstream host is configured.
        assert_eq!(
            compute_peer_sni("api.example.com", &UpstreamPassHost::REWRITE, None),
            "api.example.com"
        );
    }

    fn sample_tls(cert: &str, key: &str) -> UpstreamTls {
        UpstreamTls {
            client_cert: cert.to_string(),
            client_key: key.to_string(),
        }
    }

    #[test]
    fn client_tls_material_valid_pair_is_accepted() {
        let tls = sample_tls(
            include_str!("../testdata/example.crt"),
            include_str!("../testdata/example.key"),
        );
        validate_client_tls_material(&tls).expect("matching cert/key pair must validate");
    }

    #[test]
    fn client_tls_material_garbage_is_rejected() {
        let tls = sample_tls("CERTDATA", "PRIVATE-KEY-MATERIAL");
        assert!(
            validate_client_tls_material(&tls).is_err(),
            "unparseable PEM must be rejected"
        );
    }

    #[test]
    fn client_tls_material_mismatched_pair_is_rejected() {
        // A real certificate paired with an unrelated key must fail the
        // public-key correspondence check instead of surfacing only at the
        // first TLS handshake.
        let tls = sample_tls(
            include_str!("../testdata/example.crt"),
            include_str!("../testdata/other.key"),
        );
        assert!(
            validate_client_tls_material(&tls).is_err(),
            "cert/key pair from different keys must be rejected"
        );
    }

    #[test]
    fn upstream_with_garbage_tls_fails_preparation_not_panics() {
        // The full TryFrom path must surface a configuration error (not a
        // panic) when the mTLS material is invalid.
        use crate::config::{
            Nodes, SelectionType, Upstream, UpstreamHashOn, UpstreamPassHost, UpstreamScheme,
        };
        let upstream = Upstream {
            id: "u1".into(),
            name: None,
            retries: None,
            retry_timeout: None,
            timeout: None,
            nodes: Nodes::from_map([("127.0.0.1:80".to_string(), 1)].into_iter().collect()),
            r#type: SelectionType::RoundRobin,
            checks: None,
            hash_on: UpstreamHashOn::VARS,
            key: "uri".into(),
            scheme: UpstreamScheme::HTTP,
            pass_host: UpstreamPassHost::PASS,
            upstream_host: None,
            tls: Some(sample_tls("CERTDATA", "PRIVATE-KEY-MATERIAL")),
        };
        let result: ProxyResult<HybridDiscovery> = upstream.try_into();
        assert!(
            result.is_err(),
            "garbage TLS material must reject the upstream"
        );
    }
}
