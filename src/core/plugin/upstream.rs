//! Upstream selection and health-check types shared by plugins and the runtime.

use std::sync::Arc;

use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;
use pingora_load_balancing::Backend;
use pingora_proxy::Session;

use crate::config;

/// Outcome of a completed real-traffic interaction, used by passive health
/// checking (APISIX `checks.passive`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassiveOutcome {
    /// TCP connect/read/write failure (not a timeout).
    TcpFailure,
    /// Connect or read timeout.
    Timeout,
    /// Upstream responded with the given HTTP status code.
    Http(u16),
}

/// Abstract trait for upstream backend selection.
///
/// Decouples route logic from specific upstream implementations, enabling
/// different load balancing strategies and upstream configurations.
pub trait UpstreamSelector: Send + Sync {
    /// Select a backend for the given session.
    fn select_backend(&self, session: &mut Session) -> Option<Backend>;

    /// Observe a completed real-traffic outcome for passive health checking.
    /// Default is a no-op; upstreams without a `checks.passive` config ignore
    /// observations.
    fn observe_passive(&self, _backend: &Backend, _outcome: PassiveOutcome) {}

    /// Get the number of retries configured for this upstream.
    fn get_retries(&self) -> Option<usize>;

    /// Get the retry timeout configured for this upstream.
    fn get_retry_timeout(&self) -> Option<u64>;

    /// Get the pass host configuration for this upstream.
    fn get_pass_host(&self) -> &config::UpstreamPassHost;

    /// Rewrite the upstream host in the request header if needed.
    fn upstream_host_rewrite(&self, upstream_request: &mut RequestHeader);

    /// Stable cache-namespace fragment that changes when upstream identity or
    /// origin-selection configuration changes, so process-local cache cannot
    /// reuse stale entries after a dynamic config switch.
    fn cache_isolation_key(&self) -> u64;
}

/// One request's compiled upstream selection: the selected peer plus the
/// selector that owns retry, host-rewrite, and cache-isolation policy.
///
/// Downstream callbacks (host rewrite, retry accounting, cache key) delegate
/// to this single artifact instead of re-deriving policy from raw selectors,
/// and the route path and the traffic-split override path both produce one.
pub struct UpstreamSelection {
    pub peer: Box<HttpPeer>,
    pub upstream: Arc<dyn UpstreamSelector>,
    /// The concrete backend chosen for this request. Used for passive health
    /// checking and observability.
    pub backend: Backend,
}

/// Request-scoped remainder of an [`UpstreamSelection`] after the peer is
/// handed to Pingora. Stores only what later callbacks need (selector,
/// backend, SNI, node label) so `HttpService::upstream_peer` can move the
/// `Box<HttpPeer>` instead of cloning it.
pub struct SelectedUpstream {
    pub upstream: Arc<dyn UpstreamSelector>,
    pub backend: Backend,
    /// SNI copied from the selected peer; used for `pass_host = node`.
    pub sni: String,
    /// Address label copied from the selected peer; used for metrics.
    pub node: String,
}

impl UpstreamSelection {
    /// Extract sni/node, then move the peer to the caller.
    pub fn into_peer(self) -> (Box<HttpPeer>, SelectedUpstream) {
        let sni = self.peer.sni.clone();
        let node = self.peer._address.to_string();
        (
            self.peer,
            SelectedUpstream {
                upstream: self.upstream,
                backend: self.backend,
                sni,
                node,
            },
        )
    }
}

/// Stable fingerprint of health-check-relevant configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HealthCheckFingerprint(pub u64);

/// Spec used to reconcile background health checks without restarting unchanged ones.
pub struct HealthCheckSpec {
    pub key: String,
    pub fingerprint: HealthCheckFingerprint,
    pub service: Arc<dyn pingora_core::services::background::BackgroundService + Send + Sync>,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubSelector;

    impl UpstreamSelector for StubSelector {
        fn select_backend(&self, _session: &mut Session) -> Option<Backend> {
            None
        }

        fn get_retries(&self) -> Option<usize> {
            None
        }

        fn get_retry_timeout(&self) -> Option<u64> {
            None
        }

        fn get_pass_host(&self) -> &config::UpstreamPassHost {
            &config::UpstreamPassHost::PASS
        }

        fn upstream_host_rewrite(&self, _upstream_request: &mut RequestHeader) {}

        fn cache_isolation_key(&self) -> u64 {
            0
        }
    }

    #[test]
    fn into_peer_moves_peer_and_keeps_sni_and_node() {
        let peer = HttpPeer::new("127.0.0.1:8080", false, "example.com".into());
        let backend = Backend::new("127.0.0.1:8080").expect("test backend");
        let selection = UpstreamSelection {
            peer: Box::new(peer),
            upstream: Arc::new(StubSelector),
            backend,
        };
        let (peer, selected) = selection.into_peer();
        assert_eq!(peer.sni, "example.com");
        assert_eq!(selected.sni, "example.com");
        assert!(
            selected.node.contains("127.0.0.1"),
            "node label should keep the selected address, got {}",
            selected.node
        );
    }
}
