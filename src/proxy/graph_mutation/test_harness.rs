//! Instance-owned graph test fixture.
//!
//! Production constructs [`ConfigurationGraph`] through
//! [`ConfigurationGraph::with_state`]. Tests that previously read process-global
//! `RUNTIME` / status / keyring facades use this harness so two cases in one
//! process never share published snapshots or secrets.

use std::sync::Arc;

use hickory_resolver::TokioResolver;

use crate::config::EffectiveDefaults;
use crate::core::status::StatusStore;
use crate::proxy::runtime::RuntimeStore;
use crate::proxy::upstream::health_check::SharedHealthCheckService;
use crate::utils::encryption::KeyringService;

use super::{ConfigurationGraph, GraphStore};

/// Fully instance-owned graph plus the stores it publishes into.
pub struct GraphTestHarness {
    pub graph: ConfigurationGraph,
    pub runtime: Arc<RuntimeStore>,
    pub status: Arc<StatusStore>,
    pub keyring: Arc<KeyringService>,
    pub defaults: EffectiveDefaults,
    pub resolver: Arc<TokioResolver>,
    pub health_check: Arc<SharedHealthCheckService>,
}

impl GraphTestHarness {
    /// Build a graph bound to fresh status, runtime, keyring, defaults, and DNS.
    /// Nothing here reads process-global gateway state.
    pub fn new(store: Arc<dyn GraphStore>) -> Self {
        let status = Arc::new(StatusStore::new());
        let health_check = Arc::new(SharedHealthCheckService::new());
        let runtime = Arc::new(RuntimeStore::with_state(
            status.clone(),
            health_check.clone(),
        ));
        let defaults = EffectiveDefaults::default();
        let keyring = Arc::new(KeyringService::disabled());
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state()
            .expect("DNS resolver construction must succeed");
        let graph = ConfigurationGraph::with_state(
            store,
            status.clone(),
            runtime.clone(),
            defaults.clone(),
            keyring.clone(),
            resolver.clone(),
        );
        Self {
            graph,
            runtime,
            status,
            keyring,
            defaults,
            resolver,
            health_check,
        }
    }
}

#[cfg(test)]
mod isolation_tests {
    use super::*;
    use crate::proxy::graph_mutation::InMemoryGraphStore;
    use crate::proxy::graph_mutation::{ResourceKey, ResourceKind, StoredGraph, StoredResource};
    use std::time::Duration;

    fn upstream_json(id: &str, node: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "nodes": { node: 1 },
            "type": "roundrobin",
            "hash_on": "vars",
            "key": "uri",
            "scheme": "http",
            "pass_host": "pass",
        })
    }

    fn route_json(id: &str, upstream_id: &str, uri: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "uri": uri,
            "upstream_id": upstream_id,
        })
    }

    fn stored_graph(
        revision: i64,
        pairs: Vec<(ResourceKind, &str, serde_json::Value)>,
    ) -> StoredGraph {
        let mut graph = StoredGraph {
            revision,
            ..Default::default()
        };
        for (kind, id, value) in pairs {
            let key = ResourceKey::new(kind, id).unwrap();
            graph.resources.insert(
                key,
                StoredResource {
                    value: serde_json::to_vec(&value).unwrap(),
                    create_revision: 1,
                    mod_revision: revision,
                },
            );
        }
        graph
    }

    #[tokio::test]
    async fn two_harnesses_do_not_share_runtime_or_status() {
        let a = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let b = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));

        a.graph
            .replace_all(stored_graph(
                100,
                vec![
                    (
                        ResourceKind::Upstream,
                        "u1",
                        upstream_json("u1", "127.0.0.1:80"),
                    ),
                    (ResourceKind::Route, "r1", route_json("r1", "u1", "/")),
                ],
            ))
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if a.runtime.load().upstreams.contains_key("u1") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "harness A must publish its own upstream"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            b.runtime.load().upstreams.is_empty(),
            "harness B must not observe A's published upstream"
        );
        assert_eq!(b.status.published_revision(), 0);
        assert_ne!(a.runtime.load().revision, 0);
        assert!(!Arc::ptr_eq(&a.runtime, &b.runtime));
        assert!(!Arc::ptr_eq(&a.status, &b.status));
        assert!(!Arc::ptr_eq(&a.keyring, &b.keyring));
        assert!(!Arc::ptr_eq(&a.health_check, &b.health_check));
        assert!(!Arc::ptr_eq(&a.resolver, &b.resolver));
        assert_eq!(
            a.defaults.dns_resolution_timeout,
            b.defaults.dns_resolution_timeout
        );
        a.graph.shutdown().await;
        b.graph.shutdown().await;
    }
}
