#[cfg(test)]
mod cas_conflict_tests {
    use crate::config::etcd::InMemoryGraphStore;
    use crate::proxy::graph_mutation::*;
    use crate::proxy::graph_mutation::{GraphCommit, StoredMutation};
    use async_trait::async_trait;
    use std::sync::Arc;

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

    async fn seed_upstream(store: &InMemoryGraphStore) {
        let key = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        store
            .compare_and_swap(GraphCommit {
                mutation: StoredMutation::Put {
                    key,
                    value: serde_json::to_vec(&upstream_json("u1", "127.0.0.1:80")).unwrap(),
                },
                expected_target_mod_revision: None,
                expected_guard_mod_revision: None,
            })
            .await
            .unwrap();
    }

    /// Synchronizes two writers so both observe the same snapshot revision and
    /// then race at CAS with identical stale guard/target expectations.
    struct SyncedGraphStore {
        inner: Arc<InMemoryGraphStore>,
        snapshot_barrier: Arc<tokio::sync::Barrier>,
        cas_barrier: Arc<tokio::sync::Barrier>,
    }

    #[async_trait]
    impl GraphStore for SyncedGraphStore {
        async fn get_exact(&self, key: &ResourceKey) -> Result<Option<StoredResource>, StoreError> {
            self.inner.get_exact(key).await
        }

        async fn list_kind(
            &self,
            kind: ResourceKind,
        ) -> Result<Vec<(ResourceKey, StoredResource)>, StoreError> {
            self.inner.list_kind(kind).await
        }

        async fn snapshot(&self) -> Result<StoredGraph, StoreError> {
            let graph = self.inner.snapshot().await?;
            self.snapshot_barrier.wait().await;
            Ok(graph)
        }

        async fn compare_and_swap(
            &self,
            commit: GraphCommit,
        ) -> Result<CommitRevision, StoreError> {
            self.cas_barrier.wait().await;
            self.inner.compare_and_swap(commit).await
        }
    }

    fn synced_pair(inner: Arc<InMemoryGraphStore>) -> (Arc<dyn GraphStore>, Arc<dyn GraphStore>) {
        let snapshot_barrier = Arc::new(tokio::sync::Barrier::new(2));
        let cas_barrier = Arc::new(tokio::sync::Barrier::new(2));
        let make = || {
            Arc::new(SyncedGraphStore {
                inner: inner.clone(),
                snapshot_barrier: snapshot_barrier.clone(),
                cas_barrier: cas_barrier.clone(),
            }) as Arc<dyn GraphStore>
        };
        (make(), make())
    }

    async fn race_puts(
        put_a: impl std::future::Future<Output = Result<CommitRevision, GraphError>>,
        put_b: impl std::future::Future<Output = Result<CommitRevision, GraphError>>,
    ) {
        let (out_a, out_b) = tokio::join!(put_a, put_b);
        let results = [out_a, out_b];
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "exactly one raced put should commit"
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(GraphError::CasConflict)))
                .count(),
            1,
            "stale CAS expectations must map to GraphError::CasConflict"
        );
    }

    /// Two graph authorities sharing one store race on the generation guard.
    /// The loser must surface [`GraphError::CasConflict`], not a raw store error.
    #[tokio::test]
    async fn concurrent_puts_stale_guard_returns_cas_conflict() {
        let inner = Arc::new(InMemoryGraphStore::new());
        seed_upstream(inner.as_ref()).await;

        let (store_a, store_b) = synced_pair(inner);
        let graph_a = ConfigurationGraph::new(store_a);
        let graph_b = ConfigurationGraph::new(store_b);

        let route_a = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        let route_b = ResourceKey::new(ResourceKind::Route, "r2").unwrap();

        race_puts(
            graph_a.put(route_a, route_json("r1", "u1", "/a")),
            graph_b.put(route_b, route_json("r2", "u1", "/b")),
        )
        .await;
    }

    /// Concurrent updates to the same resource with a stale target mod revision
    /// must also surface [`GraphError::CasConflict`] at the authority layer.
    #[tokio::test]
    async fn concurrent_puts_stale_target_returns_cas_conflict() {
        let inner = Arc::new(InMemoryGraphStore::new());
        seed_upstream(inner.as_ref()).await;
        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        inner
            .compare_and_swap(GraphCommit {
                mutation: StoredMutation::Put {
                    key: route.clone(),
                    value: serde_json::to_vec(&route_json("r1", "u1", "/v1")).unwrap(),
                },
                expected_target_mod_revision: None,
                expected_guard_mod_revision: Some(1),
            })
            .await
            .unwrap();

        let (store_a, store_b) = synced_pair(inner);
        let graph_a = ConfigurationGraph::new(store_a);
        let graph_b = ConfigurationGraph::new(store_b);

        race_puts(
            graph_a.put(route.clone(), route_json("r1", "u1", "/v2-a")),
            graph_b.put(route, route_json("r1", "u1", "/v2-b")),
        )
        .await;
    }
}
