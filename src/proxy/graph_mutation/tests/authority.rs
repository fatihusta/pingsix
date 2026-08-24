#[cfg(test)]
mod authority_tests {
    use crate::proxy::graph_mutation::authority::validate_resource_json;
    use crate::proxy::graph_mutation::state::{
        safe_preparation_error, PublicationRegistry, PUBLICATION_REGISTRY_CAPACITY,
    };
    use crate::proxy::graph_mutation::InMemoryGraphStore;
    use crate::proxy::graph_mutation::*;
    use crate::proxy::graph_mutation::{GraphCommit, StoredMutation};
    use async_trait::async_trait;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn admin_validation_accepts_unknown_fields_after_warning() {
        let value = serde_json::json!({
            "id": "u1",
            "nodes": { "127.0.0.1:80": 1 },
            "retry_timout": 10,
            "checks": {
                "active": {
                    "healthy": { "sucesses": 2 },
                },
            },
        });

        // The Admin validation path invokes the warning helper but preserves
        // forward-compatible unknown fields rather than rejecting the write.
        assert!(validate_resource_json(ResourceKind::Upstream, &value).is_ok());
    }

    #[test]
    fn preparation_errors_are_safe_summaries() {
        assert_eq!(
            safe_preparation_error(false),
            "candidate preparation temporarily unavailable"
        );
        assert_eq!(
            safe_preparation_error(true),
            "candidate rejected during runtime preparation"
        );
    }

    #[test]
    fn publication_registry_tracks_terminal_states_and_bounds_history() {
        let mut registry = PublicationRegistry::default();
        registry.pending(10);
        registry.published(10);
        assert_eq!(
            registry.view(10).unwrap().state,
            PublicationState::Published
        );

        registry.pending(11);
        registry.supersede_pending_except(12);
        assert_eq!(
            registry.view(11).unwrap().state,
            PublicationState::Superseded
        );

        registry.pending(12);
        registry.rejected(12, "safe summary".into());
        let rejected = registry.view(12).unwrap();
        assert_eq!(rejected.state, PublicationState::Rejected);
        assert_eq!(rejected.error.as_deref(), Some("safe summary"));

        for revision in 13..(13 + PUBLICATION_REGISTRY_CAPACITY as i64 + 5) {
            registry.pending(revision);
            registry.published(revision);
        }
        assert!(registry.records.len() <= PUBLICATION_REGISTRY_CAPACITY);
    }

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

    fn route_json(id: &str, upstream_id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "uri": "/",
            "upstream_id": upstream_id,
        })
    }

    fn ssl_json(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "cert": include_str!("../../testdata/example.crt"),
            "key": include_str!("../../testdata/example.key"),
            "snis": ["example.com"],
        })
    }

    async fn seed(store: &InMemoryGraphStore, key: ResourceKey, value: Vec<u8>) {
        store
            .compare_and_swap(GraphCommit {
                mutation: StoredMutation::Put { key, value },
                expected_target_mod_revision: None,
                expected_guard_mod_revision: None,
            })
            .await
            .unwrap();
    }

    /// Records Admin read calls while making accidental snapshot reads fail.
    struct TargetedReadStore {
        inner: Arc<InMemoryGraphStore>,
        exact_gets: AtomicUsize,
        kind_lists: AtomicUsize,
    }

    #[async_trait]
    impl GraphStore for TargetedReadStore {
        async fn get_exact(&self, key: &ResourceKey) -> Result<Option<StoredResource>, StoreError> {
            self.exact_gets.fetch_add(1, Ordering::Relaxed);
            self.inner.get_exact(key).await
        }

        async fn list_kind(
            &self,
            kind: ResourceKind,
        ) -> Result<Vec<(ResourceKey, StoredResource)>, StoreError> {
            self.kind_lists.fetch_add(1, Ordering::Relaxed);
            self.inner.list_kind(kind).await
        }

        async fn snapshot(&self) -> Result<StoredGraph, StoreError> {
            Err(StoreError::InvalidResponse {
                message: "Admin reads must not use snapshots".into(),
            })
        }

        async fn compare_and_swap(
            &self,
            commit: GraphCommit,
        ) -> Result<CommitRevision, StoreError> {
            self.inner.compare_and_swap(commit).await
        }
    }

    #[tokio::test]
    async fn get_and_list_use_targeted_store_reads_and_redact() {
        let inner = Arc::new(InMemoryGraphStore::new());
        let ssl = ResourceKey::new(ResourceKind::Ssl, "t1").unwrap();
        seed(
            inner.as_ref(),
            ssl.clone(),
            serde_json::to_vec(&ssl_json("t1")).unwrap(),
        )
        .await;
        let store = Arc::new(TargetedReadStore {
            inner,
            exact_gets: AtomicUsize::new(0),
            kind_lists: AtomicUsize::new(0),
        });
        let graph = ConfigurationGraph::new(store.clone());

        let fetched = graph.get(&ssl).await.unwrap().unwrap();
        assert_eq!(fetched.value["key"], "***");
        let listed = graph.list(ResourceKind::Ssl).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, ssl);
        assert_eq!(listed[0].value["key"], "***");
        assert_eq!(store.exact_gets.load(Ordering::Relaxed), 1);
        assert_eq!(store.kind_lists.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn put_commits_and_get_round_trips() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        let rev = graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        assert_eq!(rev.0, 1);

        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        graph
            .put(route.clone(), route_json("r1", "u1"))
            .await
            .unwrap();

        let view = graph.get(&route).await.unwrap().unwrap();
        assert_eq!(view.value["uri"], "/");
        assert_eq!(view.mod_revision, 2);
        assert_eq!(graph.get(&up).await.unwrap().unwrap().create_revision, 1);

        assert!(graph
            .get(&ResourceKey::new(ResourceKind::Route, "ghost").unwrap())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn put_redacted_resave_restores_stored_secret() {
        let store = Arc::new(InMemoryGraphStore::new());
        let graph = ConfigurationGraph::new(store.clone());

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();

        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        let stored = serde_json::json!({
            "id": "r1",
            "uri": "/",
            "upstream_id": "u1",
            "plugins": { "key-auth": { "keys": ["real-key"] } },
        });
        graph.put(route.clone(), stored.clone()).await.unwrap();

        // Client resaves the redacted GET body: the sentinel is restored from
        // the same snapshot used for the CAS commit.
        let resave = serde_json::json!({
            "id": "r1",
            "uri": "/v2",
            "upstream_id": "u1",
            "plugins": { "key-auth": { "keys": ["***"] } },
        });
        graph.put(route.clone(), resave.clone()).await.unwrap();

        // GET returns the redacted view by design; the stored value must hold
        // the restored secret.
        let view = graph.get(&route).await.unwrap().unwrap();
        assert_eq!(view.value["uri"], "/v2");
        assert_eq!(view.value["plugins"]["key-auth"]["keys"][0], "***");
        let snapshot = store.snapshot().await.unwrap();
        let stored: serde_json::Value =
            serde_json::from_slice(&snapshot.resources[&route].value).unwrap();
        assert_eq!(stored["plugins"]["key-auth"]["keys"][0], "real-key");
    }

    #[tokio::test]
    async fn put_rotation_keeps_new_secret() {
        let store = Arc::new(InMemoryGraphStore::new());
        let graph = ConfigurationGraph::new(store.clone());

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        graph
            .put(
                route.clone(),
                serde_json::json!({
                    "id": "r1", "uri": "/", "upstream_id": "u1",
                    "plugins": { "key-auth": { "keys": ["old-key"] } },
                }),
            )
            .await
            .unwrap();

        // Rotation sends a real value (not the sentinel); it must be kept.
        graph
            .put(
                route.clone(),
                serde_json::json!({
                    "id": "r1", "uri": "/", "upstream_id": "u1",
                    "plugins": { "key-auth": { "keys": ["new-key"] } },
                }),
            )
            .await
            .unwrap();

        let view = graph.get(&route).await.unwrap().unwrap();
        assert_eq!(view.value["plugins"]["key-auth"]["keys"][0], "***");
        let snapshot = store.snapshot().await.unwrap();
        let stored: serde_json::Value =
            serde_json::from_slice(&snapshot.resources[&route].value).unwrap();
        assert_eq!(stored["plugins"]["key-auth"]["keys"][0], "new-key");
    }

    #[tokio::test]
    async fn put_normalizes_body_id_to_path_id() {
        let store = Arc::new(InMemoryGraphStore::new());
        let graph = ConfigurationGraph::new(store.clone());

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();

        // Body id deliberately differs from (and omits) the path id.
        let route = ResourceKey::new(ResourceKind::Route, "path-id").unwrap();
        graph
            .put(
                route.clone(),
                serde_json::json!({
                    "id": "body-id",
                    "uri": "/",
                    "upstream_id": "u1",
                }),
            )
            .await
            .unwrap();

        // GET and the stored bytes must both carry the authoritative path id.
        let view = graph.get(&route).await.unwrap().unwrap();
        assert_eq!(view.value["id"], "path-id");
        let snapshot = store.snapshot().await.unwrap();
        let stored: serde_json::Value =
            serde_json::from_slice(&snapshot.resources[&route].value).unwrap();
        assert_eq!(stored["id"], "path-id");

        // The body-only identity must not exist.
        assert!(graph
            .get(&ResourceKey::new(ResourceKind::Route, "body-id").unwrap())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn put_normalizes_missing_body_id_to_path_id() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();

        // No `id` in the body at all: the path id must be injected before the
        // typed validation (which requires a non-empty id).
        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        graph
            .put(
                route.clone(),
                serde_json::json!({ "uri": "/", "upstream_id": "u1" }),
            )
            .await
            .unwrap();
        let view = graph.get(&route).await.unwrap().unwrap();
        assert_eq!(view.value["id"], "r1");
    }

    #[tokio::test]
    async fn put_rejects_invalid_upstream_tls_material() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let up = ResourceKey::new(ResourceKind::Upstream, "tls-bad").unwrap();
        let err = graph
            .put(
                up.clone(),
                serde_json::json!({
                    "id": "tls-bad",
                    "nodes": { "127.0.0.1:80": 1 },
                    "type": "roundrobin",
                    "hash_on": "vars",
                    "key": "uri",
                    "scheme": "http",
                    "pass_host": "pass",
                    "tls": {
                        "client_cert": "CERTDATA",
                        "client_key": "PRIVATE-KEY-MATERIAL"
                    }
                }),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GraphError::InvalidResource { .. }), "{err:?}");
        assert!(graph.get(&up).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn put_accepts_valid_upstream_tls_material() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let up = ResourceKey::new(ResourceKind::Upstream, "tls-ok").unwrap();
        graph
            .put(
                up.clone(),
                serde_json::json!({
                    "id": "tls-ok",
                    "nodes": { "127.0.0.1:80": 1 },
                    "type": "roundrobin",
                    "hash_on": "vars",
                    "key": "uri",
                    "scheme": "https",
                    "pass_host": "pass",
                    "tls": {
                        "client_cert": include_str!("../../testdata/example.crt"),
                        "client_key": include_str!("../../testdata/example.key"),
                    }
                }),
            )
            .await
            .expect("matching cert/key pair must be accepted");
    }

    #[tokio::test]
    async fn put_rejects_route_with_both_upstream_sources() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        let err = graph
            .put(
                route.clone(),
                serde_json::json!({
                    "id": "r1",
                    "uri": "/",
                    "upstream": {
                        "nodes": { "127.0.0.1:80": 1 },
                        "type": "roundrobin",
                        "hash_on": "vars",
                        "key": "uri",
                        "scheme": "http",
                        "pass_host": "pass"
                    },
                    "upstream_id": "u1",
                }),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, GraphError::InvalidResource { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn put_invalid_candidate_rejects_without_store_mutation() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        let before = graph.list(ResourceKind::Route).await.unwrap();

        let route = ResourceKey::new(ResourceKind::Route, "bad").unwrap();
        let err = graph
            .put(route.clone(), route_json("bad", "missing"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "{err:?}"
        );

        let after = graph.list(ResourceKind::Route).await.unwrap();
        assert_eq!(before.len(), after.len());
        assert!(graph.get(&route).await.unwrap().is_none());
    }

    /// A known builtin plugin with a structurally invalid config must be
    /// rejected at Admin PUT time (before any store mutation), not deferred
    /// to async candidate preparation. This guards the `validate_plugin_config`
    /// contract for plain plugins, which validate by construction.
    #[tokio::test]
    async fn put_rejects_malformed_known_plugin_config_without_store_mutation() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        let before = graph.list(ResourceKind::Route).await.unwrap();

        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        // `limit-req` is a known plain plugin; rate <= 0 fails its validator.
        let invalid_route = serde_json::json!({
            "id": "r1",
            "uri": "/",
            "upstream_id": "u1",
            "plugins": { "limit-req": { "rate": 0.0, "key": "remote_addr" } },
        });
        let err = graph.put(route.clone(), invalid_route).await.unwrap_err();
        assert!(matches!(err, GraphError::InvalidResource { .. }), "{err:?}");

        let after = graph.list(ResourceKind::Route).await.unwrap();
        assert_eq!(before.len(), after.len());
        assert!(graph.get(&route).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_referenced_conflicts_and_missing_is_not_found() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        graph
            .put(route.clone(), route_json("r1", "u1"))
            .await
            .unwrap();

        let err = graph.delete(up.clone()).await.unwrap_err();
        assert!(
            matches!(err, GraphError::ReferentialConflict { .. }),
            "{err:?}"
        );

        let err = graph
            .delete(ResourceKey::new(ResourceKind::Route, "ghost").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, GraphError::NotFound { .. }), "{err:?}");

        graph.delete(route.clone()).await.unwrap();
        graph.delete(up.clone()).await.unwrap();
        assert!(graph.list(ResourceKind::Route).await.unwrap().is_empty());
        assert!(graph.list(ResourceKind::Upstream).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_returns_only_requested_kind() {
        let store = InMemoryGraphStore::new();
        let graph = ConfigurationGraph::new(Arc::new(store));
        graph
            .put(
                ResourceKey::new(ResourceKind::Upstream, "u1").unwrap(),
                upstream_json("u1", "127.0.0.1:80"),
            )
            .await
            .unwrap();
        graph
            .put(
                ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
                ssl_json("t1"),
            )
            .await
            .unwrap();
        graph
            .put(
                ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
                route_json("r1", "u1"),
            )
            .await
            .unwrap();

        let routes = graph.list(ResourceKind::Route).await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].key.id, "r1");
        let ssls = graph.list(ResourceKind::Ssl).await.unwrap();
        assert_eq!(ssls.len(), 1);
        assert_eq!(ssls[0].value["key"], "***", "GET/LIST views are redacted");
        assert_eq!(ssls[0].value["snis"], serde_json::json!(["example.com"]));
    }

    #[tokio::test]
    async fn undecryptable_sibling_does_not_block_unrelated_put() {
        let store = Arc::new(InMemoryGraphStore::new());
        let graph = ConfigurationGraph::new(store.clone());

        // Stored SSL whose key is ciphertext that cannot be decrypted (no
        // keyring installed in unit tests). Validation must not attempt to
        // decrypt it, so a repair PUT of an unrelated resource still works.
        let ssl = ResourceKey::new(ResourceKind::Ssl, "t1").unwrap();
        let mut ciphertext_ssl = ssl_json("t1");
        ciphertext_ssl["key"] = serde_json::json!("$pingsix-enc:v1$cipher");
        seed(
            store.as_ref(),
            ssl.clone(),
            serde_json::to_vec(&ciphertext_ssl).unwrap(),
        )
        .await;

        let up = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        graph
            .put(up.clone(), upstream_json("u1", "127.0.0.1:80"))
            .await
            .unwrap();
        let route = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        graph
            .put(route.clone(), route_json("r1", "u1"))
            .await
            .unwrap();
        assert!(graph.get(&route).await.unwrap().is_some());
    }
}
