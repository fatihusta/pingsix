#[cfg(test)]
mod worker_tests {
    use crate::config;
    use crate::config::etcd::InMemoryGraphStore;
    use crate::config::EffectiveDefaults;
    use crate::core::status::StatusStore;
    use crate::proxy::graph_mutation::*;
    use crate::proxy::graph_mutation::{GraphTestHarness, StoredChange, StoredResource};
    use crate::proxy::runtime::RuntimeStore;
    use std::sync::Arc;
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
                key.clone(),
                StoredResource {
                    value: serde_json::to_vec(&value).unwrap(),
                    create_revision: 1,
                    mod_revision: revision,
                },
            );
        }
        graph
    }

    fn upstream_change(revision: i64, id: &str, node: &str) -> WatchBatch {
        let key = ResourceKey::new(ResourceKind::Upstream, id).unwrap();
        WatchBatch {
            revision,
            changes: vec![StoredChange::Put {
                key: key.clone(),
                resource: StoredResource {
                    value: serde_json::to_vec(&upstream_json(id, node)).unwrap(),
                    create_revision: 1,
                    mod_revision: revision,
                },
            }],
        }
    }

    fn route_change(revision: i64, id: &str, upstream_id: &str, uri: &str) -> WatchBatch {
        let key = ResourceKey::new(ResourceKind::Route, id).unwrap();
        WatchBatch {
            revision,
            changes: vec![StoredChange::Put {
                key: key.clone(),
                resource: StoredResource {
                    value: serde_json::to_vec(&route_json(id, upstream_id, uri)).unwrap(),
                    create_revision: 1,
                    mod_revision: revision,
                },
            }],
        }
    }

    async fn wait_for_revision(runtime: &RuntimeStore, min: i64, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if runtime.load().revision >= min {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn replace_all_publishes_snapshot() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();
        let base = harness.runtime.load().revision;
        let revision = base + 100;
        let snapshot = stored_graph(
            revision,
            vec![
                (
                    ResourceKind::Upstream,
                    "u1",
                    upstream_json("u1", "127.0.0.1:80"),
                ),
                (ResourceKind::Route, "r1", route_json("r1", "u1", "/")),
            ],
        );
        graph.replace_all(snapshot).unwrap();
        assert!(
            wait_for_revision(&harness.runtime, revision, Duration::from_secs(5)).await,
            "snapshot must publish"
        );
        let snap = harness.runtime.load();
        assert_eq!(snap.revision, revision);
        assert!(snap.upstreams.contains_key("u1"));
        assert!(snap.routes.contains_key("r1"));
        graph.shutdown().await;
    }

    #[tokio::test]
    async fn invalid_candidate_rejected_synchronously_keeps_lkg_and_later_valid_publishes() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();
        let base = harness.runtime.load().revision;

        let good = base + 100;
        graph
            .replace_all(stored_graph(
                good,
                vec![(
                    ResourceKind::Upstream,
                    "u1",
                    upstream_json("u1", "127.0.0.1:80"),
                )],
            ))
            .unwrap();
        assert!(wait_for_revision(&harness.runtime, good, Duration::from_secs(5)).await);

        // Dangling route reference: whole-graph validation rejects the full
        // list synchronously, so nothing is submitted and the worker never
        // retries a permanently invalid candidate.
        let bad = good + 1;
        let err = graph
            .replace_all(stored_graph(
                bad,
                vec![(
                    ResourceKind::Route,
                    "bad",
                    route_json("bad", "missing", "/"),
                )],
            ))
            .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "{err:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            harness.runtime.load().revision,
            good,
            "invalid candidate must not publish"
        );

        // A later valid generation publishes on top of the LKG.
        let later = good + 2;
        graph
            .replace_all(stored_graph(
                later,
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
        assert!(
            wait_for_revision(&harness.runtime, later, Duration::from_secs(5)).await,
            "later valid generation must publish"
        );
        graph.shutdown().await;
    }

    #[tokio::test]
    async fn apply_watch_stale_and_empty_batches() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();
        let base = harness.runtime.load().revision;
        let published = base + 100;
        graph
            .replace_all(stored_graph(
                published,
                vec![(
                    ResourceKind::Upstream,
                    "u1",
                    upstream_json("u1", "127.0.0.1:80"),
                )],
            ))
            .unwrap();
        assert!(wait_for_revision(&harness.runtime, published, Duration::from_secs(5)).await);

        // Empty batch is a no-op and does not advance the published revision.
        graph.apply_watch(WatchBatch::default()).unwrap();
        assert_eq!(harness.runtime.load().revision, published);

        // A watch older than the published revision is rejected synchronously.
        let err = graph
            .apply_watch(upstream_change(published - 1, "u1", "127.0.0.1:81"))
            .unwrap_err();
        assert!(matches!(
            err,
            GraphError::StaleRevision {
                incoming,
                published: p
            } if incoming == published - 1 && p == published
        ));
        graph.shutdown().await;
    }

    #[tokio::test]
    async fn watch_changes_layer_on_pending_target() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();
        let base = harness.runtime.load().revision;
        let first = base + 100;
        graph
            .replace_all(stored_graph(
                first,
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
        assert!(wait_for_revision(&harness.runtime, first, Duration::from_secs(5)).await);

        // Two batches back-to-back: the second must layer on the first, not on
        // the committed graph, so no update is lost regardless of worker timing.
        graph
            .apply_watch(upstream_change(first + 1, "u1", "127.0.0.1:81"))
            .unwrap();
        graph
            .apply_watch(route_change(first + 2, "r1", "u1", "/v2"))
            .unwrap();
        assert!(
            wait_for_revision(&harness.runtime, first + 2, Duration::from_secs(5)).await,
            "layered watch batches must publish"
        );
        let snap = harness.runtime.load();
        assert_eq!(snap.revision, first + 2);
        assert!(snap.upstreams["u1"]
            .inner
            .nodes
            .contains_addr("127.0.0.1:81"));
        assert_eq!(snap.routes["r1"].inner.uri.as_deref(), Some("/v2"));
        graph.shutdown().await;
    }

    #[tokio::test]
    async fn route_only_change_reuses_upstream_arc() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();
        let base = harness.runtime.load().revision;
        let first = base + 100;
        graph
            .replace_all(stored_graph(
                first,
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
        assert!(wait_for_revision(&harness.runtime, first, Duration::from_secs(5)).await);
        let old_upstream = Arc::as_ptr(harness.runtime.load().upstreams.get("u1").unwrap());

        graph
            .apply_watch(route_change(first + 1, "r1", "u1", "/v2"))
            .unwrap();
        assert!(wait_for_revision(&harness.runtime, first + 1, Duration::from_secs(5)).await);
        let snap = harness.runtime.load();
        assert_eq!(
            Arc::as_ptr(snap.upstreams.get("u1").unwrap()),
            old_upstream,
            "unchanged upstream must be reused"
        );
        assert_eq!(snap.routes["r1"].inner.uri.as_deref(), Some("/v2"));
        graph.shutdown().await;
    }

    /// A stored SSL whose TLS material is structurally fine but unparseable:
    /// passes decode and whole-graph validation, fails candidate build. This is
    /// the deterministic worker-level failure used by the retry-loop tests.
    fn stored_bad_ssl_graph(revision: i64) -> StoredGraph {
        stored_graph(
            revision,
            vec![(
                ResourceKind::Ssl,
                "t1",
                serde_json::json!({
                    "id": "t1",
                    "cert": "not-a-pem",
                    "key": "not-a-pem",
                    "snis": ["example.com"],
                }),
            )],
        )
    }

    #[tokio::test]
    async fn apply_watch_rejects_invalid_batches_without_publish() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();
        let base = harness.runtime.load().revision;
        let published = base + 100;
        graph
            .replace_all(stored_graph(
                published,
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
        assert!(wait_for_revision(&harness.runtime, published, Duration::from_secs(5)).await);

        // Dangling route reference: rejected synchronously, no submission.
        let err = graph
            .apply_watch(WatchBatch {
                revision: published + 1,
                changes: vec![StoredChange::Put {
                    key: ResourceKey::new(ResourceKind::Route, "dangling").unwrap(),
                    resource: StoredResource {
                        value: serde_json::to_vec(&route_json("dangling", "missing", "/")).unwrap(),
                        create_revision: 1,
                        mod_revision: published + 1,
                    },
                }],
            })
            .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "{err:?}"
        );

        // Traffic-split referencing a missing upstream: whole-graph validation
        // catches it before submission, not after DNS preparation.
        let err = graph
            .apply_watch(WatchBatch {
                revision: published + 2,
                changes: vec![StoredChange::Put {
                    key: ResourceKey::new(ResourceKind::Route, "split").unwrap(),
                    resource: StoredResource {
                        value: serde_json::to_vec(&serde_json::json!({
                            "id": "split",
                            "uri": "/split",
                            "upstream_id": "u1",
                            "plugins": {
                                "traffic-split": {
                                    "rules": [{
                                        "weighted_upstreams": [
                                            { "upstream_id": "does-not-exist", "weight": 100 }
                                        ]
                                    }]
                                }
                            },
                        }))
                        .unwrap(),
                        create_revision: 1,
                        mod_revision: published + 2,
                    },
                }],
            })
            .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "{err:?}"
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            harness.runtime.load().revision,
            published,
            "rejected batches must not publish"
        );
        graph.shutdown().await;
    }

    #[tokio::test]
    async fn superseded_failed_generation_does_not_delay_valid_submission() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();
        let base = harness.runtime.load().revision;

        // The failing generation passes validation but fails candidate build,
        // so the worker enters its retry/backoff loop.
        let failing = base + 100;
        graph.replace_all(stored_bad_ssl_graph(failing)).unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        // A valid submission while the failed generation is backing off must
        // publish promptly — it must not wait out the failed backoff.
        let valid = failing + 1;
        graph
            .replace_all(stored_graph(
                valid,
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
        assert!(
            wait_for_revision(&harness.runtime, valid, Duration::from_secs(2)).await,
            "valid generation must publish without waiting out the failed backoff"
        );
        let snap = harness.runtime.load();
        assert_eq!(snap.revision, valid);
        assert!(snap.upstreams.contains_key("u1"));
        graph.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_cancels_retry_loop() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();
        let base = harness.runtime.load().revision;
        // Garbage TLS material passes validation but fails candidate build, so
        // the worker enters its retry/backoff loop.
        graph.replace_all(stored_bad_ssl_graph(base + 100)).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Shutdown must cancel the retry sleep and return within the bound.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        graph.shutdown().await;
        assert!(tokio::time::Instant::now() < deadline);
        assert_eq!(
            harness.runtime.load().revision,
            base,
            "failing candidate must never publish"
        );
    }

    #[tokio::test]
    async fn shutdown_is_terminal_and_submissions_fail_with_worker_stopped() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();

        // Submissions work before shutdown.
        let revision = 1_000_000;
        graph
            .replace_all(stored_graph(
                revision,
                vec![(
                    ResourceKind::Upstream,
                    "u1",
                    upstream_json("u1", "127.0.0.1:80"),
                )],
            ))
            .unwrap();
        assert!(wait_for_revision(&harness.runtime, revision, Duration::from_secs(5)).await);

        graph.shutdown().await;

        // A second shutdown is an idempotent no-op.
        graph.shutdown().await;

        // No submission may resurrect the worker after shutdown.
        let err = graph
            .replace_all(stored_graph(
                revision + 1,
                vec![(
                    ResourceKind::Upstream,
                    "u2",
                    upstream_json("u2", "127.0.0.1:81"),
                )],
            ))
            .unwrap_err();
        assert!(
            matches!(err, GraphError::WorkerStopped),
            "expected WorkerStopped after shutdown, got: {err:?}"
        );

        let err = graph
            .apply_watch(upstream_change(revision + 2, "u3", "127.0.0.1:82"))
            .unwrap_err();
        assert!(
            matches!(err, GraphError::WorkerStopped),
            "expected WorkerStopped after shutdown, got: {err:?}"
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            harness.runtime.load().revision,
            revision,
            "post-shutdown submissions must not publish"
        );
    }

    /// A deterministic candidate failure (bad SSL material passes whole-graph
    /// validation but fails compilation) must be attempted exactly once per
    /// generation: the worker waits for a new revision instead of retrying the
    /// same broken generation forever.
    #[tokio::test]
    async fn permanent_candidate_failure_is_attempted_once_per_generation() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();
        let base = harness.runtime.load().revision;

        let failing = base + 100;
        graph.replace_all(stored_bad_ssl_graph(failing)).unwrap();

        // Wait for this graph's own publication record, not the process-global
        // Prometheus counter (other tests increment it in parallel).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match graph.publication(failing) {
                Some(view) if view.state == PublicationState::Rejected => break,
                _ => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "worker must reject the permanent candidate once"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
        assert_eq!(
            harness.runtime.load().revision,
            base,
            "failing candidate must never publish"
        );

        // Longer than the old first retry backoff (1s): the permanent
        // classification must not recompile the same broken generation into a
        // publish.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let view = graph
            .publication(failing)
            .expect("rejection must remain recorded");
        assert_eq!(view.state, PublicationState::Rejected);
        assert_eq!(harness.runtime.load().revision, base);

        // A later valid generation supersedes the failed one and publishes.
        let valid = failing + 1;
        graph
            .replace_all(stored_graph(
                valid,
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
        assert!(
            wait_for_revision(&harness.runtime, valid, Duration::from_secs(2)).await,
            "a valid generation after a permanent failure must publish promptly"
        );
        graph.shutdown().await;
    }

    #[tokio::test]
    async fn replace_all_rejects_undecryptable_graph_without_publish() {
        let harness = GraphTestHarness::new(Arc::new(InMemoryGraphStore::new()));
        let graph = harness.graph.clone();
        let base = harness.runtime.load().revision;
        let err = graph
            .replace_all(stored_graph(
                base + 100,
                vec![(
                    ResourceKind::Ssl,
                    "t1",
                    serde_json::json!({
                        "id": "t1",
                        "cert": "C",
                        "key": "$pingsix-enc:v1$cipher",
                        "snis": ["example.com"],
                    }),
                )],
            ))
            .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "{err:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(harness.runtime.load().revision, base);
        graph.shutdown().await;
    }

    #[test]
    fn load_static_publishes_empty_config() {
        let status = std::sync::Arc::new(StatusStore::new());
        let health_check = std::sync::Arc::new(
            crate::proxy::upstream::health_check::SharedHealthCheckService::new(),
        );
        let runtime = std::sync::Arc::new(RuntimeStore::with_state(status.clone(), health_check));
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let snapshot = ConfigurationGraph::load_static(
            &config::Config::default(),
            &status,
            &runtime,
            &EffectiveDefaults::default(),
            &resolver,
        )
        .unwrap();
        assert!(snapshot.routes.is_empty());
        assert_eq!(runtime.load().revision, snapshot.revision);
    }
}
