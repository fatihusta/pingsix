//! Pure graph decode, watch application, and CAS planning helpers.

use crate::{
    config::{self, GlobalRule, Identifiable, Route, Service, Upstream, SSL},
    core::{ProxyError, ProxyResult},
    proxy::control_plane::{validate_stored_form, ResourceConfigSet},
    utils::encryption::{KeyringService, SecretOp},
};

use super::store::{
    GraphCommit, GraphError, ResourceKey, ResourceKind, SecretMode, StoredChange, StoredGraph,
    StoredMutation, StoredResource, WatchBatch,
};

/// Decode a stored graph into typed resources. `DecryptForRuntime` fails
/// closed on undecryptable secret values; `PreserveStored` leaves them.
pub(crate) fn decode_graph(
    graph: &StoredGraph,
    mode: SecretMode,
    keyring: &KeyringService,
) -> ProxyResult<ResourceConfigSet> {
    let decrypt = mode == SecretMode::DecryptForRuntime;
    let mut set = ResourceConfigSet::default();
    for (key, resource) in &graph.resources {
        insert_resource(&mut set, key, &resource.value, decrypt, keyring)?;
    }
    Ok(set)
}

fn insert_resource(
    set: &mut ResourceConfigSet,
    key: &ResourceKey,
    value: &[u8],
    decrypt: bool,
    keyring: &KeyringService,
) -> ProxyResult<()> {
    match key.kind {
        ResourceKind::Upstream => {
            let mut resource =
                resource_from_stored::<Upstream>(value, "upstreams", decrypt, keyring)?;
            resource.set_id(key.id.clone());
            set.upstreams.insert(key.id.clone(), resource);
        }
        ResourceKind::Service => {
            let mut resource =
                resource_from_stored::<Service>(value, "services", decrypt, keyring)?;
            resource.set_id(key.id.clone());
            set.services.insert(key.id.clone(), resource);
        }
        ResourceKind::GlobalRule => {
            let mut resource =
                resource_from_stored::<GlobalRule>(value, "global_rules", decrypt, keyring)?;
            resource.set_id(key.id.clone());
            set.global_rules.insert(key.id.clone(), resource);
        }
        ResourceKind::Route => {
            let mut resource = resource_from_stored::<Route>(value, "routes", decrypt, keyring)?;
            resource.set_id(key.id.clone());
            set.routes.insert(key.id.clone(), resource);
        }
        ResourceKind::Ssl => {
            let mut resource = resource_from_stored::<SSL>(value, "ssls", decrypt, keyring)?;
            resource.set_id(key.id.clone());
            set.ssls.insert(key.id.clone(), resource);
        }
    }
    Ok(())
}

fn resource_from_stored<T: serde::de::DeserializeOwned>(
    value: &[u8],
    resource_type: &str,
    decrypt: bool,
    keyring: &KeyringService,
) -> ProxyResult<T> {
    let mut json = serde_json::from_slice::<serde_json::Value>(value)
        .map_err(|e| ProxyError::serialization_error("Failed to parse resource JSON", e))?;
    if decrypt {
        config::transform_resource_secrets(keyring, resource_type, &mut json, SecretOp::Decrypt)?;
    }
    // Warn about likely typos of known behavior fields (e.g. `retry_timout`)
    // before the unknown field is silently dropped by the typed deserializer.
    config::warn_unrecognized_fields(resource_type, &json);
    serde_json::from_value(json)
        .map_err(|e| ProxyError::serialization_error("Failed to deserialize resource", e))
}

/// Apply a watch batch to a base graph. Later changes for the same key win.
pub(crate) fn apply_watch_batch(
    base: &StoredGraph,
    batch: &WatchBatch,
) -> Result<StoredGraph, GraphError> {
    if batch.changes.is_empty() {
        return Ok(base.clone());
    }
    let mut next = base.clone();
    next.revision = batch.revision;
    for change in &batch.changes {
        match change {
            StoredChange::Put { key, resource } => {
                next.resources.insert(key.clone(), resource.clone());
            }
            StoredChange::Delete { key } => {
                next.resources.remove(key);
            }
        }
    }
    Ok(next)
}

/// Build the candidate graph for a PUT and derive the CAS commit expectations.
pub(crate) fn plan_put_mutation(
    snapshot: &StoredGraph,
    key: &ResourceKey,
    stored_value: Vec<u8>,
    keyring: &KeyringService,
) -> Result<GraphCommit, GraphError> {
    let mut candidate = snapshot.clone();
    candidate.resources.insert(
        key.clone(),
        StoredResource {
            value: stored_value.clone(),
            create_revision: 0,
            mod_revision: 0,
        },
    );
    let set = decode_graph(&candidate, SecretMode::PreserveStored, keyring)
        .map_err(|e| GraphError::InvalidCandidate { source: e })?;
    // Stored form: secrets may still be ciphertext at this gate.
    validate_stored_form(&set).map_err(|e| GraphError::InvalidCandidate { source: e })?;
    let expected_target_mod_revision = snapshot.resources.get(key).map(|r| r.mod_revision);
    Ok(GraphCommit {
        mutation: StoredMutation::Put {
            key: key.clone(),
            value: stored_value,
        },
        expected_target_mod_revision,
        expected_guard_mod_revision: snapshot.guard_mod_revision,
    })
}

/// Build the candidate graph for a DELETE and derive the CAS commit expectations.
pub(crate) fn plan_delete_mutation(
    snapshot: &StoredGraph,
    key: &ResourceKey,
    keyring: &KeyringService,
) -> Result<GraphCommit, GraphError> {
    let existing = snapshot
        .resources
        .get(key)
        .ok_or_else(|| GraphError::NotFound { key: key.clone() })?;
    let mut candidate = snapshot.clone();
    candidate.resources.remove(key);
    let set = decode_graph(&candidate, SecretMode::PreserveStored, keyring)
        .map_err(|e| GraphError::ReferentialConflict { source: e })?;
    // Stored form: secrets may still be ciphertext at this gate.
    validate_stored_form(&set).map_err(|e| GraphError::ReferentialConflict { source: e })?;
    Ok(GraphCommit {
        mutation: StoredMutation::Delete { key: key.clone() },
        expected_target_mod_revision: Some(existing.mod_revision),
        expected_guard_mod_revision: snapshot.guard_mod_revision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::encryption::KeyringService;

    fn stored_upstream_json(id: &str, node: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "nodes": { node: 1 },
            "type": "roundrobin",
            "hash_on": "vars",
            "key": "uri",
            "scheme": "http",
            "pass_host": "pass",
        }))
        .unwrap()
    }

    fn stored_route_json(id: &str, upstream_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "uri": "/",
            "upstream_id": upstream_id,
        }))
        .unwrap()
    }

    fn stored_service_json(id: &str, upstream_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "upstream_id": upstream_id,
        }))
        .unwrap()
    }

    fn stored_global_rule_json(id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "plugins": {},
        }))
        .unwrap()
    }

    fn stored_ssl_json(id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "cert": "C",
            "key": "K",
            "snis": ["example.com"],
        }))
        .unwrap()
    }

    fn stored(_key: ResourceKey, value: Vec<u8>) -> StoredResource {
        StoredResource {
            value,
            create_revision: 1,
            mod_revision: 1,
        }
    }

    fn sample_graph() -> StoredGraph {
        let mut graph = StoredGraph {
            guard_mod_revision: Some(1),
            revision: 10,
            ..Default::default()
        };
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Upstream, "u1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Upstream, "u1").unwrap(),
                stored_upstream_json("body-id-ignored", "127.0.0.1:80"),
            ),
        );
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
                stored_route_json("r1", "u1"),
            ),
        );
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Service, "s1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Service, "s1").unwrap(),
                stored_service_json("s1", "u1"),
            ),
        );
        graph.resources.insert(
            ResourceKey::new(ResourceKind::GlobalRule, "g1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::GlobalRule, "g1").unwrap(),
                stored_global_rule_json("g1"),
            ),
        );
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
                stored_ssl_json("t1"),
            ),
        );
        graph
    }
    #[test]
    fn decode_graph_round_trips_all_kinds_and_uses_key_id() {
        let graph = sample_graph();
        let set = decode_graph(
            &graph,
            SecretMode::PreserveStored,
            &KeyringService::disabled(),
        )
        .unwrap();

        // IDs come from the storage key, never the JSON body.
        assert_eq!(set.upstreams.get("u1").unwrap().id, "u1");
        assert!(set.upstreams["u1"].nodes.contains_addr("127.0.0.1:80"));
        assert!(set.routes.contains_key("r1"));
        assert!(set.services.contains_key("s1"));
        assert!(set.global_rules.contains_key("g1"));
        assert!(set.ssls.contains_key("t1"));
        assert_eq!(set.upstreams.len(), 1);
    }

    #[test]
    fn decode_preserve_stored_tolerates_ciphertext() {
        let mut graph = StoredGraph::default();
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
                serde_json::to_vec(&serde_json::json!({
                    "id": "t1",
                    "cert": "C",
                    "key": "$pingsix-enc:v1$ciphertext",
                    "snis": ["example.com"],
                }))
                .unwrap(),
            ),
        );
        let set = decode_graph(
            &graph,
            SecretMode::PreserveStored,
            &KeyringService::disabled(),
        )
        .unwrap();
        assert_eq!(
            set.ssls["t1"].key, "$pingsix-enc:v1$ciphertext",
            "validation path must not touch secret values"
        );
    }

    #[test]
    fn decode_runtime_fails_closed_on_ciphertext() {
        let mut graph = StoredGraph::default();
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Ssl, "t1").unwrap(),
                serde_json::to_vec(&serde_json::json!({
                    "id": "t1",
                    "cert": "C",
                    "key": "$pingsix-enc:v1$ciphertext",
                    "snis": ["example.com"],
                }))
                .unwrap(),
            ),
        );
        let err = decode_graph(
            &graph,
            SecretMode::DecryptForRuntime,
            &KeyringService::disabled(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("Encrypted value found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn apply_watch_put_then_delete_removes_key() {
        let base = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        let batch = WatchBatch {
            revision: 11,
            changes: vec![
                StoredChange::Put {
                    key: key.clone(),
                    resource: stored(key.clone(), stored_route_json("r1", "u1")),
                },
                StoredChange::Delete { key: key.clone() },
            ],
        };
        let next = apply_watch_batch(&base, &batch).unwrap();
        assert!(!next.resources.contains_key(&key));
        assert_eq!(next.revision, 11);
        assert_eq!(base.revision, 10, "base graph must not be mutated");
    }

    #[test]
    fn apply_watch_delete_then_put_keeps_final_resource() {
        let base = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        let batch = WatchBatch {
            revision: 11,
            changes: vec![
                StoredChange::Delete { key: key.clone() },
                StoredChange::Put {
                    key: key.clone(),
                    resource: stored(key.clone(), stored_route_json("r1", "u1")),
                },
            ],
        };
        let next = apply_watch_batch(&base, &batch).unwrap();
        assert!(next.resources.contains_key(&key));
    }

    #[test]
    fn apply_watch_same_key_later_wins() {
        let base = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "r2").unwrap();
        let v1 = serde_json::to_vec(&serde_json::json!({"id":"r2","uri":"/v1","upstream_id":"u1"}))
            .unwrap();
        let v2 = serde_json::to_vec(&serde_json::json!({"id":"r2","uri":"/v2","upstream_id":"u1"}))
            .unwrap();
        let batch = WatchBatch {
            revision: 11,
            changes: vec![
                StoredChange::Put {
                    key: key.clone(),
                    resource: stored(key.clone(), v1),
                },
                StoredChange::Put {
                    key: key.clone(),
                    resource: stored(key.clone(), v2),
                },
            ],
        };
        let next = apply_watch_batch(&base, &batch).unwrap();
        let decoded = decode_graph(
            &next,
            SecretMode::PreserveStored,
            &KeyringService::disabled(),
        )
        .unwrap();
        assert_eq!(decoded.routes["r2"].uri.as_deref(), Some("/v2"));
    }

    #[test]
    fn apply_watch_empty_batch_is_noop() {
        let base = sample_graph();
        let next = apply_watch_batch(&base, &WatchBatch::default()).unwrap();
        assert_eq!(next, base);
    }

    #[test]
    fn apply_watch_different_keys_both_retained() {
        let base = sample_graph();
        let r2 = ResourceKey::new(ResourceKind::Route, "r2").unwrap();
        let s2 = ResourceKey::new(ResourceKind::Service, "s2").unwrap();
        let batch = WatchBatch {
            revision: 11,
            changes: vec![
                StoredChange::Put {
                    key: r2.clone(),
                    resource: stored(r2.clone(), stored_route_json("r2", "u1")),
                },
                StoredChange::Put {
                    key: s2.clone(),
                    resource: stored(s2.clone(), stored_service_json("s2", "u1")),
                },
            ],
        };
        let next = apply_watch_batch(&base, &batch).unwrap();
        assert!(next.resources.contains_key(&r2));
        assert!(next.resources.contains_key(&s2));
        assert!(next
            .resources
            .contains_key(&ResourceKey::new(ResourceKind::Upstream, "u1").unwrap()));
    }

    #[test]
    fn plan_put_create_uses_absent_target_expectation() {
        let snapshot = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "r2").unwrap();
        let commit = plan_put_mutation(
            &snapshot,
            &key,
            stored_route_json("r2", "u1"),
            &KeyringService::disabled(),
        )
        .unwrap();
        assert_eq!(commit.expected_target_mod_revision, None);
        assert_eq!(
            commit.expected_guard_mod_revision,
            snapshot.guard_mod_revision
        );
        match commit.mutation {
            StoredMutation::Put { key: k, value } => {
                assert_eq!(k, key);
                assert!(!value.is_empty());
            }
            _ => panic!("expected Put"),
        }
    }

    #[test]
    fn plan_put_replace_uses_exact_mod_revision() {
        let snapshot = sample_graph();
        let key = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        let commit = plan_put_mutation(
            &snapshot,
            &key,
            stored_upstream_json("u1", "127.0.0.1:81"),
            &KeyringService::disabled(),
        )
        .unwrap();
        assert_eq!(
            commit.expected_target_mod_revision,
            Some(snapshot.resources[&key].mod_revision)
        );
    }

    #[test]
    fn plan_put_rejects_dangling_upstream_id() {
        let snapshot = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "bad").unwrap();
        let err = plan_put_mutation(
            &snapshot,
            &key,
            stored_route_json("bad", "missing"),
            &KeyringService::disabled(),
        )
        .unwrap_err();
        assert!(
            matches!(err, GraphError::InvalidCandidate { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn plan_delete_missing_target_is_not_found() {
        let snapshot = sample_graph();
        let key = ResourceKey::new(ResourceKind::Route, "ghost").unwrap();
        let err = plan_delete_mutation(&snapshot, &key, &KeyringService::disabled()).unwrap_err();
        assert!(matches!(err, GraphError::NotFound { .. }), "got {err:?}");
    }

    #[test]
    fn plan_delete_referenced_upstream_conflicts() {
        let snapshot = sample_graph();
        let key = ResourceKey::new(ResourceKind::Upstream, "u1").unwrap();
        let err = plan_delete_mutation(&snapshot, &key, &KeyringService::disabled()).unwrap_err();
        assert!(
            matches!(err, GraphError::ReferentialConflict { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn plan_delete_unreferenced_upstream_succeeds() {
        let snapshot = sample_graph();
        let u2 = ResourceKey::new(ResourceKind::Upstream, "u2").unwrap();
        let mut snapshot = snapshot;
        snapshot.resources.insert(
            u2.clone(),
            stored(u2.clone(), stored_upstream_json("u2", "127.0.0.1:82")),
        );
        let commit = plan_delete_mutation(&snapshot, &u2, &KeyringService::disabled()).unwrap();
        assert_eq!(
            commit.expected_target_mod_revision,
            Some(snapshot.resources[&u2].mod_revision)
        );
        assert!(matches!(commit.mutation, StoredMutation::Delete { .. }));
    }

    #[test]
    fn decode_graph_rejects_invalid_document_json() {
        // A malformed stored document must fail decode before it can enter a typed graph.
        let mut graph = StoredGraph::default();
        graph.resources.insert(
            ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
            stored(
                ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
                b"not-json".to_vec(),
            ),
        );
        assert!(decode_graph(
            &graph,
            SecretMode::PreserveStored,
            &KeyringService::disabled()
        )
        .is_err());
    }
}
