//! Storage-neutral graph vocabulary and the external store seam.

use std::{collections::HashMap, fmt};

use async_trait::async_trait;

use crate::core::ProxyError;

// =============================================================================
// STORAGE-NEUTRAL GRAPH VOCABULARY
// =============================================================================

/// The configuration resource kinds managed by the graph authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    Upstream,
    Service,
    GlobalRule,
    Route,
    Ssl,
}

impl ResourceKind {
    /// Storage segment used by etcd keys and Admin API paths.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstreams",
            Self::Service => "services",
            Self::GlobalRule => "global_rules",
            Self::Route => "routes",
            Self::Ssl => "ssls",
        }
    }

    pub fn parse(value: &str) -> Result<Self, GraphError> {
        match value {
            "upstreams" => Ok(Self::Upstream),
            "services" => Ok(Self::Service),
            "global_rules" => Ok(Self::GlobalRule),
            "routes" => Ok(Self::Route),
            "ssls" => Ok(Self::Ssl),
            other => Err(GraphError::InvalidKey {
                key: other.to_string(),
                reason: "unknown resource kind".into(),
            }),
        }
    }
}

/// Logical identity of one stored configuration resource.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResourceKey {
    pub kind: ResourceKind,
    pub id: String,
}

impl ResourceKey {
    pub fn new(kind: ResourceKind, id: impl Into<String>) -> Result<Self, GraphError> {
        let id = id.into();
        if id.is_empty() || id.contains('/') {
            return Err(GraphError::InvalidKey {
                key: format!("{}/{}", kind.as_str(), id),
                reason: "resource id must be non-empty and must not contain '/'".into(),
            });
        }
        Ok(Self { kind, id })
    }

    pub fn logical_path(&self) -> String {
        format!("{}/{}", self.kind.as_str(), self.id)
    }
}

/// One stored resource: stored bytes plus revision metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredResource {
    pub value: Vec<u8>,
    pub create_revision: i64,
    pub mod_revision: i64,
}

/// A complete stored configuration graph plus its generation guard revision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredGraph {
    pub resources: HashMap<ResourceKey, StoredResource>,
    /// Mod revision of the graph generation guard; `None` before its first write.
    pub guard_mod_revision: Option<i64>,
    /// Cluster revision of the read that produced this snapshot.
    pub revision: i64,
}

/// One causally ordered watch response mapped to logical changes.
#[derive(Clone, Debug, Default)]
pub struct WatchBatch {
    pub revision: i64,
    pub changes: Vec<StoredChange>,
}

#[derive(Clone, Debug)]
pub enum StoredChange {
    Put {
        key: ResourceKey,
        resource: StoredResource,
    },
    Delete {
        key: ResourceKey,
    },
}

/// A validated mutation plus CAS expectations derived from one snapshot.
#[derive(Clone, Debug)]
pub struct GraphCommit {
    pub mutation: StoredMutation,
    /// `None` means the target must not exist yet (create).
    pub expected_target_mod_revision: Option<i64>,
    /// `None` means the guard must not exist yet.
    pub expected_guard_mod_revision: Option<i64>,
}

#[derive(Clone, Debug)]
pub enum StoredMutation {
    Put { key: ResourceKey, value: Vec<u8> },
    Delete { key: ResourceKey },
}

/// Cluster revision at which a committed mutation landed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitRevision(pub i64);

/// Admin-facing view of one stored resource: decrypted and redacted.
#[derive(Clone, Debug)]
pub struct ResourceView {
    pub key: ResourceKey,
    pub value: serde_json::Value,
    pub create_revision: i64,
    pub mod_revision: i64,
}

/// Whether stored secret fields are decrypted while decoding a graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretMode {
    /// Decrypt marked fields and fail closed on ciphertext (runtime ingestion).
    DecryptForRuntime,
    /// Leave stored bytes untouched (Admin candidate validation).
    PreserveStored,
}

/// Which secret operation failed, for error reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretOperation {
    Encrypt,
    Decrypt,
    Redact,
    Restore,
}

/// Errors from the external configuration store.
#[derive(Debug)]
pub enum StoreError {
    Unavailable { source: ProxyError },
    InvalidResponse { message: String },
    UnsupportedProtocol,
    Conflict,
}

/// The external configuration store seam: targeted Admin reads plus
/// whole-graph snapshots and guarded CAS for mutations.
#[async_trait]
pub trait GraphStore: Send + Sync {
    /// Read one resource by its exact physical key for an Admin GET.
    async fn get_exact(&self, key: &ResourceKey) -> Result<Option<StoredResource>, StoreError>;

    /// Read resources below one resource-kind physical-key prefix for an Admin LIST.
    async fn list_kind(
        &self,
        kind: ResourceKind,
    ) -> Result<Vec<(ResourceKey, StoredResource)>, StoreError>;

    /// Read the complete stored graph with its generation guard revision.
    /// Used exclusively to plan whole-graph validated mutations.
    async fn snapshot(&self) -> Result<StoredGraph, StoreError>;

    /// Atomically apply a validated mutation if target and guard still match.
    async fn compare_and_swap(&self, commit: GraphCommit) -> Result<CommitRevision, StoreError>;
}

/// Domain errors of the configuration graph authority.
#[derive(Debug)]
pub enum GraphError {
    InvalidKey {
        key: String,
        reason: String,
    },
    InvalidResource {
        key: ResourceKey,
        source: ProxyError,
    },
    InvalidCandidate {
        source: ProxyError,
    },
    ReferentialConflict {
        source: ProxyError,
    },
    NotFound {
        key: ResourceKey,
    },
    CasConflict,
    StaleRevision {
        incoming: i64,
        published: i64,
    },
    Secret {
        key: ResourceKey,
        operation: SecretOperation,
        source: ProxyError,
    },
    WorkerStopped,
    Store(StoreError),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey { key, reason } => write!(f, "invalid key '{key}': {reason}"),
            Self::InvalidResource { key, source } => {
                write!(f, "invalid resource '{}': {source}", key.logical_path())
            }
            Self::InvalidCandidate { source } => write!(f, "invalid candidate graph: {source}"),
            Self::ReferentialConflict { source } => {
                write!(f, "candidate graph has conflicting references: {source}")
            }
            Self::NotFound { key } => write!(f, "resource '{}' not found", key.logical_path()),
            Self::CasConflict => write!(f, "configuration graph changed concurrently"),
            Self::StaleRevision {
                incoming,
                published,
            } => write!(
                f,
                "rejecting stale watch revision {incoming} < published revision {published}"
            ),
            Self::Secret {
                key,
                operation,
                source,
            } => write!(
                f,
                "secret {:?} failed for '{}': {source}",
                operation,
                key.logical_path()
            ),
            Self::WorkerStopped => write!(f, "control-plane preparation worker stopped"),
            Self::Store(err) => write!(f, "configuration store error: {err:?}"),
        }
    }
}

impl std::error::Error for GraphError {}

/// Minimal faithful stand-in for the external configuration store.
///
/// The local-substitutable [`GraphStore`] adapter: models only the behavior
/// the authority relies on — whole-graph snapshots and guarded atomic CAS —
/// with no watch, lease, or TLS semantics. It is a normal public item (not a
/// test-gated fixture) so both in-crate tests/harnesses and integration tests
/// can drive hermetic authority/worker/CAS scenarios without a live etcd.
pub struct InMemoryGraphStore {
    state: tokio::sync::Mutex<InMemoryState>,
}

struct InMemoryState {
    graph: StoredGraph,
    next_revision: i64,
}

impl InMemoryGraphStore {
    pub fn new() -> Self {
        Self {
            state: tokio::sync::Mutex::new(InMemoryState {
                graph: StoredGraph::default(),
                next_revision: 1,
            }),
        }
    }
}

impl Default for InMemoryGraphStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GraphStore for InMemoryGraphStore {
    async fn get_exact(&self, key: &ResourceKey) -> Result<Option<StoredResource>, StoreError> {
        Ok(self.state.lock().await.graph.resources.get(key).cloned())
    }

    async fn list_kind(
        &self,
        kind: ResourceKind,
    ) -> Result<Vec<(ResourceKey, StoredResource)>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .graph
            .resources
            .iter()
            .filter(|(key, _)| key.kind == kind)
            .map(|(key, resource)| (key.clone(), resource.clone()))
            .collect())
    }

    async fn snapshot(&self) -> Result<StoredGraph, StoreError> {
        Ok(self.state.lock().await.graph.clone())
    }

    async fn compare_and_swap(&self, commit: GraphCommit) -> Result<CommitRevision, StoreError> {
        let mut state = self.state.lock().await;
        let target_key = match &commit.mutation {
            StoredMutation::Put { key, .. } | StoredMutation::Delete { key } => key,
        };
        let target_ok = match commit.expected_target_mod_revision {
            None => !state.graph.resources.contains_key(target_key),
            Some(expected) => {
                state
                    .graph
                    .resources
                    .get(target_key)
                    .map(|r| r.mod_revision)
                    == Some(expected)
            }
        };
        let guard_ok = match commit.expected_guard_mod_revision {
            None => state.graph.guard_mod_revision.is_none(),
            Some(expected) => state.graph.guard_mod_revision == Some(expected),
        };
        if !target_ok || !guard_ok {
            return Err(StoreError::Conflict);
        }

        let revision = state.next_revision;
        state.next_revision += 1;
        match commit.mutation {
            StoredMutation::Put { key, value } => {
                let create_revision = state
                    .graph
                    .resources
                    .get(&key)
                    .map(|r| r.create_revision)
                    .unwrap_or(revision);
                state.graph.resources.insert(
                    key,
                    StoredResource {
                        value,
                        create_revision,
                        mod_revision: revision,
                    },
                );
            }
            StoredMutation::Delete { key } => {
                state.graph.resources.remove(&key);
            }
        }
        state.graph.guard_mod_revision = Some(revision);
        state.graph.revision = revision;
        Ok(CommitRevision(revision))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_kind_parse_round_trips() {
        for kind in [
            ResourceKind::Upstream,
            ResourceKind::Service,
            ResourceKind::GlobalRule,
            ResourceKind::Route,
            ResourceKind::Ssl,
        ] {
            assert_eq!(ResourceKind::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(matches!(
            ResourceKind::parse("certificates"),
            Err(GraphError::InvalidKey { .. })
        ));
    }

    #[test]
    fn resource_key_rejects_empty_and_slashed_ids() {
        assert!(ResourceKey::new(ResourceKind::Route, "").is_err());
        assert!(ResourceKey::new(ResourceKind::Route, "a/b").is_err());
        assert_eq!(
            ResourceKey::new(ResourceKind::Route, "r1")
                .unwrap()
                .logical_path(),
            "routes/r1"
        );
    }

    #[tokio::test]
    async fn in_memory_store_cas_contract() {
        let store = InMemoryGraphStore::new();
        let key = ResourceKey::new(ResourceKind::Route, "r1").unwrap();
        let body = b"{\"id\":\"r1\"}".to_vec();

        // Create: absent target + absent guard.
        let commit = GraphCommit {
            mutation: StoredMutation::Put {
                key: key.clone(),
                value: body.clone(),
            },
            expected_target_mod_revision: None,
            expected_guard_mod_revision: None,
        };
        let rev1 = store.compare_and_swap(commit).await.unwrap();
        assert_eq!(rev1, CommitRevision(1));
        let snapshot = store.snapshot().await.unwrap();
        assert_eq!(snapshot.resources[&key].mod_revision, 1);
        assert_eq!(snapshot.guard_mod_revision, Some(1));

        // Replace with exact mod revision.
        let commit = GraphCommit {
            mutation: StoredMutation::Put {
                key: key.clone(),
                value: body.clone(),
            },
            expected_target_mod_revision: Some(1),
            expected_guard_mod_revision: Some(1),
        };
        assert_eq!(
            store.compare_and_swap(commit).await.unwrap(),
            CommitRevision(2)
        );

        // Stale target mod revision conflicts.
        let commit = GraphCommit {
            mutation: StoredMutation::Put {
                key: key.clone(),
                value: body,
            },
            expected_target_mod_revision: Some(1),
            expected_guard_mod_revision: Some(2),
        };
        assert!(matches!(
            store.compare_and_swap(commit).await,
            Err(StoreError::Conflict)
        ));

        // Stale guard conflicts even with correct target.
        let commit = GraphCommit {
            mutation: StoredMutation::Put {
                key: key.clone(),
                value: b"x".to_vec(),
            },
            expected_target_mod_revision: Some(2),
            expected_guard_mod_revision: Some(1),
        };
        assert!(matches!(
            store.compare_and_swap(commit).await,
            Err(StoreError::Conflict)
        ));

        // Conflict leaves state unchanged.
        let after = store.snapshot().await.unwrap();
        assert_eq!(after.resources[&key].mod_revision, 2);
        assert_eq!(after.guard_mod_revision, Some(2));

        // Delete of a missing target conflicts.
        let ghost = ResourceKey::new(ResourceKind::Route, "ghost").unwrap();
        let commit = GraphCommit {
            mutation: StoredMutation::Delete { key: ghost },
            expected_target_mod_revision: Some(2),
            expected_guard_mod_revision: Some(2),
        };
        assert!(matches!(
            store.compare_and_swap(commit).await,
            Err(StoreError::Conflict)
        ));

        // Delete of existing target succeeds and removes only the target.
        let commit = GraphCommit {
            mutation: StoredMutation::Delete { key: key.clone() },
            expected_target_mod_revision: Some(2),
            expected_guard_mod_revision: Some(2),
        };
        assert_eq!(
            store.compare_and_swap(commit).await.unwrap(),
            CommitRevision(3)
        );
        let after = store.snapshot().await.unwrap();
        assert!(!after.resources.contains_key(&key));
        assert_eq!(after.guard_mod_revision, Some(3));
        assert!(after.resources.is_empty());

        // Recreate after delete: create_revision tracks the new creation.
        let commit = GraphCommit {
            mutation: StoredMutation::Put {
                key: key.clone(),
                value: b"new".to_vec(),
            },
            expected_target_mod_revision: None,
            expected_guard_mod_revision: Some(3),
        };
        store.compare_and_swap(commit).await.unwrap();
        let after = store.snapshot().await.unwrap();
        assert_eq!(after.resources[&key].create_revision, 4);
        assert_eq!(after.resources[&key].mod_revision, 4);
    }
}
