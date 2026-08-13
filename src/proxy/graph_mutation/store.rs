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
}
