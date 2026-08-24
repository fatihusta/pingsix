//! Production [`GraphStore`] adapter: whole-graph snapshots and guarded CAS
//! against the configured etcd namespace.

use async_trait::async_trait;
use etcd_client::{Client, Compare, CompareOp, GetOptions, Txn, TxnOp};
use tokio::sync::OnceCell;

use super::connect::create_client;
use super::keys::{
    canonicalize_prefix, physical_key_to_resource_key, GRAPH_PROTOCOL_VERSION, GRAPH_REVISION_KEY,
};
use super::sync::{graph_snapshot_from_list, ListKv};
use crate::{
    config::Etcd,
    core::{ProxyError, ProxyResult},
    proxy::graph_mutation::{
        CommitRevision, GraphCommit, GraphStore, ResourceKey, ResourceKind, StoreError,
        StoredGraph, StoredMutation, StoredResource,
    },
};

/// Production [`GraphStore`] adapter: whole-graph snapshots and guarded CAS.
pub struct EtcdGraphStore {
    config: Etcd,
    canonical_prefix: String,
    /// `etcd_client::Client` is `Clone` and internally shares one gRPC channel,
    /// so each operation clones the handle instead of holding a mutex across a
    /// network `await`. That removes head-of-line blocking between concurrent
    /// Admin/etcd requests.
    client: OnceCell<Client>,
}

impl EtcdGraphStore {
    pub fn new(cfg: Etcd) -> Self {
        let canonical_prefix = canonicalize_prefix(&cfg.prefix);
        Self {
            config: cfg,
            canonical_prefix,
            client: OnceCell::new(),
        }
    }

    /// Configured etcd namespace (canonical trailing-slash form).
    pub fn prefix(&self) -> &str {
        &self.canonical_prefix
    }

    async fn ensure_connected(&self) -> ProxyResult<Client> {
        Ok(self
            .client
            .get_or_try_init(|| async {
                log::debug!("Creating etcd client for prefix '{}'", self.config.prefix);
                create_client(&self.config).await
            })
            .await?
            .clone())
    }

    pub async fn list(&self, key: &str) -> ProxyResult<etcd_client::GetResponse> {
        let mut client = self.ensure_connected().await?;

        let prefixed_key = self.with_prefix(key);
        let options = GetOptions::new().with_prefix();
        client
            .get(prefixed_key.as_bytes(), Some(options))
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(
                    format!("List operation for key '{prefixed_key}' failed"),
                    e,
                )
            })
    }

    /// Read every key-value pair under the configured prefix.
    ///
    /// Read resource keys and the graph-generation guard under the configured prefix.
    async fn graph_txn(
        &self,
        key: &str,
        value: Option<Vec<u8>>,
        expected_mod_revision: Option<i64>,
        guard_mod_revision: Option<i64>,
    ) -> ProxyResult<i64> {
        let mut client = self.ensure_connected().await?;
        let target = match expected_mod_revision {
            None => Compare::create_revision(key.as_bytes(), CompareOp::Equal, 0),
            Some(revision) => Compare::mod_revision(key.as_bytes(), CompareOp::Equal, revision),
        };
        let guard_key = self.prefixed_key(GRAPH_REVISION_KEY);
        let guard = match guard_mod_revision {
            None => Compare::create_revision(guard_key.as_bytes(), CompareOp::Equal, 0),
            Some(revision) => {
                Compare::mod_revision(guard_key.as_bytes(), CompareOp::Equal, revision)
            }
        };
        let mutation = match value {
            Some(value) => TxnOp::put(key.as_bytes(), value, None),
            None => TxnOp::delete(key.as_bytes(), None),
        };
        let txn = Txn::new().when(vec![target, guard]).and_then(vec![
            mutation,
            TxnOp::put(guard_key.as_bytes(), GRAPH_PROTOCOL_VERSION.to_vec(), None),
        ]);
        let response = client
            .txn(txn)
            .await
            .map_err(|e| ProxyError::etcd_error_with_cause("graph transaction failed", e))?;
        if !response.succeeded() {
            return Err(ProxyError::CasConflict(
                "configuration graph changed concurrently".into(),
            ));
        }
        response
            .header()
            .map(|header| header.revision())
            .ok_or_else(|| ProxyError::etcd_error("graph transaction: missing response header"))
    }

    fn prefixed_key(&self, key: &str) -> String {
        self.with_prefix(key)
    }

    fn with_prefix(&self, key: &str) -> String {
        format!("{}{}", self.canonical_prefix, key.trim_start_matches('/'))
    }
}

#[async_trait]
impl GraphStore for EtcdGraphStore {
    async fn get_exact(&self, key: &ResourceKey) -> Result<Option<StoredResource>, StoreError> {
        let mut client = self
            .ensure_connected()
            .await
            .map_err(|e| StoreError::Unavailable { source: e })?;
        let physical_key = self.with_prefix(&key.logical_path());
        let response = client
            .get(physical_key.as_bytes(), None)
            .await
            .map_err(|e| StoreError::Unavailable {
                source: ProxyError::etcd_error_with_cause(
                    format!("Failed to read resource '{physical_key}'"),
                    e,
                ),
            })?;
        Ok(response.kvs().first().map(|kv| StoredResource {
            value: kv.value().to_vec(),
            create_revision: kv.create_revision(),
            mod_revision: kv.mod_revision(),
        }))
    }

    async fn list_kind(
        &self,
        kind: ResourceKind,
    ) -> Result<Vec<(ResourceKey, StoredResource)>, StoreError> {
        let mut client = self
            .ensure_connected()
            .await
            .map_err(|e| StoreError::Unavailable { source: e })?;
        let physical_prefix = self.with_prefix(&format!("{}/", kind.as_str()));
        let response = client
            .get(
                physical_prefix.as_bytes(),
                Some(GetOptions::new().with_prefix()),
            )
            .await
            .map_err(|e| StoreError::Unavailable {
                source: ProxyError::etcd_error_with_cause(
                    format!("Failed to list resources under '{physical_prefix}'"),
                    e,
                ),
            })?;
        response
            .kvs()
            .iter()
            .map(|kv| {
                let key = physical_key_to_resource_key(kv.key(), &self.canonical_prefix)
                    .map_err(|message| StoreError::InvalidResponse { message })?;
                if key.kind != kind {
                    return Err(StoreError::InvalidResponse {
                        message: format!(
                            "resource '{}' is outside requested kind '{}'",
                            key.logical_path(),
                            kind.as_str()
                        ),
                    });
                }
                Ok((
                    key,
                    StoredResource {
                        value: kv.value().to_vec(),
                        create_revision: kv.create_revision(),
                        mod_revision: kv.mod_revision(),
                    },
                ))
            })
            .collect()
    }

    async fn snapshot(&self) -> Result<StoredGraph, StoreError> {
        let mut client = self
            .ensure_connected()
            .await
            .map_err(|e| StoreError::Unavailable { source: e })?;

        let options = GetOptions::new().with_prefix();
        let response = client
            .get(self.canonical_prefix.as_bytes(), Some(options))
            .await
            .map_err(|e| StoreError::Unavailable {
                source: ProxyError::etcd_error_with_cause(
                    format!(
                        "Failed to read full graph for prefix '{}'",
                        self.canonical_prefix
                    ),
                    e,
                ),
            })?;
        let header = response
            .header()
            .ok_or_else(|| StoreError::InvalidResponse {
                message: "snapshot: missing response header".into(),
            })?;
        let kvs: Vec<ListKv<'_>> = response
            .kvs()
            .iter()
            .map(|kv| ListKv {
                key: kv.key(),
                value: kv.value(),
                create_revision: kv.create_revision(),
                mod_revision: kv.mod_revision(),
            })
            .collect();
        graph_snapshot_from_list(&kvs, header.revision(), &self.canonical_prefix)
    }

    async fn compare_and_swap(&self, commit: GraphCommit) -> Result<CommitRevision, StoreError> {
        let (key, value, expected_target) = match commit.mutation {
            StoredMutation::Put { key, value } => (
                self.with_prefix(&key.logical_path()),
                Some(value),
                commit.expected_target_mod_revision,
            ),
            StoredMutation::Delete { key } => (
                self.with_prefix(&key.logical_path()),
                None,
                commit.expected_target_mod_revision,
            ),
        };
        self.graph_txn(
            &key,
            value,
            expected_target,
            commit.expected_guard_mod_revision,
        )
        .await
        .map(CommitRevision)
        .map_err(|e| match e {
            ProxyError::CasConflict(_) => StoreError::Conflict,
            other => StoreError::Unavailable { source: other },
        })
    }
}
