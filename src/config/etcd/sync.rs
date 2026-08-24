//! [`EtcdConfigSync`]: the list/watch adapter for the configuration graph
//! authority, mapping etcd native responses into storage-neutral
//! [`StoredGraph`]/[`WatchBatch`] inputs and feeding them to the shared
//! [`ConfigurationGraph`].

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use etcd_client::{Client, Event, GetOptions, WatchOptions};
use pingora::server::ListenFds;
use pingora_core::{server::ShutdownWatch, services::Service};
use tokio::time::sleep;

use super::connect::create_client;
use super::keys::{
    canonicalize_prefix, is_metadata_key, physical_key_to_resource_key, validate_guard_value,
    GRAPH_REVISION_KEY,
};
use crate::{
    config::Etcd,
    core::{status::StatusStore, ProxyError, ProxyResult},
    proxy::graph_mutation::{
        ConfigurationGraph, GraphError, ResourceKey, StoreError, StoredChange, StoredGraph,
        StoredResource, WatchBatch,
    },
};

// Retry delay constants
const LIST_RETRY_DELAY: Duration = Duration::from_secs(3);
const WATCH_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Service responsible for syncing and watching etcd configuration changes.
///
/// The list/watch adapter for the configuration graph authority: maps etcd
/// native responses into storage-neutral [`StoredGraph`]/[`WatchBatch`] inputs
/// and feeds them to the shared [`ConfigurationGraph`].
pub struct EtcdConfigSync {
    config: Etcd,
    /// Trailing-slash form used for list/watch range queries.
    canonical_prefix: String,
    client: Option<Client>,
    revision: i64,
    graph: Arc<ConfigurationGraph>,
    status: Arc<StatusStore>,
}

impl EtcdConfigSync {
    pub fn new(config: Etcd, graph: Arc<ConfigurationGraph>, status: Arc<StatusStore>) -> Self {
        let canonical_prefix = canonicalize_prefix(&config.prefix);
        Self {
            config,
            canonical_prefix,
            client: None,
            revision: 0,
            graph,
            status,
        }
    }

    /// Get or initialize the etcd client.
    async fn get_client(&mut self) -> ProxyResult<&mut Client> {
        if self.client.is_none() {
            log::debug!("Creating etcd client for prefix '{}'", self.config.prefix);
            self.client = Some(create_client(&self.config).await?);
        }

        self.client
            .as_mut()
            .ok_or_else(|| ProxyError::etcd_error("Etcd client is not initialized"))
    }

    /// Synchronize etcd data on initialization.
    async fn list(&mut self) -> Result<(), SyncError> {
        let prefix = self.canonical_prefix.clone();
        let client = self.get_client().await?;

        let options = GetOptions::new().with_prefix();
        let response = client
            .get(prefix.as_str(), Some(options))
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(format!("Failed to list key '{prefix}'"), e)
            })?;

        let revision = response
            .header()
            .ok_or_else(|| ProxyError::etcd_error("Failed to get header from list response"))?
            .revision();

        // Mark transport recovery before submitting: a fast publish must be the
        // operation that clears the reconnect publication fence.
        self.status.record_sync_success(revision);
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
        let snapshot =
            graph_snapshot_from_list(&kvs, revision, &self.canonical_prefix).map_err(|e| {
                SyncError::Transport(ProxyError::Configuration(format!(
                    "Failed to map etcd list response: {e:?}"
                )))
            })?;
        self.graph
            .replace_all(snapshot)
            .map_err(classify_rejection)?;
        self.revision = revision;
        self.status.set_revision(Some(revision));
        Ok(())
    }

    /// Watch for etcd data changes.
    async fn watch(&mut self) -> Result<(), SyncError> {
        let prefix = self.canonical_prefix.clone();
        let start_revision = self.revision + 1;
        let options = WatchOptions::new()
            .with_start_revision(start_revision)
            .with_prefix()
            // Idle watches must still refresh liveness; without progress notify a healthy
            // connection with no config changes looks stale to readiness probes.
            .with_progress_notify();

        let client = self.get_client().await?;

        let mut stream = client
            .watch(prefix.as_str(), Some(options))
            .await
            .map_err(|e| {
                ProxyError::etcd_error_with_cause(format!("Failed to watch key '{prefix}'"), e)
            })?;

        self.status.mark_etcd_connected(true);

        // Periodically request progress so last_success advances even when the server
        // is quiet and its own progress interval is longer than config_stale_after.
        let mut progress_interval = tokio::time::interval(Duration::from_secs(30));
        progress_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick; list() already recorded success.
        progress_interval.tick().await;

        loop {
            tokio::select! {
                result = stream.message() => {
                    let response = result.map_err(|e| {
                        ProxyError::etcd_error_with_cause("Failed to receive watch message", e)
                    })?;
                    let Some(response) = response else {
                        break;
                    };

                    if response.canceled() {
                        log::debug!("Watch stream for prefix '{prefix}' was canceled");
                        break;
                    }

                    // Propagate authority failures so the sync loop relists instead of
                    // silently advancing past a rejected revision. Progress responses
                    // have no events; the mapped batch is empty and apply_watch no-ops.
                    let changes =
                        graph_changes_from_events(response.events(), &self.canonical_prefix)?;
                    let revision = response
                        .events()
                        .iter()
                        .filter_map(|event| event.kv().map(|kv| kv.mod_revision()))
                        .max()
                        .unwrap_or(0);
                    self.graph
                        .apply_watch(WatchBatch { revision, changes })
                        .map_err(classify_rejection)?;

                    if let Some(header) = response.header() {
                        self.revision = header.revision();
                        self.status.record_sync_success(self.revision);
                    }
                }
                _ = progress_interval.tick() => {
                    if let Err(e) = stream.request_progress().await {
                        return Err(SyncError::Transport(
                            ProxyError::etcd_error_with_cause(
                                "Failed to request etcd watch progress",
                                e,
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Reset the client on failure.
    fn reset_client(&mut self) {
        log::debug!("Resetting etcd client for prefix '{}'", self.config.prefix);
        self.client = None;
        self.status.mark_etcd_connected(false);
    }

    /// Main task loop for synchronization.
    async fn run_sync_loop(&mut self, mut shutdown: ShutdownWatch) {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::debug!("Shutdown signal received, stopping etcd config sync for prefix '{}'", self.config.prefix);
                        return;
                    }
                },

                result = self.list() => {
                    if let Err(err) = result {
                        log::error!("List operation failed for prefix '{}': {:?}", self.config.prefix, err);
                        match &err {
                            SyncError::Transport(_) => {
                                self.status.record_sync_error(err.to_string());
                                self.reset_client();
                            }
                            SyncError::Data(_) => {
                                // Broken configuration data: keep the etcd
                                // connection and readiness on the LKG while
                                // relisting for an operator repair.
                                self.status.record_preparation_error(err.to_string());
                            }
                        }
                        if sleep_or_shutdown(LIST_RETRY_DELAY, &shutdown).await {
                            return;
                        }
                        continue;
                    }
                }
            }

            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        log::debug!("Shutdown signal received, stopping etcd config sync for prefix '{}'", self.config.prefix);
                        return;
                    }
                },

                result = self.watch() => {
                    if let Err(err) = result {
                        log::error!("Watch operation failed for prefix '{}': {:?}", self.config.prefix, err);
                        match &err {
                            SyncError::Transport(_) => {
                                self.status.record_sync_error(err.to_string());
                                self.reset_client();
                            }
                            SyncError::Data(_) => {
                                self.status.record_preparation_error(err.to_string());
                            }
                        }
                        if sleep_or_shutdown(WATCH_RETRY_DELAY, &shutdown).await {
                            return;
                        }
                        // Loop continues to list() — full resync after watch failure.
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Service for EtcdConfigSync {
    async fn start_service(
        &mut self,
        _fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        self.status.begin_etcd_sync();
        self.run_sync_loop(shutdown).await
    }

    fn name(&self) -> &'static str {
        "Etcd config SYNC"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

/// One key-value pair from a list response, decoupled from etcd types so the
/// mapping logic stays pure and testable without constructing etcd responses.
pub(super) struct ListKv<'a> {
    pub(super) key: &'a [u8],
    pub(super) value: &'a [u8],
    pub(super) create_revision: i64,
    pub(super) mod_revision: i64,
}

/// Map a full etcd list response into a storage-neutral [`StoredGraph`].
///
/// Shared by the sync adapter and [`EtcdGraphStore`](super::EtcdGraphStore) so
/// both interpret the same physical namespace identically. The graph
/// generation guard (`.pingsix_graph_revision`) is validated and its mod
/// revision recorded; metadata keys and foreign-prefix keys are excluded here,
/// at the adapter boundary, so the graph authority never sees physical etcd
/// concerns.
pub(super) fn graph_snapshot_from_list(
    kvs: &[ListKv<'_>],
    header_revision: i64,
    canonical_prefix: &str,
) -> Result<StoredGraph, StoreError> {
    let guard_key = format!("{canonical_prefix}{GRAPH_REVISION_KEY}");
    let mut resources = HashMap::new();
    let mut guard_mod_revision = None;
    for kv in kvs {
        let key = String::from_utf8_lossy(kv.key).into_owned();
        if !key.starts_with(canonical_prefix) {
            log::warn!("Ignoring etcd key outside configured namespace: {key}");
            continue;
        }
        if key == guard_key {
            validate_guard_value(kv.value)?;
            guard_mod_revision = Some(kv.mod_revision);
            continue;
        }
        if is_metadata_key(kv.key) {
            continue;
        }
        let resource_key = physical_key_to_resource_key(kv.key, canonical_prefix)
            .map_err(|message| StoreError::InvalidResponse { message })?;
        resources.insert(
            resource_key,
            StoredResource {
                value: kv.value.to_vec(),
                create_revision: kv.create_revision,
                mod_revision: kv.mod_revision,
            },
        );
    }
    Ok(StoredGraph {
        resources,
        guard_mod_revision,
        revision: header_revision,
    })
}

/// Map one watch response into a storage-neutral, per-key coalesced batch.
///
/// Later events for the same key win (causal order per key). Metadata and
/// foreign-prefix keys are excluded; malformed keys reject the whole batch so
/// the sync loop relists rather than advancing past a rejected revision.
fn graph_changes_from_events(
    events: &[Event],
    canonical_prefix: &str,
) -> ProxyResult<Vec<StoredChange>> {
    let mut final_by_key: HashMap<ResourceKey, StoredChange> = HashMap::new();
    for event in events {
        let kv = event
            .kv()
            .ok_or_else(|| ProxyError::Configuration("Etcd event missing key-value pair".into()))?;
        let key = String::from_utf8_lossy(kv.key()).into_owned();
        if is_metadata_key(kv.key()) {
            continue;
        }
        if !key.starts_with(canonical_prefix) {
            log::warn!("Ignoring etcd event outside configured namespace: {key}");
            continue;
        }
        let resource_key = physical_key_to_resource_key(kv.key(), canonical_prefix)
            .map_err(ProxyError::Configuration)?;
        let change = match event.event_type() {
            etcd_client::EventType::Put => StoredChange::Put {
                key: resource_key.clone(),
                resource: StoredResource {
                    value: kv.value().to_vec(),
                    create_revision: kv.create_revision(),
                    mod_revision: kv.mod_revision(),
                },
            },
            etcd_client::EventType::Delete => StoredChange::Delete {
                key: resource_key.clone(),
            },
        };
        final_by_key.insert(resource_key, change);
    }
    Ok(final_by_key.into_values().collect())
}

/// Failure classification of one list/watch iteration, distinguishing
/// configuration data rejected by the graph authority (relist while keeping
/// the etcd connection and readiness on the last-known-good graph) from
/// transport/protocol failures (reset the client and mark etcd disconnected).
#[derive(Debug)]
enum SyncError {
    Transport(ProxyError),
    Data(ProxyError),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::Transport(err) | SyncError::Data(err) => write!(f, "{err}"),
        }
    }
}

impl From<ProxyError> for SyncError {
    fn from(err: ProxyError) -> Self {
        SyncError::Transport(err)
    }
}

/// Classify a rejection from the configuration graph authority's ingestion
/// surface. Invalid candidate data is a data problem, not a transport one: the
/// sync loop relists without marking etcd disconnected, readiness stays green
/// on the last-known-good graph, and the error surfaces as a candidate
/// preparation error. Anything else is treated as a sync failure.
fn classify_rejection(err: GraphError) -> SyncError {
    let is_data = matches!(
        err,
        GraphError::InvalidCandidate { .. }
            | GraphError::InvalidResource { .. }
            | GraphError::Secret { .. }
    );
    let message = format!("Configuration graph rejected input: {err}");
    if is_data {
        SyncError::Data(ProxyError::Configuration(message))
    } else {
        SyncError::Transport(ProxyError::Configuration(message))
    }
}

/// Sleep for `delay`, but return `true` immediately if shutdown is requested.
async fn sleep_or_shutdown(delay: Duration, shutdown: &ShutdownWatch) -> bool {
    let mut shutdown = shutdown.clone();
    tokio::select! {
        _ = sleep(delay) => false,
        result = shutdown.changed() => {
            match result {
                Ok(()) => *shutdown.borrow(),
                Err(_) => true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::keys::GRAPH_PROTOCOL_VERSION;
    use super::*;
    use crate::proxy::graph_mutation::ResourceKind;

    #[test]
    fn rejection_classification_distinguishes_data_from_transport() {
        let data = classify_rejection(GraphError::InvalidCandidate {
            source: ProxyError::Configuration("broken graph".into()),
        });
        assert!(matches!(data, SyncError::Data(_)), "{data:?}");

        let data = classify_rejection(GraphError::InvalidResource {
            key: ResourceKey::new(ResourceKind::Route, "r1").unwrap(),
            source: ProxyError::Configuration("bad document".into()),
        });
        assert!(matches!(data, SyncError::Data(_)), "{data:?}");

        let transport = classify_rejection(GraphError::StaleRevision {
            incoming: 1,
            published: 2,
        });
        assert!(
            matches!(transport, SyncError::Transport(_)),
            "{transport:?}"
        );

        let transport = classify_rejection(GraphError::WorkerStopped);
        assert!(
            matches!(transport, SyncError::Transport(_)),
            "{transport:?}"
        );
    }

    fn list_kv(
        key: &'static str,
        value: &'static [u8],
        create_revision: i64,
        mod_revision: i64,
    ) -> ListKv<'static> {
        ListKv {
            key: key.as_bytes(),
            value,
            create_revision,
            mod_revision,
        }
    }

    #[test]
    fn list_mapping_reads_and_validates_guard() {
        let prefix = "/pingsix/";
        let kvs = vec![
            list_kv("/pingsix/upstreams/u1", b"{}", 1, 3),
            list_kv("/pingsix/routes/r1", b"{}", 1, 5),
            list_kv(
                "/pingsix/.pingsix_graph_revision",
                GRAPH_PROTOCOL_VERSION,
                2,
                4,
            ),
        ];
        let graph = graph_snapshot_from_list(&kvs, 42, prefix).unwrap();
        assert_eq!(graph.revision, 42);
        assert_eq!(graph.guard_mod_revision, Some(4));
        assert_eq!(graph.resources.len(), 2);
        assert!(graph
            .resources
            .contains_key(&ResourceKey::new(ResourceKind::Upstream, "u1").unwrap()));
        assert!(graph
            .resources
            .contains_key(&ResourceKey::new(ResourceKind::Route, "r1").unwrap()));
    }

    #[test]
    fn list_mapping_accepts_legacy_guard_value() {
        let prefix = "/pingsix/";
        let kvs = vec![list_kv("/pingsix/.pingsix_graph_revision", b"1", 2, 4)];
        let graph = graph_snapshot_from_list(&kvs, 7, prefix).unwrap();
        assert_eq!(graph.guard_mod_revision, Some(4));
        assert!(graph.resources.is_empty());
    }

    #[test]
    fn list_mapping_rejects_unsupported_guard() {
        let prefix = "/pingsix/";
        let kvs = vec![list_kv(
            "/pingsix/.pingsix_graph_revision",
            b"pingsix-graph-v2",
            2,
            4,
        )];
        assert!(matches!(
            graph_snapshot_from_list(&kvs, 7, prefix),
            Err(StoreError::UnsupportedProtocol)
        ));
    }

    #[test]
    fn list_mapping_excludes_metadata_and_foreign_keys() {
        let prefix = "/pingsix/";
        let kvs = vec![
            list_kv("/pingsix/.ingress_sync_barrier", b"{}", 1, 1),
            list_kv("/pingsix-other/routes/1", b"{}", 1, 1),
            list_kv("/pingsix/ssls/t1", b"{}", 1, 2),
        ];
        let graph = graph_snapshot_from_list(&kvs, 9, prefix).unwrap();
        assert_eq!(graph.resources.len(), 1);
        assert!(graph
            .resources
            .contains_key(&ResourceKey::new(ResourceKind::Ssl, "t1").unwrap()));
        assert_eq!(graph.guard_mod_revision, None);
    }
}
