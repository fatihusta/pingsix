//! Preparation worker and publication state for the configuration graph authority.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use hickory_resolver::TokioResolver;
use once_cell::sync::Lazy;
use prometheus::{register_int_counter_vec, register_int_gauge, IntCounterVec, IntGauge};
use serde::Serialize;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;

use crate::{
    config::EffectiveDefaults,
    core::{status::StatusStore, ProxyError, ProxyResult},
    proxy::{
        control_plane::{prepare_candidate, CandidateSnapshot, ResourceConfigSet},
        runtime::{RuntimeSnapshot, RuntimeStore},
    },
    utils::encryption::KeyringService,
};

use super::store::{GraphError, GraphStore, StoredGraph};

static PREPARATION_ATTEMPTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "pingsix_control_plane_preparation_total",
        "Control-plane candidate preparation attempts",
        &["outcome"]
    )
    .expect("control-plane preparation metric registration must succeed")
});
pub(crate) static PENDING_REVISION: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "pingsix_control_plane_pending_revision",
        "Latest etcd revision awaiting successful publication, or zero"
    )
    .expect("control-plane pending revision metric registration must succeed")
});
pub(crate) const PUBLICATION_REGISTRY_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationState {
    Pending,
    Published,
    Rejected,
    Superseded,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublicationView {
    pub state: PublicationState,
    pub published_revision: Option<i64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct PublicationRecord {
    state: PublicationState,
    error: Option<String>,
}

#[derive(Default)]
pub(crate) struct PublicationRegistry {
    pub(crate) records: BTreeMap<i64, PublicationRecord>,
    published_revision: Option<i64>,
}

impl PublicationRegistry {
    pub(crate) fn pending(&mut self, revision: i64) {
        if revision > 0 {
            self.records.entry(revision).or_insert(PublicationRecord {
                state: PublicationState::Pending,
                error: None,
            });
            self.trim();
        }
    }
    pub(crate) fn supersede_pending_except(&mut self, revision: i64) {
        for (candidate, record) in &mut self.records {
            if *candidate != revision && record.state == PublicationState::Pending {
                record.state = PublicationState::Superseded;
                record.error = None;
            }
        }
    }
    pub(crate) fn published(&mut self, revision: i64) {
        self.pending(revision);
        if let Some(record) = self.records.get_mut(&revision) {
            record.state = PublicationState::Published;
            record.error = None;
        }
        self.published_revision = Some(revision);
        self.trim();
    }
    pub(crate) fn rejected(&mut self, revision: i64, error: String) {
        if let Some(record) = self.records.get_mut(&revision) {
            if record.state == PublicationState::Pending {
                record.state = PublicationState::Rejected;
                record.error = Some(error);
            }
        }
    }
    pub(crate) fn view(&self, revision: i64) -> Option<PublicationView> {
        self.records.get(&revision).map(|record| PublicationView {
            state: record.state,
            published_revision: self.published_revision,
            error: record.error.clone(),
        })
    }
    fn trim(&mut self) {
        while self.records.len() > PUBLICATION_REGISTRY_CAPACITY {
            let Some(revision) = self.records.iter().find_map(|(revision, record)| {
                (record.state != PublicationState::Pending).then_some(*revision)
            }) else {
                break;
            };
            self.records.remove(&revision);
        }
    }
}

pub(crate) fn safe_preparation_error(permanent: bool) -> String {
    if permanent {
        "candidate rejected during runtime preparation".into()
    } else {
        "candidate preparation temporarily unavailable".into()
    }
}

/// The single authority over stored and pending configuration graph state.
///
/// All graph reads, mutations, list/watch ingestion, and runtime publication
/// cross this interface. The store is injected behind the [`GraphStore`] seam;
/// HTTP and etcd transport stay in their adapters.
#[derive(Clone)]
pub struct ConfigurationGraph {
    pub(crate) inner: Arc<Inner>,
}

/// Last generation whose runtime snapshot published successfully.
pub(crate) struct CommittedGraph {
    pub(crate) stored: StoredGraph,
}

/// Latest submitted generation, including invalid or DNS-pending candidates.
#[derive(Clone)]
pub(crate) struct PendingGraph {
    pub(crate) generation: u64,
    pub(crate) revision: i64,
    pub(crate) stored: StoredGraph,
    pub(crate) logical: ResourceConfigSet,
    pub(crate) cancellation: CancellationToken,
}

/// Lifecycle of the graph authority's preparation worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lifecycle {
    Running,
    /// [`ConfigurationGraph::shutdown`] has been called. Submissions fail with
    /// [`GraphError::WorkerStopped`] and the worker is never resurrected.
    Stopped,
}

pub(crate) struct Inner {
    pub(crate) store: Arc<dyn GraphStore>,
    /// Instance-owned readiness store; published revisions and preparation
    /// errors are recorded here.
    pub(crate) status: Arc<StatusStore>,
    /// Instance-owned runtime store; candidate publications land here.
    pub(crate) runtime: Arc<RuntimeStore>,
    /// Effective `pingsix.defaults` resolved at startup; candidate
    /// preparation and compilation bake these in.
    pub(crate) defaults: EffectiveDefaults,
    /// Instance-owned encryption service; secret encrypt/decrypt/redact paths
    /// use this instead of constructing a process-wide keyring.
    pub(crate) keyring: Arc<KeyringService>,
    /// Instance-owned DNS resolver used during candidate preparation.
    pub(crate) resolver: Arc<TokioResolver>,
    pub(crate) committed: Mutex<Option<CommittedGraph>>,
    pub(crate) target: Mutex<Option<PendingGraph>>,
    /// Serializes only short raw-candidate creation and fenced publish commits.
    pub(crate) write_lock: Mutex<()>,
    pub(crate) latest_generation: Mutex<u64>,
    /// One bounded owner serializes preparation; submissions replace its
    /// pending target and never block list/watch processing on DNS.
    pub(crate) preparation: AsyncMutex<()>,
    pub(crate) worker_tx: Mutex<Option<mpsc::Sender<()>>>,
    pub(crate) worker_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(crate) active_cancellation: Mutex<Option<CancellationToken>>,
    pub(crate) lifecycle: Mutex<Lifecycle>,
    pub(crate) publications: Mutex<PublicationRegistry>,
}

/// Outcome of one preparation/compile attempt in the sole worker.
#[derive(Debug)]
enum PrepareOutcome {
    /// Published, superseded, or cancelled — nothing left to retry.
    Settled,
    /// DNS/preparation failure: worth retrying with bounded backoff.
    Transient(ProxyError),
    /// Deterministic candidate failure (SSL, plugin, matcher): compiling the
    /// same generation again cannot succeed, so it is attempted once and the
    /// worker waits for a new revision instead of retrying forever.
    Permanent(ProxyError),
}

impl ConfigurationGraph {
    /// Start the single bounded preparation worker if it is not already running.
    fn ensure_worker_started(&self) -> Result<(), GraphError> {
        if *self
            .inner
            .lifecycle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            != Lifecycle::Running
        {
            return Err(GraphError::WorkerStopped);
        }
        if self
            .inner
            .worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Ok(());
        }
        let (tx, mut rx) = mpsc::channel(1);
        *self
            .inner
            .worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let graph = self.clone();
        let task = tokio::spawn(async move {
            while rx.recv().await.is_some() {
                let mut retry_delay = std::time::Duration::from_secs(1);
                loop {
                    // Snapshot the target this attempt will serve, so a failure
                    // can tell whether a newer submission superseded it before
                    // sleeping out the failed generation's backoff.
                    let attempted = graph.current_target();
                    match graph.prepare_latest().await {
                        PrepareOutcome::Settled => break,
                        PrepareOutcome::Transient(error) => {
                            PREPARATION_ATTEMPTS.with_label_values(&["failed"]).inc();
                            graph
                                .inner
                                .status
                                .record_preparation_error(safe_preparation_error(false));
                            log::warn!(
                                "Control-plane candidate preparation failed; retrying in {}s: {error}",
                                retry_delay.as_secs()
                            );
                            let Some((failed_generation, cancellation)) = attempted else {
                                break;
                            };
                            if !graph.is_current_generation(failed_generation) {
                                // A newer submission superseded the failed
                                // generation: restart preparation for the
                                // latest target immediately instead of waiting
                                // out the old generation's backoff.
                                continue;
                            }
                            tokio::select! {
                                _ = tokio::time::sleep(retry_delay) => {}
                                _ = cancellation.cancelled() => break,
                            }
                            retry_delay = (retry_delay * 2).min(std::time::Duration::from_secs(30));
                        }
                        PrepareOutcome::Permanent(error) => {
                            PREPARATION_ATTEMPTS.with_label_values(&["failed"]).inc();
                            let summary = safe_preparation_error(true);
                            if let Some((failed_generation, _)) = attempted.as_ref() {
                                graph.reject_publication(*failed_generation, summary.clone());
                            }
                            graph.inner.status.record_preparation_error(summary);
                            log::error!(
                                "Control-plane candidate rejected permanently; waiting for a new revision: {error}"
                            );
                            // Deterministic failures cannot be fixed by retrying.
                            // Wait for this generation to be superseded (a new
                            // submission cancels it), then restart from the
                            // latest target.
                            let Some((_, cancellation)) = attempted else {
                                break;
                            };
                            cancellation.cancelled().await;
                            break;
                        }
                    }
                }
            }
        });
        self.inner
            .worker_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(task);
        Ok(())
    }

    /// Store a new pending generation and signal the worker. Submissions never
    /// wait for DNS; the worker always reads the latest generation.
    pub(crate) fn submit(
        &self,
        stored: StoredGraph,
        logical: ResourceConfigSet,
    ) -> Result<(), GraphError> {
        self.ensure_worker_started()?;
        let generation = {
            let mut generation = self
                .inner
                .latest_generation
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *generation += 1;
            *generation
        };
        let revision = stored.revision;
        {
            let mut publications = self
                .inner
                .publications
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            publications.pending(revision);
            publications.supersede_pending_except(revision);
        }
        let cancellation = CancellationToken::new();
        if let Some(previous) = self
            .inner
            .active_cancellation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace(cancellation.clone())
        {
            previous.cancel();
        }
        *self.inner.target.lock().unwrap_or_else(|e| e.into_inner()) = Some(PendingGraph {
            generation,
            revision,
            stored,
            logical,
            cancellation,
        });
        PENDING_REVISION.set(revision);
        let sender = self
            .inner
            .worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(GraphError::WorkerStopped)?;
        match sender.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => Err(GraphError::WorkerStopped),
        }
    }

    /// Snapshot of the current pending target's generation and cancellation
    /// token, taken before a preparation attempt so a failure can detect that
    /// a newer submission superseded it.
    fn current_target(&self) -> Option<(u64, CancellationToken)> {
        self.inner
            .target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|target| (target.generation, target.cancellation.clone()))
    }

    /// Whether `generation` is still the latest submitted generation.
    fn is_current_generation(&self, generation: u64) -> bool {
        *self
            .inner
            .latest_generation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            == generation
    }

    /// Prepare, compile, and publish the latest pending generation, classifying
    /// failures so the worker can distinguish retryable DNS problems from
    /// deterministic candidate defects.
    async fn prepare_latest(&self) -> PrepareOutcome {
        let _owner = self.inner.preparation.lock().await;
        let Some(target) = self
            .inner
            .target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            return PrepareOutcome::Settled;
        };
        let PendingGraph {
            generation,
            revision,
            stored,
            logical,
            cancellation,
        } = target;
        let previous = self.inner.runtime.load();
        let prepared = tokio::select! {
            result = prepare_candidate(&logical, &previous, &self.inner.defaults, &self.inner.resolver) => match result {
                Ok((plan, prepared)) => (plan, prepared),
                Err(error) => return PrepareOutcome::Transient(error),
            },
            _ = cancellation.cancelled() => return PrepareOutcome::Settled,
        };
        // Heavy CPU work (plugin/route/matcher/SSL build, route matcher
        // construction) runs OUTSIDE write_lock so a slow candidate compile
        // does not block new watch/list submissions. It also runs on the
        // blocking thread pool instead of a tokio worker, so a large graph
        // cannot stall data-plane tasks sharing this runtime. The generation
        // fence below discards the result if a newer generation superseded
        // this one while it was compiling.
        let (plan, prepared) = prepared;
        let previous = previous.clone();
        let defaults = self.inner.defaults.clone();
        let resolver = self.inner.resolver.clone();
        let compiled = tokio::select! {
            result = tokio::task::spawn_blocking(move || -> ProxyResult<RuntimeSnapshot> {
                let candidate = CandidateSnapshot::build_prepared(
                    logical,
                    &plan,
                    &prepared,
                    &previous,
                    &defaults,
                    &resolver,
                )?;
                RuntimeSnapshot::compile(candidate, revision)
            }) => match result {
                Ok(Ok(compiled)) => compiled,
                Ok(Err(error)) => return PrepareOutcome::Permanent(error),
                Err(join_error) => {
                    return PrepareOutcome::Permanent(ProxyError::Internal(format!(
                        "control-plane compile task panicked: {join_error}"
                    )))
                }
            },
            _ = cancellation.cancelled() => return PrepareOutcome::Settled,
        };
        // Acquire write_lock only for the generation fence + atomic publish +
        // committed-graph update.
        let _writer = self
            .inner
            .write_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if cancellation.is_cancelled()
            || *self
                .inner
                .latest_generation
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                != generation
        {
            return PrepareOutcome::Settled;
        }
        if revision < self.inner.runtime.load().revision {
            return PrepareOutcome::Settled;
        }
        let published = match self.inner.runtime.publish(compiled) {
            Ok(published) => published,
            Err(error) => return PrepareOutcome::Permanent(error),
        };
        *self
            .inner
            .committed
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(CommittedGraph { stored });
        self.publish_revision(revision);
        PENDING_REVISION.set(0);
        PREPARATION_ATTEMPTS.with_label_values(&["published"]).inc();
        log::debug!(
            "Published prepared control-plane generation {generation} at revision {}",
            published.revision
        );
        PrepareOutcome::Settled
    }

    /// Return the authority-owned outcome for a retained revision. `None`
    /// means unknown or aged out; it is never inferred from runtime revision.
    pub fn publication(&self, revision: i64) -> Option<PublicationView> {
        self.inner
            .publications
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .view(revision)
    }

    pub(crate) fn record_pending_publication(&self, revision: i64) {
        self.inner
            .publications
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending(revision);
    }

    fn publish_revision(&self, revision: i64) {
        self.inner
            .publications
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .published(revision);
    }

    fn reject_publication(&self, generation: u64, error: String) {
        let revision = self
            .inner
            .target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|target| target.generation == generation)
            .map(|target| target.revision);
        if let Some(revision) = revision {
            self.inner
                .publications
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .rejected(revision, error);
        }
    }
}
