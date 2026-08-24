//! Public configuration graph authority API and Admin mutation operations.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use hickory_resolver::TokioResolver;
use tokio::sync::Mutex as AsyncMutex;
use validator::Validate;

use crate::{
    config::{self, EffectiveDefaults, GlobalRule, Route, Service, Upstream, SSL},
    core::{status, status::StatusStore, ProxyError, ProxyResult},
    proxy::{
        control_plane::{
            prepare_candidate, validate_runtime_form, CandidateSnapshot, ResourceConfigSet,
        },
        runtime::{RuntimeSnapshot, RuntimeStore},
        ssl::ProxySSL,
    },
    utils::encryption::KeyringService,
};

use super::{
    decode::{apply_watch_batch, decode_graph, plan_delete_mutation, plan_put_mutation},
    secrets::{
        contains_redaction_sentinel, decrypt_for_read, encrypt_for_storage, redact,
        restore_redacted_secrets,
    },
    state::{Inner, Lifecycle, PublicationRegistry, PENDING_REVISION},
    store::{
        CommitRevision, GraphError, GraphStore, ResourceKey, ResourceKind, ResourceView,
        SecretMode, SecretOperation, StoreError, StoredGraph, WatchBatch,
    },
};

pub use super::state::{ConfigurationGraph, PublicationState, PublicationView};

impl ConfigurationGraph {
    /// Test helper: bind a graph to a fresh, isolated [`GraphTestHarness`].
    ///
    /// Production always uses [`ConfigurationGraph::with_state`] so the graph
    /// shares the owning [`crate::service::GatewayState`].
    #[cfg(test)]
    pub fn new(store: Arc<dyn GraphStore>) -> Self {
        super::GraphTestHarness::new(store).graph
    }

    /// Create a graph publishing readiness through `status`, runtime snapshots
    /// through `runtime`, applying instance defaults `defaults` during
    /// candidate preparation/compilation, handling secrets through `keyring`,
    /// and resolving DNS through `resolver`.
    pub fn with_state(
        store: Arc<dyn GraphStore>,
        status: Arc<StatusStore>,
        runtime: Arc<RuntimeStore>,
        defaults: EffectiveDefaults,
        keyring: Arc<KeyringService>,
        resolver: Arc<TokioResolver>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                status,
                runtime,
                defaults,
                keyring,
                resolver,
                committed: Mutex::new(None),
                target: Mutex::new(None),
                write_lock: Mutex::new(()),
                latest_generation: Mutex::new(0),
                preparation: AsyncMutex::new(()),
                worker_tx: Mutex::new(None),
                worker_task: Mutex::new(None),
                active_cancellation: Mutex::new(None),
                lifecycle: Mutex::new(Lifecycle::Running),
                publications: Mutex::new(PublicationRegistry::default()),
            }),
        }
    }

    /// Accept an authoritative full list snapshot without waiting for DNS.
    ///
    /// The snapshot is decoded (fail-closed on secrets) and whole-graph
    /// validated synchronously before submission, so the etcd adapter can
    /// relist instead of silently accepting a broken graph; the worker only
    /// prepares DNS and compiles.
    pub fn replace_all(&self, snapshot: StoredGraph) -> Result<(), GraphError> {
        // Serialized with `apply_watch` submissions: generation, cancellation,
        // target, and work-signal updates in `submit` must never interleave.
        let _writer = self
            .inner
            .write_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let logical = decode_graph(
            &snapshot,
            SecretMode::DecryptForRuntime,
            &self.inner.keyring,
        )
        .map_err(|e| GraphError::InvalidCandidate { source: e })?;
        validate_runtime_form(&logical).map_err(|e| GraphError::InvalidCandidate { source: e })?;
        self.submit(snapshot, logical)
    }

    /// Accept one causally ordered watch batch without waiting for DNS.
    ///
    /// Changes layer on the latest pending target (otherwise the committed
    /// graph), so updates arriving while a previous generation is still
    /// preparing DNS are not lost. Empty batches are no-ops. The resulting
    /// graph is decoded and whole-graph validated synchronously, so invalid
    /// batches are rejected and the sync loop relists instead of retrying a
    /// broken candidate in the worker.
    pub fn apply_watch(&self, batch: WatchBatch) -> Result<(), GraphError> {
        if batch.changes.is_empty() {
            return Ok(());
        }
        let _writer = self
            .inner
            .write_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let published = self.inner.runtime.load().revision;
        if batch.revision < published {
            return Err(GraphError::StaleRevision {
                incoming: batch.revision,
                published,
            });
        }
        let base = self
            .inner
            .target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|t| t.stored.clone())
            .unwrap_or_else(|| {
                self.inner
                    .committed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|c| c.stored.clone())
                    .unwrap_or_default()
            });
        let stored = apply_watch_batch(&base, &batch)?;
        let logical = decode_graph(&stored, SecretMode::DecryptForRuntime, &self.inner.keyring)
            .map_err(|e| GraphError::InvalidCandidate { source: e })?;
        validate_runtime_form(&logical).map_err(|e| GraphError::InvalidCandidate { source: e })?;
        self.submit(stored, logical)
    }

    /// Stop accepting work, cancel in-flight preparation, and wait a bounded
    /// interval for the sole worker to observe cancellation.
    ///
    /// Terminal and idempotent: after the first call the lifecycle is `Stopped`
    /// and no later submission can resurrect the worker.
    pub async fn shutdown(&self) {
        {
            let mut lifecycle = self
                .inner
                .lifecycle
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if *lifecycle == Lifecycle::Stopped {
                return;
            }
            *lifecycle = Lifecycle::Stopped;
        }
        if let Some(active) = self
            .inner
            .active_cancellation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            active.cancel();
        }
        self.inner
            .worker_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        PENDING_REVISION.set(0);
        let task = self
            .inner
            .worker_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(mut task) = task {
            if tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
                .await
                .is_err()
            {
                log::warn!("Control-plane preparation worker missed shutdown deadline; aborting");
                task.abort();
                let _ = task.await;
            }
        }
    }

    /// Static startup path: this graph ingests the static YAML snapshot
    /// through the same validate → prepare → compile → publish funnel as the
    /// dynamic list/watch path (filesystem as source instead of watch), but
    /// driven synchronously: DNS preparation must finish before listeners
    /// start, and unresolvable DNS-only upstreams fail the process.
    ///
    /// Single-writer: this call is the one and only publication in static
    /// mode; the graph never runs a watch loop and accepts no further
    /// submissions.
    pub fn load_static(&self, resources: &ResourceConfigSet) -> ProxyResult<Arc<RuntimeSnapshot>> {
        validate_runtime_form(resources)?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                ProxyError::Configuration(format!("Failed to create DNS preparation runtime: {e}"))
            })?;
        // The pre-publish runtime is the reuse baseline for the static path; at
        // boot it is the empty snapshot, so every occurrence is prepared.
        let previous = self.inner.runtime.load();
        let prepared = rt.block_on(async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate()).map_err(|e| {
                    ProxyError::Configuration(format!("Failed to install SIGTERM handler: {e}"))
                })?;
                tokio::select! {
                    result = prepare_candidate(resources, &previous, &self.inner.defaults, &self.inner.resolver) => result,
                    _ = sigterm.recv() => Err(ProxyError::Configuration(
                        "Static configuration DNS preparation cancelled by SIGTERM".into(),
                    )),
                }
            }
            #[cfg(not(unix))]
            {
                prepare_candidate(resources, &previous, &self.inner.defaults, &self.inner.resolver)
                    .await
            }
        })?;
        let (plan, prepared) = prepared;
        let candidate = CandidateSnapshot::build_prepared(
            resources.clone(),
            &plan,
            &prepared,
            &previous,
            &self.inner.defaults,
            &self.inner.resolver,
        )?;
        let snapshot = RuntimeSnapshot::compile(candidate, 0)?;
        let published = self.inner.runtime.publish(snapshot)?;
        self.inner.status.mark_ready(status::ConfigSource::Yaml);
        Ok(published)
    }
}

impl ConfigurationGraph {
    /// Read one stored resource, decrypted and redacted, for the Admin API.
    pub async fn get(&self, key: &ResourceKey) -> Result<Option<ResourceView>, GraphError> {
        let Some(resource) = self
            .inner
            .store
            .get_exact(key)
            .await
            .map_err(GraphError::Store)?
        else {
            return Ok(None);
        };
        let mut json = parse_stored_resource(key, &resource.value)?;
        decrypt_for_read(key.kind, &mut json, &self.inner.keyring).map_err(|source| {
            GraphError::Secret {
                key: key.clone(),
                operation: SecretOperation::Decrypt,
                source,
            }
        })?;
        redact(key.kind, &mut json, &self.inner.keyring);
        Ok(Some(ResourceView {
            key: key.clone(),
            value: json,
            create_revision: resource.create_revision,
            mod_revision: resource.mod_revision,
        }))
    }

    /// List all stored resources of one kind, decrypted and redacted.
    pub async fn list(&self, kind: ResourceKind) -> Result<Vec<ResourceView>, GraphError> {
        let resources = self
            .inner
            .store
            .list_kind(kind)
            .await
            .map_err(GraphError::Store)?;
        let mut views = Vec::new();
        for (key, resource) in resources {
            let mut json = parse_stored_resource(&key, &resource.value)?;
            decrypt_for_read(kind, &mut json, &self.inner.keyring).map_err(|source| {
                GraphError::Secret {
                    key: key.clone(),
                    operation: SecretOperation::Decrypt,
                    source,
                }
            })?;
            redact(kind, &mut json, &self.inner.keyring);
            views.push(ResourceView {
                key,
                value: json,
                create_revision: resource.create_revision,
                mod_revision: resource.mod_revision,
            });
        }
        views.sort_by(|a, b| a.key.id.cmp(&b.key.id));
        Ok(views)
    }

    /// Validate and commit an Admin PUT. `value` is the logical plaintext JSON,
    /// possibly containing the redaction sentinel at genuine secret paths.
    ///
    /// Secret restoration and CAS planning derive from the same snapshot, so a
    /// concurrent update cannot mix an older secret with a newer observation.
    pub async fn put(
        &self,
        key: ResourceKey,
        mut value: serde_json::Value,
    ) -> Result<CommitRevision, GraphError> {
        let snapshot = self
            .inner
            .store
            .snapshot()
            .await
            .map_err(GraphError::Store)?;

        // The storage/path key is the single authority for resource identity:
        // normalize the body `id` before validation, persistence, and every
        // later read, so Admin GET/LIST and the runtime can never disagree
        // about which resource this is.
        let body_id = value.get("id").and_then(|v| v.as_str());
        if body_id != Some(key.id.as_str()) {
            if let Some(body_id) = body_id.filter(|s| !s.is_empty()) {
                log::warn!(
                    "Admin PUT {}: body id '{body_id}' ignored; path id '{}' is authoritative",
                    key.logical_path(),
                    key.id
                );
            }
            value["id"] = serde_json::Value::String(key.id.clone());
        }

        if contains_redaction_sentinel(&value) {
            if let Some(stored) = snapshot.resources.get(&key) {
                let mut existing = parse_stored_resource(&key, &stored.value)?;
                decrypt_for_read(key.kind, &mut existing, &self.inner.keyring).map_err(
                    |source| GraphError::Secret {
                        key: key.clone(),
                        operation: SecretOperation::Restore,
                        source,
                    },
                )?;
                restore_redacted_secrets(key.kind, &mut value, &existing, &self.inner.keyring);
            }
        }

        validate_resource_json(key.kind, &value).map_err(|source| GraphError::InvalidResource {
            key: key.clone(),
            source,
        })?;

        let stored =
            encrypt_for_storage(key.kind, &mut value, &self.inner.keyring).map_err(|source| {
                GraphError::Secret {
                    key: key.clone(),
                    operation: SecretOperation::Encrypt,
                    source,
                }
            })?;

        let commit = plan_put_mutation(&snapshot, &key, stored, &self.inner.keyring)?;
        let revision = self
            .inner
            .store
            .compare_and_swap(commit)
            .await
            .map_err(map_store_error)?;
        self.record_pending_publication(revision.0);
        Ok(revision)
    }

    /// Last runtime-published revision from this graph's status store.
    ///
    /// Reads the injected [`StatusStore`] so the Admin API reflects the same
    /// per-build state as the status app.
    pub fn published_revision(&self) -> i64 {
        self.inner.status.published_revision()
    }

    /// Validate and commit an Admin DELETE against the whole graph.
    pub async fn delete(&self, key: ResourceKey) -> Result<CommitRevision, GraphError> {
        let snapshot = self
            .inner
            .store
            .snapshot()
            .await
            .map_err(GraphError::Store)?;
        let commit = plan_delete_mutation(&snapshot, &key, &self.inner.keyring)?;
        let revision = self
            .inner
            .store
            .compare_and_swap(commit)
            .await
            .map_err(map_store_error)?;
        self.record_pending_publication(revision.0);
        Ok(revision)
    }
}

fn map_store_error(err: StoreError) -> GraphError {
    match err {
        StoreError::Conflict => GraphError::CasConflict,
        other => GraphError::Store(other),
    }
}

fn parse_stored_resource(key: &ResourceKey, value: &[u8]) -> Result<serde_json::Value, GraphError> {
    serde_json::from_slice(value).map_err(|e| GraphError::InvalidResource {
        key: key.clone(),
        source: ProxyError::serialization_error("Failed to parse stored resource", e),
    })
}

/// Validate a logical resource JSON document against its typed schema, plugin
/// configurations, deterministic upstream mTLS material, and (for SSL)
/// certificate/key material.
pub(crate) fn validate_resource_json(
    kind: ResourceKind,
    value: &serde_json::Value,
) -> ProxyResult<()> {
    // Admin writes bypass stored-resource decoding, so they must use the same
    // compatibility-preserving warning path before serde drops unknown fields.
    config::warn_unrecognized_fields(kind.as_str(), value);
    match kind {
        ResourceKind::Upstream => {
            let resource: Upstream =
                serde_json::from_value(value.clone()).map_err(serialization_error)?;
            resource.validate()?;
            validate_upstream_tls_material(&resource)?;
        }
        ResourceKind::Service => {
            let resource: Service =
                serde_json::from_value(value.clone()).map_err(serialization_error)?;
            resource.validate()?;
            validate_plugins(&resource.plugins)?;
            if let Some(upstream) = &resource.upstream {
                validate_upstream_tls_material(upstream)?;
            }
        }
        ResourceKind::GlobalRule => {
            let resource: GlobalRule =
                serde_json::from_value(value.clone()).map_err(serialization_error)?;
            resource.validate()?;
            validate_plugins(&resource.plugins)?;
        }
        ResourceKind::Route => {
            let resource: Route =
                serde_json::from_value(value.clone()).map_err(serialization_error)?;
            resource.validate()?;
            validate_plugins(&resource.plugins)?;
            if let Some(upstream) = &resource.upstream {
                validate_upstream_tls_material(upstream)?;
            }
        }
        ResourceKind::Ssl => {
            let resource: SSL =
                serde_json::from_value(value.clone()).map_err(serialization_error)?;
            resource.validate()?;
            ProxySSL::try_from(resource)?;
        }
    }
    Ok(())
}

/// Deterministic check of upstream mTLS material so invalid client
/// certificate/key pairs are rejected by the Admin write path before they are
/// committed, instead of being stored and only failing publication later.
fn validate_upstream_tls_material(upstream: &Upstream) -> ProxyResult<()> {
    if let Some(tls) = &upstream.tls {
        crate::proxy::upstream::discovery::validate_client_tls_material(tls)?;
    }
    Ok(())
}

fn serialization_error(e: serde_json::Error) -> ProxyError {
    ProxyError::serialization_error("Failed to deserialize resource JSON", e)
}

/// Build every configured plugin to surface invalid plugin configuration.
/// Validation is delegated to each plugin's declared capabilities: plain
/// plugins are built (construction parses their config), dependency-aware
/// plugins validate structurally without resolving named upstreams. Candidate
/// publication owns reference resolution against the same graph.
fn validate_plugins(plugins: &HashMap<String, serde_json::Value>) -> ProxyResult<()> {
    for (name, value) in plugins {
        crate::plugins::validate_plugin_config(name, value)
            .map_err(|e| ProxyError::Plugin(format!("Failed to validate plugin '{name}': {e}")))?;
    }
    Ok(())
}
