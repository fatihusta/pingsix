//! Immutable runtime snapshots for the data plane.
//!
//! Writers compile a `CandidateSnapshot` into a `RuntimeSnapshot` and publish it
//! atomically. Health checks are reconciled incrementally by `RuntimeStore`.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;

use crate::{
    config,
    core::{
        status::StatusStore, HealthCheckFingerprint, HealthCheckSpec, ProxyPluginExecutor,
        ProxyResult,
    },
};

use super::{
    control_plane::CandidateSnapshot,
    global_rule::{build_global_plugin_executor, ProxyGlobalRule},
    route::{MatchEntry as RouteMatcher, ProxyRoute},
    service::ProxyService,
    ssl::{MatchEntry as SslMatcher, ProxySSL},
    upstream::{
        health_check::{HealthCheckRegistration, SharedHealthCheckService},
        ProxyUpstream,
    },
};

/// Immutable data-plane view. Requests must only read from this snapshot.
pub struct RuntimeSnapshot {
    pub revision: i64,
    pub routes: Arc<HashMap<String, Arc<ProxyRoute>>>,
    pub upstreams: Arc<HashMap<String, Arc<ProxyUpstream>>>,
    pub services: Arc<HashMap<String, Arc<ProxyService>>>,
    pub global_rules: Arc<HashMap<String, Arc<ProxyGlobalRule>>>,
    pub ssls: Arc<HashMap<String, Arc<ProxySSL>>>,
    pub route_matcher: Arc<RouteMatcher>,
    pub global_plugins: Arc<ProxyPluginExecutor>,
    pub ssl_matcher: Arc<SslMatcher>,
}

impl RuntimeSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            revision: 0,
            routes: Arc::new(HashMap::new()),
            upstreams: Arc::new(HashMap::new()),
            services: Arc::new(HashMap::new()),
            global_rules: Arc::new(HashMap::new()),
            ssls: Arc::new(HashMap::new()),
            route_matcher: Arc::new(RouteMatcher::default()),
            global_plugins: ProxyPluginExecutor::default_shared(),
            ssl_matcher: Arc::new(SslMatcher::default()),
        }
    }

    /// Sole construction path for published runtime state.
    pub fn compile(candidate: CandidateSnapshot, revision: i64) -> ProxyResult<Self> {
        let routes = Arc::new(candidate.routes);
        let upstreams = Arc::new(candidate.upstreams);
        let services = Arc::new(candidate.services);
        let global_rules = Arc::new(candidate.global_rules);
        let ssls = Arc::new(candidate.ssls);
        let global_plugins = build_global_plugin_executor(&global_rules);
        // Preflight fallback eligibility (global CORS) is compiled into the
        // matcher so the request path never inspects plugin names.
        let route_matcher = Arc::new(RouteMatcher::build(&routes, &global_plugins)?);
        let ssl_matcher = Arc::new(SslMatcher::build(&ssls)?);

        Ok(Self {
            revision,
            routes,
            upstreams,
            services,
            global_rules,
            ssls,
            route_matcher,
            global_plugins,
            ssl_matcher,
        })
    }
}

/// Stable fingerprint of upstream fields that affect health-check behavior.
///
/// The field policy (scheme, effective node addresses, `checks`; no weights,
/// retries or other LB-only fields) is declared next to the type as
/// [`config::UpstreamFingerprintProfile::HealthCheck`].
fn health_check_fingerprint(upstream: &config::Upstream) -> HealthCheckFingerprint {
    HealthCheckFingerprint(upstream.fingerprint(config::UpstreamFingerprintProfile::HealthCheck))
}

fn collect_health_checks(snapshot: &RuntimeSnapshot) -> Vec<HealthCheckSpec> {
    let mut targets = Vec::new();

    for (id, upstream) in snapshot.upstreams.iter() {
        targets.push(HealthCheckSpec {
            key: format!("upstream/{id}"),
            fingerprint: health_check_fingerprint(&upstream.inner),
            service: upstream.health_check_service(),
        });
    }
    for (id, service) in snapshot.services.iter() {
        if let Some(upstream) = &service.inline_upstream {
            targets.push(HealthCheckSpec {
                key: format!("service/{id}/inline"),
                fingerprint: health_check_fingerprint(&upstream.inner),
                service: upstream.health_check_service(),
            });
        }
        for entry in &service.plugins {
            targets.extend(plugin_health_checks(
                &format!("service/{id}/plugin"),
                &entry.plugin,
            ));
        }
    }
    for (id, route) in snapshot.routes.iter() {
        if let Some(upstream) = &route.inline_upstream {
            targets.push(HealthCheckSpec {
                key: format!("route/{id}/inline"),
                fingerprint: health_check_fingerprint(&upstream.inner),
                service: upstream.health_check_service(),
            });
        }
        for entry in &route.plugins {
            targets.extend(plugin_health_checks(
                &format!("route/{id}/plugin"),
                &entry.plugin,
            ));
        }
    }
    for (id, rule) in snapshot.global_rules.iter() {
        for entry in &rule.plugins {
            targets.extend(plugin_health_checks(
                &format!("global-rule/{id}/plugin"),
                &entry.plugin,
            ));
        }
    }

    targets
}

fn plugin_health_checks(
    prefix: &str,
    plugin: &Arc<dyn crate::core::ProxyPlugin>,
) -> Vec<HealthCheckSpec> {
    // Typed specs carry stable fingerprints; registration happens only when the
    // containing runtime snapshot is published.
    plugin
        .health_check_specs()
        .into_iter()
        .map(|mut spec| {
            spec.key = format!("{prefix}/{}", spec.key);
            spec
        })
        .collect()
}

struct ActiveHealthCheckEntry {
    fingerprint: HealthCheckFingerprint,
    registration: HealthCheckRegistration,
    /// Retained so publish can detect "same fingerprint, different LB Arc".
    service: Arc<dyn pingora_core::services::background::BackgroundService + Send + Sync>,
}

/// Currently activated health checks owned by the runtime store.
///
/// Ownership lives here (not on snapshot Drop) so unchanged checks survive republish.
struct ActiveHealthCheckSet {
    entries: HashMap<String, ActiveHealthCheckEntry>,
}

impl ActiveHealthCheckSet {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

pub struct RuntimeStore {
    current: ArcSwap<RuntimeSnapshot>,
    health_checks: Mutex<ActiveHealthCheckSet>,
    publish_lock: Mutex<()>,
    /// Instance-owned readiness store: publish records the published revision
    /// here.
    status: Arc<StatusStore>,
    /// Instance-owned health-check registry/service: publish registers and
    /// unregisters upstream probes here.
    health_check: Arc<SharedHealthCheckService>,
}

impl Default for RuntimeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeStore {
    /// Create a store with a private status store and health-check service.
    /// Production uses [`RuntimeStore::with_state`] so the runtime shares the
    /// owning [`crate::service::GatewayState`].
    pub fn new() -> Self {
        Self::with_state(
            Arc::new(StatusStore::new()),
            Arc::new(SharedHealthCheckService::new()),
        )
    }

    /// Create a store recording published revisions on `status` and
    /// registering health checks through `health_check`.
    pub fn with_state(
        status: Arc<StatusStore>,
        health_check: Arc<SharedHealthCheckService>,
    ) -> Self {
        Self {
            current: ArcSwap::from_pointee(RuntimeSnapshot::empty()),
            health_checks: Mutex::new(ActiveHealthCheckSet::new()),
            publish_lock: Mutex::new(()),
            status,
            health_check,
        }
    }

    pub fn load(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    /// Publish a compiled snapshot and incrementally reconcile health checks.
    ///
    /// Order:
    /// 1. Start new / replacement checks without stopping displaced ones
    /// 2. Store the runtime snapshot
    /// 3. Discard displaced checks and stop removed keys
    ///
    /// Registration is infallible (Candidate build owns fallible work). Displaced
    /// checks keep running until after snapshot commit.
    pub fn publish(&self, snapshot: RuntimeSnapshot) -> ProxyResult<Arc<RuntimeSnapshot>> {
        let _guard = self.publish_lock.lock().unwrap_or_else(|e| e.into_inner());
        let desired = collect_health_checks(&snapshot);
        let mut active = self.health_checks.lock().unwrap_or_else(|e| e.into_inner());

        let mut next_entries = HashMap::with_capacity(desired.len());
        let mut displaced = Vec::new();

        for spec in desired {
            if let Some(existing) = active.entries.get(&spec.key) {
                // Fingerprint alone is insufficient: a rebuilt ProxyUpstream can share the
                // HC fingerprint (e.g. weight-only edits) while owning a different LB Arc.
                // Only keep the registration when the LB service Arc is identical.
                if existing.fingerprint == spec.fingerprint
                    && Arc::ptr_eq(&existing.service, &spec.service)
                {
                    next_entries.insert(
                        spec.key,
                        ActiveHealthCheckEntry {
                            fingerprint: existing.fingerprint,
                            registration: existing.registration,
                            service: existing.service.clone(),
                        },
                    );
                    continue;
                }
            }

            let (registration, maybe_displaced) = self
                .health_check
                .register_upstream(spec.key.clone(), spec.service.clone());
            if let Some(d) = maybe_displaced {
                displaced.push(d);
            }
            next_entries.insert(
                spec.key,
                ActiveHealthCheckEntry {
                    fingerprint: spec.fingerprint,
                    registration,
                    service: spec.service,
                },
            );
        }

        let mut removed = Vec::new();
        for (key, entry) in active.entries.iter() {
            match next_entries.get(key) {
                Some(next) if next.registration == entry.registration => {}
                Some(_) => {
                    // Replacement: old generation is stopped via displaced.discard() below.
                }
                None => {
                    removed.push((key.clone(), entry.registration));
                }
            }
        }

        let snapshot = Arc::new(snapshot);
        self.current.store(snapshot.clone());
        self.status.set_published_revision(snapshot.revision);

        for d in displaced {
            d.discard();
        }
        for (key, registration) in removed {
            self.health_check.unregister_upstream(&key, registration);
        }

        active.entries = next_entries;
        Ok(snapshot)
    }

    /// Test helper: currently active health-check generations by key.
    #[cfg(test)]
    pub fn health_check_generation(&self, key: &str) -> Option<u64> {
        self.health_checks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .get(key)
            .map(|e| e.registration.generation())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::control_plane::test_fixtures::{
        route_with_upstream_id, upstream, upstream_weighted,
    };

    #[test]
    fn per_instance_health_check_registries_are_isolated() {
        use crate::proxy::control_plane::{CandidateSnapshot, ResourceConfigSet};

        let status_a = Arc::new(crate::core::status::StatusStore::new());
        let status_b = Arc::new(crate::core::status::StatusStore::new());
        let service_a = Arc::new(SharedHealthCheckService::new());
        let service_b = Arc::new(SharedHealthCheckService::new());
        let store_a = RuntimeStore::with_state(status_a, service_a.clone());
        let store_b = RuntimeStore::with_state(status_b, service_b.clone());

        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        let snap = RuntimeSnapshot::compile(CandidateSnapshot::build(set).unwrap(), 1).unwrap();
        store_a.publish(snap).unwrap();

        // Registration landed only on A's registry: B (and its tasks) see nothing.
        assert_eq!(service_a.registry().get_all_upstreams().len(), 1);
        assert!(service_b.registry().get_all_upstreams().is_empty());
        assert!(store_a.health_check_generation("upstream/u1").is_some());
        assert_eq!(store_b.health_check_generation("upstream/u1"), None);
    }

    #[test]
    fn runtime_store_keeps_loaded_snapshot_after_publish() {
        let store = RuntimeStore::new();
        let old = store.load();
        let empty = RuntimeSnapshot::empty();
        let published = store.publish(empty).unwrap();

        assert!(!Arc::ptr_eq(&old, &published));
        assert!(old.routes.is_empty());
        assert!(published.routes.is_empty());
        assert!(Arc::ptr_eq(&store.load(), &published));
    }

    #[test]
    fn health_check_fingerprint_is_stable_across_hashmap_insertion_order() {
        let a = upstream_weighted("u", &[("10.0.0.2:80", 1), ("10.0.0.1:80", 2)]);
        let b = upstream_weighted("u", &[("10.0.0.1:80", 2), ("10.0.0.2:80", 1)]);
        assert_eq!(
            a.fingerprint(config::UpstreamFingerprintProfile::HealthCheck),
            b.fingerprint(config::UpstreamFingerprintProfile::HealthCheck)
        );
    }

    #[test]
    fn health_check_fingerprint_ignores_node_weight_changes() {
        let a = upstream_weighted("u", &[("10.0.0.1:80", 1)]);
        let b = upstream_weighted("u", &[("10.0.0.1:80", 99)]);
        assert_eq!(
            a.fingerprint(config::UpstreamFingerprintProfile::HealthCheck),
            b.fingerprint(config::UpstreamFingerprintProfile::HealthCheck)
        );
    }

    fn publish_set(
        store: &RuntimeStore,
        set: &crate::proxy::control_plane::ResourceConfigSet,
        revision: i64,
    ) {
        use crate::proxy::control_plane::CandidateSnapshot;
        let previous = store.load();
        let snap = RuntimeSnapshot::compile(
            CandidateSnapshot::build_against(set.clone(), &previous).unwrap(),
            revision,
        )
        .unwrap();
        store.publish(snap).unwrap();
    }

    #[test]
    fn unchanged_upstream_keeps_health_check_generation_across_publish() {
        use crate::proxy::control_plane::ResourceConfigSet;

        let store = RuntimeStore::new();
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.1:80"));
        publish_set(&store, &set, 1);
        let gen1 = store
            .health_check_generation("upstream/u1")
            .expect("hc registered");

        set.routes
            .insert("r1".into(), route_with_upstream_id("r1", "/", "u1"));
        publish_set(&store, &set, 2);
        let gen2 = store
            .health_check_generation("upstream/u1")
            .expect("hc still registered");
        assert_eq!(gen1, gen2);
    }

    #[test]
    fn route_only_update_reuses_upstream_arc_and_keeps_backends_selectable() {
        use crate::proxy::control_plane::ResourceConfigSet;

        let store = RuntimeStore::new();
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.1:80"));
        publish_set(&store, &set, 1);
        let before = store.load().upstreams.get("u1").cloned().unwrap();
        assert!(
            before.select_backend_for_test().is_some(),
            "eager discovery must populate backends before publish"
        );

        set.routes
            .insert("r1".into(), route_with_upstream_id("r1", "/", "u1"));
        publish_set(&store, &set, 2);
        let after = store.load().upstreams.get("u1").cloned().unwrap();
        assert!(
            Arc::ptr_eq(&before, &after),
            "route-only publish must reuse ProxyUpstream Arc so HC stays bound to the live LB"
        );
        assert!(
            after.select_backend_for_test().is_some(),
            "published runtime LB must still select a backend after route-only update"
        );
    }

    #[test]
    fn weight_only_upstream_change_replaces_health_check_generation() {
        use crate::proxy::control_plane::ResourceConfigSet;

        let store = RuntimeStore::new();
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.1:80"));
        publish_set(&store, &set, 1);
        let gen1 = store.health_check_generation("upstream/u1").unwrap();
        let before = store.load().upstreams.get("u1").cloned().unwrap();

        set.upstreams
            .insert("u1".into(), upstream_weighted("u1", &[("10.0.0.1:80", 99)]));
        publish_set(&store, &set, 2);
        let after = store.load().upstreams.get("u1").cloned().unwrap();
        let gen2 = store.health_check_generation("upstream/u1").unwrap();
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(
            before
                .inner
                .fingerprint(config::UpstreamFingerprintProfile::HealthCheck),
            after
                .inner
                .fingerprint(config::UpstreamFingerprintProfile::HealthCheck)
        );
        assert_ne!(
            gen1, gen2,
            "new LB Arc must get its own HC registration even when fingerprint matches"
        );
        assert!(after.select_backend_for_test().is_some());
    }

    #[test]
    fn upstream_node_change_replaces_health_check_generation() {
        use crate::proxy::control_plane::ResourceConfigSet;

        let store = RuntimeStore::new();
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.1:80"));
        publish_set(&store, &set, 1);
        let gen1 = store.health_check_generation("upstream/u1").unwrap();

        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.2:80"));
        publish_set(&store, &set, 2);
        let gen2 = store.health_check_generation("upstream/u1").unwrap();
        assert_ne!(gen1, gen2);
    }
}
