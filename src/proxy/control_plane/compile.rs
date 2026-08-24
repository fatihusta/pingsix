use std::{collections::HashMap, sync::Arc};

use validator::Validate;

use crate::core::{ProxyError, ProxyResult};

use crate::proxy::{
    global_rule::ProxyGlobalRule,
    route::ProxyRoute,
    service::ProxyService,
    ssl::ProxySSL,
    upstream::{PreparedUpstreams, ProxyUpstream, UpstreamOccurrence},
};

#[cfg(test)]
use super::plan::prepare_static_candidate;
use super::plan::CandidatePlan;
use super::resources::{
    plugin_upstream_deps, scope_upstream_deps, scope_upstream_deps_rule, upstream_arc_reused,
    ResourceConfigSet,
};

/// Control-plane-only candidate built from a single version of the resource graph.
pub struct CandidateSnapshot {
    pub upstreams: HashMap<String, Arc<ProxyUpstream>>,
    pub services: HashMap<String, Arc<ProxyService>>,
    pub global_rules: HashMap<String, Arc<ProxyGlobalRule>>,
    pub routes: HashMap<String, Arc<ProxyRoute>>,
    pub ssls: HashMap<String, Arc<ProxySSL>>,
}

impl CandidateSnapshot {
    /// Compile every runtime object from the same raw resource graph against
    /// an empty previous snapshot (no Arc reuse). Tests that need reuse must
    /// call [`Self::build_against`].
    ///
    /// Constructors must never initiate DNS I/O beyond the prepared material.
    #[cfg(test)]
    pub fn build(config: ResourceConfigSet) -> ProxyResult<Self> {
        Self::build_against(config, &crate::proxy::runtime::RuntimeSnapshot::empty())
    }

    /// Compile `config` using `previous` as the Arc-reuse baseline.
    ///
    /// Uses instance-local defaults and a freshly built resolver.
    #[cfg(test)]
    pub fn build_against(
        config: ResourceConfigSet,
        previous: &crate::proxy::runtime::RuntimeSnapshot,
    ) -> ProxyResult<Self> {
        let plan = CandidatePlan::build(&config, previous)?;
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state()?;
        let prepared = prepare_static_candidate(&config, &resolver)?;
        Self::build_prepared(
            config,
            &plan,
            &prepared,
            previous,
            &crate::config::EffectiveDefaults::default(),
            &resolver,
        )
    }

    /// Compile a candidate from the material prepared by the same
    /// [`CandidatePlan`], against an explicitly supplied previous runtime
    /// (Arc reuse baseline). `defaults` supplies the owning gateway
    /// instance's effective `pingsix.defaults`. This method must never
    /// initiate DNS I/O.
    pub(crate) fn build_prepared(
        config: ResourceConfigSet,
        plan: &CandidatePlan,
        prepared: &PreparedUpstreams,
        previous: &crate::proxy::runtime::RuntimeSnapshot,
        defaults: &crate::config::EffectiveDefaults,
        resolver: &Arc<hickory_resolver::TokioResolver>,
    ) -> ProxyResult<Self> {
        for upstream in config.upstreams.values() {
            upstream.validate().map_err(|e| {
                ProxyError::Configuration(format!(
                    "Upstream '{}' validation failed: {e}",
                    upstream.id
                ))
            })?;
        }
        for service in config.services.values() {
            service.validate().map_err(|e| {
                ProxyError::Configuration(format!(
                    "Service '{}' validation failed: {e}",
                    service.id
                ))
            })?;
        }
        for rule in config.global_rules.values() {
            rule.validate().map_err(|e| {
                ProxyError::Configuration(format!(
                    "GlobalRule '{}' validation failed: {e}",
                    rule.id
                ))
            })?;
        }
        for route in config.routes.values() {
            route.validate().map_err(|e| {
                ProxyError::Configuration(format!("Route '{}' validation failed: {e}", route.id))
            })?;
        }
        for ssl in config.ssls.values() {
            ssl.validate().map_err(|e| {
                ProxyError::Configuration(format!("SSL '{}' validation failed: {e}", ssl.id))
            })?;
        }

        let mut upstreams = HashMap::with_capacity(config.upstreams.len());
        for (id, upstream) in config.upstreams {
            log::info!("Configuring upstream: {id}");
            let arc = if plan.upstream_reused(&id) {
                previous.upstreams.get(&id).cloned().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "Upstream '{id}' marked reused but missing from previous runtime"
                    ))
                })?
            } else {
                Arc::new(ProxyUpstream::build(
                    upstream,
                    prepared
                        .get(&UpstreamOccurrence::Named(id.clone()))
                        .cloned()
                        .ok_or_else(|| {
                            ProxyError::Configuration(format!("Upstream '{id}' was not prepared"))
                        })?,
                    defaults,
                    resolver,
                )?)
            };
            upstreams.insert(id, arc);
        }

        let mut services = HashMap::with_capacity(config.services.len());
        for (id, service) in config.services {
            log::info!("Configuring service: {id}");
            // Reuse only when the plan agrees and every named upstream this
            // service references was actually Arc-reused above.
            let arc = if plan.service_reused(&id)
                && scope_upstream_deps(&service)?
                    .iter()
                    .all(|dep| upstream_arc_reused(dep, &upstreams, previous))
            {
                previous.services.get(&id).cloned().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "Service '{id}' marked reused but missing from previous runtime"
                    ))
                })?
            } else {
                Arc::new(ProxyService::build(
                    service, &upstreams, prepared, defaults, resolver,
                )?)
            };
            services.insert(id, arc);
        }

        let mut global_rules = HashMap::with_capacity(config.global_rules.len());
        for (id, rule) in config.global_rules {
            log::info!("Configuring global rule: {id}");
            let arc = if plan.global_rule_reused(&id)
                && plugin_upstream_deps(&rule.plugins)?
                    .iter()
                    .all(|dep| upstream_arc_reused(dep, &upstreams, previous))
            {
                previous.global_rules.get(&id).cloned().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "Global rule '{id}' marked reused but missing from previous runtime"
                    ))
                })?
            } else {
                Arc::new(ProxyGlobalRule::build(
                    rule, &upstreams, prepared, defaults, resolver,
                )?)
            };
            global_rules.insert(id, arc);
        }

        let mut routes = HashMap::with_capacity(config.routes.len());
        for (id, route) in config.routes {
            log::info!("Configuring route: {id}");
            // A route is only reusable when the service it binds to was itself
            // Arc-reused and every named upstream it references was Arc-reused
            // above; unlike the former all-services cascade this is checked
            // per route against just its own `service_id` and upstream deps.
            let service_reused = route.service_id.as_ref().is_none_or(|sid| {
                services
                    .get(sid)
                    .zip(previous.services.get(sid))
                    .is_some_and(|(a, b)| Arc::ptr_eq(a, b))
            });
            let arc = if plan.route_reused(&id)
                && service_reused
                && scope_upstream_deps_rule(&route)?
                    .iter()
                    .all(|dep| upstream_arc_reused(dep, &upstreams, previous))
            {
                previous.routes.get(&id).cloned().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "Route '{id}' marked reused but missing from previous runtime"
                    ))
                })?
            } else {
                Arc::new(ProxyRoute::build(
                    route, &upstreams, &services, prepared, defaults, resolver,
                )?)
            };
            routes.insert(id, arc);
        }

        let mut ssls = HashMap::with_capacity(config.ssls.len());
        for (id, ssl) in config.ssls {
            log::info!("Configuring ssl: {id}");
            let arc = if plan.ssl_reused(&id) {
                previous.ssls.get(&id).cloned().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "SSL '{id}' marked reused but missing from previous runtime"
                    ))
                })?
            } else {
                Arc::new(ProxySSL::try_from(ssl)?)
            };
            ssls.insert(id, arc);
        }

        Ok(Self {
            upstreams,
            services,
            global_rules,
            routes,
            ssls,
        })
    }
}

/// Behavior-level invalidation contracts (Task 4): the published snapshot must
/// reuse exactly the scopes whose real dependencies are unchanged, verified
/// through the same plan preparation and compilation both consume.
#[cfg(test)]
mod dependency_invalidation {
    use super::*;
    use crate::config::{
        GlobalRule, Nodes, Route, SelectionType, Service, Upstream, UpstreamHashOn,
        UpstreamPassHost, UpstreamScheme,
    };
    use crate::proxy::runtime::RuntimeSnapshot;
    use std::collections::HashMap as StdHashMap;

    fn sample_upstream(id: &str, node: &str) -> Upstream {
        let mut nodes = StdHashMap::new();
        nodes.insert(node.to_string(), 1);
        Upstream {
            id: id.to_string(),
            retries: None,
            retry_timeout: None,
            timeout: None,
            nodes: Nodes::from_map(nodes),
            r#type: SelectionType::RoundRobin,
            checks: None,
            hash_on: UpstreamHashOn::VARS,
            key: "uri".into(),
            scheme: UpstreamScheme::HTTP,
            pass_host: UpstreamPassHost::PASS,
            upstream_host: None,
            tls: None,
            keepalive_pool: None,
        }
    }

    fn service_with_upstream_id(id: &str, upstream_id: &str) -> Service {
        Service {
            id: id.into(),
            name: None,
            plugins: Default::default(),
            upstream: None,
            upstream_id: Some(upstream_id.into()),
            hosts: vec![],
        }
    }

    fn route_with_upstream_id(id: &str, uri: &str, upstream_id: &str) -> Route {
        Route {
            id: id.into(),
            name: None,
            uri: Some(uri.into()),
            uris: vec![],
            methods: vec![],
            host: None,
            hosts: vec![],
            priority: 0,
            plugins: Default::default(),
            upstream: None,
            upstream_id: Some(upstream_id.into()),
            service_id: None,
            timeout: None,
            enable_websocket: false,
        }
    }

    fn route_with_inline(id: &str, uri: &str, node: &str) -> Route {
        Route {
            id: id.into(),
            name: None,
            uri: Some(uri.into()),
            uris: vec![],
            methods: vec![],
            host: None,
            hosts: vec![],
            priority: 0,
            plugins: Default::default(),
            upstream: Some(sample_upstream("", node)),
            upstream_id: None,
            service_id: None,
            timeout: None,
            enable_websocket: false,
        }
    }

    fn route_bound_to_service(id: &str, uri: &str, service_id: &str) -> Route {
        Route {
            id: id.into(),
            name: None,
            uri: Some(uri.into()),
            uris: vec![],
            methods: vec![],
            host: None,
            hosts: vec![],
            priority: 0,
            plugins: Default::default(),
            upstream: None,
            upstream_id: None,
            service_id: Some(service_id.into()),
            timeout: None,
            enable_websocket: false,
        }
    }

    /// Compile a snapshot from an empty previous runtime (no Arc reuse).
    fn publish_seed(set: &ResourceConfigSet, revision: i64) -> Arc<RuntimeSnapshot> {
        let snapshot =
            RuntimeSnapshot::compile(CandidateSnapshot::build(set.clone()).unwrap(), revision)
                .unwrap();
        Arc::new(snapshot)
    }

    /// Compile `next` against `previous` through one plan, preparing exactly
    /// the planned jobs (static path; nodes are plain IPs). Mirrors what the
    /// graph authority does for an async update, minus the DNS I/O.
    fn compile_next(
        next: &ResourceConfigSet,
        previous: &RuntimeSnapshot,
        revision: i64,
    ) -> (CandidatePlan, Arc<RuntimeSnapshot>) {
        let plan = CandidatePlan::build(next, previous).unwrap();
        let mut prepared = PreparedUpstreams::new();
        for (occurrence, upstream) in &plan.jobs {
            prepared.insert(
                occurrence.clone(),
                crate::proxy::upstream::discovery::prepare_static_upstream(
                    upstream,
                    &crate::proxy::upstream::discovery::build_resolver_for_state().unwrap(),
                )
                .unwrap(),
            );
        }
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let candidate = CandidateSnapshot::build_prepared(
            next.clone(),
            &plan,
            &prepared,
            previous,
            &crate::config::EffectiveDefaults::default(),
            &resolver,
        )
        .expect("plan-guided compilation must succeed");
        let snapshot = RuntimeSnapshot::compile(candidate, revision).unwrap();
        (plan, Arc::new(snapshot))
    }

    /// Changing `u1` must not rebuild a service that only references `u2`;
    /// routes bound to the reused service stay reused too.
    #[test]
    fn changing_u1_does_not_rebuild_service_that_only_references_u2() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
        set.upstreams
            .insert("u2".into(), sample_upstream("u2", "127.0.0.1:81"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u2"));
        set.services
            .insert("s2".into(), service_with_upstream_id("s2", "u1"));
        set.routes
            .insert("r1".into(), route_bound_to_service("r1", "/a", "s1"));
        set.routes
            .insert("r2".into(), route_bound_to_service("r2", "/b", "s2"));
        let previous = publish_seed(&set, 1000);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
        let (plan, compiled) = compile_next(&next, &previous, 1001);

        assert!(!plan.upstream_reused("u1"));
        assert!(plan.upstream_reused("u2"));
        assert!(
            plan.service_reused("s1"),
            "s1 only references u2 and must be reused"
        );
        assert!(!plan.service_reused("s2"));
        assert!(Arc::ptr_eq(
            previous.services.get("s1").unwrap(),
            compiled.services.get("s1").unwrap()
        ));
        assert!(!Arc::ptr_eq(
            previous.services.get("s2").unwrap(),
            compiled.services.get("s2").unwrap()
        ));
        // r1 binds the reused s1 and follows it; r2 binds the rebuilt s2.
        assert!(Arc::ptr_eq(
            previous.routes.get("r1").unwrap(),
            compiled.routes.get("r1").unwrap()
        ));
        assert!(!Arc::ptr_eq(
            previous.routes.get("r2").unwrap(),
            compiled.routes.get("r2").unwrap()
        ));
    }

    /// A route that names upstream `u1` must be recompiled when `u1`'s Arc is
    /// rebuilt, even if an unrelated `u2` route stays reused.
    #[test]
    fn route_rebuilt_when_referenced_named_upstream_arc_rebuilt() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
        set.upstreams
            .insert("u2".into(), sample_upstream("u2", "127.0.0.1:81"));
        set.routes
            .insert("r1".into(), route_with_upstream_id("r1", "/a", "u1"));
        set.routes
            .insert("r2".into(), route_with_upstream_id("r2", "/b", "u2"));
        let previous = publish_seed(&set, 1050);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
        let (plan, compiled) = compile_next(&next, &previous, 1051);

        assert!(!plan.upstream_reused("u1"));
        assert!(plan.upstream_reused("u2"));
        assert!(!plan.route_reused("r1"));
        assert!(plan.route_reused("r2"));
        assert!(!Arc::ptr_eq(
            previous.upstreams.get("u1").unwrap(),
            compiled.upstreams.get("u1").unwrap()
        ));
        assert!(Arc::ptr_eq(
            previous.upstreams.get("u2").unwrap(),
            compiled.upstreams.get("u2").unwrap()
        ));
        assert!(!Arc::ptr_eq(
            previous.routes.get("r1").unwrap(),
            compiled.routes.get("r1").unwrap()
        ));
        assert!(Arc::ptr_eq(
            previous.routes.get("r2").unwrap(),
            compiled.routes.get("r2").unwrap()
        ));
    }

    /// Changing an upstream that no service references must not rebuild all
    /// routes: only routes that reference it are rebuilt.
    #[test]
    fn changing_upstream_not_referenced_by_services_does_not_rebuild_all_routes() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
        set.upstreams
            .insert("u2".into(), sample_upstream("u2", "127.0.0.1:81"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u2"));
        set.routes
            .insert("r1".into(), route_with_upstream_id("r1", "/a", "u1"));
        set.routes
            .insert("r2".into(), route_with_inline("r2", "/b", "127.0.0.1:82"));
        set.routes
            .insert("r3".into(), route_bound_to_service("r3", "/c", "s1"));
        let previous = publish_seed(&set, 1100);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
        let (plan, compiled) = compile_next(&next, &previous, 1101);

        assert!(!plan.route_reused("r1"));
        assert!(plan.route_reused("r2"));
        assert!(plan.route_reused("r3"));
        assert!(plan.service_reused("s1"));
        assert!(!Arc::ptr_eq(
            previous.routes.get("r1").unwrap(),
            compiled.routes.get("r1").unwrap()
        ));
        assert!(Arc::ptr_eq(
            previous.routes.get("r2").unwrap(),
            compiled.routes.get("r2").unwrap()
        ));
        assert!(Arc::ptr_eq(
            previous.routes.get("r3").unwrap(),
            compiled.routes.get("r3").unwrap()
        ));
    }

    /// An unrelated inline occurrence must not block a named upstream's
    /// independent update: the plan never schedules the untouched occurrence,
    /// so compilation and publication never touch it. DNS failure injection is
    /// covered at the resolver/discovery boundary; this test locks the plan's
    /// observable publication behavior without relying on external DNS.
    #[test]
    fn unrelated_inline_occurrence_does_not_block_named_upstream_update() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        set.routes
            .insert("r1".into(), route_with_inline("r1", "/a", "127.0.0.1:81"));
        let previous = publish_seed(&set, 1400);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
        let (plan, compiled) = compile_next(&next, &previous, 1401);

        assert_eq!(plan.jobs.len(), 1, "only u1 may need preparation");
        assert!(matches!(
            &plan.jobs[0].0,
            UpstreamOccurrence::Named(id) if id == "u1"
        ));
        // The published snapshot reuses the untouched route wholesale, so its
        // inline occurrence never enters this update.
        assert!(Arc::ptr_eq(
            previous.routes.get("r1").unwrap(),
            compiled.routes.get("r1").unwrap()
        ));
        assert!(!Arc::ptr_eq(
            previous.upstreams.get("u1").unwrap(),
            compiled.upstreams.get("u1").unwrap()
        ));
    }

    /// A global rule with no named-upstream dependency remains reused when an
    /// otherwise unrelated named upstream changes.
    #[test]
    fn changing_unrelated_upstream_does_not_rebuild_global_rule() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
        set.global_rules.insert(
            "g1".into(),
            GlobalRule {
                id: "g1".into(),
                plugins: Default::default(),
            },
        );
        let previous = publish_seed(&set, 1150);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
        let (plan, compiled) = compile_next(&next, &previous, 1151);

        assert!(plan.global_rule_reused("g1"));
        assert!(Arc::ptr_eq(
            previous.global_rules.get("g1").unwrap(),
            compiled.global_rules.get("g1").unwrap()
        ));
    }

    /// Deleting a named upstream invalidates only its real dependents: a
    /// service that references it loses reuse even though its own config is
    /// unchanged, while services referencing other upstreams are untouched.
    #[test]
    fn deleting_upstream_only_invalidates_its_real_dependents() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
        set.upstreams
            .insert("u2".into(), sample_upstream("u2", "127.0.0.1:81"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        set.services
            .insert("s2".into(), service_with_upstream_id("s2", "u2"));
        let previous = publish_seed(&set, 1200);

        // s2 still references the deleted u2 (an invalid graph, rejected by
        // validation before it ever reaches the plan), so this asserts the
        // plan-level invalidation: only s2 loses reuse.
        let mut next = set;
        next.upstreams.remove("u2");
        let plan = CandidatePlan::build(&next, &previous).unwrap();
        assert!(plan.service_reused("s1"));
        assert!(
            !plan.service_reused("s2"),
            "s2 depends on the deleted u2 and must be invalidated"
        );
    }

    /// Deleting an upstream nobody references must not disturb the dependents
    /// of the remaining upstreams: compilation keeps reusing them.
    #[test]
    fn deleting_unreferenced_upstream_keeps_real_dependents_reused() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
        set.upstreams
            .insert("u2".into(), sample_upstream("u2", "127.0.0.1:81"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        set.routes
            .insert("r1".into(), route_bound_to_service("r1", "/a", "s1"));
        let previous = publish_seed(&set, 1300);

        let mut next = set;
        next.upstreams.remove("u2");
        let (plan, compiled) = compile_next(&next, &previous, 1301);

        assert!(plan.service_reused("s1"));
        assert!(plan.route_reused("r1"));
        assert!(Arc::ptr_eq(
            previous.services.get("s1").unwrap(),
            compiled.services.get("s1").unwrap()
        ));
        assert!(Arc::ptr_eq(
            previous.routes.get("r1").unwrap(),
            compiled.routes.get("r1").unwrap()
        ));
    }
}
