use std::{collections::HashMap, sync::Arc};

use crate::core::{ProxyError, ProxyResult};

use crate::proxy::{
    global_rule::ProxyGlobalRule,
    route::ProxyRoute,
    service::ProxyService,
    ssl::ProxySSL,
    upstream::{PreparedUpstreams, ProxyUpstream, UpstreamOccurrence},
};

#[cfg(test)]
use super::plan::prepare_candidate_static;
use super::plan::{CandidatePlan, ResourceDecision};
use super::resources::{validate_runtime_form, ResourceConfigSet};

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
    /// Runs the production plan → prepare → compile pipeline with DNS switched
    /// off ([`prepare_candidate_static`]): fixtures must use IP-literal nodes.
    /// Uses instance-local defaults and a freshly built resolver.
    #[cfg(test)]
    pub fn build_against(
        config: ResourceConfigSet,
        previous: &crate::proxy::runtime::RuntimeSnapshot,
    ) -> ProxyResult<Self> {
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state()?;
        let (plan, prepared) = prepare_candidate_static(&config, previous, &resolver)?;
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
    /// [`CandidatePlan`]. The previous runtime is the Arc-reuse baseline the
    /// plan was computed against — its reusable objects are already carried
    /// by the plan's decisions, so `_previous` is not consulted again here.
    /// `defaults` supplies the owning gateway instance's effective
    /// `pingsix.defaults`. This method must never initiate DNS I/O.
    pub(crate) fn build_prepared(
        config: ResourceConfigSet,
        plan: &CandidatePlan,
        prepared: &PreparedUpstreams,
        _previous: &crate::proxy::runtime::RuntimeSnapshot,
        defaults: &crate::config::EffectiveDefaults,
        resolver: &Arc<hickory_resolver::TokioResolver>,
    ) -> ProxyResult<Self> {
        // Defense-in-depth gate: in production the graph authority already
        // validated this candidate (runtime form, secrets decrypted) before
        // submission; this call shares the exact gate body
        // (`validate_runtime_form`) so the checks cannot diverge. The gate is
        // accept/reject-neutral for every candidate the authority admits.
        validate_runtime_form(&config)?;

        // Every pass below consumes the plan's typed per-resource decisions
        // mechanically. The decisions already encode "own config unchanged and
        // every referenced dependency kept its Arc", and because the passes run
        // in dependency order (upstreams → services/global rules → routes)
        // applying exactly those decisions, Arc identity for transitive
        // dependents follows by construction: no second dependency derivation
        // (`scope_upstream_deps*_` re-walks) and no Arc-pointer re-checks
        // remain here.

        let mut upstreams = HashMap::with_capacity(config.upstreams.len());
        for (id, upstream) in config.upstreams {
            log::info!("Configuring upstream: {id}");
            let arc = match plan.upstream_decision(&id) {
                ResourceDecision::Reuse(existing) => existing,
                ResourceDecision::Rebuild => Arc::new(ProxyUpstream::build(
                    upstream,
                    prepared
                        .get(&UpstreamOccurrence::Named(id.clone()))
                        .cloned()
                        .ok_or_else(|| {
                            ProxyError::Configuration(format!("Upstream '{id}' was not prepared"))
                        })?,
                    defaults,
                    resolver,
                )?),
            };
            upstreams.insert(id, arc);
        }

        let mut services = HashMap::with_capacity(config.services.len());
        for (id, service) in config.services {
            log::info!("Configuring service: {id}");
            let arc = match plan.service_decision(&id) {
                ResourceDecision::Reuse(existing) => existing,
                ResourceDecision::Rebuild => Arc::new(ProxyService::build(
                    service, &upstreams, prepared, defaults, resolver,
                )?),
            };
            services.insert(id, arc);
        }

        let mut global_rules = HashMap::with_capacity(config.global_rules.len());
        for (id, rule) in config.global_rules {
            log::info!("Configuring global rule: {id}");
            let arc = match plan.global_rule_decision(&id) {
                ResourceDecision::Reuse(existing) => existing,
                ResourceDecision::Rebuild => Arc::new(ProxyGlobalRule::build(
                    rule, &upstreams, prepared, defaults, resolver,
                )?),
            };
            global_rules.insert(id, arc);
        }

        let mut routes = HashMap::with_capacity(config.routes.len());
        for (id, route) in config.routes {
            log::info!("Configuring route: {id}");
            // The plan's route decision already encodes that the service this
            // route binds to was itself reused and that every named upstream
            // the route references was reused, so no per-route service Arc or
            // dependency re-check is needed here.
            let arc = match plan.route_decision(&id) {
                ResourceDecision::Reuse(existing) => existing,
                ResourceDecision::Rebuild => Arc::new(ProxyRoute::build(
                    route, &upstreams, &services, prepared, defaults, resolver,
                )?),
            };
            routes.insert(id, arc);
        }

        let mut ssls = HashMap::with_capacity(config.ssls.len());
        for (id, ssl) in config.ssls {
            log::info!("Configuring ssl: {id}");
            let arc = match plan.ssl_decision(&id) {
                ResourceDecision::Reuse(existing) => existing,
                ResourceDecision::Rebuild => Arc::new(ProxySSL::try_from(ssl)?),
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
/// through the same production plan → prepare → compile pipeline that the
/// graph authority drives (with DNS switched off: fixtures use IP literals).
/// Assertions live at the publish boundary (Arc identity), not on plan
/// internals; the plan's own module pins job/reuse decisions.
#[cfg(test)]
mod dependency_invalidation {
    use super::*;
    use crate::proxy::control_plane::test_fixtures::{
        global_rule, route_bound_to_service, route_with_inline, route_with_upstream_id,
        service_with_upstream_id, upstream,
    };
    use crate::proxy::runtime::RuntimeSnapshot;

    /// Compile a snapshot from an empty previous runtime (no Arc reuse).
    fn publish_seed(set: &ResourceConfigSet, revision: i64) -> Arc<RuntimeSnapshot> {
        let snapshot =
            RuntimeSnapshot::compile(CandidateSnapshot::build(set.clone()).unwrap(), revision)
                .unwrap();
        Arc::new(snapshot)
    }

    /// Compile `next` against `previous` through the production
    /// control-plane pipeline: plan build → occurrence preparation →
    /// plan-guided compile → snapshot publication, with DNS switched off.
    fn compile_next(
        next: &ResourceConfigSet,
        previous: &RuntimeSnapshot,
        revision: i64,
    ) -> Arc<RuntimeSnapshot> {
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let (plan, prepared) = prepare_candidate_static(next, previous, &resolver).unwrap();
        let candidate = CandidateSnapshot::build_prepared(
            next.clone(),
            &plan,
            &prepared,
            previous,
            &crate::config::EffectiveDefaults::default(),
            &resolver,
        )
        .expect("plan-guided compilation must succeed");
        Arc::new(RuntimeSnapshot::compile(candidate, revision).unwrap())
    }

    /// Changing `u1` must not rebuild a service that only references `u2`;
    /// routes bound to the reused service stay reused too.
    #[test]
    fn changing_u1_does_not_rebuild_service_that_only_references_u2() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        set.upstreams
            .insert("u2".into(), upstream("u2", "127.0.0.1:81"));
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
            .insert("u1".into(), upstream("u1", "127.0.0.1:90"));
        let compiled = compile_next(&next, &previous, 1001);

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
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        set.upstreams
            .insert("u2".into(), upstream("u2", "127.0.0.1:81"));
        set.routes
            .insert("r1".into(), route_with_upstream_id("r1", "/a", "u1"));
        set.routes
            .insert("r2".into(), route_with_upstream_id("r2", "/b", "u2"));
        let previous = publish_seed(&set, 1050);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:90"));
        let compiled = compile_next(&next, &previous, 1051);

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
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        set.upstreams
            .insert("u2".into(), upstream("u2", "127.0.0.1:81"));
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
            .insert("u1".into(), upstream("u1", "127.0.0.1:90"));
        let compiled = compile_next(&next, &previous, 1101);

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
    ///
    /// The plan-level job set this relies on (only `Named("u1")` prepared) is
    /// pinned in `plan::tests::preparation_jobs_only_affect_scopes_referencing_the_changed_upstream`.
    #[test]
    fn unrelated_inline_occurrence_does_not_block_named_upstream_update() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        set.routes
            .insert("r1".into(), route_with_inline("r1", "/a", "127.0.0.1:81"));
        let previous = publish_seed(&set, 1400);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:90"));
        let compiled = compile_next(&next, &previous, 1401);

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
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        set.global_rules.insert("g1".into(), global_rule("g1"));
        let previous = publish_seed(&set, 1150);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:90"));
        let compiled = compile_next(&next, &previous, 1151);

        assert!(Arc::ptr_eq(
            previous.global_rules.get("g1").unwrap(),
            compiled.global_rules.get("g1").unwrap()
        ));
    }

    /// Deleting a named upstream invalidates only its real dependents: a
    /// service that references it loses reuse even though its own config is
    /// unchanged, while services referencing other upstreams are untouched.
    ///
    /// This candidate is an invalid graph (rejected by the validation gate
    /// before it ever reaches the plan in production), so it is asserted at
    /// the plan level only — compilation of such a graph is never attempted.
    #[test]
    fn deleting_upstream_only_invalidates_its_real_dependents() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        set.upstreams
            .insert("u2".into(), upstream("u2", "127.0.0.1:81"));
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
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        set.upstreams
            .insert("u2".into(), upstream("u2", "127.0.0.1:81"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        set.routes
            .insert("r1".into(), route_bound_to_service("r1", "/a", "s1"));
        let previous = publish_seed(&set, 1300);

        let mut next = set;
        next.upstreams.remove("u2");
        let compiled = compile_next(&next, &previous, 1301);

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
