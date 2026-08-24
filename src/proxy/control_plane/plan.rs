use std::{collections::HashMap, sync::Arc};

use futures::{stream, StreamExt, TryStreamExt};

use crate::{
    config,
    core::{ProxyError, ProxyResult},
    proxy::{
        global_rule::ProxyGlobalRule,
        route::ProxyRoute,
        service::ProxyService,
        ssl::ProxySSL,
        upstream::{
            discovery::prepare_upstream, PreparedUpstreams, ProxyUpstream, TrafficSplitOwner,
            UpstreamOccurrence,
        },
    },
};

#[cfg(test)]
use crate::proxy::upstream::discovery::prepare_static_upstream;

use super::resources::{
    plugin_upstream_deps, scope_upstream_deps, scope_upstream_deps_rule, ResourceConfigSet,
};

/// A per-resource compile decision produced by the plan.
///
/// The compiler consumes these mechanically: `Reuse` carries the previously
/// compiled object (the same `Arc`), `Rebuild` means "construct from
/// candidate inputs". Decisions are computed once in [`CandidatePlan::build`]
/// from `(config, previous)`; the compiler never re-derives them.
#[derive(Clone, Debug)]
pub(crate) enum ResourceDecision<T> {
    /// Reuse the previously compiled object, Arc-identical.
    Reuse(T),
    /// The plan proved reuse unsound (own config changed, or a referenced
    /// dependency is itself rebuilt): compile from candidate inputs.
    Rebuild,
}

impl<T> ResourceDecision<T> {
    /// True for `Reuse`.
    #[cfg(test)]
    pub(crate) fn is_reuse(&self) -> bool {
        matches!(self, Self::Reuse(_))
    }
}

/// One authoritative reuse/preparation plan for a candidate graph.
///
/// Computed once from `(config, previous)` and consumed by both stages that
/// previously mirrored the same dependency chain: upstream preparation (which
/// occurrences need DNS work) and candidate compilation (which compiled
/// objects are Arc-reused). Keeping both stages on one plan removes the former
/// lockstep requirement between `preparation_jobs` and
/// [`super::compile::CandidateSnapshot::build_prepared`].
///
/// Reuse chain (single source of truth):
/// - a named upstream is reused when its compiled `ProxyUpstream` matches;
/// - a service/global rule/route is reused when its own config matches **and**
///   every named upstream it actually references (direct `upstream_id` plus
///   plugin refs) is reused;
/// - a route additionally requires the service its `service_id` points at to
///   be reused (not all services);
/// - SSL entries reuse independently;
/// - inline and traffic-split upstreams of a reused scope need no preparation.
pub(crate) struct CandidatePlan {
    /// Reusable previously-compiled upstreams (cloned `Arc`s), keyed by id.
    /// Absence means "rebuild".
    reused_upstreams: HashMap<String, Arc<ProxyUpstream>>,
    reused_services: HashMap<String, Arc<ProxyService>>,
    reused_global_rules: HashMap<String, Arc<ProxyGlobalRule>>,
    reused_routes: HashMap<String, Arc<ProxyRoute>>,
    reused_ssls: HashMap<String, Arc<ProxySSL>>,
    /// Upstream occurrences that must be (re)prepared because their owning
    /// scope will be rebuilt. Exactly the material `build_prepared` needs.
    pub(crate) jobs: Vec<(UpstreamOccurrence, config::Upstream)>,
}

impl CandidatePlan {
    /// Compute the reuse decisions and preparation jobs for a candidate.
    ///
    /// Jobs are derived from the same reuse decisions the compiler consumes,
    /// so an unrelated config update never re-resolves unchanged inline DNS
    /// and a transient DNS failure on an untouched occurrence cannot block
    /// publication.
    pub(crate) fn build(
        config: &ResourceConfigSet,
        previous: &crate::proxy::runtime::RuntimeSnapshot,
    ) -> ProxyResult<Self> {
        let mut reused_upstreams = HashMap::new();
        for (id, upstream) in &config.upstreams {
            if let Some(existing) = previous
                .upstreams
                .get(id)
                .filter(|existing| existing.inner == *upstream)
            {
                reused_upstreams.insert(id.clone(), existing.clone());
            }
        }

        // A scope is reused only when its own config matches and every named
        // upstream it actually references is reused; a changed upstream no
        // longer cascades to scopes that never referenced it. Evaluation order
        // (config match first, dependency derivation only for unchanged
        // configs) is preserved from the pre-consolidation build.
        let mut reused_services = HashMap::new();
        for (id, service) in &config.services {
            if let Some(existing) = previous.services.get(id) {
                if existing.inner == *service
                    && scope_upstream_deps(service)?
                        .iter()
                        .all(|dep| reused_upstreams.contains_key(dep))
                {
                    reused_services.insert(id.clone(), existing.clone());
                }
            }
        }
        let mut reused_global_rules = HashMap::new();
        for (id, rule) in &config.global_rules {
            if let Some(existing) = previous.global_rules.get(id) {
                if existing.inner == *rule
                    && plugin_upstream_deps(&rule.plugins)?
                        .iter()
                        .all(|dep| reused_upstreams.contains_key(dep))
                {
                    reused_global_rules.insert(id.clone(), existing.clone());
                }
            }
        }

        let mut reused_routes = HashMap::new();
        for (id, route) in &config.routes {
            // A route additionally requires the service its `service_id`
            // points at to be reused (not all services).
            let service_ok = route
                .service_id
                .as_ref()
                .is_none_or(|sid| reused_services.contains_key(sid));
            if service_ok {
                if let Some(existing) = previous.routes.get(id) {
                    if existing.inner == *route
                        && scope_upstream_deps_rule(route)?
                            .iter()
                            .all(|dep| reused_upstreams.contains_key(dep))
                    {
                        reused_routes.insert(id.clone(), existing.clone());
                    }
                }
            }
        }
        let mut reused_ssls = HashMap::new();
        for (id, ssl) in &config.ssls {
            if let Some(existing) = previous
                .ssls
                .get(id)
                .filter(|existing| existing.inner == *ssl)
            {
                reused_ssls.insert(id.clone(), existing.clone());
            }
        }

        // Preparation jobs: every occurrence owned by a scope that will be rebuilt.
        let mut jobs = Vec::new();
        for (id, upstream) in &config.upstreams {
            if !reused_upstreams.contains_key(id) {
                jobs.push((UpstreamOccurrence::Named(id.clone()), upstream.clone()));
            }
        }
        for (id, service) in &config.services {
            if !reused_services.contains_key(id) {
                if let Some(upstream) = &service.upstream {
                    jobs.push((
                        UpstreamOccurrence::ServiceInline(id.clone()),
                        upstream.clone(),
                    ));
                }
                jobs.extend(crate::plugins::plugin_upstream_jobs(
                    TrafficSplitOwner::Service(id.clone()),
                    &service.plugins,
                )?);
            }
        }
        for (id, rule) in &config.global_rules {
            if !reused_global_rules.contains_key(id) {
                jobs.extend(crate::plugins::plugin_upstream_jobs(
                    TrafficSplitOwner::GlobalRule(id.clone()),
                    &rule.plugins,
                )?);
            }
        }
        for (id, route) in &config.routes {
            if !reused_routes.contains_key(id) {
                if let Some(upstream) = &route.upstream {
                    jobs.push((
                        UpstreamOccurrence::RouteInline(id.clone()),
                        upstream.clone(),
                    ));
                }
                jobs.extend(crate::plugins::plugin_upstream_jobs(
                    TrafficSplitOwner::Route(id.clone()),
                    &route.plugins,
                )?);
            }
        }

        Ok(Self {
            reused_upstreams,
            reused_services,
            reused_global_rules,
            reused_routes,
            reused_ssls,
            jobs,
        })
    }

    /// Typed decision for `id`, consumed mechanically by the compiler.
    pub(crate) fn upstream_decision(&self, id: &str) -> ResourceDecision<Arc<ProxyUpstream>> {
        match self.reused_upstreams.get(id) {
            Some(existing) => ResourceDecision::Reuse(existing.clone()),
            None => ResourceDecision::Rebuild,
        }
    }

    pub(crate) fn service_decision(&self, id: &str) -> ResourceDecision<Arc<ProxyService>> {
        match self.reused_services.get(id) {
            Some(existing) => ResourceDecision::Reuse(existing.clone()),
            None => ResourceDecision::Rebuild,
        }
    }

    pub(crate) fn global_rule_decision(&self, id: &str) -> ResourceDecision<Arc<ProxyGlobalRule>> {
        match self.reused_global_rules.get(id) {
            Some(existing) => ResourceDecision::Reuse(existing.clone()),
            None => ResourceDecision::Rebuild,
        }
    }

    pub(crate) fn route_decision(&self, id: &str) -> ResourceDecision<Arc<ProxyRoute>> {
        match self.reused_routes.get(id) {
            Some(existing) => ResourceDecision::Reuse(existing.clone()),
            None => ResourceDecision::Rebuild,
        }
    }

    pub(crate) fn ssl_decision(&self, id: &str) -> ResourceDecision<Arc<ProxySSL>> {
        match self.reused_ssls.get(id) {
            Some(existing) => ResourceDecision::Reuse(existing.clone()),
            None => ResourceDecision::Rebuild,
        }
    }

    #[cfg(test)]
    pub(crate) fn upstream_reused(&self, id: &str) -> bool {
        self.upstream_decision(id).is_reuse()
    }

    #[cfg(test)]
    pub(crate) fn service_reused(&self, id: &str) -> bool {
        self.service_decision(id).is_reuse()
    }

    #[cfg(test)]
    pub(crate) fn route_reused(&self, id: &str) -> bool {
        self.route_decision(id).is_reuse()
    }
}

/// DNS strategy used to prepare the plan's occurrences.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DnsPreparation {
    /// Production path: resolve hostname nodes asynchronously with the
    /// configured `dns_resolution_timeout`.
    Resolve,
    /// No DNS I/O: only IP-literal nodes are accepted; hostname nodes fail
    /// with the static-discovery error. Test path.
    #[cfg(test)]
    StaticOnly,
}

/// Shared core: build the plan, then prepare exactly the plan's jobs.
///
/// This is the *only* occurrence walk in the control plane; the DNS strategy
/// is the single difference between the production and DNS-off (test) paths.
async fn prepare_candidate_mode(
    config: &ResourceConfigSet,
    previous: &crate::proxy::runtime::RuntimeSnapshot,
    defaults: &config::EffectiveDefaults,
    resolver: &Arc<hickory_resolver::TokioResolver>,
    dns: DnsPreparation,
) -> ProxyResult<(CandidatePlan, PreparedUpstreams)> {
    let plan = CandidatePlan::build(config, previous)?;
    let prepared = stream::iter(plan.jobs.clone())
        .map(|(occurrence, upstream)| async move {
            let prepared = match dns {
                DnsPreparation::Resolve => prepare_upstream(&upstream, defaults, resolver).await?,
                #[cfg(test)]
                DnsPreparation::StaticOnly => prepare_static_upstream(&upstream, resolver)?,
            };
            Ok::<_, ProxyError>((occurrence, prepared))
        })
        .buffer_unordered(8)
        .try_collect::<Vec<_>>()
        .await?;
    Ok((plan, prepared.into_iter().collect()))
}

/// Prepare every upstream occurrence the candidate plan marks for rebuild.
///
/// Returns the plan together with the prepared material so the caller can
/// hand the *same* plan to [`super::compile::CandidateSnapshot::build_prepared`]; compilation
/// never re-derives reuse decisions.
pub(crate) async fn prepare_candidate(
    config: &ResourceConfigSet,
    previous: &crate::proxy::runtime::RuntimeSnapshot,
    defaults: &crate::config::EffectiveDefaults,
    resolver: &Arc<hickory_resolver::TokioResolver>,
) -> ProxyResult<(CandidatePlan, PreparedUpstreams)> {
    prepare_candidate_mode(
        config,
        previous,
        defaults,
        resolver,
        DnsPreparation::Resolve,
    )
    .await
}

/// DNS-off variant of [`prepare_candidate`]: the identical plan build and
/// occurrence dispatch, with every job resolved through the static
/// (IP-literal-only) path instead of asynchronous DNS. Tests therefore
/// exercise the production plan → prepare → compile pipeline end to end.
#[cfg(test)]
pub(crate) fn prepare_candidate_static(
    config: &ResourceConfigSet,
    previous: &crate::proxy::runtime::RuntimeSnapshot,
    resolver: &Arc<hickory_resolver::TokioResolver>,
) -> ProxyResult<(CandidatePlan, PreparedUpstreams)> {
    // `StaticOnly` never awaits real I/O, so the core completes on first poll.
    futures::executor::block_on(prepare_candidate_mode(
        config,
        previous,
        &config::EffectiveDefaults::default(),
        resolver,
        DnsPreparation::StaticOnly,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Upstream;
    use crate::proxy::control_plane::test_fixtures::{
        route_bound_to_service, route_with_inline, route_with_upstream_id, service_with_inline,
        service_with_upstream_id, traffic_split_with_named_and_inline, upstream,
    };
    use crate::proxy::control_plane::CandidateSnapshot;

    // ---------------------------------------------------------------------
    // Preparation jobs: derived from the same plan compilation consumes, so
    // an unchanged occurrence is never re-resolved.
    // ---------------------------------------------------------------------

    /// Compile a snapshot from an empty previous runtime (no Arc reuse).
    fn publish_seed(
        set: &ResourceConfigSet,
        revision: i64,
    ) -> Arc<crate::proxy::runtime::RuntimeSnapshot> {
        use crate::proxy::runtime::RuntimeSnapshot;
        let snapshot =
            RuntimeSnapshot::compile(CandidateSnapshot::build(set.clone()).unwrap(), revision)
                .unwrap();
        Arc::new(snapshot)
    }

    fn job_occurrences(
        jobs: &[(UpstreamOccurrence, Upstream)],
    ) -> std::collections::HashSet<UpstreamOccurrence> {
        jobs.iter()
            .map(|(occurrence, _)| occurrence.clone())
            .collect()
    }

    /// A route-only update must not re-prepare unchanged inline upstreams: the
    /// whole point of the reuse plan is that an unrelated config edit cannot be
    /// rejected by a transient DNS failure on an untouched occurrence.
    #[test]
    fn preparation_jobs_skips_unchanged_inline_upstreams_on_route_update() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        set.routes
            .insert("r1".into(), route_with_inline("r1", "/a", "127.0.0.1:81"));
        set.routes
            .insert("r2".into(), route_with_inline("r2", "/b", "127.0.0.1:82"));
        let previous = publish_seed(&set, 100);

        // Only r1's URI changes; both inline upstream configs are untouched.
        let mut next = set;
        next.routes.insert(
            "r1".into(),
            route_with_inline("r1", "/a/v2", "127.0.0.1:81"),
        );
        let plan = CandidatePlan::build(&next, &previous).unwrap();
        assert_eq!(
            job_occurrences(&plan.jobs),
            std::collections::HashSet::from([UpstreamOccurrence::RouteInline("r1".into())]),
            "only the changed route's inline upstream may be re-prepared"
        );
    }

    /// Changing a named upstream invalidates only scopes that actually
    /// reference it: routes owning unrelated inline upstreams are neither
    /// rebuilt nor re-prepared.
    #[test]
    fn preparation_jobs_only_affect_scopes_referencing_the_changed_upstream() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        // r1 references u1 directly (no inline occurrence of its own).
        set.routes
            .insert("r1".into(), route_with_upstream_id("r1", "/a", "u1"));
        // r2 owns an inline occurrence but never references u1.
        set.routes
            .insert("r2".into(), route_with_inline("r2", "/b", "127.0.0.1:82"));
        let previous = publish_seed(&set, 200);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:90"));
        let plan = CandidatePlan::build(&next, &previous).unwrap();
        assert_eq!(
            job_occurrences(&plan.jobs),
            std::collections::HashSet::from([UpstreamOccurrence::Named("u1".into())]),
            "only the changed named upstream may be re-prepared; r2's inline must be untouched"
        );
    }

    /// A route that resolves through a service has no upstream occurrence of
    /// its own; editing only its URI requires zero DNS work.
    #[test]
    fn preparation_jobs_service_backed_route_update_needs_no_dns() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        set.routes
            .insert("r1".into(), route_bound_to_service("r1", "/a", "s1"));
        let previous = publish_seed(&set, 300);

        let mut next = set;
        next.routes
            .insert("r1".into(), route_bound_to_service("r1", "/b", "s1"));
        let plan = CandidatePlan::build(&next, &previous).unwrap();
        assert!(
            plan.jobs.is_empty(),
            "a service-backed route URI edit must need no upstream preparation"
        );
    }

    /// The plan is the single reuse authority: compiling with the same plan
    /// must Arc-reuse exactly the scopes the plan marks reused and rebuild the
    /// rest. Guards against preparation/compilation lockstep drift.
    #[test]
    fn plan_drives_compilation_reuse() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        set.routes
            .insert("r1".into(), route_with_inline("r1", "/a", "127.0.0.1:81"));
        let previous = publish_seed(&set, 400);

        // Route-only edit: u1 and s1 stay, r1 is rebuilt.
        let mut next = set;
        next.routes.insert(
            "r1".into(),
            route_with_inline("r1", "/a/v2", "127.0.0.1:81"),
        );
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let (plan, prepared) = prepare_candidate_static(&next, &previous, &resolver).unwrap();
        assert!(plan.upstream_reused("u1"));
        assert!(plan.service_reused("s1"));
        assert!(!plan.route_reused("r1"));
        assert_eq!(
            job_occurrences(&plan.jobs),
            std::collections::HashSet::from([UpstreamOccurrence::RouteInline("r1".into())])
        );

        let candidate = CandidateSnapshot::build_prepared(
            next,
            &plan,
            &prepared,
            &previous,
            &crate::config::EffectiveDefaults::default(),
            &resolver,
        )
        .expect("plan-guided compilation must succeed");
        let compiled = crate::proxy::runtime::RuntimeSnapshot::compile(candidate, 401).unwrap();
        assert!(Arc::ptr_eq(
            previous.upstreams.get("u1").unwrap(),
            compiled.upstreams.get("u1").unwrap()
        ));
        assert!(Arc::ptr_eq(
            previous.services.get("s1").unwrap(),
            compiled.services.get("s1").unwrap()
        ));
        assert!(!Arc::ptr_eq(
            previous.routes.get("r1").unwrap(),
            compiled.routes.get("r1").unwrap()
        ));

        // Named-upstream edit: every scope that references it loses reuse and
        // compilation follows the plan. r1 references u1 directly here.
        let mut next = ResourceConfigSet::default();
        next.upstreams
            .insert("u1".into(), upstream("u1", "127.0.0.1:90"));
        next.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        next.routes
            .insert("r1".into(), route_with_upstream_id("r1", "/a/v2", "u1"));
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let (plan, prepared) = prepare_candidate_static(&next, &previous, &resolver).unwrap();
        assert!(!plan.upstream_reused("u1"));
        assert!(!plan.service_reused("s1"));
        assert!(!plan.route_reused("r1"));

        let candidate = CandidateSnapshot::build_prepared(
            next,
            &plan,
            &prepared,
            &previous,
            &crate::config::EffectiveDefaults::default(),
            &resolver,
        )
        .expect("plan-guided compilation must succeed");
        let compiled = crate::proxy::runtime::RuntimeSnapshot::compile(candidate, 402).unwrap();
        assert!(!Arc::ptr_eq(
            previous.upstreams.get("u1").unwrap(),
            compiled.upstreams.get("u1").unwrap()
        ));
        assert!(!Arc::ptr_eq(
            previous.services.get("s1").unwrap(),
            compiled.services.get("s1").unwrap()
        ));
        assert!(!Arc::ptr_eq(
            previous.routes.get("r1").unwrap(),
            compiled.routes.get("r1").unwrap()
        ));
    }

    // ---------------------------------------------------------------------
    // Preparation jobs follow the narrowed reuse decisions (Task 3).
    // ---------------------------------------------------------------------

    mod jobs {
        use super::*;

        /// Changing a named upstream must not schedule the inline DNS of an
        /// unrelated scope that never references it.
        #[test]
        fn unrelated_inline_dns_is_not_prepared() {
            let mut set = ResourceConfigSet::default();
            set.upstreams
                .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
            set.routes
                .insert("r1".into(), route_with_upstream_id("r1", "/a", "u1"));
            set.routes
                .insert("r2".into(), route_with_inline("r2", "/b", "127.0.0.1:82"));
            let previous = publish_seed(&set, 500);

            let mut next = set;
            next.upstreams
                .insert("u1".into(), upstream("u1", "127.0.0.1:90"));
            let plan = CandidatePlan::build(&next, &previous).unwrap();
            let occurrences = job_occurrences(&plan.jobs);
            assert!(
                !occurrences.contains(&UpstreamOccurrence::RouteInline("r2".into())),
                "r2's inline DNS is unrelated to u1 and must not be re-prepared: {occurrences:?}"
            );
            assert!(occurrences.contains(&UpstreamOccurrence::Named("u1".into())));
        }

        /// Both service and route traffic-split occurrences are owned by scopes
        /// that only reference u2, so changing u1 must schedule neither their
        /// direct inline upstreams nor their plugin inline upstreams.
        #[test]
        fn unrelated_service_and_traffic_split_occurrences_are_not_prepared() {
            let mut set = ResourceConfigSet::default();
            set.upstreams
                .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
            set.upstreams
                .insert("u2".into(), upstream("u2", "127.0.0.1:81"));

            // A direct service inline upstream has no named dependency.
            set.services.insert(
                "s-inline".into(),
                service_with_inline("s-inline", "127.0.0.1:82"),
            );

            let mut service_plugin = service_with_upstream_id("s-plugin", "u2");
            service_plugin.plugins = traffic_split_with_named_and_inline("u2", "127.0.0.1:83");
            set.services.insert("s-plugin".into(), service_plugin);

            let mut route = route_with_inline("r1", "/route", "127.0.0.1:84");
            route.plugins = traffic_split_with_named_and_inline("u2", "127.0.0.1:85");
            set.routes.insert("r1".into(), route);
            let previous = publish_seed(&set, 550);

            let mut next = set;
            next.upstreams
                .insert("u1".into(), upstream("u1", "127.0.0.1:90"));
            let plan = CandidatePlan::build(&next, &previous).unwrap();
            let occurrences = job_occurrences(&plan.jobs);

            assert_eq!(
                occurrences,
                std::collections::HashSet::from([UpstreamOccurrence::Named("u1".into())]),
                "u1 is unrelated to these scopes, so neither service/route inline nor traffic-split DNS may be prepared"
            );
        }

        /// A scope that actually depends on the changed upstream is rebuilt,
        /// including the inline occurrence declared by its traffic-split plugin.
        #[test]
        fn dependent_traffic_split_occurrence_is_still_prepared() {
            let mut set = ResourceConfigSet::default();
            set.upstreams
                .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
            let mut route = route_with_upstream_id("r1", "/a", "u1");
            route.plugins = traffic_split_with_named_and_inline("u1", "127.0.0.1:81");
            set.routes.insert("r1".into(), route);
            let previous = publish_seed(&set, 560);

            let mut next = set;
            next.upstreams
                .insert("u1".into(), upstream("u1", "127.0.0.1:90"));
            let plan = CandidatePlan::build(&next, &previous).unwrap();
            let occurrences = job_occurrences(&plan.jobs);
            assert!(occurrences.contains(&UpstreamOccurrence::Named("u1".into())));
            assert!(occurrences.contains(&UpstreamOccurrence::TrafficSplit(
                TrafficSplitOwner::Route("r1".into()),
                0,
                1,
            )));
        }

        /// The inline occurrence of a scope that is actually rebuilt is still
        /// prepared; narrowing only skips untouched occurrences.
        #[test]
        fn rebuilt_scope_inline_dns_is_still_prepared() {
            let mut set = ResourceConfigSet::default();
            set.upstreams
                .insert("u1".into(), upstream("u1", "127.0.0.1:80"));
            set.routes
                .insert("r1".into(), route_with_inline("r1", "/a", "127.0.0.1:81"));
            let previous = publish_seed(&set, 600);

            // r1 itself changes (URI edit): its inline occurrence must be prepared.
            let mut next = set;
            next.routes.insert(
                "r1".into(),
                route_with_inline("r1", "/a/v2", "127.0.0.1:81"),
            );
            let plan = CandidatePlan::build(&next, &previous).unwrap();
            let occurrences = job_occurrences(&plan.jobs);
            assert!(
                occurrences.contains(&UpstreamOccurrence::RouteInline("r1".into())),
                "the rebuilt route's inline DNS must still be prepared: {occurrences:?}"
            );
        }
    }
}
