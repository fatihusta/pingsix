use std::{collections::HashSet, sync::Arc};

#[cfg(test)]
use std::collections::HashMap;

use futures::{stream, StreamExt, TryStreamExt};

use crate::{
    config,
    core::{ProxyError, ProxyResult},
};

use crate::proxy::upstream::{
    discovery::prepare_upstream, PreparedUpstreams, TrafficSplitOwner, UpstreamOccurrence,
};

#[cfg(test)]
use crate::proxy::upstream::discovery::prepare_static_upstream;

use super::resources::{
    plugin_upstream_deps, scope_upstream_deps, scope_upstream_deps_rule, ResourceConfigSet,
};

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
    reused_upstreams: HashSet<String>,
    reused_services: HashSet<String>,
    reused_global_rules: HashSet<String>,
    reused_routes: HashSet<String>,
    reused_ssls: HashSet<String>,
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
        let mut reused_upstreams = HashSet::new();
        for (id, upstream) in &config.upstreams {
            if previous
                .upstreams
                .get(id)
                .is_some_and(|existing| existing.inner == *upstream)
            {
                reused_upstreams.insert(id.clone());
            }
        }

        // A scope is reused only when its own config matches and every named
        // upstream it actually references is reused; a changed upstream no
        // longer cascades to scopes that never referenced it.
        let mut reused_services = HashSet::new();
        for (id, service) in &config.services {
            if previous
                .services
                .get(id)
                .is_some_and(|existing| existing.inner == *service)
                && scope_upstream_deps(service)?
                    .iter()
                    .all(|dep| reused_upstreams.contains(dep))
            {
                reused_services.insert(id.clone());
            }
        }
        let mut reused_global_rules = HashSet::new();
        for (id, rule) in &config.global_rules {
            if previous
                .global_rules
                .get(id)
                .is_some_and(|existing| existing.inner == *rule)
                && plugin_upstream_deps(&rule.plugins)?
                    .iter()
                    .all(|dep| reused_upstreams.contains(dep))
            {
                reused_global_rules.insert(id.clone());
            }
        }

        let mut reused_routes = HashSet::new();
        for (id, route) in &config.routes {
            let service_ok = route
                .service_id
                .as_ref()
                .is_none_or(|sid| reused_services.contains(sid));
            if service_ok
                && previous
                    .routes
                    .get(id)
                    .is_some_and(|existing| existing.inner == *route)
                && scope_upstream_deps_rule(route)?
                    .iter()
                    .all(|dep| reused_upstreams.contains(dep))
            {
                reused_routes.insert(id.clone());
            }
        }
        let mut reused_ssls = HashSet::new();
        for (id, ssl) in &config.ssls {
            if previous
                .ssls
                .get(id)
                .is_some_and(|existing| existing.inner == *ssl)
            {
                reused_ssls.insert(id.clone());
            }
        }

        // Preparation jobs: every occurrence owned by a scope that will be rebuilt.
        let mut jobs = Vec::new();
        for (id, upstream) in &config.upstreams {
            if !reused_upstreams.contains(id) {
                jobs.push((UpstreamOccurrence::Named(id.clone()), upstream.clone()));
            }
        }
        for (id, service) in &config.services {
            if !reused_services.contains(id) {
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
            if !reused_global_rules.contains(id) {
                jobs.extend(crate::plugins::plugin_upstream_jobs(
                    TrafficSplitOwner::GlobalRule(id.clone()),
                    &rule.plugins,
                )?);
            }
        }
        for (id, route) in &config.routes {
            if !reused_routes.contains(id) {
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

    pub(crate) fn upstream_reused(&self, id: &str) -> bool {
        self.reused_upstreams.contains(id)
    }

    pub(crate) fn service_reused(&self, id: &str) -> bool {
        self.reused_services.contains(id)
    }

    pub(crate) fn global_rule_reused(&self, id: &str) -> bool {
        self.reused_global_rules.contains(id)
    }

    pub(crate) fn route_reused(&self, id: &str) -> bool {
        self.reused_routes.contains(id)
    }

    pub(crate) fn ssl_reused(&self, id: &str) -> bool {
        self.reused_ssls.contains(id)
    }
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
    let plan = CandidatePlan::build(config, previous)?;
    let prepared = stream::iter(plan.jobs.clone())
        .map(|(occurrence, upstream)| async move {
            Ok::<_, ProxyError>((
                occurrence,
                prepare_upstream(&upstream, defaults, resolver).await?,
            ))
        })
        .buffer_unordered(8)
        .try_collect::<Vec<_>>()
        .await?;
    Ok((plan, prepared.into_iter().collect()))
}

/// Prepare every upstream occurrence synchronously for static startup.
///
/// There is no previous runtime to reuse, so every occurrence is prepared;
/// DNS-only occurrences return an error directing callers to the asynchronous
/// preparation path.
#[cfg(test)]
pub(crate) fn prepare_static_candidate(
    config: &ResourceConfigSet,
    resolver: &Arc<hickory_resolver::TokioResolver>,
) -> ProxyResult<PreparedUpstreams> {
    let mut prepared = PreparedUpstreams::new();
    for (id, upstream) in &config.upstreams {
        prepared.insert(
            UpstreamOccurrence::Named(id.clone()),
            prepare_static_upstream(upstream, resolver)?,
        );
    }
    for (id, route) in &config.routes {
        if let Some(upstream) = &route.upstream {
            prepared.insert(
                UpstreamOccurrence::RouteInline(id.clone()),
                prepare_static_upstream(upstream, resolver)?,
            );
        }
        prepare_static_plugin_upstreams(
            &mut prepared,
            TrafficSplitOwner::Route(id.clone()),
            &route.plugins,
            resolver,
        )?;
    }
    for (id, service) in &config.services {
        if let Some(upstream) = &service.upstream {
            prepared.insert(
                UpstreamOccurrence::ServiceInline(id.clone()),
                prepare_static_upstream(upstream, resolver)?,
            );
        }
        prepare_static_plugin_upstreams(
            &mut prepared,
            TrafficSplitOwner::Service(id.clone()),
            &service.plugins,
            resolver,
        )?;
    }
    for (id, rule) in &config.global_rules {
        prepare_static_plugin_upstreams(
            &mut prepared,
            TrafficSplitOwner::GlobalRule(id.clone()),
            &rule.plugins,
            resolver,
        )?;
    }
    Ok(prepared)
}

#[cfg(test)]
fn prepare_static_plugin_upstreams(
    prepared: &mut PreparedUpstreams,
    owner: TrafficSplitOwner,
    plugins: &HashMap<String, serde_json::Value>,
    resolver: &Arc<hickory_resolver::TokioResolver>,
) -> ProxyResult<()> {
    for (occurrence, upstream) in crate::plugins::plugin_upstream_jobs(owner, plugins)? {
        prepared.insert(occurrence, prepare_static_upstream(&upstream, resolver)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Nodes, SelectionType, Upstream, UpstreamHashOn, UpstreamPassHost, UpstreamScheme,
    };
    use crate::proxy::control_plane::CandidateSnapshot;
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

    // ---------------------------------------------------------------------
    // Preparation jobs: derived from the same plan compilation consumes, so
    // an unchanged occurrence is never re-resolved.
    // ---------------------------------------------------------------------

    fn route_with_inline(id: &str, uri: &str, node: &str) -> crate::config::Route {
        crate::config::Route {
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

    fn route_with_upstream_id(id: &str, uri: &str, upstream_id: &str) -> crate::config::Route {
        crate::config::Route {
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

    fn service_with_upstream_id(id: &str, upstream_id: &str) -> crate::config::Service {
        crate::config::Service {
            id: id.into(),
            name: None,
            plugins: Default::default(),
            upstream: None,
            upstream_id: Some(upstream_id.into()),
            hosts: vec![],
        }
    }

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
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
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
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
        // r1 references u1 directly (no inline occurrence of its own).
        set.routes
            .insert("r1".into(), route_with_upstream_id("r1", "/a", "u1"));
        // r2 owns an inline occurrence but never references u1.
        set.routes
            .insert("r2".into(), route_with_inline("r2", "/b", "127.0.0.1:82"));
        let previous = publish_seed(&set, 200);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
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
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        set.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                name: None,
                uri: Some("/a".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins: Default::default(),
                upstream: None,
                upstream_id: None,
                service_id: Some("s1".into()),
                timeout: None,
                enable_websocket: false,
            },
        );
        let previous = publish_seed(&set, 300);

        let mut next = set;
        next.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                name: None,
                uri: Some("/b".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins: Default::default(),
                upstream: None,
                upstream_id: None,
                service_id: Some("s1".into()),
                timeout: None,
                enable_websocket: false,
            },
        );
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
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
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
        let plan = CandidatePlan::build(&next, &previous).unwrap();
        assert!(plan.upstream_reused("u1"));
        assert!(plan.service_reused("s1"));
        assert!(!plan.route_reused("r1"));
        assert_eq!(
            job_occurrences(&plan.jobs),
            std::collections::HashSet::from([UpstreamOccurrence::RouteInline("r1".into())])
        );

        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let prepared = prepare_static_candidate(&next, &resolver).unwrap();
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
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
        next.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        next.routes
            .insert("r1".into(), route_with_upstream_id("r1", "/a/v2", "u1"));
        let plan = CandidatePlan::build(&next, &previous).unwrap();
        assert!(!plan.upstream_reused("u1"));
        assert!(!plan.service_reused("s1"));
        assert!(!plan.route_reused("r1"));

        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state().unwrap();
        let prepared = prepare_static_candidate(&next, &resolver).unwrap();
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

        fn traffic_split_with_named_and_inline(
            named_upstream: &str,
            inline_node: &str,
        ) -> HashMap<String, serde_json::Value> {
            HashMap::from([(
                "traffic-split".into(),
                serde_json::json!({
                    "rules": [{
                        "weighted_upstreams": [
                            { "upstream_id": named_upstream, "weight": 1 },
                            {
                                "upstream": {
                                    "nodes": { inline_node: 1 },
                                    "type": "roundrobin"
                                },
                                "weight": 1
                            }
                        ]
                    }]
                }),
            )])
        }

        /// Changing a named upstream must not schedule the inline DNS of an
        /// unrelated scope that never references it.
        #[test]
        fn unrelated_inline_dns_is_not_prepared() {
            let mut set = ResourceConfigSet::default();
            set.upstreams
                .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
            set.routes
                .insert("r1".into(), route_with_upstream_id("r1", "/a", "u1"));
            set.routes
                .insert("r2".into(), route_with_inline("r2", "/b", "127.0.0.1:82"));
            let previous = publish_seed(&set, 500);

            let mut next = set;
            next.upstreams
                .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
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
                .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
            set.upstreams
                .insert("u2".into(), sample_upstream("u2", "127.0.0.1:81"));

            // A direct service inline upstream has no named dependency.
            let service_inline = crate::config::Service {
                id: "s-inline".into(),
                name: None,
                plugins: Default::default(),
                upstream: Some(sample_upstream("", "127.0.0.1:82")),
                upstream_id: None,
                hosts: vec![],
            };
            set.services.insert("s-inline".into(), service_inline);

            let mut service_plugin = service_with_upstream_id("s-plugin", "u2");
            service_plugin.plugins = traffic_split_with_named_and_inline("u2", "127.0.0.1:83");
            set.services.insert("s-plugin".into(), service_plugin);

            let mut route = route_with_inline("r1", "/route", "127.0.0.1:84");
            route.plugins = traffic_split_with_named_and_inline("u2", "127.0.0.1:85");
            set.routes.insert("r1".into(), route);
            let previous = publish_seed(&set, 550);

            let mut next = set;
            next.upstreams
                .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
            let plan = CandidatePlan::build(&next, &previous).unwrap();
            let occurrences = job_occurrences(&plan.jobs);

            assert_eq!(
                occurrences,
                HashSet::from([UpstreamOccurrence::Named("u1".into())]),
                "u1 is unrelated to these scopes, so neither service/route inline nor traffic-split DNS may be prepared"
            );
        }

        /// A scope that actually depends on the changed upstream is rebuilt,
        /// including the inline occurrence declared by its traffic-split plugin.
        #[test]
        fn dependent_traffic_split_occurrence_is_still_prepared() {
            let mut set = ResourceConfigSet::default();
            set.upstreams
                .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
            let mut route = route_with_upstream_id("r1", "/a", "u1");
            route.plugins = traffic_split_with_named_and_inline("u1", "127.0.0.1:81");
            set.routes.insert("r1".into(), route);
            let previous = publish_seed(&set, 560);

            let mut next = set;
            next.upstreams
                .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
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
                .insert("u1".into(), sample_upstream("u1", "127.0.0.1:80"));
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
