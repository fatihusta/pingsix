//! Runtime compiler for the configuration graph authority.
//!
//! Decodes typed resources, validates whole-graph references, prepares DNS
//! material, and compiles immutable `RuntimeSnapshot`s. The graph authority in
//! [`crate::proxy::graph_mutation`] owns pending/committed state, the
//! preparation worker, and publication; this module never initiates I/O that
//! the authority has not already bounded.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use futures::{stream, StreamExt, TryStreamExt};
use validator::Validate;

use crate::{
    config::{self, GlobalRule, Route, Service, Upstream, SSL},
    core::{ProxyError, ProxyResult},
};

use super::{
    global_rule::ProxyGlobalRule,
    route::ProxyRoute,
    runtime::RUNTIME,
    service::ProxyService,
    ssl::ProxySSL,
    upstream::{
        discovery::{prepare_static_upstream, prepare_upstream},
        PreparedUpstreams, ProxyUpstream, TrafficSplitOwner, UpstreamOccurrence,
    },
};

/// Deserialized raw configuration graph used by the control plane.
#[derive(Clone, Debug, Default)]
pub struct ResourceConfigSet {
    pub upstreams: HashMap<String, Upstream>,
    pub services: HashMap<String, Service>,
    pub global_rules: HashMap<String, GlobalRule>,
    pub routes: HashMap<String, Route>,
    pub ssls: HashMap<String, SSL>,
}

impl ResourceConfigSet {
    pub fn from_yaml_config(config: &config::Config) -> Self {
        let mut set = Self::default();
        for upstream in &config.upstreams {
            set.upstreams.insert(upstream.id.clone(), upstream.clone());
        }
        for service in &config.services {
            set.services.insert(service.id.clone(), service.clone());
        }
        for rule in &config.global_rules {
            set.global_rules.insert(rule.id.clone(), rule.clone());
        }
        for route in &config.routes {
            set.routes.insert(route.id.clone(), route.clone());
        }
        for ssl in &config.ssls {
            set.ssls.insert(ssl.id.clone(), ssl.clone());
        }
        set
    }
}

pub fn validate_config_set(set: &ResourceConfigSet) -> ProxyResult<()> {
    for upstream in set.upstreams.values() {
        upstream.validate().map_err(|e| {
            ProxyError::Configuration(format!("Upstream '{}' validation failed: {e}", upstream.id))
        })?;
    }
    for service in set.services.values() {
        service.validate().map_err(|e| {
            ProxyError::Configuration(format!("Service '{}' validation failed: {e}", service.id))
        })?;
    }
    for rule in set.global_rules.values() {
        rule.validate().map_err(|e| {
            ProxyError::Configuration(format!("GlobalRule '{}' validation failed: {e}", rule.id))
        })?;
    }
    for route in set.routes.values() {
        route.validate().map_err(|e| {
            ProxyError::Configuration(format!("Route '{}' validation failed: {e}", route.id))
        })?;
    }
    for ssl in set.ssls.values() {
        ssl.validate().map_err(|e| {
            ProxyError::Configuration(format!("SSL '{}' validation failed: {e}", ssl.id))
        })?;
    }

    // Cross-resource reference checks.
    for route in set.routes.values() {
        if let Some(id) = &route.service_id {
            if !set.services.contains_key(id) {
                return Err(ProxyError::Configuration(format!(
                    "Route '{}' references missing service '{}'",
                    route.id, id
                )));
            }
        }
        if route.upstream.is_none() {
            if let Some(id) = &route.upstream_id {
                if !set.upstreams.contains_key(id) {
                    return Err(ProxyError::Configuration(format!(
                        "Route '{}' references missing upstream '{}'",
                        route.id, id
                    )));
                }
            }
        }
        validate_plugin_upstream_refs(
            &format!("Route '{}'", route.id),
            &route.plugins,
            &set.upstreams,
        )?;
    }
    for service in set.services.values() {
        if service.upstream.is_none() {
            if let Some(id) = &service.upstream_id {
                if !set.upstreams.contains_key(id) {
                    return Err(ProxyError::Configuration(format!(
                        "Service '{}' references missing upstream '{}'",
                        service.id, id
                    )));
                }
            }
        }
        validate_plugin_upstream_refs(
            &format!("Service '{}'", service.id),
            &service.plugins,
            &set.upstreams,
        )?;
    }
    for rule in set.global_rules.values() {
        validate_plugin_upstream_refs(
            &format!("GlobalRule '{}'", rule.id),
            &rule.plugins,
            &set.upstreams,
        )?;
    }
    Ok(())
}

/// Validate plugin-embedded named upstream references.
///
/// Generic over every plugin that declares an `upstream_refs` capability, so
/// graph validation never names a specific plugin.
fn validate_plugin_upstream_refs(
    owner: &str,
    plugins: &HashMap<String, serde_json::Value>,
    upstreams: &HashMap<String, Upstream>,
) -> ProxyResult<()> {
    for (name, value) in plugins {
        crate::plugins::validate_plugin_config(name, value)?;
        for id in crate::plugins::plugin_upstream_refs(name, value)? {
            if !upstreams.contains_key(&id) {
                return Err(ProxyError::Configuration(format!(
                    "{owner} plugin '{name}' references missing upstream '{id}'"
                )));
            }
        }
    }
    Ok(())
}

/// Named upstream ids referenced across a resource's plugin configs.
///
/// Empty for resources without dependency-aware plugins.
fn plugin_upstream_deps(
    plugins: &HashMap<String, serde_json::Value>,
) -> ProxyResult<HashSet<String>> {
    let mut deps = HashSet::new();
    for (name, cfg) in plugins {
        deps.extend(crate::plugins::plugin_upstream_refs(name, cfg)?);
    }
    Ok(deps)
}

/// Named upstream ids a service actually references: its direct `upstream_id`
/// plus any plugin-declared refs. Inline upstreams are excluded — they are
/// owned by the scope's rebuild decision, not a cross-scope dependency.
fn scope_upstream_deps(service: &Service) -> ProxyResult<HashSet<String>> {
    let mut deps = plugin_upstream_deps(&service.plugins)?;
    if let Some(id) = &service.upstream_id {
        deps.insert(id.clone());
    }
    Ok(deps)
}

/// Named upstream ids a route actually references: its direct `upstream_id`
/// plus any plugin-declared refs. The `service_id` link is checked separately
/// by callers because it binds a service, not an upstream.
fn scope_upstream_deps_rule(route: &Route) -> ProxyResult<HashSet<String>> {
    let mut deps = plugin_upstream_deps(&route.plugins)?;
    if let Some(id) = &route.upstream_id {
        deps.insert(id.clone());
    }
    Ok(deps)
}

/// True when `dep` compiled to the same `Arc` in both runtimes, i.e. the
/// dependency was actually reused rather than rebuilt by this candidate.
fn upstream_arc_reused(
    dep: &str,
    upstreams: &HashMap<String, Arc<ProxyUpstream>>,
    previous: &crate::proxy::runtime::RuntimeSnapshot,
) -> bool {
    upstreams
        .get(dep)
        .zip(previous.upstreams.get(dep))
        .is_some_and(|(a, b)| Arc::ptr_eq(a, b))
}

/// Control-plane-only candidate built from a single version of the resource graph.
pub struct CandidateSnapshot {
    pub upstreams: HashMap<String, Arc<ProxyUpstream>>,
    pub services: HashMap<String, Arc<ProxyService>>,
    pub global_rules: HashMap<String, Arc<ProxyGlobalRule>>,
    pub routes: HashMap<String, Arc<ProxyRoute>>,
    pub ssls: HashMap<String, Arc<ProxySSL>>,
}

impl CandidateSnapshot {
    /// Build every runtime object from the same raw resource graph.
    ///
    /// Static path: no previous runtime exists, so every occurrence is prepared
    /// and the current (empty-at-boot) runtime snapshot is the reuse baseline.
    /// Constructors must never initiate DNS I/O beyond the prepared material.
    pub fn build(config: ResourceConfigSet) -> ProxyResult<Self> {
        let previous = RUNTIME.load();
        let plan = CandidatePlan::build(&config, &previous)?;
        let resolver = crate::proxy::upstream::discovery::get_global_resolver_for_build()?;
        let prepared = prepare_static_candidate(&config, &resolver)?;
        Self::build_prepared(
            config,
            &plan,
            &prepared,
            &previous,
            &crate::config::EffectiveDefaults::global(),
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
            // Arc-reused; unlike the former all-services cascade this is
            // checked per route against just its own `service_id`.
            let service_reused = route.service_id.as_ref().is_none_or(|sid| {
                services
                    .get(sid)
                    .zip(previous.services.get(sid))
                    .is_some_and(|(a, b)| Arc::ptr_eq(a, b))
            });
            let arc = if plan.route_reused(&id) && service_reused {
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

/// One authoritative reuse/preparation plan for a candidate graph.
///
/// Computed once from `(config, previous)` and consumed by both stages that
/// previously mirrored the same dependency chain: upstream preparation (which
/// occurrences need DNS work) and candidate compilation (which compiled
/// objects are Arc-reused). Keeping both stages on one plan removes the former
/// lockstep requirement between `preparation_jobs` and
/// [`CandidateSnapshot::build_prepared`].
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
/// hand the *same* plan to [`CandidateSnapshot::build_prepared`]; compilation
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
fn prepare_static_candidate(
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
    use std::collections::HashMap as StdHashMap;

    fn sample_upstream(id: &str, node: &str) -> Upstream {
        let mut nodes = StdHashMap::new();
        nodes.insert(node.to_string(), 1);
        Upstream {
            id: id.to_string(),
            name: None,
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
        }
    }

    #[test]
    fn validate_config_set_rejects_dangling_route_upstream_id() {
        let mut set = ResourceConfigSet::default();
        set.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                name: None,
                uri: Some("/".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("missing".into()),
                service_id: None,
                timeout: None,
                enable_websocket: false,
            },
        );
        assert!(validate_config_set(&set).is_err());
    }

    #[test]
    fn validate_config_set_rejects_dangling_route_service_id() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        set.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                name: None,
                uri: Some("/".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("u1".into()),
                service_id: Some("missing".into()),
                timeout: None,
                enable_websocket: false,
            },
        );
        assert!(validate_config_set(&set).is_err());
    }

    #[test]
    fn validate_config_set_rejects_dangling_service_upstream_id() {
        let mut set = ResourceConfigSet::default();
        set.services.insert(
            "s1".into(),
            crate::config::Service {
                id: "s1".into(),
                name: None,
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("missing".into()),
                hosts: vec![],
            },
        );
        assert!(validate_config_set(&set).is_err());
    }

    #[test]
    fn validate_config_set_rejects_traffic_split_missing_upstream_on_route() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        let mut plugins = std::collections::HashMap::new();
        plugins.insert(
            "traffic-split".into(),
            serde_json::json!({
                "rules": [{
                    "weighted_upstreams": [
                        { "upstream_id": "does-not-exist", "weight": 100 }
                    ]
                }]
            }),
        );
        set.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                name: None,
                uri: Some("/".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins,
                upstream: None,
                upstream_id: Some("u1".into()),
                service_id: None,
                timeout: None,
                enable_websocket: false,
            },
        );
        let err = validate_config_set(&set).unwrap_err().to_string();
        assert!(
            err.contains("does-not-exist"),
            "expected missing upstream error, got: {err}"
        );
    }

    #[test]
    fn validate_config_set_rejects_traffic_split_missing_upstream_on_service() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        let mut plugins = std::collections::HashMap::new();
        plugins.insert(
            "traffic-split".into(),
            serde_json::json!({
                "rules": [{
                    "weighted_upstreams": [
                        { "upstream_id": "missing-svc-up", "weight": 100 }
                    ]
                }]
            }),
        );
        set.services.insert(
            "s1".into(),
            crate::config::Service {
                id: "s1".into(),
                name: None,
                plugins,
                upstream: None,
                upstream_id: Some("u1".into()),
                hosts: vec![],
            },
        );
        let err = validate_config_set(&set).unwrap_err().to_string();
        assert!(err.contains("missing-svc-up"), "got: {err}");
    }

    #[test]
    fn validate_config_set_rejects_traffic_split_missing_upstream_on_global_rule() {
        let mut set = ResourceConfigSet::default();
        let mut plugins = std::collections::HashMap::new();
        plugins.insert(
            "traffic-split".into(),
            serde_json::json!({
                "rules": [{
                    "weighted_upstreams": [
                        { "upstream_id": "missing-gr-up", "weight": 100 }
                    ]
                }]
            }),
        );
        set.global_rules.insert(
            "g1".into(),
            crate::config::GlobalRule {
                id: "g1".into(),
                plugins,
            },
        );
        let err = validate_config_set(&set).unwrap_err().to_string();
        assert!(err.contains("missing-gr-up"), "got: {err}");
    }

    #[test]
    fn validate_config_set_accepts_traffic_split_with_existing_upstream() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        set.upstreams.insert(
            "payments".into(),
            sample_upstream("payments", "10.0.0.2:80"),
        );
        let mut plugins = std::collections::HashMap::new();
        plugins.insert(
            "traffic-split".into(),
            serde_json::json!({
                "rules": [{
                    "weighted_upstreams": [
                        { "upstream_id": "payments", "weight": 100 }
                    ]
                }]
            }),
        );
        set.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                name: None,
                uri: Some("/".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins,
                upstream: None,
                upstream_id: Some("u1".into()),
                service_id: None,
                timeout: None,
                enable_websocket: false,
            },
        );
        assert!(validate_config_set(&set).is_ok());
    }

    #[test]
    fn validate_config_set_delete_upstream_referenced_by_traffic_split_fails() {
        // Simulate DELETE of upstream "payments" while a route traffic-split still
        // references it: the candidate set without "payments" must be rejected.
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        // payments intentionally absent (deleted).
        let mut plugins = std::collections::HashMap::new();
        plugins.insert(
            "traffic-split".into(),
            serde_json::json!({
                "rules": [{
                    "weighted_upstreams": [
                        { "upstream_id": "payments", "weight": 100 }
                    ]
                }]
            }),
        );
        set.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                name: None,
                uri: Some("/".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins,
                upstream: None,
                upstream_id: Some("u1".into()),
                service_id: None,
                timeout: None,
                enable_websocket: false,
            },
        );
        assert!(validate_config_set(&set).is_err());
    }

    #[test]
    fn validate_config_set_accepts_valid_graph() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), sample_upstream("u1", "10.0.0.1:80"));
        set.services.insert(
            "s1".into(),
            crate::config::Service {
                id: "s1".into(),
                name: None,
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("u1".into()),
                hosts: vec![],
            },
        );
        set.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                name: None,
                uri: Some("/".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("u1".into()),
                service_id: Some("s1".into()),
                timeout: None,
                enable_websocket: false,
            },
        );
        assert!(validate_config_set(&set).is_ok());
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

    /// Seed the global RUNTIME with a published snapshot and return it.
    fn publish_seed(
        set: &ResourceConfigSet,
        revision: i64,
    ) -> Arc<super::super::runtime::RuntimeSnapshot> {
        use crate::proxy::runtime::RuntimeSnapshot;
        use crate::proxy::runtime::RUNTIME;
        let snapshot =
            RuntimeSnapshot::compile(CandidateSnapshot::build(set.clone()).unwrap(), revision)
                .unwrap();
        RUNTIME.publish(snapshot).unwrap()
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
        let _guard = crate::proxy::runtime::RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::proxy::runtime::RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::proxy::runtime::RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        let _guard = crate::proxy::runtime::RUNTIME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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

        let resolver = crate::proxy::upstream::discovery::get_global_resolver_for_build().unwrap();
        let prepared = prepare_static_candidate(&next, &resolver).unwrap();
        let candidate = CandidateSnapshot::build_prepared(
            next,
            &plan,
            &prepared,
            &previous,
            &crate::config::EffectiveDefaults::global(),
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

        let resolver = crate::proxy::upstream::discovery::get_global_resolver_for_build().unwrap();
        let prepared = prepare_static_candidate(&next, &resolver).unwrap();
        let candidate = CandidateSnapshot::build_prepared(
            next,
            &plan,
            &prepared,
            &previous,
            &crate::config::EffectiveDefaults::global(),
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
    // Scope dependency sets: what each scope actually references (Task 1).
    // ---------------------------------------------------------------------

    mod scope_dependency {
        use super::*;

        fn traffic_split_plugin(upstream_id: &str) -> HashMap<String, serde_json::Value> {
            let mut plugins = HashMap::new();
            plugins.insert(
                "traffic-split".into(),
                serde_json::json!({
                    "rules": [{
                        "weighted_upstreams": [
                            { "upstream_id": upstream_id, "weight": 100 }
                        ]
                    }]
                }),
            );
            plugins
        }

        #[test]
        fn service_deps_are_direct_id_plus_plugin_refs() {
            let mut service = service_with_upstream_id("s1", "u1");
            service.plugins = traffic_split_plugin("payments");
            let deps = scope_upstream_deps(&service).unwrap();
            assert_eq!(
                deps,
                HashSet::from(["u1".to_string(), "payments".to_string()])
            );
        }

        #[test]
        fn route_deps_are_own_upstream_id_plus_plugin_refs() {
            let mut route = route_with_upstream_id("r1", "/a", "u1");
            route.plugins = traffic_split_plugin("payments");
            let deps = scope_upstream_deps_rule(&route).unwrap();
            assert_eq!(
                deps,
                HashSet::from(["u1".to_string(), "payments".to_string()])
            );
        }

        #[test]
        fn global_rule_without_plugins_has_empty_deps() {
            let rule = crate::config::GlobalRule {
                id: "g1".into(),
                plugins: Default::default(),
            };
            assert!(plugin_upstream_deps(&rule.plugins).unwrap().is_empty());
        }

        #[test]
        fn service_without_refs_has_empty_deps() {
            let service = crate::config::Service {
                id: "s1".into(),
                name: None,
                plugins: Default::default(),
                upstream: None,
                upstream_id: None,
                hosts: vec![],
            };
            assert!(scope_upstream_deps(&service).unwrap().is_empty());
        }
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
            let _guard = crate::proxy::runtime::RUNTIME_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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
            let _guard = crate::proxy::runtime::RUNTIME_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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
            let _guard = crate::proxy::runtime::RUNTIME_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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
            let _guard = crate::proxy::runtime::RUNTIME_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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

/// Behavior-level invalidation contracts (Task 4): the published snapshot must
/// reuse exactly the scopes whose real dependencies are unchanged, verified
/// through the same plan preparation and compilation both consume.
#[cfg(test)]
mod dependency_invalidation {
    use super::*;
    use crate::config::{Nodes, SelectionType, UpstreamHashOn, UpstreamPassHost, UpstreamScheme};
    use crate::proxy::runtime::{RuntimeSnapshot, RUNTIME_TEST_LOCK};
    use std::collections::HashMap as StdHashMap;

    fn sample_upstream(id: &str, node: &str) -> Upstream {
        let mut nodes = StdHashMap::new();
        nodes.insert(node.to_string(), 1);
        Upstream {
            id: id.to_string(),
            name: None,
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

    /// Seed the global RUNTIME with a published snapshot and return it.
    fn publish_seed(set: &ResourceConfigSet, revision: i64) -> Arc<RuntimeSnapshot> {
        let snapshot =
            RuntimeSnapshot::compile(CandidateSnapshot::build(set.clone()).unwrap(), revision)
                .unwrap();
        RUNTIME.publish(snapshot).unwrap()
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
                prepare_static_upstream(
                    upstream,
                    &crate::proxy::upstream::discovery::get_global_resolver_for_build().unwrap(),
                )
                .unwrap(),
            );
        }
        let resolver = crate::proxy::upstream::discovery::get_global_resolver_for_build().unwrap();
        let candidate = CandidateSnapshot::build_prepared(
            next.clone(),
            &plan,
            &prepared,
            previous,
            &crate::config::EffectiveDefaults::global(),
            &resolver,
        )
        .expect("plan-guided compilation must succeed");
        let snapshot = RuntimeSnapshot::compile(candidate, revision).unwrap();
        (plan, RUNTIME.publish(snapshot).unwrap())
    }

    /// Changing `u1` must not rebuild a service that only references `u2`;
    /// routes bound to the reused service stay reused too.
    #[test]
    fn changing_u1_does_not_rebuild_service_that_only_references_u2() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

    /// Changing an upstream that no service references must not rebuild all
    /// routes: only routes that reference it are rebuilt.
    #[test]
    fn changing_upstream_not_referenced_by_services_does_not_rebuild_all_routes() {
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
