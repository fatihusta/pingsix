//! Runtime compiler for the configuration graph authority.
//!
//! Decodes typed resources, validates whole-graph references, prepares DNS
//! material, and compiles immutable `RuntimeSnapshot`s. The graph authority in
//! [`crate::proxy::graph_mutation`] owns pending/committed state, the
//! preparation worker, and publication; this module never initiates I/O that
//! the authority has not already bounded.

use std::{collections::HashMap, sync::Arc};

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
        let prepared = prepare_static_candidate(&config)?;
        Self::build_prepared(config, &plan, &prepared, &previous)
    }

    /// Compile a candidate from the material prepared by the same
    /// [`CandidatePlan`], against an explicitly supplied previous runtime
    /// (Arc reuse baseline). This method must never initiate DNS I/O.
    pub(crate) fn build_prepared(
        config: ResourceConfigSet,
        plan: &CandidatePlan,
        prepared: &PreparedUpstreams,
        previous: &crate::proxy::runtime::RuntimeSnapshot,
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
        let mut all_named_upstreams_reused = plan.all_named_reused();
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
                )?)
            };
            upstreams.insert(id, arc);
        }
        // Deleted named upstreams also invalidate dependent reuse.
        if previous
            .upstreams
            .keys()
            .any(|id| !upstreams.contains_key(id))
        {
            all_named_upstreams_reused = false;
        }

        let mut services = HashMap::with_capacity(config.services.len());
        for (id, service) in config.services {
            log::info!("Configuring service: {id}");
            let arc = if all_named_upstreams_reused && plan.service_reused(&id) {
                previous.services.get(&id).cloned().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "Service '{id}' marked reused but missing from previous runtime"
                    ))
                })?
            } else {
                Arc::new(ProxyService::build(service, &upstreams, prepared)?)
            };
            services.insert(id, arc);
        }

        let mut global_rules = HashMap::with_capacity(config.global_rules.len());
        for (id, rule) in config.global_rules {
            log::info!("Configuring global rule: {id}");
            let arc = if all_named_upstreams_reused && plan.global_rule_reused(&id) {
                previous.global_rules.get(&id).cloned().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "Global rule '{id}' marked reused but missing from previous runtime"
                    ))
                })?
            } else {
                Arc::new(ProxyGlobalRule::build(rule, &upstreams, prepared)?)
            };
            global_rules.insert(id, arc);
        }

        let services_stable = plan.services_stable()
            && previous.services.keys().all(|id| {
                services
                    .get(id)
                    .zip(previous.services.get(id))
                    .is_some_and(|(a, b)| Arc::ptr_eq(a, b))
            })
            && previous.services.len() == services.len();

        let mut routes = HashMap::with_capacity(config.routes.len());
        for (id, route) in config.routes {
            log::info!("Configuring route: {id}");
            let arc = if services_stable && plan.route_reused(&id) {
                previous.routes.get(&id).cloned().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "Route '{id}' marked reused but missing from previous runtime"
                    ))
                })?
            } else {
                Arc::new(ProxyRoute::build(route, &upstreams, &services, prepared)?)
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
/// - services and global rules reuse only when *every* named upstream is reused;
/// - routes reuse only when every service is reused (stable) and the route matches;
/// - SSL entries reuse independently;
/// - inline and traffic-split upstreams of a reused scope need no preparation.
pub(crate) struct CandidatePlan {
    reused_upstreams: std::collections::HashSet<String>,
    all_named_reused: bool,
    reused_services: std::collections::HashSet<String>,
    reused_global_rules: std::collections::HashSet<String>,
    reused_routes: std::collections::HashSet<String>,
    reused_ssls: std::collections::HashSet<String>,
    services_stable: bool,
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
        let mut reused_upstreams = std::collections::HashSet::new();
        for (id, upstream) in &config.upstreams {
            if previous
                .upstreams
                .get(id)
                .is_some_and(|existing| existing.inner == *upstream)
            {
                reused_upstreams.insert(id.clone());
            }
        }
        let all_named_reused = reused_upstreams.len() == config.upstreams.len()
            && previous
                .upstreams
                .keys()
                .all(|id| config.upstreams.contains_key(id));

        let mut reused_services = std::collections::HashSet::new();
        for (id, service) in &config.services {
            if all_named_reused
                && previous
                    .services
                    .get(id)
                    .is_some_and(|existing| existing.inner == *service)
            {
                reused_services.insert(id.clone());
            }
        }
        let mut reused_global_rules = std::collections::HashSet::new();
        for (id, rule) in &config.global_rules {
            if all_named_reused
                && previous
                    .global_rules
                    .get(id)
                    .is_some_and(|existing| existing.inner == *rule)
            {
                reused_global_rules.insert(id.clone());
            }
        }
        let services_stable = all_named_reused
            && config.services.len() == previous.services.len()
            && reused_services.len() == config.services.len();

        let mut reused_routes = std::collections::HashSet::new();
        for (id, route) in &config.routes {
            if services_stable
                && previous
                    .routes
                    .get(id)
                    .is_some_and(|existing| existing.inner == *route)
            {
                reused_routes.insert(id.clone());
            }
        }
        let mut reused_ssls = std::collections::HashSet::new();
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
            all_named_reused,
            reused_services,
            reused_global_rules,
            reused_routes,
            reused_ssls,
            services_stable,
            jobs,
        })
    }

    pub(crate) fn upstream_reused(&self, id: &str) -> bool {
        self.reused_upstreams.contains(id)
    }

    pub(crate) fn all_named_reused(&self) -> bool {
        self.all_named_reused
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

    pub(crate) fn services_stable(&self) -> bool {
        self.services_stable
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
) -> ProxyResult<(CandidatePlan, PreparedUpstreams)> {
    let plan = CandidatePlan::build(config, previous)?;
    let prepared = stream::iter(plan.jobs.clone())
        .map(|(occurrence, upstream)| async move {
            Ok::<_, ProxyError>((occurrence, prepare_upstream(&upstream).await?))
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
fn prepare_static_candidate(config: &ResourceConfigSet) -> ProxyResult<PreparedUpstreams> {
    let mut prepared = PreparedUpstreams::new();
    for (id, upstream) in &config.upstreams {
        prepared.insert(
            UpstreamOccurrence::Named(id.clone()),
            prepare_static_upstream(upstream)?,
        );
    }
    for (id, route) in &config.routes {
        if let Some(upstream) = &route.upstream {
            prepared.insert(
                UpstreamOccurrence::RouteInline(id.clone()),
                prepare_static_upstream(upstream)?,
            );
        }
        prepare_static_plugin_upstreams(
            &mut prepared,
            TrafficSplitOwner::Route(id.clone()),
            &route.plugins,
        )?;
    }
    for (id, service) in &config.services {
        if let Some(upstream) = &service.upstream {
            prepared.insert(
                UpstreamOccurrence::ServiceInline(id.clone()),
                prepare_static_upstream(upstream)?,
            );
        }
        prepare_static_plugin_upstreams(
            &mut prepared,
            TrafficSplitOwner::Service(id.clone()),
            &service.plugins,
        )?;
    }
    for (id, rule) in &config.global_rules {
        prepare_static_plugin_upstreams(
            &mut prepared,
            TrafficSplitOwner::GlobalRule(id.clone()),
            &rule.plugins,
        )?;
    }
    Ok(prepared)
}

fn prepare_static_plugin_upstreams(
    prepared: &mut PreparedUpstreams,
    owner: TrafficSplitOwner,
    plugins: &HashMap<String, serde_json::Value>,
) -> ProxyResult<()> {
    for (occurrence, upstream) in crate::plugins::plugin_upstream_jobs(owner, plugins)? {
        prepared.insert(occurrence, prepare_static_upstream(&upstream)?);
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
            },
        );
        assert!(validate_config_set(&set).is_ok());
    }

    // ---------------------------------------------------------------------
    // Preparation reuse decisions (must stay in lockstep with build_prepared)
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

    /// Changing a named upstream breaks the reuse chain: services, rules, and
    /// routes (and their inline upstreams) are all rebuilt, so all inline
    /// occurrences must be prepared again.
    #[test]
    fn preparation_jobs_cascade_when_named_upstream_changes() {
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
        let previous = publish_seed(&set, 200);

        let mut next = set;
        next.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
        let plan = CandidatePlan::build(&next, &previous).unwrap();
        assert_eq!(
            job_occurrences(&plan.jobs),
            std::collections::HashSet::from([
                UpstreamOccurrence::Named("u1".into()),
                UpstreamOccurrence::RouteInline("r1".into()),
                UpstreamOccurrence::RouteInline("r2".into()),
            ]),
            "a named-upstream change must invalidate every inline occurrence"
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
        assert!(plan.services_stable());
        assert!(!plan.route_reused("r1"));
        assert_eq!(
            job_occurrences(&plan.jobs),
            std::collections::HashSet::from([UpstreamOccurrence::RouteInline("r1".into())])
        );

        let prepared = prepare_static_candidate(&next).unwrap();
        let candidate = CandidateSnapshot::build_prepared(next, &plan, &prepared, &previous)
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

        // Named-upstream edit: the plan cascades and compilation follows it.
        let mut next = ResourceConfigSet::default();
        next.upstreams
            .insert("u1".into(), sample_upstream("u1", "127.0.0.1:90"));
        next.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        next.routes.insert(
            "r1".into(),
            route_with_inline("r1", "/a/v2", "127.0.0.1:81"),
        );
        let plan = CandidatePlan::build(&next, &previous).unwrap();
        assert!(!plan.upstream_reused("u1"));
        assert!(!plan.service_reused("s1"));
        assert!(!plan.services_stable());
        assert!(!plan.route_reused("r1"));

        let prepared = prepare_static_candidate(&next).unwrap();
        let candidate = CandidateSnapshot::build_prepared(next, &plan, &prepared, &previous)
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
}
