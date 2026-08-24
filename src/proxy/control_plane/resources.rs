use std::collections::{HashMap, HashSet};

use validator::Validate;

use crate::{
    config::{self, GlobalRule, Route, Service, Upstream, SSL},
    core::{ProxyError, ProxyResult},
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

/// Validation gate named after the *runtime form* of a candidate graph:
/// decoded with `SecretMode::DecryptForRuntime` (secrets decrypted, fail-closed
/// on undecryptable values). This is the gate the graph authority
/// (`replace_all`/`apply_watch`/`load_static`) runs on every candidate before
/// submission, and the defense-in-depth gate candidate compilation runs on
/// the decoded set it is handed.
///
/// Today the checks are form-independent — validators never look inside
/// secret values — so both named gates enforce the identical body; the name
/// states which form the caller holds so future secret-shape checks attach
/// to the right boundary.
pub fn validate_runtime_form(set: &ResourceConfigSet) -> ProxyResult<()> {
    validate_config_set(set)
}

/// Validation gate named after the *stored form*: decoded with
/// `SecretMode::PreserveStored`, so secret fields may still be ciphertext.
/// Used by the etcd CAS planner (`graph_mutation::decode`) when validating a
/// planned PUT/DELETE before it is committed.
pub fn validate_stored_form(set: &ResourceConfigSet) -> ProxyResult<()> {
    validate_config_set(set)
}

/// Whole-graph validation without a form name: structural validation of
/// every resource plus cross-resource reference checks. Retained for
/// existing authority call sites (which validate the runtime form); new call
/// sites must use [`validate_runtime_form`] or [`validate_stored_form`].
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
pub(crate) fn plugin_upstream_deps(
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
pub(crate) fn scope_upstream_deps(service: &Service) -> ProxyResult<HashSet<String>> {
    let mut deps = plugin_upstream_deps(&service.plugins)?;
    if let Some(id) = &service.upstream_id {
        deps.insert(id.clone());
    }
    Ok(deps)
}

/// Named upstream ids a route actually references: its direct `upstream_id`
/// plus any plugin-declared refs. The `service_id` link is checked separately
/// by callers because it binds a service, not an upstream.
pub(crate) fn scope_upstream_deps_rule(route: &Route) -> ProxyResult<HashSet<String>> {
    let mut deps = plugin_upstream_deps(&route.plugins)?;
    if let Some(id) = &route.upstream_id {
        deps.insert(id.clone());
    }
    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::control_plane::test_fixtures::{
        global_rule, route_with_upstream_id, service, service_with_upstream_id,
        traffic_split_plugin, upstream,
    };

    #[test]
    fn validate_stored_form_rejects_dangling_route_upstream_id() {
        let mut set = ResourceConfigSet::default();
        set.routes
            .insert("r1".into(), route_with_upstream_id("r1", "/", "missing"));
        assert!(validate_stored_form(&set).is_err());
    }

    #[test]
    fn validate_stored_form_rejects_dangling_route_service_id() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.1:80"));
        let mut route = route_with_upstream_id("r1", "/", "u1");
        route.service_id = Some("missing".into());
        set.routes.insert("r1".into(), route);
        assert!(validate_stored_form(&set).is_err());
    }

    #[test]
    fn validate_stored_form_rejects_dangling_service_upstream_id() {
        let mut set = ResourceConfigSet::default();
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "missing"));
        assert!(validate_stored_form(&set).is_err());
    }

    #[test]
    fn validate_stored_form_rejects_traffic_split_missing_upstream_on_route() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.1:80"));
        let mut route = route_with_upstream_id("r1", "/", "u1");
        route.plugins = traffic_split_plugin("does-not-exist");
        set.routes.insert("r1".into(), route);
        let err = validate_stored_form(&set).unwrap_err().to_string();
        assert!(
            err.contains("does-not-exist"),
            "expected missing upstream error, got: {err}"
        );
    }

    #[test]
    fn validate_stored_form_rejects_traffic_split_missing_upstream_on_service() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.1:80"));
        let mut service = service_with_upstream_id("s1", "u1");
        service.plugins = traffic_split_plugin("missing-svc-up");
        set.services.insert("s1".into(), service);
        let err = validate_stored_form(&set).unwrap_err().to_string();
        assert!(err.contains("missing-svc-up"), "got: {err}");
    }

    #[test]
    fn validate_stored_form_rejects_traffic_split_missing_upstream_on_global_rule() {
        let mut set = ResourceConfigSet::default();
        let mut rule = global_rule("g1");
        rule.plugins = traffic_split_plugin("missing-gr-up");
        set.global_rules.insert("g1".into(), rule);
        let err = validate_stored_form(&set).unwrap_err().to_string();
        assert!(err.contains("missing-gr-up"), "got: {err}");
    }

    #[test]
    fn validate_stored_form_accepts_traffic_split_with_existing_upstream() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.1:80"));
        set.upstreams
            .insert("payments".into(), upstream("payments", "10.0.0.2:80"));
        let mut route = route_with_upstream_id("r1", "/", "u1");
        route.plugins = traffic_split_plugin("payments");
        set.routes.insert("r1".into(), route);
        assert!(validate_stored_form(&set).is_ok());
    }

    #[test]
    fn validate_stored_form_delete_upstream_referenced_by_traffic_split_fails() {
        // Simulate DELETE of upstream "payments" while a route traffic-split still
        // references it: the candidate set without "payments" must be rejected.
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.1:80"));
        // payments intentionally absent (deleted).
        let mut route = route_with_upstream_id("r1", "/", "u1");
        route.plugins = traffic_split_plugin("payments");
        set.routes.insert("r1".into(), route);
        assert!(validate_stored_form(&set).is_err());
    }

    #[test]
    fn validate_runtime_form_accepts_valid_graph() {
        let mut set = ResourceConfigSet::default();
        set.upstreams
            .insert("u1".into(), upstream("u1", "10.0.0.1:80"));
        set.services
            .insert("s1".into(), service_with_upstream_id("s1", "u1"));
        let mut route = route_with_upstream_id("r1", "/", "u1");
        route.service_id = Some("s1".into());
        set.routes.insert("r1".into(), route);
        assert!(validate_runtime_form(&set).is_ok());
    }

    // ---------------------------------------------------------------------
    // Scope dependency sets: what each scope actually references (Task 1).
    // ---------------------------------------------------------------------

    mod scope_dependency {
        use super::*;

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
            let rule = global_rule("g1");
            assert!(plugin_upstream_deps(&rule.plugins).unwrap().is_empty());
        }

        #[test]
        fn service_without_refs_has_empty_deps() {
            let service = service("s1");
            assert!(scope_upstream_deps(&service).unwrap().is_empty());
        }
    }
}
