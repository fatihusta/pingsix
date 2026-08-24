//! Shared config-fixture builders for control-plane and data-plane tests.
//!
//! Every builder starts from sensible defaults and exposes overrides through
//! either dedicated helpers below or direct field mutation on the returned
//! struct. Adding a field to `config::Route`/`Upstream`/`Service` must touch
//! only this file — test call sites mutate the fields they care about.
//!
//! All fixture nodes are IP literals, so the DNS-off preparation path
//! (`prepare_candidate_static`) can resolve them without any I/O.

use std::collections::HashMap;

use crate::config::{
    GlobalRule, Nodes, Route, SelectionType, Service, Upstream, UpstreamHashOn, UpstreamPassHost,
    UpstreamScheme,
};

/// Upstream with a single IP-literal node of weight 1.
pub(crate) fn upstream(id: &str, node: &str) -> Upstream {
    upstream_weighted(id, &[(node, 1)])
}

/// Upstream with explicit `(address, weight)` IP-literal nodes.
pub(crate) fn upstream_weighted(id: &str, nodes: &[(&str, u32)]) -> Upstream {
    let map: HashMap<String, u32> = nodes
        .iter()
        .map(|(addr, weight)| ((*addr).to_string(), *weight))
        .collect();
    Upstream {
        id: id.to_string(),
        retries: None,
        retry_timeout: None,
        timeout: None,
        nodes: Nodes::from_map(map),
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

/// Bare route matching `uri`; override fields as needed.
pub(crate) fn route(id: &str, uri: &str) -> Route {
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
        service_id: None,
        timeout: None,
        enable_websocket: false,
    }
}

/// Route owning an inline upstream occurrence at `node` (IP literal).
pub(crate) fn route_with_inline(id: &str, uri: &str, node: &str) -> Route {
    let mut route = route(id, uri);
    route.upstream = Some(upstream("", node));
    route
}

/// Route resolving through a named upstream.
pub(crate) fn route_with_upstream_id(id: &str, uri: &str, upstream_id: &str) -> Route {
    let mut route = route(id, uri);
    route.upstream_id = Some(upstream_id.into());
    route
}

/// Route resolving through a service.
pub(crate) fn route_bound_to_service(id: &str, uri: &str, service_id: &str) -> Route {
    let mut route = route(id, uri);
    route.service_id = Some(service_id.into());
    route
}

/// Bare service; override fields as needed.
pub(crate) fn service(id: &str) -> Service {
    Service {
        id: id.into(),
        name: None,
        plugins: Default::default(),
        upstream: None,
        upstream_id: None,
        hosts: vec![],
    }
}

/// Service resolving through a named upstream.
pub(crate) fn service_with_upstream_id(id: &str, upstream_id: &str) -> Service {
    let mut service = service(id);
    service.upstream_id = Some(upstream_id.into());
    service
}

/// Service owning an inline upstream occurrence at `node` (IP literal).
pub(crate) fn service_with_inline(id: &str, node: &str) -> Service {
    let mut service = service(id);
    service.upstream = Some(upstream("", node));
    service
}

/// Bare global rule; override `plugins` as needed.
pub(crate) fn global_rule(id: &str) -> GlobalRule {
    GlobalRule {
        id: id.into(),
        plugins: Default::default(),
    }
}

/// `traffic-split` plugin config with a single named-upstream rule.
pub(crate) fn traffic_split_plugin(named_upstream: &str) -> HashMap<String, serde_json::Value> {
    HashMap::from([(
        "traffic-split".into(),
        serde_json::json!({
            "rules": [{
                "weighted_upstreams": [
                    { "upstream_id": named_upstream, "weight": 100 }
                ]
            }]
        }),
    )])
}

/// `traffic-split` plugin config mixing one named and one inline upstream in
/// the same rule — the shape that exercises plugin-owned inline occurrences.
pub(crate) fn traffic_split_with_named_and_inline(
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
