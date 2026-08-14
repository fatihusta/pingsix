use serde_json::Value as JsonValue;

/// Schema of a dynamic configuration resource for unrecognized-field warnings.
///
/// Only typed object fields appear in `nested`. Deliberately free-form objects
/// (`plugins`, `nodes`, and compatibility metadata) remain leaves: their
/// contents belong to another schema or external producer and must not be
/// diagnosed here.
pub(crate) struct ResourceSchema {
    fields: &'static [&'static str],
    nested: &'static [(&'static str, &'static str)],
}

pub(crate) fn schema_for(id: &str) -> Option<&'static ResourceSchema> {
    const ROUTE: ResourceSchema = ResourceSchema {
        fields: &[
            "id",
            "name",
            "uri",
            "uris",
            "methods",
            "host",
            "hosts",
            "priority",
            "plugins",
            "upstream",
            "upstream_id",
            "service_id",
            "timeout",
            "enable_websocket",
            "metadata",
        ],
        nested: &[("upstream", "upstream"), ("timeout", "timeout")],
    };
    const UPSTREAM: ResourceSchema = ResourceSchema {
        fields: &[
            "id",
            "name",
            "retries",
            "retry_timeout",
            "timeout",
            "nodes",
            "plugins",
            "type",
            "checks",
            "hash_on",
            "key",
            "scheme",
            "pass_host",
            "upstream_host",
            "tls",
            "keepalive_pool",
            "metadata",
        ],
        nested: &[
            ("timeout", "timeout"),
            ("checks", "health_check"),
            ("tls", "upstream_tls"),
            ("keepalive_pool", "keepalive_pool"),
        ],
    };
    const SERVICE: ResourceSchema = ResourceSchema {
        fields: &[
            "id",
            "name",
            "plugins",
            "upstream",
            "upstream_id",
            "hosts",
            "metadata",
        ],
        nested: &[("upstream", "upstream")],
    };
    const GLOBAL_RULE: ResourceSchema = ResourceSchema {
        fields: &["id", "plugins", "metadata"],
        nested: &[],
    };
    const SSL: ResourceSchema = ResourceSchema {
        fields: &["id", "cert", "key", "snis", "metadata"],
        nested: &[],
    };
    const TIMEOUT: ResourceSchema = ResourceSchema {
        fields: &["connect", "send", "read"],
        nested: &[],
    };
    const UPSTREAM_TLS: ResourceSchema = ResourceSchema {
        fields: &["client_cert", "client_key"],
        nested: &[],
    };
    const KEEPALIVE_POOL: ResourceSchema = ResourceSchema {
        fields: &["size", "idle_timeout", "requests"],
        nested: &[],
    };
    const HEALTH_CHECK: ResourceSchema = ResourceSchema {
        fields: &["active", "passive"],
        nested: &[("active", "active_check"), ("passive", "passive_check")],
    };
    const ACTIVE_CHECK: ResourceSchema = ResourceSchema {
        fields: &[
            "type",
            "timeout",
            "http_path",
            "host",
            "port",
            "https_verify_certificate",
            "req_headers",
            "healthy",
            "unhealthy",
        ],
        nested: &[("healthy", "health"), ("unhealthy", "unhealthy")],
    };
    const HEALTH: ResourceSchema = ResourceSchema {
        fields: &["interval", "http_statuses", "successes"],
        nested: &[],
    };
    const UNHEALTHY: ResourceSchema = ResourceSchema {
        fields: &["http_failures", "tcp_failures"],
        nested: &[],
    };
    const PASSIVE_CHECK: ResourceSchema = ResourceSchema {
        fields: &["type", "healthy", "unhealthy"],
        nested: &[
            ("healthy", "passive_healthy"),
            ("unhealthy", "passive_unhealthy"),
        ],
    };
    const PASSIVE_HEALTHY: ResourceSchema = ResourceSchema {
        fields: &["http_statuses", "successes"],
        nested: &[],
    };
    const PASSIVE_UNHEALTHY: ResourceSchema = ResourceSchema {
        fields: &["http_statuses", "tcp_failures", "timeouts", "http_failures"],
        nested: &[],
    };
    match id {
        "route" => Some(&ROUTE),
        "upstream" => Some(&UPSTREAM),
        "service" => Some(&SERVICE),
        "global_rule" => Some(&GLOBAL_RULE),
        "ssl" => Some(&SSL),
        "timeout" => Some(&TIMEOUT),
        "upstream_tls" => Some(&UPSTREAM_TLS),
        "keepalive_pool" => Some(&KEEPALIVE_POOL),
        "health_check" => Some(&HEALTH_CHECK),
        "active_check" => Some(&ACTIVE_CHECK),
        "health" => Some(&HEALTH),
        "unhealthy" => Some(&UNHEALTHY),
        "passive_check" => Some(&PASSIVE_CHECK),
        "passive_healthy" => Some(&PASSIVE_HEALTHY),
        "passive_unhealthy" => Some(&PASSIVE_UNHEALTHY),
        _ => None,
    }
}

/// Edit distance between two short field names for typo suggestions.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for (i, ac) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, bc) in b.iter().enumerate() {
            let cost = if ac == bc { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Warn about unrecognized fields on a resource object, suggesting likely
/// typos of known behavior fields. Unknown fields are still accepted (ingress
/// metadata compatibility); this only logs, so a typo like `retry_timout` does
/// not fail silently while the operator believes it took effect.
///
/// `resource_type` is the plural store segment (e.g. `"upstreams"`).
pub(crate) fn warn_unrecognized_fields(resource_type: &str, value: &JsonValue) {
    for warning in unrecognized_fields(resource_type, value) {
        if let Some(suggestion) = warning.suggestion {
            log::warn!(
                "Configuration: field '{}' is not recognized; did you mean '{}'? It will be ignored.",
                warning.path,
                suggestion,
            );
        } else {
            log::warn!(
                "Configuration: field '{}' is not recognized and will be ignored.",
                warning.path,
            );
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FieldWarning {
    pub(crate) path: String,
    pub(crate) suggestion: Option<&'static str>,
}

/// Find warnings without emitting them, keeping warning traversal testable.
pub(crate) fn unrecognized_fields(resource_type: &str, value: &JsonValue) -> Vec<FieldWarning> {
    let schema_id = match resource_type {
        "routes" => "route",
        "upstreams" => "upstream",
        "services" => "service",
        "global_rules" => "global_rule",
        "ssls" => "ssl",
        _ => return Vec::new(),
    };
    let mut warnings = Vec::new();
    collect_schema_warnings(schema_id, resource_type, value, &mut warnings);
    warnings
}

fn collect_schema_warnings(
    schema_id: &str,
    path: &str,
    value: &JsonValue,
    warnings: &mut Vec<FieldWarning>,
) {
    let (Some(schema), Some(obj)) = (schema_for(schema_id), value.as_object()) else {
        return;
    };
    for (key, val) in obj {
        let field_path = format!("{path}.{key}");
        if schema.fields.contains(&key.as_str()) {
            if let Some(nested_id) = schema
                .nested
                .iter()
                .find_map(|(field, id)| (*field == key.as_str()).then_some(*id))
            {
                collect_schema_warnings(nested_id, &field_path, val, warnings);
            }
            continue;
        }
        warnings.push(FieldWarning {
            path: field_path,
            suggestion: suggest_field(schema, key, key.chars().count()),
        });
    }
}

/// Closest known field to `key` within edit distance 1..=2, else `None`.
pub(crate) fn suggest_field(
    schema: &ResourceSchema,
    key: &str,
    key_len: usize,
) -> Option<&'static str> {
    schema
        .fields
        .iter()
        .copied()
        .filter(|known| known.chars().count().abs_diff(key_len) <= 2)
        .map(|known| (known, edit_distance(key, known)))
        .filter(|(_, d)| *d > 0 && *d <= 2)
        .min_by_key(|(_, d)| *d)
        .map(|(k, _)| k)
}

/// Best-effort unrecognized-field warnings for the top-level resource arrays of
/// a static YAML document (etcd/Admin resources are checked at decode time).
pub(crate) fn warn_static_resources(graph: &JsonValue) {
    for key in ["routes", "upstreams", "services", "global_rules", "ssls"] {
        if let Some(arr) = graph.get(key).and_then(|v| v.as_array()) {
            for elem in arr {
                warn_unrecognized_fields(key, elem);
            }
        }
    }
}
