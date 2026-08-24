//! Physical etcd key namespace handling: prefix canonicalization, the
//! graph-generation guard key/protocol constants, and physical→logical
//! resource key mapping.

use crate::proxy::graph_mutation::{ResourceKey, ResourceKind, StoreError};

/// Normalize an etcd namespace so range queries cannot leak across sibling prefixes.
///
/// `/apisix` and `/apisix/` both become `/apisix/`, which excludes `/apisix-other/...`.
pub fn canonicalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("{trimmed}/")
    }
}

/// Reserved metadata key serializing supported Admin mutations of a resource graph.
pub const GRAPH_REVISION_KEY: &str = ".pingsix_graph_revision";
/// Guard value identifies the transaction protocol. Changing this requires an
/// explicit mixed-version migration; old single-key writers are unsupported.
pub const GRAPH_PROTOCOL_VERSION: &[u8] = b"pingsix-graph-v1";

/// Accept the current graph guard value plus the legacy transition value `1`.
pub(super) fn validate_guard_value(value: &[u8]) -> Result<(), StoreError> {
    if value != GRAPH_PROTOCOL_VERSION && value != b"1" {
        return Err(StoreError::UnsupportedProtocol);
    }
    Ok(())
}

/// Whether an etcd key is internal control-plane metadata (dotted leaf segment).
pub(super) fn is_metadata_key(key: &[u8]) -> bool {
    std::str::from_utf8(key)
        .ok()
        .and_then(|key| key.rsplit('/').next())
        .is_some_and(|leaf| leaf.starts_with('.'))
}

/// Map a physical etcd key to a logical [`ResourceKey`] under the canonical prefix.
pub(super) fn physical_key_to_resource_key(
    key: &[u8],
    canonical_prefix: &str,
) -> Result<ResourceKey, String> {
    let key = std::str::from_utf8(key).map_err(|e| format!("Key is not valid UTF-8: {e}"))?;
    let rest = key
        .strip_prefix(canonical_prefix)
        .ok_or_else(|| format!("Key '{key}' is outside etcd namespace '{canonical_prefix}'"))?;
    let (kind, id) = rest
        .split_once('/')
        .ok_or_else(|| format!("Invalid key format under namespace: {key}"))?;
    if kind.is_empty() || id.is_empty() || id.contains('/') {
        return Err(format!("Invalid key format under namespace: {key}"));
    }
    let kind = ResourceKind::parse(kind).map_err(|e| e.to_string())?;
    ResourceKey::new(kind, id).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_prefix_adds_trailing_slash_and_isolates_siblings() {
        assert_eq!(canonicalize_prefix("/apisix"), "/apisix/");
        assert_eq!(canonicalize_prefix("/apisix/"), "/apisix/");
        assert_eq!(canonicalize_prefix("/apisix///"), "/apisix/");
        let canonical = canonicalize_prefix("/apisix");
        assert!(!"/apisix-other/routes/1".starts_with(&canonical));
        assert!("/apisix/routes/1".starts_with(&canonical));
    }

    #[test]
    fn metadata_key_detection_matches_dotted_leaves() {
        assert!(is_metadata_key(b"/apisix/.pingsix_graph_revision"));
        assert!(is_metadata_key(b"/apisix/.ingress_sync_barrier"));
        assert!(!is_metadata_key(b"/apisix/routes/1"));
        assert!(is_metadata_key(b"/apisix/routes/.hidden"));
    }

    #[test]
    fn physical_key_maps_to_resource_key_under_namespace() {
        let prefix = "/pingsix/";
        let upstream = physical_key_to_resource_key(b"/pingsix/upstreams/u1", prefix).unwrap();
        assert_eq!(upstream.kind, ResourceKind::Upstream);
        assert_eq!(upstream.id, "u1");
        let ssl = physical_key_to_resource_key(b"/pingsix/ssls/t1", prefix).unwrap();
        assert_eq!(ssl.kind, ResourceKind::Ssl);
        assert_eq!(ssl.id, "t1");
        assert_eq!(
            physical_key_to_resource_key(b"/pingsix/routes/1", prefix)
                .unwrap()
                .logical_path(),
            "routes/1"
        );
    }

    #[test]
    fn physical_key_rejects_foreign_nested_and_unknown() {
        let prefix = "/pingsix/";
        assert!(physical_key_to_resource_key(b"/pingsix-other/routes/1", prefix).is_err());
        assert!(physical_key_to_resource_key(b"/pingsix/routes", prefix).is_err());
        assert!(physical_key_to_resource_key(b"/pingsix/routes/a/b", prefix).is_err());
        assert!(physical_key_to_resource_key(b"/pingsix/certificates/1", prefix).is_err());
    }

    #[test]
    fn guard_value_accepts_current_and_legacy() {
        assert!(validate_guard_value(GRAPH_PROTOCOL_VERSION).is_ok());
        assert!(validate_guard_value(b"1").is_ok());
        assert!(matches!(
            validate_guard_value(b"pingsix-graph-v2"),
            Err(StoreError::UnsupportedProtocol)
        ));
    }
}
