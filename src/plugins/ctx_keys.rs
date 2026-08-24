//! Per-instance `ProxyContext` keys for plugins that stash request state.
//!
//! Several plugins keep per-request counters, buffers, or flags in the
//! request context. When the same plugin is attached at both the global and
//! the route layer, both instances run within one request and one context, so
//! every instance needs its own key namespace. These helpers mint those keys
//! from a single process-wide counter plus the plugin-owned prefix, keeping
//! the key format (`{prefix}{instance_id}`) uniform across plugins instead of
//! each plugin re-deriving the same scaffolding.

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a unique per-instance context key with the given prefix, so a
/// global and a route instance of the same plugin never share ctx slots.
pub(crate) fn next_instance_ctx_key(prefix: &str) -> String {
    instance_ctx_key(prefix, NEXT_INSTANCE_ID.fetch_add(1, Ordering::Relaxed))
}

/// Format the context key for a concrete instance id (test-stable).
pub(crate) fn instance_ctx_key(prefix: &str, instance_id: u64) -> String {
    format!("{prefix}{instance_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_ctx_keys_keep_the_prefix_and_share_one_counter() {
        assert_eq!(
            instance_ctx_key("pingsix_limit_conn_guard_", 99),
            "pingsix_limit_conn_guard_99"
        );
        let first = next_instance_ctx_key("pingsix_test_");
        let second = next_instance_ctx_key("pingsix_test_");
        assert!(first.starts_with("pingsix_test_"));
        assert_ne!(first, second);
    }
}
