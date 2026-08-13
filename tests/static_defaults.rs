//! Static YAML defaults must be applied before the resource graph is built.
//!
//! Asserts that [`EffectiveDefaults::from_pingsix`] is the production path
//! plugins and upstreams use at construction — not process-global OnceCells.

use pingsix::config::{CacheDefaults, Defaults, EffectiveDefaults, Pingsix, Timeout};
use pingsix::plugins::cache::resolved_max_file_size_bytes;

#[test]
fn static_cache_default_applies_before_plugin_build() {
    let defaults = Defaults {
        upstream_timeout: Some(Timeout {
            connect: 5,
            send: 5,
            read: 5,
        }),
        dns_resolution_timeout: 3,
        dns_refresh_interval: Some(7),
        cache: Some(CacheDefaults {
            max_memory_bytes: 64 * 1024 * 1024,
            default_max_object_bytes: 10_485_760,
        }),
    };
    let pingsix = Pingsix {
        defaults: Some(defaults),
        ..Default::default()
    };
    let effective = EffectiveDefaults::from_pingsix(&pingsix);

    assert_eq!(effective.cache.default_max_object_bytes, 10_485_760);

    let size = resolved_max_file_size_bytes(
        serde_json::json!({ "ttl": 60 }),
        effective.cache.default_max_object_bytes,
    )
    .unwrap();
    assert_eq!(
        size, 10_485_760,
        "cache plugin must bake in YAML default_max_object_bytes, not the 1 MiB fallback"
    );

    assert_eq!(
        effective.upstream_timeout,
        Some(Timeout {
            connect: 5,
            send: 5,
            read: 5,
        })
    );

    assert_eq!(effective.dns_resolution_timeout, 3);
    assert_eq!(effective.dns_refresh_interval, Some(7));
}
