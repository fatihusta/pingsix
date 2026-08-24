//! Shared implementation for the gzip and brotli compression plugins.
//!
//! Both plugins configure Pingora's `ResponseCompression` module identically;
//! only the algorithm, plugin name, priority, and compression-level range
//! differ. The external plugin schemas and names stay separate (see
//! `gzip`/`brotli`), while the internal behavior lives here once.
//!
//! Pingora 0.8's `ResponseCompression` exposes only level and decompression.
//! APISIX behavior fields that cannot be enforced are rejected rather than
//! accepted as misleading no-ops.

use std::sync::Arc;

use async_trait::async_trait;
use pingora::{
    modules::http::compression::ResponseCompression, protocols::http::compression::Algorithm,
};
use pingora_error::Result;
use pingora_proxy::Session;
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::core::{PluginPhases, ProxyContext, ProxyError, ProxyPlugin, ProxyResult};

/// Compression plugin parameterized by algorithm and level range.
pub(crate) struct CompressionPlugin {
    name: &'static str,
    priority: i32,
    algorithm: Algorithm,
    comp_level: u32,
    decompression: bool,
}

#[derive(Debug)]
struct ParsedConfig {
    comp_level: u32,
    decompression: bool,
}

impl CompressionPlugin {
    /// Build a compression plugin from its JSON configuration.
    ///
    /// `plugin_label` is used in error messages so a rejected config names the
    /// actual plugin (gzip/brotli) that owns it.
    pub fn build(
        name: &'static str,
        priority: i32,
        algorithm: Algorithm,
        cfg: JsonValue,
        plugin_label: &str,
        min_level: u32,
        max_level: u32,
    ) -> ProxyResult<Arc<dyn ProxyPlugin>> {
        let parsed = parse_config(cfg, plugin_label, algorithm, min_level, max_level)?;

        Ok(Arc::new(Self {
            name,
            priority,
            algorithm,
            comp_level: parsed.comp_level,
            decompression: parsed.decompression,
        }))
    }
}

#[derive(Default, Deserialize)]
struct RawConfig {
    #[serde(default)]
    comp_level: Option<u32>,
    #[serde(default)]
    decompression: bool,
}

/// Deserialize and validate the shared compression config.
///
/// Known behavior-bearing fields unsupported by Pingora 0.8 are rejected.
/// Other unknown fields retain the project's existing forward-compatibility behavior.
fn parse_config(
    cfg: JsonValue,
    plugin_label: &str,
    _algorithm: Algorithm,
    min_level: u32,
    max_level: u32,
) -> ProxyResult<ParsedConfig> {
    const UNSUPPORTED: [&str; 8] = [
        "types",
        "min_length",
        "http_version",
        "buffers",
        "vary",
        "mode",
        "lgwin",
        "lgblock",
    ];
    if let Some(field) = UNSUPPORTED.iter().find(|field| cfg.get(**field).is_some()) {
        return Err(ProxyError::validation_error(format!(
            "{plugin_label} field '{field}' is not supported by Pingora 0.8 response compression"
        )));
    }

    let raw: RawConfig = serde_json::from_value(cfg).map_err(|e| {
        ProxyError::serialization_error(format!("Invalid {plugin_label} plugin config"), e)
    })?;

    let comp_level = raw.comp_level.unwrap_or(1);
    if !(min_level..=max_level).contains(&comp_level) {
        return Err(ProxyError::Configuration(format!(
            "{plugin_label} comp_level must be in {min_level}..={max_level}, got {comp_level}"
        )));
    }

    Ok(ParsedConfig {
        comp_level,
        decompression: raw.decompression,
    })
}

#[async_trait]
impl ProxyPlugin for CompressionPlugin {
    fn name(&self) -> &str {
        self.name
    }

    fn priority(&self) -> i32 {
        self.priority
    }
    fn phases(&self) -> PluginPhases {
        PluginPhases::EARLY_REQUEST
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        let Some(resp_compression) = session
            .downstream_modules_ctx
            .get_mut::<ResponseCompression>()
        else {
            return Ok(());
        };

        resp_compression.adjust_algorithm_level(self.algorithm, self.comp_level);

        resp_compression.adjust_decompression(self.decompression);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(
        label: &str,
        algorithm: Algorithm,
        min: u32,
        max: u32,
        cfg: JsonValue,
    ) -> ParsedConfig {
        parse_config(cfg, label, algorithm, min, max).unwrap()
    }

    #[test]
    fn rejects_out_of_range_level() {
        let err = CompressionPlugin::build(
            "gzip",
            995,
            Algorithm::Gzip,
            serde_json::json!({ "comp_level": 99 }),
            "gzip",
            0,
            9,
        )
        .err()
        .expect("out-of-range level must be rejected")
        .to_string();
        assert!(
            err.contains("gzip comp_level must be in 0..=9"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn accepts_boundary_levels_and_defaults() {
        let low = CompressionPlugin::build(
            "gzip",
            995,
            Algorithm::Gzip,
            serde_json::json!({ "comp_level": 0 }),
            "gzip",
            0,
            9,
        )
        .unwrap();
        assert_eq!(low.name(), "gzip");

        let high = CompressionPlugin::build(
            "brotli",
            996,
            Algorithm::Brotli,
            serde_json::json!({ "comp_level": 11 }),
            "brotli",
            0,
            11,
        )
        .unwrap();
        assert_eq!(high.name(), "brotli");

        // Default level is 1; unknown fields stay tolerated like before.
        CompressionPlugin::build(
            "gzip",
            995,
            Algorithm::Gzip,
            serde_json::json!({ "future_field": true }),
            "gzip",
            0,
            9,
        )
        .unwrap();
    }

    #[test]
    fn defaults_are_applied() {
        let parsed = parse("gzip", Algorithm::Gzip, 0, 9, serde_json::json!({}));
        assert_eq!(parsed.comp_level, 1);
        assert!(!parsed.decompression);
    }

    #[test]
    fn unenforceable_apisix_fields_are_rejected() {
        for field in [
            "types",
            "min_length",
            "http_version",
            "buffers",
            "vary",
            "mode",
            "lgwin",
            "lgblock",
        ] {
            let mut cfg = serde_json::Map::new();
            cfg.insert(field.to_string(), JsonValue::Bool(true));
            let err = parse_config(JsonValue::Object(cfg), "gzip", Algorithm::Gzip, 0, 9)
                .expect_err("unsupported behavior must fail closed");
            assert!(err.to_string().contains(field), "{err}");
        }
    }
}
