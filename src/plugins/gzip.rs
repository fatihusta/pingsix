use std::sync::Arc;

use pingora::protocols::http::compression::Algorithm;
use serde_json::Value as JsonValue;

use crate::core::{ProxyPlugin, ProxyResult};

use super::compression::CompressionPlugin;

pub const PLUGIN_NAME: &str = "gzip";
const PRIORITY: i32 = 995;

/// Creates a Gzip plugin instance with the given configuration.
///
/// Schema and plugin name stay here; the shared implementation lives in
/// [`CompressionPlugin`].
pub fn create_gzip_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    CompressionPlugin::build(PLUGIN_NAME, PRIORITY, Algorithm::Gzip, cfg, "gzip", 0, 9)
}

/// `PLUGIN_META::validate` capability: parse and validate the shared
/// compression config WITHOUT constructing the plugin.
pub fn validate_gzip_config(cfg: &JsonValue) -> ProxyResult<()> {
    super::compression::validate_config(cfg, "gzip", Algorithm::Gzip, 0, 9)
}
