//! Client request body size control plugin, APISIX `client-control` compatible.
//!
//! Limits the maximum request body size in bytes (APISIX `max_body_size`).
//! A `Content-Length` header larger than the limit is rejected immediately in
//! the request phase; chunked or lying bodies are caught by counting bytes as
//! they stream through `request_body_filter` (Guide L40 dual-channel defense).
//!
//! The streaming rejection returns `ErrorType::Custom("PayloadTooLarge")`,
//! which `HttpService::fail_to_proxy` maps to HTTP 413.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingora_error::{Error, ErrorType, Result};
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    core::{PluginPhases, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::config::parse_and_validate_plugin_config,
    utils::response::ResponseBuilder,
};

pub const PLUGIN_NAME: &str = "client-control";

/// APISIX `client-control` runs at priority 22000 (before request-id 12015).
const PRIORITY: i32 = 22000;

/// Context key accumulating streamed request body bytes for this request.
const CTX_KEY_BODY_BYTES: &str = "pingsix_client_control_body_bytes";

/// Sentinel error type matched by `fail_to_proxy` to emit 413.
pub const ERROR_PAYLOAD_TOO_LARGE: &str = "PayloadTooLarge";

/// Creates a `client-control` plugin instance from JSON configuration.
pub fn create_client_control_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginClientControl { config }))
}

#[derive(Debug, Default, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Maximum request body size in bytes. `0` disables the check.
    #[serde(default)]
    #[validate(range(min = 0))]
    max_body_size: u64,
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid client-control plugin config")?;
        Ok(config)
    }
}

pub struct PluginClientControl {
    config: PluginConfig,
}

#[async_trait]
impl ProxyPlugin for PluginClientControl {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }
    fn phases(&self) -> PluginPhases {
        PluginPhases::REQUEST | PluginPhases::REQUEST_BODY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        let limit = self.config.max_body_size;
        if limit == 0 {
            return Ok(false);
        }

        // Fast path: trust a declared Content-Length and reject immediately.
        if let Some(value) = session
            .req_header()
            .headers
            .get(http::header::CONTENT_LENGTH)
        {
            if let Ok(len_str) = value.to_str() {
                if let Ok(len) = len_str.parse::<u64>() {
                    if len > limit {
                        log::debug!("client-control: Content-Length {len} exceeds limit {limit}");
                        ResponseBuilder::send_proxy_error(
                            session,
                            StatusCode::PAYLOAD_TOO_LARGE,
                            None,
                            None,
                        )
                        .await?;
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        let limit = self.config.max_body_size;
        if limit == 0 {
            return Ok(());
        }
        if let Some(bytes) = body {
            let accumulated =
                ctx.get::<u64>(CTX_KEY_BODY_BYTES).copied().unwrap_or(0) + bytes.len() as u64;
            ctx.set(CTX_KEY_BODY_BYTES, accumulated);
            if accumulated > limit {
                log::debug!("client-control: streamed {accumulated} bytes exceeds limit {limit}");
                return Err(Error::explain(
                    ErrorType::Custom(ERROR_PAYLOAD_TOO_LARGE),
                    format!("request body exceeded max_body_size {limit}"),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_disabled() {
        let config = PluginConfig::try_from(serde_json::json!({})).unwrap();
        assert_eq!(config.max_body_size, 0);
    }

    #[test]
    fn config_accepts_zero_and_positive() {
        assert_eq!(
            PluginConfig::try_from(serde_json::json!({ "max_body_size": 0 }))
                .unwrap()
                .max_body_size,
            0
        );
        assert_eq!(
            PluginConfig::try_from(serde_json::json!({ "max_body_size": 1024 }))
                .unwrap()
                .max_body_size,
            1024
        );
    }

    #[test]
    fn config_rejects_negative() {
        assert!(PluginConfig::try_from(serde_json::json!({ "max_body_size": -1 })).is_err());
    }

    #[test]
    fn error_sentinel_is_stable() {
        // The fail_to_proxy mapping depends on this exact string.
        assert_eq!(ERROR_PAYLOAD_TOO_LARGE, "PayloadTooLarge");
    }
}
