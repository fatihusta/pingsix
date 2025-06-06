use std::sync::Arc;

use async_trait::async_trait;
use http::{header, StatusCode};
use pingora_error::{ErrorType::ReadError, OrErr, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use validator::Validate;

use crate::{proxy::ProxyContext, utils::request};

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "key-auth";
const PRIORITY: i32 = 2500;
const DEFAULT_HEADER: &str = "apikey";
const DEFAULT_QUERY: &str = "apikey";

/// Creates a Key Auth plugin instance with the given configuration.
/// This plugin authenticates requests by matching an API key in the HTTP header or query parameter
/// against a configured key. If the key is invalid or missing, it returns a `401 Unauthorized` response.
pub fn create_key_auth_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig =
        serde_yaml::from_value(cfg).or_err_with(ReadError, || "Invalid key auth plugin config")?;

    config
        .validate()
        .or_err_with(ReadError, || "Invalid key auth plugin config")?;

    Ok(Arc::new(PluginKeyAuth { config }))
}

/// Configuration for the Key Auth plugin.
#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// HTTP header field name containing the API key (default: `apikey`).
    #[serde(default = "PluginConfig::default_header")]
    header: String,

    /// Query parameter name containing the API key (default: `apikey`).
    #[serde(default = "PluginConfig::default_query")]
    query: String,

    /// The API key to match against. Must be non-empty.
    #[validate(length(min = 1))]
    key: String,

    /// Whether to remove the API key from headers or query parameters after validation (default: false).
    #[serde(default = "PluginConfig::default_hide_credentials")]
    hide_credentials: bool,
}

impl PluginConfig {
    fn default_header() -> String {
        DEFAULT_HEADER.to_string()
    }

    fn default_query() -> String {
        DEFAULT_QUERY.to_string()
    }

    fn default_hide_credentials() -> bool {
        false
    }
}

/// Source of the API key (header, query, or none).
#[derive(PartialEq)]
enum KeySource {
    Header,
    Query,
    None,
}

/// Key Auth plugin implementation.
/// Validates API keys from HTTP headers or query parameters.
/// Note: For production environments, consider using more secure mechanisms like HMAC signatures
/// or integration with a consumer management system instead of fixed key matching.
pub struct PluginKeyAuth {
    config: PluginConfig,
}

#[async_trait]
impl ProxyPlugin for PluginKeyAuth {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut ProxyContext) -> Result<bool> {
        // Try to extract key from header or query
        let (value, source) =
            request::get_req_header_value(session.req_header(), &self.config.header)
                .map(|val| (val, KeySource::Header))
                .or_else(|| {
                    request::get_query_value(session.req_header(), &self.config.query)
                        .map(|val| (val, KeySource::Query))
                })
                .unwrap_or(("", KeySource::None));

        // Match key
        if value.is_empty() || value != self.config.key {
            let msg = "Invalid user authorization";
            let mut header = ResponseHeader::build(StatusCode::UNAUTHORIZED, None)?;
            header.insert_header(header::CONTENT_LENGTH, msg.len().to_string())?;
            header.insert_header(header::WWW_AUTHENTICATE, "ApiKey error=\"invalid_key\"")?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session.write_response_body(Some(msg.into()), true).await?;
            return Ok(true);
        }

        // Hide credentials if configured
        if self.config.hide_credentials {
            match source {
                KeySource::Header => {
                    session.req_header_mut().remove_header(&self.config.header);
                }
                KeySource::Query => {
                    let _ = request::remove_query_from_header(
                        session.req_header_mut(),
                        &self.config.query,
                    );
                }
                KeySource::None => {}
            }
        }

        Ok(false)
    }
}
