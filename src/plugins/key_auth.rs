use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::Result;
use pingora_proxy::Session;
use pingsix_macros::EncryptFields;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    core::{
        constant_time_digest_eq, secret_digest, FilterVerdict, ProxyContext, ProxyError,
        ProxyPlugin, ProxyResult, Rejection,
    },
    plugins::config::{parse_and_validate_plugin_config, validate_apisix_realm},
    utils::{request, response::content_type},
};

pub const PLUGIN_NAME: &str = "key-auth";
const PRIORITY: i32 = 2500;

/// Default header name for API key
const DEFAULT_API_KEY_HEADER: &str = "apikey";

/// Creates a Key Auth plugin instance with the given configuration.
/// This plugin authenticates requests by matching an API key in the HTTP header or query parameter
/// against configured keys. If the key is invalid or missing, it returns a `401 Unauthorized` response.
pub fn create_key_auth_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    let key_digests = config
        .get_valid_keys()
        .into_iter()
        .map(|key| secret_digest(key))
        .collect();
    Ok(Arc::new(PluginKeyAuth {
        config,
        key_digests,
    }))
}

/// Configuration for the Key Auth plugin.
#[derive(Default, Debug, Serialize, Deserialize, Validate, EncryptFields)]
#[encrypt_fields(export)]
struct PluginConfig {
    /// HTTP header field name containing the API key (default: `apikey`).
    #[serde(default = "PluginConfig::default_header")]
    header: String,

    /// Query parameter name containing the API key. Empty (the default) disables query auth.
    #[serde(default = "PluginConfig::default_query")]
    query: String,

    /// The API key to match against. Must be non-empty when present.
    /// For backward compatibility, single key as string.
    /// No `length(min = 1)` here — the struct-level TryFrom ensures
    /// that at least one of `key` or `keys` is non-empty.
    #[encrypt]
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,

    /// Multiple API keys to match against. Supports key rotation.
    /// Takes precedence over single `key` if both are provided.
    /// No `length(min = 1)` here — the struct-level validator ensures
    /// that at least one of `key` or `keys` is non-empty.
    #[encrypt]
    #[serde(default)]
    keys: Vec<String>,

    /// Whether to remove the API key from headers or query parameters after validation (default: false).
    #[serde(default = "PluginConfig::default_hide_credentials")]
    hide_credentials: bool,

    /// Realm advertised in the `WWW-Authenticate` challenge. APISIX's default
    /// would be `key`, but pingsix keeps its legacy `ApiKey error="invalid_key"`
    /// challenge unless a realm is configured explicitly.
    #[serde(default)]
    realm: Option<String>,
}

impl PluginConfig {
    fn default_header() -> String {
        DEFAULT_API_KEY_HEADER.to_string()
    }

    fn default_query() -> String {
        String::new()
    }

    fn default_hide_credentials() -> bool {
        false
    }

    /// Get all valid keys (combines single key and multiple keys)
    fn get_valid_keys(&self) -> Vec<&String> {
        if !self.keys.is_empty() {
            self.keys.iter().collect()
        } else if let Some(ref key) = self.key {
            vec![key]
        } else {
            vec![]
        }
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Failed to parse key auth plugin config")?;
        if let Some(realm) = config.realm.as_deref() {
            validate_apisix_realm(realm).map_err(ProxyError::from)?;
        }

        // Custom validation: at least one of `key` or `keys` must be non-empty.
        if config.get_valid_keys().is_empty() {
            return Err(ProxyError::validation_error(
                "key-auth plugin requires at least one of 'key' or 'keys' to be non-empty",
            ));
        }

        Ok(config)
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
/// Validates API keys from HTTP headers or query parameters using constant-time comparison.
/// Supports multiple keys for key rotation scenarios.
/// Note: For production environments, consider using more secure mechanisms like HMAC signatures
/// or integration with a consumer management system instead of fixed key matching.
pub struct PluginKeyAuth {
    config: PluginConfig,
    key_digests: Vec<[u8; 32]>,
}

#[async_trait]
impl ProxyPlugin for PluginKeyAuth {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        // Try to extract key from header or query
        let (value, source) =
            request::get_req_header_value(session.req_header(), &self.config.header)
                .map(|val| (val, KeySource::Header))
                .or_else(|| {
                    (!self.config.query.is_empty())
                        .then(|| request::get_query_value(session.req_header(), &self.config.query))
                        .flatten()
                        .map(|val| (val, KeySource::Query))
                })
                .unwrap_or(("", KeySource::None));

        if source != KeySource::None {
            ctx.mark_request_has_credentials();
        }

        // Validate key using constant-time comparison
        if value.is_empty() || !self.is_valid_key(value) {
            return Ok(FilterVerdict::Reject(
                Rejection::new(StatusCode::UNAUTHORIZED)
                    .with_body("Invalid user authorization")
                    .with_content_type(content_type::TEXT_PLAIN)
                    .with_header("WWW-Authenticate", self.build_challenge()),
            ));
        }

        // Record the verified credential for shared-cache consumer
        // isolation before it can be stripped from the upstream request.
        ctx.note_request_credential(value);

        // Hide credentials if configured
        if self.config.hide_credentials {
            match source {
                KeySource::Header => {
                    session.req_header_mut().remove_header(&self.config.header);
                }
                KeySource::Query => {
                    request::remove_query_from_header(session.req_header_mut(), &self.config.query)
                        .map_err(|e| {
                            ProxyError::validation_error(format!(
                                "Failed to hide API key query credential: {e}"
                            ))
                        })?;
                }
                KeySource::None => {}
            }
        }

        Ok(FilterVerdict::Continue)
    }
}

impl PluginKeyAuth {
    fn build_challenge(&self) -> String {
        match self.config.realm.as_deref() {
            Some(realm) => format!("apikey realm=\"{realm}\""),
            None => "ApiKey error=\"invalid_key\"".to_string(),
        }
    }

    /// Validate the provided key against configured keys using constant-time comparison
    fn is_valid_key(&self, provided_key: &str) -> bool {
        let provided_digest = secret_digest(provided_key);
        let mut matched = 0u8;

        // Compare every configured digest to avoid leaking which rotation key matched.
        for valid_key_digest in &self.key_digests {
            matched |= u8::from(constant_time_digest_eq(&provided_digest, valid_key_digest));
        }

        matched != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::encryption::KeyringService;
    use crate::utils::encryption::{EncryptFields, SecretOp, CIPHERTEXT_PREFIX};

    #[test]
    fn transform_secrets_touches_key_and_keys_not_header() {
        let mut cfg = serde_json::json!({
            "header": "apikey",
            "key": "single-secret",
            "keys": ["a", "b"],
        });
        // Encryption disabled → plaintext pass-through.
        PluginConfig::transform_secrets(&mut cfg, SecretOp::Decrypt, &KeyringService::disabled())
            .unwrap();
        assert_eq!(cfg["header"], "apikey");
        assert_eq!(cfg["key"], "single-secret");
        assert_eq!(cfg["keys"], serde_json::json!(["a", "b"]));
    }

    #[test]
    fn transform_secrets_visits_keys_array_elements() {
        let mut cfg = serde_json::json!({
            "header": "apikey",
            "keys": [format!("{CIPHERTEXT_PREFIX}deadbeef"), "plain"],
        });
        // Ciphertext with encryption disabled proves the array walk ran.
        let err = PluginConfig::transform_secrets(
            &mut cfg,
            SecretOp::Decrypt,
            &KeyringService::disabled(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("data_encryption is disabled")
                || err.to_string().contains("Encrypted value"),
            "{err}"
        );
    }

    #[test]
    fn secrets_transform_const_matches_trait_method() {
        let mut via_const = serde_json::json!({ "keys": ["s"] });
        let mut via_trait = via_const.clone();
        (SECRETS_TRANSFORM)(
            &mut via_const,
            SecretOp::Decrypt,
            &KeyringService::disabled(),
        )
        .unwrap();
        PluginConfig::transform_secrets(
            &mut via_trait,
            SecretOp::Decrypt,
            &KeyringService::disabled(),
        )
        .unwrap();
        assert_eq!(via_const, via_trait);
    }

    #[test]
    fn apisix_consumer_fields_are_ignored() {
        // APISIX uses consumer objects for credentials; PingSIX keeps them in
        // the plugin config. Unknown fields such as `anonymous_consumer` are
        // tolerated and ignored — authentication stays enforced with the
        // configured keys.
        let config = PluginConfig::try_from(serde_json::json!({
            "keys": ["secret"],
            "anonymous_consumer": "anonymous"
        }))
        .expect("unknown fields are tolerated");
        assert_eq!(config.get_valid_keys(), vec![&"secret".to_string()]);
    }

    #[test]
    fn query_auth_is_disabled_by_default() {
        let config = PluginConfig::try_from(serde_json::json!({ "keys": ["secret"] })).unwrap();
        assert!(config.query.is_empty());
    }

    #[test]
    fn query_auth_can_be_explicitly_enabled() {
        let config =
            PluginConfig::try_from(serde_json::json!({ "keys": ["secret"], "query": "apikey" }))
                .unwrap();
        assert_eq!(config.query, "apikey");
    }

    #[test]
    fn realm_is_optional_and_defaults_to_legacy_challenge() {
        let config = PluginConfig::try_from(serde_json::json!({ "keys": ["secret"] })).unwrap();
        assert_eq!(config.realm, None);

        let plugin = PluginKeyAuth {
            config,
            key_digests: vec![secret_digest("secret")],
        };
        assert_eq!(plugin.build_challenge(), "ApiKey error=\"invalid_key\"");
    }

    #[test]
    fn custom_realm_is_used_in_challenge() {
        let config =
            PluginConfig::try_from(serde_json::json!({ "keys": ["secret"], "realm": "api" }))
                .unwrap();
        let plugin = PluginKeyAuth {
            config,
            key_digests: vec![secret_digest("secret")],
        };
        assert_eq!(plugin.build_challenge(), "apikey realm=\"api\"");
    }

    #[test]
    fn invalid_realms_are_rejected() {
        for invalid in ["", "a\"b", "a\\b", "caf\u{e9}"] {
            let err =
                PluginConfig::try_from(serde_json::json!({ "keys": ["secret"], "realm": invalid }))
                    .expect_err("invalid realm must be rejected");
            assert!(err.to_string().contains("realm"), "{err}");
        }

        let long_realm = "a".repeat(129);
        let err =
            PluginConfig::try_from(serde_json::json!({ "keys": ["secret"], "realm": long_realm }))
                .expect_err("overlong realm must be rejected");
        assert!(err.to_string().contains("realm"), "{err}");
    }
}
