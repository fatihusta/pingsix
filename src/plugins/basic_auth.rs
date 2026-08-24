use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use http::{header, StatusCode};
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

pub const PLUGIN_NAME: &str = "basic-auth";
const PRIORITY: i32 = 2520;

/// Creates a Basic Auth plugin instance.
pub fn create_basic_auth_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    let username_digest = secret_digest(&config.username);
    let password_digest = secret_digest(&config.password);
    Ok(Arc::new(PluginBasicAuth {
        config,
        username_digest,
        password_digest,
    }))
}

#[derive(Debug, Serialize, Deserialize, Validate, EncryptFields)]
#[encrypt_fields(export)]
struct PluginConfig {
    #[validate(length(min = 1))]
    username: String,
    #[encrypt]
    #[validate(length(min = 1))]
    password: String,
    #[serde(default)]
    hide_credentials: bool,
    /// Realm advertised in the `WWW-Authenticate` challenge. APISIX's default
    /// would be `basic`, but pingsix keeps its legacy `realm="pingsix"`
    /// challenge unless a realm is configured explicitly.
    #[serde(default)]
    realm: Option<String>,
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Failed to parse basic auth plugin config")?;
        if let Some(realm) = config.realm.as_deref() {
            validate_apisix_realm(realm).map_err(ProxyError::from)?;
        }
        Ok(config)
    }
}

pub struct PluginBasicAuth {
    config: PluginConfig,
    username_digest: [u8; 32],
    password_digest: [u8; 32],
}

impl PluginBasicAuth {
    fn build_challenge(&self) -> String {
        match self.config.realm.as_deref() {
            Some(realm) => format!("Basic realm=\"{realm}\""),
            None => "Basic realm=\"pingsix\"".to_string(),
        }
    }

    /// Validates Basic Authentication credentials using constant-time comparison.
    ///
    /// This method:
    /// 1. Checks for "Basic " prefix (case-insensitive)
    /// 2. Decodes the Base64-encoded credentials
    /// 3. Splits username and password at the first colon
    /// 4. Uses constant-time comparison to prevent timing attacks
    fn validate_credentials(&self, auth_value: &str) -> bool {
        // 1. Check prefix without allocating a lowercased copy.
        if auth_value.len() < 6 || !auth_value[..6].eq_ignore_ascii_case("basic ") {
            return false;
        }

        // 2. Decode Base64
        let credential_part = &auth_value[6..];
        let Ok(decoded_bytes) = general_purpose::STANDARD.decode(credential_part) else {
            return false;
        };

        let Ok(decoded_str) = String::from_utf8(decoded_bytes) else {
            return false;
        };

        // 3. Separate username:password
        let Some((user, pass)) = decoded_str.split_once(':') else {
            return false;
        };

        // 4. Hash each supplied value once and compare against configuration
        // digests in constant time.
        constant_time_digest_eq(&secret_digest(user), &self.username_digest)
            & constant_time_digest_eq(&secret_digest(pass), &self.password_digest)
    }
}

#[async_trait]
impl ProxyPlugin for PluginBasicAuth {
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
        let auth_header =
            request::get_req_header_value(session.req_header(), header::AUTHORIZATION.as_str());

        if auth_header.is_some() {
            ctx.mark_request_has_credentials();
        }

        let is_valid = match auth_header {
            Some(val) => self.validate_credentials(val),
            None => false,
        };

        if !is_valid {
            // Return 401 and include the standard Basic challenge header
            return Ok(FilterVerdict::Reject(
                Rejection::new(StatusCode::UNAUTHORIZED)
                    .with_body("Invalid user authorization")
                    .with_content_type(content_type::TEXT_PLAIN)
                    .with_header("WWW-Authenticate", self.build_challenge()),
            ));
        }

        // Record the verified credential for shared-cache consumer
        // isolation before it can be stripped from the upstream request.
        if let Some(credential) = auth_header {
            ctx.note_request_credential(credential);
        }

        // Hide credentials by removing the Authorization header before forwarding upstream
        if self.config.hide_credentials {
            session
                .req_header_mut()
                .remove_header(&header::AUTHORIZATION);
        }

        Ok(FilterVerdict::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::encryption::KeyringService;
    use crate::utils::encryption::{EncryptFields, SecretOp};

    fn build_plugin(username: &str, password: &str) -> PluginBasicAuth {
        PluginBasicAuth {
            config: PluginConfig {
                username: username.to_string(),
                password: password.to_string(),
                hide_credentials: false,
                realm: None,
            },
            username_digest: secret_digest(username),
            password_digest: secret_digest(password),
        }
    }

    #[test]
    fn transform_secrets_touches_password_not_username() {
        let mut cfg = serde_json::json!({
            "username": "demo",
            "password": "s3cret",
        });
        // Encryption disabled → plaintext pass-through.
        PluginConfig::transform_secrets(&mut cfg, SecretOp::Decrypt, &KeyringService::disabled())
            .unwrap();
        assert_eq!(cfg["username"], "demo");
        assert_eq!(cfg["password"], "s3cret");
    }

    #[test]
    fn validate_credentials_accepts_valid_pairs() {
        let plugin = build_plugin("demo", "s3cret");
        let header = format!("Basic {}", general_purpose::STANDARD.encode("demo:s3cret"));
        assert!(plugin.validate_credentials(&header));
    }

    #[test]
    fn realm_is_optional_and_defaults_to_legacy_challenge() {
        let config = PluginConfig::try_from(serde_json::json!({
            "username": "demo",
            "password": "s3cret",
        }))
        .unwrap();
        assert_eq!(config.realm, None);

        let plugin = build_plugin("demo", "s3cret");
        assert_eq!(plugin.build_challenge(), "Basic realm=\"pingsix\"");
    }

    #[test]
    fn custom_realm_is_used_in_challenge() {
        let plugin = PluginBasicAuth {
            config: PluginConfig {
                username: "demo".to_string(),
                password: "s3cret".to_string(),
                hide_credentials: false,
                realm: Some("secure-area".to_string()),
            },
            username_digest: secret_digest("demo"),
            password_digest: secret_digest("s3cret"),
        };
        assert_eq!(plugin.build_challenge(), "Basic realm=\"secure-area\"");
    }

    #[test]
    fn invalid_realms_are_rejected() {
        for invalid in ["", "a\"b", "a\\b", "caf\u{e9}"] {
            let err = PluginConfig::try_from(serde_json::json!({
                "username": "demo",
                "password": "s3cret",
                "realm": invalid,
            }))
            .expect_err("invalid realm must be rejected");
            assert!(err.to_string().contains("realm"), "{err}");
        }

        let long_realm = "a".repeat(129);
        let err = PluginConfig::try_from(serde_json::json!({
            "username": "demo",
            "password": "s3cret",
            "realm": long_realm,
        }))
        .expect_err("overlong realm must be rejected");
        assert!(err.to_string().contains("realm"), "{err}");
    }

    #[test]
    fn apisix_consumer_fields_are_ignored() {
        // APISIX uses consumer objects for credentials; PingSIX keeps them in
        // the plugin config. Unknown fields such as `anonymous_consumer` are
        // tolerated and ignored — authentication stays enforced with the
        // configured credentials.
        let config = PluginConfig::try_from(serde_json::json!({
            "username": "demo",
            "password": "s3cret",
            "anonymous_consumer": "anonymous"
        }))
        .expect("unknown fields are tolerated");
        assert_eq!(config.username, "demo");
        assert_eq!(config.password, "s3cret");
    }

    #[test]
    fn validate_credentials_rejects_invalid_pairs() {
        let plugin = build_plugin("demo", "s3cret");

        // Wrong prefix
        assert!(!plugin.validate_credentials("Bearer something"));

        // Wrong password
        let header = format!("Basic {}", general_purpose::STANDARD.encode("demo:badpass"));
        assert!(!plugin.validate_credentials(&header));
    }
}
