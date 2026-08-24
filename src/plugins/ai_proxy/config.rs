//! ai-proxy plugin configuration: APISIX-compatible schema (v1 subset).
//!
//! Field names, types, bounds, and defaults mirror
//! `apisix/plugins/ai-proxy/schema.lua`. Deviations from APISIX:
//!
//! * `auth` must carry at least one non-empty `header` or `query` entry —
//!   v1 has no `gcp`/`aws` auth, so an effectively empty auth is rejected
//!   at config time instead of failing every request later.
//! * `override.request_body` and `override.request_body_force_override`
//!   (APISIX ≥ 3.12) are out of v1 scope and are ignored for APISIX
//!   forward compatibility, like unknown fields in other plugins.

use std::collections::BTreeMap;

use http::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::core::{ProxyError, ProxyResult};

use super::provider::Provider;
use super::upstream::resolve_endpoint;

/// APISIX default: 30s, bounds 1..=600000 (milliseconds).
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// APISIX default: 64 MiB.
const DEFAULT_MAX_REQ_BODY_SIZE: u64 = 67_108_864;
/// APISIX default: 60s (milliseconds).
const DEFAULT_KEEPALIVE_TIMEOUT_MS: u64 = 60_000;

fn default_true() -> bool {
    true
}

/// ai-proxy plugin configuration (`ai_proxy` schema, APISIX-compatible v1).
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub(crate) struct AiProxyConfig {
    pub(crate) provider: Provider,
    #[validate(nested)]
    pub(crate) auth: AuthConfig,
    /// Arbitrary model options deep-merged into the client request body
    /// (`options` values win on conflict, like APISIX model options).
    #[serde(default)]
    pub(crate) options: Option<JsonValue>,
    #[serde(default)]
    #[validate(nested)]
    pub(crate) r#override: OverrideConfig,
    /// Upstream timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    #[validate(range(min = 1, max = 600_000))]
    pub(crate) timeout: u64,
    /// Request-body read cap in bytes.
    #[serde(default = "default_max_req_body_size")]
    #[validate(range(min = 1))]
    pub(crate) max_req_body_size: u64,
    /// Keepalive to the provider; `false` disables connection reuse.
    #[serde(default = "default_true")]
    pub(crate) keepalive: bool,
    /// Idle keepalive timeout in milliseconds.
    #[serde(default = "default_keepalive_timeout_ms")]
    #[validate(range(min = 1000))]
    pub(crate) keepalive_timeout: u64,
    /// Verify the provider's TLS certificate.
    #[serde(default = "default_true")]
    pub(crate) ssl_verify: bool,
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

fn default_max_req_body_size() -> u64 {
    DEFAULT_MAX_REQ_BODY_SIZE
}

fn default_keepalive_timeout_ms() -> u64 {
    DEFAULT_KEEPALIVE_TIMEOUT_MS
}

/// Provider credentials injected as headers and/or query parameters.
/// Values are field-encrypted at rest (`SECRETS_TRANSFORM`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, Validate)]
pub(crate) struct AuthConfig {
    /// Header name → value (e.g. `Authorization: Bearer sk-...`).
    #[serde(default)]
    pub(crate) header: BTreeMap<String, String>,
    /// Query parameter → value (e.g. `key=...`).
    #[serde(default)]
    pub(crate) query: BTreeMap<String, String>,
}

/// Request overrides (APISIX `override`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, Validate)]
pub(crate) struct OverrideConfig {
    /// Replace the provider's default endpoint (scheme://host[:port][/path]).
    #[validate(length(min = 1))]
    pub(crate) endpoint: Option<String>,
    /// Forced LLM options.
    #[validate(nested)]
    pub(crate) llm_options: Option<LlmOptions>,
}

/// Forced LLM options (APISIX: `max_tokens` only, minimum 1).
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub(crate) struct LlmOptions {
    #[validate(range(min = 1))]
    pub(crate) max_tokens: u64,
}

/// Header names that must not appear in `auth.header`: they would fight the
/// gateway's own request framing/rewriting (chunked transfer, provider
/// Content-Type, Host/SNI) or, for hop-by-hop headers (RFC 9110 §7.6.1 plus
/// the legacy `Keep-Alive`/`Proxy-Connection`), are not end-to-end and can
/// disagree with the gateway's actual connection/framing state.
const FORBIDDEN_AUTH_HEADERS: [&str; 12] = [
    "host",
    "content-length",
    "transfer-encoding",
    "content-type",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

impl AiProxyConfig {
    /// Deserialize, run declarative validation, then the cross-field checks
    /// that validator cannot express.
    pub(crate) fn parse(value: JsonValue) -> ProxyResult<Self> {
        let config: AiProxyConfig = super::super::config::parse_and_validate_plugin_config(
            value,
            "Invalid ai-proxy plugin config",
        )?;
        config.post_validate()?;
        Ok(config)
    }

    fn post_validate(&self) -> ProxyResult<()> {
        // v1 has no gcp/aws auth: an auth block without header or query
        // entries could never authenticate and is rejected up front.
        if self.auth.header.is_empty() && self.auth.query.is_empty() {
            return Err(ProxyError::validation_error(
                "ai-proxy: auth must configure at least one of auth.header or auth.query",
            ));
        }
        for (section, map) in [
            ("auth.header", &self.auth.header),
            ("auth.query", &self.auth.query),
        ] {
            for (name, value) in map {
                if name.trim().is_empty() || value.is_empty() {
                    return Err(ProxyError::validation_error(format!(
                        "ai-proxy: {section}[{name:?}] must be a non-empty string"
                    )));
                }
            }
        }
        // Headers are injected verbatim on every request, so their legality
        // is a config-time property, not a per-request failure: parse each
        // name/value exactly like the runtime injection will, and reject the
        // framing/hop-by-hop headers the gateway itself manages.
        for (name, value) in &self.auth.header {
            if FORBIDDEN_AUTH_HEADERS
                .iter()
                .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
            {
                return Err(ProxyError::validation_error(format!(
                    "ai-proxy: auth.header[{name:?}] is managed by the gateway and cannot be \
                     overridden (managed: {FORBIDDEN_AUTH_HEADERS:?})"
                )));
            }
            HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                ProxyError::validation_error(format!(
                    "ai-proxy: auth.header name {name:?} is not a valid HTTP header name: {error}"
                ))
            })?;
            HeaderValue::from_str(value).map_err(|error| {
                ProxyError::validation_error(format!(
                    "ai-proxy: auth.header[{name:?}] is not a valid HTTP header value: {error}"
                ))
            })?;
        }
        // Query parameters are form-urlencoded, so any non-empty string is
        // legal; still reject values that would encode to nothing usable.
        for (name, value) in &self.auth.query {
            if name.trim().is_empty() || value.trim().is_empty() {
                return Err(ProxyError::validation_error(format!(
                    "ai-proxy: auth.query[{name:?}] must be a non-empty string"
                )));
            }
        }

        if let Some(options) = &self.options {
            if !options.is_object() {
                return Err(ProxyError::validation_error(
                    "ai-proxy: options must be a JSON object",
                ));
            }
            // APISIX types `options.model` as a string when present.
            if let Some(model) = options.get("model") {
                if !model.is_string() {
                    return Err(ProxyError::validation_error(
                        "ai-proxy: options.model must be a string",
                    ));
                }
            }
        }

        if self.provider == Provider::OpenaiCompatible && self.r#override.endpoint.is_none() {
            return Err(ProxyError::validation_error(
                "ai-proxy: provider 'openai-compatible' requires override.endpoint",
            ));
        }

        // Endpoint URLs must parse into scheme + host now (DNS resolution
        // happens later, in the preparation pipeline).
        resolve_endpoint(self).map_err(|error| {
            ProxyError::validation_error(format!("ai-proxy: override.endpoint: {error}"))
        })?;

        Ok(())
    }
}

/// Field-level encryption for `auth.header.*` and `auth.query.*` values.
///
/// Hand-written instead of `#[derive(EncryptFields)]` because the derive can
/// only walk fixed field names, while ai-proxy auth is an arbitrary-key map
/// (mirroring APISIX's `encrypt_fields = { "auth.header", "auth.query" }`).
pub(crate) const SECRETS_TRANSFORM: crate::utils::encryption::PluginSecretsTransform =
    transform_ai_proxy_secrets;

fn transform_ai_proxy_secrets(
    config: &mut JsonValue,
    op: crate::utils::encryption::SecretOp,
    keyring: &crate::utils::encryption::KeyringService,
) -> ProxyResult<()> {
    use crate::utils::encryption::SecretOp;

    let Some(JsonValue::Object(auth)) = config.get_mut("auth") else {
        return Ok(());
    };
    for section in ["header", "query"] {
        let Some(JsonValue::Object(entries)) = auth.get_mut(section) else {
            continue;
        };
        for value in entries.values_mut() {
            if let JsonValue::String(plaintext) = value {
                *plaintext = match op {
                    SecretOp::Encrypt => keyring.encrypt(plaintext)?,
                    SecretOp::Decrypt => keyring.decrypt(plaintext)?,
                    SecretOp::Redact => crate::utils::encryption::REDACTED.to_string(),
                };
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse_ok(value: JsonValue) -> AiProxyConfig {
        AiProxyConfig::parse(value).unwrap_or_else(|e| panic!("expected ok: {e}"))
    }

    fn parse_err(value: JsonValue) -> String {
        AiProxyConfig::parse(value).unwrap_err().to_string()
    }

    fn minimal(provider: &str) -> JsonValue {
        json!({
            "provider": provider,
            "auth": { "header": { "Authorization": "Bearer sk-test" } }
        })
    }

    #[test]
    fn minimal_configs_parse_for_every_provider() {
        for provider in ["openai", "deepseek", "anthropic"] {
            let config = parse_ok(minimal(provider));
            assert_eq!(config.timeout, DEFAULT_TIMEOUT_MS);
            assert_eq!(config.max_req_body_size, DEFAULT_MAX_REQ_BODY_SIZE);
            assert!(config.keepalive);
            assert_eq!(config.keepalive_timeout, DEFAULT_KEEPALIVE_TIMEOUT_MS);
            assert!(config.ssl_verify);
            assert!(config.options.is_none());
            assert_eq!(config.r#override.endpoint, None);
        }

        // openai-compatible additionally requires override.endpoint.
        let err = parse_err(minimal("openai-compatible"));
        assert!(err.contains("override.endpoint"), "{err}");
    }

    #[test]
    fn full_field_config_parses() {
        let config = parse_ok(json!({
            "provider": "anthropic",
            "auth": {
                "header": { "x-api-key": "sk-ant", "X-Extra": "v" },
                "query": { "key": "qk" }
            },
            "options": { "model": "claude-3-5-sonnet", "temperature": 0.2, "nested": {"a": 1} },
            "override": {
                "endpoint": "https://llm.internal:8443/v2/messages",
                "llm_options": { "max_tokens": 1024 }
            },
            "timeout": 60000,
            "max_req_body_size": 1048576,
            "keepalive": false,
            "keepalive_timeout": 30000,
            "ssl_verify": false
        }));
        assert_eq!(config.provider, Provider::Anthropic);
        assert_eq!(config.auth.query.get("key").map(String::as_str), Some("qk"));
        assert_eq!(
            config.options.as_ref().unwrap().get("model"),
            Some(&json!("claude-3-5-sonnet"))
        );
        assert_eq!(
            config.r#override.llm_options.as_ref().unwrap().max_tokens,
            1024
        );
        assert!(!config.keepalive);
        assert!(!config.ssl_verify);
    }

    #[test]
    fn missing_provider_is_rejected_with_field_path() {
        let err = parse_err(json!({ "auth": { "header": { "Authorization": "Bearer x" } } }));
        assert!(err.contains("provider"), "{err}");
    }

    #[test]
    fn empty_auth_is_rejected() {
        let err = parse_err(json!({ "provider": "openai", "auth": {} }));
        assert!(
            err.contains("auth.header") && err.contains("auth.query"),
            "{err}"
        );

        let err = parse_err(json!({
            "provider": "openai",
            "auth": { "header": { "": "v" } }
        }));
        assert!(err.contains("auth.header"), "{err}");
    }

    fn header_config(entries: &[(&str, &str)]) -> JsonValue {
        let header: serde_json::Map<String, JsonValue> = entries
            .iter()
            .map(|(name, value)| (name.to_string(), json!(value)))
            .collect();
        json!({ "provider": "openai", "auth": { "header": header } })
    }

    #[test]
    fn invalid_auth_headers_are_rejected_at_config_time() {
        // Illegal header names (whitespace, control characters).
        for name in ["Bad Name", "a\nb", "x y"] {
            let err = parse_err(header_config(&[(name, "v")]));
            assert!(err.contains("auth.header"), "{name:?}: {err}");
        }

        // Illegal values (control characters are never header-safe).
        let err = parse_err(header_config(&[("X-Key", "v\r\nHost: evil")]));
        assert!(err.contains("auth.header"), "{err}");

        // Gateway-managed framing headers and the full RFC 9110 hop-by-hop
        // set (plus legacy keep-alive variants) cannot be overridden; the
        // rejection is case-insensitive.
        for name in [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Content-Type",
            "Connection",
            "Keep-Alive",
            "Proxy-Connection",
            "TE",
            "Trailer",
            "Upgrade",
            "Proxy-Authenticate",
            "proxy-authorization",
        ] {
            let err = parse_err(header_config(&[(name, "x")]));
            assert!(err.contains("managed"), "{name}: {err}");
        }

        // Well-formed custom headers (incl. anthropic-version) pass.
        parse_ok(header_config(&[
            ("Authorization", "Bearer sk"),
            ("x-api-key", "k"),
            ("anthropic-version", "2023-06-01"),
        ]));
    }

    #[test]
    fn blank_auth_query_entries_are_rejected() {
        let err = parse_err(json!({
            "provider": "openai",
            "auth": { "query": { "key": "   " } }
        }));
        assert!(err.contains("auth.query"), "{err}");
    }

    #[test]
    fn unknown_provider_lists_legal_values() {
        let err = parse_err(json!({
            "provider": "openrouter",
            "auth": { "header": { "Authorization": "Bearer x" } }
        }));
        assert!(err.contains("openai") && err.contains("anthropic"), "{err}");
    }

    #[test]
    fn unknown_fields_are_tolerated_and_ignored() {
        // APISIX forward compatibility: fields outside the v1 subset (and
        // typos) are ignored, never rejected by serde.
        for extra in [
            json!({"provder": "typo"}),
            json!({"max_stream_duration_ms": 60000}),
            json!({"override": { "request_body": { "model": "x" } }}),
        ] {
            let mut value = minimal("openai");
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            parse_ok(value);
        }
    }

    #[test]
    fn bounds_match_apisix() {
        for bad in [0_u64, 600_001] {
            let err = parse_err(json!({
                "provider": "openai",
                "auth": { "header": { "Authorization": "Bearer x" } },
                "timeout": bad
            }));
            assert!(err.contains("timeout"), "{err}");
        }

        let err = parse_err(json!({
            "provider": "openai",
            "auth": { "header": { "Authorization": "Bearer x" } },
            "keepalive_timeout": 999
        }));
        assert!(err.contains("keepalive_timeout"), "{err}");

        let err = parse_err(json!({
            "provider": "openai",
            "auth": { "header": { "Authorization": "Bearer x" } },
            "max_req_body_size": 0
        }));
        assert!(err.contains("max_req_body_size"), "{err}");

        let err = parse_err(json!({
            "provider": "openai",
            "auth": { "header": { "Authorization": "Bearer x" } },
            "override": { "llm_options": { "max_tokens": 0 } }
        }));
        assert!(err.contains("max_tokens"), "{err}");
    }

    #[test]
    fn invalid_endpoints_are_rejected() {
        for endpoint in ["", "not-a-url", "ftp://api.example.com/v1", "http://"] {
            let err = parse_err(json!({
                "provider": "openai-compatible",
                "auth": { "header": { "Authorization": "Bearer x" } },
                "override": { "endpoint": endpoint }
            }));
            assert!(err.contains("endpoint"), "{endpoint}: {err}");
        }
    }

    #[test]
    fn options_must_be_an_object_with_string_model() {
        let err = parse_err(json!({
            "provider": "openai",
            "auth": { "header": { "Authorization": "Bearer x" } },
            "options": [1, 2]
        }));
        assert!(err.contains("options"), "{err}");

        let err = parse_err(json!({
            "provider": "openai",
            "auth": { "header": { "Authorization": "Bearer x" } },
            "options": { "model": 42 }
        }));
        assert!(err.contains("model"), "{err}");
    }

    #[test]
    fn secrets_transform_round_trips_auth_values_only() {
        use crate::utils::encryption::{KeyringService, SecretOp};

        let keyring = KeyringService::new(true, &["test-key".into()]).unwrap();
        let mut config = json!({
            "provider": "openai",
            "auth": {
                "header": { "Authorization": "Bearer sk-plain" },
                "query": { "key": "qk-plain" }
            },
            "options": { "model": "gpt-4o" }
        });

        SECRETS_TRANSFORM(&mut config, SecretOp::Encrypt, &keyring).unwrap();
        let header_key = config["auth"]["header"]["Authorization"].as_str().unwrap();
        let query_key = config["auth"]["query"]["key"].as_str().unwrap();
        assert!(crate::utils::encryption::is_ciphertext(header_key));
        assert!(crate::utils::encryption::is_ciphertext(query_key));
        assert_eq!(config["options"]["model"], json!("gpt-4o"));

        SECRETS_TRANSFORM(&mut config, SecretOp::Decrypt, &keyring).unwrap();
        assert_eq!(
            config["auth"]["header"]["Authorization"],
            json!("Bearer sk-plain")
        );
        assert_eq!(config["auth"]["query"]["key"], json!("qk-plain"));

        SECRETS_TRANSFORM(&mut config, SecretOp::Redact, &keyring).unwrap();
        assert_eq!(config["auth"]["header"]["Authorization"], json!("***"));
    }
}
