//! URI blocker plugin, APISIX `uri-blocker` compatible.
//!
//! Intercepts requests whose **request URI** (path plus query string, exactly
//! like nginx `$request_uri`) matches any configured regular expression and
//! rejects them with `rejected_code` (default 403). Matches are unanchored
//! searches: a rule matches when the pattern occurs anywhere in the URI.
//!
//! With `rejected_msg` set the response body is `{"error_msg": "<msg>"}`
//! (JSON, mirroring APISIX); otherwise the rejection carries an empty body.
//! Every rejection flows through the shared exit-response helper so a
//! configured `exit-transformer` can still rewrite it.

use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::Result;
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult, Rejection},
    plugins::config::parse_and_validate_plugin_config,
    utils::response::content_type,
};

pub const PLUGIN_NAME: &str = "uri-blocker";

/// APISIX `uri-blocker` runs at priority 2900 (after ip-restriction 3000,
/// before request-validation 2800).
const PRIORITY: i32 = 2900;

/// Creates a `uri-blocker` plugin instance from JSON configuration.
pub fn create_uri_blocker_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    let matcher = config.compile_matcher()?;
    Ok(Arc::new(PluginUriBlocker { config, matcher }))
}

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators (including the block-rules regex compile) WITHOUT constructing
/// the plugin.
pub fn validate_uri_blocker_config(cfg: &JsonValue) -> ProxyResult<()> {
    let config = PluginConfig::try_from(cfg.clone())?;
    config.compile_matcher()?;
    Ok(())
}

/// APISIX `uri-blocker` schema: `block_rules` (required, unique regex
/// strings), `rejected_code` (>=200, default 403), `rejected_msg`,
/// `case_insensitive` (default false).
#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Regular expressions matched against the request URI (path + query).
    #[validate(length(min = 1))]
    block_rules: Vec<String>,
    /// Status code returned to blocked requests.
    #[serde(default = "PluginConfig::default_rejected_code")]
    #[validate(range(min = 200, max = 599))]
    rejected_code: u16,
    /// JSON `error_msg` body returned to blocked requests.
    #[validate(length(min = 1))]
    rejected_msg: Option<String>,
    /// Compile all rules with the `i` flag.
    #[serde(default)]
    case_insensitive: bool,
}

impl PluginConfig {
    fn default_rejected_code() -> u16 {
        403
    }

    /// Compile the rules into one alternation regex, mirroring APISIX's
    /// `concat(block_rules, "|")` with an optional leading `(?i)`. Fails with
    /// a validation error for an invalid pattern, like APISIX's
    /// `re_compile` check.
    fn compile_matcher(&self) -> ProxyResult<Regex> {
        let alternation = self
            .block_rules
            .iter()
            .map(|rule| format!("(?:{rule})"))
            .collect::<Vec<_>>()
            .join("|");
        regex::RegexBuilder::new(&alternation)
            .case_insensitive(self.case_insensitive)
            .build()
            .map_err(|e| {
                ProxyError::validation_error(format!("Invalid uri-blocker block_rules regex: {e}"))
            })
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid uri-blocker plugin config")?;

        // APISIX schema: each rule is 1..=4096 characters and the list is unique.
        for rule in &config.block_rules {
            let length = rule.chars().count();
            if !(1..=4096).contains(&length) {
                return Err(ProxyError::validation_error(format!(
                    "uri-blocker block_rules entries must be between 1 and 4096 characters, got {length}"
                )));
            }
        }

        // uniqueItems: reject duplicates instead of silently deduplicating.
        let mut seen = std::collections::HashSet::with_capacity(config.block_rules.len());
        for rule in &config.block_rules {
            if !seen.insert(rule.as_str()) {
                return Err(ProxyError::validation_error(format!(
                    "uri-blocker block_rules contains duplicate rule '{rule}'"
                )));
            }
        }
        Ok(config)
    }
}

pub struct PluginUriBlocker {
    config: PluginConfig,
    /// Case-insensitivity-aware compiled matcher (sole source of truth for
    /// the `case_insensitive` flag).
    matcher: Regex,
}

impl PluginUriBlocker {
    fn matched_matcher(&self) -> &Regex {
        &self.matcher
    }
}

/// The request URI as nginx sees `$request_uri`: raw path plus query string.
fn request_uri(session: &Session) -> String {
    let uri = session
        .req_header()
        .uri
        .path_and_query()
        .map(|pq| pq.as_str());
    uri.unwrap_or_default().to_string()
}

#[async_trait]
impl ProxyPlugin for PluginUriBlocker {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        let uri = request_uri(session);
        if self.matched_matcher().is_match(&uri) {
            log::debug!("uri-blocker: blocked request URI '{uri}'");
            let body = self.config.rejected_msg.as_ref().map(|msg| {
                serde_json::to_string(&serde_json::json!({ "error_msg": msg }))
                    .expect("error_msg serializes")
            });
            let mut rejection = Rejection::new(
                StatusCode::from_u16(self.config.rejected_code).unwrap_or(StatusCode::FORBIDDEN),
            );
            if let Some(body) = body {
                rejection = rejection
                    .with_body(body)
                    .with_content_type(content_type::APPLICATION_JSON);
            }
            return Ok(FilterVerdict::Reject(rejection));
        }

        Ok(FilterVerdict::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(cfg: JsonValue) -> (PluginConfig, Regex) {
        let config = PluginConfig::try_from(cfg).expect("valid config");
        let matcher = config.compile_matcher().expect("valid regex");
        (config, matcher)
    }

    #[test]
    fn config_requires_block_rules() {
        assert!(PluginConfig::try_from(serde_json::json!({})).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "block_rules": [] })).is_err());
    }

    #[test]
    fn config_rejects_duplicate_rules() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "block_rules": ["/foo", "/foo"]
        }))
        .is_err());
    }

    #[test]
    fn config_rejects_empty_and_overlong_rules() {
        assert!(PluginConfig::try_from(serde_json::json!({ "block_rules": [""] })).is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({ "block_rules": ["x".repeat(4097)] }))
                .is_err()
        );
        assert!(
            PluginConfig::try_from(serde_json::json!({ "block_rules": ["x".repeat(4096)] }))
                .is_ok()
        );
    }

    #[test]
    fn config_tolerates_unknown_fields() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "block_rules": ["/foo"], "typo_field": true
        }))
        .is_ok());
    }

    #[test]
    fn rejected_code_defaults_and_validates() {
        let (config, _) = parse(serde_json::json!({ "block_rules": ["/secret"] }));
        assert_eq!(config.rejected_code, 403);
        assert!(!config.case_insensitive);

        assert!(PluginConfig::try_from(serde_json::json!({
            "block_rules": ["/secret"], "rejected_code": 199
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "block_rules": ["/secret"], "rejected_code": 600
        }))
        .is_err());
        let (config, _) = parse(serde_json::json!({
            "block_rules": ["/secret"], "rejected_code": 418
        }));
        assert_eq!(config.rejected_code, 418);
    }

    #[test]
    fn invalid_regex_fails_to_compile() {
        let config = PluginConfig::try_from(serde_json::json!({
            "block_rules": ["[unclosed"]
        }))
        .expect("serde shape is valid");
        assert!(config.compile_matcher().is_err());
    }

    #[test]
    fn matcher_is_unanchored_and_covers_query_string() {
        let (_, matcher) = parse(serde_json::json!({
            "block_rules": ["weapon"]
        }));
        assert!(matcher.is_match("/buy/weapon"));
        assert!(matcher.is_match("/search?q=weapons"));
        assert!(!matcher.is_match("/search?q=tools"));
    }

    #[test]
    fn case_insensitive_flag_is_folded_into_matcher() {
        let (_, matcher) = parse(serde_json::json!({
            "block_rules": ["^/admin"], "case_insensitive": true
        }));
        assert!(matcher.is_match("/ADMIN/console"));
        assert!(!matcher.is_match("/user/ADMIN"));

        let (_, matcher) = parse(serde_json::json!({
            "block_rules": ["^/admin"]
        }));
        assert!(!matcher.is_match("/ADMIN/console"));
    }

    #[test]
    fn multiple_rules_are_alternated() {
        let (_, matcher) = parse(serde_json::json!({
            "block_rules": ["^/private/", "\\.sql$"]
        }));
        assert!(matcher.is_match("/private/data"));
        assert!(matcher.is_match("/dump/backup.sql"));
        assert!(!matcher.is_match("/public/data"));
    }

    #[test]
    fn rejected_msg_renders_as_apisix_error_json() {
        let (config, _) = parse(serde_json::json!({
            "block_rules": ["/x"], "rejected_msg": "blocked by policy"
        }));
        let body = serde_json::to_string(&serde_json::json!({
            "error_msg": config.rejected_msg.unwrap()
        }))
        .unwrap();
        assert_eq!(body, r#"{"error_msg":"blocked by policy"}"#);
    }
}
