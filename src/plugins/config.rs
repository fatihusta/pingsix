//! Shared helpers for plugin configuration schemas: cross-plugin config
//! value types (like [`HeaderValue`]) and the common parse-then-validate
//! entry point every plugin config flows through.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::core::{ProxyError, ProxyResult};

/// Header values in APISIX configurations are Lua values, so a header may
/// be either a string or a number. Numbers are rendered with `to_string`,
/// which is what Lua's `tostring` produces for header assignment. Shared by
/// every plugin whose APISIX schema accepts string-or-number header values
/// (echo, response-rewrite, ...).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub(crate) enum HeaderValue {
    Text(String),
    Number(f64),
}

impl HeaderValue {
    /// Render the configured value the way APISIX assigns it to a header.
    pub(crate) fn render(&self) -> String {
        match self {
            HeaderValue::Text(value) => value.clone(),
            HeaderValue::Number(value) => value.to_string(),
        }
    }
}

/// APISIX `realm` validation shared by the auth plugins: printable ASCII,
/// 1..=128 characters, no `"` or `\`.
pub(crate) fn validate_apisix_realm(realm: &str) -> Result<(), ValidationError> {
    // A single byte predicate: every byte printable ASCII already implies
    // `is_ascii()` (so multi-byte UTF-8 fails), and excluding the `"` and
    // `\` bytes replaces both `contains` passes.
    let valid = (1..=128).contains(&realm.len())
        && realm
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\');
    if valid {
        Ok(())
    } else {
        Err(ValidationError::new(
            "realm must be 1..=128 printable ASCII characters and cannot contain \" or \\",
        ))
    }
}

/// Deserialize and run declarative validation for a plugin configuration.
///
/// Plugin-specific checks that go beyond `validator` remain at their call site
/// so their established error wording and ordering are unchanged.
pub(crate) fn parse_and_validate_plugin_config<T>(
    value: JsonValue,
    error_context: &'static str,
) -> ProxyResult<T>
where
    T: DeserializeOwned + Validate,
{
    let config: T = serde_json::from_value(value)
        .map_err(|error| ProxyError::serialization_error(error_context, error))?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::json;
    use validator::Validate;

    use super::{parse_and_validate_plugin_config, validate_apisix_realm, HeaderValue};
    use crate::core::ProxyError;

    #[derive(Debug, Deserialize, Validate, PartialEq)]
    struct TestConfig {
        #[validate(length(min = 1))]
        name: String,
    }

    #[test]
    fn parses_and_validates_config() {
        let config = parse_and_validate_plugin_config::<TestConfig>(
            json!({ "name": "pingsix" }),
            "Invalid test plugin config",
        )
        .expect("valid config");

        assert_eq!(
            config,
            TestConfig {
                name: "pingsix".into()
            }
        );
    }

    #[test]
    fn preserves_parse_error_context() {
        let error =
            parse_and_validate_plugin_config::<TestConfig>(json!({}), "Invalid test plugin config")
                .expect_err("invalid JSON shape");

        assert!(matches!(error, ProxyError::WithCause { .. }));
        assert!(error
            .to_string()
            .starts_with("Serialization error: Invalid test plugin config:"));
    }

    #[test]
    fn preserves_validation_error_type() {
        let error = parse_and_validate_plugin_config::<TestConfig>(
            json!({ "name": "" }),
            "Invalid test plugin config",
        )
        .expect_err("invalid field value");

        assert!(matches!(error, ProxyError::ValidationStructured(_)));
    }

    #[test]
    fn apisix_realm_accepts_printable_ascii_without_quote_or_backslash() {
        validate_apisix_realm("pingsix").expect("plain ASCII realm is valid");
        validate_apisix_realm(&"a".repeat(128)).expect("128 chars is the upper bound");
        validate_apisix_realm("basic realm=\"pingsix\"").expect_err("double quote is rejected");

        for invalid in [
            "",               // empty (0 chars)
            &"a".repeat(129), // 129 chars
            "caf\u{e9}",      // multi-byte UTF-8
            "line\nbreak",    // control byte below 0x20
            "back\\slash",    // backslash byte
            "\u{7f}del",      // DEL byte above 0x7e
        ] {
            let error = validate_apisix_realm(invalid)
                .expect_err("realm must be printable ASCII without quote or backslash");
            assert_eq!(
                error.code,
                "realm must be 1..=128 printable ASCII characters and cannot contain \" or \\"
            );
        }
    }

    #[test]
    fn header_value_renders_strings_and_numbers() {
        assert_eq!(HeaderValue::Text("plain".to_string()).render(), "plain");
        assert_eq!(HeaderValue::Number(42.0).render(), "42");
        assert_eq!(HeaderValue::Number(1.5).render(), "1.5");

        // The untagged serde shape is preserved: JSON strings and numbers
        // both deserialize, anything else fails.
        assert_eq!(
            serde_json::from_value::<HeaderValue>(json!("text")).unwrap(),
            HeaderValue::Text("text".to_string())
        );
        assert_eq!(
            serde_json::from_value::<HeaderValue>(json!(7)).unwrap(),
            HeaderValue::Number(7.0)
        );
        assert!(serde_json::from_value::<HeaderValue>(json!(true)).is_err());
        assert!(serde_json::from_value::<HeaderValue>(json!(null)).is_err());
    }
}
