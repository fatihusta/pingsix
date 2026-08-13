use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::core::{ProxyError, ProxyResult};

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

    use super::parse_and_validate_plugin_config;
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
}
