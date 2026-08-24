use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use http::Uri;
use pingora_error::Result;
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as JsonValue;
use validator::{Validate, ValidationError};

use crate::{
    core::{
        apply_regex_uri_template, PluginPhases, ProxyContext, ProxyError, ProxyPlugin, ProxyResult,
    },
    plugins::config::parse_and_validate_plugin_config,
};

pub const PLUGIN_NAME: &str = "proxy-rewrite";
const PRIORITY: i32 = 1008;

pub fn create_proxy_rewrite_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    validate_configured_header_entries(config.headers.as_ref())?;

    // Precompile regex patterns for regex_uri to improve performance
    let regex_uri = config.regex_uri.as_deref().unwrap_or(&[]);
    let mut regex_patterns = Vec::new();
    for i in (0..regex_uri.len()).step_by(2) {
        let pattern = &regex_uri[i];
        let template = &regex_uri[i + 1];
        // Validation ensures regex is valid; propagate error if it somehow isn't
        let re = Regex::new(pattern).map_err(|e| {
            ProxyError::Plugin(format!(
                "Invalid proxy-rewrite regex pattern '{pattern}': {e}"
            ))
        })?;
        regex_patterns.push((re, template.clone()));
    }

    Ok(Arc::new(PluginProxyRewrite {
        config,
        regex_patterns,
    }))
}

/// One header entry in `headers.set` / `headers.add`.
///
/// APISIX accepts a scalar string/number or an array of strings/numbers as
/// `value`; arrays expand to multiple header fields.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct HeaderEntry {
    name: String,
    value: HeaderValues,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
enum HeaderValues {
    Many(Vec<String>),
    One(String),
}

impl Default for HeaderValues {
    fn default() -> Self {
        HeaderValues::Many(Vec::new())
    }
}

impl<'de> Deserialize<'de> for HeaderValues {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = JsonValue::deserialize(deserializer)?;
        match value {
            JsonValue::Array(items) if items.is_empty() => Err(serde::de::Error::custom(
                "header value array must contain at least one string or number",
            )),
            JsonValue::Array(items) => items
                .into_iter()
                .map(header_value_to_string)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map(HeaderValues::Many),
            other => header_value_to_string(other).map(HeaderValues::One),
        }
    }
}

/// Dry-runs every configured header name/value at plugin build time so a
/// malformed entry fails the config write once instead of erroring every
/// proxied request on the route.
fn validate_configured_header_entries(headers: Option<&Headers>) -> ProxyResult<()> {
    let Some(headers) = headers else {
        return Ok(());
    };
    let check = |name: &str, value: Option<&str>| -> ProxyResult<()> {
        http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            ProxyError::validation_error(format!("proxy-rewrite: invalid header name '{name}'"))
        })?;
        if let Some(value) = value {
            http::HeaderValue::from_str(value).map_err(|_| {
                ProxyError::validation_error(format!(
                    "proxy-rewrite: invalid value for header '{name}'"
                ))
            })?;
        }
        Ok(())
    };
    for entry in headers.add.iter().chain(headers.set.iter()) {
        match &entry.value {
            HeaderValues::One(value) => check(&entry.name, Some(value))?,
            HeaderValues::Many(values) => {
                check(&entry.name, None)?;
                for value in values {
                    check(&entry.name, Some(value))?;
                }
            }
        }
    }
    for name in &headers.remove {
        http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            ProxyError::validation_error(format!("proxy-rewrite: invalid header name '{name}'"))
        })?;
    }
    Ok(())
}

fn header_value_to_string<E: serde::de::Error>(value: JsonValue) -> std::result::Result<String, E> {
    match value {
        JsonValue::String(value) => Ok(value),
        JsonValue::Number(value) => Ok(value.to_string()),
        other => Err(E::custom(format!(
            "header value must be a string, number, or array of strings/numbers, got {other}"
        ))),
    }
}

#[derive(Clone, Default, Debug, Serialize)]
struct Headers {
    #[serde(default)]
    add: Vec<HeaderEntry>,
    #[serde(default)]
    set: Vec<HeaderEntry>,
    #[serde(default)]
    remove: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawHeaderEntries {
    PingSIX(Vec<HeaderEntry>),
    Apisix(BTreeMap<String, HeaderValues>),
}

impl Default for RawHeaderEntries {
    fn default() -> Self {
        Self::PingSIX(Vec::new())
    }
}

impl RawHeaderEntries {
    fn into_entries(self) -> Vec<HeaderEntry> {
        match self {
            RawHeaderEntries::PingSIX(entries) => entries,
            RawHeaderEntries::Apisix(map) => map
                .into_iter()
                .map(|(name, value)| HeaderEntry { name, value })
                .collect(),
        }
    }
}

#[derive(Deserialize)]
struct StructuredHeaders {
    #[serde(default)]
    add: RawHeaderEntries,
    #[serde(default)]
    set: RawHeaderEntries,
    #[serde(default)]
    remove: Vec<String>,
}

impl<'de> Deserialize<'de> for Headers {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = JsonValue::deserialize(deserializer)?;
        let is_structured = value.as_object().is_some_and(|object| {
            object.contains_key("add")
                || object.contains_key("set")
                || object.contains_key("remove")
        });

        if is_structured {
            // APISIX's structured arm is `additionalProperties: false`: plain
            // header entries next to add/set/remove are a porting mistake that
            // would otherwise be silently ignored — reject naming the key(s).
            let object = value.as_object().expect("is_structured checked");
            let unknown: Vec<&str> = object
                .keys()
                .map(String::as_str)
                .filter(|key| !matches!(*key, "add" | "set" | "remove"))
                .collect();
            if !unknown.is_empty() {
                return Err(serde::de::Error::custom(format!(
                    "headers: unknown key(s) {} — plain header entries cannot be \
                     mixed with add/set/remove; list them under 'set'",
                    unknown
                        .iter()
                        .map(|key| format!("'{key}'"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            let raw: StructuredHeaders = serde_json::from_value(value)
                .map_err(|error| serde::de::Error::custom(error.to_string()))?;
            Ok(Headers {
                add: raw.add.into_entries(),
                set: raw.set.into_entries(),
                remove: raw.remove,
            })
        } else {
            let map: BTreeMap<String, HeaderValues> = serde_json::from_value(value)
                .map_err(|error| serde::de::Error::custom(error.to_string()))?;
            let set = map
                .into_iter()
                .map(|(name, value)| HeaderEntry { name, value })
                .collect();
            Ok(Headers {
                add: Vec::new(),
                set,
                remove: Vec::new(),
            })
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "PluginConfig::validate"))]
struct PluginConfig {
    /// The URI to rewrite to. Takes precedence over `regex_uri` if both are set.
    uri: Option<String>,
    method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    regex_uri: Option<Vec<String>>,
    host: Option<String>,
    #[serde(default)]
    headers: Option<Headers>,
}

impl PluginConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(regex_uri) = &self.regex_uri {
            Self::validate_regex_uri(regex_uri)?;
        }

        if let Some(uri) = &self.uri {
            if uri.is_empty() || !uri.starts_with('/') {
                return Err(ValidationError::new(
                    "uri must start with '/' and be at least 1 character long",
                ));
            }
            if uri.chars().count() > 4096 {
                return Err(ValidationError::new("uri must be at most 4096 characters"));
            }
        }

        if let Some(method) = &self.method {
            const APISIX_REWRITE_METHODS: [&str; 9] = [
                "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
            ];
            if !APISIX_REWRITE_METHODS.contains(&method.as_str()) {
                return Err(ValidationError::new(
                    "method must be one of GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, CONNECT, TRACE",
                ));
            }
        }

        Ok(())
    }

    fn validate_regex_uri(regex_uri: &[String]) -> Result<(), ValidationError> {
        if regex_uri.len() < 2 || !regex_uri.len().is_multiple_of(2) {
            return Err(ValidationError::new(
                "regex_uri must have at least 2 entries and an even length",
            ));
        }

        regex_uri
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 2 == 0)
            .map(|(_, pattern)| {
                Regex::new(pattern).map_err(|_| ValidationError::new("invalid_regex"))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid proxy rewrite plugin config")?;

        Ok(config)
    }
}

pub struct PluginProxyRewrite {
    config: PluginConfig,
    regex_patterns: Vec<(Regex, String)>, // Precompiled regex and template pairs
}

#[async_trait]
impl ProxyPlugin for PluginProxyRewrite {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }
    fn phases(&self) -> PluginPhases {
        PluginPhases::UPSTREAM_REQUEST
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        if let Some(path_and_query) = session.req_header().uri.path_and_query() {
            if let Some(uri) = self.construct_path_and_query(Some(path_and_query)) {
                upstream_request.set_uri(uri);
            }
        }

        if let Some(ref method) = self.config.method {
            upstream_request.set_method(
                method
                    .as_bytes()
                    .try_into()
                    .map_err(|e| ProxyError::Internal(format!("Invalid method: {e}")))?,
            );
        }

        if let Some(ref host) = self.config.host {
            upstream_request
                .insert_header(http::header::HOST, host)
                .map_err(|e| ProxyError::Internal(format!("Invalid host: {e}")))?;
        }

        if let Some(ref headers) = self.config.headers {
            self.apply_headers(upstream_request, headers)?;
        }

        Ok(())
    }
}

impl PluginProxyRewrite {
    fn construct_path_and_query(
        &self,
        path_and_query: Option<&http::uri::PathAndQuery>,
    ) -> Option<Uri> {
        if let Some(ref path) = self.config.uri {
            let query = path_and_query.and_then(|pq| pq.query()).unwrap_or("");
            return if query.is_empty() {
                path.parse().ok()
            } else {
                format!("{path}?{query}").parse().ok()
            };
        }

        if !self.regex_patterns.is_empty() {
            if let Some(pq) = path_and_query {
                let query = pq.query().unwrap_or("");
                let new_path = apply_regex_uri_template(pq.path(), &self.regex_patterns);
                return if query.is_empty() {
                    new_path.parse().ok()
                } else {
                    format!("{new_path}?{query}").parse().ok()
                };
            }
        }

        None
    }

    fn apply_headers(&self, upstream_request: &mut RequestHeader, headers: &Headers) -> Result<()> {
        // APISIX applies add, then set, then remove.
        for entry in &headers.add {
            for value in entry.values() {
                upstream_request.append_header(entry.name.clone(), value)?;
            }
        }

        for entry in &headers.set {
            // `set` replaces the header with every configured value, so clear
            // the name once and append all values (APISIX array semantics).
            upstream_request.remove_header(&entry.name);
            for value in entry.values() {
                upstream_request.append_header(entry.name.clone(), value)?;
            }
        }

        for name in &headers.remove {
            upstream_request.remove_header(name);
        }

        Ok(())
    }
}

impl HeaderEntry {
    fn values(&self) -> &[String] {
        match &self.value {
            HeaderValues::Many(values) => values,
            HeaderValues::One(value) => std::slice::from_ref(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_map_headers_are_treated_as_set() {
        let config = PluginConfig::try_from(serde_json::json!({
            "uri": "/new",
            "headers": {
                "X-String": "value",
                "X-Number": 42,
                "X-Many": ["a", 3]
            }
        }))
        .expect("plain map headers should parse");

        let headers = config.headers.clone().expect("headers parsed");
        assert!(headers.add.is_empty());
        assert!(headers.remove.is_empty());
        assert_eq!(headers.set.len(), 3);

        let mut upstream =
            RequestHeader::build("GET", b"/", Some(1)).expect("request header builds");
        PluginProxyRewrite {
            config,
            regex_patterns: Vec::new(),
        }
        .apply_headers(&mut upstream, &headers)
        .expect("headers apply");

        assert_eq!(
            upstream.headers.get("x-string").unwrap().to_str().unwrap(),
            "value"
        );
        assert_eq!(
            upstream.headers.get("x-number").unwrap().to_str().unwrap(),
            "42"
        );
        let many: Vec<String> = upstream
            .headers
            .get_all("x-many")
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        // Plain maps are `set`: array values replace any existing fields with
        // every configured value.
        assert_eq!(many, ["a", "3"]);
    }

    #[test]
    fn structured_headers_expand_arrays_for_add_and_set() {
        let config = PluginConfig::try_from(serde_json::json!({
            "uri": "/new",
            "headers": {
                "set": [{ "name": "X-Set", "value": ["one", 2] }],
                "add": [{ "name": "X-Add", "value": ["alpha", "beta"] }],
                "remove": ["X-Remove"]
            }
        }))
        .expect("structured headers should parse");

        let headers = config.headers.clone().expect("headers parsed");
        let mut upstream = RequestHeader::build("GET", b"/", Some(2)).expect("request builds");
        upstream
            .insert_header("X-Remove", "drop-me")
            .expect("insert");

        PluginProxyRewrite {
            config,
            regex_patterns: Vec::new(),
        }
        .apply_headers(&mut upstream, &headers)
        .expect("headers apply");

        // `set` replaces the header with every configured value.
        let set_values: Vec<String> = upstream
            .headers
            .get_all("x-set")
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        assert_eq!(set_values, ["one", "2"]);
        let added: Vec<String> = upstream
            .headers
            .get_all("x-add")
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        assert_eq!(added, ["alpha", "beta"]);
        assert!(upstream.headers.get("x-remove").is_none());
    }

    #[test]
    fn apisix_structured_header_maps_are_accepted() {
        let config = PluginConfig::try_from(serde_json::json!({
            "uri": "/new",
            "headers": {
                "set": { "X-Set": ["one", 2] },
                "add": { "X-Add": ["alpha", "beta"] },
                "remove": ["X-Remove"]
            }
        }))
        .expect("APISIX structured header maps should parse");

        let headers = config.headers.clone().expect("headers parsed");
        let mut upstream = RequestHeader::build("GET", b"/", Some(2)).expect("request builds");
        upstream
            .insert_header("X-Remove", "drop-me")
            .expect("insert");

        PluginProxyRewrite {
            config,
            regex_patterns: Vec::new(),
        }
        .apply_headers(&mut upstream, &headers)
        .expect("headers apply");

        // `set` replaces the header with every configured value.
        let set_values: Vec<String> = upstream
            .headers
            .get_all("x-set")
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        assert_eq!(set_values, ["one", "2"]);
        let added: Vec<String> = upstream
            .headers
            .get_all("x-add")
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        assert_eq!(added, ["alpha", "beta"]);
        assert!(upstream.headers.get("x-remove").is_none());
    }

    #[test]
    fn header_operation_order_matches_apisix_add_then_set_then_remove() {
        let config = PluginConfig::try_from(serde_json::json!({
            "uri": "/new",
            "headers": {
                "add": { "X-Mix": "added" },
                "set": { "X-Mix": "set" },
                "remove": ["X-Mix"]
            }
        }))
        .expect("structured headers parse");

        let headers = config.headers.clone().expect("headers parsed");
        let mut upstream = RequestHeader::build("GET", b"/", Some(1)).expect("request builds");
        upstream.insert_header("X-Mix", "original").expect("insert");

        PluginProxyRewrite {
            config,
            regex_patterns: Vec::new(),
        }
        .apply_headers(&mut upstream, &headers)
        .expect("headers apply");

        // add appends, set replaces with its values, remove deletes last.
        assert!(upstream.headers.get("x-mix").is_none());
    }

    #[test]
    fn header_values_reject_bool_null_object_and_array_of_bad_values() {
        for bad in [
            serde_json::json!({ "headers": { "X": true } }),
            serde_json::json!({ "headers": { "X": null } }),
            serde_json::json!({ "headers": { "X": { "nested": true } } }),
            serde_json::json!({ "headers": { "X": ["ok", false] } }),
            serde_json::json!({ "headers": { "X": [] } }),
        ] {
            let cfg = serde_json::json!({ "uri": "/new", "headers": bad["headers"] });
            assert!(PluginConfig::try_from(cfg).is_err(), "expected rejection");
        }
    }

    #[test]
    fn use_real_request_uri_unsafe_is_ignored() {
        // PingSIX always forwards the session's real request URI, so the
        // APISIX flag is a tolerated unknown field.
        let config = PluginConfig::try_from(serde_json::json!({
            "uri": "/new",
            "use_real_request_uri_unsafe": true
        }))
        .unwrap();
        assert_eq!(config.uri.as_deref(), Some("/new"));
    }

    #[test]
    fn uri_must_start_with_slash() {
        assert!(PluginConfig::try_from(serde_json::json!({ "uri": "relative" })).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "uri": "" })).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "uri": "/" })).is_ok());
        assert!(PluginConfig::try_from(serde_json::json!({ "uri": "/ok" })).is_ok());
    }

    #[test]
    fn regex_uri_must_have_even_length_of_at_least_two() {
        assert!(PluginConfig::try_from(serde_json::json!({ "regex_uri": [] })).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "regex_uri": ["^/a$"] })).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "regex_uri": ["^/a$", "/b"] })).is_ok());
    }

    #[test]
    fn method_is_restricted_to_the_apisix_enum() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "uri": "/new",
            "method": ""
        }))
        .is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({
                "uri": "/new",
                "method": "post"
            }))
            .is_err(),
            "method enum is case-sensitive like APISIX"
        );
        for method in [
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
        ] {
            assert!(
                PluginConfig::try_from(serde_json::json!({
                    "uri": "/new",
                    "method": method
                }))
                .is_ok(),
                "{method} must be accepted"
            );
        }
    }

    #[test]
    fn uri_is_bounded_by_the_apisix_schema() {
        let long = format!("/{}", "a".repeat(4096));
        assert!(PluginConfig::try_from(serde_json::json!({ "uri": long })).is_err());
        let ok = format!("/{}", "a".repeat(4095));
        assert!(PluginConfig::try_from(serde_json::json!({ "uri": ok })).is_ok());
    }

    #[test]
    fn mixed_plain_and_structured_header_shapes_are_rejected() {
        // APISIX's structured arm is additionalProperties: false; a plain
        // entry next to add/set/remove must fail loudly, not silently drop.
        let err = PluginConfig::try_from(serde_json::json!({
            "headers": {"X-Api-Key": "v", "set": {"X-Other": "w"}}
        }))
        .unwrap_err();
        assert!(err.to_string().contains("'X-Api-Key'"), "{err}");

        // Valid shapes keep parsing.
        assert!(PluginConfig::try_from(serde_json::json!({
            "headers": {"X-Api-Key": "v"}
        }))
        .is_ok());
        assert!(PluginConfig::try_from(serde_json::json!({
            "headers": {"set": {"X-Other": "w"}}
        }))
        .is_ok());
    }

    #[test]
    fn invalid_configured_headers_fail_at_build_time() {
        let create = |headers: serde_json::Value| {
            create_proxy_rewrite_plugin(
                serde_json::json!({ "uri": "/new", "headers": headers }),
                &crate::config::EffectiveDefaults::default(),
            )
        };
        // Invalid name (space) in the plain shape.
        let err = match create(serde_json::json!({ "X Bad": "v" })) {
            Ok(_) => panic!("invalid header name must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("X Bad"), "{err}");
        // Invalid value (CR/LF) in the structured shape.
        let err = match create(serde_json::json!({ "set": {"X-Other": "bad\r\nvalue"} })) {
            Ok(_) => panic!("invalid header value must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("X-Other"), "{err}");
        // Invalid name in remove.
        let err = match create(serde_json::json!({ "remove": ["X Bad"] })) {
            Ok(_) => panic!("invalid remove name must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("X Bad"), "{err}");
        // Valid entries still build.
        assert!(create(serde_json::json!({ "X-Good": "ok" })).is_ok());
    }
}
