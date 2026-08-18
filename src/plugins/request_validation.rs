//! Request validation plugin, APISIX `request-validation` compatible.
//!
//! Validates requests against JSON Schemas before they reach the upstream:
//!
//! * `header_schema` — validated in the request phase against a JSON view of
//!   the request headers (single-valued headers become strings, repeated
//!   headers become arrays, mirroring APISIX's `ngx.req.get_headers` table).
//! * `body_schema` — the body is buffered (never forwarded) until complete,
//!   decoded by content type (`application/x-www-form-urlencoded` as a form
//!   object, anything else as JSON — APISIX's default), and validated as a
//!   whole. Only after validation passes is the body released upstream, so an
//!   invalid payload never reaches the backend.
//!
//! Rejections in the request phase carry `rejected_msg` (or the first schema
//! violation) as the response body. Body-phase failures must travel through
//! Pingora's error path (`request_body_filter` has no short-circuit channel),
//! so they surface with `rejected_code` and an empty body — an
//! `exit-transformer` rule can supply one when needed.
//!
//! APISIX parity notes: a request without a body is rejected when
//! `body_schema` is set (fail-closed, like `core.request.get_body` returning
//! nil), a duplicated `Content-Type` header is rejected as ambiguous, and
//! buffering is bounded by `max_req_body_size` (default 64 MiB).

use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use jsonschema::Validator;
use pingora_error::{Error, ErrorType, Result};
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    core::{PluginPhases, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::config::parse_and_validate_plugin_config,
    utils::response::send_exit_response,
};

pub const PLUGIN_NAME: &str = "request-validation";

/// APISIX `request-validation` runs at priority 2800 (after uri-blocker
/// 2900, before auth plugins).
const PRIORITY: i32 = 2800;

/// Context key holding the buffered request body for this request.
const CTX_KEY_BODY_BUFFER: &str = "pingsix_request_validation_body";

/// Creates a `request-validation` plugin instance from JSON configuration.
pub fn create_request_validation_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    let compiled = config.compile()?;
    Ok(Arc::new(PluginRequestValidation { compiled }))
}

/// APISIX `request-validation` schema.
#[derive(Debug, Serialize, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct PluginConfig {
    /// JSON Schema validated against the request headers.
    header_schema: Option<JsonValue>,
    /// JSON Schema validated against the decoded request body.
    body_schema: Option<JsonValue>,
    /// Maximum request body size in bytes buffered into memory; larger
    /// bodies are rejected.
    #[serde(default = "PluginConfig::default_max_req_body_size")]
    #[validate(range(min = 1))]
    max_req_body_size: u64,
    /// Status code returned when rejecting requests.
    #[serde(default = "PluginConfig::default_rejected_code")]
    #[validate(range(min = 200, max = 599))]
    rejected_code: u16,
    /// Message returned when rejecting requests.
    #[validate(length(min = 1, max = 256))]
    rejected_msg: Option<String>,
}

impl PluginConfig {
    fn default_max_req_body_size() -> u64 {
        // APISIX master: 64 MiB.
        64 * 1024 * 1024
    }

    fn default_rejected_code() -> u16 {
        400
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        // anyOf: at least one of header_schema / body_schema (APISIX schema).
        let has_header = value
            .get("header_schema")
            .is_some_and(|schema| !schema.is_null());
        let has_body = value
            .get("body_schema")
            .is_some_and(|schema| !schema.is_null());
        if !has_header && !has_body {
            return Err(ProxyError::validation_error(
                "request-validation requires at least one of header_schema or body_schema",
            ));
        }

        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid request-validation plugin config")?;
        Ok(config)
    }
}

/// Compiled validation artifacts, built once at plugin construction.
struct Compiled {
    header_validator: Option<Arc<Validator>>,
    body_validator: Option<Arc<Validator>>,
    max_req_body_size: u64,
    rejected_code: u16,
    rejected_msg: Option<String>,
}

impl PluginConfig {
    fn compile(&self) -> ProxyResult<Compiled> {
        let compile =
            |schema: &Option<JsonValue>, field: &str| -> ProxyResult<Option<Arc<Validator>>> {
                match schema {
                    Some(schema) => {
                        let validator = jsonschema::validator_for(schema).map_err(|e| {
                            ProxyError::validation_error(format!(
                                "request-validation {field} is not a valid JSON Schema: {e}"
                            ))
                        })?;
                        Ok(Some(Arc::new(validator)))
                    }
                    None => Ok(None),
                }
            };

        Ok(Compiled {
            header_validator: compile(&self.header_schema, "header_schema")?,
            body_validator: compile(&self.body_schema, "body_schema")?,
            max_req_body_size: self.max_req_body_size,
            rejected_code: self.rejected_code,
            rejected_msg: self.rejected_msg.clone(),
        })
    }
}

pub struct PluginRequestValidation {
    compiled: Compiled,
}

/// Canonical title-case form of a header name (`content-type` ->
/// `Content-Type`), reproducing the casing of `ngx.req.get_headers` that
/// APISIX header schemas are written against.
fn titled_header_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut uppercase_next = true;
    for ch in name.chars() {
        if uppercase_next {
            out.extend(ch.to_uppercase());
        } else {
            out.extend(ch.to_lowercase());
        }
        uppercase_next = ch == '-';
    }
    out
}

/// Convert request headers into the JSON object JSON Schema validates
/// against. Repeated headers become arrays (ngx table semantics) and names
/// are canonicalized to title case.
pub(crate) fn headers_to_json(headers: &HeaderMap) -> JsonValue {
    use serde_json::{Map, Value};

    let mut map: Map<String, Value> = Map::new();
    for (name, value) in headers {
        let key = titled_header_name(name.as_str());
        let value = value.to_str().map(str::to_string).unwrap_or_default();
        match map.get_mut(&key) {
            None => {
                map.insert(key, Value::String(value));
            }
            Some(Value::String(existing)) => {
                let mut values: Vec<Value> = vec![Value::String(std::mem::take(existing))];
                values.push(Value::String(value));
                map.insert(key, Value::Array(values));
            }
            Some(Value::Array(values)) => values.push(Value::String(value)),
            Some(_) => unreachable!("headers_to_json only inserts strings and arrays"),
        }
    }
    Value::Object(map)
}

/// Decode a form-urlencoded body into a JSON object. Duplicate keys become
/// arrays, matching `ngx.decode_args`.
pub(crate) fn form_body_to_json(body: &[u8]) -> Option<JsonValue> {
    use serde_json::{Map, Value};

    let mut map: Map<String, Value> = Map::new();
    for (key, value) in url::form_urlencoded::parse(body) {
        let (key, value) = (key.into_owned(), value.into_owned());
        match map.get_mut(&key) {
            None => {
                map.insert(key, Value::String(value));
            }
            Some(Value::String(existing)) => {
                let mut values: Vec<Value> = vec![Value::String(std::mem::take(existing))];
                values.push(Value::String(value));
                map.insert(key, Value::Array(values));
            }
            Some(Value::Array(values)) => values.push(Value::String(value)),
            Some(_) => return None,
        }
    }
    Some(Value::Object(map))
}

/// Decode the buffered body by content type: form-urlencoded when the
/// Content-Type says so, JSON otherwise (APISIX default).
pub(crate) fn decode_body(body: &[u8], content_type: Option<&str>) -> Option<JsonValue> {
    let is_form = content_type.is_some_and(|ct| {
        ct.trim_start()
            .to_ascii_lowercase()
            .starts_with("application/x-www-form-urlencoded")
    });
    if is_form {
        form_body_to_json(body)
    } else {
        serde_json::from_slice(body).ok()
    }
}

/// First schema violation message for an instance, for rejection bodies.
fn first_error(validator: &Validator, instance: &JsonValue) -> Option<String> {
    validator
        .iter_errors(instance)
        .next()
        .map(|e| e.to_string())
}

impl PluginRequestValidation {
    /// Whether the request carries a body at all (declared or chunked).
    fn request_declares_body(headers: &HeaderMap) -> bool {
        let chunked = headers
            .get(http::header::TRANSFER_ENCODING)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let content_length = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        chunked || content_length > 0
    }

    /// Reject via the shared exit helper with `rejected_msg` (or the schema
    /// error) as the body.
    async fn reject(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
        detail: Option<String>,
    ) -> Result<bool> {
        let body = self
            .compiled
            .rejected_msg
            .clone()
            .or(detail)
            .unwrap_or_default();
        send_exit_response(
            session,
            self.compiled.rejected_code,
            Some(body.as_str()),
            None,
            &[],
            ctx,
        )
        .await?;
        Ok(true)
    }

    /// Reject a streaming body failure through Pingora's error path. The
    /// status travels on `ErrorType::HTTPStatus`, which the service's
    /// `fail_to_proxy` maps to the client response.
    fn reject_streaming(&self, reason: &'static str) -> Box<Error> {
        Error::explain(ErrorType::HTTPStatus(self.compiled.rejected_code), reason)
    }
}

#[async_trait]
impl ProxyPlugin for PluginRequestValidation {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    fn phases(&self) -> PluginPhases {
        PluginPhases::REQUEST | PluginPhases::REQUEST_BODY
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        let headers = &session.req_header().headers;

        // 1. Header schema validation.
        if let Some(validator) = &self.compiled.header_validator {
            let instance = headers_to_json(headers);
            if !validator.is_valid(&instance) {
                log::debug!("request-validation: header schema violation");
                let detail = first_error(validator, &instance);
                return self.reject(session, ctx, detail).await;
            }
        }

        // 2. Body pre-checks (only when a body schema is configured).
        //
        // A body-transforming plugin (ai-proxy, priority 2900) may already
        // have replaced the request body before this plugin runs; validating
        // a replacement against a client-format body_schema would misreject,
        // so body handling is skipped whenever the body was replaced. Header
        // validation above still applies. (This covers same-scope mixes; a
        // global-scope request-validation still buffers before a route-scope
        // ai-proxy injects — see the ai-proxy docs.)
        if self.compiled.body_validator.is_some() && !ctx.request_body_replaced() {
            // Duplicated Content-Type is ambiguous: the gateway and the
            // upstream may parse the body differently, bypassing validation.
            if headers.get_all(http::header::CONTENT_TYPE).iter().count() > 1 {
                log::debug!("request-validation: duplicated Content-Type header");
                return self.reject(session, ctx, None).await;
            }

            // APISIX parity: with body_schema set, a bodyless request is
            // rejected (fail closed).
            if !Self::request_declares_body(headers) {
                log::debug!("request-validation: body_schema set but request has no body");
                return self.reject(session, ctx, None).await;
            }
        }

        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Only participate when a body schema is configured; otherwise chunks
        // pass through untouched.
        let Some(validator) = &self.compiled.body_validator else {
            return Ok(());
        };

        // A plugin replaced the request body with a gateway-generated one;
        // the client-format body schema does not apply to the replacement.
        if ctx.request_body_replaced() {
            return Ok(());
        }

        // Swallow the chunk into the per-request buffer; nothing reaches the
        // upstream until validation passes.
        if let Some(chunk) = body.take() {
            let buffer = ctx
                .vars
                .get_or_insert_with(Default::default)
                .entry(CTX_KEY_BODY_BUFFER.to_string())
                .or_insert_with(|| Box::new(BytesMut::new()));
            let buffer = buffer
                .downcast_mut::<BytesMut>()
                .expect("request-validation body buffer");
            buffer.extend_from_slice(&chunk);

            if buffer.len() as u64 > self.compiled.max_req_body_size {
                log::debug!(
                    "request-validation: body exceeded max_req_body_size {}",
                    self.compiled.max_req_body_size
                );
                return Err(self.reject_streaming("request body too large"));
            }
        }

        if !end_of_stream {
            // Keep the upstream stream open. Returning `None` here would be
            // read as "body finished" by pingora's request-body pipeline
            // (h1 sends the terminating chunk, h2 sets END_STREAM), so the
            // swallowed chunk must leave an empty-but-present placeholder;
            // pingora skips writing 0-byte chunks mid-stream. Without this,
            // chunked client requests would reach the upstream as an empty
            // body after the very first chunk.
            *body = Some(Bytes::new());
            return Ok(());
        }

        // End of body: take the buffer back out of the context and validate.
        let buffer = ctx
            .vars
            .as_mut()
            .and_then(|vars| vars.remove(CTX_KEY_BODY_BUFFER))
            .and_then(|boxed| boxed.downcast::<BytesMut>().ok())
            .map(|boxed| *boxed)
            .unwrap_or_default();

        let instance = match decode_body(
            &buffer,
            session
                .req_header()
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
        ) {
            Some(instance) => instance,
            None => {
                log::debug!("request-validation: request body failed to decode");
                return Err(self.reject_streaming("request body failed to decode"));
            }
        };

        if !validator.is_valid(&instance) {
            let detail = first_error(validator, &instance);
            log::debug!("request-validation: body schema violation: {detail:?}");
            return Err(self.reject_streaming("request body failed schema validation"));
        }

        // Validation passed: release the full original body upstream.
        if !buffer.is_empty() {
            *body = Some(buffer.freeze());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled(cfg: JsonValue) -> Arc<PluginRequestValidation> {
        // Child module: construct the concrete type directly so tests can
        // inspect the private compiled artifacts.
        let config = PluginConfig::try_from(cfg).expect("valid config");
        Arc::new(PluginRequestValidation {
            compiled: config.compile().expect("compiles"),
        })
    }

    #[test]
    fn config_requires_at_least_one_schema() {
        assert!(PluginConfig::try_from(serde_json::json!({})).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "rejected_code": 400 })).is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({ "header_schema": {"type": "object"} }))
                .is_ok()
        );
        assert!(
            PluginConfig::try_from(serde_json::json!({ "body_schema": {"type": "object"} }))
                .is_ok()
        );
    }

    #[test]
    fn config_rejects_unknown_fields() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "header_schema": {"type": "object"}, "typo": true
        }))
        .is_err());
    }

    #[test]
    fn defaults_match_apisix() {
        let plugin = compiled(serde_json::json!({ "header_schema": {"type": "object"} }));
        assert_eq!(plugin.compiled.rejected_code, 400);
        assert_eq!(plugin.compiled.max_req_body_size, 64 * 1024 * 1024);
        assert!(plugin.compiled.rejected_msg.is_none());
    }

    #[test]
    fn rejected_code_and_msg_validate() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "header_schema": {"type": "object"}, "rejected_code": 199
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "header_schema": {"type": "object"}, "rejected_msg": ""
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "header_schema": {"type": "object"},
            "rejected_code": 422,
            "rejected_msg": "invalid request"
        }))
        .is_ok());
    }

    #[test]
    fn invalid_json_schema_fails_at_build() {
        // A `$ref` to a remote document cannot resolve offline: fail at
        // config time, never per request.
        let err = match create_request_validation_plugin(
            serde_json::json!({
                "body_schema": {"$ref": "https://example.com/schema.json"}
            }),
            &crate::config::EffectiveDefaults::default(),
        ) {
            Err(err) => err,
            Ok(_) => panic!("unresolvable ref must fail"),
        };
        assert!(err.to_string().contains("body_schema"));
    }

    #[test]
    fn header_view_strings_and_arrays() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-version", "2".parse().unwrap());
        headers.append("x-tag", "a".parse().unwrap());
        headers.append("x-tag", "b".parse().unwrap());
        let view = headers_to_json(&headers);
        assert_eq!(view["X-Api-Version"], serde_json::json!("2"));
        assert_eq!(view["X-Tag"], serde_json::json!(["a", "b"]));
    }

    #[test]
    fn header_view_names_are_title_cased() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "curl/8".parse().unwrap());
        let view = headers_to_json(&headers);
        assert_eq!(view["User-Agent"], serde_json::json!("curl/8"));
    }

    #[test]
    fn header_view_validates_against_schema() {
        let plugin = compiled(serde_json::json!({
            "header_schema": {
                "type": "object",
                "required": ["X-Api-Version"],
                "properties": {"X-Api-Version": {"type": "string", "pattern": "^v[0-9]+$"}}
            }
        }));
        let validator = plugin.compiled.header_validator.as_ref().unwrap();

        let mut ok = HeaderMap::new();
        ok.insert("X-Api-Version", "v2".parse().unwrap());
        assert!(validator.is_valid(&headers_to_json(&ok)));

        let mut bad = HeaderMap::new();
        bad.insert("X-Api-Version", "2".parse().unwrap());
        assert!(!validator.is_valid(&headers_to_json(&bad)));

        assert!(!validator.is_valid(&headers_to_json(&HeaderMap::new())));
    }

    #[test]
    fn body_decode_json_and_form() {
        let json = decode_body(br#"{"a": 1}"#, Some("application/json")).unwrap();
        assert_eq!(json["a"], serde_json::json!(1));

        let form = decode_body(b"a=1&b=x&b=y", Some("application/x-www-form-urlencoded")).unwrap();
        assert_eq!(form["a"], serde_json::json!("1"));
        assert_eq!(form["b"], serde_json::json!(["x", "y"]));

        // No content type: JSON is the default (APISIX).
        assert!(decode_body(b"{\"k\": true}", None).is_some());
        // Invalid JSON fails closed.
        assert!(decode_body(b"{not json", None).is_none());
    }

    #[test]
    fn body_schema_validates_decoded_instance() {
        let plugin = compiled(serde_json::json!({
            "body_schema": {
                "type": "object",
                "required": ["quantity"],
                "properties": {"quantity": {"type": "integer", "minimum": 1}}
            }
        }));
        let validator = plugin.compiled.body_validator.as_ref().unwrap();
        assert!(validator.is_valid(&serde_json::json!({"quantity": 3})));
        assert!(!validator.is_valid(&serde_json::json!({"quantity": 0})));
        assert!(!validator.is_valid(&serde_json::json!("string")));
    }

    #[test]
    fn streaming_rejection_carries_status() {
        let plugin = compiled(serde_json::json!({
            "body_schema": {"type": "object"},
            "rejected_code": 422
        }));
        let err = plugin.reject_streaming("request body failed to decode");
        assert_eq!(*err.etype(), ErrorType::HTTPStatus(422));
    }
}
