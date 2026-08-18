//! Pure request-body transformation: client OpenAI-format JSON → provider
//! request body.
//!
//! Everything here is a pure function over bytes/JSON — no `Session`, no
//! context — so the full matrix (merge, mapping, conversion, errors) is
//! exhaustively unit-testable and the runtime layers stay thin.
//!
//! Pipeline (order is load-bearing):
//! 1. Parse the client body and validate the OpenAI chat shape
//!    (fail-closed, like APISIX's `chat_request_schema`).
//! 2. Deep-merge `options` (objects recurse; arrays and scalars replace
//!    wholesale — options values win, mirroring APISIX model options).
//! 3. Apply `override.llm_options.max_tokens` to the provider's target
//!    field (forced: always overwrites the client value).
//! 4. For anthropic, convert the structure to Anthropic Messages format.
//! 5. Serialize once (`serde_json::to_vec`): the byte length is the exact
//!    upstream Content-Length.

use bytes::Bytes;
use serde_json::{Map, Value as JsonValue};

use super::provider::{provider_spec, MaxTokensField, Provider};

/// The transformed outbound request.
#[derive(Debug, Clone)]
pub(crate) struct TransformedRequest {
    /// Deterministically serialized provider-format body. Its length is the
    /// recomputed upstream Content-Length.
    pub(crate) body: Bytes,
    /// Whether the final body carries `"stream": true`.
    pub(crate) streaming: bool,
}

/// Structured transformation failure, mapped to a 400 response by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TransformError {
    /// Body is not parseable JSON or not a JSON object.
    InvalidJson(String),
    /// A required field is absent (e.g. `messages`).
    MissingField(String),
    /// `messages` has an unusable shape (non-array, bad element, bad role).
    BadMessagesShape(String),
}

impl TransformError {
    /// Client-facing error detail (goes into the 400 response body).
    pub(crate) fn detail(&self) -> String {
        match self {
            TransformError::InvalidJson(message) => message.clone(),
            TransformError::MissingField(field) => {
                format!("request body is missing required field '{field}'")
            }
            TransformError::BadMessagesShape(message) => message.clone(),
        }
    }
}

/// Transform a client OpenAI-format body into the provider request body.
///
/// * `options` — deep-merged over the client body (`None` = no options).
/// * `max_tokens` — forced value for the provider's token-limit field
///   (`None` = leave the body untouched).
pub(crate) fn transform_request(
    client_body: &[u8],
    options: Option<&JsonValue>,
    max_tokens: Option<u64>,
    provider: Provider,
) -> Result<TransformedRequest, TransformError> {
    let mut body: JsonValue = serde_json::from_slice(client_body).map_err(|error| {
        TransformError::InvalidJson(format!("request body is not valid JSON: {error}"))
    })?;
    if !body.is_object() {
        return Err(TransformError::InvalidJson(
            "request body must be a JSON object".to_string(),
        ));
    }

    // Validate the client's chat shape BEFORE merging options (APISIX
    // validates the client body at read time; options cannot repair it).
    validate_messages_shape(&body)?;

    if let Some(options) = options.filter(|options| options.is_object()) {
        deep_merge(&mut body, options);
    }

    if let Some(max_tokens) = max_tokens {
        apply_max_tokens(&mut body, max_tokens, provider);
    }

    if provider == Provider::Anthropic {
        let converted = convert_to_anthropic(&body)?;
        body = JsonValue::Object(converted);
    }

    let streaming = body.get("stream") == Some(&JsonValue::Bool(true));
    let serialized = serde_json::to_vec(&body).map_err(|error| {
        TransformError::InvalidJson(format!("failed to serialize transformed body: {error}"))
    })?;
    Ok(TransformedRequest {
        body: Bytes::from(serialized),
        streaming,
    })
}

/// Fail-closed OpenAI chat-shape validation: `messages` must be a non-empty
/// array of objects with string `role` and string `content`.
fn validate_messages_shape(body: &JsonValue) -> Result<(), TransformError> {
    let Some(messages) = body.get("messages") else {
        return Err(TransformError::MissingField("messages".to_string()));
    };
    let Some(array) = messages.as_array() else {
        return Err(TransformError::BadMessagesShape(
            "messages must be an array".to_string(),
        ));
    };
    if array.is_empty() {
        return Err(TransformError::BadMessagesShape(
            "messages must contain at least one message".to_string(),
        ));
    }
    for (index, message) in array.iter().enumerate() {
        let Some(object) = message.as_object() else {
            return Err(TransformError::BadMessagesShape(format!(
                "messages[{index}] must be an object"
            )));
        };
        let Some(role) = object.get("role").and_then(JsonValue::as_str) else {
            return Err(TransformError::BadMessagesShape(format!(
                "messages[{index}].role must be a string"
            )));
        };
        if role.is_empty() {
            return Err(TransformError::BadMessagesShape(format!(
                "messages[{index}].role must not be empty"
            )));
        }
        if object.get("content").and_then(JsonValue::as_str).is_none() {
            return Err(TransformError::BadMessagesShape(format!(
                "messages[{index}].content must be a string"
            )));
        }
    }
    Ok(())
}

/// RFC-7396-style deep merge: objects recurse; arrays and scalars replace
/// wholesale; keys absent from the target are inserted. Patch values win.
/// (Unlike RFC 7396, `null` patches overwrite instead of deleting — APISIX's
/// merge semantics do not delete either.)
pub(crate) fn deep_merge(target: &mut JsonValue, patch: &JsonValue) {
    match (target, patch) {
        (JsonValue::Object(target_map), JsonValue::Object(patch_map)) => {
            for (key, patch_value) in patch_map {
                match target_map.get_mut(key) {
                    Some(target_value) if target_value.is_object() && patch_value.is_object() => {
                        deep_merge(target_value, patch_value);
                    }
                    _ => {
                        target_map.insert(key.clone(), patch_value.clone());
                    }
                }
            }
        }
        (target_value, patch_value) => {
            *target_value = patch_value.clone();
        }
    }
}

/// Forced `override.llm_options.max_tokens` mapping.
///
/// OpenAI writes `max_completion_tokens` and deletes the legacy
/// `max_tokens` (carrying both is rejected upstream — APISIX openai driver
/// does the same). Every other v1 provider writes classic `max_tokens`.
fn apply_max_tokens(body: &mut JsonValue, max_tokens: u64, provider: Provider) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    match provider_spec(provider).max_tokens_field {
        MaxTokensField::MaxCompletionTokens => {
            object.insert(
                "max_completion_tokens".to_string(),
                JsonValue::from(max_tokens),
            );
            object.remove("max_tokens");
        }
        MaxTokensField::MaxTokens => {
            object.insert("max_tokens".to_string(), JsonValue::from(max_tokens));
        }
    }
}

/// OpenAI Chat → Anthropic Messages conversion.
///
/// * `system` role messages are extracted into the top-level `system` string.
/// * `user`/`assistant` messages are kept as-is (string content).
/// * `max_tokens` is required by Anthropic; when only the OpenAI-style
///   `max_completion_tokens` is present it is renamed.
/// * A small whitelist of compatible fields passes through
///   (`stream`, `temperature`, `top_p`, `top_k`); `stop` becomes
///   `stop_sequences`. Other OpenAI-only fields (`tools`, `n`,
///   `response_format`, …) are dropped — Anthropic rejects unknown fields.
fn convert_to_anthropic(body: &JsonValue) -> Result<Map<String, JsonValue>, TransformError> {
    let mut out = Map::new();

    let mut system_parts: Vec<String> = Vec::new();
    let mut messages: Vec<JsonValue> = Vec::new();
    if let Some(array) = body.get("messages").and_then(JsonValue::as_array) {
        for (index, message) in array.iter().enumerate() {
            let role = message.get("role").and_then(JsonValue::as_str);
            let content = message.get("content").and_then(JsonValue::as_str);
            match (role, content) {
                (Some(role), Some(content)) => match role {
                    "system" => system_parts.push(content.to_string()),
                    "user" | "assistant" => {
                        messages.push(serde_json::json!({ "role": role, "content": content }));
                    }
                    other => {
                        return Err(TransformError::BadMessagesShape(format!(
                            "messages[{index}].role '{other}' is not supported by provider \
                             anthropic (supported: system, user, assistant)"
                        )));
                    }
                },
                (Some(_), None) => {
                    return Err(TransformError::BadMessagesShape(format!(
                        "messages[{index}].content must be a string"
                    )));
                }
                (None, _) => {
                    return Err(TransformError::BadMessagesShape(format!(
                        "messages[{index}].role must be a string"
                    )));
                }
            }
        }
    }

    if let Some(model) = body.get("model").filter(|value| !value.is_null()) {
        out.insert("model".to_string(), model.clone());
    }
    if !system_parts.is_empty() {
        out.insert(
            "system".to_string(),
            JsonValue::String(system_parts.join("\n\n")),
        );
    }
    out.insert("messages".to_string(), JsonValue::Array(messages));

    // Anthropic requires `max_tokens`; fall back from the OpenAI spelling.
    let max_tokens = body
        .get("max_tokens")
        .filter(|value| !value.is_null())
        .or_else(|| {
            body.get("max_completion_tokens")
                .filter(|value| !value.is_null())
        });
    if let Some(max_tokens) = max_tokens {
        out.insert("max_tokens".to_string(), max_tokens.clone());
    }

    for field in ["stream", "temperature", "top_p", "top_k"] {
        if let Some(value) = body.get(field).filter(|value| !value.is_null()) {
            out.insert(field.to_string(), value.clone());
        }
    }
    if let Some(stop) = body.get("stop").filter(|value| !value.is_null()) {
        out.insert("stop_sequences".to_string(), stop.clone());
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn transform(
        body: &[u8],
        options: Option<&JsonValue>,
        max_tokens: Option<u64>,
        provider: Provider,
    ) -> Result<TransformedRequest, TransformError> {
        transform_request(body, options, max_tokens, provider)
    }

    fn ok_body(
        body: &[u8],
        options: Option<&JsonValue>,
        max_tokens: Option<u64>,
        provider: Provider,
    ) -> JsonValue {
        serde_json::from_slice(&transform(body, options, max_tokens, provider).unwrap().body)
            .unwrap()
    }

    const CLIENT_BODY: &str =
        r#"{"model":"client-model","messages":[{"role":"user","content":"hi"}]}"#;

    // ------------------------------------------------------------------
    // Error paths
    // ------------------------------------------------------------------

    #[test]
    fn invalid_json_and_non_object_roots_are_rejected() {
        for bad in [
            &b"{not json"[..],
            &b"[1,2]"[..],
            &b"\"string\""[..],
            &b"null"[..],
        ] {
            let error = transform(bad, None, None, Provider::Openai).unwrap_err();
            assert!(matches!(error, TransformError::InvalidJson(_)), "{error:?}");
            assert!(!error.detail().is_empty());
        }
    }

    #[test]
    fn missing_or_malformed_messages_are_rejected() {
        // Missing messages.
        let error = transform(b"{}", None, None, Provider::Openai).unwrap_err();
        assert_eq!(error, TransformError::MissingField("messages".into()));
        assert!(error.detail().contains("messages"));

        // Not an array.
        let error = transform(br#"{"messages": "hi"}"#, None, None, Provider::Openai).unwrap_err();
        assert!(matches!(error, TransformError::BadMessagesShape(_)));

        // Empty array.
        let error = transform(br#"{"messages": []}"#, None, None, Provider::Openai).unwrap_err();
        assert!(error.detail().contains("at least one"));

        // Element missing role / content not a string.
        let error = transform(
            br#"{"messages": [{"content": "hi"}]}"#,
            None,
            None,
            Provider::Openai,
        )
        .unwrap_err();
        assert!(error.detail().contains("role"));

        let error = transform(
            br#"{"messages": [{"role": "user", "content": 42}]}"#,
            None,
            None,
            Provider::Openai,
        )
        .unwrap_err();
        assert!(error.detail().contains("content"));

        let error = transform(
            br#"{"messages": ["just a string"]}"#,
            None,
            None,
            Provider::Openai,
        )
        .unwrap_err();
        assert!(error.detail().contains("messages[0]"));

        // Client shape is validated BEFORE options merge: options cannot
        // repair a broken client body.
        let options = json!({"messages": [{"role": "user", "content": "ok"}]});
        let error = transform(b"{}", Some(&options), None, Provider::Openai).unwrap_err();
        assert_eq!(error, TransformError::MissingField("messages".into()));
    }

    // ------------------------------------------------------------------
    // options deep merge
    // ------------------------------------------------------------------

    #[test]
    fn options_deep_merge_recurses_objects_and_replaces_scalars() {
        let client =
            br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"nested":{"a":1,"b":2},"temperature":0.9}"#;
        let options = json!({"model": "cfg-model", "nested": {"b": 20, "c": 3}, "max_tokens": 512});
        let body = ok_body(client, Some(&options), None, Provider::Deepseek);

        // options values win; untouched client fields are kept.
        assert_eq!(body["model"], json!("cfg-model"));
        assert_eq!(body["nested"], json!({"a": 1, "b": 20, "c": 3}));
        assert_eq!(body["temperature"], json!(0.9));
        assert_eq!(body["max_tokens"], json!(512));
    }

    #[test]
    fn options_arrays_replace_wholesale() {
        let client = br#"{"messages":[{"role":"user","content":"hi"}],"stop":[1,2,3]}"#;
        let options = json!({"stop": ["END"]});
        let body = ok_body(client, Some(&options), None, Provider::Openai);
        assert_eq!(body["stop"], json!(["END"]));
    }

    #[test]
    fn options_null_overwrites() {
        let client = br#"{"messages":[{"role":"user","content":"hi"}],"temperature":0.5}"#;
        let options = json!({"temperature": null});
        let body = ok_body(client, Some(&options), None, Provider::Openai);
        assert_eq!(body["temperature"], JsonValue::Null);
    }

    #[test]
    fn openai_body_structure_is_untouched_without_options() {
        let body = ok_body(CLIENT_BODY.as_bytes(), None, None, Provider::Openai);
        assert_eq!(
            body,
            json!({"model": "client-model", "messages": [{"role": "user", "content": "hi"}]})
        );
    }

    // ------------------------------------------------------------------
    // max_tokens mapping
    // ------------------------------------------------------------------

    #[test]
    fn max_tokens_maps_per_provider_and_overrides_client_values() {
        let with_client_tokens = br#"{"messages":[{"role":"user","content":"hi"}],"max_tokens":8}"#;

        // openai: max_completion_tokens + legacy field removed.
        let body = ok_body(with_client_tokens, None, Some(1024), Provider::Openai);
        assert_eq!(body["max_completion_tokens"], json!(1024));
        assert!(body.get("max_tokens").is_none());

        // deepseek / openai-compatible / anthropic: classic field.
        for provider in [Provider::Deepseek, Provider::OpenaiCompatible] {
            let body = ok_body(with_client_tokens, None, Some(2048), provider);
            assert_eq!(body["max_tokens"], json!(2048), "{provider:?}");
        }
        let body = ok_body(with_client_tokens, None, Some(2048), Provider::Anthropic);
        assert_eq!(body["max_tokens"], json!(2048));

        // Without an override the client's fields pass through untouched.
        let body = ok_body(with_client_tokens, None, None, Provider::Openai);
        assert_eq!(body["max_tokens"], json!(8));
        assert!(body.get("max_completion_tokens").is_none());
    }

    // ------------------------------------------------------------------
    // Anthropic conversion
    // ------------------------------------------------------------------

    #[test]
    fn anthropic_extracts_system_and_keeps_user_assistant() {
        let client = br#"{"model":"claude-3","messages":[
            {"role":"system","content":"be brief"},
            {"role":"user","content":"hi"},
            {"role":"assistant","content":"hello"},
            {"role":"system","content":"stay brief"},
            {"role":"user","content":"bye"}
        ],"max_tokens":64,"temperature":0.3,"stop":["END"],"frequency_penalty":0.5}"#;
        let body = ok_body(client, None, None, Provider::Anthropic);

        assert_eq!(body["system"], json!("be brief\n\nstay brief"));
        assert_eq!(
            body["messages"],
            json!([
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"},
                {"role": "user", "content": "bye"}
            ])
        );
        assert_eq!(body["model"], json!("claude-3"));
        assert_eq!(body["max_tokens"], json!(64));
        assert_eq!(body["temperature"], json!(0.3));
        assert_eq!(body["stop_sequences"], json!(["END"]));
        // OpenAI-only fields are dropped.
        assert!(body.get("frequency_penalty").is_none());
        assert!(body.get("stop").is_none());
    }

    #[test]
    fn anthropic_renames_max_completion_tokens_fallback() {
        let client = br#"{"messages":[{"role":"user","content":"hi"}],"max_completion_tokens":77}"#;
        let body = ok_body(client, None, None, Provider::Anthropic);
        assert_eq!(body["max_tokens"], json!(77));
        assert!(body.get("max_completion_tokens").is_none());
    }

    #[test]
    fn anthropic_rejects_unsupported_roles() {
        let client = br#"{"messages":[{"role":"tool","content":"toolout"}]}"#;
        let error = transform(client, None, None, Provider::Anthropic).unwrap_err();
        assert!(error.detail().contains("'tool'"), "{}", error.detail());
    }

    #[test]
    fn anthropic_merge_happens_before_conversion() {
        // options injected model/temperature survive conversion.
        let options = json!({"model": "claude-3-5", "temperature": 0.7});
        let body = ok_body(
            br#"{"messages":[{"role":"user","content":"hi"}]}"#,
            Some(&options),
            None,
            Provider::Anthropic,
        );
        assert_eq!(body["model"], json!("claude-3-5"));
        assert_eq!(body["temperature"], json!(0.7));
    }

    // ------------------------------------------------------------------
    // stream detection
    // ------------------------------------------------------------------

    #[test]
    fn stream_flag_is_detected_from_the_final_body() {
        let base = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        assert!(
            !transform(base, None, None, Provider::Openai)
                .unwrap()
                .streaming
        );

        let streaming = br#"{"messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        assert!(
            transform(streaming, None, None, Provider::Openai)
                .unwrap()
                .streaming
        );

        // stream: false is not streaming.
        let not_streaming = br#"{"messages":[{"role":"user","content":"hi"}],"stream":false}"#;
        assert!(
            !transform(not_streaming, None, None, Provider::Openai)
                .unwrap()
                .streaming
        );

        // Detected through options too, and for anthropic.
        let options = json!({"stream": true});
        assert!(
            transform(base, Some(&options), None, Provider::Anthropic)
                .unwrap()
                .streaming
        );
    }

    #[test]
    fn serialization_is_deterministic_and_matches_body_length() {
        let transformed = transform(CLIENT_BODY.as_bytes(), None, None, Provider::Openai).unwrap();
        let reparsed = serde_json::from_slice::<JsonValue>(&transformed.body).unwrap();
        let reserialized = serde_json::to_vec(&reparsed).unwrap();
        assert_eq!(transformed.body.as_ref(), reserialized.as_slice());
    }
}
