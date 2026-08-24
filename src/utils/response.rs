//! Unified response handling utilities for both Admin API and Plugin responses.
//!
//! This module provides a consistent interface for building success and error responses
//! across different parts of the application, following the DRY principle.

use bytes::Bytes;
use http::{header, HeaderValue, Response, StatusCode};
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::Serialize;

use crate::core::{ExitTransform, ProxyContext, Rejection};

/// Standard content types
pub mod content_type {
    pub const TEXT_PLAIN: &str = "text/plain";
    pub const APPLICATION_JSON: &str = "application/json";
}

/// Unified response builder for different response types
pub struct ResponseBuilder;

impl ResponseBuilder {
    /// Build a success HTTP Response for Admin API
    pub fn success_http(body: Vec<u8>, content_type: Option<&str>) -> Response<Vec<u8>> {
        let mut builder = Response::builder().status(StatusCode::OK);

        if let Some(ct) = content_type {
            match HeaderValue::from_str(ct) {
                Ok(header_value) => {
                    builder = builder.header(header::CONTENT_TYPE, header_value);
                }
                Err(e) => {
                    log::error!("Invalid content type '{ct}': {e}");
                }
            }
        }

        builder.body(body).unwrap_or_else(|e| {
            log::error!("Failed to build success response: {e}");
            Self::error_http(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        })
    }

    /// Build an error HTTP Response for Admin API
    pub fn error_http(status: StatusCode, message: &str) -> Response<Vec<u8>> {
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, content_type::TEXT_PLAIN)
            .body(message.as_bytes().to_vec())
            .unwrap_or_else(|e| {
                log::error!("Failed to build error response: {e}");
                let mut resp = Response::new(b"Internal Server Error".to_vec());
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                resp
            })
    }

    /// Build a JSON success HTTP Response for Admin API
    pub fn success_json<T: Serialize>(data: &T) -> Response<Vec<u8>> {
        match serde_json::to_vec(data) {
            Ok(json_body) => Self::success_http(json_body, Some(content_type::APPLICATION_JSON)),
            Err(e) => {
                log::error!("Failed to serialize JSON response: {e}");
                Self::error_http(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "JSON serialization failed",
                )
            }
        }
    }
}

/// Fully resolved gateway exit response after `exit-transformer` rewriting.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ResolvedExitResponse {
    pub status: u16,
    pub body: Option<Vec<u8>>,
    pub content_type: Option<String>,
    /// Extra headers beyond content type and length.
    pub headers: Vec<(String, String)>,
}

/// Substitute `$status`, `$message`, and `$request_id` variables in a
/// transformer template.
pub(crate) fn substitute_exit_vars(
    template: &str,
    status: u16,
    message: Option<&str>,
    request_id: Option<&str>,
) -> String {
    template
        .replace("$status", &status.to_string())
        .replace("$message", message.unwrap_or(""))
        .replace("$request_id", request_id.unwrap_or(""))
}

/// Resolve a gateway exit through the request's `exit-transformer` rules.
///
/// Pure transform of `(status, body, content_type, headers)` so tests can pin
/// the rewriting contract without a session. Rules are first-match-wins on the
/// *original* status; `status_code` remaps the response, `body` replaces the
/// payload (with variable substitution), and `headers` are appended with
/// case-insensitive `Content-Type` recognized as the body content type.
pub(crate) fn resolve_exit_response(
    transform: Option<&ExitTransform>,
    status: u16,
    body: Option<&str>,
    content_type: Option<&str>,
    extra_headers: &[(String, String)],
    request_id: Option<&str>,
) -> ResolvedExitResponse {
    let mut resolved = ResolvedExitResponse {
        status,
        body: body.map(|b| b.as_bytes().to_vec()),
        content_type: content_type.map(str::to_string),
        headers: extra_headers.to_vec(),
    };

    let Some(rule) = transform.and_then(|t| t.matching(status)) else {
        return resolved;
    };

    if let Some(remap) = rule.status_code {
        resolved.status = remap;
    }

    if let Some(template) = &rule.body {
        // The template's `$status` refers to the final (remapped) status and
        // `$message` to the original exit message.
        resolved.body =
            Some(substitute_exit_vars(template, resolved.status, body, request_id).into_bytes());
        // A replaced body no longer matches the original content type; unless
        // the rule names one, fall back to text/plain (APISIX-style default).
        resolved.content_type = None;
    }

    for (name, value) in &rule.headers {
        let value = substitute_exit_vars(value, resolved.status, body, request_id);
        if name.eq_ignore_ascii_case("content-type") {
            resolved.content_type = Some(value);
        } else {
            // Later rule headers override earlier ones with the same name.
            resolved
                .headers
                .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
            resolved.headers.push((name.clone(), value));
        }
    }

    resolved
}

/// Send a gateway-generated exit response through `exit-transformer` rules.
///
/// Single choke point for every gateway rejection (plugin short-circuits,
/// `fail_to_proxy` error mapping, no-route 404): when the request's pipeline
/// carries an `exit-transformer` configuration, its matching rule rewrites the
/// status, body, and headers before anything reaches the client.
pub(crate) async fn send_exit_response(
    session: &mut Session,
    status: u16,
    body: Option<&str>,
    content_type: Option<&str>,
    extra_headers: &[(String, String)],
    ctx: &ProxyContext,
) -> Result<()> {
    use pingora_error::ErrorType;

    let resolved = resolve_exit_response(
        ctx.pipeline.exit_transform(),
        status,
        body,
        content_type,
        extra_headers,
        ctx.request_id(),
    );
    let ResolvedExitResponse {
        status: final_status,
        body: final_body,
        content_type: final_content_type,
        headers,
    } = resolved;

    let status_code = StatusCode::from_u16(final_status).map_err(|e| {
        pingora_error::Error::because(
            ErrorType::InternalError,
            "invalid exit-transformer status",
            e,
        )
    })?;

    // 1xx/204/304 responses MUST NOT carry a body or a Content-Length
    // (RFC 9110 §6.4.1, §15.4.5). A rule remapping onto one drops its body.
    let body_forbidden = matches!(final_status, 100..=199 | 204 | 304);
    let final_body = if body_forbidden { None } else { final_body };

    let mut resp = ResponseHeader::build(status_code, None)?;

    let has_body = final_body.as_ref().is_some_and(|body| !body.is_empty());
    if has_body {
        let body = final_body.expect("checked above");
        resp.insert_header(header::CONTENT_LENGTH, body.len().to_string())?;
        if let Some(ct) = &final_content_type {
            resp.insert_header(header::CONTENT_TYPE, ct.as_str())?;
        }
        for (name, value) in &headers {
            resp.insert_header(name.clone(), value.clone())?;
        }
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
    } else {
        // A bodyless HTTP/1.1 response without Content-Length is
        // close-delimited: on a kept-alive connection a strict client waits
        // for the body until timeout (framing desync). Advertise the empty
        // body explicitly, mirroring Pingora's own error responses.
        if !body_forbidden {
            resp.insert_header(header::CONTENT_LENGTH, "0")?;
        }
        for (name, value) in &headers {
            resp.insert_header(name.clone(), value.clone())?;
        }
        session.write_response_header(Box::new(resp), true).await?;
    }

    Ok(())
}

/// Write a plugin-returned [`Rejection`] through the unified exit path (T10).
///
/// The single rendering site for plugin-request-phase rejections: called by
/// [`crate::core::CompiledPluginPipeline::request_filter`] when a plugin
/// returns `FilterVerdict::Reject`. Plugins never call this — they return
/// values; the pipeline owns the session.
pub(crate) async fn send_rejection(
    session: &mut Session,
    rejection: &Rejection,
    ctx: &ProxyContext,
) -> Result<()> {
    if rejection.close_connection {
        session.set_keepalive(None);
    }
    send_exit_response(
        session,
        rejection.status.as_u16(),
        rejection.body.as_deref(),
        rejection.content_type.as_deref(),
        &rejection.headers,
        ctx,
    )
    .await
}

/// Common error response helpers
pub struct CommonErrors;

impl CommonErrors {
    pub fn bad_request(message: &str) -> Response<Vec<u8>> {
        ResponseBuilder::error_http(StatusCode::BAD_REQUEST, message)
    }

    pub fn forbidden(message: &str) -> Response<Vec<u8>> {
        ResponseBuilder::error_http(StatusCode::FORBIDDEN, message)
    }

    pub fn internal_server_error(message: &str) -> Response<Vec<u8>> {
        ResponseBuilder::error_http(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{ExitTransform, ExitTransformRule};

    fn transform(rules: Vec<ExitTransformRule>) -> Option<ExitTransform> {
        Some(ExitTransform { rules })
    }

    #[test]
    fn no_transform_passes_through() {
        let resolved = resolve_exit_response(None, 429, Some("too many"), None, &[], None);
        assert_eq!(
            resolved,
            ResolvedExitResponse {
                status: 429,
                body: Some(b"too many".to_vec()),
                content_type: None,
                headers: vec![],
            }
        );
    }

    #[test]
    fn unmatched_status_passes_through() {
        let t = transform(vec![ExitTransformRule {
            codes: vec![401],
            status_code: Some(403),
            body: Some("denied".into()),
            headers: vec![],
        }]);
        let resolved = resolve_exit_response(t.as_ref(), 500, None, None, &[], None);
        assert_eq!(resolved.status, 500);
        assert!(resolved.body.is_none());
    }

    #[test]
    fn rule_remaps_status_and_body_with_vars() {
        let t = transform(vec![ExitTransformRule {
            codes: vec![401, 403],
            status_code: Some(403),
            body: Some(
                "{\"error\":true,\"status\":$status,\"message\":\"$message\",\"rid\":\"$request_id\"}"
                    .into(),
            ),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("X-Error-Code".into(), "$status".into()),
            ],
        }]);
        let resolved = resolve_exit_response(
            t.as_ref(),
            401,
            Some("missing token"),
            Some("text/plain"),
            &[],
            Some("req-42"),
        );
        assert_eq!(resolved.status, 403);
        assert_eq!(
            String::from_utf8(resolved.body.unwrap()).unwrap(),
            "{\"error\":true,\"status\":403,\"message\":\"missing token\",\"rid\":\"req-42\"}"
        );
        assert_eq!(resolved.content_type.as_deref(), Some("application/json"));
        assert_eq!(
            resolved.headers,
            vec![("X-Error-Code".to_string(), "403".to_string())]
        );
    }

    #[test]
    fn rule_headers_override_default_and_dedupe() {
        let t = transform(vec![ExitTransformRule {
            codes: vec![502],
            status_code: None,
            body: None,
            headers: vec![("X-Upstream".into(), "overridden".into())],
        }]);
        let resolved = resolve_exit_response(
            t.as_ref(),
            502,
            None,
            None,
            &[("X-Upstream".into(), "original".into())],
            None,
        );
        assert_eq!(resolved.status, 502);
        assert_eq!(
            resolved.headers,
            vec![("X-Upstream".to_string(), "overridden".to_string())]
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let t = transform(vec![
            ExitTransformRule {
                codes: vec![500],
                status_code: Some(501),
                body: None,
                headers: vec![],
            },
            ExitTransformRule {
                codes: vec![500],
                status_code: Some(502),
                body: None,
                headers: vec![],
            },
        ]);
        let resolved = resolve_exit_response(t.as_ref(), 500, None, None, &[], None);
        assert_eq!(resolved.status, 501);
    }

    #[test]
    fn test_success_response() {
        let response =
            ResponseBuilder::success_http(b"OK".to_vec(), Some(content_type::TEXT_PLAIN));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"OK");
    }

    #[test]
    fn test_error_response() {
        let response = ResponseBuilder::error_http(StatusCode::BAD_REQUEST, "Invalid input");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.body(), b"Invalid input");
    }

    #[test]
    fn test_json_response() {
        use serde_json::json;
        let data = json!({"message": "success", "code": 200});
        let response = ResponseBuilder::success_json(&data);
        assert_eq!(response.status(), StatusCode::OK);
        let expected = r#"{"code":200,"message":"success"}"#;
        assert_eq!(response.body(), expected.as_bytes());
    }

    #[test]
    fn test_common_errors() {
        let response = CommonErrors::bad_request("Missing parameter");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.body(), b"Missing parameter");
    }
}
