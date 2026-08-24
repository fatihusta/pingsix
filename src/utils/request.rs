use std::{borrow::Cow, net::IpAddr};

use pingora_http::RequestHeader;
use pingora_proxy::Session;

use crate::config::UpstreamHashOn;

/// Build request selector key based on configuration.
///
/// Selects a value from the request (variable, header, or cookie) to be used,
/// typically for consistent upstream hashing.
pub fn request_selector_key<'a>(
    session: &'a mut Session,
    hash_on: &UpstreamHashOn,
    key: &str,
) -> Cow<'a, str> {
    match hash_on {
        UpstreamHashOn::VARS => resolve_var(session, key),
        UpstreamHashOn::HEAD => {
            Cow::Borrowed(get_req_header_value(session.req_header(), key).unwrap_or_default())
        }
        UpstreamHashOn::COOKIE => {
            Cow::Borrowed(get_cookie_value(session.req_header(), key).unwrap_or_default())
        }
    }
}

/// Split `s` on `sep` into `(name, value)` pairs. Segments are trimmed, empty
/// segments are skipped, and a key-only segment yields `(name, "")`.
///
/// Shared by the query (`'&'`) and cookie (`';'`) parsers so that lookup and
/// removal always agree on the same wire format.
fn split_pairs(s: &str, sep: char) -> impl Iterator<Item = (&str, &str)> {
    s.split(sep)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|seg| match seg.split_once('=') {
            Some((n, v)) => (n.trim(), v.trim()),
            None => (seg, ""),
        })
}

/// Extracts the value of a specific query parameter from the request URI.
///
/// Returns the first occurrence of the parameter's value.
pub fn get_query_value<'a>(req_header: &'a RequestHeader, name: &str) -> Option<&'a str> {
    req_header.uri.query().and_then(|query| {
        split_pairs(query, '&')
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
    })
}

/// Removes a specified query parameter from the request header's URI.
///
/// Modifies the `req_header` in place.
///
/// # Arguments
/// * `req_header` - The HTTP request header to modify.
/// * `name` - Name of the query parameter to remove.
///
/// # Returns
/// `Ok(())` if the URI was successfully modified or if the parameter/query didn't exist.
/// `Err(http::uri::InvalidUri)` if reconstructing the URI fails.
pub fn remove_query_from_header(
    req_header: &mut RequestHeader,
    name: &str,
) -> Result<(), http::uri::InvalidUri> {
    if let Some(query) = req_header.uri.query() {
        let query = split_pairs(query, '&')
            .filter(|(n, _)| *n != name)
            .map(|(n, v)| {
                if v.is_empty() {
                    n.to_string()
                } else {
                    format!("{n}={v}")
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        let mut new_path = req_header.uri.path().to_string();
        if !query.is_empty() {
            new_path = format!("{new_path}?{query}");
        }
        return new_path
            .parse::<http::Uri>()
            .map(|uri| req_header.set_uri(uri));
    }

    Ok(())
}

/// Retrieves the value of a specific header from the request.
///
/// Returns `None` if the header is not present or its value is not valid UTF-8.
pub fn get_req_header_value<'a>(req_header: &'a RequestHeader, key: &str) -> Option<&'a str> {
    req_header
        .headers
        .get(key)
        .and_then(|value| value.to_str().ok())
}

/// Retrieves the value of a specific cookie from the `Cookie` header.
///
/// Parses the `Cookie` header string manually. This is sufficient for simple
/// key=value pairs but might not handle complex/encoded cookie values robustly.
/// Returns the first occurrence of the cookie's value.
pub fn get_cookie_value<'a>(req_header: &'a RequestHeader, cookie_name: &str) -> Option<&'a str> {
    req_header
        .headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| split_pairs(value, ';'))
        .find(|(n, _)| *n == cookie_name)
        .map(|(_, v)| v)
}

/// Remove every cookie named `cookie_name` from all Cookie fields. Other cookie
/// pairs retain their order; fields that become empty are removed.
pub fn remove_cookie_from_header(
    req_header: &mut RequestHeader,
    cookie_name: &str,
) -> crate::core::ProxyResult<()> {
    let retained = req_header
        .headers
        .get_all(http::header::COOKIE)
        .iter()
        .map(|value| {
            value.to_str().map_err(|_| {
                crate::core::ProxyError::validation_error("Cookie header is not valid text")
            })
        })
        .collect::<crate::core::ProxyResult<Vec<_>>>()?
        .into_iter()
        .map(|value| {
            split_pairs(value, ';')
                .filter(|(n, _)| *n != cookie_name)
                .map(|(n, v)| {
                    if v.is_empty() {
                        n.to_string()
                    } else {
                        format!("{n}={v}")
                    }
                })
                .collect::<Vec<_>>()
                .join("; ")
        })
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    req_header.headers.remove(http::header::COOKIE);
    for value in retained {
        let value = value.parse().map_err(|e| {
            crate::core::ProxyError::validation_error(format!(
                "Failed to rebuild Cookie header: {e}"
            ))
        })?;
        req_header.headers.append(http::header::COOKIE, value);
    }
    Ok(())
}

/// Resolve an APISIX limiter key. A `var` key is exactly one variable;
/// `var_combination` renders `$name` / `${name}` placeholders while retaining
/// all literal text (including separators next to missing variables).
///
/// APISIX falls back to `remote_addr` when the configured key is
/// unavailable: for `var_combination` that means no placeholder resolved
/// (every variable absent), even though the rendered template may still
/// contain literal separator text like `"-"`.
pub fn apisix_key(session: &mut Session, key: &str, var_combination: bool) -> Cow<'static, str> {
    if var_combination {
        let (rendered, resolved) =
            render_apisix_template_with_count(key, |name| resolve_var(session, name).into_owned());
        if resolved > 0 {
            return Cow::Owned(rendered);
        }
        // Zero placeholders resolved: APISIX treats the combination as
        // key-missing and buckets the request by client address instead of
        // keying it on the literal separators alone.
        resolve_var(session, "remote_addr").into_owned().into()
    } else {
        // Plain `var` keys keep the empty-value fallback.
        let value = resolve_var(session, key.trim_start_matches('$')).into_owned();
        if value.is_empty() {
            resolve_var(session, "remote_addr").into_owned().into()
        } else {
            Cow::Owned(value)
        }
    }
}

/// Render an APISIX nginx-variable template. Kept independent of `Session` so
/// plugins that need templates can share the exact parser and it is unit-testable.
pub fn render_apisix_template<F>(template: &str, resolve: F) -> String
where
    F: FnMut(&str) -> String,
{
    render_template(template, TemplateOptions::default(), resolve)
}

/// Parser options for [`render_template`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TemplateOptions {
    /// When true, `\$` renders a literal `$` instead of starting a
    /// placeholder; a `\` followed by any other character (or at end of
    /// input) is passed through unchanged. Redirect URI templates enable
    /// escaping so a path containing a literal `$` stays configurable.
    pub escape_dollar: bool,
}

/// The single `$name` / `${name}` template parser shared by request-phase
/// plugins (upstream hashing, APISIX limiter keys, redirect URI templates)
/// and log-phase rendering (file-logger formats). Unknown or empty names
/// resolve through `resolve` like any other; a bare `$` (not followed by a
/// name or `{`) is emitted literally.
pub fn render_template<F>(template: &str, options: TemplateOptions, resolve: F) -> String
where
    F: FnMut(&str) -> String,
{
    render_template_with_count(template, options, resolve).0
}

/// Like [`render_template`], additionally reporting how many placeholders
/// resolved to a non-empty value. APISIX `var_combination` limiter keys
/// treat a fully unresolved template (count 0) as key-missing, even when
/// the rendered string still contains literal separator text.
fn render_template_with_count<F>(
    template: &str,
    options: TemplateOptions,
    mut resolve: F,
) -> (String, usize)
where
    F: FnMut(&str) -> String,
{
    let mut rendered = String::with_capacity(template.len());
    let mut resolved = 0;
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        if options.escape_dollar && ch == '\\' {
            if chars.peek() == Some(&'$') {
                chars.next();
                rendered.push('$');
            } else {
                rendered.push('\\');
            }
            continue;
        }
        if ch != '$' {
            rendered.push(ch);
            continue;
        }
        let name = if chars.peek() == Some(&'{') {
            chars.next();
            let mut name = String::new();
            for ch in chars.by_ref() {
                if ch == '}' {
                    break;
                }
                name.push(ch);
            }
            name
        } else {
            let mut name = String::new();
            while matches!(chars.peek(), Some(ch) if ch.is_ascii_alphanumeric() || *ch == '_') {
                name.push(chars.next().expect("peeked character exists"));
            }
            name
        };
        if name.is_empty() {
            rendered.push('$');
        } else {
            let value = resolve(&name);
            if !value.is_empty() {
                resolved += 1;
            }
            rendered.push_str(&value);
        }
    }
    (rendered, resolved)
}

/// Alias for [`render_template_with_count`] with the default (no-escape)
/// options, kept for existing APISIX-template callers.
fn render_apisix_template_with_count<F>(template: &str, resolve: F) -> (String, usize)
where
    F: FnMut(&str) -> String,
{
    render_template_with_count(template, TemplateOptions::default(), resolve)
}

/// Render an APISIX nginx-variable template against the live request.
///
/// Variable names use the same resolution as [`apisix_key`]: `arg_*`, `http_*`,
/// and the predefined nginx-style names. Literals without `$` are returned
/// verbatim, so header values like `"30"` survive unchanged.
pub fn render_apisix_request_template(session: &mut Session, template: &str) -> String {
    render_apisix_template(template, |name| resolve_var(session, name).into_owned())
}

/// Resolve a request-header-scoped nginx-style variable without a live
/// `Session`. Shared by every request-phase resolver so the lookup rules —
/// host precedence via [`get_request_host`], nginx `http_*` header naming,
/// `arg_*` query lookup, uri shapes — live in exactly one place.
///
/// Returns `None` for connection-scoped variables (`remote_addr`,
/// `remote_port`, `server_addr`) and for unknown names; callers choose the
/// fallback. Header-derived variables return `Some` even when the
/// underlying value is absent (empty string), matching nginx semantics.
///
/// `is_tls` only affects the `scheme` fallback for origin-form URIs, mirroring
/// nginx `$scheme`.
pub fn resolve_request_var<'a>(
    req: &'a RequestHeader,
    is_tls: bool,
    name: &str,
) -> Option<Cow<'a, str>> {
    if let Some(arg) = name.strip_prefix("arg_") {
        return Some(Cow::Borrowed(get_query_value(req, arg).unwrap_or_default()));
    }
    if let Some(header) = name.strip_prefix("http_") {
        // nginx normalizes header names: `X-Custom-Id` -> `http_x_custom_id`
        let header_name = header.replace('_', "-");
        return Some(Cow::Borrowed(
            get_req_header_value(req, &header_name).unwrap_or_default(),
        ));
    }
    Some(match name {
        "uri" => Cow::Borrowed(req.uri.path()),
        "request_uri" => Cow::Borrowed(
            req.uri
                .path_and_query()
                .map_or_else(|| req.uri.path(), |pq| pq.as_str()),
        ),
        "query_string" => Cow::Borrowed(req.uri.query().unwrap_or_default()),
        "host" => Cow::Borrowed(get_request_host(req).unwrap_or_default()),
        "scheme" => {
            Cow::Borrowed(
                req.uri
                    .scheme_str()
                    .unwrap_or(if is_tls { "https" } else { "http" }),
            )
        }
        "request_method" => Cow::Borrowed(req.method.as_str()),
        _ => return None,
    })
}

/// Whether the downstream connection of `session` is TLS (the redirect
/// plugin's `$scheme` fallback and http-to-https decision both key off this).
pub fn session_is_tls(session: &Session) -> bool {
    session.digest().is_some_and(|d| d.ssl_digest.is_some())
}

/// Resolve a single nginx-style variable name to a request-derived value.
///
/// Backs upstream hashing (`UpstreamHashOn::VARS`), APISIX-style limiter
/// keys, and redirect URI templates. Supports `arg_*` query arguments,
/// `http_*` headers (nginx naming: `X-Custom-Id` -> `http_x_custom_id`),
/// and the predefined names `uri`, `request_uri`, `query_string`,
/// `remote_addr`, `remote_port`, `server_addr`, `host`, `scheme`,
/// `request_method`.
///
/// Unknown variables resolve to an empty string so a missing value never
/// panics; callers decide whether an empty key means "no limit" or "deny".
pub fn resolve_var<'a>(session: &'a Session, name: &str) -> Cow<'a, str> {
    match name {
        "remote_addr" => get_direct_client_ip(session)
            .map_or_else(|| Cow::Borrowed(""), |ip| Cow::Owned(ip.to_string())),
        "remote_port" => session
            .client_addr()
            .and_then(|s| s.as_inet())
            .map_or_else(|| Cow::Borrowed(""), |i| Cow::Owned(i.port().to_string())),
        "server_addr" => session
            .server_addr()
            .map_or_else(|| Cow::Borrowed(""), |addr| Cow::Owned(addr.to_string())),
        _ => resolve_request_var(session.req_header(), session_is_tls(session), name)
            .unwrap_or_else(|| {
                log::debug!("Unsupported variable key: {name}");
                Cow::Borrowed("")
            }),
    }
}

/// Retrieves the request host (domain name) from the request header.
///
/// Prefers the host from the URI, falls back to the `Host` header.
/// Removes the port number if present in the `Host` header.
/// Correctly handles IPv6 addresses (e.g., `[::1]:8080` -> `[::1]`).
pub fn get_request_host(header: &RequestHeader) -> Option<&str> {
    // 1. Try host from URI (highest precedence, less likely to be ambiguous)
    if let Some(host) = header.uri.host() {
        // Check if it's not empty, as uri.host() can return "" in some cases
        if !host.is_empty() {
            return Some(host);
        }
    }
    // 2. Fallback to Host header with proper IPv6 support (RFC 3986 authority parsing)
    if let Some(host_header_value) = header.headers.get(http::header::HOST) {
        if let Ok(host_str) = host_header_value.to_str() {
            // Handle IPv6 addresses: [::1]:8080 -> [::1]
            if host_str.starts_with('[') {
                if let Some(bracket_end) = host_str.find(']') {
                    return Some(&host_str[..=bracket_end]);
                }
                // Malformed IPv6, return as-is
                return Some(host_str);
            } else {
                // IPv4/domain: example.com:8080 -> example.com
                // Use rfind to handle edge cases correctly
                if let Some(colon_pos) = host_str.rfind(':') {
                    return Some(&host_str[..colon_pos]);
                }
                return Some(host_str);
            }
        }
    }
    // 3. No host found
    None
}

/// Returns the peer address without formatting it as a string.
pub fn get_direct_client_ip(session: &Session) -> Option<IpAddr> {
    session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|inet| inet.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_var_combinations_without_removing_literal_separators() {
        assert_eq!(
            render_apisix_template("$name:${missing}/${name}", |name| match name {
                "name" => "alice".to_string(),
                _ => String::new(),
            }),
            "alice:/alice"
        );
    }

    #[test]
    fn render_counts_placeholders_resolved_to_a_value() {
        // Only placeholders that resolve to a non-empty value count as
        // resolved; empty resolutions and bare `$` literals do not.
        let (rendered, resolved) =
            render_apisix_template_with_count("$a-${b}-$-$c", |name| match name {
                "b" => "x".to_string(),
                _ => String::new(),
            });
        assert_eq!(rendered, "-x-$-");
        assert_eq!(resolved, 1);

        let (rendered, resolved) = render_apisix_template_with_count("$a-$b", |_| String::new());
        assert_eq!(rendered, "-");
        assert_eq!(resolved, 0);
    }

    /// A session fed a canned request, for exercising key resolution against
    /// a live (non-socket) request.
    async fn request_session(raw: &str) -> Session {
        crate::utils::testing::session_from_request(raw).await
    }

    #[tokio::test]
    async fn apisix_key_var_combination_without_resolved_vars_uses_remote_addr() {
        // Both placeholders unresolved: the template renders the literal
        // "-", but APISIX treats the combination as key-missing and buckets
        // the request by remote_addr instead.
        let mut session = request_session("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        let remote_addr = resolve_var(&session, "remote_addr").into_owned();
        let key = apisix_key(&mut session, "$http_a-$http_b", true).into_owned();
        assert_eq!(key, remote_addr);
        assert_ne!(key, "-");

        // One placeholder resolved: the rendered template is the key.
        let mut session =
            request_session("GET / HTTP/1.1\r\nHost: example.com\r\na: left\r\n\r\n").await;
        assert_eq!(
            apisix_key(&mut session, "$http_a-$http_b", true).into_owned(),
            "left-"
        );
    }

    #[tokio::test]
    async fn apisix_key_plain_var_resolves_and_falls_back_to_remote_addr() {
        // The plain-var branch is unchanged: a present variable is used
        // verbatim, an absent one falls back to remote_addr.
        let mut session =
            request_session("GET / HTTP/1.1\r\nHost: example.com\r\na: left\r\n\r\n").await;
        assert_eq!(
            apisix_key(&mut session, "http_a", false).into_owned(),
            "left"
        );
        let remote_addr = resolve_var(&session, "remote_addr").into_owned();
        assert_eq!(
            apisix_key(&mut session, "http_b", false).into_owned(),
            remote_addr
        );
    }

    #[test]
    fn render_template_escape_dollar_keeps_literal_dollar() {
        // `\$` emits a literal `$` and swallows the backslash; any other
        // backslash sequence (including `\\` and a trailing `\`) passes
        // through byte-for-byte.
        let resolve = |name: &str| match name {
            "host" => "example.com".to_string(),
            _ => String::new(),
        };
        assert_eq!(
            render_template(
                "\\$host-$host-\\x-\\$$-end\\",
                TemplateOptions {
                    escape_dollar: true
                },
                resolve,
            ),
            "$host-example.com-\\x-$$-end\\"
        );

        // Without escaping, backslashes are ordinary characters: `\$host`
        // keeps the backslash and still expands `$host`.
        assert_eq!(
            render_template("\\$host", TemplateOptions::default(), resolve),
            "\\example.com"
        );
    }

    #[test]
    fn render_template_braced_and_plain_forms_are_equivalent() {
        let resolve = |name: &str| match name {
            "name" => "alice".to_string(),
            _ => String::new(),
        };
        assert_eq!(
            render_template("$name-$missing", TemplateOptions::default(), resolve),
            render_template("${name}-${missing}", TemplateOptions::default(), resolve),
        );
        assert_eq!(
            render_template("${name}x", TemplateOptions::default(), resolve),
            "alicex"
        );
    }

    #[tokio::test]
    async fn resolve_request_var_covers_header_scoped_registry() {
        let mut req = RequestHeader::build("POST", b"/x?a=1&q=2", Some(2)).unwrap();
        req.insert_header("host", "header.example:8080").unwrap();
        req.insert_header("x-custom-id", "7").unwrap();

        assert_eq!(
            resolve_request_var(&req, false, "arg_a").as_deref(),
            Some("1")
        );
        assert_eq!(
            resolve_request_var(&req, false, "arg_missing").as_deref(),
            Some("")
        );
        assert_eq!(
            resolve_request_var(&req, false, "http_x_custom_id").as_deref(),
            Some("7")
        );
        assert_eq!(
            resolve_request_var(&req, false, "http_host").as_deref(),
            Some("header.example:8080")
        );
        assert_eq!(
            resolve_request_var(&req, false, "uri").as_deref(),
            Some("/x")
        );
        assert_eq!(
            resolve_request_var(&req, false, "request_uri").as_deref(),
            Some("/x?a=1&q=2")
        );
        assert_eq!(
            resolve_request_var(&req, false, "query_string").as_deref(),
            Some("a=1&q=2")
        );
        assert_eq!(
            resolve_request_var(&req, false, "request_method").as_deref(),
            Some("POST")
        );
        // Origin-form URI: scheme falls back to the connection's TLS state.
        assert_eq!(
            resolve_request_var(&req, false, "scheme").as_deref(),
            Some("http")
        );
        assert_eq!(
            resolve_request_var(&req, true, "scheme").as_deref(),
            Some("https")
        );

        // Connection-scoped and unknown names are out of header scope.
        assert!(resolve_request_var(&req, false, "remote_addr").is_none());
        assert!(resolve_request_var(&req, false, "remote_port").is_none());
        assert!(resolve_request_var(&req, false, "server_addr").is_none());
        assert!(resolve_request_var(&req, false, "unknown").is_none());
    }

    #[test]
    fn resolve_request_var_host_prefers_uri_authority_over_host_header() {
        // The precedence rule lives here, not in any plugin: URI authority
        // wins over the Host header, and the Host header's port is stripped.
        let mut req = RequestHeader::build("GET", b"/", Some(1)).unwrap();
        req.uri = "http://uri.example:8080/p".parse().unwrap();
        req.insert_header("host", "header.example:9090").unwrap();
        assert_eq!(
            resolve_request_var(&req, false, "host").as_deref(),
            Some("uri.example")
        );

        let mut req = RequestHeader::build("GET", b"/p", Some(1)).unwrap();
        req.insert_header("host", "header.example:9090").unwrap();
        assert_eq!(
            resolve_request_var(&req, false, "host").as_deref(),
            Some("header.example")
        );
    }

    #[tokio::test]
    async fn resolve_var_still_owns_connection_scoped_vars() {
        let session = request_session("GET /x HTTP/1.1\r\nHost: t\r\n\r\n").await;
        // Mock streams carry no socket digest: unknown at this scope means
        // the empty string, never a panic.
        assert_eq!(resolve_var(&session, "remote_addr"), "");
        assert_eq!(resolve_var(&session, "remote_port"), "");
        assert_eq!(resolve_var(&session, "server_addr"), "");
        assert_eq!(resolve_var(&session, "unknown"), "");
        assert_eq!(resolve_var(&session, "http_host"), "t");
    }

    #[test]
    fn split_pairs_trims_and_skips_empty_segments() {
        assert_eq!(
            split_pairs(" a = 1 ; jwt; b=2;; ", ';').collect::<Vec<_>>(),
            vec![("a", "1"), ("jwt", ""), ("b", "2")]
        );
    }

    #[test]
    fn query_lookup_and_removal_agree_on_the_same_parser() {
        let mut req = RequestHeader::build("GET", b"/x?keep=1&flag&jwt=t", None).unwrap();
        // Lookup sees the same normalized pairs that removal filters.
        assert_eq!(get_query_value(&req, "flag"), Some(""));
        assert_eq!(get_query_value(&req, "jwt"), Some("t"));
        remove_query_from_header(&mut req, "jwt").unwrap();
        assert_eq!(req.uri.to_string(), "/x?keep=1&flag");
    }

    #[test]
    fn cookie_lookup_and_removal_agree_on_the_same_parser() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.headers
            .append(http::header::COOKIE, " a = 1 ; jwt; b=2 ".parse().unwrap());
        // Key-only cookies are visible to lookup ...
        assert_eq!(get_cookie_value(&req, "jwt"), Some(""));
        assert_eq!(get_cookie_value(&req, "a"), Some("1"));
        // ... and removal drops them exactly like named pairs.
        remove_cookie_from_header(&mut req, "jwt").unwrap();
        assert_eq!(
            req.headers
                .get_all(http::header::COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["a=1; b=2"]
        );
    }

    #[test]
    fn removes_named_cookie_from_every_cookie_header() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.headers
            .append(http::header::COOKIE, "a=1; jwt=first".parse().unwrap());
        req.headers.append(
            http::header::COOKIE,
            "jwt=second; b=2; jwt=third".parse().unwrap(),
        );
        remove_cookie_from_header(&mut req, "jwt").unwrap();
        assert_eq!(
            req.headers
                .get_all(http::header::COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["a=1", "b=2"]
        );
    }
}
