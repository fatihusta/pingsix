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

/// Extracts the value of a specific query parameter from the request URI.
///
/// Returns the first occurrence of the parameter's value.
pub fn get_query_value<'a>(req_header: &'a RequestHeader, name: &str) -> Option<&'a str> {
    req_header.uri.query().and_then(|query| {
        query.split('&').find_map(|pair| {
            if let Some((k, v)) = pair.split_once('=') {
                if k == name {
                    Some(v.trim()) // Trim whitespace from value
                } else {
                    None
                }
            } else if pair == name {
                // Handle key-only parameters if needed? Usually not.
                Some("") // Or None, depending on desired behavior for key-only params
            } else {
                None
            }
        })
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
        let mut query_list = vec![];
        for item in query.split('&') {
            if let Some((k, v)) = item.split_once('=') {
                if k != name {
                    query_list.push(format!("{k}={v}"));
                }
            } else if item != name {
                query_list.push(item.to_string());
            }
        }
        let query = query_list.join("&");
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
    for cookie_header_value in req_header.headers.get_all(http::header::COOKIE) {
        if let Ok(cookie_header_value) = cookie_header_value.to_str() {
            for item in cookie_header_value.split(';') {
                let trimmed_item = item.trim();
                if let Some((k, v)) = trimmed_item.split_once('=') {
                    if k.trim() == cookie_name {
                        return Some(v.trim());
                    }
                }
            }
        }
    }
    None
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
            value
                .split(';')
                .filter_map(|item| {
                    let item = item.trim();
                    let name = item.split_once('=').map_or(item, |(name, _)| name.trim());
                    (name != cookie_name).then_some(item)
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
/// APISIX falls back to `remote_addr` when the configured key is unavailable.
pub fn apisix_key(session: &mut Session, key: &str, var_combination: bool) -> Cow<'static, str> {
    let value = if var_combination {
        render_apisix_template(key, |name| resolve_var(session, name).into_owned())
    } else {
        resolve_var(session, key.trim_start_matches('$')).into_owned()
    };
    if value.is_empty() {
        resolve_var(session, "remote_addr").into_owned().into()
    } else {
        Cow::Owned(value)
    }
}

/// Render an APISIX nginx-variable template. Kept independent of `Session` so
/// plugins that need templates can share the exact parser and it is unit-testable.
pub fn render_apisix_template<F>(template: &str, mut resolve: F) -> String
where
    F: FnMut(&str) -> String,
{
    let mut rendered = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
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
            rendered.push_str(&resolve(&name));
        }
    }
    rendered
}

/// Render an APISIX nginx-variable template against the live request.
///
/// Variable names use the same resolution as [`apisix_key`]: `arg_*`, `http_*`,
/// and the predefined nginx-style names. Literals without `$` are returned
/// verbatim, so header values like `"30"` survive unchanged.
pub fn render_apisix_request_template(session: &mut Session, template: &str) -> String {
    render_apisix_template(template, |name| resolve_var(session, name).into_owned())
}

/// Resolve a single nginx-style variable name to a request-derived value.
///
/// Backs both upstream hashing (`UpstreamHashOn::VARS`) and APISIX-style
/// limiter keys. Supports `arg_*` query arguments, `http_*` headers (nginx
/// naming: `X-Custom-Id` -> `http_x_custom_id`), and the predefined names
/// `uri`, `request_uri`, `query_string`, `remote_addr`, `remote_port`,
/// `server_addr`, `host`.
///
/// Unknown variables resolve to an empty string so a missing value never
/// panics; callers decide whether an empty key means "no limit" or "deny".
fn resolve_var<'a>(session: &'a mut Session, name: &str) -> Cow<'a, str> {
    if let Some(arg) = name.strip_prefix("arg_") {
        return Cow::Borrowed(get_query_value(session.req_header(), arg).unwrap_or_default());
    }
    if let Some(header) = name.strip_prefix("http_") {
        // nginx normalizes header names: `X-Custom-Id` -> `http_x_custom_id`
        let header_name = header.replace('_', "-");
        return Cow::Borrowed(
            get_req_header_value(session.req_header(), &header_name).unwrap_or_default(),
        );
    }
    match name {
        "uri" => Cow::Borrowed(session.req_header().uri.path()),
        "request_uri" => Cow::Borrowed(
            session
                .req_header()
                .uri
                .path_and_query()
                .map_or_else(|| session.req_header().uri.path(), |pq| pq.as_str()),
        ),
        "query_string" => Cow::Borrowed(session.req_header().uri.query().unwrap_or_default()),
        "remote_addr" => get_direct_client_ip(session)
            .map_or_else(|| Cow::Borrowed(""), |ip| Cow::Owned(ip.to_string())),
        "remote_port" => session
            .client_addr()
            .and_then(|s| s.as_inet())
            .map_or_else(|| Cow::Borrowed(""), |i| Cow::Owned(i.port().to_string())),
        "server_addr" => session
            .server_addr()
            .map_or_else(|| Cow::Borrowed(""), |addr| Cow::Owned(addr.to_string())),
        "host" => Cow::Borrowed(get_request_host(session.req_header()).unwrap_or_default()),
        _ => {
            log::debug!("Unsupported variable key: {name}");
            Cow::Borrowed("")
        }
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
