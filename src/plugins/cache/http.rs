//! HTTP cache policy helpers shared by the cache plugin and Pingora adapter.

use std::sync::Arc;

use http::{
    header::{SET_COOKIE, VARY},
    StatusCode,
};
use pingora_cache::{
    cache_control::{CacheControl, DirectiveMap, DirectiveValue},
    filters::resp_cacheable,
    key::{CacheKey, HashBinary},
    CacheMeta, CacheMetaDefaults, NoCacheReason, RespCacheable, VarianceBuilder,
};
use pingora_error::{Error, ErrorSource, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

use crate::{
    core::ProxyContext,
    plugins::cache::{should_bypass_authenticated_request, CacheSettings, CTX_KEY_CACHE_SETTINGS},
};

const CACHE_DEFAULT: CacheMetaDefaults = CacheMetaDefaults::new(|_| None, 0, 0);

pub(crate) fn headers_indicate_shared_cache_credentials(headers: &http::HeaderMap) -> bool {
    headers.contains_key("authorization")
        || headers.contains_key("proxy-authorization")
        || headers.contains_key("cookie")
}

pub(crate) fn response_has_vary_star(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("*"))
}

pub(crate) fn cache_key_method(method: &str) -> &str {
    if method == "PURGE" {
        "GET"
    } else {
        method
    }
}

/// Whether a `PURGE` request may remove the matching cache entry.
///
/// PURGE is an opt-in because it is intentionally unauthenticated: an
/// unconditional purge lets any client force cache misses (stampede DoS).
/// Deployments that enable it must front the proxy with their own ACL.
pub(crate) fn should_enable_purge(settings: Option<&Arc<CacheSettings>>) -> bool {
    settings.is_some_and(|settings| settings.enable_purge)
}

pub(crate) fn should_enable_request_cache(
    headers: &http::HeaderMap,
    settings: Option<&Arc<CacheSettings>>,
    ctx: &ProxyContext,
) -> bool {
    if headers.contains_key("x-bypass-cache") {
        log::debug!("Cache bypass requested via x-bypass-cache header");
        return false;
    }
    if headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("no-cache"))
    {
        log::debug!("Cache bypass requested via cache-control: no-cache");
        return false;
    }
    let Some(settings) = settings else {
        return false;
    };
    if should_bypass_authenticated_request(settings, ctx) {
        log::debug!("Skipping shared cache: request has credentials");
        return false;
    }
    true
}

pub(crate) fn cache_key(session: &Session, ctx: &ProxyContext) -> CacheKey {
    let req = session.req_header();
    let host = req
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let primary = format!(
        "{} {} {}",
        cache_key_method(req.method.as_str()),
        host,
        req.uri
    );
    let route_fp = ctx
        .route
        .as_ref()
        .map(|r| r.cache_namespace_fingerprint())
        .unwrap_or(0);
    let policy_fp = ctx
        .get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)
        .map(|s| s.policy_fingerprint)
        .unwrap_or(0);
    let upstream_key = if let Some(upstream) = ctx.upstream_override.as_ref() {
        upstream.cache_isolation_key()
    } else {
        ctx.route
            .as_ref()
            .and_then(|r| r.resolve_upstream())
            .map(|u| u.cache_isolation_key())
            .unwrap_or_default()
    };
    let scheme = if session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .is_some()
    {
        "https"
    } else {
        "http"
    };
    CacheKey::new(
        format!("rf={route_fp:x}|c={policy_fp:x}|u={upstream_key:x}|sch={scheme}"),
        primary,
        "",
    )
}

pub(crate) fn cache_vary(
    meta: &CacheMeta,
    ctx: &ProxyContext,
    req: &RequestHeader,
) -> Option<HashBinary> {
    let settings = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)?;
    if response_has_vary_star(meta.headers()) {
        return None;
    }
    let mut headers: Vec<String> = meta
        .headers()
        .get_all(VARY)
        .iter()
        .flat_map(|v| v.to_str().unwrap_or("").split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect();
    headers.extend(settings.vary.iter().cloned());
    if headers.is_empty() {
        return None;
    }
    headers.sort_unstable();
    headers.dedup();
    let mut key = VarianceBuilder::new();
    for name in &headers {
        key.add_value(
            name,
            req.headers.get(name).map(|v| v.as_bytes()).unwrap_or(&[]),
        );
    }
    key.finalize()
}

pub(crate) fn response_cacheability(
    resp: &ResponseHeader,
    ctx: &ProxyContext,
) -> Result<RespCacheable> {
    let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) else {
        return Ok(RespCacheable::Uncacheable(NoCacheReason::NeverEnabled));
    };
    if should_bypass_authenticated_request(settings, ctx)
        || !settings.statuses.contains(&resp.status.as_u16())
        || (!settings.cache_set_cookie_responses && resp.headers.contains_key(SET_COOKIE))
        || response_has_vary_star(&resp.headers)
    {
        return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
    }
    let control = ensure_max_age(CacheControl::from_resp_headers(resp), settings);
    let authorized = ctx.original_request_had_credentials || ctx.request_has_credentials;
    Ok(resp_cacheable(
        control.as_ref(),
        resp.clone(),
        authorized,
        &CACHE_DEFAULT,
    ))
}

pub(crate) fn error_status(error: &Error) -> u16 {
    match error.etype() {
        ErrorType::Custom(custom)
            if *custom == crate::plugins::client_control::ERROR_PAYLOAD_TOO_LARGE =>
        {
            StatusCode::PAYLOAD_TOO_LARGE.as_u16()
        }
        ErrorType::HTTPStatus(code) => *code,
        _ => match error.esource() {
            ErrorSource::Upstream => 502,
            ErrorSource::Downstream => match error.etype() {
                ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
                _ => 400,
            },
            ErrorSource::Internal | ErrorSource::Unset => 500,
        },
    }
}

fn ensure_max_age(cc: Option<CacheControl>, settings: &CacheSettings) -> Option<CacheControl> {
    match cc {
        Some(existing) => {
            let has_max_age = existing.directives.contains_key("max-age");
            let rewrite_smaxage =
                settings.respect_s_maxage && existing.directives.contains_key("s-maxage");
            let add_swr = settings
                .stale_while_revalidate
                .is_some_and(|_| !existing.directives.contains_key("stale-while-revalidate"));
            if has_max_age && !rewrite_smaxage && !add_swr {
                return Some(existing);
            }
            let mut directives = DirectiveMap::with_capacity(existing.directives.len() + 3);
            let mut final_has_max_age = false;
            for (key, value) in &existing.directives {
                let cloned = value.as_ref().map(|v| DirectiveValue(v.0.clone()));
                if settings.respect_s_maxage && key == "s-maxage" {
                    if let Some(value) = value {
                        directives.insert("max-age".into(), Some(DirectiveValue(value.0.clone())));
                        final_has_max_age = true;
                    }
                    directives.insert(key.clone(), cloned);
                } else {
                    if key == "max-age" {
                        final_has_max_age = true;
                    }
                    directives.insert(key.clone(), cloned);
                }
            }
            if !final_has_max_age {
                directives.insert(
                    "max-age".into(),
                    Some(DirectiveValue(
                        settings.ttl.as_secs().to_string().into_bytes(),
                    )),
                );
            }
            if let Some(swr) = settings
                .stale_while_revalidate
                .filter(|_| !directives.contains_key("stale-while-revalidate"))
            {
                directives.insert(
                    "stale-while-revalidate".into(),
                    Some(DirectiveValue(swr.as_secs().to_string().into_bytes())),
                );
            }
            Some(CacheControl { directives })
        }
        None => {
            let mut directives =
                DirectiveMap::with_capacity(1 + settings.stale_while_revalidate.is_some() as usize);
            directives.insert(
                "max-age".into(),
                Some(DirectiveValue(
                    settings.ttl.as_secs().to_string().into_bytes(),
                )),
            );
            if let Some(swr) = settings.stale_while_revalidate {
                directives.insert(
                    "stale-while-revalidate".into(),
                    Some(DirectiveValue(swr.as_secs().to_string().into_bytes())),
                );
            }
            Some(CacheControl { directives })
        }
    }
}
