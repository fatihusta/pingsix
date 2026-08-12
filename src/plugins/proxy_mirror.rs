//! Request mirroring plugin, APISIX `proxy-mirror` compatible.
//!
//! Asynchronously duplicates a sampled portion of requests to a shadow
//! upstream (`host`) without waiting for or influencing the real response.
//! The original request's headers and body are streamed to the mirror while
//! the primary proxy flow is unaffected; mirror connection failures are logged
//! and never fail the main request (Guide L6-style forwarding to a shadow peer,
//! APISIX `enable_mirror` semantics).
//!
//! Only `http://`/`https://` mirror targets are supported in this release.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use pingora_core::{connectors::http::Connector, upstreams::peer::HttpPeer};
use pingora_error::Result;
use pingora_http::RequestHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::sync::mpsc;
use validator::{Validate, ValidationError};

use crate::core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult};

pub const PLUGIN_NAME: &str = "proxy-mirror";

/// APISIX `proxy-mirror` runs at priority 1010.
const PRIORITY: i32 = 1010;

/// Context key: whether this request is sampled for mirroring.
const CTX_KEY_MIRROR: &str = "pingsix_proxy_mirror";
/// Context key: bounded producer for the background mirror task.
const CTX_KEY_MIRROR_SENDER: &str = "pingsix_proxy_mirror_sender";

/// A small, fixed queue keeps a slow shadow upstream from accumulating request
/// bodies in process memory.
const MIRROR_QUEUE_CAPACITY: usize = 32;
const MIRROR_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const MIRROR_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Creates a `proxy-mirror` plugin instance from JSON configuration.
pub fn create_proxy_mirror_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    let peer = build_mirror_peer(&config.host)?;
    Ok(Arc::new(PluginProxyMirror {
        config,
        peer,
        connector: Arc::new(Connector::new(None)),
    }))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PathConcatMode {
    /// Replace the original path with the configured one (keep query).
    #[default]
    Replace,
    /// Prefix the configured path onto the original path.
    Prefix,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    /// Mirror target base URL, e.g. `http://127.0.0.1:9797`.
    #[validate(custom(function = "validate_host"))]
    host: String,

    /// Custom path applied per `path_concat_mode`.
    #[serde(default)]
    path: Option<String>,

    #[serde(default)]
    path_concat_mode: PathConcatMode,

    /// Proportion of requests to mirror (0.00001..=1).
    #[serde(default = "PluginConfig::default_sample_ratio")]
    #[validate(range(min = 0.00001, max = 1.0))]
    sample_ratio: f64,
}

impl PluginConfig {
    fn default_sample_ratio() -> f64 {
        1.0
    }
}

fn validate_host(host: &str) -> Result<(), ValidationError> {
    if build_mirror_peer(host).is_err() {
        return Err(ValidationError::new(
            "host must be an http(s) scheme and authority only, e.g. http://127.0.0.1:9797",
        ));
    }
    Ok(())
}

fn validate_path(path: Option<&str>) -> ProxyResult<()> {
    if path.is_some_and(|path| {
        !path.starts_with('/') || path.len() == 1 || path.contains('?') || path.contains('&')
    }) {
        return Err(ProxyError::validation_error(
            "mirror path must match ^/[^?&]+$",
        ));
    }
    Ok(())
}

/// Parse `host` into an [`HttpPeer`]. Returns a validation error for
/// unsupported schemes or malformed URLs.
fn build_mirror_peer(host: &str) -> ProxyResult<HttpPeer> {
    let uri: http::Uri = host
        .parse()
        .map_err(|e| ProxyError::validation_error(format!("invalid mirror host '{host}': {e}")))?;

    // `http::Uri` normalizes an authority-only URL to path `/`; accept that
    // representation but reject every explicit non-root path.
    if uri.authority().is_none()
        || uri.path() != "/"
        || uri.query().is_some()
        || host.contains('#')
        || host.ends_with('/')
    {
        return Err(ProxyError::validation_error(
            "mirror host must contain only scheme and authority (no path or query)",
        ));
    }

    let (tls, default_port) = match uri.scheme_str() {
        Some("http") => (false, 80),
        Some("https") => (true, 443),
        Some(other) => {
            return Err(ProxyError::validation_error(format!(
                "unsupported mirror scheme '{other}'; only http/https are supported"
            )))
        }
        None => {
            return Err(ProxyError::validation_error(
                "mirror host must include a scheme (http:// or https://)",
            ))
        }
    };

    let host_str = uri
        .host()
        .ok_or_else(|| ProxyError::validation_error("mirror host is missing a hostname"))?;
    let port = uri.port_u16().unwrap_or(default_port);
    let sni = host_str.to_string();

    Ok(HttpPeer::new((host_str.to_string(), port), tls, sni))
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value).map_err(|e| {
            ProxyError::serialization_error("Invalid proxy-mirror plugin config", e)
        })?;
        config.validate()?;
        validate_path(config.path.as_deref())?;
        Ok(config)
    }
}

pub struct PluginProxyMirror {
    config: PluginConfig,
    peer: HttpPeer,
    connector: Arc<Connector>,
}

#[derive(Clone)]
struct MirrorSender {
    sender: mpsc::Sender<MirrorBody>,
    active: Arc<AtomicBool>,
}

enum MirrorBody {
    Chunk(Bytes, bool),
    Finish,
}

impl MirrorSender {
    fn try_send(&self, body: MirrorBody) {
        if !self.active.load(Ordering::Relaxed) {
            return;
        }
        if let Err(error) = self.sender.try_send(body) {
            self.active.store(false, Ordering::Relaxed);
            match error {
                mpsc::error::TrySendError::Full(_) => {
                    log::warn!("proxy-mirror: mirror queue is full; dropping mirror request");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    log::debug!("proxy-mirror: mirror task is no longer available");
                }
            }
        }
    }
}

impl PluginProxyMirror {
    /// Build the mirrored request header: cloned original with an optional
    /// path rewrite per `path_concat_mode`.
    fn build_mirror_request(&self, original: &RequestHeader) -> ProxyResult<RequestHeader> {
        let mut mirror = original.clone();

        if let Some(conf_path) = &self.config.path {
            let query = original
                .uri
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            let new_path = match self.config.path_concat_mode {
                PathConcatMode::Replace => format!("{conf_path}{query}"),
                PathConcatMode::Prefix => {
                    format!("{conf_path}{}{query}", original.uri.path())
                }
            };
            let new_uri: http::Uri = new_path.parse().map_err(|e| {
                ProxyError::validation_error(format!("failed to build mirror URI: {e}"))
            })?;
            mirror.set_uri(new_uri);
        }

        Ok(mirror)
    }
}

#[async_trait]
impl ProxyPlugin for PluginProxyMirror {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        // Sample independently per request (APISIX `sample_ratio`).
        let sampled = rand::random::<f64>() < self.config.sample_ratio;
        ctx.set(CTX_KEY_MIRROR, sampled);
        if sampled {
            log::trace!(
                "proxy-mirror: mirroring request {} {}",
                session.req_header().method,
                session.req_header().uri
            );
        }
        Ok(false)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        if !ctx.get::<bool>(CTX_KEY_MIRROR).copied().unwrap_or(false) {
            return Ok(());
        }

        let mirror_req = match self.build_mirror_request(upstream_request) {
            Ok(req) => req,
            Err(e) => {
                log::warn!("proxy-mirror: failed to build mirror request: {e}");
                return Ok(());
            }
        };

        let (sender, mut receiver) = mpsc::channel(MIRROR_QUEUE_CAPACITY);
        let active = Arc::new(AtomicBool::new(true));
        ctx.set(
            CTX_KEY_MIRROR_SENDER,
            MirrorSender {
                sender,
                active: active.clone(),
            },
        );
        let connector = self.connector.clone();
        let peer = self.peer.clone();
        tokio::spawn(async move {
            let result = async {
                let (mut session, _) =
                    tokio::time::timeout(MIRROR_CONNECT_TIMEOUT, connector.get_http_session(&peer))
                        .await
                        .map_err(|_| "connection timed out")?
                        .map_err(|_| "connection failed")?;
                tokio::time::timeout(
                    MIRROR_WRITE_TIMEOUT,
                    session.write_request_header(Box::new(mirror_req)),
                )
                .await
                .map_err(|_| "header write timed out")?
                .map_err(|_| "header write failed")?;
                // Always wait for the body stream from `request_body_filter`.
                // Inferring body presence from Content-Length/Transfer-Encoding
                // would drop HTTP/2 streaming bodies that carry neither header;
                // bodyless requests signal end-of-stream immediately.
                while let Some(body) = receiver.recv().await {
                    match body {
                        MirrorBody::Chunk(bytes, end) => {
                            tokio::time::timeout(
                                MIRROR_WRITE_TIMEOUT,
                                session.write_request_body(bytes, end),
                            )
                            .await
                            .map_err(|_| "body write timed out")?
                            .map_err(|_| "body write failed")?;
                            if end {
                                return Ok::<(), &str>(());
                            }
                        }
                        MirrorBody::Finish => {
                            tokio::time::timeout(
                                MIRROR_WRITE_TIMEOUT,
                                session.finish_request_body(),
                            )
                            .await
                            .map_err(|_| "body completion timed out")?
                            .map_err(|_| "body completion failed")?;
                            return Ok(());
                        }
                    }
                }
                Err("request body ended without completion")
            }
            .await;
            active.store(false, Ordering::Relaxed);
            if let Err(error) = result {
                log::warn!("proxy-mirror: dropping mirror request: {error}");
            }
        });
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        let Some(sender) = ctx.get::<MirrorSender>(CTX_KEY_MIRROR_SENDER) else {
            return Ok(());
        };
        match body {
            Some(bytes) => sender.try_send(MirrorBody::Chunk(bytes.clone(), end_of_stream)),
            None if end_of_stream => sender.try_send(MirrorBody::Finish),
            None => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_http::RequestHeader;

    #[test]
    fn config_requires_http_url_host() {
        assert!(PluginConfig::try_from(serde_json::json!({})).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "host": "ftp://x" })).is_err());
        assert!(PluginConfig::try_from(serde_json::json!({ "host": "127.0.0.1:9797" })).is_err());
        assert!(
            PluginConfig::try_from(serde_json::json!({ "host": "http://127.0.0.1:9797" })).is_ok()
        );
        assert!(PluginConfig::try_from(
            serde_json::json!({ "host": "https://mirror.example.com" })
        )
        .is_ok());
        for invalid in [
            "grpc://mirror.example.com",
            "grpcs://mirror.example.com",
            "http://mirror.example.com/path",
            "http://mirror.example.com?query=1",
            "http://mirror.example.com/#fragment",
        ] {
            assert!(PluginConfig::try_from(serde_json::json!({ "host": invalid })).is_err());
        }
    }

    #[test]
    fn config_defaults() {
        let config =
            PluginConfig::try_from(serde_json::json!({ "host": "http://127.0.0.1:9797" })).unwrap();
        assert_eq!(config.sample_ratio, 1.0);
        assert_eq!(config.path_concat_mode, PathConcatMode::Replace);
        assert!(config.path.is_none());
    }

    #[test]
    fn config_requires_apisix_subset_path() {
        for invalid in ["shadow", "/", "/shadow?x=1", "/shadow&x=1"] {
            assert!(PluginConfig::try_from(serde_json::json!({
                "host": "http://127.0.0.1:9797",
                "path": invalid,
            }))
            .is_err());
        }
        assert!(PluginConfig::try_from(serde_json::json!({
            "host": "http://127.0.0.1:9797",
            "path": "/shadow/path",
        }))
        .is_ok());
    }

    #[test]
    fn config_rejects_bad_sample_ratio() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "host": "http://127.0.0.1:9797",
            "sample_ratio": 2.0
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "host": "http://127.0.0.1:9797",
            "sample_ratio": 0.0
        }))
        .is_err());
    }

    #[test]
    fn bounded_queue_drops_mirror_when_full() {
        let (sender, _receiver) = mpsc::channel(1);
        let active = Arc::new(AtomicBool::new(true));
        let mirror = MirrorSender {
            sender,
            active: active.clone(),
        };
        mirror.try_send(MirrorBody::Finish);
        mirror.try_send(MirrorBody::Finish);
        assert!(!active.load(Ordering::Relaxed));
    }

    #[test]
    fn mirror_peer_parses_scheme_and_default_port() {
        let peer = build_mirror_peer("https://mirror.example.com").unwrap();
        assert_eq!(peer.sni, "mirror.example.com");
    }

    #[test]
    fn mirror_request_replace_path_keeps_query() {
        let plugin = PluginProxyMirror {
            config: PluginConfig {
                host: "http://127.0.0.1:9797".into(),
                path: Some("/shadow".into()),
                path_concat_mode: PathConcatMode::Replace,
                sample_ratio: 1.0,
            },
            peer: build_mirror_peer("http://127.0.0.1:9797").unwrap(),
            connector: Arc::new(Connector::new(None)),
        };
        let mut req = RequestHeader::build("GET", b"/original?a=1", None).unwrap();
        req.insert_header("Host", "example.com").unwrap();
        let mirror = plugin.build_mirror_request(&req).unwrap();
        assert_eq!(mirror.uri.to_string(), "/shadow?a=1");
    }

    #[test]
    fn mirror_request_prefix_mode() {
        let plugin = PluginProxyMirror {
            config: PluginConfig {
                host: "http://127.0.0.1:9797".into(),
                path: Some("/pre".into()),
                path_concat_mode: PathConcatMode::Prefix,
                sample_ratio: 1.0,
            },
            peer: build_mirror_peer("http://127.0.0.1:9797").unwrap(),
            connector: Arc::new(Connector::new(None)),
        };
        let req = RequestHeader::build("GET", b"/api/x", None).unwrap();
        let mirror = plugin.build_mirror_request(&req).unwrap();
        assert_eq!(mirror.uri.to_string(), "/pre/api/x");
    }

    #[test]
    fn mirror_request_without_path_keeps_uri() {
        let plugin = PluginProxyMirror {
            config: PluginConfig {
                host: "http://127.0.0.1:9797".into(),
                path: None,
                path_concat_mode: PathConcatMode::Replace,
                sample_ratio: 1.0,
            },
            peer: build_mirror_peer("http://127.0.0.1:9797").unwrap(),
            connector: Arc::new(Connector::new(None)),
        };
        let req = RequestHeader::build("GET", b"/api/x?b=2", None).unwrap();
        let mirror = plugin.build_mirror_request(&req).unwrap();
        assert_eq!(mirror.uri.to_string(), "/api/x?b=2");
    }
}
