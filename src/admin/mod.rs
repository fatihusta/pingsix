use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    sync::Arc,
};

use async_trait::async_trait;
use http::{header, Method, Response, StatusCode};
use matchit::{Match, Router};
use pingora::{
    apps::http_app::ServeHttp, protocols::http::ServerSession, services::listening::Service,
};
use serde::{Deserialize, Serialize};

use crate::{
    config::{etcd::canonicalize_prefix, Admin, Pingsix},
    core::{constant_time_eq, ProxyError},
    proxy::graph_mutation::{ConfigurationGraph, GraphError, ResourceKey, ResourceKind},
    utils::response::{CommonErrors, ResponseBuilder},
};

#[derive(Debug)]
enum ApiError {
    ValidationError(String),
    MissingParameter(String),
    InvalidRequest(String),
    RequestBodyReadError(String),
    /// Resource does not exist (maps to 404).
    NotFound(String),
    /// Preserves the original ProxyError with full context
    ProxyError(ProxyError),
    /// A categorized graph-authority failure. The category is exposed as a
    /// stable JSON code while the server logs retain the original source.
    Graph {
        status: StatusCode,
        code: &'static str,
        message: &'static str,
        source: Box<GraphError>,
    },
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            ApiError::MissingParameter(msg) => write!(f, "Missing parameter: {msg}"),
            ApiError::InvalidRequest(msg) => write!(f, "Invalid request: {msg}"),
            ApiError::RequestBodyReadError(msg) => write!(f, "Request body read error: {msg}"),
            ApiError::NotFound(msg) => write!(f, "Not found: {msg}"),
            ApiError::ProxyError(err) => write!(f, "{err}"),
            ApiError::Graph {
                code,
                message,
                source,
                ..
            } => write!(f, "graph {code}: {message} ({source})"),
        }
    }
}

impl Error for ApiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ApiError::ProxyError(err) => Some(err),
            ApiError::Graph { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<ProxyError> for ApiError {
    fn from(err: ProxyError) -> Self {
        ApiError::ProxyError(err)
    }
}

impl From<GraphError> for ApiError {
    fn from(err: GraphError) -> Self {
        let (status, code, message) = match &err {
            GraphError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "not_found", "Resource not found")
            }
            GraphError::CasConflict => (
                StatusCode::CONFLICT,
                "cas_conflict",
                "Configuration changed concurrently",
            ),
            GraphError::ReferentialConflict { .. } => (
                StatusCode::CONFLICT,
                "referential_conflict",
                "Resource is still referenced",
            ),
            GraphError::InvalidKey { .. }
            | GraphError::InvalidResource { .. }
            | GraphError::InvalidCandidate { .. }
            | GraphError::Secret { .. } => (
                StatusCode::BAD_REQUEST,
                "validation_failed",
                "Configuration validation failed",
            ),
            GraphError::Store(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "Backend configuration store unavailable",
            ),
            // These states are not normally reachable from Admin mutations;
            // expose only a stable internal category if they are.
            GraphError::StaleRevision { .. } | GraphError::WorkerStopped => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal server error",
            ),
        };
        ApiError::Graph {
            status,
            code,
            message,
            source: Box::new(err),
        }
    }
}

impl ApiError {
    fn into_response(self) -> ApiResponse {
        use ApiError::*;
        match self {
            RequestBodyReadError(_) => CommonErrors::bad_request("Failed to read request body"),
            NotFound(_) => ResponseBuilder::error_http(StatusCode::NOT_FOUND, &self.to_string()),
            ValidationError(_) | MissingParameter(_) | InvalidRequest(_) => {
                CommonErrors::bad_request(&self.to_string())
            }
            ProxyError(proxy_err) => Self::proxy_error_response(&proxy_err),
            Graph {
                status,
                code,
                message,
                source,
            } => {
                if status.is_server_error() {
                    log::error!("Admin graph error ({code}): {source}");
                } else {
                    log::warn!("Admin graph error ({code}): {source}");
                }
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(
                        serde_json::json!({ "code": code, "error": message })
                            .to_string()
                            .into_bytes(),
                    )
                    .unwrap_or_else(|build_error| {
                        log::error!("Failed to build Admin graph error response: {build_error}");
                        CommonErrors::internal_server_error("Internal server error")
                    })
            }
        }
    }

    fn proxy_error_response(proxy_err: &ProxyError) -> ApiResponse {
        match proxy_err {
            ProxyError::ValidationStructured(validation_errors) => {
                let detailed_errors: HashMap<String, Vec<String>> = validation_errors
                    .field_errors()
                    .iter()
                    .map(|(field, errors)| {
                        (
                            field.to_string(),
                            errors.iter().map(|e| e.to_string()).collect(),
                        )
                    })
                    .collect();

                let response_body = serde_json::json!({
                    "error": "Validation failed",
                    "details": detailed_errors
                });

                Response::builder()
                    .status(400)
                    .header("Content-Type", "application/json")
                    .body(response_body.to_string().into_bytes())
                    .unwrap_or_else(|_| {
                        CommonErrors::internal_server_error("Internal server error")
                    })
            }
            ProxyError::Validation(_) | ProxyError::Configuration(_) => {
                CommonErrors::bad_request(&proxy_err.to_string())
            }
            ProxyError::Etcd(_) => {
                // Do not echo etcd endpoints/keys in client responses.
                log::error!("Admin etcd error: {proxy_err}");
                CommonErrors::internal_server_error("Backend configuration store unavailable")
            }
            ProxyError::CasConflict(_) => {
                ResponseBuilder::error_http(StatusCode::CONFLICT, &proxy_err.to_string())
            }
            _ => {
                log::error!("Admin internal error: {proxy_err}");
                CommonErrors::internal_server_error("Internal server error")
            }
        }
    }
}

type ApiResult<T> = Result<T, ApiError>;
type ApiResponse = Response<Vec<u8>>;
type RequestParams = BTreeMap<String, String>;

// Maximum request body size for admin API (1 MB)
const MAX_BODY_SIZE: usize = 1_048_576;

// Handlers are value-parameterized by [`ResourceKind`]: one handler instance
// per operation and resource kind is constructed at route registration.
// Per-kind validation dispatch lives in the configuration graph authority;
// the handlers below only carry HTTP-specific concerns.

struct ResourceHandler {
    kind: ResourceKind,
}

struct GetHandler {
    kind: ResourceKind,
}

struct DeleteHandler {
    kind: ResourceKind,
}

struct ListHandler {
    kind: ResourceKind,
}

impl ResourceHandler {
    fn new(kind: ResourceKind) -> Self {
        Self { kind }
    }
}

impl GetHandler {
    fn new(kind: ResourceKind) -> Self {
        Self { kind }
    }
}

impl DeleteHandler {
    fn new(kind: ResourceKind) -> Self {
        Self { kind }
    }
}

impl ListHandler {
    fn new(kind: ResourceKind) -> Self {
        Self { kind }
    }
}

struct PublicationHandler;

#[async_trait]
impl Handler for PublicationHandler {
    async fn handle(
        &self,
        graph: &ConfigurationGraph,
        _prefix: &str,
        _session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<ApiResponse> {
        let revision = params
            .get("revision")
            .ok_or_else(|| ApiError::MissingParameter("revision".into()))?
            .parse::<i64>()
            .ok()
            .filter(|revision| *revision > 0)
            .ok_or_else(|| {
                ApiError::InvalidRequest("revision must be a positive integer".into())
            })?;
        let publication = graph
            .publication(revision)
            .ok_or_else(|| ApiError::NotFound("Publication revision not found".into()))?;
        Ok(ResponseBuilder::success_json(&serde_json::json!({
            "state": publication.state,
            "published_revision": publication.published_revision,
            "error": publication.error,
        })))
    }
}

fn extract_key(kind: ResourceKind, params: &RequestParams) -> ApiResult<ResourceKey> {
    let id = params
        .get("id")
        .ok_or_else(|| ApiError::MissingParameter("id".into()))?;

    ResourceKey::new(kind, id).map_err(ApiError::from)
}

#[async_trait]
trait Handler {
    async fn handle(
        &self,
        graph: &ConfigurationGraph,
        prefix: &str,
        session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<ApiResponse>;
}

// PUT handler
#[async_trait]
impl Handler for ResourceHandler {
    async fn handle(
        &self,
        graph: &ConfigurationGraph,
        _prefix: &str,
        http_session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<ApiResponse> {
        http_session.validate_content_type()?;

        let body_data = read_request_body(http_session)
            .await
            .map_err(|e| ApiError::RequestBodyReadError(e.to_string()))?;

        let key = extract_key(self.kind, &params)?;

        let value: serde_json::Value = serde_json::from_slice(&body_data)
            .map_err(|e| ApiError::ValidationError(format!("Invalid JSON: {e}")))?;

        // Secret restoration, typed validation, encryption, whole-graph
        // validation, and the guarded CAS all happen behind the authority.
        let committed = graph.put(key, value).await?;

        let publication = graph
            .publication(committed.0)
            .expect("committed revisions are registered before returning");
        let body = serde_json::json!({
            "revision": committed.0,
            "committed_revision": committed.0,
            "state": publication.state,
            "published_revision": publication.published_revision,
            "error": publication.error,
        });
        Ok(ResponseBuilder::success_json(&body))
    }
}

// GET handler - separate type needed to distinguish operation types
#[async_trait]
impl Handler for GetHandler {
    async fn handle(
        &self,
        graph: &ConfigurationGraph,
        _prefix: &str,
        _http_session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<ApiResponse> {
        let key = extract_key(self.kind, &params)?;

        match graph.get(&key).await? {
            Some(view) => Ok(ResponseBuilder::success_json(&ValueWrapper {
                value: view.value,
            })),
            None => Err(ApiError::NotFound("Resource not found".into())),
        }
    }
}

// DELETE handler
#[async_trait]
impl Handler for DeleteHandler {
    async fn handle(
        &self,
        graph: &ConfigurationGraph,
        _prefix: &str,
        _http_session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<ApiResponse> {
        let key = extract_key(self.kind, &params)?;

        let committed = graph.delete(key).await?;

        let publication = graph
            .publication(committed.0)
            .expect("committed revisions are registered before returning");
        let body = serde_json::json!({
            "revision": committed.0,
            "committed_revision": committed.0,
            "state": publication.state,
            "published_revision": publication.published_revision,
            "error": publication.error,
        });
        Ok(ResponseBuilder::success_json(&body))
    }
}

// LIST handler
#[async_trait]
impl Handler for ListHandler {
    async fn handle(
        &self,
        graph: &ConfigurationGraph,
        prefix: &str,
        _http_session: &mut ServerSession,
        _params: RequestParams,
    ) -> ApiResult<ApiResponse> {
        let views = graph.list(self.kind).await?;

        let list_items: Vec<serde_json::Value> = views
            .into_iter()
            .map(|view| {
                serde_json::json!({
                    "key": format!("{}{}", prefix, view.key.logical_path()),
                    "value": view.value,
                    "createdIndex": view.create_revision,
                    "modifiedIndex": view.mod_revision,
                })
            })
            .collect();

        let result = serde_json::json!({
            "total": list_items.len(),
            "list": list_items,
        });

        Ok(ResponseBuilder::success_json(&result))
    }
}

#[derive(Serialize, Deserialize)]
struct ValueWrapper<T> {
    value: T,
}

type HttpHandler = Box<dyn Handler + Send + Sync>;

pub struct AdminHttpApp {
    config: Admin,
    graph: Arc<ConfigurationGraph>,
    /// Canonical etcd namespace used to format LIST response keys.
    prefix: String,
    router: Router<HashMap<Method, HttpHandler>>,
}

impl AdminHttpApp {
    pub fn new(admin: Admin, graph: Arc<ConfigurationGraph>, prefix: String) -> Self {
        let mut this = Self {
            config: admin,
            graph,
            prefix,
            router: Router::new(),
        };

        // Register routes for each resource kind.
        this.route(
            "/apisix/admin/publications/{revision}",
            Method::GET,
            Box::new(PublicationHandler),
        );

        for kind in [
            ResourceKind::Route,
            ResourceKind::Upstream,
            ResourceKind::Service,
            ResourceKind::GlobalRule,
            ResourceKind::Ssl,
        ] {
            this.register_resource_routes(kind);
        }

        this
    }

    fn register_resource_routes(&mut self, kind: ResourceKind) -> &mut Self {
        let path = format!("/apisix/admin/{}/{{id}}", kind.as_str());
        let list_path = format!("/apisix/admin/{}", kind.as_str());

        self.route(&path, Method::PUT, Box::new(ResourceHandler::new(kind)))
            .route(&path, Method::GET, Box::new(GetHandler::new(kind)))
            .route(&path, Method::DELETE, Box::new(DeleteHandler::new(kind)))
            .route(&list_path, Method::GET, Box::new(ListHandler::new(kind)));

        self
    }

    fn route(&mut self, path: &str, method: Method, handler: HttpHandler) -> &mut Self {
        if self.router.at(path).is_err() {
            let mut handlers = HashMap::new();
            handlers.insert(method, handler);
            if let Err(e) = self.router.insert(path, handlers) {
                log::error!("Failed to insert admin route '{path}': {e}");
            }
        } else if let Ok(routes) = self.router.at_mut(path) {
            routes.value.insert(method, handler);
        } else {
            log::error!("Failed to get mutable route for path '{path}'");
        }
        self
    }

    pub fn admin_http_service(
        cfg: &Pingsix,
        graph: Arc<ConfigurationGraph>,
    ) -> Option<Service<Self>> {
        let admin = cfg.admin.clone()?;
        let prefix = cfg
            .etcd
            .as_ref()
            .map(|etcd_cfg| canonicalize_prefix(&etcd_cfg.prefix))
            .unwrap_or_default();
        let app = Self::new(admin, graph, prefix);
        let addr = &app.config.address.to_string();
        let mut service = Service::new("Admin HTTP".to_string(), app);
        service.add_tcp(addr);
        Some(service)
    }
}

#[async_trait]
impl ServeHttp for AdminHttpApp {
    async fn response(&self, http_session: &mut ServerSession) -> ApiResponse {
        http_session.set_keepalive(None);

        if http_session.validate_api_key(&self.config.api_key).is_err() {
            return CommonErrors::forbidden("Invalid API key");
        }

        let (path, method) = {
            let req_header = http_session.req_header();
            (req_header.uri.path().to_string(), req_header.method.clone())
        };

        match self.router.at(&path) {
            Ok(Match { value, params }) => match value.get(&method) {
                Some(handler) => {
                    let params: RequestParams = params
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    match handler
                        .handle(&self.graph, &self.prefix, http_session, params)
                        .await
                    {
                        Ok(resp) => resp,
                        Err(e) => e.into_response(),
                    }
                }
                None => ResponseBuilder::error_http(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Method not allowed",
                ),
            },
            Err(_) => ResponseBuilder::error_http(StatusCode::NOT_FOUND, "Not Found"),
        }
    }
}

trait AdminSessionExt {
    fn validate_api_key(&self, api_key: &str) -> ApiResult<()>;
    fn validate_content_type(&self) -> ApiResult<()>;
}

impl AdminSessionExt for ServerSession {
    fn validate_api_key(&self, api_key: &str) -> ApiResult<()> {
        if api_key.trim().is_empty() {
            return Err(ApiError::InvalidRequest(
                "Must provide valid API key".into(),
            ));
        }

        let provided_key = self
            .get_header("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !provided_key.is_empty() && constant_time_eq(provided_key, api_key) {
            Ok(())
        } else {
            Err(ApiError::InvalidRequest(
                "Must provide valid API key".into(),
            ))
        }
    }

    fn validate_content_type(&self) -> ApiResult<()> {
        match self.get_header(header::CONTENT_TYPE) {
            Some(content_type) => {
                let ct_str = content_type.to_str().unwrap_or("");
                if is_json_content_type(ct_str) {
                    Ok(())
                } else {
                    Err(ApiError::InvalidRequest(
                        "Content-Type must be application/json".into(),
                    ))
                }
            }
            None => Err(ApiError::InvalidRequest(
                "Content-Type header is required".into(),
            )),
        }
    }
}

fn is_json_content_type(ct_str: &str) -> bool {
    ct_str
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/json"))
}

async fn read_request_body(http_session: &mut ServerSession) -> Result<Vec<u8>, ApiError> {
    let mut body_data = Vec::with_capacity(1024); // Initial capacity
    while let Some(bytes) = http_session
        .read_request_body()
        .await
        .map_err(|e| ApiError::RequestBodyReadError(e.to_string()))?
    {
        // Check if the cumulative size exceeds the limit
        if body_data.len() + bytes.len() > MAX_BODY_SIZE {
            return Err(ApiError::InvalidRequest("Request body too large".into()));
        }
        body_data.extend_from_slice(&bytes);
    }
    Ok(body_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_accepts_json_with_charset() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(is_json_content_type("Application/JSON;charset=UTF-8"));
    }

    #[test]
    fn content_type_rejects_near_misses() {
        assert!(!is_json_content_type("application/json-malformed"));
        assert!(!is_json_content_type("text/json"));
        assert!(!is_json_content_type(""));
    }

    #[test]
    fn empty_api_key_config_is_rejected_by_validator() {
        use validator::Validate;
        let admin = Admin {
            address: "127.0.0.1:9181".parse().unwrap(),
            api_key: "   ".into(),
            allow_insecure_remote: false,
        };
        assert!(admin.validate().is_err());
    }

    fn assert_error_response(response: ApiResponse, status: StatusCode, code: &str) {
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["code"], code);
    }

    #[test]
    fn graph_not_found_returns_safe_machine_readable_error() {
        let key = ResourceKey::new(ResourceKind::Route, "missing").unwrap();
        let response = ApiError::from(GraphError::NotFound { key }).into_response();
        assert_error_response(response, StatusCode::NOT_FOUND, "not_found");
    }

    #[test]
    fn graph_cas_conflict_returns_safe_machine_readable_error() {
        let response = ApiError::from(GraphError::CasConflict).into_response();
        assert_error_response(response, StatusCode::CONFLICT, "cas_conflict");
    }

    #[test]
    fn graph_referential_conflict_returns_safe_machine_readable_error() {
        let response = ApiError::from(GraphError::ReferentialConflict {
            source: ProxyError::Configuration("route still references upstream".into()),
        })
        .into_response();
        assert_error_response(response, StatusCode::CONFLICT, "referential_conflict");
    }

    #[test]
    fn graph_validation_failure_returns_safe_machine_readable_error() {
        let response = ApiError::from(GraphError::InvalidKey {
            key: "routes/bad/id".into(),
            reason: "resource id must not contain '/'".into(),
        })
        .into_response();
        assert_error_response(response, StatusCode::BAD_REQUEST, "validation_failed");
    }

    #[test]
    fn graph_store_failure_returns_safe_machine_readable_error() {
        let response = ApiError::from(GraphError::Store(
            crate::proxy::graph_mutation::StoreError::UnsupportedProtocol,
        ))
        .into_response();
        assert_error_response(
            response,
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
        );
    }
}
