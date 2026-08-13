//! Process-level gateway runtime.
//!
//! [`GatewayRuntime::build`] assembles one instance-owned [`GatewayState`]
//! (readiness, runtime snapshots, effective defaults, encryption keyring,
//! cache, health-check registry, DNS resolver) and injects it into every
//! submodule, so repeated in-process builds never share state. `main` is a
//! thin CLI/fatal-error adapter.

pub mod http;
pub mod status;

use std::ops::DerefMut;
use std::sync::Arc;

use async_trait::async_trait;
use pingora::services::listening::Service;
use pingora_core::{
    apps::HttpServerOptions,
    listeners::tls::TlsSettings,
    server::{configuration::Opt, Server, ShutdownWatch},
};
use pingora_proxy::{http_proxy_service_with_name, HttpProxy};
use sentry::IntoDsn;

use crate::admin::AdminHttpApp;
use crate::config::{self, etcd::EtcdConfigSync, Config, EffectiveDefaults};
use crate::core::status::StatusStore;
use crate::logging::Logger;
use crate::proxy::{
    graph_mutation::ConfigurationGraph, runtime::RuntimeStore, ssl::DynamicCert,
    upstream::health_check::SharedHealthCheckService,
};
use crate::service::{
    http::{CacheRuntime, HttpService},
    status::StatusHttpApp,
};
use crate::utils::encryption::KeyringService;
use hickory_resolver::TokioResolver;

// Service name constants
const PINGSIX_SERVICE: &str = "pingsix";

/// Instance-owned runtime state assembled once per [`GatewayRuntime::build`].
///
/// Every submodule (configuration graph, etcd sync, status app, HTTP service,
/// health-check executor) receives references into this single state, so two
/// builds in one process never share readiness, published snapshots, defaults,
/// encryption keyrings, cache namespaces, health-check registries, or DNS
/// resolvers.
///
/// Process-level statics that remain (not gateway state):
/// - Pingora cache objects leaked by [`CacheRuntime`] (`'static` API). This is
///   intentional: Pingora eviction and stale-revalidation tasks may retain the
///   references, so reclaiming them before process exit would be unsound.
/// - Prometheus `register_*` collectors (cache, logging, limit-count,
///   proxy-mirror, prometheus plugin, graph mutation)
/// - plugin metadata inventory (compile-time closed builtin declarations)
/// - the process logger (`init_logger` is first-wins)
pub struct GatewayState {
    /// Readiness / etcd-sync status (status HTTP app, graph, etcd sync).
    pub status: Arc<StatusStore>,
    /// Published runtime snapshots + health-check registration (graph, HTTP
    /// service, TLS callback).
    pub runtime: Arc<RuntimeStore>,
    /// Effective `pingsix.defaults` resolved at startup (candidate
    /// preparation/compilation, cache sizing).
    pub defaults: EffectiveDefaults,
    /// Field-encryption service (admin write path, control-plane load path).
    pub keyring: Arc<KeyringService>,
    /// Response-cache backend/eviction/lock (HTTP service).
    pub cache: Arc<CacheRuntime>,
    /// Health-check registry + executor service (registered with the server).
    pub health_check: Arc<SharedHealthCheckService>,
    /// DNS resolver (candidate preparation, refresh discovery).
    pub resolver: Arc<TokioResolver>,
}

impl GatewayState {
    /// Assemble a fresh state from configuration. Every component is
    /// instance-owned: nothing here reads process-global gateway facades.
    pub fn build(config: &Config) -> Result<Self, String> {
        let defaults = EffectiveDefaults::from_pingsix(&config.pingsix);
        let status = Arc::new(StatusStore::new());
        let health_check = Arc::new(SharedHealthCheckService::new());
        let runtime = Arc::new(RuntimeStore::with_state(
            status.clone(),
            health_check.clone(),
        ));
        let (enable, keyring) = match &config.pingsix.data_encryption {
            Some(c) => (c.enable, c.keyring.as_slice()),
            None => (false, &[][..]),
        };
        let keyring = Arc::new(KeyringService::new(enable, keyring).map_err(|e| e.to_string())?);
        if enable {
            log::info!(
                "Data encryption enabled with {} keyring key(s)",
                keyring_key_count(&config.pingsix)
            );
        }
        let cache = Arc::new(CacheRuntime::new(&defaults.cache));
        let resolver = crate::proxy::upstream::discovery::build_resolver_for_state()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            status,
            runtime,
            defaults,
            keyring,
            cache,
            health_check,
            resolver,
        })
    }
}

fn keyring_key_count(cfg: &config::Pingsix) -> usize {
    cfg.data_encryption
        .as_ref()
        .map(|c| c.keyring.len())
        .unwrap_or(0)
}

/// The complete gateway process: owns startup order, service registration, and
/// the configuration graph's lifecycle.
pub struct GatewayRuntime {
    server: Server,
    http_service: Option<Service<HttpProxy<HttpService>>>,
}

impl GatewayRuntime {
    /// Build the full process from a loaded configuration.
    ///
    /// Order is significant: process-global logging, then instance-owned
    /// [`GatewayState`] (defaults, encryption, cache, health checks, DNS),
    /// then the configuration source (etcd graph or static YAML), then the
    /// server, services, and listeners. A failure here aborts startup before
    /// any listener accepts traffic.
    pub fn build(opt: Opt, config: Config) -> Result<Self, String> {
        let logger = init_logger(&config);

        // Single composition root: every submodule below receives references
        // into this one instance-owned state.
        let state = GatewayState::build(&config)?;

        let (etcd_sync, config_graph) = init_config_source(&config, &state)?;

        let mut server = Server::new_with_opt_and_conf(Some(opt), config.pingora);

        // Register logger service to enable centralized log handling across all workers.
        if let Some(log_service) = logger {
            log::debug!("Initializing log sync service");
            server.add_service(log_service);
        }

        // Register etcd service for real-time config synchronization in cluster deployments.
        if let Some(etcd_service) = etcd_sync {
            log::debug!("Initializing etcd config sync service");
            server.add_service(etcd_service);
        }

        // Shared health check service reduces overhead by consolidating upstream
        // health monitoring and DNS refresh. The instance-owned service is
        // registered so its executor runs against THIS state's registry.
        log::debug!("Initializing shared health check service");
        server.add_service((*state.health_check).clone());

        // The runtime owns the graph's shutdown: a lifecycle service stops the
        // preparation worker on process shutdown, so the etcd transport never
        // reaches into the graph authority.
        if let Some(graph) = config_graph.clone() {
            server.add_service(GraphShutdownService { graph });
        }

        add_optional_services(
            &mut server,
            &config.pingsix,
            config_graph,
            state.status.clone(),
        )?;

        let http_service = build_proxy_service(
            &server.configuration,
            &config.pingsix,
            state.runtime.clone(),
            state.cache.clone(),
        )
        .map_err(|e| format!("Failed to configure listeners: {e}"))?;

        Ok(Self {
            server,
            http_service: Some(http_service),
        })
    }

    /// Bootstrap the server, attach the proxy service, and run until shutdown.
    pub fn run(mut self) {
        log::info!("Starting pingsix server");
        self.server.bootstrap();
        log::debug!("Server bootstrapped, adding services");
        self.server
            .add_service(self.http_service.take().expect("proxy service was built"));

        log::info!("Pingsix server running");
        self.server.run_forever();
    }
}

/// Stops the configuration graph's preparation worker when the process shuts
/// down. Keeps graph lifecycle ownership in the runtime instead of the etcd
/// transport.
struct GraphShutdownService {
    graph: Arc<ConfigurationGraph>,
}

#[async_trait]
impl pingora_core::services::Service for GraphShutdownService {
    async fn start_service(
        &mut self,
        _fds: Option<pingora_core::server::ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    log::debug!("Process shutdown: stopping configuration graph worker");
                    self.graph.shutdown().await;
                }
            }
        }
    }

    fn name(&self) -> &str {
        "GraphShutdown"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

/// Set up process-wide logging and return the service that owns the installed
/// writer, if this runtime won the one-time process-global installation race.
///
/// Rust's [`log`] facade has one immutable logger per process. Consequently the
/// first successful gateway build owns the logging sink; later builds never
/// panic and deliberately retain that sink instead of creating a Logger service
/// whose channel cannot receive any records. Changing the log destination in a
/// long-lived multi-runtime process requires a process restart.
fn init_logger(config: &Config) -> Option<Logger> {
    let install = if let Some(log_cfg) = &config.pingsix.log {
        let logger = Logger::new(log_cfg.clone());
        match logger.try_init_env_logger() {
            Ok(()) => return Some(logger),
            Err(_) => "custom file logger",
        }
    } else {
        match env_logger::try_init() {
            Ok(()) => return None,
            Err(_) => "default env logger",
        }
    };

    // `try_init` only fails here because a logger is already installed. Do not
    // use `log::warn!`: the pre-existing logger may itself be a failed/custom
    // sink, and direct stderr keeps the ownership decision observable.
    eprintln!(
        "A process-global logger is already installed; this gateway build will retain it and ignore its requested {install}"
    );
    None
}

/// Choose the configuration source: etcd for dynamic updates in distributed
/// environments, or static file for simple setups.
fn init_config_source(
    config: &Config,
    state: &GatewayState,
) -> Result<(Option<EtcdConfigSync>, Option<Arc<ConfigurationGraph>>), String> {
    if let Some(etcd_cfg) = &config.pingsix.etcd {
        log::debug!(
            "Initializing etcd config sync with prefix: {}",
            etcd_cfg.prefix
        );
        let graph = Arc::new(ConfigurationGraph::with_state(
            Arc::new(crate::config::etcd::EtcdGraphStore::new(etcd_cfg.clone())),
            state.status.clone(),
            state.runtime.clone(),
            state.defaults.clone(),
            state.keyring.clone(),
            state.resolver.clone(),
        ));
        Ok((
            Some(EtcdConfigSync::new(
                etcd_cfg.clone(),
                graph.clone(),
                state.status.clone(),
            )),
            Some(graph),
        ))
    } else {
        log::debug!("Loading static configurations from config file");
        ConfigurationGraph::load_static(
            config,
            &state.status,
            &state.runtime,
            &state.defaults,
            &state.resolver,
        )
        .map_err(|e| format!("Failed to load static configurations: {e}"))?;
        Ok((None, None))
    }
}

/// Configures HTTP/HTTPS listeners with TLS settings.
///
/// Uses dynamic cert loading to enable SNI support without server restart.
/// H2 and H2C are enabled separately because they require different TLS negotiation.
fn build_proxy_service(
    server_conf: &Arc<pingora::server::configuration::ServerConf>,
    cfg: &config::Pingsix,
    runtime: Arc<RuntimeStore>,
    cache: Arc<CacheRuntime>,
) -> Result<Service<HttpProxy<HttpService>>, Box<dyn std::error::Error>> {
    let mut http_service = http_proxy_service_with_name(
        server_conf,
        HttpService::new(runtime.clone(), cache),
        PINGSIX_SERVICE,
    );

    for list_cfg in cfg.listeners.iter() {
        if let Some(tls) = &list_cfg.tls {
            let dynamic_cert = DynamicCert::new(tls, runtime.clone()).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Failed to initialize TLS certificate: {e}"),
                )
            })?;
            let mut tls_settings = TlsSettings::with_callbacks(dynamic_cert)?;

            // Enforce TLS 1.2+ for security - older versions have known vulnerabilities
            // Set both minimum and maximum to prevent negotiation of TLS 1.0/1.1
            tls_settings
                .deref_mut()
                .set_min_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_2))?;
            tls_settings
                .deref_mut()
                .set_max_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_3))?;

            if list_cfg.offer_h2 {
                tls_settings.enable_h2();
            }
            http_service.add_tls_with_settings(&list_cfg.address.to_string(), None, tls_settings);
        } else {
            // Enable H2C (HTTP/2 over cleartext) for better performance without TLS overhead
            if list_cfg.offer_h2c {
                let http_logic = http_service
                    .app_logic_mut()
                    .ok_or("Failed to get app logic")?;
                let mut http_server_options = HttpServerOptions::default();
                http_server_options.h2c = true;
                http_logic.server_options = Some(http_server_options);
            }
            http_service.add_tcp(&list_cfg.address.to_string());
        }
    }
    Ok(http_service)
}

/// Conditionally enables monitoring and admin services based on configuration.
///
/// Invalid Sentry configuration only disables Sentry; Admin/Status/Prometheus still start.
/// Admin interface is only available when etcd is enabled.
fn add_optional_services(
    server: &mut Server,
    cfg: &config::Pingsix,
    config_graph: Option<Arc<ConfigurationGraph>>,
    status: Arc<StatusStore>,
) -> Result<(), String> {
    if let Some(sentry_cfg) = &cfg.sentry {
        if is_example_sentry_dsn(&sentry_cfg.dsn) {
            log::warn!("Ignoring example Sentry DSN, Sentry disabled");
        } else {
            log::debug!("Configuring Sentry monitoring");
            match sentry_cfg.dsn.clone().into_dsn() {
                Ok(Some(dsn)) => {
                    server.set_sentry_config(sentry::ClientOptions {
                        dsn: Some(dsn),
                        ..Default::default()
                    });
                    log::info!("Sentry monitoring enabled");
                }
                Ok(None) => {
                    log::warn!("Sentry DSN is empty, Sentry monitoring disabled");
                }
                Err(e) => {
                    log::error!("Invalid Sentry DSN configuration, Sentry disabled: {e}");
                }
            }
        }
    }

    if let (Some(graph), Some(admin_cfg)) = (config_graph, &cfg.admin) {
        admin_cfg.validate_bind_safety().map_err(|e| {
            log::error!("{e}");
            e
        })?;
        log::debug!("Configuring admin HTTP interface");
        if let Some(admin_service_http) = AdminHttpApp::admin_http_service(cfg, graph) {
            server.add_service(admin_service_http);
            log::info!("Admin HTTP interface enabled");
        } else {
            log::error!("Admin HTTP interface not configured (missing admin or etcd config)");
        }
    }

    if let Some(status_cfg) = &cfg.status {
        status_cfg.log_bind_safety();
        status.configure_policy(
            status_cfg.config_stale_after.unwrap_or(300),
            status_cfg.fail_readiness_when_stale,
        );
        log::debug!("Configuring status HTTP endpoint on {}", status_cfg.address);
        let status_service_http = StatusHttpApp::status_http_service(status_cfg, status);
        server.add_service(status_service_http);
        log::info!("Status HTTP endpoint enabled on {}", status_cfg.address);
    }

    if let Some(prometheus_cfg) = &cfg.prometheus {
        log::debug!(
            "Configuring Prometheus metrics endpoint on {}",
            prometheus_cfg.address
        );
        let mut prometheus_service_http = Service::prometheus_http_service();
        prometheus_service_http.add_tcp(&prometheus_cfg.address.to_string());
        server.add_service(prometheus_service_http);
        log::info!(
            "Prometheus metrics endpoint enabled on {}",
            prometheus_cfg.address
        );
    }
    Ok(())
}

/// Returns true if the Sentry DSN is the well-known placeholder used in docs/examples.
///
/// Starting up with this DSN would still ship (empty) events to a real project, so we
/// detect and ignore it to avoid accidental telemetry from default configs.
fn is_example_sentry_dsn(dsn: &str) -> bool {
    dsn.contains("examplePublicKey") || dsn.contains("o0.ingest.sentry.io/0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_sentry_dsn_detected() {
        assert!(is_example_sentry_dsn(
            "https://examplePublicKey@o0.ingest.sentry.io/0"
        ));
        assert!(!is_example_sentry_dsn("https://real@o1.ingest.sentry.io/1"));
    }

    #[test]
    fn repeated_logger_initialization_is_non_panicking_and_first_wins() {
        // The test process may already have a logger (or another test may win
        // first). In either case both calls must be safe and only an installer
        // receives a Logger service to register.
        let config = config::Config::default();
        let first = std::panic::catch_unwind(|| init_logger(&config));
        assert!(first.is_ok());
        let second = std::panic::catch_unwind(|| init_logger(&config));
        assert!(second.is_ok());
        assert!(first.unwrap().is_none() || second.unwrap().is_none());
    }

    #[test]
    fn gateway_runtime_builds_twice_in_one_process() {
        let mut config_a = config::Config::default();
        config_a.pingsix.defaults = Some(config::Defaults {
            upstream_timeout: Some(config::Timeout {
                connect: 1,
                send: 2,
                read: 3,
            }),
            dns_resolution_timeout: 5,
            dns_refresh_interval: None,
            cache: None,
        });
        let mut config_b = config::Config::default();
        config_b.pingsix.defaults = Some(config::Defaults {
            upstream_timeout: Some(config::Timeout {
                connect: 9,
                send: 8,
                read: 7,
            }),
            dns_resolution_timeout: 5,
            dns_refresh_interval: None,
            cache: None,
        });

        // Regression for `env_logger::init()`: the second complete runtime
        // build must not panic or silently reuse A's injected state.
        let first = GatewayRuntime::build(Opt::default(), config_a);
        assert!(first.is_ok());
        drop(first);
        let second = GatewayRuntime::build(Opt::default(), config_b);
        assert!(second.is_ok());
    }

    #[test]
    fn gateway_state_rejects_bad_encryption_keyring() {
        let mut config = config::Config::default();
        config.pingsix.data_encryption = Some(config::DataEncryption {
            enable: true,
            keyring: vec![],
        });
        assert!(GatewayState::build(&config).is_err());
    }

    #[test]
    fn two_states_with_different_defaults_do_not_pollute_each_other() {
        // Task 6 acceptance: repeated in-process builds must not silently
        // ignore configuration — every state owns its defaults, status, and
        // cache sizing.
        let mut config_a = config::Config::default();
        config_a.pingsix.defaults = Some(config::Defaults {
            upstream_timeout: Some(config::Timeout {
                connect: 1,
                send: 2,
                read: 3,
            }),
            dns_resolution_timeout: 2,
            dns_refresh_interval: Some(7),
            cache: Some(config::CacheDefaults {
                max_memory_bytes: 11,
                default_max_object_bytes: 12,
            }),
        });
        let state_a = GatewayState::build(&config_a).unwrap();

        let mut config_b = config::Config::default();
        config_b.pingsix.defaults = Some(config::Defaults {
            upstream_timeout: Some(config::Timeout {
                connect: 9,
                send: 8,
                read: 7,
            }),
            dns_resolution_timeout: 5,
            dns_refresh_interval: None,
            cache: Some(config::CacheDefaults {
                max_memory_bytes: 22,
                default_max_object_bytes: 23,
            }),
        });
        let state_b = GatewayState::build(&config_b).unwrap();

        // Each build resolved its own defaults (no first-write-wins globals).
        assert_eq!(
            state_a.defaults.upstream_timeout.as_ref().unwrap().connect,
            1
        );
        assert_eq!(
            state_b.defaults.upstream_timeout.as_ref().unwrap().connect,
            9
        );
        assert_eq!(state_a.defaults.cache.max_memory_bytes, 11);
        assert_eq!(state_b.defaults.cache.max_memory_bytes, 22);

        // Readiness state is per-instance: publishing on A never touches B.
        state_a.status.set_published_revision(42);
        assert_eq!(state_b.status.published_revision(), 0);
        assert_eq!(state_a.status.published_revision(), 42);

        // Distinct runtime snapshots, health-check registries, and cache
        // backends (the Pingora `'static` edge is owned per instance).
        assert!(!Arc::ptr_eq(&state_a.runtime, &state_b.runtime));
        assert!(!Arc::ptr_eq(&state_a.health_check, &state_b.health_check));
        assert!(!Arc::ptr_eq(&state_a.cache, &state_b.cache));
    }
}
