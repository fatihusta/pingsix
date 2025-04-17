#![allow(clippy::upper_case_acronyms)]
mod admin;
mod config;
mod logging;
mod plugin;
mod proxy;
mod service;
mod utils;

use std::ops::DerefMut;

use pingora::services::listening::Service;
use pingora_core::{
    apps::HttpServerOptions,
    listeners::tls::TlsSettings,
    server::{configuration::Opt, Server},
};
use pingora_proxy::{http_proxy_service_with_name, HttpProxy};
use sentry::IntoDsn;

use admin::AdminHttpApp;
use config::{etcd::EtcdConfigSync, Config};
use logging::Logger;
use proxy::{
    event::ProxyEventHandler,
    global_rule::load_static_global_rules,
    route::load_static_routes,
    service::load_static_services,
    ssl::{load_static_ssls, DynamicCert},
    upstream::load_static_upstreams,
};
use service::http::HttpService;

fn main() {
    // 加载配置和命令行参数
    let cli_options = Opt::parse_args();
    let config =
        Config::load_yaml_with_opt_override(&cli_options).expect("Failed to load configuration");

    // 初始化日志
    let logger = if let Some(log_cfg) = &config.pingsix.log {
        let logger = Logger::new(log_cfg.clone());
        logger.init_env_logger();
        Some(logger)
    } else {
        env_logger::init();
        None
    };

    // 配置同步
    let etcd_sync = if let Some(etcd_cfg) = &config.pingsix.etcd {
        log::info!("Adding etcd config sync...");
        let event_handler = ProxyEventHandler::new(config.pingora.work_stealing);
        Some(EtcdConfigSync::new(
            etcd_cfg.clone(),
            Box::new(event_handler),
        ))
    } else {
        log::info!("Loading services, upstreams, and routes...");
        load_static_upstreams(&config).expect("Failed to load static upstreams");
        load_static_services(&config).expect("Failed to load static services");
        load_static_global_rules(&config).expect("Failed to load static global rules");
        load_static_routes(&config).expect("Failed to load  static routes");
        load_static_ssls(&config).expect("Failed to load  static ssls");
        None
    };

    // 创建服务器实例
    let mut pingsix_server = Server::new_with_opt_and_conf(Some(cli_options), config.pingora);

    // 添加日志服务
    if let Some(log_service) = logger {
        log::info!("Adding log sync service...");
        pingsix_server.add_service(log_service);
    }

    // 添加 Etcd 配置同步服务
    if let Some(etcd_service) = etcd_sync {
        log::info!("Adding etcd config sync service...");
        pingsix_server.add_service(etcd_service);
    }

    // 初始化 HTTP 服务
    let mut http_service =
        http_proxy_service_with_name(&pingsix_server.configuration, HttpService {}, "pingsix");

    // 添加监听器
    log::info!("Adding listeners...");
    add_listeners(&mut http_service, &config.pingsix);

    // 添加扩展服务（如 Sentry 和 Prometheus, Admin）
    add_optional_services(&mut pingsix_server, &config.pingsix);

    // 启动服务器
    log::info!("Bootstrapping...");
    pingsix_server.bootstrap();
    log::info!("Bootstrapped. Adding Services...");
    pingsix_server.add_service(http_service);

    log::info!("Starting Server...");
    pingsix_server.run_forever();
}

// 添加监听器的辅助函数
fn add_listeners(http_service: &mut Service<HttpProxy<HttpService>>, cfg: &config::Pingsix) {
    for list_cfg in cfg.listeners.iter() {
        if let Some(tls) = &list_cfg.tls {
            // ... TLS 配置
            let dynamic_cert = DynamicCert::new(tls);
            let mut tls_settings = TlsSettings::with_callbacks(dynamic_cert)
                .expect("Init dynamic cert shouldn't fail");

            tls_settings
                .deref_mut()
                .deref_mut()
                .set_max_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_3))
                .expect("Init dynamic cert shouldn't fail");

            if list_cfg.offer_h2 {
                tls_settings.enable_h2();
            }
            http_service.add_tls_with_settings(&list_cfg.address.to_string(), None, tls_settings);
        } else {
            // 无 TLS
            if list_cfg.offer_h2c {
                //... H2C 配置
                let http_logic = http_service.app_logic_mut().unwrap();
                let mut http_server_options = HttpServerOptions::default();
                http_server_options.h2c = true;
                http_logic.server_options = Some(http_server_options);
            }
            http_service.add_tcp(&list_cfg.address.to_string());
        }
    }
}

// 添加可选服务（如 Sentry 和 Prometheus, Admin）的辅助函数
fn add_optional_services(server: &mut Server, cfg: &config::Pingsix) {
    if let Some(sentry_cfg) = &cfg.sentry {
        log::info!("Adding Sentry config...");
        server.sentry = Some(sentry::ClientOptions {
            dsn: sentry_cfg
                .dsn
                .clone()
                .into_dsn()
                .expect("Invalid Sentry DSN"),
            ..Default::default()
        });
    }

    if cfg.etcd.is_some() && cfg.admin.is_some() {
        log::info!("Adding Admin Service...");
        let admin_service_http = AdminHttpApp::admin_http_service(cfg);
        server.add_service(admin_service_http);
    }

    if let Some(prometheus_cfg) = &cfg.prometheus {
        log::info!("Adding Prometheus Service...");
        let mut prometheus_service_http = Service::prometheus_http_service();
        prometheus_service_http.add_tcp(&prometheus_cfg.address.to_string());
        server.add_service(prometheus_service_http);
    }
}
