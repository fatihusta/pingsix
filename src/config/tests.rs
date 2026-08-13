//! Tests for process configuration, resource schemas, defaults, and encryption
//! metadata. Kept out of `mod.rs` so the production module stays focused.

use super::schema::{schema_for, suggest_field, unrecognized_fields, FieldWarning};
use super::*;
use crate::utils::encryption::EncryptFields;
use crate::utils::encryption::KeyringService;
use http::Method;

fn init_log() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn passive_schema_accepts_disabled_thresholds_and_rejects_bad_statuses() {
    let valid = PassiveCheck {
        r#type: PassiveCheckType::HTTP,
        healthy: PassiveHealthy {
            http_statuses: vec![200],
            successes: 0,
        },
        unhealthy: PassiveUnhealthy {
            http_statuses: vec![500],
            tcp_failures: 0,
            timeouts: 0,
            http_failures: 0,
        },
    };
    assert!(valid.validate().is_ok());

    for statuses in [vec![], vec![199], vec![600], vec![500, 500]] {
        let mut invalid = valid.clone();
        invalid.unhealthy.http_statuses = statuses;
        assert!(invalid.validate().is_err());
    }
    let mut too_large = valid;
    too_large.healthy.successes = 255;
    assert!(too_large.validate().is_err());
}

#[test]
fn health_check_requires_active_or_passive() {
    // Passive-only is valid (APISIX allows a `checks` block with only passive).
    let passive_only = HealthCheck {
        active: None,
        passive: Some(PassiveCheck {
            r#type: PassiveCheckType::HTTP,
            healthy: PassiveHealthy::default(),
            unhealthy: PassiveUnhealthy::default(),
        }),
    };
    assert!(passive_only.validate().is_ok());

    // Neither active nor passive is rejected.
    let neither = HealthCheck {
        active: None,
        passive: None,
    };
    assert!(neither.validate().is_err());
}

#[test]
fn test_print_default_yaml() {
    init_log();
    let conf = Config::default();
    println!("{}", conf.to_yaml());
}

#[test]
fn test_load_file() {
    init_log();
    let conf_str = r#"
---
pingora:
  version: 1
  client_bind_to_ipv4:
      - 1.2.3.4
      - 5.6.7.8
  client_bind_to_ipv6: []

pingsix:
  listeners:
    - address: 0.0.0.0:8080
    - address: "[::1]:8080"
      tls:
        cert_path: /etc/ssl/server.crt
        key_path: /etc/ssl/server.key
      offer_h2: true

routes:
  - id: "1"
    uri: /
    methods: [GET, POST]
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http

upstreams:
  - nodes:
      "127.0.0.1:1980": 1
    id: "1"
    checks:
      active:
        type: http

services:
  - id: "1"
    upstream_id: "1"
    hosts: ["example.com"]
        "#;
    let conf = Config::from_yaml(conf_str).unwrap();
    assert_eq!(2, conf.pingora.client_bind_to_ipv4.len());
    assert_eq!(0, conf.pingora.client_bind_to_ipv6.len());
    assert_eq!(1, conf.pingora.version);
    assert_eq!(2, conf.pingsix.listeners.len());
    assert_eq!(1, conf.routes.len());
    assert_eq!(1, conf.upstreams.len());
    assert_eq!(1, conf.services.len());
    assert_eq!(vec![Method::GET, Method::POST], conf.routes[0].methods);
    print!("{}", conf.to_yaml());
}

#[test]
fn test_load_file_upstream_id() {
    init_log();
    let conf_str = r#"
---
pingora:
  version: 1
  client_bind_to_ipv4:
      - 1.2.3.4
      - 5.6.7.8
  client_bind_to_ipv6: []

pingsix:
  listeners:
    - address: 0.0.0.0:8080
      offer_h2c: true
    - address: "[::1]:8080"
      tls:
        cert_path: /etc/ssl/server.crt
        key_path: /etc/ssl/server.key
      offer_h2: true

routes:
  - id: "1"
    uri: /
    methods: [GET]
    upstream_id: "1"

upstreams:
  - nodes:
      "127.0.0.1:1980": 1
    id: "1"
    checks:
      active:
        type: http
  - nodes:
      "127.0.0.1:1981": 1
    id: "2"
    checks:
      active:
        type: http

services:
  - id: "1"
    upstream_id: "1"
    hosts: ["example.com"]
        "#;
    let conf = Config::from_yaml(conf_str).unwrap();
    assert_eq!(2, conf.pingora.client_bind_to_ipv4.len());
    assert_eq!(0, conf.pingora.client_bind_to_ipv6.len());
    assert_eq!(1, conf.pingora.version);
    assert_eq!(2, conf.pingsix.listeners.len());
    assert_eq!(1, conf.routes.len());
    assert_eq!(2, conf.upstreams.len());
    assert_eq!(1, conf.services.len());
    assert_eq!(vec![Method::GET], conf.routes[0].methods);
    print!("{}", conf.to_yaml());
}

#[test]
fn test_valid_listeners_length() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners: []

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
    let conf = Config::from_yaml(conf_str);
    match conf {
        Ok(_) => panic!("Expected error, but got a valid config"),
        Err(e) => {
            eprintln!("Error: {e:?}");
            // Test passes if we get an error
        }
    }
}

#[test]
fn test_valid_listeners_tls_for_offer_h2() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
      offer_h2: true

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
    let conf = Config::from_yaml(conf_str);
    match conf {
        Ok(_) => panic!("Expected error, but got a valid config"),
        Err(e) => {
            eprintln!("Error: {e:?}");
            // Test passes if we get an error
        }
    }
}

#[test]
fn test_valid_routes_uri_and_uris() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
    let conf = Config::from_yaml(conf_str);
    match conf {
        Ok(_) => panic!("Expected error, but got a valid config"),
        Err(e) => {
            eprintln!("Error: {e:?}");
            // Test passes if we get an error
        }
    }
}

#[test]
fn route_rejects_uri_and_uris_together() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    uris: ["/other"]
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
    assert!(
        Config::from_yaml(conf_str).is_err(),
        "uri and uris are mutually exclusive forms"
    );
}

#[test]
fn route_rejects_host_and_hosts_together() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    host: api.example.com
    hosts: ["other.example.com"]
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;
    assert!(
        Config::from_yaml(conf_str).is_err(),
        "host and hosts are mutually exclusive forms"
    );
}

#[test]
fn route_rejects_upstream_and_upstream_id_together() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
    upstream_id: "named-upstream"
        "#;
    assert!(
        Config::from_yaml(conf_str).is_err(),
        "inline upstream and upstream_id are mutually exclusive forms"
    );
}

#[test]
fn route_allows_upstream_id_with_service_id() {
    init_log();
    // Route-level upstream_id overriding a service's upstream is a valid
    // APISIX pattern and must remain accepted.
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

services:
  - id: "s1"
    upstream:
      nodes:
        "127.0.0.1:1981": 1

routes:
  - id: "1"
    uri: /
    upstream_id: "u1"
    service_id: "s1"

upstreams:
  - id: "u1"
    nodes:
      "127.0.0.1:1982": 1
        "#;
    assert!(
        Config::from_yaml(conf_str).is_ok(),
        "upstream_id + service_id must remain valid"
    );
}

#[test]
fn service_rejects_upstream_and_upstream_id_together() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

services:
  - id: "s1"
    upstream:
      nodes:
        "127.0.0.1:1981": 1
    upstream_id: "u1"
        "#;
    assert!(
        Config::from_yaml(conf_str).is_err(),
        "service inline upstream and upstream_id are mutually exclusive"
    );
}

#[test]
fn test_valid_routes_upstream_host() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      pass_host: rewrite
        "#;
    let conf = Config::from_yaml(conf_str);
    match conf {
        Ok(_) => panic!("Expected error, but got a valid config"),
        Err(e) => {
            eprintln!("Error: {e:?}");
            // Test passes if we get an error
        }
    }
}

#[test]
fn test_valid_config_upstream_id() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http

upstreams:
  - nodes:
      "127.0.0.1:1980": 1
    checks:
      active:
        type: http
        "#;
    let conf = Config::from_yaml(conf_str);
    match conf {
        Ok(_) => panic!("Expected error, but got a valid config"),
        Err(e) => {
            eprintln!("Error: {e:?}");
            // Test passes if we get an error
        }
    }
}

#[test]
fn test_valid_route_upstream() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
        "#;
    let conf = Config::from_yaml(conf_str);
    match conf {
        Ok(_) => panic!("Expected error, but got a valid config"),
        Err(e) => {
            eprintln!("Error: {e:?}");
            // Test passes if we get an error
        }
    }
}

#[test]
fn test_valid_service_upstream() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http

services:
  - id: "1"
    hosts: ["example.com"]
        "#;
    let conf = Config::from_yaml(conf_str);
    match conf {
        Ok(_) => panic!("Expected error, but got a valid config"),
        Err(e) => {
            eprintln!("Error: {e:?}");
            // Test passes if we get an error
        }
    }
}

#[test]
fn test_admin_api_key_must_not_be_empty() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
  admin:
    address: "127.0.0.1:9180"
    api_key: "   "

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
        "#;

    let conf = Config::from_yaml(conf_str);
    match conf {
        Ok(_) => panic!("Expected error, but got a valid config"),
        Err(e) => {
            eprintln!("Error: {e:?}");
        }
    }
}

#[test]
fn test_duplicate_ids() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
  - id: "1"
    uri: /other
    upstream:
      nodes:
        "127.0.0.1:1981": 1

upstreams:
  - id: "1"
    nodes:
      "127.0.0.1:1980": 1
  - id: "1"
    nodes:
      "127.0.0.1:1981": 1
        "#;
    let conf = Config::from_yaml(conf_str);
    match conf {
        Ok(_) => panic!("Expected error, but got a valid config"),
        Err(e) => {
            eprintln!("Error: {e:?}");
            // Test passes if we get an error
        }
    }
}

#[test]
fn test_invalid_node_key() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "-invalid.com:8080": 1
        "#;
    let conf = Config::from_yaml(conf_str);
    match conf {
        Ok(_) => panic!("Expected error, but got a valid config"),
        Err(e) => {
            eprintln!("Error: {e:?}");
            // Test passes if we get an error
        }
    }
}

#[test]
fn test_upstream_with_tls() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"

routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      scheme: https
      tls:
        client_cert: |
          -----BEGIN CERTIFICATE-----
          MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
          A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
          aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
          ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
          CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
          dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
          dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
          BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
          uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
          DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
          SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
          l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
          -----END CERTIFICATE-----
        client_key: |
          -----BEGIN EC PRIVATE KEY-----
          MHcCAQEEIIrYSSNdykVHguvz6t+tCg4EBdAy/pQjf4qwl3VhfhBloAoGCCqGSM49
          AwEHoUQDQgAEUtiNI4rjZ9eGNrEgCwl9yMm6oiCVL8VKY/qDX854L4/zYsr9t/eA
          Vp1uF7kOEUxIssCvO1kXFjBoCQeZF/7dp6A==
          -----END EC PRIVATE KEY-----

upstreams:
  - id: "1"
    nodes:
      "192.168.1.100:8443": 1
    scheme: https
    tls:
      client_cert: |
        -----BEGIN CERTIFICATE-----
        MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
        A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
        aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
        ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
        CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
        dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
        dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
        BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
        uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
        DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
        SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
        l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
        -----END CERTIFICATE-----
      client_key: |
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIIrYSSNdykVHguvz6t+tCg4EBdAy/pQjf4qwl3VhfhBloAoGCCqGSM49
        AwEHoUQDQgAEUtiNI4rjZ9eGNrEgCwl9yMm6oiCVL8VKY/qDX854L4/zYsr9t/eA
        Vp1uF7kOEUxIssCvO1kXFjBoCQeZF/7dp6A==
        -----END EC PRIVATE KEY-----
        "#;
    let conf = Config::from_yaml(conf_str).unwrap();
    assert_eq!(1, conf.routes.len());
    assert_eq!(1, conf.upstreams.len());

    // Check route upstream TLS config
    let route_upstream = conf.routes[0].upstream.as_ref().unwrap();
    assert!(route_upstream.tls.is_some());
    let route_tls = route_upstream.tls.as_ref().unwrap();
    assert!(route_tls.client_cert.contains("BEGIN CERTIFICATE"));
    assert!(route_tls.client_key.contains("BEGIN EC PRIVATE KEY"));

    // Check upstream TLS config
    let upstream = &conf.upstreams[0];
    assert!(upstream.tls.is_some());
    let upstream_tls = upstream.tls.as_ref().unwrap();
    assert!(upstream_tls.client_cert.contains("BEGIN CERTIFICATE"));
    assert!(upstream_tls.client_key.contains("BEGIN EC PRIVATE KEY"));
}

#[test]
fn upstream_tls_encrypt_fields_visits_client_key_not_cert() {
    use crate::utils::encryption::CIPHERTEXT_PREFIX;

    let mut cfg = serde_json::json!({
        "nodes": { "127.0.0.1:443": 1 },
        "tls": {
            "client_cert": "cert-pem",
            "client_key": format!("{CIPHERTEXT_PREFIX}deadbeef"),
        }
    });
    let err = Upstream::transform_secrets(&mut cfg, SecretOp::Decrypt, &KeyringService::disabled())
        .unwrap_err();
    assert!(
        err.to_string().contains("data_encryption is disabled")
            || err.to_string().contains("Encrypted value"),
        "{err}"
    );
    assert_eq!(cfg["tls"]["client_cert"], "cert-pem");
}

/// A resource's derived `EncryptFields` must descend into its `plugins`
/// map (via `#[encrypt(plugins)]`) and its inline `upstream`, so wiring a
/// new secret only requires marking the plugin/struct field.
#[test]
fn route_transform_secrets_walks_plugins_and_inline_upstream() {
    use crate::utils::encryption::CIPHERTEXT_PREFIX;

    // Ciphertext with encryption disabled surfaces an error, proving the
    // walk reached the plugin secret field.
    let mut route = serde_json::json!({
        "uri": "/",
        "plugins": {
            "basic-auth": {
                "username": "demo",
                "password": format!("{CIPHERTEXT_PREFIX}deadbeef"),
            }
        }
    });
    let err = transform_resource_secrets(
        &KeyringService::disabled(),
        "routes",
        &mut route,
        SecretOp::Decrypt,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("data_encryption is disabled")
            || err.to_string().contains("Encrypted value"),
        "{err}"
    );

    // Same for an inline upstream TLS private key.
    let mut route = serde_json::json!({
        "uri": "/",
        "upstream": {
            "nodes": { "127.0.0.1:443": 1 },
            "tls": {
                "client_cert": "cert-pem",
                "client_key": format!("{CIPHERTEXT_PREFIX}deadbeef"),
            }
        }
    });
    let err = transform_resource_secrets(
        &KeyringService::disabled(),
        "routes",
        &mut route,
        SecretOp::Decrypt,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("data_encryption is disabled")
            || err.to_string().contains("Encrypted value"),
        "{err}"
    );

    // Unknown resource types are a no-op pass-through.
    let mut other = serde_json::json!({ "foo": "bar" });
    transform_resource_secrets(
        &KeyringService::disabled(),
        "unknown",
        &mut other,
        SecretOp::Decrypt,
    )
    .unwrap();
    assert_eq!(other["foo"], "bar");
}

#[test]
fn admin_bind_rejects_non_loopback_without_insecure_flag() {
    let admin = Admin {
        address: "0.0.0.0:9181".parse().unwrap(),
        api_key: "secret".into(),
        allow_insecure_remote: false,
    };
    assert!(admin.validate_bind_safety().is_err());
}

#[test]
fn admin_bind_allows_loopback_and_explicit_insecure_remote() {
    let loopback = Admin {
        address: "127.0.0.1:9181".parse().unwrap(),
        api_key: "secret".into(),
        allow_insecure_remote: false,
    };
    assert!(loopback.validate_bind_safety().is_ok());

    let remote = Admin {
        address: "0.0.0.0:9181".parse().unwrap(),
        api_key: "secret".into(),
        allow_insecure_remote: true,
    };
    assert!(remote.validate_bind_safety().is_ok());
}

#[test]
fn data_encryption_requires_keyring_when_enabled() {
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "127.0.0.1:8080"
  data_encryption:
    enable: true
    keyring: []
"#;
    assert!(Config::from_yaml(conf_str).is_err());
}

#[test]
fn data_encryption_accepts_keyring() {
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "127.0.0.1:8080"
  data_encryption:
    enable: true
    keyring:
      - "12387412834"
      - "89731823413"
"#;
    let conf = Config::from_yaml(conf_str).unwrap();
    let enc = conf.pingsix.data_encryption.unwrap();
    assert!(enc.enable);
    assert_eq!(enc.keyring.len(), 2);
}

#[test]
fn test_unknown_fields_in_resources_accepted() {
    init_log();
    // Resource types (Route, Upstream, Service, SSL) must tolerate unknown fields
    // for compatibility with ingress-controller which embeds metadata fields
    // (name, description, labels) in the serialized JSON/YAML.
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    name: "my-route"
    labels:
      managed-by: apisix-ingress-controller
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      retry_timout: 10
"#;
    let conf = Config::from_yaml(conf_str);
    assert!(
        conf.is_ok(),
        "Expected unknown fields in resources to be accepted, got error: {:?}",
        conf.err()
    );
}

#[test]
fn unrecognized_field_warnings_include_full_typed_paths_and_skip_free_objects() {
    let resource = serde_json::json!({
        "nodes": { "backend:80": { "weigth": 1 } },
        "plugins": { "example": { "config_typo": true } },
        "metadata": { "annotation_typo": true },
        "checks": {
            "active": {
                "healthy": { "sucesses": 2 },
            },
            "passive": {
                "unhealthy": { "http_failuers": 3 },
            },
        },
        "tls": { "client_kay": "private" },
    });

    let warnings = unrecognized_fields("upstreams", &resource);
    assert_eq!(
        warnings,
        vec![
            FieldWarning {
                path: "upstreams.checks.active.healthy.sucesses".into(),
                suggestion: Some("successes"),
            },
            FieldWarning {
                path: "upstreams.checks.passive.unhealthy.http_failuers".into(),
                suggestion: Some("http_failures"),
            },
            FieldWarning {
                path: "upstreams.tls.client_kay".into(),
                suggestion: Some("client_key"),
            },
        ]
    );
}

#[test]
fn unknown_field_typos_suggest_the_closest_known_field() {
    let upstream = schema_for("upstream").expect("upstream schema exists");
    // `retry_timout` is one deletion away from `retry_timeout`.
    assert_eq!(
        suggest_field(upstream, "retry_timout", "retry_timout".chars().count()),
        Some("retry_timeout")
    );
    // A completely unrelated field gets no suggestion.
    assert_eq!(
        suggest_field(
            upstream,
            "totally_unrelated",
            "totally_unrelated".chars().count()
        ),
        None
    );
    // A known field is not a typo of itself; suggestion is for *other* fields only.
    assert_eq!(
        suggest_field(
            schema_for("route").unwrap(),
            "upstream",
            "upstream".chars().count()
        ),
        None
    );
}

#[test]
fn resolve_upstream_timeout_prefers_explicit() {
    init_log();
    let explicit = Timeout {
        connect: 1,
        send: 2,
        read: 3,
    };
    let global = Timeout {
        connect: 9,
        send: 9,
        read: 9,
    };
    let t = resolve_upstream_timeout(Some(explicit), Some(global));
    assert_eq!(t.connect, 1);
    assert_eq!(t.read, 3);
}

#[test]
fn resolve_upstream_timeout_uses_global_when_explicit_none() {
    init_log();
    let global = Timeout {
        connect: 9,
        send: 9,
        read: 9,
    };
    let t = resolve_upstream_timeout(None, Some(global));
    assert_eq!(t.connect, 9);
}

#[test]
fn resolve_upstream_timeout_uses_built_in_when_both_absent() {
    init_log();
    assert_eq!(
        resolve_upstream_timeout(None, None),
        BUILTIN_UPSTREAM_TIMEOUT
    );
}

#[test]
fn log_rotation_defaults_internal_and_accepts_explicit_modes() {
    let internal: Log = serde_yml::from_str("path: /tmp/pingsix.log").unwrap();
    assert_eq!(internal.rotation, LogRotation::Internal);
    let external: Log = serde_yml::from_str("path: /tmp/pingsix.log\nrotation: external").unwrap();
    assert_eq!(external.rotation, LogRotation::External);
    let disabled: Log = serde_yml::from_str("path: /tmp/pingsix.log\nrotation: disabled").unwrap();
    assert_eq!(disabled.rotation, LogRotation::Disabled);
}

#[test]
fn status_defaults_to_fail_closed_and_protects_remote_diagnostics() {
    let status: Status = serde_yml::from_str("address: 127.0.0.1:9000").unwrap();
    assert!(status.fail_readiness_when_stale);
    assert!(status.diagnostics_enabled());
    let remote: Status = serde_yml::from_str("address: 0.0.0.0:9000").unwrap();
    assert!(!remote.diagnostics_enabled());
}

#[test]
fn test_health_check_port_out_of_range() {
    init_log();
    for port in [0u32, 70000] {
        let conf_str = format!(
            r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          port: {port}
"#
        );
        let conf = Config::from_yaml(&conf_str);
        assert!(
            conf.is_err(),
            "Expected health check port {port} to be rejected"
        );
    }
}

#[test]
fn test_health_check_zero_interval_rejected() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          healthy:
            interval: 0
"#;
    assert!(Config::from_yaml(conf_str).is_err());
}

#[test]
fn test_health_check_zero_timeout_rejected() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          timeout: 0
"#;
    assert!(Config::from_yaml(conf_str).is_err());
}

#[test]
fn test_health_check_zero_successes_rejected() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          healthy:
            successes: 0
"#;
    assert!(Config::from_yaml(conf_str).is_err());
}

#[test]
fn test_health_check_zero_failures_rejected() {
    init_log();
    for (field, yaml) in [
        (
            "http_failures",
            r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          unhealthy:
            http_failures: 0
"#,
        ),
        (
            "tcp_failures",
            r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
      checks:
        active:
          type: http
          unhealthy:
            tcp_failures: 0
"#,
        ),
    ] {
        let conf = Config::from_yaml(yaml);
        assert!(
            conf.is_err(),
            "Expected health check {field}=0 to be rejected"
        );
    }
}

#[test]
fn test_defaults_cache_parsed() {
    init_log();
    // Explicit values.
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
  defaults:
    cache:
      max_memory_bytes: 1048576
      default_max_object_bytes: 2048
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
"#;
    let conf = Config::from_yaml(conf_str).unwrap();
    let cache = conf
        .pingsix
        .defaults
        .expect("defaults present")
        .cache
        .expect("cache present");
    assert_eq!(cache.max_memory_bytes, 1048576);
    assert_eq!(cache.default_max_object_bytes, 2048);

    // Empty cache -> defaults 512MB / 1MB.
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
  defaults:
    cache: {}
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
"#;
    let conf = Config::from_yaml(conf_str).unwrap();
    let cache = conf
        .pingsix
        .defaults
        .expect("defaults present")
        .cache
        .expect("cache present");
    assert_eq!(cache.max_memory_bytes, 512 * 1024 * 1024);
    assert_eq!(cache.default_max_object_bytes, 1024 * 1024);
}

#[test]
fn test_defaults_upstream_timeout_parsed() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
  defaults:
    upstream_timeout:
      connect: 1
      send: 2
      read: 3
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
"#;
    let conf = Config::from_yaml(conf_str).unwrap();
    let t = conf
        .pingsix
        .defaults
        .expect("defaults present")
        .upstream_timeout
        .expect("upstream_timeout present");
    assert_eq!(t.connect, 1);
    assert_eq!(t.send, 2);
    assert_eq!(t.read, 3);
}

#[test]
fn test_etcd_tls_parsed() {
    init_log();
    let conf_str = r#"
---
pingsix:
  listeners:
    - address: "[::1]:8080"
  etcd:
    host:
      - "https://127.0.0.1:2379"
    prefix: "/pingsix"
    tls:
      ca_cert: /a.pem
      client_cert: /c.pem
      client_key: /k.pem
      domain: etcd.x
routes:
  - id: "1"
    uri: /
    upstream:
      nodes:
        "127.0.0.1:1980": 1
"#;
    let conf = Config::from_yaml(conf_str).unwrap();
    let tls = conf
        .pingsix
        .etcd
        .expect("etcd present")
        .tls
        .expect("tls present");
    assert_eq!(tls.ca_cert, "/a.pem");
    assert_eq!(tls.client_cert.as_deref(), Some("/c.pem"));
    assert_eq!(tls.client_key.as_deref(), Some("/k.pem"));
    assert_eq!(tls.domain.as_deref(), Some("etcd.x"));
}

#[test]
fn etcd_tls_rejects_partial_mtls() {
    use validator::Validate;
    // client_cert present without client_key must fail validation rather
    // than silently skip mTLS.
    let tls = EtcdTls {
        ca_cert: "/a.pem".to_string(),
        client_cert: Some("/c.pem".to_string()),
        client_key: None,
        domain: None,
    };
    assert!(tls.validate().is_err());

    // Symmetric: key without cert also fails.
    let tls = EtcdTls {
        ca_cert: "/a.pem".to_string(),
        client_cert: None,
        client_key: Some("/k.pem".to_string()),
        domain: None,
    };
    assert!(tls.validate().is_err());

    // Both present (or both absent) is valid.
    let tls = EtcdTls {
        ca_cert: "/a.pem".to_string(),
        client_cert: Some("/c.pem".to_string()),
        client_key: Some("/k.pem".to_string()),
        domain: None,
    };
    assert!(tls.validate().is_ok());

    let tls = EtcdTls {
        ca_cert: "/a.pem".to_string(),
        client_cert: None,
        client_key: None,
        domain: None,
    };
    assert!(tls.validate().is_ok());
}

#[test]
fn upstream_yaml_accepts_both_map_and_list_nodes() {
    let map_yaml = r#"
id: u1
nodes:
  "127.0.0.1:1980": 1
"#;
    let list_yaml = r#"
id: u2
nodes:
  - host: 127.0.0.1
    port: 1980
    weight: 1
"#;
    let from_map: Upstream = serde_yml::from_str(map_yaml).unwrap();
    let from_list: Upstream = serde_yml::from_str(list_yaml).unwrap();
    assert!(from_map.nodes.contains_addr("127.0.0.1:1980"));
    assert!(from_list.nodes.contains_addr("127.0.0.1:1980"));
    assert!(from_map.validate().is_ok());
    assert!(from_list.validate().is_ok());
}

#[test]
fn upstream_rejects_mixed_map_and_list_node_forms() {
    // YAML cannot express map entries and sequence items in the same
    // mapping value; the document itself is invalid.
    let mixed_yaml = r#"
id: u1
nodes:
  "127.0.0.1:1980": 1
  - host: 10.0.0.2
    port: 1980
    weight: 1
"#;
    assert!(
        serde_yml::from_str::<Upstream>(mixed_yaml).is_err(),
        "mixed map/list under nodes must not parse"
    );
}

fn upstream_with_nodes(nodes: &str, scheme: &str) -> Upstream {
    let yaml = format!("id: u1\nscheme: {scheme}\nnodes:\n{nodes}");
    serde_yml::from_str(&yaml).expect("valid upstream yaml")
}

#[test]
fn upstream_rejects_duplicate_node_addresses() {
    let dup = upstream_with_nodes(
        "  - host: 127.0.0.1\n    port: 443\n    priority: -1\n  \
             - host: 127.0.0.1\n    port: 443\n    priority: 10\n",
        "https",
    );
    let err = dup.validate().expect_err("duplicate host:port must fail");
    assert!(
        err.to_string().contains("nodes_duplicate_address"),
        "unexpected error: {err}"
    );
}

#[test]
fn upstream_rejects_omitted_port_colliding_with_scheme_default() {
    // Over HTTP the portless node dials :80, so these are one endpoint and
    // Pingora would collapse them into a single backend.
    let http = upstream_with_nodes(
        "  - host: example.com\n  - host: example.com\n    port: 80\n",
        "http",
    );
    let err = http
        .validate()
        .expect_err("omitted port must collide with explicit :80 over http");
    assert!(
        err.to_string().contains("nodes_duplicate_address"),
        "unexpected error: {err}"
    );

    // Over HTTPS the same pair dials :443 and :80, so they are distinct.
    let https = upstream_with_nodes(
        "  - host: example.com\n  - host: example.com\n    port: 80\n",
        "https",
    );
    assert!(
        https.validate().is_ok(),
        "explicit :80 must not collide with the https default :443"
    );

    let grpcs = upstream_with_nodes(
        "  - host: example.com\n  - host: example.com\n    port: 443\n",
        "grpcs",
    );
    assert!(
        grpcs.validate().is_err(),
        "omitted port must collide with explicit :443 over grpcs"
    );
}

#[test]
fn upstream_duplicate_check_ignores_disabled_nodes() {
    let with_disabled = upstream_with_nodes(
        "  - host: example.com\n    port: 80\n  - host: example.com\n    port: 80\n    weight: 0\n",
        "http",
    );
    assert!(
        with_disabled.validate().is_ok(),
        "a weight 0 node never becomes a backend, so it cannot collide"
    );
}

#[test]
fn upstream_nested_nodes_validation_reports_invalid_host_without_panicking() {
    // `#[validate(nested)]` wraps the manual `Nodes::validate` errors; the
    // merged path must surface the specific error instead of panicking on
    // duplicate field entries.
    let up = upstream_with_nodes(
        "  - host: 'not a host'\n    port: 80\n  - host: 'also bad'\n    port: 80\n",
        "http",
    );
    let err = up
        .validate()
        .expect_err("invalid node hosts must fail upstream validation");
    assert!(
        err.to_string().contains("invalid_host"),
        "nested error must name the real cause: {err}"
    );
}

#[test]
fn upstream_rejects_explicit_zero_port_in_list_form() {
    // An explicit `port: 0` must be a parse error (like `"host:0"` in the
    // map form), never a silent remap to the scheme default.
    let yaml = "id: u1\nscheme: http\nnodes:\n  - host: example.com\n    port: 0\n";
    let err = serde_yml::from_str::<Upstream>(yaml).expect_err("explicit port 0 must not parse");
    assert!(
        err.to_string().contains("1..=65535"),
        "parse error must explain the port rule: {err}"
    );
}
