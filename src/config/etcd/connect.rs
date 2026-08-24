//! etcd connection building: endpoint validation, auth/timeouts, and TLS
//! options. Separated so the TLS/options logic is unit-testable without a
//! live etcd endpoint.

use std::time::Duration;

use url::Url;

use etcd_client::{Client, ConnectOptions};

use crate::{
    config::{Etcd, EtcdTls},
    core::{ProxyError, ProxyResult},
};

pub(super) async fn create_client(cfg: &Etcd) -> ProxyResult<Client> {
    let options = build_connect_options(cfg)?;
    let endpoints = validate_etcd_endpoints(&cfg.host, cfg.tls.is_some())?;
    Client::connect(endpoints, Some(options))
        .await
        .map_err(|e| {
            ProxyError::etcd_error_with_cause(
                format!("Failed to connect to host '{:?}'", cfg.host),
                e,
            )
        })
}

/// Parse etcd endpoints and require an explicit scheme to agree with TLS.
/// Bare authorities infer the scheme from the TLS configuration; explicit URLs
/// are never rewritten, preventing an accidental HTTPS-to-HTTP downgrade.
pub(crate) fn validate_etcd_endpoints(hosts: &[String], use_tls: bool) -> ProxyResult<Vec<String>> {
    hosts
        .iter()
        .map(|host| {
            let endpoint = if host.contains("://") {
                host.clone()
            } else {
                format!("{}://{host}", if use_tls { "https" } else { "http" })
            };
            let parsed = Url::parse(&endpoint)
                .map_err(|_| ProxyError::validation_error("Invalid etcd endpoint"))?;
            let scheme_matches_tls = match parsed.scheme() {
                "http" => !use_tls,
                "https" => use_tls,
                _ => false,
            };
            if !scheme_matches_tls
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(ProxyError::validation_error("Invalid etcd endpoint"));
            }
            Ok(endpoint)
        })
        .collect()
}

/// Build etcd `ConnectOptions` from config (timeout, auth, TLS).
///
/// Separated from `create_client` so the TLS/options logic is unit-testable
/// without a live etcd endpoint. TLS is only attached when `etcd.tls` is set.
fn build_connect_options(cfg: &Etcd) -> ProxyResult<ConnectOptions> {
    let mut options = ConnectOptions::default();
    // Production-safe defaults when omitted from YAML.
    let timeout = cfg.timeout.unwrap_or(5);
    let connect_timeout = cfg.connect_timeout.unwrap_or(3);
    options = options.with_timeout(Duration::from_secs(timeout as _));
    options = options.with_connect_timeout(Duration::from_secs(connect_timeout as _));
    if let (Some(user), Some(password)) = (&cfg.user, &cfg.password) {
        options = options.with_user(user.clone(), password.clone());
    }
    if let Some(tls_cfg) = &cfg.tls {
        options = options.with_tls(build_tls_options(tls_cfg)?);
    }
    Ok(options)
}

/// Build tonic `ClientTlsConfig` from `EtcdTls` by reading the configured PEM
/// files. Used for both server certificate verification (CA) and mutual TLS
/// (client cert/key) when the latter are present.
fn build_tls_options(tls_cfg: &EtcdTls) -> ProxyResult<etcd_client::TlsOptions> {
    let ca_pem = read_pem(&tls_cfg.ca_cert, "CA cert")?;
    let mut tls =
        etcd_client::TlsOptions::new().ca_certificate(etcd_client::Certificate::from_pem(ca_pem));
    if let (Some(cert_path), Some(key_path)) = (&tls_cfg.client_cert, &tls_cfg.client_key) {
        let cert_pem = read_pem(cert_path, "client cert")?;
        let key_pem = read_pem(key_path, "client key")?;
        tls = tls.identity(etcd_client::Identity::from_pem(cert_pem, key_pem));
    }
    if let Some(domain) = &tls_cfg.domain {
        tls = tls.domain_name(domain);
    }
    Ok(tls)
}

/// Read a PEM file, mapping the IO error to an etcd error with a descriptive cause.
fn read_pem(path: &str, label: &str) -> ProxyResult<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        ProxyError::etcd_error_with_cause(format!("Failed to read etcd {label} '{path}'"), e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Etcd, EtcdTls};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Monotonic counter so each test gets a unique temp-file name.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Write `contents` to a unique temp file and return its path.
    /// Files are cleaned up via `TempFile`'s Drop.
    struct TempFile(std::path::PathBuf);

    impl TempFile {
        fn new(contents: &[u8], _ext: &str) -> Self {
            let id = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir()
                .join(format!("pingsix_etcd_tls_{}_{id}.pem", std::process::id(),));
            std::fs::write(&path, contents).expect("write temp file");
            TempFile(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().expect("utf8 temp path")
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    const CA_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
fake-ca
-----END CERTIFICATE-----\n";
    const CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
fake-cert
-----END CERTIFICATE-----\n";
    const KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
fake-key
-----END PRIVATE KEY-----\n";

    fn etcd_with_tls(tls: EtcdTls) -> Etcd {
        Etcd {
            host: vec!["127.0.0.1:2379".to_string()],
            prefix: "/pingsix".to_string(),
            timeout: None,
            connect_timeout: None,
            user: None,
            password: None,
            tls: Some(tls),
        }
    }

    #[test]
    fn endpoints_infer_scheme_only_for_bare_authorities() {
        assert_eq!(
            validate_etcd_endpoints(&["127.0.0.1:2379".into()], false).unwrap(),
            vec!["http://127.0.0.1:2379"]
        );
        assert_eq!(
            validate_etcd_endpoints(&["127.0.0.1:2379".into()], true).unwrap(),
            vec!["https://127.0.0.1:2379"]
        );
    }

    #[test]
    fn endpoints_reject_scheme_tls_mismatch_and_url_components() {
        assert!(validate_etcd_endpoints(&["https://etcd:2379".into()], false).is_err());
        assert!(validate_etcd_endpoints(&["http://etcd:2379".into()], true).is_err());
        for endpoint in [
            "ftp://etcd:2379",
            "http://user:secret@etcd:2379",
            "http://etcd:2379/path",
            "http://etcd:2379/?query",
            "http://etcd:2379/#fragment",
        ] {
            assert!(
                validate_etcd_endpoints(&[endpoint.into()], false).is_err(),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn build_tls_options_with_ca_only() {
        let ca = TempFile::new(CA_PEM, "pem");
        let tls = EtcdTls {
            ca_cert: ca.path().to_string(),
            client_cert: None,
            client_key: None,
            domain: None,
        };
        // TlsOptions internals are opaque; success means CA was parsed and config built.
        assert!(build_tls_options(&tls).is_ok());
    }

    #[test]
    fn build_tls_options_with_mtls() {
        let ca = TempFile::new(CA_PEM, "pem");
        let cert = TempFile::new(CERT_PEM, "pem");
        let key = TempFile::new(KEY_PEM, "pem");
        let tls = EtcdTls {
            ca_cert: ca.path().to_string(),
            client_cert: Some(cert.path().to_string()),
            client_key: Some(key.path().to_string()),
            domain: Some("etcd.example".to_string()),
        };
        assert!(build_tls_options(&tls).is_ok());
    }

    #[test]
    fn build_tls_options_missing_ca_file() {
        let tls = EtcdTls {
            ca_cert: "/nonexistent/path/ca.pem".to_string(),
            client_cert: None,
            client_key: None,
            domain: None,
        };
        assert!(build_tls_options(&tls).is_err());
    }

    #[test]
    fn build_tls_options_missing_client_cert_file() {
        let ca = TempFile::new(CA_PEM, "pem");
        // cert path missing while key is present — must error rather than silently skip mTLS.
        let key = TempFile::new(KEY_PEM, "pem");
        let tls = EtcdTls {
            ca_cert: ca.path().to_string(),
            client_cert: Some("/nonexistent/path/cert.pem".to_string()),
            client_key: Some(key.path().to_string()),
            domain: None,
        };
        assert!(build_tls_options(&tls).is_err());
    }

    #[test]
    fn create_client_no_tls_keeps_options_plain() {
        let cfg = Etcd {
            host: vec!["http://127.0.0.1:2379".to_string()],
            prefix: "/pingsix".to_string(),
            timeout: Some(5),
            connect_timeout: Some(2),
            user: Some("root".to_string()),
            password: Some("pw".to_string()),
            tls: None,
        };
        // No TLS configured: options must build without invoking any file reads.
        assert!(build_connect_options(&cfg).is_ok());
    }

    #[test]
    fn build_connect_options_with_tls_succeeds() {
        let ca = TempFile::new(CA_PEM, "pem");
        let tls = EtcdTls {
            ca_cert: ca.path().to_string(),
            client_cert: None,
            client_key: None,
            domain: Some("etcd.example".to_string()),
        };
        let cfg = etcd_with_tls(tls);
        assert!(build_connect_options(&cfg).is_ok());
    }
}
