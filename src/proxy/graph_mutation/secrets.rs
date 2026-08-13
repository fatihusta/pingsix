//! Secret redaction, restoration, and storage encryption helpers.

use crate::{
    config,
    core::{ProxyError, ProxyResult},
    utils::encryption::{KeyringService, SecretOp},
};

use super::store::ResourceKind;

const REDACTED_SENTINEL: &str = "***";

pub fn redact(kind: ResourceKind, value: &mut serde_json::Value, keyring: &KeyringService) {
    config::transform_resource_secrets(keyring, kind.as_str(), value, SecretOp::Redact)
        .expect("redaction performs no fallible crypto");
}

/// Does any string leaf equal the redaction sentinel? Used to skip the extra
/// store read on the common PUT path where the client sends real values.
pub(crate) fn contains_redaction_sentinel(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => s == REDACTED_SENTINEL,
        serde_json::Value::Array(items) => items.iter().any(contains_redaction_sentinel),
        serde_json::Value::Object(map) => map.values().any(contains_redaction_sentinel),
        _ => false,
    }
}

/// Restore secrets the client left redacted (`"***"`) from the stored resource,
/// so a GET/LIST → edit → PUT round-trip preserves untouched secrets.
///
/// Restoration is scoped to true secret leaves: redacting a copy of the stored
/// (decrypted) resource yields exactly the secret paths, and only there is an
/// incoming sentinel swapped for the stored plaintext. A client rotating a
/// secret sends its new value (not the sentinel), which is left untouched.
pub fn restore_redacted_secrets(
    kind: ResourceKind,
    incoming: &mut serde_json::Value,
    existing_plaintext: &serde_json::Value,
    keyring: &KeyringService,
) {
    let mut secret_map = existing_plaintext.clone();
    redact(kind, &mut secret_map, keyring);
    restore_walk(incoming, existing_plaintext, &secret_map);
}

/// Walk driven by `secret_map` (the redacted stored resource): its sentinel
/// leaves mark secret paths. Where `incoming` still holds the sentinel at such
/// a path, replace it with the stored plaintext at the same path.
fn restore_walk(
    incoming: &mut serde_json::Value,
    plaintext: &serde_json::Value,
    secret_map: &serde_json::Value,
) {
    match secret_map {
        serde_json::Value::String(s)
            if s == REDACTED_SENTINEL && incoming.as_str() == Some(REDACTED_SENTINEL) =>
        {
            *incoming = plaintext.clone();
        }
        serde_json::Value::Object(map) => {
            let (Some(inc), Some(pt)) = (incoming.as_object_mut(), plaintext.as_object()) else {
                return;
            };
            for (key, sub) in map {
                if let (Some(iv), Some(pv)) = (inc.get_mut(key), pt.get(key)) {
                    restore_walk(iv, pv, sub);
                }
            }
        }
        serde_json::Value::Array(items) => {
            let (Some(inc), Some(pt)) = (incoming.as_array_mut(), plaintext.as_array()) else {
                return;
            };
            for (i, sub) in items.iter().enumerate() {
                if let (Some(iv), Some(pv)) = (inc.get_mut(i), pt.get(i)) {
                    restore_walk(iv, pv, sub);
                }
            }
        }
        _ => {}
    }
}

/// Compact a validated resource to storage bytes, encrypting sensitive fields
/// first when data encryption is enabled. No-op when encryption is disabled.
pub(crate) fn encrypt_for_storage(
    kind: ResourceKind,
    value: &mut serde_json::Value,
    keyring: &KeyringService,
) -> ProxyResult<Vec<u8>> {
    if keyring.is_enabled() {
        config::transform_resource_secrets(keyring, kind.as_str(), value, SecretOp::Encrypt)?;
    }
    serde_json::to_vec(value)
        .map_err(|e| ProxyError::serialization_error("Failed to serialize resource for storage", e))
}

/// Decrypt a resource's secret fields for the read API (GET/LIST). Fail-closed:
/// an undecryptable value surfaces an error rather than leaking ciphertext.
pub(crate) fn decrypt_for_read(
    kind: ResourceKind,
    value: &mut serde_json::Value,
    keyring: &KeyringService,
) -> ProxyResult<()> {
    if keyring.is_enabled() {
        config::transform_resource_secrets(keyring, kind.as_str(), value, SecretOp::Decrypt)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::encryption::KeyringService;

    // ---- Moved from admin: secret helper semantics ----

    #[test]
    fn redact_ssl_key() {
        let mut input = serde_json::json!({
            "cert": "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
            "key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
        });
        redact(ResourceKind::Ssl, &mut input, &KeyringService::disabled());
        assert_eq!(
            input["cert"],
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
        );
        assert_eq!(input["key"], "***");
    }

    #[test]
    fn redact_jwt_secret() {
        let mut input = serde_json::json!({ "plugins": { "jwt-auth": { "secret": "abc" } } });
        redact(ResourceKind::Route, &mut input, &KeyringService::disabled());
        assert_eq!(input["plugins"]["jwt-auth"]["secret"], "***");
    }

    #[test]
    fn redact_basic_auth_password() {
        let mut input = serde_json::json!({
            "plugins": { "basic-auth": { "username": "u", "password": "p" } },
        });
        redact(ResourceKind::Route, &mut input, &KeyringService::disabled());
        assert_eq!(input["plugins"]["basic-auth"]["username"], "u");
        assert_eq!(input["plugins"]["basic-auth"]["password"], "***");
    }

    #[test]
    fn redact_key_auth_keys() {
        let mut input = serde_json::json!({
            "plugins": { "key-auth": { "key": "k0", "keys": ["k1", "k2"] } },
        });
        redact(ResourceKind::Route, &mut input, &KeyringService::disabled());
        assert_eq!(input["plugins"]["key-auth"]["key"], "***");
        assert_eq!(
            input["plugins"]["key-auth"]["keys"],
            serde_json::json!(["***", "***"])
        );
    }

    #[test]
    fn redact_csrf_key() {
        let mut input = serde_json::json!({ "plugins": { "csrf": { "key": "secret-csrf" } } });
        redact(
            ResourceKind::GlobalRule,
            &mut input,
            &KeyringService::disabled(),
        );
        assert_eq!(input["plugins"]["csrf"]["key"], "***");
    }

    #[test]
    fn redact_nested_upstream_tls() {
        let mut input = serde_json::json!({
            "upstream": {
                "tls": {
                    "client_key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
                    "client_cert": "cert-data",
                }
            }
        });
        redact(ResourceKind::Route, &mut input, &KeyringService::disabled());
        assert_eq!(input["upstream"]["tls"]["client_key"], "***");
        assert_eq!(input["upstream"]["tls"]["client_cert"], "cert-data");
        let mut service = serde_json::json!({
            "upstream": { "tls": { "client_key": "k", "client_cert": "c" } }
        });
        redact(
            ResourceKind::Service,
            &mut service,
            &KeyringService::disabled(),
        );
        assert_eq!(service["upstream"]["tls"]["client_key"], "***");
    }

    #[test]
    fn redact_preserves_upstream_hash_on_key() {
        let mut input = serde_json::json!({ "key": "uri", "type": "roundrobin" });
        redact(
            ResourceKind::Upstream,
            &mut input,
            &KeyringService::disabled(),
        );
        assert_eq!(input["key"], "uri");
        assert_eq!(input["type"], "roundrobin");
    }

    #[test]
    fn redact_redacts_upstream_tls_client_key() {
        let mut input = serde_json::json!({
            "key": "uri",
            "type": "roundrobin",
            "tls": {
                "client_key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
                "client_cert": "cert-data",
            },
        });
        redact(
            ResourceKind::Upstream,
            &mut input,
            &KeyringService::disabled(),
        );
        assert_eq!(input["key"], "uri");
        assert_eq!(input["tls"]["client_key"], "***");
        assert_eq!(input["tls"]["client_cert"], "cert-data");
    }

    #[test]
    fn redact_non_sensitive_unchanged() {
        let mut input = serde_json::json!({
            "id": "r1",
            "uri": "/x",
            "methods": ["GET"],
            "upstream_id": "u1",
        });
        let original = input.clone();
        redact(ResourceKind::Route, &mut input, &KeyringService::disabled());
        assert_eq!(input, original);
    }

    #[test]
    fn restore_keeps_masked_secret_and_accepts_rotation() {
        let existing = serde_json::json!({
            "id": "s1",
            "cert": "cert-pem",
            "key": "-----BEGIN PRIVATE KEY-----\nreal\n-----END PRIVATE KEY-----",
        });
        let mut resave = serde_json::json!({
            "id": "s1",
            "cert": "cert-pem",
            "key": "***",
        });
        restore_redacted_secrets(
            ResourceKind::Ssl,
            &mut resave,
            &existing,
            &KeyringService::disabled(),
        );
        assert_eq!(resave["key"], existing["key"]);

        let mut rotate = serde_json::json!({
            "id": "s1",
            "cert": "cert-pem",
            "key": "-----BEGIN PRIVATE KEY-----\nnew\n-----END PRIVATE KEY-----",
        });
        restore_redacted_secrets(
            ResourceKind::Ssl,
            &mut rotate,
            &existing,
            &KeyringService::disabled(),
        );
        assert_eq!(
            rotate["key"],
            "-----BEGIN PRIVATE KEY-----\nnew\n-----END PRIVATE KEY-----"
        );
    }

    #[test]
    fn restore_walks_plugins_nested_upstream_and_arrays() {
        let existing = serde_json::json!({
            "uri": "/",
            "plugins": {
                "basic-auth": { "username": "demo", "password": "s3cret" },
                "key-auth": { "key": "k0", "keys": ["k1", "k2"] },
            },
            "upstream": {
                "nodes": { "127.0.0.1:443": 1 },
                "tls": {
                    "client_cert": "cert-pem",
                    "client_key": "-----BEGIN PRIVATE KEY-----\nreal\n-----END PRIVATE KEY-----",
                },
            },
        });
        let mut resave = serde_json::json!({
            "uri": "/",
            "plugins": {
                "basic-auth": { "username": "changed", "password": "***" },
                "key-auth": { "key": "***", "keys": ["***", "***"] },
            },
            "upstream": {
                "nodes": { "127.0.0.1:443": 1 },
                "tls": { "client_cert": "cert-pem", "client_key": "***" },
            },
        });
        restore_redacted_secrets(
            ResourceKind::Route,
            &mut resave,
            &existing,
            &KeyringService::disabled(),
        );
        assert_eq!(resave["plugins"]["basic-auth"]["username"], "changed");
        assert_eq!(resave["plugins"]["basic-auth"]["password"], "s3cret");
        assert_eq!(resave["plugins"]["key-auth"]["key"], "k0");
        assert_eq!(
            resave["plugins"]["key-auth"]["keys"],
            serde_json::json!(["k1", "k2"])
        );
        assert_eq!(
            resave["upstream"]["tls"]["client_key"],
            existing["upstream"]["tls"]["client_key"]
        );
        assert!(!contains_redaction_sentinel(&resave));
    }

    #[test]
    fn restore_ignores_non_secret_sentinel() {
        let existing = serde_json::json!({ "uri": "/old", "id": "r1" });
        let mut resave = serde_json::json!({ "uri": "***", "id": "r1" });
        restore_redacted_secrets(
            ResourceKind::Route,
            &mut resave,
            &existing,
            &KeyringService::disabled(),
        );
        assert_eq!(resave["uri"], "***");
    }

    #[test]
    fn encrypt_for_storage_noop_when_disabled() {
        let mut input = serde_json::json!({
            "id": "1",
            "cert": "c",
            "key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
            "snis": ["example.com"],
        });
        let out = encrypt_for_storage(ResourceKind::Ssl, &mut input, &KeyringService::disabled())
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["key"], input["key"]);
        // Output is compacted even when encryption is disabled.
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains('\n'));
    }

    #[test]
    fn encrypt_for_storage_leaves_plugin_and_inline_upstream_secrets_when_disabled() {
        let mut input = serde_json::json!({
            "id": "1",
            "uri": "/",
            "plugins": {
                "basic-auth": { "username": "demo", "password": "s3cret" }
            },
            "upstream": {
                "nodes": { "127.0.0.1:443": 1 },
                "tls": { "client_cert": "cert", "client_key": "key-material" }
            }
        });
        let out = encrypt_for_storage(ResourceKind::Route, &mut input, &KeyringService::disabled())
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["plugins"]["basic-auth"]["password"], "s3cret");
        assert_eq!(parsed["upstream"]["tls"]["client_key"], "key-material");
    }
}
