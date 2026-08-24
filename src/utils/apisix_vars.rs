use pingora_proxy::Session;

use crate::config::UpstreamHashOn;
use crate::utils::request::request_selector_key;

/// Evaluate APISIX-style `vars` conditions against the current request.
///
/// An empty `vars` slice matches every request. Each entry is
/// `[name, op, value, ...]`; entries with fewer than three elements are
/// skipped. Names prefixed with `http_` resolve via request headers; all
/// others use nginx-style variables. Only `==` and `!=` are supported.
pub fn match_apisix_vars(session: &mut Session, vars: &[Vec<String>]) -> bool {
    if vars.is_empty() {
        return true;
    }

    for v in vars {
        if v.len() < 3 {
            continue;
        }
        let var_name = &v[0];
        let op = &v[1];
        let val = &v[2];

        let actual_val = if let Some(header_name) = var_name.strip_prefix("http_") {
            request_selector_key(session, &UpstreamHashOn::HEAD, header_name)
        } else {
            request_selector_key(session, &UpstreamHashOn::VARS, var_name)
        };

        match op.as_str() {
            "==" => {
                if actual_val != *val {
                    return false;
                }
            }
            "!=" => {
                if actual_val == *val {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::utils::testing::{http_get_wire, session_from_request};

    use super::*;

    async fn make_session(path: &str, headers: &[(&str, &str)]) -> Session {
        session_from_request(&http_get_wire(path, headers)).await
    }

    #[tokio::test]
    async fn empty_vars_matches() {
        let mut session = make_session("/any", &[]).await;
        assert!(match_apisix_vars(&mut session, &[]));
    }

    #[tokio::test]
    async fn http_header_eq_hit_and_miss() {
        let mut session = make_session("/any", &[("x-user-type", "beta")]).await;
        let hit = vec![vec!["http_x-user-type".into(), "==".into(), "beta".into()]];
        assert!(match_apisix_vars(&mut session, &hit));

        let miss = vec![vec![
            "http_x-user-type".into(),
            "==".into(),
            "premium".into(),
        ]];
        assert!(!match_apisix_vars(&mut session, &miss));
    }

    #[tokio::test]
    async fn unknown_op_fails() {
        let mut session = make_session("/any", &[("x-user-type", "beta")]).await;
        let vars = vec![vec!["http_x-user-type".into(), "~=".into(), "beta".into()]];
        assert!(!match_apisix_vars(&mut session, &vars));
    }

    #[tokio::test]
    async fn short_entries_are_skipped_without_failing_later_conditions() {
        let mut session = make_session("/target", &[]).await;
        let vars = vec![
            vec!["only".into(), "one".into()],
            vec!["uri".into(), "==".into(), "/target".into()],
        ];
        assert!(match_apisix_vars(&mut session, &vars));
    }
}
