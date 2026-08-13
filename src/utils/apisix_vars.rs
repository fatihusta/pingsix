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
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use pingora_core::protocols::raw_connect::ProxyDigest;
    use pingora_core::protocols::{
        GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
        TimingDigest, UniqueID, UniqueIDType, IO,
    };
    use pingora_proxy::Session;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    #[derive(Debug)]
    struct MockStream {
        data: Vec<u8>,
        pos: usize,
    }

    impl MockStream {
        fn with_request(path: &str, headers: &[(&str, &str)]) -> Self {
            let mut wire = format!("GET {path} HTTP/1.1\r\n");
            for (name, value) in headers {
                wire.push_str(name);
                wire.push(':');
                wire.push(' ');
                wire.push_str(value);
                wire.push_str("\r\n");
            }
            wire.push_str("\r\n");
            Self {
                data: wire.into_bytes(),
                pos: 0,
            }
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.pos >= self.data.len() {
                return Poll::Ready(Ok(()));
            }
            let remaining = &self.data[self.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[async_trait]
    impl Shutdown for MockStream {
        async fn shutdown(&mut self) {}
    }

    impl UniqueID for MockStream {
        fn id(&self) -> UniqueIDType {
            0
        }
    }

    impl Ssl for MockStream {}

    impl GetTimingDigest for MockStream {
        fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
            Vec::new()
        }
    }

    impl GetProxyDigest for MockStream {
        fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
            None
        }
    }

    impl GetSocketDigest for MockStream {
        fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
            None
        }
    }

    #[async_trait]
    impl Peek for MockStream {}

    async fn make_session(path: &str, headers: &[(&str, &str)]) -> Session {
        let stream: Box<dyn IO> = Box::new(MockStream::with_request(path, headers));
        let mut session = Session::new_h1(stream);
        session.as_downstream_mut().read_request().await.unwrap();
        session
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
