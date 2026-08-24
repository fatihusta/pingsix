//! Shared mock-IO machinery for unit tests, integration tests, and benches.
//!
//! Enabled by `cfg(test)` inside the crate, or by the `test-utils` feature
//! when linked from `tests/` / `benches/` (those targets link the library
//! without `cfg(test)`). Kept out of production builds: the feature is off by
//! default.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use pingora_core::protocols::raw_connect::ProxyDigest;
use pingora_core::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType, IO,
};
use pingora_proxy::Session;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// In-memory downstream stream implementing the full pingora `IO` trait set.
///
/// Reads yield canned bytes once, then EOF; writes are captured into a
/// shared buffer that tests can inspect after the fact. `poll_flush` and
/// `poll_shutdown` succeed immediately, and all digest/peek/SSL stubs return
/// empty defaults.
///
/// `MockStream::default()` (empty read buffer, immediate EOF, writes still
/// captured) covers the "just need a session shell" cases.
#[derive(Debug, Default)]
pub struct MockStream {
    to_read: Vec<u8>,
    read_offset: usize,
    written: Arc<Mutex<Vec<u8>>>,
}

impl MockStream {
    /// Empty stream: reads return EOF immediately, writes are captured.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stream that yields `bytes`, then EOF.
    pub fn with_bytes(bytes: &[u8]) -> Self {
        Self {
            to_read: bytes.to_vec(),
            ..Self::default()
        }
    }

    /// Stream that yields `wire` (raw HTTP bytes as text), then EOF.
    pub fn with_request(wire: &str) -> Self {
        Self::with_bytes(wire.as_bytes())
    }

    /// Stream that yields `GET <path> HTTP/1.1` with the given headers.
    pub fn http_get(path: &str, headers: &[(&str, &str)]) -> Self {
        Self::with_request(&http_get_wire(path, headers))
    }

    /// Handle to the buffer capturing everything the peer wrote.
    pub fn written(&self) -> Arc<Mutex<Vec<u8>>> {
        self.written.clone()
    }
}

impl AsyncRead for MockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_offset >= self.to_read.len() {
            // EOF
            return Poll::Ready(Ok(()));
        }
        let remaining = &self.to_read[self.read_offset..];
        let n = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..n]);
        self.read_offset += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.written.lock().unwrap().extend_from_slice(buf);
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

/// Render `GET <path> HTTP/1.1` wire bytes with the given headers.
pub fn http_get_wire(path: &str, headers: &[(&str, &str)]) -> String {
    let mut wire = format!("GET {path} HTTP/1.1\r\n");
    for (name, value) in headers {
        wire.push_str(name);
        wire.push(':');
        wire.push(' ');
        wire.push_str(value);
        wire.push_str("\r\n");
    }
    wire.push_str("\r\n");
    wire
}

/// Build a session whose downstream yields `request` (raw HTTP/1.1 bytes) and
/// whose writes are captured into the returned buffer. The request is parsed
/// before the session is handed back.
pub async fn session_for(request: &[u8]) -> (Session, Arc<Mutex<Vec<u8>>>) {
    let stream = MockStream::with_bytes(request);
    let written = stream.written();
    let mut session = Session::new_h1(Box::new(stream) as Box<dyn IO>);
    session
        .downstream_session
        .read_request()
        .await
        .expect("canned request parses");
    (session, written)
}

/// Build a session whose downstream yields `wire` and whose writes are
/// silently discarded. The request is parsed before the session is handed
/// back.
pub async fn session_from_request(wire: &str) -> Session {
    session_for(wire.as_bytes()).await.0
}

/// Session over an empty stream: enough `Session::new_h1` plumbing to pass a
/// `&mut Session` through phase traversal without reading a request.
pub fn noop_session() -> Session {
    Session::new_h1(Box::new(MockStream::new()) as Box<dyn IO>)
}

/// Run one plugin's `request_filter` the way the compiled pipeline does (T10):
/// a returned `FilterVerdict::Reject` is written through the shared
/// exit-response helper exactly once (exit-transformer rules on
/// `ctx.pipeline` apply), then the request reports short-circuited.
///
/// Single-plugin wire-format tests use this instead of calling
/// `request_filter` directly: plugins return rejection values and never write
/// to the session themselves (multi-plugin composition is exercised through
/// `crate::core::CompiledPluginPipeline` instead).
pub async fn run_request_filter(
    plugin: &dyn crate::core::ProxyPlugin,
    session: &mut Session,
    ctx: &mut crate::core::ProxyContext,
) -> pingora_error::Result<bool> {
    match plugin.request_filter(session, ctx).await? {
        crate::core::FilterVerdict::Continue => Ok(false),
        crate::core::FilterVerdict::Reject(rejection) => {
            crate::utils::response::send_rejection(session, &rejection, ctx).await?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_for_parses_request_and_captures_writes() {
        let (session, written) = session_for(b"GET /x HTTP/1.1\r\nHost: e.com\r\n\r\n").await;
        assert_eq!(session.req_header().uri.path(), "/x");

        let mut stream = MockStream::new();
        use tokio::io::AsyncWriteExt;
        AsyncWriteExt::write_all(&mut stream, b"hello")
            .await
            .unwrap();
        AsyncWriteExt::flush(&mut stream).await.unwrap();
        Shutdown::shutdown(&mut stream).await;
        assert_eq!(*stream.written().lock().unwrap(), b"hello");
        assert!(written.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn http_get_builds_wire_with_headers() {
        let mut session = {
            let stream = MockStream::http_get("/p", &[("x-a", "b")]);
            let mut session = Session::new_h1(Box::new(stream) as Box<dyn IO>);
            session
                .downstream_session
                .read_request()
                .await
                .expect("canned request parses");
            session
        };
        let headers = session.req_header_mut();
        assert_eq!(headers.uri.path(), "/p");
        assert_eq!(headers.headers.get("x-a").unwrap(), "b");
    }
}
