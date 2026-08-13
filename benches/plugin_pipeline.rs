//! Dispatch-gate benchmark for the plugin executor.
//!
//! The static candidates deliberately retain `#[async_trait]`: built-in hooks
//! are async-trait methods today, so this measures the dispatch change that a
//! `CompiledPlugin::Builtin` enum could actually make, rather than comparing it
//! with a different (unboxed) hook API.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use futures::executor::block_on;
use pingora_core::protocols::{
    raw_connect::ProxyDigest, GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown,
    SocketDigest, Ssl, TimingDigest, UniqueID, UniqueIDType, IO,
};
use pingora_error::Result;
use pingora_proxy::Session;
use pingsix::core::{PluginPhases, ProxyContext, ProxyPlugin, ProxyPluginExecutor};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct HotPhasePlugin {
    name: &'static str,
    priority: i32,
}

#[async_trait]
impl ProxyPlugin for HotPhasePlugin {
    fn name(&self) -> &str {
        self.name
    }

    fn priority(&self) -> i32 {
        self.priority
    }

    fn phases(&self) -> PluginPhases {
        PluginPhases::REQUEST
    }

    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<bool> {
        Ok(false)
    }
}

/// Models the proposed builtin arm after construction has selected a concrete
/// plugin. Its hook calls remain `async_trait` calls, exactly like real builtin
/// implementations; only the plugin-object vtable lookup is removed.
enum BenchmarkBuiltin {
    Hot(HotPhasePlugin),
}

impl BenchmarkBuiltin {
    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        match self {
            Self::Hot(plugin) => plugin.request_filter(session, ctx).await,
        }
    }
}

fn dynamic_plugins(count: usize) -> Vec<Arc<dyn ProxyPlugin>> {
    (0..count)
        .map(|index| {
            Arc::new(HotPhasePlugin {
                name: if index % 2 == 0 { "request-id" } else { "cors" },
                priority: 10_000 - index as i32,
            }) as Arc<dyn ProxyPlugin>
        })
        .collect()
}

fn static_plugins(count: usize) -> Vec<BenchmarkBuiltin> {
    (0..count)
        .map(|index| {
            BenchmarkBuiltin::Hot(HotPhasePlugin {
                name: if index % 2 == 0 { "request-id" } else { "cors" },
                priority: 10_000 - index as i32,
            })
        })
        .collect()
}

/// Minimal initialized Pingora session for the no-op hook benchmark.
#[derive(Debug)]
struct BenchmarkStream;

impl AsyncRead for BenchmarkStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for BenchmarkStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[async_trait]
impl Shutdown for BenchmarkStream {
    async fn shutdown(&mut self) {}
}
impl UniqueID for BenchmarkStream {
    fn id(&self) -> UniqueIDType {
        0
    }
}
impl Ssl for BenchmarkStream {}
impl GetTimingDigest for BenchmarkStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        Vec::new()
    }
}
impl GetProxyDigest for BenchmarkStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        None
    }
}
impl GetSocketDigest for BenchmarkStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        None
    }
}
#[async_trait]
impl Peek for BenchmarkStream {}

fn benchmark_session() -> Session {
    Session::new_h1(Box::new(BenchmarkStream) as Box<dyn IO>)
}

fn bench_hot_request_phase(c: &mut Criterion, plugin_count: usize) {
    let dynamic = Arc::new(ProxyPluginExecutor::new(dynamic_plugins(plugin_count)));
    let static_plugins = static_plugins(plugin_count);
    let name = format!("plugin_pipeline/request_hot/{plugin_count}_plugins");
    let mut group = c.benchmark_group(name);

    group.bench_function("dynamic", |b| {
        b.iter_batched(
            benchmark_session,
            |mut session| {
                let mut ctx = ProxyContext::default();
                black_box(block_on(dynamic.request_filter(&mut session, &mut ctx)).unwrap())
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("builtin_enum", |b| {
        b.iter_batched(
            benchmark_session,
            |mut session| {
                let mut ctx = ProxyContext::default();
                black_box(block_on(async {
                    for plugin in &static_plugins {
                        if plugin.request_filter(&mut session, &mut ctx).await.unwrap() {
                            return true;
                        }
                    }
                    false
                }))
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn plugin_pipeline(c: &mut Criterion) {
    // Three and eight configured request-phase plugins represent common small
    // and moderately composed route pipelines.
    bench_hot_request_phase(c, 3);
    bench_hot_request_phase(c, 8);
}

criterion_group!(benches, plugin_pipeline);
criterion_main!(benches);
