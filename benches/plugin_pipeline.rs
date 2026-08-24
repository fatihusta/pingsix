//! Dispatch-gate benchmark for the plugin executor.
//!
//! The static candidates deliberately retain `#[async_trait]`: built-in hooks
//! are async-trait methods today, so this measures the dispatch change that a
//! `CompiledPlugin::Builtin` enum could actually make, rather than comparing it
//! with a different (unboxed) hook API.

use std::sync::Arc;

use async_trait::async_trait;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use futures::executor::block_on;
use pingora_error::Result;
use pingora_proxy::Session;
use pingsix::core::{
    FilterVerdict, PluginEntry, PluginPhases, ProxyContext, ProxyPlugin, ProxyPluginExecutor,
};
use pingsix::utils::testing::noop_session;

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

    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        Ok(FilterVerdict::Continue)
    }
}

/// Models the proposed builtin arm after construction has selected a concrete
/// plugin. Its hook calls remain `async_trait` calls, exactly like real builtin
/// implementations; only the plugin-object vtable lookup is removed.
enum BenchmarkBuiltin {
    Hot(HotPhasePlugin),
}

impl BenchmarkBuiltin {
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        match self {
            Self::Hot(plugin) => plugin.request_filter(session, ctx).await,
        }
    }
}

fn dynamic_plugins(count: usize) -> Vec<PluginEntry> {
    (0..count)
        .map(|index| {
            PluginEntry::new(
                Arc::new(HotPhasePlugin {
                    name: if index % 2 == 0 { "request-id" } else { "cors" },
                    priority: 10_000 - index as i32,
                }),
                PluginPhases::REQUEST,
            )
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

fn benchmark_session() -> Session {
    noop_session()
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
                        if matches!(
                            plugin.request_filter(&mut session, &mut ctx).await.unwrap(),
                            FilterVerdict::Reject(_)
                        ) {
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
