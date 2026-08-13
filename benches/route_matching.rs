use criterion::{black_box, criterion_group, criterion_main, Criterion};
use matchit::Router;

fn build_router() -> Router<&'static str> {
    let mut router = Router::new();
    router.insert("/health", "health").unwrap();
    router.insert("/users/{id}", "user").unwrap();
    router.insert("/assets/{*path}", "assets").unwrap();
    router
}

fn route_matching(c: &mut Criterion) {
    let router = build_router();
    c.bench_function("route_matching/static", |b| {
        b.iter(|| black_box(router.at(black_box("/health")).unwrap().value))
    });
    c.bench_function("route_matching/parameter", |b| {
        b.iter(|| black_box(router.at(black_box("/users/12345")).unwrap().value))
    });
    c.bench_function("route_matching/catch_all", |b| {
        b.iter(|| {
            black_box(
                router
                    .at(black_box("/assets/css/application.css"))
                    .unwrap()
                    .value,
            )
        })
    });
}

criterion_group!(benches, route_matching);
criterion_main!(benches);
