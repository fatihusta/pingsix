# Plan — Architecture Deepening (all 10 review candidates)

Follows review: `docs/architecture-reviews/2026-08-24-whole-codebase.md`

## Goal

Land all 10 review candidates in risk-ascending waves: internal cleanups first, ending with the single breaking plugin-contract change (FilterVerdict + phases-in-PLUGIN_META).

## Settled decisions (from grilling)

- **C1 contract**: full `FilterVerdict` breaking change; bypass becomes unrepresentable.
- **C1 scope**: PluginPhases dual-bookkeeping fix rides the same break (phases move into `PLUGIN_META`; `fn phases()` and the mirror test table are deleted).
- **C7**: option (a) — narrow `RouteContext`/`UpstreamSelector`; no layer restructure.
- **Sequencing**: risk-ascending; contract break last.

## Explicit assumptions

- Wave boundaries are also commit/PR boundaries; each wave lands green (`make checkfmt && make clippy && make test`) before the next starts.
- No user-facing behavior changes except: uniform exit-transformer application (C1) and redirect template variables gaining `arg_*`/`http_*`/fixed host precedence (C3).
- Benchmarks (`benches/`) must still compile and run after each wave.

## Non-goals

- Option (b) layer restructure (moving `ProxyContext`/pipeline out of `core`).
- Redis policies for limiters; typed ctx slots; `RequestView` extraction.
- New user-facing features.

## Architecture (fit with existing layers)

- Plugin-module deepening follows the established `compression.rs` / `plugins/config.rs` model: shared mechanism in one module, plugins contribute schema + pure transition + hook wiring.
- Control-plane consolidation preserves the single-writer funnel (`ConfigurationGraph` → worker → `RuntimeStore::publish`) and the `GraphStore` seam; no change to ownership.
- The C1 contract extends the existing `CompiledPluginPipeline` short-circuit point (pipeline.rs:558) — one writer for all rejections, via `send_exit_response`.

## Validation

- Focused per task: `cargo test <name>` (+ `--locked --all-features` as in Makefile).
- Wave gate: `make checkfmt && make clippy && make test`.
- External etcd tests: run the non-etcd subset in CI; etcd-dependent integration tests are unchanged in shape.

## Dependency table

| Task | Slice | Type | Blocked by | Parallelizable with |
|---|---|---|---|---|
| T1 | C5 admin seam collapse | AFK | — | T2, T3, T4 |
| T2 | C10 test-support consolidation | AFK | — | T1, T3, T4 |
| T3 | C6 fingerprint consolidation | AFK | — | T1, T2, T4 |
| T4 | C4 etcd.rs split + test-double relocation | AFK | — | T1, T2, T3 |
| T5 | C3 template/var unification | AFK | T2 | T6, T7 |
| T6 | C2 `plugins::limiting` module | AFK | T2 | T5, T7 |
| T7 | C8 plan/compile consolidation + fixtures | AFK | — | T5, T6 |
| T8 | C9 Config vec-layer deletion | AFK | T7, T4 | T9 |
| T9 | C7a narrow RouteContext/UpstreamSelector | AFK | T3 | T8 |
| T10 | C1 core contract: FilterVerdict + phases-in-PLUGIN_META | HITL | T2, T5, T6, T9 | — |
| T11a | C1 migrate auth/security plugins | AFK | T10 | T11b, T11c |
| T11b | C1 migrate traffic plugins | AFK | T10 | T11a, T11c |
| T11c | C1 migrate observability/AI/misc plugins | AFK | T10 | T11a, T11b |
| T12 | C1 integration polish + minor-items batch | HITL | T11a-c | — |

Coverage: candidates 1–10 all mapped (C1→T10–T12; C2→T6; C3→T5; C4→T4; C5→T1; C6→T3; C7→T9; C8→T7; C9→T8; C10→T2). Minor "also noted" items folded into T12. No dependency cycles; parallel tasks share no files (verified below per task).

---

### Task T1: Collapse the admin phantom generic seam (C5)

Type: AFK · Blocked by: none · Areas: admin

Goal: replace `trait AdminResource` + `admin_handler!` macro + `PhantomData` structs with value-parameterized handlers over `ResourceKind`.

Acceptance criteria:
- `src/admin/mod.rs` contains no `PhantomData`, no `admin_handler!` macro, no `AdminResource` trait.
- All existing admin routes (`/apisix/admin/{routes,upstreams,services,global_rules,ssls}/{id}`) behave identically; admin integration tests pass unchanged.

Files: Modify `src/admin/mod.rs` only.

Contracts: `struct ResourceHandler { kind: ResourceKind }` (and Get/Delete/List equivalents) constructed once per kind at registration.

Tests: existing admin tests (integration `tests/`) are the spec — no new tests needed; none deleted.

Validation: `cargo test admin` + wave gate.

---

### Task T2: Consolidate test-support mock IO (C10)

Type: AFK · Blocked by: none · Areas: plugins, core/plugin, utils, tests/

Goal: one shared mock `IO` implementation replaces the ~6 copies (tests/common:838-940, pipeline.rs:681-743, apisix_vars.rs:44-140, file_logger, ai_proxy, benches).

Acceptance criteria:
- A single mock stream + canned-request session builder exists; all six sites use it.
- No test assertions change observably (same behaviors verified); `cargo test` and `cargo bench --no-run` green.

Files: Create `src/utils/testing.rs`; Modify `src/utils/mod.rs`, `src/utils/apisix_vars.rs` (test mod), `src/core/plugin/pipeline.rs` (test mod), `src/plugins/file_logger.rs` (test mod), `src/plugins/ai_proxy/mod.rs` (test mod), `tests/common/mod.rs`, `benches/plugin_pipeline.rs`, `Cargo.toml`.

Contracts:
- Gate: `#[cfg(any(test, feature = "test-utils"))] pub mod testing;` with `test-utils = []` feature; self dev-dependency `pingsix = { path = ".", features = ["test-utils"] }` so `tests/` and `benches/` can link it. If the self-dev-dep proves circular in practice, fall back to: unit tests use the cfg(test) module, `tests/common` keeps the integration copy (record the deviation in the plan).
- Builder shape: `testing::mock_session(request_line_and_headers: &str) -> Session` and `testing::capture_stream() -> (stream, ResponseCapture)`.

Tests: existing suites are the spec.

Validation: `make test` + `cargo bench --no-run`.

Risk controls (moderate): the module is test-only; production binary size unchanged (feature off by default). Rollback = revert.

---

### Task T3: Consolidate fingerprint field-lists (C6)

Type: AFK · Blocked by: none · Areas: config, proxy

Goal: "which fields matter" declared once, next to the config types; the three hand-rolled `DefaultHasher` walks become calls to named profiles.

Acceptance criteria:
- `src/config/resources.rs` defines the fingerprint mechanism (serde-serialized canonical form + named exclusion profiles, e.g. `HealthCheck`, `CacheOrigin`, `RouteCacheNamespace`).
- Call sites (`load_balancer.rs:203`, `runtime.rs:99`, `route.rs:33,49`) name a profile instead of walking fields.
- Existing fingerprint behavior preserved: HC still excludes weights/retries; scheme-default port canonicalization still applied (encode exclusions/canonicalization in the profile or keep as documented pre-pass).

Files: Modify `src/config/resources.rs`, `src/proxy/upstream/load_balancer.rs`, `src/proxy/runtime.rs`, `src/proxy/route.rs`.

Contracts: `config::Upstream::fingerprint(profile: UpstreamFingerprintProfile) -> u64`; `config::Route` equivalent for the cache-namespace profile. Profiles are exhaustive enums — adding a profile is additive; adding a config field forces a per-profile decision at the definition site (that's the win).

Tests: port the existing per-function tests (load_balancer.rs:877/900/955 and route/runtime equivalents) to assert profile behavior at the new interface: stability across node order, port canonicalization, weight/retries exclusion, and **a new drift test** (adding every current field to the profile expectation).

Validation: focused `cargo test fingerprint` + wave gate.

---

### Task T4: Split `config/etcd.rs`; relocate `InMemoryGraphStore` (C4)

Type: AFK · Blocked by: none · Areas: config, proxy/graph_mutation

Goal: `config/etcd/{mod,sync,store,keys,tls}.rs`; `InMemoryGraphStore` lives next to the `GraphStore` trait as test support. Behavior unchanged.

Acceptance criteria:
- `src/config/etcd.rs` no longer exists as a 1377-line file; `config::etcd::EtcdConfigSync` public paths preserved via re-exports (no caller churn).
- `graph_mutation` tests and harnesses import the in-memory store from `graph_mutation::store` (or its `testing` submodule), no longer from `config::etcd`.

Files: Split `src/config/etcd.rs` into `src/config/etcd/{mod,sync,store,keys,tls}.rs`; Modify `src/proxy/graph_mutation/store.rs` (add in-memory adapter behind cfg-gate used by tests), `src/proxy/graph_mutation/tests/*`, `tests/common/mod.rs` (import path only).

Contracts: none downstream (re-export shim preserves all public paths).

Tests: existing etcd/graph suites unchanged (pure move).

Validation: `cargo test graph_mutation` + non-etcd suite + wave gate.

---

### Task T5: One template parser + variable registry (C3)

Type: AFK · Blocked by: T2 · Areas: utils, plugins

Goal: `utils/request.rs` owns the single `$var`/`${var}` parser (with `\$` escape option); a variable registry keyed by lifecycle phase serves redirect and file_logger resolvers.

Acceptance criteria:
- `redirect.rs::render_redirect_template` is deleted; redirect uses the shared parser with escape enabled and the same `resolve_var` semantics as other plugins (`$remote_addr`, `arg_*`, `http_*` now work in redirect templates; host precedence matches `get_request_host`). **Documented behavior change** in USER_GUIDE redirect section.
- `file_logger` parses via the shared parser (regex parser deleted); log-phase-only vars (`status`, `body_bytes_sent`, `request_time`) come from a log-phase resolver passed to the same parser; the hand-maintained size-estimate table is deleted or derived.
- `${name}` now renders in log formats (was impossible) — note in USER_GUIDE.

Files: Modify `src/utils/request.rs`, `src/plugins/redirect.rs`, `src/plugins/file_logger.rs`, `USER_GUIDE.md`.

Contracts: `render_template(template, opts, resolve: FnMut(&str)->String)` where `opts` includes `escape_dollar: bool`; resolve closures are phase-scoped.

Tests: redirect's existing template tests pass against the new resolver (adjust only tests that pinned the old divergent behavior); new tests for `$remote_addr`/`arg_*` in redirect templates; file_logger format tests unchanged otherwise.

Validation: `cargo test redirect file_logger` + wave gate.

Risk: APISIX config-portability fix changes observable redirect output for templates that previously produced `""`. Called out in commit message and USER_GUIDE.

---

### Task T6: `plugins::limiting` deep module (C2)

Type: AFK · Blocked by: T2 · Areas: plugins

Goal: one module owns Policy/KeyType enums + rejections, `BoundedShardMap<V>` (admission, overflow bucket, budgeted sweep), rule/key resolution, and a shared `RejectPolicy`; each limiter keeps schema + pure transition + hook wiring.

Acceptance criteria:
- `limit_req.rs`, `limit_conn.rs`, `limit_count.rs` lose the duplicated shapes listed in review C2; `api_breaker.rs`'s hand-rolled LRU is replaced by the shared bounded map.
- `limit_req.rs:225-243` uses `parse_and_validate_plugin_config` + post-check (hand-inlined body deleted).
- Limiter behavior (including overflow keying, sweep bounds, 429/503 codes and messages, quota headers) unchanged; existing integration tests pass.

Files: Create `src/plugins/limiting.rs` (or `src/plugins/limiting/` dir); Modify `src/plugins/{mod,limit_req,limit_conn,limit_count,api_breaker,limiter_shards}.rs`.

Contracts (for T10): `limiting::RejectPolicy { code, msg }` with one `reject()` writer — pre-T10 it goes through `send_exit_response` returning `true`; post-T10 it constructs a `Rejection` value. Keep this behind one function so T10 touches it once.

Tests: existing per-plugin suites are the spec; the pure transition functions stay pure and keep their unit tests; duplicated parse/validate tests for the deleted copies collapse into `limiting` module tests (delete subsumed copies).

Validation: `cargo test limit_ api_breaker` + wave gate.

---

### Task T7: plan/compile consolidation + test fixtures (C8)

Type: AFK · Blocked by: none · Areas: proxy/control_plane

Goal: `build_prepared` consumes plan decisions mechanically; one named validation routine; one occurrence-walk; fixture builders replace ~20 struct literals.

Acceptance criteria:
- `compile.rs`'s copied validation loops (70-116) and re-derived deps (`scope_upstream_deps` ×3) are gone; compile consumes typed per-resource decisions from the plan.
- The three validation gates are named (`validate_stored_form` / `validate_runtime_form` or mode-tagged `validate_config_set`); call sites say which form they validate.
- `prepare_static_candidate`/`prepare_static_upstream` (cfg(test) mirrors) replaced by a DNS-off variant of the production prepare path; `compile_next`'s "mirrors the authority" comment deleted.
- Shared fixture builders (`test_fixtures::{route, upstream, service}`) replace the struct literals across plan.rs/compile.rs/resources.rs/runtime.rs test mods + duplicated `sample_upstream`s; adding a `config::Route` field touches one builder.

Files: Modify `src/proxy/control_plane/{plan,compile,resources}.rs`, create `src/proxy/control_plane/test_fixtures.rs` (cfg(test)), `src/proxy/runtime.rs` (test fixtures only), `src/proxy/graph_mutation/decode.rs` (gate naming).

Contracts: `CandidatePlan` exposes per-resource `Decision::{Reuse(Arc<..>), Rebuild(inputs)}`; tests must not reach into `plan.jobs`/`upstream_reused` internals — assert at publish boundary instead.

Tests: plan/compile assertions re-pointed to the production path and the publish boundary; `resources.rs`/decode validation tests updated to gate names. Behavior-level assertions in runtime.rs tests unchanged.

Validation: `cargo test control_plane runtime` + wave gate.

---

### Task T8: Delete the `Config` resource-Vec shallow layer (C9)

Type: AFK · Blocked by: T7, T4 · Areas: config, proxy/control_plane, service

Goal: `ResourceConfigSet` becomes the single bootstrap representation; static YAML flows through the same ingestion core shape as etcd.

Acceptance criteria:
- `Config` loses its five resource Vec fields and the `validate_unique_ids` pass; YAML loading produces `ResourceConfigSet` directly.
- `load_static` is no longer a static escape hatch — static mode runs through a `ConfigurationGraph` instance with the same `prepare → compile → publish` path (filesystem as source instead of watch).
- `config.yaml` example and USER_GUIDE updated to the new static-config shape **if the YAML schema changes**; otherwise schema stays with conversion internal (preferred: zero user-facing schema change).

Files: Modify `src/config/mod.rs`, `src/proxy/control_plane/resources.rs`, `src/proxy/graph_mutation/authority.rs`, `src/service/mod.rs`, `src/config/tests.rs` (1497 lines — update to ResourceConfigSet-level assertions where they pinned the Vec layer).

Contracts: `Config` keeps pingora/pingsix server settings only; resource containers move to the control-plane vocabulary at the boundary.

Tests: config/tests.rs remains schema-behavioral; static-boot integration tests unchanged in behavior.

Validation: `cargo test config` + boot tests + wave gate.

---

### Task T9: Narrow the cycle-breaker seams (C7a)

Type: AFK · Blocked by: T3 · Areas: core/plugin, proxy, plugins (call sites)

Goal: `RouteContext` shrinks to the request-path contract; label getters move behind an optional downcast trait; one canonical import path per type.

Acceptance criteria:
- `RouteContext` retains only the methods the request path provably needs (audit first: expect `id`, `timeout`, `build_plugin_executor`, `select_upstream`-adjacent items, `cache_namespace_fingerprint`); the rest (`name`, `service_name`, `uri_template`, `effective_hosts`, non-essential label getters) move to `RouteLabels` obtained via downcast.
- `HealthCheckSpec` gets one canonical import path; the `proxy/upstream/health_check.rs:30` re-export hop is deleted.
- Every call site migrated; audit note in the PR describing the final method split and why.

Files: Modify `src/core/plugin/{mod,pipeline,upstream}.rs`, `src/proxy/route.rs`, `src/proxy/upstream/health_check.rs`, whichever plugins consume moved getters (audit: ai_proxy, traffic_split at minimum), `src/core/mod.rs` re-export list.

Contracts: `RouteContext` slimmed trait + `RouteLabels` trait; `MockRoute`/`StubSelector` test doubles updated (T2's consolidation should make this cheap).

Tests: existing plugin + pipeline tests updated to the split; no behavior change.

Validation: `make test` (cross-cutting by nature) + wave gate.

---

### Task T10: Core contract — `FilterVerdict` + phases-in-`PLUGIN_META` (C1 core) — **high risk**

Type: HITL · Blocked by: T2, T5, T6, T9 · Areas: core/plugin, utils, service, plugins/mod

Goal: rejection becomes a returned value crossing one seam; phases derive from a single source.

Acceptance criteria:
- `ProxyPlugin::request_filter` returns `ProxyResult<FilterVerdict>`: `FilterVerdict::{Continue, Reject(Rejection)}` with `Rejection { status, headers, body, content_type }` (exact shape finalized in review of the drafted trait).
- The pipeline (and `service/http.rs` fail_to_proxy / no-route-404 paths) write every rejection through `send_exit_response` exactly once — exit-transformer applies uniformly.
- `ResponseBuilder::send_proxy_error` no longer has plugin call sites.
- `PluginMeta` gains `phases: PluginPhases`; `fn phases()` is deleted from the trait; the ~120-line expected-phases table test (plugins/mod.rs:504-600) is replaced by construction-time derivation; the silent-no-op failure mode is unrepresentable for builtins.
- `ProxyPluginExecutor` phase partition built from `PLUGIN_META`.

Files: Modify `src/core/plugin/{mod,pipeline,upstream}.rs`, `src/plugins/mod.rs`, `src/utils/response.rs`, `src/service/http.rs`.

Contracts (exact, for T11a-c):
```rust
pub enum FilterVerdict { Continue, Reject(Rejection) }
pub struct Rejection { /* status: StatusCode, headers, body: BodyKind, content_type */ }
// PluginMeta { name, priority, phases: PluginPhases, kind, ... }
// request_filter(&self, session, ctx) -> ProxyResult<FilterVerdict>
```
Coordinator: draft these, verify against all 31 plugins' current reject shapes (including grpc_web's trailers? and ai_proxy's streamed error), then freeze before dispatching T11.

Tests: `tests/plugin_gateway_rejections.rs` extended so the uniform-transform assertions cover jwt-auth/key-auth/basic-auth 401s (the previously bypassed family — this is the observable win); pipeline unit tests via T2 harness for verdict write-through; phases construction test replacing the mirror table.

Validation: `cargo test plugin core service` + wave gate.

Risk controls:
- Failure mode: a plugin that needs streaming/connection-close semantics that `Rejection` can't express (check grpc_web and ai_proxy first). Mitigation: `Rejection` carries an escape variant (`Raw`) used only by the audited exceptions, each with a comment + test.
- Breaking change mitigations: README plugin-contract section updated in same changeset; USER_GUIDE plugin-dev guide updated in T12.
- Rollback: revert the wave (no data-compat concerns; in-repo only).
- Dispatch order: T10 lands alone and green before any T11 dispatch.

---

### Task T11a/b/c: Migrate plugin groups to `FilterVerdict`

Type: AFK · Blocked by: T10 · Areas: plugins

Groups (disjoint files):
- **T11a auth/security**: `jwt_auth.rs`, `key_auth.rs`, `basic_auth.rs`, `csrf.rs`, `ip_restriction.rs`, `uri_blocker.rs`, `request_validation.rs`, `cors.rs`
- **T11b traffic**: `limit_req.rs`, `limit_conn.rs`, `limit_count.rs`, `api_breaker.rs` (via `limiting::RejectPolicy` — mostly T6's seam), `client_control.rs`, `traffic_split.rs`, `proxy_mirror.rs`, `proxy_rewrite.rs`, `response_rewrite.rs`, `redirect.rs`, `cache.rs`, `grpc_web.rs`
- **T11c observability/AI/misc**: `ai_proxy/`, `echo.rs`, `fault_injection.rs`, `file_logger.rs`, `prometheus.rs`, `request_id.rs`, `gzip.rs`, `brotli.rs`, `exit_transformer.rs`

Each group's acceptance criteria:
- Every plugin in the group returns verdicts; no `send_exit_response`/`send_proxy_error` call remains inside plugins (the write happens in the pipeline).
- Plugin phases come from `PLUGIN_META`, not overrides.
- Per-plugin rejection wire format pinned by tests (T2 harness makes this cheap); existing integration tests pass.

Validation: `cargo test <plugin names>` + `tests/plugin_gateway_rejections.rs` per group + wave gate at wave end.

---

### Task T12: Integration polish + minor-items batch

Type: HITL · Blocked by: T11a-c · Areas: docs, plugins, proxy/upstream

Content:
1. README "Creating Custom Plugins" + "Breaking plugin contract" sections rewritten for FilterVerdict/PLUGIN_META; USER_GUIDE plugin-dev chapter synced.
2. Minor items from the review's "also noted": drop `PassiveHealthState.on_transition` (tests assert via selection outcomes), mandatory `ValidatePluginFn`-style validate-without-construct for plain plugins, executor/`ProxyContext::instance_key(prefix)` helper replacing 7 `NEXT_INSTANCE_ID` blocks, peer-timeout precedence note co-located in load_balancer.rs.

Acceptance criteria: docs build coherent; each minor item lands as its own commit; suite green.

Validation: full — `make checkfmt && make clippy && make test`.

Final validation: full make targets + one `code-review-expert` pass over the T10–T12 changeset (public-contract change; per review policy, exactly one pass at the end).

---

## Execution record (completed 2026-08-24)

- Wave 1 `592b480` — T1 admin seam, T2 test mocks, T3 fingerprint profiles, T4 etcd split
- Wave 2 `8e239b2` — T5 template unification, T6 plugins::limiting, T7 plan/compile
- Wave 3 `c234211` — T8 Config vec-layer deletion, T9 narrowed seams
- Wave 4 `762fb87` (T10 contract + all 29 plugins converted; T11 folded in), `44536f0` (T12 polish/docs), nit-fix commit after independent code-review (verdict: APPROVE WITH NITS, 3 P3 fixed)
- Final gate: full suite green except 2 pre-existing flaky chunked-body tests in tests/ai_proxy_upstream.rs (fail identically at clean HEAD — environmental, out of scope; recommended as separate follow-up)
