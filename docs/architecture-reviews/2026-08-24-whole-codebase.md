# Architecture Review — Whole Codebase

Date: 2026-08-24 · Scope: all of `src/` (~47k lines) · Method: three parallel read-only surveys (proxy core, plugin system, config/control-plane), spot-verified against the code.

## Overall verdict

PingSIX's load-bearing structures are genuinely deep and should not be regressed:

- **Single-writer funnel**: every mutation — static YAML, etcd watch, Admin CAS — converges through `ConfigurationGraph` → one worker → `RuntimeStore::publish`. No dual writers; the Admin API is a pure HTTP adapter re-entering through the same etcd watch.
- **`GraphStore` seam**: exactly two adapters (`EtcdGraphStore`, `InMemoryGraphStore`) and it is what makes authority/worker/CAS tests hermetic. Keep.
- **`CandidatePlan` / `RuntimeStore::publish`**: one source of truth for Arc-reuse and DNS-prep; publish tests assert observable outcomes (Arc identity, generation stability).
- **`GatewayState` composition root** with a regression test for the former process-global failure mode.
- **Local deepening victories in plugins**: `compression.rs` (gzip/brotli are pure delegations), `plugins/config.rs::parse_and_validate_plugin_config`, `limiter_shards.rs`, and pure decision functions (`leaky_bucket_step`, `decide`, `breaker_secs`).

The friction is concentrated in *adjacent shallow layers and duplicated connective tissue*: two competing rejection paths, near-verbatim template engines, hand-maintained fingerprint field-lists, and several implementations of one limiter scaffolding shape. The healthy parts are individual; the deepenings have not been made system policy.

---

## Candidate 1 — Rejection as a returned value: unify the two rejection-write paths

**Files:** `src/utils/response.rs` (`send_exit_response:204`, `ResponseBuilder::send_proxy_error:97`), `src/core/plugin/pipeline.rs:558`, 12+ plugin call sites.

**Problem.** `exit_transformer.rs:23` claims `send_exit_response` is consulted "at every gateway exit... a single choke point." It isn't. Plugin short-circuits are split between two helpers with different semantics:

- `send_exit_response` (exit-transformer applies; handles 1xx/204/304 body-strip, close-delimited framing fix, `$status` templating): `ip_restriction.rs:343`, `uri_blocker.rs:165`, `request_validation.rs:276`, `ai_proxy/mod.rs:245`, `service/http.rs:186/389`.
- `ResponseBuilder::send_proxy_error` (exit-transformer silently bypassed): `jwt_auth.rs:328/354`, `key_auth.rs:182`, `basic_auth.rs:148`, `csrf.rs:225/238/250/262`, `limit_req.rs:249`, `limit_conn.rs:496`, `limit_count.rs:667/871/987`, `api_breaker.rs:358`, `client_control.rs:96`, `grpc_web.rs:200/222/240`.

An `exit-transformer` rule targeting 401 rewrites an ip-restriction rejection but not a jwt-auth one — same priority family, opposite behavior. The `bool` return contract (`true` = "I already wrote raw bytes") is what allows the routes around the choke point.

**Solution.** Change `request_filter` from `Result<bool>` to a verdict type, e.g. `FilterVerdict::{Continue, Reject(Rejection { status, body, headers, content_type })}`. The pipeline (which already short-circuits at pipeline.rs:558) writes rejections through `send_exit_response` exactly once. Both helpers' plugin call sites disappear; "did this plugin remember the transform?" becomes unrepresentable.

**Benefits.** Locality — one place owns gateway rejections, the exit-transformer contract becomes true. Leverage — every plugin drops its response-writing code (status line framing, keep-alive edge cases). Testability — `tests/plugin_gateway_rejections.rs` already pins wire format for the compliant family; the same assertions extend to auth plugins.

**Strength: Strong.**

---

## Candidate 2 — A `plugins::limiting` module absorbing the limiter-family scaffolding

**Files:** `src/plugins/limit_req.rs` (615), `limit_conn.rs` (1107), `limit_count.rs` (1810), `api_breaker.rs` (554), shared nucleus `limiter_shards.rs` (104).

**Problem.** Three limiters re-derive identical scaffolding around genuinely different cores (leaky bucket vs. connection counting vs. rate+window): `Policy`/`KeyType` enums with "only local supported" rejections; rule-selection (`select_limits` in two files with near-identical docstrings); shard admission + stable overflow bucket; budgeted sweep loops over `TouchOrder`; `rejected_code`/`rejected_msg` parse-validate-write chains; `NEXT_INSTANCE_ID` ctx keys. `api_breaker.rs:92-131` can't reuse `TouchOrder` and ships a fourth hand-rolled LRU. `limit_req.rs:225-243` even hand-inlines `parse_and_validate_plugin_config`'s body to append one policy check.

**Solution.** A `plugins/limiting` module owning: the shared enums and their rejections; a `BoundedShardMap<V>` generic over entry type (absorbing all three sweep loops and api-breaker's LRU); rule/key resolution; a shared `RejectPolicy` writing through the unified rejection path (Candidate 1). Each limiter keeps only its `TryFrom` schema, its (already pure, already unit-tested) transition function, and hook wiring — the `compression.rs` model.

**Benefits.** Locality — eviction, overflow, and rejection policy fixed once, fixed everywhere (3,532 lines shrink by roughly half). Leverage — a future redis policy is added once.

**Strength: Strong.**

---

## Candidate 3 — One template parser + variable registry; fix the redirect resolver divergence

**Files:** `src/utils/request.rs` (`render_apisix_template:199`, `resolve_var:240`), `src/plugins/redirect.rs` (`render_redirect_template:417`, `resolve_redirect_var:465`), `src/plugins/file_logger.rs` (`LogFormat:618-690`), `src/utils/response.rs` (`substitute_exit_vars:132`).

**Problem.** Four engines expand `$name`/`${name}` with subtly different grammars and resolvers. `redirect.rs::render_redirect_template` is a near-verbatim copy of `render_apisix_template_with_count` (same peekable-chars loop and placeholder grammar) plus `\$` escaping — but its resolver supports only 5 variables, resolves `host` by a *different precedence order* than `get_request_host`, and lacks `arg_*`/`http_*`. `$remote_addr` in a redirect template silently renders `""` while the same variable works in a limiter key — a latent APISIX config-portability bug. `file_logger` re-parses with a regex that cannot express `${name}`, plus a hand-maintained size table and a third (log-phase) resolver.

**Solution.** Keep one parser (already generic over `FnMut(&str) -> String` — exactly the right seam) with an escape option; add an extensible variable registry keyed by lifecycle phase (request-phase vs. log-phase). Redirect and file_logger pass resolvers, not parsers.

**Benefits.** Locality — grammar and precedence bugs get one fix site. Correctness — the redirect/host divergence is a real compat hazard today.

**Strength: Strong.**

---

## Candidate 4 — Split `config/etcd.rs`; relocate the exported test double

**Files:** `src/config/etcd.rs` (1377 lines).

**Problem.** One file bundles: watch/retry/liveness sync (`EtcdConfigSync`, 50-260), physical→logical key mapping (763-813), TLS/endpoint connection building (455-527), response mapping (313-400), the `EtcdGraphStore` CAS adapter (520-830), and — critically — `InMemoryGraphStore` (835-925), a public, non-`cfg(test)` test double imported by every `graph_mutation` test and harness. The two real adapters share almost nothing (a watching `Client` vs. a lazy `OnceCell<Client>`); they're fused by location. The test double inverts the dependency direction: `proxy::graph_mutation` tests reach into `config::etcd` for their seam implementation. It's not a god-module — it reads as several honest modules stapled into one file.

**Solution.** Split into `config/etcd/{sync,store,keys,tls}.rs`; move `InMemoryGraphStore` next to the `GraphStore` trait (`graph_mutation/store.rs` test support). Logical split only, no behavior change.

**Benefits.** Locality — the searn's adapters live at the seam. Testability — the test adapter sits where tests look for it.

**Strength: Strong.**

---

## Candidate 5 — Collapse the admin phantom generic seam

**Files:** `src/admin/mod.rs:219-262`.

**Problem.** To parameterize `/apisix/admin/{kind}/{id}` over five resource kinds, the code builds `trait AdminResource { const RESOURCE_KIND }` + five empty impls + an `admin_handler!` macro generating four `PhantomData` structs + a second `Handler` trait. Deletion test: deleting all of it and registering `ResourceHandler { kind: ResourceKind }` values makes complexity vanish; the generic layer buys zero behavior variation.

**Solution.** Value-parameterized handlers over the existing `ResourceKind` enum.

**Benefits.** Locality — "PUT → graph.put" is findable without walking a macro and two traits. Small but unambiguous.

**Strength: Strong (small).**

---

## Candidate 6 — Consolidate the three hand-maintained config-field fingerprint functions

**Files:** `src/proxy/upstream/load_balancer.rs:203` (`cache_origin_fingerprint`), `src/proxy/runtime.rs:99` (`fingerprint_upstream_for_health_check`), `src/proxy/route.rs:49` (`route_cache_namespace_fingerprint`) + `hash_plugin_map:33`.

**Problem.** Each is a separate `DefaultHasher` walk over config fields, and each silently encodes policy in its field list (health-check excludes weights/retries; origin canonicalizes scheme-default ports; route includes only "response-affecting" plugins). Adding a field to `config::Upstream` or `config::Route` requires a human to audit three functions in three directories; the tests pin each function's *existing* field list, not its completeness. Latent correctness trap, not broken today.

**Solution.** Declare "which fields matter" next to the config types (`src/config/resources.rs`) — serde-serialized fingerprints with explicit exclusion profiles, or named `Hash`-profile impls on the config types. Call sites name a profile instead of walking fields.

**Benefits.** Locality — new fields are fingerprint-audited where they are defined. Correctness — drift becomes a compile-adjacent concern instead of a memory exercise.

**Strength: Strong (drift hazard).**

---

## Candidate 7 — Decide what `core` is: the inverted layering behind `RouteContext`/`UpstreamSelector`

**Files:** `src/core/plugin/upstream.rs:28`, `src/core/plugin/pipeline.rs:26-77`, `src/proxy/route.rs:290`, `src/proxy/upstream/load_balancer.rs:407`.

**Problem.** Both traits have exactly one production adapter each (`ProxyRoute`, `ProxyUpstream`) and exist to invert a `core` ⇄ `proxy` cycle — the placement comment at pipeline.rs:27-29 concedes it. `RouteContext` is ~12 methods, most field pass-throughs; its seam leaks Pingora types into `core` (`select_backend(&mut Session) -> Option<Backend>`), so it decouples from `proxy` but not from Pingora. Related evidence: double re-export bounce chains (`HealthCheckSpec` through three hops, two sibling import paths for one struct). Deletion test: deleting the traits without restructuring just recreates the cycle — they are load-bearing, but only because request-path types (`ProxyContext`, pipeline) live in `core` while the resources they serve live in `proxy`.

**Solution.** Two options: (a) narrow — shrink `RouteContext` to the 3–4 methods the request path actually needs, move label getters into an optional downcast trait; one canonical import path per type; (b) restructure — move `ProxyContext`/pipeline to `proxy` territory so concrete types are visible and the traits disappear. (b) is large; (a) is cheap and honest.

**Benefits.** Locality — readers can tell from imports which layer owns a concept. Interface honesty — the seam stops pretending to decouple from Pingora.

**Strength: Worth exploring.**

---

## Candidate 8 — `plan.rs` vs `compile.rs`: stop re-deriving what the plan computed

**Files:** `src/proxy/control_plane/plan.rs:52-192`, `compile.rs:66-235`, `resources.rs:44-113`.

**Problem.** The plan claims to be the single source of truth for reuse decisions, yet `build_prepared` re-derives upstream deps (`scope_upstream_deps` ×3), re-checks Arc pointers, and re-runs `.validate()` on every resource in five loops textually duplicated from `validate_config_set` (compile.rs:70-116 ≈ resources.rs:45-67). In production, validation already ran in the authority before submission; the duplication exists largely to serve test entry points (`#[cfg(test)]` paths, a cfg(test)-only `prepare_static_candidate` that mirrors the production occurrence-walk, and `compile_next` which admits it "mirrors what the graph authority does"). Deletion test: if compile trusted the plan, deleting the re-derivation makes real complexity vanish — only one authority calls `build_prepared` in production.

**Solution.** Plan yields typed per-resource decisions (reuse-Arc / rebuild-inputs); compile consumes them mechanically. Hoist the validation loops into one named function shared by both files; replace the cfg(test) mirror pipeline with a DNS-off variant of the production prepare path. Also add a shared fixture-builder module for the ~20 copies of the 13-field `config::Route` struct literal across four test modules.

**Benefits.** Locality — one occurrence-walk, one validation content. Testability — tests exercise the code they certify. Note the subtler sibling issue: the three validation gates on the etcd path validate *different documents* (`SecretMode::DecryptForRuntime` vs `PreserveStored`); naming the gates (`validate_stored_form` / `validate_runtime_form`) would make "we already validated it" checkable.

**Strength: Worth exploring.**

---

## Candidate 9 — Delete the `Config` resource-Vec shallow layer

**Files:** `src/config/mod.rs:64-83`, `src/proxy/control_plane/resources.rs:17-43` (`from_yaml_config` — five identical `id.clone()+clone()` loops), `src/proxy/graph_mutation/authority.rs:208-235` (`load_static` bypasses `ConfigurationGraph` entirely).

**Problem.** `Config.routes/upstreams/...` exist only to be cloned field-for-field into `ResourceConfigSet`; static and etcd modes share the compile core but not the ingestion core, and validation differs by path (unique-ID checks vs. key-namespace checks). Deletion test: deleting the layer pushes ~40 lines into the loader — complexity does not fan out into callers.

**Solution.** Make `ResourceConfigSet` the single bootstrap representation (YAML loader constructs it directly, or through a thin static instance of the authority); delete the five Vec fields and their `validate_unique_ids` pass from `Config`.

**Benefits.** Locality — one ingestion story for both modes; one validation content at bootstrap.

**Strength: Worth exploring.**

---

## Candidate 10 — Plugin test machinery: one mock session/stream, not six

**Files:** `tests/common/mod.rs` (MockStream:838-940), `src/core/plugin/pipeline.rs` (NoopStream:681-743), `src/utils/apisix_vars.rs` (MockStream:44-140), `src/plugins/file_logger.rs`, `src/plugins/ai_proxy/mod.rs`, `benches/plugin_pipeline.rs` (BenchmarkStream).

**Problem.** The pingora `IO` trait plumbing (~80–120 lines: AsyncRead/AsyncWrite/Shutdown/UniqueID/Ssl/digests/Peek) is reimplemented ~6 times, which is why only the uri-blocker/request-validation/exit-transformer family has wire-level rejection tests; most plugins test config parsing and pure helpers only, leaving session-interacting paths (jwt-auth challenge chain, cors preflight branching, limiter quota-header emission) covered only via heavy integration tests, if at all.

**Solution.** One in-crate `utils::testing` (behind `cfg(test)` + `tests/common` re-export) with a canned-request session and a response-capture stream — deletes five copies immediately. (Longer-term speculative: a thin `RequestView` for decision logic instead of `&mut Session`.)

**Benefits.** Testability — the friction that currently suppresses plugin hook tests drops to near zero. Leverage — Candidate 1's unified rejection path becomes cheap to test per-plugin.

**Strength: Strong (mock consolidation) / Speculative (`RequestView`).**

---

## Also noted (not standalone candidates)

- **`PluginPhases` dual bookkeeping**: every plugin declares hooks twice (method + bitflag); forgetting the flag is a designed-in silent no-op whose only guard is a ~120-line expected-phases table in `plugins/mod.rs:504-600`. Options: move phases into `PLUGIN_META` (deletes both the method and the mirror table), or the direction `benches/plugin_pipeline.rs` already probes — a `CompiledPlugin` static enum for builtins. *Worth exploring.*
- **Seven plugins** mint `NEXT_INSTANCE_ID` + formatted ctx keys; an executor-assigned instance id or `ProxyContext::instance_key(prefix)` would delete them. *Minor.*
- **Backend eligibility** logic nests three fallback ladders across two files (`load_balancer.rs::select_with_passive` → `selection.rs::select_backend` → `PriorityGroupedIter`); coherent but the precedence chain lives in no single place. Co-location or folding passive admission into the iterator. *Worth exploring.*
- **Peer-timeout precedence** is written at four sites across three layers, documented only in `service/http.rs:198-211`. *Minor doc/locality.*
- **Cache isolation fields** on `ProxyContext` (`original_credential_digest` etc., pipeline.rs:107-133) are cache-plugin concerns living in the generic context; a typed ctx entry would do. *Speculative.*
- **Validation-by-construction** in `plugins/mod.rs:339-348` (`validate_plugin_config` builds and discards the plugin — file-logger opens a file during Admin pre-checks). Make `ValidatePluginFn` mandatory: parse + validate without construct. *Worth exploring.*
- **`#[cfg(test)]` instrumentation in production structs**: `PassiveHealthState.on_transition` (load_balancer.rs:72-79) — tests should assert via selection outcomes. *Minor.*

---

## Top recommendation

**Candidate 1 — rejection as a returned value (`FilterVerdict`).** It converts a currently false architectural claim ("single choke point") into a true one, makes a whole category of plugin behavior (auth vs. ip-restriction 401s) consistent and observable, deletes ~15 side-effecting call sites, and compounds: Candidate 2's shared `RejectPolicy`, Candidate 3's `$status` templating, and Candidate 10's cheap per-plugin wire tests all get easier once the rejection is a value crossing one seam. It does change the `ProxyPlugin` hook signature — a breaking change for external plugin authors — which is exactly the kind of decision to grill before planning.
