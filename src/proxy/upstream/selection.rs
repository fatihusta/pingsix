//! Upstream backend selection (priority + health).
//!
//! Backends sharing a node `priority` form a group. Each group gets its own
//! inner [`BackendSelection`] instance, so weights and hash rings are computed
//! from that group alone: adding or removing a backup node cannot change how
//! traffic is distributed among the primary nodes.
//!
//! [`PriorityGrouped`] iterates groups from highest to lowest priority, which
//! makes Pingora's own health filtering pick the first ready backend in the
//! highest priority group that still has one. When no group has a ready
//! backend, [`select_backend`] retries ignoring health, still in priority
//! order.
//!
//! Within a group, failover keeps the inner algorithm's own semantics: the
//! group's selector drives the candidate order (weights, hash rings, and
//! round-robin state), so a down primary does not collapse the group onto the
//! lexicographically smallest address. A bounded number of inner draws is
//! followed by a deterministic enumeration of any member the inner phase
//! missed, so a ready backend is never skipped over. Single-group upstreams
//! bypass this bookkeeping entirely and behave exactly like plain Pingora.
//!
//! Because grouping happens inside the selector, Pingora rebuilds the groups
//! atomically whenever service discovery replaces the backend set.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use pingora_load_balancing::{
    selection::{BackendIter, BackendSelection},
    Backend, LoadBalancer,
};

/// Opaque backend metadata: node priority (`i8`, default 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NodePriority(pub i8);

pub(crate) fn set_backend_priority(backend: &mut Backend, priority: i8) {
    backend.ext.insert(NodePriority(priority));
}

pub(crate) fn backend_priority(backend: &Backend) -> i8 {
    backend.ext.get::<NodePriority>().map(|p| p.0).unwrap_or(0)
}

/// Insert `backend` into `set`, keeping the higher priority when Pingora identity
/// collides (same addr **and** weight; `ext` is ignored by `Backend` equality).
///
/// Config validation already rejects duplicate effective addresses among enabled
/// nodes, so a full-identity collision here means two distinct hostnames resolved
/// to the same address at the same weight. Dropping the lower priority is the
/// only representable outcome. Note that two hostnames resolving to the same
/// address at *different* weights are distinct Pingora backends and both stay in
/// the set, mirroring Pingora's identity semantics.
pub(crate) fn insert_backend(set: &mut BTreeSet<Backend>, backend: Backend) {
    let Some(existing) = set.get(&backend).cloned() else {
        set.insert(backend);
        return;
    };

    let (new_priority, existing_priority) =
        (backend_priority(&backend), backend_priority(&existing));
    if new_priority == existing_priority {
        return;
    }

    log::warn!(
        "backend {} resolved twice with different priorities ({existing_priority}, {new_priority}); keeping {}",
        backend.addr,
        new_priority.max(existing_priority)
    );

    if new_priority > existing_priority {
        set.remove(&existing);
        set.insert(backend);
    }
}

/// One priority level and the selector built from exactly its members.
struct PriorityGroup<BS> {
    priority: i8,
    selector: Arc<BS>,
    /// Same members as `selector`, in [`Backend`] order. Used to map inner
    /// candidates back to stable indices (dedupe) and to enumerate any member
    /// the inner phase missed, before falling through to the next priority.
    backends: Box<[Backend]>,
}

/// Wraps a [`BackendSelection`] so selection walks priority groups from highest
/// to lowest, each group selected by its own instance of the inner algorithm.
pub(crate) struct PriorityGrouped<BS> {
    /// Highest priority first; empty when there are no backends.
    groups: Box<[PriorityGroup<BS>]>,
}

impl<BS> PriorityGrouped<BS> {
    fn group_by_priority(
        backends: &BTreeSet<Backend>,
        build: impl Fn(&BTreeSet<Backend>) -> BS,
    ) -> Self {
        let mut by_priority: BTreeMap<Reverse<i8>, BTreeSet<Backend>> = BTreeMap::new();
        for backend in backends {
            by_priority
                .entry(Reverse(backend_priority(backend)))
                .or_default()
                .insert(backend.clone());
        }

        let groups: Box<[PriorityGroup<BS>]> = by_priority
            .into_iter()
            .map(|(Reverse(priority), members)| PriorityGroup {
                priority,
                selector: Arc::new(build(&members)),
                backends: members.into_iter().collect(),
            })
            .collect();

        if log::log_enabled!(log::Level::Debug) {
            let summary: Vec<_> = groups
                .iter()
                .map(|group| (group.priority, group.backends.len()))
                .collect();
            log::debug!("proxy lb priority groups (priority, backends): {summary:?}");
        }

        Self { groups }
    }
}

impl<BS> BackendSelection for PriorityGrouped<BS>
where
    BS: BackendSelection,
    BS::Iter: BackendIter,
{
    type Iter = PriorityGroupedIter<BS>;
    type Config = BS::Config;

    fn build(backends: &BTreeSet<Backend>) -> Self {
        Self::group_by_priority(backends, BS::build)
    }

    fn build_with_config(backends: &BTreeSet<Backend>, config: &Self::Config) -> Self {
        Self::group_by_priority(backends, |members| BS::build_with_config(members, config))
    }

    fn iter(self: &Arc<Self>, key: &[u8]) -> Self::Iter {
        match self.groups.split_first() {
            None => PriorityGroupedIter::Empty,
            // A single group cannot be reordered, so skip the bookkeeping and
            // hand out the inner iterator as-is.
            Some((only, [])) => PriorityGroupedIter::Flat(only.selector.iter(key)),
            Some(_) => PriorityGroupedIter::Grouped(GroupedCursor {
                grouped: self.clone(),
                key: key.into(),
                group: 0,
                inner: None,
                seen: Box::new([]),
                drawn: 0,
                next: 0,
            }),
        }
    }
}

/// Candidate order for [`PriorityGrouped`].
pub(crate) enum PriorityGroupedIter<BS: BackendSelection> {
    Empty,
    Flat(BS::Iter),
    Grouped(GroupedCursor<BS>),
}

pub(crate) struct GroupedCursor<BS: BackendSelection> {
    grouped: Arc<PriorityGrouped<BS>>,
    key: Box<[u8]>,
    /// Index into `grouped.groups`.
    group: usize,
    /// Inner iterator of the current group, built on first use.
    inner: Option<BS::Iter>,
    /// Members of the current group already yielded, indexed by position in
    /// [`PriorityGroup::backends`].
    seen: Box<[bool]>,
    /// Inner draws made for the current group. Bounds the inner phase so a
    /// cycling iterator (weighted round robin, fnv) cannot spin forever.
    drawn: usize,
    /// Next position for the coverage-enumeration phase of the current group.
    next: usize,
}

/// Maximum inner draws per group before the coverage enumeration kicks in.
///
/// The inner selectors need only a handful of draws to cover a typical group
/// (round robin cycles in `len` draws; a ketama ring visits most members within
/// a few positions). The budget is a loose multiple of the group size so the
/// algorithm's own order dominates, while a hard floor keeps tiny groups from
/// being starved by a long hash ring. Whatever the inner phase misses is
/// enumerated afterwards, so the budget only affects *order*, never coverage.
fn group_draw_budget(group_len: usize) -> usize {
    group_len.saturating_mul(8).max(64)
}

impl<BS> BackendIter for PriorityGroupedIter<BS>
where
    BS: BackendSelection,
    BS::Iter: BackendIter,
{
    fn next(&mut self) -> Option<&Backend> {
        let cursor = match self {
            Self::Empty => return None,
            Self::Flat(inner) => return inner.next(),
            Self::Grouped(cursor) => cursor,
        };

        loop {
            let group = cursor.grouped.groups.get(cursor.group)?;

            // (Re)initialize per-group state on first entry.
            if cursor.seen.len() != group.backends.len() {
                cursor.seen = vec![false; group.backends.len()].into_boxed_slice();
                cursor.drawn = 0;
                cursor.next = 0;
                cursor.inner = Some(group.selector.iter(&cursor.key));
            }

            // Phase 1: let the group's own algorithm drive the order, so
            // weights, hash rings, and round-robin state are honored during
            // failover too. Dedupe by index; the inner selector can repeat a
            // candidate (weighted iterators cycle, a ketama ring walks many
            // points per backend).
            if cursor.drawn < group_draw_budget(group.backends.len()) {
                let Some(backend) = cursor.inner.as_mut().and_then(BackendIter::next) else {
                    // Inner exhausted (e.g. the ring walked end to end).
                    cursor.drawn = group_draw_budget(group.backends.len());
                    continue;
                };
                cursor.drawn += 1;
                if let Ok(index) = group.backends.binary_search(backend) {
                    if !cursor.seen[index] {
                        cursor.seen[index] = true;
                        return group.backends.get(index);
                    }
                }
                continue; // duplicate candidate; keep drawing
            }

            // Phase 2: cover any member the inner phase missed, in
            // deterministic order, so a ready backend is never skipped over.
            while cursor.next < group.backends.len() {
                let index = cursor.next;
                cursor.next += 1;
                if !cursor.seen[index] {
                    cursor.seen[index] = true;
                    return group.backends.get(index);
                }
            }

            // Group exhausted: move to the next priority level.
            cursor.group += 1;
            cursor.inner = None;
            cursor.seen = Box::new([]);
        }
    }
}

/// Select a backend: the highest priority group with a ready member, else the
/// same order ignoring health.
pub(crate) fn select_backend<BS>(
    lb: &LoadBalancer<PriorityGrouped<BS>>,
    key: &[u8],
    max_iterations: usize,
) -> Option<Backend>
where
    BS: BackendSelection + 'static,
    BS::Iter: BackendIter,
{
    if let Some(backend) = lb.select(key, max_iterations) {
        log::debug!(
            "proxy lb select: {} priority={}",
            backend.addr,
            backend_priority(&backend)
        );
        return Some(backend);
    }

    let backend = lb.select_with(key, max_iterations, |_, _| true);
    if let Some(ref backend) = backend {
        log::debug!(
            "proxy lb select: {} priority={} (no ready backend, ignoring health)",
            backend.addr,
            backend_priority(backend)
        );
    }
    backend
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use futures::FutureExt;
    use pingora_error::Result as PingoraResult;
    use pingora_load_balancing::{
        discovery::{ServiceDiscovery, Static},
        selection::{consistent::KetamaHashing, FVNHash, RoundRobin},
        Backends,
    };

    fn backend(addr: &str, weight: usize, priority: i8) -> Backend {
        let mut backend = Backend::new_with_weight(addr, weight).unwrap();
        set_backend_priority(&mut backend, priority);
        backend
    }

    fn backend_set(nodes: &[(&str, usize, i8)]) -> BTreeSet<Backend> {
        nodes
            .iter()
            .map(|&(addr, weight, priority)| backend(addr, weight, priority))
            .collect()
    }

    fn lb_from_backends<BS>(backends: BTreeSet<Backend>) -> LoadBalancer<PriorityGrouped<BS>>
    where
        BS: BackendSelection + 'static,
        BS::Iter: BackendIter,
    {
        let lb = LoadBalancer::from_backends(Backends::new(Static::new(backends)));
        lb.update()
            .now_or_never()
            .expect("static discovery is ready")
            .expect("static discovery succeeds");
        lb
    }

    /// Unweighted round-robin nodes, `(addr, priority)`.
    fn lb_from(nodes: &[(&str, i8)]) -> LoadBalancer<PriorityGrouped<RoundRobin>> {
        let nodes: Vec<_> = nodes
            .iter()
            .map(|&(addr, priority)| (addr, 1usize, priority))
            .collect();
        lb_from_backends(backend_set(&nodes))
    }

    fn set_ready<BS>(lb: &LoadBalancer<PriorityGrouped<BS>>, addr: &str, enabled: bool)
    where
        BS: BackendSelection + 'static,
        BS::Iter: BackendIter,
    {
        for backend in lb.backends().get_backend().iter() {
            if backend.addr.to_string() == addr {
                lb.backends().set_enable(backend, enabled);
            }
        }
    }

    fn pick_addr<BS>(lb: &LoadBalancer<PriorityGrouped<BS>>) -> String
    where
        BS: BackendSelection + 'static,
        BS::Iter: BackendIter,
    {
        pick_addr_keyed(lb, b"")
    }

    fn pick_addr_keyed<BS>(lb: &LoadBalancer<PriorityGrouped<BS>>, key: &[u8]) -> String
    where
        BS: BackendSelection + 'static,
        BS::Iter: BackendIter,
    {
        select_backend(lb, key, 256)
            .expect("expected a backend")
            .addr
            .to_string()
    }

    #[test]
    fn selects_highest_ready_group_then_recovers() {
        let high = "127.0.0.1:18081";
        let low = "127.0.0.1:18082";
        let lb = lb_from(&[(high, 10), (low, 0)]);

        assert_eq!(pick_addr(&lb), high);

        set_ready(&lb, high, false);
        assert_eq!(
            pick_addr(&lb),
            low,
            "must fall over to lower priority when highest group is not ready"
        );

        set_ready(&lb, high, true);
        assert_eq!(
            pick_addr(&lb),
            high,
            "must recover to highest priority on the next select"
        );
    }

    #[test]
    fn all_unready_falls_back_ignoring_health() {
        let high = "127.0.0.1:18091";
        let low = "127.0.0.1:18092";
        let lb = lb_from(&[(high, 5), (low, 1)]);
        set_ready(&lb, high, false);
        set_ready(&lb, low, false);

        assert_eq!(
            pick_addr(&lb),
            high,
            "fallback must keep priority order while ignoring health"
        );
    }

    #[test]
    fn prefers_zero_over_negative_and_negative_over_lower() {
        let high = "127.0.0.1:18201";
        let mid = "127.0.0.1:18202";
        let low = "127.0.0.1:18203";
        let lb = lb_from(&[(high, 0), (mid, -1), (low, -2)]);
        assert_eq!(pick_addr(&lb), high);

        set_ready(&lb, high, false);
        assert_eq!(pick_addr(&lb), mid);

        set_ready(&lb, mid, false);
        assert_eq!(pick_addr(&lb), low);
    }

    #[test]
    fn single_group_delegates_to_inner_selector() {
        let a = "127.0.0.1:18211";
        let b = "127.0.0.1:18212";
        let lb = lb_from(&[(a, 7), (b, 7)]);

        let selector_iter = lb.backends().get_backend();
        assert_eq!(selector_iter.len(), 2);

        set_ready(&lb, a, false);
        assert_eq!(pick_addr(&lb), b, "health still filters within one group");
    }

    #[test]
    fn weights_are_honored_within_priority_group() {
        let light = "127.0.0.1:18301";
        let heavy = "127.0.0.1:18302";
        // A large backup group must not dilute the primary group's weights.
        let mut nodes = vec![(light, 1usize, 10i8), (heavy, 9, 10)];
        let backups: Vec<String> = (0..20)
            .map(|i| format!("127.0.0.2:{}", 19000 + i))
            .collect();
        nodes.extend(backups.iter().map(|addr| (addr.as_str(), 1usize, 0i8)));
        let lb = lb_from_backends::<RoundRobin>(backend_set(&nodes));

        let mut counts: HashMap<String, usize> = HashMap::new();
        for _ in 0..100 {
            *counts.entry(pick_addr(&lb)).or_default() += 1;
        }

        assert_eq!(
            counts.get(heavy).copied().unwrap_or(0),
            90,
            "weight 9 of 10 within the group must win 90 of 100 selections: {counts:?}"
        );
        assert_eq!(counts.get(light).copied().unwrap_or(0), 10, "{counts:?}");
        assert_eq!(counts.len(), 2, "backup group must not serve: {counts:?}");
    }

    /// The primary group's hash mapping must depend only on its own members.
    fn assert_hash_mapping_ignores_backups<BS>()
    where
        BS: BackendSelection + 'static,
        BS::Iter: BackendIter,
    {
        let primaries = [
            ("127.0.0.1:18401", 1usize, 10i8),
            ("127.0.0.1:18402", 1, 10),
            ("127.0.0.1:18403", 1, 10),
        ];
        let with_backups: Vec<_> = primaries
            .iter()
            .copied()
            .chain([
                ("127.0.0.2:18501", 1usize, 0i8),
                ("127.0.0.2:18502", 3, 0),
                ("127.0.0.2:18503", 7, -5),
            ])
            .collect();

        let only_primaries = lb_from_backends::<BS>(backend_set(&primaries));
        let all = lb_from_backends::<BS>(backend_set(&with_backups));

        for key in ["alice", "bob", "carol", "dave", "erin", "frank", "grace"] {
            assert_eq!(
                pick_addr_keyed(&only_primaries, key.as_bytes()),
                pick_addr_keyed(&all, key.as_bytes()),
                "lower priority nodes must not remap key {key}"
            );
        }
    }

    #[test]
    fn fnv_mapping_unaffected_by_lower_priority_nodes() {
        assert_hash_mapping_ignores_backups::<FVNHash>();
    }

    #[test]
    fn ketama_mapping_unaffected_by_lower_priority_nodes() {
        assert_hash_mapping_ignores_backups::<KetamaHashing>();
    }

    /// Discovery whose backend set can be swapped between refreshes.
    #[derive(Clone)]
    struct MutableDiscovery(Arc<Mutex<BTreeSet<Backend>>>);

    impl MutableDiscovery {
        fn new(nodes: &[(&str, usize, i8)]) -> Self {
            Self(Arc::new(Mutex::new(backend_set(nodes))))
        }

        fn replace(&self, nodes: &[(&str, usize, i8)]) {
            *self.0.lock().unwrap() = backend_set(nodes);
        }
    }

    #[async_trait]
    impl ServiceDiscovery for MutableDiscovery {
        async fn discover(&self) -> PingoraResult<(BTreeSet<Backend>, HashMap<u64, bool>)> {
            Ok((self.0.lock().unwrap().clone(), HashMap::new()))
        }
    }

    #[test]
    fn higher_priority_backend_added_by_refresh_is_selected() {
        let existing = "127.0.0.1:18601";
        let discovered = "127.0.0.1:18602";
        let discovery = MutableDiscovery::new(&[(existing, 1, 0)]);

        let lb: LoadBalancer<PriorityGrouped<RoundRobin>> =
            LoadBalancer::from_backends(Backends::new(Box::new(discovery.clone())));
        lb.update().now_or_never().unwrap().unwrap();
        assert_eq!(pick_addr(&lb), existing);

        // A DNS refresh reveals a node whose priority level did not exist before.
        discovery.replace(&[(existing, 1, 0), (discovered, 1, 10)]);
        lb.update().now_or_never().unwrap().unwrap();

        assert_eq!(
            pick_addr(&lb),
            discovered,
            "a priority level introduced by a refresh must be honored"
        );
    }

    #[test]
    fn ketama_failover_within_group_follows_the_ring() {
        let a = "127.0.0.1:18701";
        let b = "127.0.0.1:18702";
        let c = "127.0.0.1:18703";
        let backup = "127.0.0.2:18704";
        let key = b"ketama-failover-key";

        // The primary group's ring on its own, as plain Pingora would see it.
        let primary = backend_set(&[(a, 1, 10), (b, 1, 10), (c, 1, 10)]);
        let selector = Arc::new(KetamaHashing::build(&primary));
        let mut inner = selector.iter(key);
        let first = inner.next().expect("ring is non-empty").addr.to_string();
        let second = {
            let mut seen = HashSet::new();
            seen.insert(first.clone());
            loop {
                let addr = inner.next().expect("ring is non-empty").addr.to_string();
                if seen.insert(addr.clone()) {
                    break addr;
                }
            }
        };

        // The same primary group plus a lower-priority backup forces the
        // grouped (non-flat) iterator path.
        let mut members = primary.clone();
        members.extend(backend_set(&[(backup, 1, 0)]));
        let lb = lb_from_backends::<KetamaHashing>(members);
        set_ready(&lb, &first, false);

        assert_eq!(
            pick_addr_keyed(&lb, key),
            second,
            "in-group failover must walk the ketama ring, not fall back to address order"
        );
    }

    #[test]
    fn round_robin_failover_within_group_reaches_the_healthy_member() {
        let light = "127.0.0.1:18801";
        let heavy = "127.0.0.1:18802";
        let backup = "127.0.0.2:18803";
        let lb = lb_from_backends::<RoundRobin>(backend_set(&[
            (light, 1, 10),
            (heavy, 9, 10),
            (backup, 1, 0),
        ]));
        // The weighted first choice can be the light node (1 slot in 10); with
        // it down, the group's own round-robin continuation must still land on
        // the heavy node instead of skipping to the backup group.
        set_ready(&lb, light, false);

        for _ in 0..50 {
            assert_eq!(
                pick_addr(&lb),
                heavy,
                "every selection must reach the remaining ready member of the group"
            );
        }
    }

    #[test]
    fn insert_backend_keeps_higher_priority_on_addr_collision() {
        let mut set = BTreeSet::new();
        insert_backend(&mut set, backend("127.0.0.1:443", 1, -1));
        insert_backend(&mut set, backend("127.0.0.1:443", 1, 10));

        assert_eq!(set.len(), 1);
        assert_eq!(backend_priority(set.iter().next().unwrap()), 10);
    }

    #[test]
    fn insert_backend_keeps_distinct_weights_at_the_same_addr() {
        // Pingora identity includes weight, so same-addr different-weight
        // backends are distinct and must both survive.
        let mut set = BTreeSet::new();
        insert_backend(&mut set, backend("127.0.0.1:443", 1, 10));
        insert_backend(&mut set, backend("127.0.0.1:443", 2, 0));

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn groups_are_ordered_highest_priority_first() {
        let grouped = PriorityGrouped::<RoundRobin>::build(&backend_set(&[
            ("127.0.0.1:1", 1, -3),
            ("127.0.0.1:2", 1, 10),
            ("127.0.0.1:3", 1, 0),
            ("127.0.0.1:4", 1, 10),
        ]));

        let levels: Vec<i8> = grouped.groups.iter().map(|g| g.priority).collect();
        assert_eq!(levels, vec![10, 0, -3]);
        assert_eq!(grouped.groups[0].backends.len(), 2);
    }
}
