//! Shared bounded-shard bookkeeping for local limiter plugins.
//!
//! This module deliberately owns only shard sizing, deterministic key routing,
//! and recency ordering. Individual limiters retain their own admission and
//! eviction predicates.

use std::{
    collections::{BTreeMap, HashMap},
    hash::{Hash, Hasher},
};

/// Upper bound on tracked keys across all shards.
pub(crate) const MAX_KEYS: usize = 4096;
/// Number of independent limiter shards.
pub(crate) const LIMIT_SHARDS: usize = 16;
pub(crate) const PER_SHARD_MAX: usize = MAX_KEYS / LIMIT_SHARDS;
/// One slot per shard is reserved for that limiter's stable overflow state.
pub(crate) const PER_SHARD_REGULAR_MAX: usize = PER_SHARD_MAX - 1;
/// Maximum oldest entries a request-time cleanup may examine.
pub(crate) const CLEANUP_BUDGET: usize = 8;

/// Deterministically select the shard which owns a limiter key.
pub(crate) fn shard_idx(key: &str) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % LIMIT_SHARDS
}

/// Recency index for one shard's entries.
#[derive(Default)]
pub(crate) struct TouchOrder {
    oldest: BTreeMap<u64, String>,
    touches: HashMap<String, u64>,
    next_touch: u64,
}

impl TouchOrder {
    /// Mark an entry as most recently used, replacing its former token.
    ///
    /// This clones the key string into both LRU indexes (`oldest` and
    /// `touches`) on every touch. Deliberate simplicity: the two short-lived
    /// clones per limited request were measured as acceptable next to the
    /// limiter's own hashing, so no index-by-identity structure is warranted.
    pub(crate) fn touch(&mut self, key: &str) {
        if let Some(previous_touch) = self.touches.remove(key) {
            self.oldest.remove(&previous_touch);
        }
        self.next_touch = self.next_touch.wrapping_add(1);
        if self.next_touch == 0 {
            self.next_touch = 1;
        }
        self.oldest.insert(self.next_touch, key.to_string());
        self.touches.insert(key.to_string(), self.next_touch);
    }

    /// Remove and return the current oldest entry, if any.
    pub(crate) fn pop_oldest(&mut self) -> Option<(u64, String)> {
        let entry = self.oldest.pop_first()?;
        self.touches.remove(&entry.1);
        Some(entry)
    }

    /// Restore an entry that did not meet its limiter-specific eviction rule.
    pub(crate) fn restore(&mut self, touch: u64, key: String) {
        self.oldest.insert(touch, key.clone());
        self.touches.insert(key, touch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_replaces_an_entries_oldest_token() {
        let mut order = TouchOrder::default();
        order.touch("first");
        order.touch("second");
        order.touch("first");

        assert_eq!(order.pop_oldest(), Some((2, "second".into())));
        assert_eq!(order.pop_oldest(), Some((3, "first".into())));
        assert_eq!(order.pop_oldest(), None);
    }

    #[test]
    fn restored_entry_remains_available_for_later_bounded_cleanup() {
        let mut order = TouchOrder::default();
        order.touch("active");
        let popped = order.pop_oldest().unwrap();
        order.restore(popped.0, popped.1.clone());
        assert_eq!(order.pop_oldest(), Some(popped));
    }

    #[test]
    fn different_keys_can_select_independent_shards() {
        let first = (0..10_000).map(|i| format!("key-{i}")).next().unwrap();
        let second = (1..10_000)
            .map(|i| format!("key-{i}"))
            .find(|key| shard_idx(key) != shard_idx(&first))
            .unwrap();
        assert_ne!(shard_idx(&first), shard_idx(&second));
    }
}
