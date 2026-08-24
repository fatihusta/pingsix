//! Configuration graph authority: the single owner of stored graph state,
//! whole-graph validation, secret handling, guarded mutations, and (via the
//! preparation worker) last-known-good runtime publication.
//!
//! HTTP parsing and response mapping stay in the admin adapter; concrete etcd
//! I/O stays behind the [`GraphStore`] seam in [`crate::config::etcd`].

mod authority;
mod decode;
mod secrets;
mod state;
mod store;
#[cfg(test)]
mod test_harness;
pub use authority::{ConfigurationGraph, PublicationState, PublicationView};
pub use secrets::{redact, restore_redacted_secrets};
pub use store::{
    CommitRevision, GraphCommit, GraphError, GraphStore, InMemoryGraphStore, ResourceKey,
    ResourceKind, ResourceView, SecretMode, SecretOperation, StoreError, StoredChange, StoredGraph,
    StoredMutation, StoredResource, WatchBatch,
};
#[cfg(test)]
pub(crate) use test_harness::GraphTestHarness;

#[cfg(test)]
mod tests {
    mod authority;
    mod cas_conflict;
    mod worker;
}
