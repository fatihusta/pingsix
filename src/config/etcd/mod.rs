//! etcd-backed storage adapters for the configuration graph authority.
//!
//! Split into focused submodules; this root only re-exports so every existing
//! `crate::config::etcd::*` path keeps working:
//! - [`sync`]: the list/watch loop mapping etcd responses into graph inputs.
//! - [`store`]: [`EtcdGraphStore`], the guarded-CAS [`crate::proxy::graph_mutation::GraphStore`] adapter.
//! - [`keys`]: namespace canonicalization and physical→logical key mapping.
//! - [`connect`]: endpoint validation, auth/timeouts, and TLS options.

mod connect;
mod keys;
mod store;
mod sync;

pub(crate) use connect::validate_etcd_endpoints;
pub use keys::{canonicalize_prefix, GRAPH_PROTOCOL_VERSION, GRAPH_REVISION_KEY};
pub use store::EtcdGraphStore;
pub use sync::EtcdConfigSync;
