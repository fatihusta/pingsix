//! Runtime compiler for the configuration graph authority.
//!
//! Decodes typed resources, validates whole-graph references, prepares DNS
//! material, and compiles immutable `RuntimeSnapshot`s. The graph authority in
//! [`crate::proxy::graph_mutation`] owns pending/committed state, the
//! preparation worker, and publication; this module never initiates I/O that
//! the authority has not already bounded.

mod compile;
mod plan;
mod resources;
#[cfg(test)]
pub(crate) mod test_fixtures;

pub use compile::CandidateSnapshot;
pub use resources::{
    validate_config_set, validate_runtime_form, validate_stored_form, ResourceConfigSet,
};

pub(crate) use plan::prepare_candidate;
