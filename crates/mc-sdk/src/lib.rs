//! Rust SDK for Mission Clearance.
//!
//! Provides an embedded kernel for in-process usage within the Claude Code plugin.

pub mod embedded;

// Re-export key types for convenience.
pub use embedded::EmbeddedKernel;

// Re-export DTO types used by both client and embedded modes.
pub use mc_api::routes::missions::{CapabilitySpec, MissionResponse};
pub use mc_api::routes::operations::OperationDecisionResponse;
pub use mc_api::routes::vault::VaultEntryResponse;

// Re-export core types useful for advanced operation submission.
pub use mc_core::operation::OperationContext;
