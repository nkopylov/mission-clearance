//! Append-only event log with SHA-256 cryptographic chaining.
//!
//! Provides tamper-evident trace storage and a mission delegation graph
//! for post-hoc auditing of all agent operations.

pub mod event_log;
pub mod graph;
pub mod query;
