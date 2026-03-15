//! Operation classification, capability checking, and content analysis.
//!
//! The kernel is the central decision point: it classifies incoming operations,
//! verifies that the requesting mission holds a matching capability, and runs
//! content analysis to detect malicious payloads.

pub mod checker;
pub mod classifier;
pub mod content_analyzer;
pub mod manager;
pub mod pipe_chain;
pub mod session_tracker;
pub mod signal_enricher;
