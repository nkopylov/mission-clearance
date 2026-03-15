//! Multi-stage policy pipeline for Mission Clearance.
//!
//! Evaluates operations through a chain of policy stages -- deterministic rules,
//! LLM judge, and human-in-the-loop escalation -- with fail-closed semantics.

pub mod deterministic;
pub mod feedback;
pub mod human;
pub mod llm_judge;
pub mod pipeline;
pub mod taint;
