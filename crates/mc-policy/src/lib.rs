pub mod deterministic;
/// Adaptive feedback loop that spawns a sub-agent to update pattern lists.
///
/// # Safety / Production Warning
///
/// This module is gated behind the **`feedback-loop`** Cargo feature (disabled
/// by default) because it:
///
/// 1. Spawns `claude --dangerously-skip-permissions` as a child process.
/// 2. Runs `cargo build` and then `exec()`s into the newly built binary,
///    replacing the running process.
///
/// **Never** enable `feedback-loop` in production, CI, or any environment
/// where untrusted input could reach the disagreement prompt.  It is intended
/// solely for local development experimentation.
#[cfg(feature = "feedback-loop")]
pub mod feedback;
pub mod human;
pub mod llm_judge;
pub mod pipeline;
pub mod taint;
