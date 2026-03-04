use std::sync::{Arc, Mutex};

/// Shared application state for the API server.
///
/// Holds Mutex-protected references to all subsystems. Cloned into each
/// axum handler via `Arc<AppState>`.
pub struct AppState {
    pub mission_manager: Mutex<mc_kernel::manager::MissionManager>,
    pub vault: Mutex<mc_vault::store::VaultStore>,
    pub event_log: Mutex<mc_trace::event_log::EventLog>,
    pub graph: Mutex<mc_trace::graph::MissionGraph>,
    pub policy_pipeline: mc_policy::pipeline::PolicyPipeline,
}

impl AppState {
    /// Create a new `AppState` suitable for testing with in-memory stores.
    pub fn new_for_testing() -> Arc<Self> {
        Arc::new(Self {
            mission_manager: Mutex::new(mc_kernel::manager::MissionManager::new(10)),
            vault: Mutex::new(
                mc_vault::store::VaultStore::new(":memory:", "test-pass").unwrap(),
            ),
            event_log: Mutex::new(mc_trace::event_log::EventLog::new(":memory:").unwrap()),
            graph: Mutex::new(mc_trace::graph::MissionGraph::new(":memory:").unwrap()),
            policy_pipeline: mc_policy::pipeline::PolicyPipeline::new(),
        })
    }
}
