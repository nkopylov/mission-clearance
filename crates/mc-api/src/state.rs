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
    /// Feedback loop for automatic pattern learning from LLM judge disagreements.
    /// Only available when mc-policy is compiled with the `feedback-loop` feature.
    #[cfg(feature = "feedback-loop")]
    pub feedback_loop: Option<mc_policy::feedback::FeedbackLoop>,
    /// Expected API key for authentication. When `None`, any non-empty key is
    /// accepted (dev mode) with a warning logged on the first request.
    pub expected_api_key: Option<String>,
    /// Permission graph store for principals, roles, delegation edges, etc.
    pub permission_graph: Mutex<mc_graph::store::PermissionGraphStore>,
    /// Delegation policy engine for evaluating delegation requests.
    pub delegation_engine: mc_graph::delegation_engine::DelegationChecker,
}

impl AppState {
    /// Create a new `AppState` suitable for testing with in-memory stores.
    ///
    /// Uses a hardcoded test passphrase and no expected API key (dev mode).
    pub fn new_for_testing() -> Arc<Self> {
        Arc::new(Self {
            mission_manager: Mutex::new(mc_kernel::manager::MissionManager::new(10)),
            vault: Mutex::new(
                mc_vault::store::VaultStore::new(":memory:", "test-pass").unwrap(),
            ),
            event_log: Mutex::new(mc_trace::event_log::EventLog::new(":memory:").unwrap()),
            graph: Mutex::new(mc_trace::graph::MissionGraph::new(":memory:").unwrap()),
            policy_pipeline: mc_policy::pipeline::PolicyPipeline::new(),
            #[cfg(feature = "feedback-loop")]
            feedback_loop: None,
            expected_api_key: None,
            permission_graph: Mutex::new(
                mc_graph::store::PermissionGraphStore::new(":memory:").unwrap(),
            ),
            delegation_engine: mc_graph::delegation_engine::DelegationChecker::permissive(),
        })
    }
}
