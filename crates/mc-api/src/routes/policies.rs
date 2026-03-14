use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use mc_core::operation::{OperationContext, OperationRequest};
use mc_core::policy::EvaluationContext;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// Build the policies sub-router.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(list_policies))
        .route("/test", post(test_policy))
}

// ---------- DTOs ----------

#[derive(Serialize)]
pub struct PolicyInfo {
    pub evaluator_count: usize,
}

#[derive(Deserialize)]
pub struct TestPolicyRequest {
    pub resource: String,
    pub operation: String,
    pub justification: String,
    pub mission_goal: String,
}

#[derive(Serialize)]
pub struct TestPolicyResponse {
    pub decision: String,
    pub reasoning: String,
}

// ---------- Handlers ----------

async fn list_policies(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let info = PolicyInfo {
        evaluator_count: state.policy_pipeline.evaluator_count(),
    };
    Json(info)
}

async fn test_policy(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TestPolicyRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let resource = mc_core::resource::ResourceUri::new(&body.resource)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid resource: {e}")))?;

    let operation = match body.operation.as_str() {
        "Read" => mc_core::operation::Operation::Read,
        "Write" => mc_core::operation::Operation::Write,
        "Execute" => mc_core::operation::Operation::Execute,
        "Delete" => mc_core::operation::Operation::Delete,
        "Connect" => mc_core::operation::Operation::Connect,
        "Delegate" => mc_core::operation::Operation::Delegate,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown operation: {other}"),
            ))
        }
    };

    // Build a synthetic request for dry-run evaluation.
    let request = OperationRequest {
        id: mc_core::id::RequestId::new(),
        mission_id: mc_core::id::MissionId::new(),
        resource,
        operation,
        context: OperationContext::ToolCall {
            tool_name: "dry-run".to_string(),
            arguments: serde_json::json!({}),
        },
        justification: body.justification,
        chain: vec![],
        timestamp: chrono::Utc::now(),
    };

    // Use classifier for classification.
    let classification = mc_kernel::classifier::OperationClassifier::classify(&request);

    let context = EvaluationContext {
        mission_goal: body.mission_goal,
        mission_chain: vec![],
        recent_operations: vec![],
        anomaly_history: vec![],
        executes_session_written_file: false,
    };

    let decision = state
        .policy_pipeline
        .evaluate(&request, &classification, &context);

    Ok(Json(TestPolicyResponse {
        decision: format!("{:?}", decision.kind),
        reasoning: decision.reasoning,
    }))
}
