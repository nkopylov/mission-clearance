use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use mc_core::id::{MissionToken, RequestId};
use mc_core::operation::{Operation, OperationContext, OperationRequest};
use mc_core::policy::{EvaluationContext, PolicyDecisionKind};
use mc_core::resource::ResourceUri;
use mc_core::trace::TraceEventType;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// Build the operations sub-router.
pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/request", post(submit_operation))
}

// ---------- DTOs ----------

#[derive(Deserialize)]
pub struct OperationSubmitRequest {
    pub mission_token: String,
    pub resource: String,
    pub operation: String,
    #[serde(default)]
    pub context: serde_json::Value,
    #[serde(default)]
    pub justification: String,
}

#[derive(Serialize, Deserialize)]
pub struct OperationDecisionResponse {
    pub decision: String,
    pub reasoning: String,
    pub request_id: String,
}

// ---------- Helpers ----------

fn parse_operation(s: &str) -> Result<Operation, String> {
    match s {
        "Read" => Ok(Operation::Read),
        "Write" => Ok(Operation::Write),
        "Execute" => Ok(Operation::Execute),
        "Delete" => Ok(Operation::Delete),
        "Connect" => Ok(Operation::Connect),
        "Delegate" => Ok(Operation::Delegate),
        other => Err(format!("unknown operation: {other}")),
    }
}

// ---------- Handlers ----------

async fn submit_operation(
    State(state): State<Arc<AppState>>,
    Json(body): Json<OperationSubmitRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Parse the mission token.
    let token_uuid = uuid::Uuid::parse_str(&body.mission_token)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid mission token".to_string()))?;
    let token = MissionToken::from_uuid(token_uuid);

    // Resolve the token to a mission.
    let mgr = state.mission_manager.lock().unwrap();
    let mission_id = mgr
        .resolve_token(&token)
        .ok_or((StatusCode::UNAUTHORIZED, "unknown mission token".to_string()))?;

    let mission = mgr
        .get(&mission_id)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "mission not found".to_string()))?;

    if !mission.is_active() {
        return Err((StatusCode::FORBIDDEN, "mission is not active".to_string()));
    }

    // Parse operation and resource.
    let operation = parse_operation(&body.operation)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let resource = ResourceUri::new(&body.resource)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid resource: {e}")))?;

    // Check capabilities.
    let has_capability = mc_kernel::checker::CapabilityChecker::check(
        &mgr,
        &mission_id,
        &resource,
        &operation,
    );

    let request_id = RequestId::new();

    if has_capability.is_none() {
        // Log denied event.
        if let Ok(log) = state.event_log.lock() {
            let _ = log.append(
                mission_id,
                TraceEventType::OperationDenied,
                None,
                serde_json::json!({
                    "resource": body.resource,
                    "operation": body.operation,
                    "reason": "no matching capability"
                }),
            );
        }

        return Ok(Json(OperationDecisionResponse {
            decision: "denied".to_string(),
            reasoning: "No matching capability for this resource and operation".to_string(),
            request_id: request_id.to_string(),
        }));
    }

    // Build the OperationRequest for policy evaluation.
    let op_request = OperationRequest {
        id: request_id,
        mission_id,
        resource,
        operation,
        context: OperationContext::ToolCall {
            tool_name: "api-request".to_string(),
            arguments: body.context,
        },
        justification: body.justification,
        chain: vec![],
        timestamp: chrono::Utc::now(),
    };

    // Classify the operation.
    let classification = mc_kernel::classifier::OperationClassifier::classify(&op_request);

    // Build evaluation context.
    let eval_context = EvaluationContext {
        mission_goal: mission.goal.clone(),
        mission_chain: vec![],
        recent_operations: vec![],
        anomaly_history: vec![],
    };

    // Drop the manager lock before policy evaluation.
    drop(mgr);

    // Run through the policy pipeline.
    let decision = state
        .policy_pipeline
        .evaluate(&op_request, &classification, &eval_context);

    // Log the result.
    let event_type = match decision.kind {
        PolicyDecisionKind::Allow => TraceEventType::OperationAllowed,
        PolicyDecisionKind::Deny => TraceEventType::OperationDenied,
        PolicyDecisionKind::Escalate => TraceEventType::OperationEscalated,
    };

    if let Ok(log) = state.event_log.lock() {
        let _ = log.append(
            mission_id,
            event_type,
            None,
            serde_json::json!({
                "resource": op_request.resource.as_str(),
                "operation": format!("{:?}", op_request.operation),
                "decision": format!("{:?}", decision.kind),
                "reasoning": &decision.reasoning,
            }),
        );
    }

    let decision_str = match decision.kind {
        PolicyDecisionKind::Allow => "allowed",
        PolicyDecisionKind::Deny => "denied",
        PolicyDecisionKind::Escalate => "escalated",
    };

    Ok(Json(OperationDecisionResponse {
        decision: decision_str.to_string(),
        reasoning: decision.reasoning,
        request_id: request_id.to_string(),
    }))
}
