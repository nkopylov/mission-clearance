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

/// Parse a raw JSON context into a typed OperationContext.
///
/// The hook sends context like `{"type": "shell", "command": "rm -rf /"}`.
/// We need to convert this so the classifier can analyze the command.
fn parse_operation_context(ctx: &serde_json::Value, resource_uri: &str) -> OperationContext {
    let ctx_type = ctx.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match ctx_type {
        "shell" => {
            let raw_command = ctx
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Split the command into binary + args for the classifier.
            // The classifier expects Shell { command, args, working_dir }.
            let parts: Vec<&str> = raw_command.splitn(2, ' ').collect();
            let command = parts.first().unwrap_or(&"").to_string();
            let mut args = if parts.len() > 1 {
                vec![parts[1].to_string()]
            } else {
                vec![]
            };
            // If the hook expanded script/package-manager content, append it
            // so the classifier's pattern matching sees the full script body.
            if let Some(script_content) = ctx.get("script_content").and_then(|v| v.as_str()) {
                args.push(script_content.to_string());
            }
            OperationContext::Shell {
                command,
                args,
                working_dir: ctx.get("working_dir").and_then(|v| v.as_str()).map(String::from),
            }
        }
        "http" => {
            let method = ctx
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("GET")
                .to_string();
            OperationContext::Http {
                method,
                headers: vec![],
                body_preview: ctx.get("body").and_then(|v| v.as_str()).map(String::from),
            }
        }
        "database" | "db" => {
            let query = ctx
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let database = ctx
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            OperationContext::Database { query, database }
        }
        "file_write" | "file_edit" => {
            let file_path = ctx
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let content_preview = ctx
                .get("content_preview")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            OperationContext::FileWrite {
                path: file_path,
                content_preview,
            }
        }
        _ => {
            // For file operations and unknown types, infer from resource URI
            if resource_uri.starts_with("shell://") {
                // Fallback: treat justification as command hint
                OperationContext::Shell {
                    command: "unknown".to_string(),
                    args: vec![],
                    working_dir: None,
                }
            } else if resource_uri.starts_with("http://") || resource_uri.starts_with("https://") {
                OperationContext::Http {
                    method: "GET".to_string(),
                    headers: vec![],
                    body_preview: None,
                }
            } else {
                OperationContext::ToolCall {
                    tool_name: ctx_type.to_string(),
                    arguments: ctx.clone(),
                }
            }
        }
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

    // Parse the context JSON into a typed OperationContext so the classifier
    // can detect dangerous patterns (rm -rf, reverse shells, curl exfiltration, etc.)
    let context = parse_operation_context(&body.context, &body.resource);

    // Build the OperationRequest for policy evaluation.
    let op_request = OperationRequest {
        id: request_id,
        mission_id,
        resource,
        operation,
        context,
        justification: body.justification,
        chain: vec![],
        timestamp: chrono::Utc::now(),
    };

    // Classify the operation.
    let mut classification = mc_kernel::classifier::OperationClassifier::classify(&op_request);

    // Enrich signals (e.g. analyze inline code for benign/dangerous patterns).
    let enricher = mc_kernel::signal_enricher::HeuristicEnricher::new();
    mc_kernel::signal_enricher::SignalEnricher::enrich(&enricher, &op_request, &mut classification);

    // Build evaluation context.
    let eval_context = EvaluationContext {
        mission_goal: mission.goal.clone(),
        mission_chain: vec![],
        recent_operations: vec![],
        anomaly_history: vec![],
        executes_session_written_file: false,
    };

    // Drop the manager lock before policy evaluation.
    drop(mgr);

    // Run through the policy pipeline with trace for feedback loop.
    let pipeline_result = state
        .policy_pipeline
        .evaluate_with_trace(&op_request, &classification, &eval_context);

    // Trigger feedback loop if there's a disagreement.
    #[cfg(feature = "feedback-loop")]
    if let Some(ref feedback) = state.feedback_loop {
        feedback.check_and_learn(&pipeline_result.trace, &op_request, &classification);
    }

    let decision = pipeline_result.decision;

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
