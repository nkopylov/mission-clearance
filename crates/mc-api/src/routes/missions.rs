use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use mc_core::capability::{Capability, Constraints};
use mc_core::id::CapabilityId;
use mc_core::mission::Mission;
use mc_core::operation::Operation;
use mc_core::resource::ResourcePattern;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// Build the missions sub-router.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(create_mission))
        .route("/{id}", get(get_mission))
        .route("/{id}", delete(revoke_mission))
        .route("/{id}/delegate", post(delegate_mission))
        .route("/{id}/tree", get(get_mission_tree))
}

// ---------- DTOs ----------

#[derive(Deserialize)]
pub struct CreateMissionRequest {
    pub goal: String,
    #[serde(default)]
    pub capabilities: Vec<CapabilitySpec>,
    #[serde(default)]
    pub policies: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub struct CapabilitySpec {
    pub resource_pattern: String,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub delegatable: bool,
}

#[derive(Serialize, Deserialize)]
pub struct MissionResponse {
    pub id: String,
    pub token: String,
    pub goal: String,
    pub status: String,
    pub parent: Option<String>,
    pub depth: u32,
    pub created_at: String,
}

#[derive(Serialize)]
struct MissionTreeNode {
    mission: MissionResponse,
    children: Vec<MissionTreeNode>,
}

// ---------- Helpers ----------

fn parse_operation(s: &str) -> Option<Operation> {
    match s {
        "Read" => Some(Operation::Read),
        "Write" => Some(Operation::Write),
        "Execute" => Some(Operation::Execute),
        "Delete" => Some(Operation::Delete),
        "Connect" => Some(Operation::Connect),
        "Delegate" => Some(Operation::Delegate),
        _ => None,
    }
}

fn spec_to_capability(spec: &CapabilitySpec) -> Result<Capability, String> {
    let resource_pattern = ResourcePattern::new(&spec.resource_pattern)
        .map_err(|e| format!("invalid resource pattern: {e}"))?;

    let operations = spec
        .operations
        .iter()
        .map(|s| parse_operation(s).ok_or_else(|| format!("unknown operation: {s}")))
        .collect::<Result<_, _>>()?;

    Ok(Capability {
        id: CapabilityId::new(),
        resource_pattern,
        operations,
        constraints: Constraints::default(),
        delegatable: spec.delegatable,
    })
}

fn mission_to_response(m: &Mission) -> MissionResponse {
    MissionResponse {
        id: m.id.to_string(),
        token: m.token.to_string(),
        goal: m.goal.clone(),
        status: format!("{:?}", m.status),
        parent: m.parent.map(|p| p.to_string()),
        depth: m.depth,
        created_at: m.created_at.to_rfc3339(),
    }
}

// ---------- Handlers ----------

async fn create_mission(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateMissionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let capabilities: Vec<Capability> = body
        .capabilities
        .iter()
        .map(spec_to_capability)
        .collect::<Result<_, _>>()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let policies = body
        .policies
        .iter()
        .map(|s| {
            uuid::Uuid::parse_str(s)
                .map(mc_core::id::PolicyId::from_uuid)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid policy id: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut mgr = state.mission_manager.lock().unwrap();
    let mission = mgr
        .create_root_mission(body.goal, capabilities, policies)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Log the event.
    if let Ok(log) = state.event_log.lock() {
        let _ = log.append(
            mission.id,
            mc_core::trace::TraceEventType::MissionCreated,
            None,
            serde_json::json!({"goal": &mission.goal}),
        );
    }

    Ok(Json(mission_to_response(&mission)))
}

async fn get_mission(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let mission_id = uuid::Uuid::parse_str(&id)
        .map(mc_core::id::MissionId::from_uuid)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let mgr = state.mission_manager.lock().unwrap();
    let mission = mgr.get(&mission_id).ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(mission_to_response(mission)))
}

async fn revoke_mission(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mission_id = uuid::Uuid::parse_str(&id)
        .map(mc_core::id::MissionId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid mission id".to_string()))?;

    let mut mgr = state.mission_manager.lock().unwrap();
    let revoked = mgr
        .revoke(mission_id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    // Log revocation events.
    if let Ok(log) = state.event_log.lock() {
        for mid in &revoked {
            let _ = log.append(
                *mid,
                mc_core::trace::TraceEventType::MissionRevoked,
                None,
                serde_json::json!({"revoked_by": id}),
            );
        }
    }

    let ids: Vec<String> = revoked.iter().map(|m| m.to_string()).collect();
    Ok(Json(serde_json::json!({ "revoked": ids })))
}

async fn delegate_mission(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<CreateMissionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let parent_id = uuid::Uuid::parse_str(&id)
        .map(mc_core::id::MissionId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid parent mission id".to_string()))?;

    let capabilities: Vec<Capability> = body
        .capabilities
        .iter()
        .map(spec_to_capability)
        .collect::<Result<_, _>>()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let policies = body
        .policies
        .iter()
        .map(|s| {
            uuid::Uuid::parse_str(s)
                .map(mc_core::id::PolicyId::from_uuid)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid policy id: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut mgr = state.mission_manager.lock().unwrap();
    let child = mgr
        .delegate(parent_id, body.goal, capabilities, policies)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Log delegation event.
    if let Ok(log) = state.event_log.lock() {
        let _ = log.append(
            child.id,
            mc_core::trace::TraceEventType::MissionDelegated,
            None,
            serde_json::json!({"parent": id, "goal": &child.goal}),
        );
    }

    Ok(Json(mission_to_response(&child)))
}

async fn get_mission_tree(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let mission_id = uuid::Uuid::parse_str(&id)
        .map(mc_core::id::MissionId::from_uuid)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let mgr = state.mission_manager.lock().unwrap();
    let mission = mgr.get(&mission_id).ok_or(StatusCode::NOT_FOUND)?;

    let tree = build_tree(&mgr, mission);
    Ok(Json(tree))
}

fn build_tree(
    mgr: &mc_kernel::manager::MissionManager,
    mission: &Mission,
) -> MissionTreeNode {
    let children = mgr
        .get_children(&mission.id)
        .into_iter()
        .map(|child| build_tree(mgr, child))
        .collect();

    MissionTreeNode {
        mission: mission_to_response(mission),
        children,
    }
}
