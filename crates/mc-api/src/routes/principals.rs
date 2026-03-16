use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
};
use mc_core::id::PrincipalId;
use mc_core::principal::{
    Principal, PrincipalDetails, PrincipalKind, PrincipalStatus, PrincipalTrustLevel,
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(create_principal).get(list_principals))
        .route("/{id}", get(get_principal))
        .route("/{id}/status", put(update_status))
}

#[derive(Deserialize)]
pub struct CreatePrincipalRequest {
    pub kind: PrincipalKind,
    pub display_name: String,
    pub details: PrincipalDetails,
}

#[derive(Serialize)]
pub struct PrincipalResponse {
    pub id: String,
    pub kind: PrincipalKind,
    pub status: PrincipalStatus,
    pub trust_level: PrincipalTrustLevel,
    pub display_name: String,
}

impl From<&Principal> for PrincipalResponse {
    fn from(p: &Principal) -> Self {
        Self {
            id: p.id.to_string(),
            kind: p.kind,
            status: p.status,
            trust_level: p.trust_level,
            display_name: p.display_name.clone(),
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateStatusRequest {
    pub status: PrincipalStatus,
}

async fn create_principal(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreatePrincipalRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let trust_level = match body.kind {
        PrincipalKind::Human => PrincipalTrustLevel::Human,
        PrincipalKind::AiAgent => PrincipalTrustLevel::Agent,
        PrincipalKind::ServiceAccount => PrincipalTrustLevel::ServiceAccount,
        PrincipalKind::Team => PrincipalTrustLevel::Human,
    };

    let principal = Principal {
        id: PrincipalId::new(),
        kind: body.kind,
        status: PrincipalStatus::Active,
        trust_level,
        display_name: body.display_name,
        details: body.details,
        org_position: None,
        teams: vec![],
    };

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    store
        .add_principal(&principal)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(PrincipalResponse::from(&principal)))
}

async fn list_principals(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    let principals = store
        .list_principals()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let responses: Vec<PrincipalResponse> = principals.iter().map(PrincipalResponse::from).collect();
    Ok(Json(responses))
}

async fn get_principal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let pid = id
        .parse::<uuid::Uuid>()
        .map(PrincipalId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid principal id".into()))?;

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    let principal = store
        .get_principal(&pid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "principal not found".into()))?;

    Ok(Json(PrincipalResponse::from(&principal)))
}

async fn update_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<UpdateStatusRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let pid = id
        .parse::<uuid::Uuid>()
        .map(PrincipalId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid principal id".into()))?;

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    store
        .update_principal_status(&pid, body.status)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok(Json(serde_json::json!({"status": "updated"})))
}
