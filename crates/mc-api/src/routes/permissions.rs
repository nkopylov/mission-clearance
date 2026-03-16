use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use mc_core::delegation::DelegationEdge;
use mc_core::id::{DelegationEdgeId, GrantId, PrincipalId};
use serde::Serialize;

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/delegations", post(create_delegation))
        .route("/delegations/from/{principal_id}", get(get_delegations_from))
        .route("/delegations/to/{principal_id}", get(get_delegations_to))
        .route("/delegations/{id}", delete(revoke_delegation))
        .route("/grants", post(create_grant))
        .route("/grants/{id}/consume", post(consume_grant))
}

#[derive(Serialize)]
pub struct DelegationResponse {
    pub id: String,
    pub from: String,
    pub to: String,
    pub revoked: bool,
}

impl From<&DelegationEdge> for DelegationResponse {
    fn from(e: &DelegationEdge) -> Self {
        Self {
            id: e.id.to_string(),
            from: e.from.to_string(),
            to: e.to.to_string(),
            revoked: e.revoked,
        }
    }
}

#[derive(Serialize)]
pub struct ConsumeResponse {
    pub consumed: bool,
}

async fn create_delegation(
    State(state): State<Arc<AppState>>,
    Json(edge): Json<DelegationEdge>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    store
        .add_delegation_edge(&edge)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(DelegationResponse::from(&edge)))
}

async fn get_delegations_from(
    State(state): State<Arc<AppState>>,
    Path(principal_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let pid = principal_id
        .parse::<uuid::Uuid>()
        .map(PrincipalId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid principal id".into()))?;

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    let edges = store
        .get_delegations_from(&pid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let responses: Vec<DelegationResponse> = edges.iter().map(DelegationResponse::from).collect();
    Ok(Json(responses))
}

async fn get_delegations_to(
    State(state): State<Arc<AppState>>,
    Path(principal_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let pid = principal_id
        .parse::<uuid::Uuid>()
        .map(PrincipalId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid principal id".into()))?;

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    let edges = store
        .get_delegations_to(&pid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let responses: Vec<DelegationResponse> = edges.iter().map(DelegationResponse::from).collect();
    Ok(Json(responses))
}

async fn revoke_delegation(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let eid = id
        .parse::<uuid::Uuid>()
        .map(DelegationEdgeId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid delegation edge id".into()))?;

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    store
        .revoke_delegation_edge(&eid)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok(Json(serde_json::json!({"status": "revoked"})))
}

async fn create_grant(
    State(state): State<Arc<AppState>>,
    Json(grant): Json<mc_core::delegation::BoundedAuthorization>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    store
        .add_bounded_authorization(&grant)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "id": grant.id.to_string(),
        "status": "created"
    })))
}

async fn consume_grant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let gid = id
        .parse::<uuid::Uuid>()
        .map(GrantId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid grant id".into()))?;

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    let consumed = store
        .try_consume_bounded(&gid)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok(Json(ConsumeResponse { consumed }))
}
