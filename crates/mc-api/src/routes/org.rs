use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use mc_core::id::{OrgPositionId, TeamId};
use mc_core::org::{OrgLevel, OrgPosition, Team};
use serde::Serialize;

use crate::state::AppState;

/// Build the org sub-router.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/positions", post(create_position))
        .route("/positions/{id}", get(get_position))
        .route("/teams", post(create_team))
        .route("/teams/{id}", get(get_team))
}

// ---------- DTOs ----------

#[derive(Serialize)]
pub struct PositionResponse {
    pub id: String,
    pub title: String,
    pub level: OrgLevel,
    pub reports_to: Option<String>,
    pub team: Option<String>,
    pub holder: Option<String>,
}

#[derive(Serialize)]
pub struct TeamResponse {
    pub id: String,
    pub name: String,
    pub parent: Option<String>,
}

// ---------- Handlers ----------

async fn create_position(
    State(state): State<Arc<AppState>>,
    Json(position): Json<OrgPosition>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    store
        .add_org_position(&position)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(PositionResponse {
        id: position.id.to_string(),
        title: position.title,
        level: position.level,
        reports_to: position.reports_to.map(|id| id.to_string()),
        team: position.team.map(|id| id.to_string()),
        holder: position.holder.map(|id| id.to_string()),
    }))
}

async fn get_position(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let oid = id
        .parse::<uuid::Uuid>()
        .map(OrgPositionId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid position id".into()))?;

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    let position = store
        .get_org_position(&oid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "position not found".into()))?;

    Ok(Json(PositionResponse {
        id: position.id.to_string(),
        title: position.title,
        level: position.level,
        reports_to: position.reports_to.map(|id| id.to_string()),
        team: position.team.map(|id| id.to_string()),
        holder: position.holder.map(|id| id.to_string()),
    }))
}

async fn create_team(
    State(state): State<Arc<AppState>>,
    Json(team): Json<Team>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    store
        .add_team(&team)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TeamResponse {
        id: team.id.to_string(),
        name: team.name,
        parent: team.parent.map(|p| p.to_string()),
    }))
}

async fn get_team(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tid = id
        .parse::<uuid::Uuid>()
        .map(TeamId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid team id".into()))?;

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    let team = store
        .get_team(&tid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "team not found".into()))?;

    Ok(Json(TeamResponse {
        id: team.id.to_string(),
        name: team.name,
        parent: team.parent.map(|p| p.to_string()),
    }))
}
