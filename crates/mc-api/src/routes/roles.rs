use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use mc_core::id::{PrincipalId, RoleId};
use mc_core::role::{Role, RoleAssignmentScope};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", post(create_role))
        .route("/{id}", get(get_role))
        .route("/assign", post(assign_role))
        .route("/principal/{principal_id}", get(get_roles_for_principal))
}

#[derive(Serialize)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub permissions_count: usize,
}

impl From<&Role> for RoleResponse {
    fn from(r: &Role) -> Self {
        Self {
            id: r.id.to_string(),
            name: r.name.clone(),
            permissions_count: r.permissions.len(),
        }
    }
}

#[derive(Deserialize)]
pub struct AssignRoleRequest {
    pub principal_id: String,
    pub role_id: String,
    #[serde(default = "default_scope")]
    pub scope: RoleAssignmentScope,
}

fn default_scope() -> RoleAssignmentScope {
    RoleAssignmentScope::Global
}

#[derive(Serialize)]
pub struct AssignmentResponse {
    pub assignment_id: String,
}

#[derive(Serialize)]
pub struct PrincipalRoleEntry {
    pub assignment_id: String,
    pub role_id: String,
    pub scope: RoleAssignmentScope,
}

async fn create_role(
    State(state): State<Arc<AppState>>,
    Json(role): Json<Role>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    store
        .add_role(&role)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(RoleResponse::from(&role)))
}

async fn get_role(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let rid = id
        .parse::<uuid::Uuid>()
        .map(RoleId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid role id".into()))?;

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    let role = store
        .get_role(&rid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "role not found".into()))?;

    Ok(Json(RoleResponse::from(&role)))
}

async fn assign_role(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AssignRoleRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let pid = body
        .principal_id
        .parse::<uuid::Uuid>()
        .map(PrincipalId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid principal id".into()))?;

    let rid = body
        .role_id
        .parse::<uuid::Uuid>()
        .map(RoleId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid role id".into()))?;

    let store = state
        .permission_graph
        .lock()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "lock poisoned".into()))?;

    let assignment_id = store
        .assign_role(&pid, &rid, body.scope, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AssignmentResponse {
        assignment_id: assignment_id.to_string(),
    }))
}

async fn get_roles_for_principal(
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

    let roles = store
        .get_principal_roles(&pid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let entries: Vec<PrincipalRoleEntry> = roles
        .into_iter()
        .map(|(aid, rid, scope)| PrincipalRoleEntry {
            assignment_id: aid.to_string(),
            role_id: rid.to_string(),
            scope,
        })
        .collect();

    Ok(Json(entries))
}
