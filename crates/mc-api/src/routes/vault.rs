use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use mc_core::resource::ResourcePattern;
use mc_core::vault::SecretType;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// Build the vault sub-router.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/entries", post(add_entry))
        .route("/entries", get(list_entries))
        .route("/entries/{id}/rotate", post(rotate_entry))
        .route("/entries/{id}", delete(revoke_entry))
}

// ---------- DTOs ----------

#[derive(Deserialize)]
pub struct AddEntryRequest {
    pub name: String,
    pub secret_type: String,
    pub value: String,
    #[serde(default)]
    pub bound_to: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct VaultEntryResponse {
    pub id: String,
    pub name: String,
    pub secret_type: String,
    pub revoked: bool,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct RotateRequest {
    pub new_value: String,
}

// ---------- Helpers ----------

fn parse_secret_type(s: &str) -> Result<SecretType, String> {
    match s {
        "ApiKey" => Ok(SecretType::ApiKey),
        "BearerToken" => Ok(SecretType::BearerToken),
        "Certificate" => Ok(SecretType::Certificate),
        "ConnectionString" => Ok(SecretType::ConnectionString),
        "Password" => Ok(SecretType::Password),
        "SshKey" => Ok(SecretType::SshKey),
        "Custom" => Ok(SecretType::Custom),
        _ => Err(format!("unknown secret type: {s}")),
    }
}

// ---------- Handlers ----------

async fn add_entry(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddEntryRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let secret_type = parse_secret_type(&body.secret_type)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let bound_to: HashSet<ResourcePattern> = body
        .bound_to
        .iter()
        .map(|s| {
            ResourcePattern::new(s)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid resource pattern: {e}")))
        })
        .collect::<Result<_, _>>()?;

    let vault = state.vault.lock().unwrap();
    let id = vault
        .add(&body.name, secret_type, &body.value, bound_to)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "id": id.to_string() })))
}

async fn list_entries(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let vault = state.vault.lock().unwrap();
    let entries = vault
        .list()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let response: Vec<VaultEntryResponse> = entries
        .iter()
        .map(|e| VaultEntryResponse {
            id: e.id.to_string(),
            name: e.name.clone(),
            secret_type: format!("{:?}", e.secret_type),
            revoked: e.revoked,
            created_at: e.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(response))
}

async fn rotate_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<RotateRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let entry_id = uuid::Uuid::parse_str(&id)
        .map(mc_core::id::VaultEntryId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid vault entry id".to_string()))?;

    let vault = state.vault.lock().unwrap();
    vault
        .rotate(&entry_id, &body.new_value)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "rotated" })))
}

async fn revoke_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let entry_id = uuid::Uuid::parse_str(&id)
        .map(mc_core::id::VaultEntryId::from_uuid)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid vault entry id".to_string()))?;

    let vault = state.vault.lock().unwrap();
    vault
        .revoke(&entry_id)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({ "status": "revoked" })))
}
