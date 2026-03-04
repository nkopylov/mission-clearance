use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use mc_core::trace::GraphFormat;
use serde::Deserialize;

use crate::state::AppState;

/// Build the trace sub-router.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/events", get(query_events))
        .route("/graph", get(export_graph))
        .route("/anomalies", get(recent_anomalies))
}

// ---------- Query params ----------

#[derive(Deserialize)]
pub struct EventsQuery {
    pub mission: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Deserialize)]
pub struct GraphQuery {
    pub mission: Option<String>,
    pub format: Option<String>,
}

// ---------- Handlers ----------

async fn query_events(
    State(state): State<Arc<AppState>>,
    Query(params): Query<EventsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let log = state.event_log.lock().unwrap();

    let events = if let Some(mission_id_str) = &params.mission {
        let mission_id = uuid::Uuid::parse_str(mission_id_str)
            .map(mc_core::id::MissionId::from_uuid)
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid mission id".to_string()))?;
        log.get_events_for_mission(mission_id)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        let limit = params.limit.unwrap_or(50);
        log.get_recent(limit)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    };

    // Serialize events to JSON values.
    let event_values: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id.to_string(),
                "sequence": e.sequence,
                "timestamp": e.timestamp.to_rfc3339(),
                "mission_id": e.mission_id.to_string(),
                "event_type": e.event_type,
                "parent_event": e.parent_event.map(|p| p.to_string()),
                "payload": e.payload,
            })
        })
        .collect();

    Ok(Json(event_values))
}

async fn export_graph(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GraphQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph = state.graph.lock().unwrap();

    let format = match params.format.as_deref() {
        Some("dot") | None => GraphFormat::Dot,
        Some("json") => GraphFormat::Json,
        Some(other) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unsupported format: {other}"),
            ))
        }
    };

    let output = graph
        .export(format)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(output)
}

async fn recent_anomalies(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let log = state.event_log.lock().unwrap();

    // Get recent events and filter for anomaly types.
    let events = log
        .get_recent(200)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let anomaly_types = [
        mc_core::trace::TraceEventType::TaintDetected,
        mc_core::trace::TraceEventType::GoalDriftDetected,
        mc_core::trace::TraceEventType::PromptInjectionSuspected,
    ];

    let anomalies: Vec<serde_json::Value> = events
        .into_iter()
        .filter(|e| anomaly_types.contains(&e.event_type))
        .map(|e| {
            serde_json::json!({
                "id": e.id.to_string(),
                "sequence": e.sequence,
                "timestamp": e.timestamp.to_rfc3339(),
                "mission_id": e.mission_id.to_string(),
                "event_type": e.event_type,
                "payload": e.payload,
            })
        })
        .collect();

    Ok(Json(anomalies))
}
