use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;

use crate::state::AppState;

/// Middleware that validates the `X-API-Key` header.
///
/// When `AppState::expected_api_key` is `Some(key)`, the provided header
/// must match using constant-time comparison (to prevent timing attacks).
///
/// When `expected_api_key` is `None` (dev mode), any non-empty key is
/// accepted and a warning is logged.
pub async fn require_api_key(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .filter(|k| !k.is_empty());

    let provided = match provided {
        Some(k) => k,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    match state.expected_api_key.as_deref() {
        Some(expected_key) => {
            // Constant-time comparison to prevent timing attacks.
            // First check lengths (this leaks length info but is standard practice
            // since HTTP headers already expose timing based on length).
            let provided_bytes = provided.as_bytes();
            let expected_bytes = expected_key.as_bytes();
            if provided_bytes.len() != expected_bytes.len()
                || provided_bytes.ct_eq(expected_bytes).unwrap_u8() != 1
            {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        None => {
            // Dev mode: any non-empty key is accepted, but log a warning.
            tracing::warn!(
                "No API key configured (MC_API_KEY not set). Accepting any non-empty key. \
                 Do NOT run in production without setting MC_API_KEY."
            );
        }
    }

    Ok(next.run(req).await)
}
