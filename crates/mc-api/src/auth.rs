use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};

/// Middleware that requires a non-empty `X-API-Key` header.
///
/// For now, any non-empty key is accepted. Real validation (e.g. against a
/// database of API keys) will be added later.
pub async fn require_api_key(req: Request, next: Next) -> Result<Response, StatusCode> {
    if req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .filter(|k| !k.is_empty())
        .is_some()
    {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
