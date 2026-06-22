use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use caas_api::validation::{compute_signature, constant_time_eq};
use serde_json::json;

use crate::{models::auth::Claims, AppState};

/// Validate the `X-Signature` header on every authenticated request.
///
/// Formula: `hex(sha256(hex(sha256(salt)) + hex(sha256(hex(sha256(body))))))`
///
/// If the developer's `api_salt` is empty (legacy account), the header is optional.
/// For new developers the header is always required.
pub async fn validate_signature(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let claims = req.extensions().get::<Claims>().cloned();
    let Some(claims) = claims else {
        return next.run(req).await;
    };

    let salt_row: Result<(String,), _> =
        sqlx::query_as("SELECT api_salt FROM developer_clients WHERE client_id = $1")
            .bind(&claims.sub)
            .fetch_one(&state.db.pool)
            .await;

    let Ok((api_salt,)) = salt_row else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": { "code": "UNAUTHORIZED", "message": "Invalid client" } })),
        )
            .into_response();
    };

    // Legacy accounts without a salt skip validation (backward-compatible)
    if api_salt.is_empty() {
        tracing::warn!(client_id = %claims.sub, "request from client with no api_salt — skipping signature check");
        return next.run(req).await;
    }

    let provided = req
        .headers()
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let Some(provided_sig) = provided else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": { "code": "MISSING_SIGNATURE", "message": "X-Signature header is required" } })),
        )
            .into_response();
    };

    // Buffer request body to compute signature (body is rebuilt before passing to handler)
    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let expected = compute_signature(&api_salt, &bytes);

    if !constant_time_eq(&provided_sig, &expected) {
        tracing::warn!(client_id = %claims.sub, "invalid X-Signature");
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                json!({ "error": { "code": "INVALID_SIGNATURE", "message": "X-Signature is invalid" } }),
            ),
        )
            .into_response();
    }

    let req = Request::from_parts(parts, Body::from(bytes));
    next.run(req).await
}
