use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use deadpool_redis::redis::AsyncCommands;

use crate::{models::auth::Claims, AppState};

/// Cache POST responses in Redis keyed by `X-Idempotency-Key` + `client_id`.
/// Replayed responses are returned as-is with an `X-Idempotent-Replayed: true` header.
pub async fn idempotency(State(state): State<AppState>, req: Request, next: Next) -> Response {
    // Only idempotency-cache POST requests
    if req.method() != axum::http::Method::POST {
        return next.run(req).await;
    }

    let idem_key = req
        .headers()
        .get("X-Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let claims = req.extensions().get::<Claims>().cloned();

    let (idem_key, claims) = match (idem_key, claims) {
        (Some(k), Some(c)) => (k, c),
        _ => return next.run(req).await,
    };

    let redis_key = format!("idempotency:{}:{}", claims.sub, idem_key);

    // Cache hit → return stored response immediately
    if let Ok(mut conn) = state.redis.get().await {
        let cached: Option<String> = conn.get(&redis_key).await.unwrap_or(None);
        if let Some(body_str) = cached {
            tracing::debug!(key = %redis_key, "idempotency cache hit");
            return match Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .header("X-Idempotent-Replayed", "true")
                .body(Body::from(body_str))
            {
                Ok(r) => r,
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
        }
    }

    // Cache miss → process normally
    let response = next.run(req).await;
    let (parts, body) = response.into_parts();

    let bytes = match to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Store in Redis only for 2xx responses
    if parts.status.is_success() {
        if let Ok(mut conn) = state.redis.get().await {
            let body_str = String::from_utf8_lossy(&bytes).to_string();
            let _: Result<(), _> = conn.set_ex(&redis_key, &body_str, 86400u64).await;
        }
    }

    Response::from_parts(parts, Body::from(bytes))
}
