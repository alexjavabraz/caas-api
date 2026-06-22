use axum::{extract::Request, middleware::Next, response::Response};

use crate::{models::auth::Claims, AppState};

/// Record every authenticated request in the `api_requests` table for billing.
pub async fn track_request(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let idem_key = req
        .headers()
        .get("X-Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let claims = req.extensions().get::<Claims>().cloned();

    let response = next.run(req).await;

    let Some(claims) = claims else {
        return response;
    };

    let status_code = response.status().as_u16() as i16;
    let is_replay = response.headers().get("X-Idempotent-Replayed").is_some();
    let pool = state.db.pool.clone();
    let client_id = claims.sub;

    tokio::spawn(async move {
        let result = sqlx::query(
            "INSERT INTO api_requests \
             (client_id, method, path, idempotency_key, is_idempotent_hit, status_code) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&client_id)
        .bind(&method)
        .bind(&path)
        .bind(&idem_key)
        .bind(is_replay)
        .bind(status_code)
        .execute(&pool)
        .await;

        if let Err(e) = result {
            tracing::warn!(error = %e, "Failed to record API request");
        }
    });

    response
}
