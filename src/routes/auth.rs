use crate::{
    errors::{ApiError, ApiResult},
    models::auth::TokenRequest,
    services::auth,
    AppState,
};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};

pub fn router() -> Router<AppState> {
    Router::new().route("/token", post(token))
}

async fn token(
    State(state): State<AppState>,
    Json(body): Json<TokenRequest>,
) -> ApiResult<Json<crate::models::auth::TokenResponse>> {
    if body.grant_type != "client_credentials" {
        return Err(ApiError::Validation(
            "grant_type must be 'client_credentials'".into(),
        ));
    }

    let resp = auth::authenticate(&body, &state.config.jwt_secret, &state.db.pool)
        .await
        .map_err(|_| ApiError::Unauthorized)?;

    Ok(Json(resp))
}
