use axum::{
    extract::{Path, State},
    routing::post,
    Json, Router,
};
use uuid::Uuid;

use crate::{
    errors::{ApiError, ApiResult},
    models::user::{
        AddFiatBalanceRequest, AddTokenBalanceRequest, BalanceOperationResponse, CreateUserRequest,
        CreateUserResponse,
    },
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_user))
        .route("/:external_id/fiat-balance", post(add_fiat_balance))
        .route("/:external_id/token-balance", post(add_token_balance))
}

async fn create_user(
    State(state): State<AppState>,
    Json(body): Json<CreateUserRequest>,
) -> ApiResult<Json<CreateUserResponse>> {
    let idempotency_key = body
        .idempotency_key
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let payload = serde_json::json!({
        "event": "account.create.requested",
        "idempotencyKey": idempotency_key,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "externalId": body.external_id,
        "email": body.email,
        "network": { "name": format!("{:?}", body.network).to_lowercase() },
    });

    let operation_id = state
        .mq
        .publish(
            "EXCHANGE_ACCOUNT_CREATE_REQUEST",
            "account.create.requested",
            &payload,
        )
        .await
        .map_err(ApiError::Internal)?;

    Ok(Json(CreateUserResponse {
        operation_id,
        external_id: body.external_id,
        status: "queued".into(),
    }))
}

async fn add_fiat_balance(
    State(state): State<AppState>,
    Path(external_id): Path<String>,
    Json(body): Json<AddFiatBalanceRequest>,
) -> ApiResult<Json<BalanceOperationResponse>> {
    let idempotency_key = body
        .idempotency_key
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let payload = serde_json::json!({
        "event": "fiat.balance.add.requested",
        "idempotencyKey": idempotency_key,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "externalId": external_id,
        "amount": body.amount,
        "currency": body.currency,
    });

    let operation_id = state
        .mq
        .publish(
            "EXCHANGE_FIAT_BALANCE_REQUEST",
            "fiat.balance.add.requested",
            &payload,
        )
        .await
        .map_err(ApiError::Internal)?;

    Ok(Json(BalanceOperationResponse {
        operation_id,
        external_id,
        status: "queued".into(),
    }))
}

async fn add_token_balance(
    State(state): State<AppState>,
    Path(external_id): Path<String>,
    Json(body): Json<AddTokenBalanceRequest>,
) -> ApiResult<Json<BalanceOperationResponse>> {
    let idempotency_key = body
        .idempotency_key
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let payload = serde_json::json!({
        "event": "token.balance.add.requested",
        "idempotencyKey": idempotency_key,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "externalId": external_id,
        "network": { "name": format!("{:?}", body.network).to_lowercase() },
        "contractAddress": body.contract_address,
        "amount": body.amount,
    });

    let operation_id = state
        .mq
        .publish(
            "EXCHANGE_TOKEN_BALANCE_REQUEST",
            "token.balance.add.requested",
            &payload,
        )
        .await
        .map_err(ApiError::Internal)?;

    Ok(Json(BalanceOperationResponse {
        operation_id,
        external_id,
        status: "queued".into(),
    }))
}
