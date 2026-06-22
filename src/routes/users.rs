use axum::{
    extract::{Path, State},
    routing::post,
    Json, Router,
};
use caas_api::validation::{is_evm_address, is_safe_text};
use uuid::Uuid;
use validator::Validate;

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
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;
    if !is_safe_text(&body.external_id) {
        return Err(ApiError::Validation(
            "external_id contains invalid characters".into(),
        ));
    }

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
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;
    if !is_safe_text(&external_id) {
        return Err(ApiError::Validation(
            "external_id contains invalid characters".into(),
        ));
    }
    if !is_safe_text(&body.currency) {
        return Err(ApiError::Validation(
            "currency contains invalid characters".into(),
        ));
    }

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
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;
    if !is_safe_text(&external_id) {
        return Err(ApiError::Validation(
            "external_id contains invalid characters".into(),
        ));
    }
    if !is_evm_address(&body.contract_address) {
        return Err(ApiError::Validation(
            "contract_address must be a valid EVM address (0x + 40 hex chars)".into(),
        ));
    }

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
