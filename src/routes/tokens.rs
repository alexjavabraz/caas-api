use axum::{
    extract::{Path, State},
    Json, Router,
    routing::post,
};
use uuid::Uuid;

use crate::{
    errors::{ApiError, ApiResult},
    models::token::{
        BurnRequest, DeployTokenRequest, MintRequest, OperationResponse, PauseRequest, TransferRequest,
    },
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(deploy))
        .route("/:address/mint", post(mint))
        .route("/:address/burn", post(burn))
        .route("/:address/pause", post(pause))
        .route("/:address/unpause", post(unpause))
        .route("/:address/transfer", post(transfer))
}

async fn deploy(
    State(state): State<AppState>,
    Json(body): Json<DeployTokenRequest>,
) -> ApiResult<Json<OperationResponse>> {
    let idempotency_key = body.idempotency_key.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
    let payload = serde_json::json!({
        "event": "token.creation.requested",
        "idempotencyKey": idempotency_key,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "network": { "name": format!("{:?}", body.network).to_lowercase() },
        "token": {
            "standard": format!("{:?}", body.standard).to_uppercase(),
            "name": body.name,
            "symbol": body.symbol,
            "ownerAddress": body.owner_address,
        },
        "params": {
            "erc20": { "decimals": body.decimals, "supply": body.supply }
        }
    });

    let operation_id = state.mq
        .publish("EXCHANGE_TOKEN_TRANSFER_REQUEST", "token.creation.requested", &payload)
        .await
        .map_err(|e| ApiError::Internal(e))?;

    Ok(Json(OperationResponse {
        operation_id,
        status: "queued".into(),
        message: "Token deployment queued. Poll /v1/operations/{id} for status.".into(),
    }))
}

async fn mint(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Json(body): Json<MintRequest>,
) -> ApiResult<Json<OperationResponse>> {
    let idempotency_key = body.idempotency_key.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
    let payload = serde_json::json!({
        "event": "token.event.requested",
        "idempotencyKey": idempotency_key,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "network": { "name": format!("{:?}", body.network).to_lowercase() },
        "token": { "address": address, "standard": format!("{:?}", body.standard).to_uppercase() },
        "operation": { "type": "mint", "params": { "to": body.to, "amount": body.amount } }
    });

    let operation_id = state.mq
        .publish("TOKEN_EVENT", "token.event.requested", &payload)
        .await
        .map_err(|e| ApiError::Internal(e))?;

    Ok(Json(OperationResponse { operation_id, status: "queued".into(), message: "Mint queued.".into() }))
}

async fn burn(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Json(body): Json<BurnRequest>,
) -> ApiResult<Json<OperationResponse>> {
    let idempotency_key = body.idempotency_key.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
    let payload = serde_json::json!({
        "event": "token.event.requested",
        "idempotencyKey": idempotency_key,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "network": { "name": format!("{:?}", body.network).to_lowercase() },
        "token": { "address": address, "standard": format!("{:?}", body.standard).to_uppercase() },
        "operation": { "type": "burn", "params": { "from": body.from, "amount": body.amount } }
    });

    let operation_id = state.mq
        .publish("TOKEN_EVENT", "token.event.requested", &payload)
        .await
        .map_err(|e| ApiError::Internal(e))?;

    Ok(Json(OperationResponse { operation_id, status: "queued".into(), message: "Burn queued.".into() }))
}

async fn pause(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Json(body): Json<PauseRequest>,
) -> ApiResult<Json<OperationResponse>> {
    let operation_id = enqueue_pause(&state, &address, &body, "pause").await?;
    Ok(Json(OperationResponse { operation_id, status: "queued".into(), message: "Pause queued.".into() }))
}

async fn unpause(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Json(body): Json<PauseRequest>,
) -> ApiResult<Json<OperationResponse>> {
    let operation_id = enqueue_pause(&state, &address, &body, "unpause").await?;
    Ok(Json(OperationResponse { operation_id, status: "queued".into(), message: "Unpause queued.".into() }))
}

async fn transfer(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Json(body): Json<TransferRequest>,
) -> ApiResult<Json<OperationResponse>> {
    let idempotency_key = body.idempotency_key.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
    let payload = serde_json::json!({
        "event": "token.event.requested",
        "idempotencyKey": idempotency_key,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "network": { "name": format!("{:?}", body.network).to_lowercase() },
        "token": { "address": address, "standard": format!("{:?}", body.standard).to_uppercase() },
        "operation": { "type": "transfer", "params": { "to": body.to, "amount": body.amount } }
    });

    let operation_id = state.mq
        .publish("TOKEN_EVENT", "token.event.requested", &payload)
        .await
        .map_err(|e| ApiError::Internal(e))?;

    Ok(Json(OperationResponse { operation_id, status: "queued".into(), message: "Transfer queued.".into() }))
}

async fn enqueue_pause(state: &AppState, address: &str, body: &PauseRequest, op: &str) -> ApiResult<String> {
    let idempotency_key = body.idempotency_key.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
    let payload = serde_json::json!({
        "event": "token.event.requested",
        "idempotencyKey": idempotency_key,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "network": { "name": format!("{:?}", body.network).to_lowercase() },
        "token": { "address": address, "standard": format!("{:?}", body.standard).to_uppercase() },
        "operation": { "type": op }
    });

    state.mq
        .publish("TOKEN_EVENT", "token.event.requested", &payload)
        .await
        .map_err(|e| ApiError::Internal(e))
}
