use serde::{Deserialize, Serialize};
use validator::Validate;

/// POST /v1/users — create a user with a managed wallet
#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 1, max = 128))]
    pub external_id: String, // your system's user ID
    #[validate(email)]
    pub email: Option<String>,
    pub network: super::token::Network,
    pub idempotency_key: Option<String>,
}

/// Response after user creation
#[derive(Debug, Serialize)]
pub struct CreateUserResponse {
    pub operation_id: String,
    pub external_id: String,
    pub status: String, // "queued" — wallet provisioned async
}

/// POST /v1/users/{external_id}/fiat-balance
#[derive(Debug, Deserialize, Validate)]
pub struct AddFiatBalanceRequest {
    #[validate(range(min = 1))]
    pub amount: u64, // integer, no decimals
    pub currency: String, // "BRL"
    pub idempotency_key: Option<String>,
}

/// POST /v1/users/{external_id}/token-balance
#[derive(Debug, Deserialize, Validate)]
pub struct AddTokenBalanceRequest {
    pub network: super::token::Network,
    #[validate(length(min = 42, max = 42))]
    pub contract_address: String,
    pub amount: String, // wei string
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BalanceOperationResponse {
    pub operation_id: String,
    pub external_id: String,
    pub status: String,
}
