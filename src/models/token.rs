use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum TokenStandard {
    Erc20,
    Erc721,
    Erc1155,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Ethereum,
    Polygon,
    Arbitrum,
}

/// POST /v1/tokens — deploy a new token contract
#[derive(Debug, Deserialize, Validate)]
pub struct DeployTokenRequest {
    pub standard: TokenStandard,
    pub network: Network,
    #[validate(length(min = 1, max = 64))]
    pub name: Option<String>,
    #[validate(length(min = 1, max = 11))]
    pub symbol: Option<String>,
    #[validate(range(min = 0, max = 18))]
    pub decimals: Option<u8>,
    pub supply: Option<u64>,
    #[validate(length(min = 42, max = 42))]
    pub owner_address: String,
    pub metadata_uri: Option<String>,
    pub idempotency_key: Option<String>,
}

/// POST /v1/tokens/{address}/mint
#[derive(Debug, Deserialize, Validate)]
pub struct MintRequest {
    pub network: Network,
    pub standard: TokenStandard,
    #[validate(length(min = 42, max = 42))]
    pub to: String,
    pub amount: Option<String>, // ERC-20: amount in wei; ERC-721: ignored
    pub idempotency_key: Option<String>,
}

/// POST /v1/tokens/{address}/burn
#[derive(Debug, Deserialize, Validate)]
pub struct BurnRequest {
    pub network: Network,
    pub standard: TokenStandard,
    #[validate(length(min = 42, max = 42))]
    pub from: String,
    pub amount: Option<String>,
    pub idempotency_key: Option<String>,
}

/// POST /v1/tokens/{address}/pause
/// POST /v1/tokens/{address}/unpause
#[derive(Debug, Deserialize, Validate)]
pub struct PauseRequest {
    pub network: Network,
    pub standard: TokenStandard,
    pub idempotency_key: Option<String>,
}

/// POST /v1/tokens/{address}/transfer
#[derive(Debug, Deserialize, Validate)]
pub struct TransferRequest {
    pub network: Network,
    pub standard: TokenStandard,
    #[validate(length(min = 42, max = 42))]
    pub to: String,
    pub amount: Option<String>,
    pub idempotency_key: Option<String>,
}

/// Async operation response (operations are queued via RabbitMQ)
#[derive(Debug, Serialize)]
pub struct OperationResponse {
    pub operation_id: String,
    pub status: String, // "queued"
    pub message: String,
}
