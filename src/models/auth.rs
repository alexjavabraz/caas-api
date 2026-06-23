use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DeveloperClient {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub client_id: String,
    pub client_secret_hash: String,
    pub password_hash: String,
    pub api_salt: String,
    pub is_active: bool,
    pub is_email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// POST /v1/auth/forgot-password request body
#[derive(Debug, Deserialize, Validate)]
pub struct ForgotPasswordRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
}

/// POST /v1/auth/forgot-password response
#[derive(Debug, Serialize)]
pub struct ForgotPasswordResponse {
    pub message: String,
}

/// Returned to the developer after registration (one-time — secret is not stored in plaintext)
#[derive(Debug, Serialize)]
pub struct NewClientCredentials {
    pub client_id: String,
    pub client_secret: String,
    /// Signing salt for X-Signature header — generated once and visible in the portal.
    pub api_salt: String,
}

/// JWT claims embedded in access tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub client_name: String,
    pub exp: i64,
    pub iat: i64,
}

/// POST /v1/auth/token request body
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub client_id: String,
    pub client_secret: String,
    pub grant_type: String,
}

/// POST /v1/auth/token response
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// POST /v1/auth/register request body
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 2, max = 100))]
    pub name: String,
    #[validate(email, length(max = 254))]
    pub email: String,
    /// 8–128 chars; strength (uppercase+lowercase+digit+special) validated separately
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

/// POST /v1/auth/developer/login request body
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email, length(max = 254))]
    pub email: String,
    #[validate(length(min = 1, max = 128))]
    pub password: String,
}

/// Developer identity returned in login and /me responses
#[derive(Debug, Serialize)]
pub struct DeveloperInfo {
    pub client_id: String,
    pub name: String,
    pub email: String,
}

/// POST /v1/auth/developer/login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub developer: DeveloperInfo,
}

/// GET /v1/auth/me response
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct MeResponse {
    pub client_id: String,
    pub name: String,
    pub email: String,
    pub is_active: bool,
    pub api_salt: String,
    pub created_at: DateTime<Utc>,
}

/// POST /v1/auth/rotate-secret response (one-time plaintext)
#[derive(Debug, Serialize)]
pub struct RotateSecretResponse {
    pub client_id: String,
    pub client_secret: String,
    pub message: String,
}

/// POST /v1/auth/regenerate-salt response
#[derive(Debug, Serialize)]
pub struct RegenerateSaltResponse {
    pub api_salt: String,
    pub message: String,
}

/// GET /v1/auth/requests response
#[derive(Debug, Serialize)]
pub struct RequestStats {
    pub total: i64,
    pub requests: Vec<ApiRequestRecord>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ApiRequestRecord {
    pub method: String,
    pub path: String,
    pub status_code: i16,
    pub idempotency_key: Option<String>,
    pub is_idempotent_hit: bool,
    pub created_at: DateTime<Utc>,
}
