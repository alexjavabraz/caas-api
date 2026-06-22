use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A registered developer client (has client_id + client_secret)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DeveloperClient {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub client_id: String,
    pub client_secret_hash: String, // bcrypt hash — never returned in API responses
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Returned to the developer after registration (one-time — secret is not stored in plaintext)
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct NewClientCredentials {
    pub client_id: String,
    pub client_secret: String, // plaintext — shown once
}

/// JWT claims embedded in access tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // client_id
    pub client_name: String,
    pub exp: i64,
    pub iat: i64,
}

/// POST /v1/auth/token request body
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub client_id: String,
    pub client_secret: String,
    pub grant_type: String, // must be "client_credentials"
}

/// POST /v1/auth/token response
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String, // "Bearer"
    pub expires_in: u64,    // seconds
}
