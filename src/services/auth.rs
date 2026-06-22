use anyhow::Context;
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::auth::{
    Claims, DeveloperClient, NewClientCredentials, TokenRequest, TokenResponse,
};

const TOKEN_EXPIRY_SECS: i64 = 3600; // 1 hour

/// Hash a client secret with SHA-256 for storage.
/// In production consider argon2 — SHA-256 is acceptable for high-entropy random secrets.
pub fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a new random client_id (prefix `cid_`) and client_secret (prefix `sk_`).
#[allow(dead_code)]
pub fn generate_credentials() -> NewClientCredentials {
    let client_id = format!("cid_{}", Uuid::new_v4().simple());
    let secret_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let client_secret = format!("sk_{}", hex::encode(secret_bytes));
    NewClientCredentials {
        client_id,
        client_secret,
    }
}

/// Issue a JWT access token for a verified developer client.
pub fn issue_token(client: &DeveloperClient, jwt_secret: &str) -> anyhow::Result<TokenResponse> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: client.client_id.clone(),
        client_name: client.name.clone(),
        exp: now + TOKEN_EXPIRY_SECS,
        iat: now,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .context("Failed to sign JWT")?;

    Ok(TokenResponse {
        access_token: token,
        token_type: "Bearer".into(),
        expires_in: TOKEN_EXPIRY_SECS as u64,
    })
}

/// Validate a token request and return a TokenResponse or error.
pub async fn authenticate(
    req: &TokenRequest,
    jwt_secret: &str,
    db: &sqlx::PgPool,
) -> anyhow::Result<TokenResponse> {
    if req.grant_type != "client_credentials" {
        anyhow::bail!("grant_type must be 'client_credentials'");
    }

    let client: Option<DeveloperClient> =
        sqlx::query_as("SELECT * FROM developer_clients WHERE client_id = $1 AND is_active = true")
            .bind(&req.client_id)
            .fetch_optional(db)
            .await?;

    let client = client.ok_or_else(|| anyhow::anyhow!("Invalid credentials"))?;

    let provided_hash = hash_secret(&req.client_secret);
    if provided_hash != client.client_secret_hash {
        anyhow::bail!("Invalid credentials");
    }

    issue_token(&client, jwt_secret)
}
