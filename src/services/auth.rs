use anyhow::Context;
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::models::auth::{
    ApiRequestRecord, Claims, DeveloperClient, DeveloperInfo, LoginRequest, LoginResponse,
    MeResponse, NewClientCredentials, RegisterRequest, RequestStats, RotateSecretResponse,
    TokenRequest, TokenResponse,
};

const TOKEN_EXPIRY_SECS: i64 = 3600;
const BCRYPT_COST: u32 = 12;

/// Hash a high-entropy API client secret with SHA-256.
/// SHA-256 is acceptable here because client secrets are 32 random bytes —
/// they are not user-chosen, so precomputation attacks do not apply.
pub fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a new random client_id (prefix `cid_`) and client_secret (prefix `sk_`).
pub fn generate_credentials() -> NewClientCredentials {
    let client_id = format!("cid_{}", Uuid::new_v4().simple());
    let secret_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let client_secret = format!("sk_{}", hex::encode(secret_bytes));
    NewClientCredentials {
        client_id,
        client_secret,
    }
}

/// Issue a JWT access token for a developer client (client_credentials or portal session).
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

/// Validate a client_credentials token request.
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

/// Create a new developer account. Returns one-time plaintext credentials.
/// Returns `Err` with the string "EMAIL_CONFLICT" when the email is already taken.
pub async fn register_developer(
    req: RegisterRequest,
    db: &sqlx::PgPool,
) -> anyhow::Result<NewClientCredentials> {
    let creds = generate_credentials();
    let secret_hash = hash_secret(&creds.client_secret);

    // bcrypt is CPU-intensive — run on a blocking thread
    let password = req.password.clone();
    let password_hash = tokio::task::spawn_blocking(move || bcrypt::hash(password, BCRYPT_COST))
        .await
        .context("bcrypt spawn failed")?
        .context("bcrypt hash failed")?;

    let result = sqlx::query(
        "INSERT INTO developer_clients (name, email, client_id, client_secret_hash, password_hash)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&req.name)
    .bind(req.email.to_lowercase())
    .bind(&creds.client_id)
    .bind(&secret_hash)
    .bind(&password_hash)
    .execute(db)
    .await;

    match result {
        Ok(_) => Ok(creds),
        Err(sqlx::Error::Database(ref e)) if e.code().as_deref() == Some("23505") => {
            Err(anyhow::anyhow!("EMAIL_CONFLICT"))
        }
        Err(e) => Err(e.into()),
    }
}

/// Authenticate a developer with email + password, returning a portal JWT.
pub async fn login_developer(
    req: LoginRequest,
    jwt_secret: &str,
    db: &sqlx::PgPool,
) -> anyhow::Result<LoginResponse> {
    let client: Option<DeveloperClient> =
        sqlx::query_as("SELECT * FROM developer_clients WHERE email = $1 AND is_active = true")
            .bind(req.email.to_lowercase())
            .fetch_optional(db)
            .await?;

    // Always run bcrypt verify to prevent timing-based user enumeration.
    // Use a dummy hash when the account does not exist.
    let dummy = "$2b$12$invalidhashforenumerationprotect";
    let stored_hash = client
        .as_ref()
        .map(|c| c.password_hash.as_str())
        .unwrap_or(dummy)
        .to_owned();

    let password = req.password.clone();
    let valid = tokio::task::spawn_blocking(move || bcrypt::verify(password, &stored_hash))
        .await
        .context("bcrypt spawn failed")?
        .unwrap_or(false);

    let client = client
        .filter(|_| valid)
        .ok_or_else(|| anyhow::anyhow!("Invalid credentials"))?;

    let token_resp = issue_token(&client, jwt_secret)?;

    Ok(LoginResponse {
        access_token: token_resp.access_token,
        developer: DeveloperInfo {
            client_id: client.client_id,
            name: client.name,
            email: client.email,
        },
    })
}

/// Fetch a developer's own profile by client_id.
pub async fn get_me(client_id: &str, db: &sqlx::PgPool) -> anyhow::Result<MeResponse> {
    sqlx::query_as(
        "SELECT client_id, name, email, is_active, created_at \
         FROM developer_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_one(db)
    .await
    .map_err(|e| anyhow::anyhow!(e))
}

/// Generate a new client secret, persist its hash, and return the plaintext (one-time).
pub async fn rotate_secret(
    client_id: &str,
    db: &sqlx::PgPool,
) -> anyhow::Result<RotateSecretResponse> {
    let creds = generate_credentials();
    let new_hash = hash_secret(&creds.client_secret);

    sqlx::query(
        "UPDATE developer_clients \
         SET client_secret_hash = $1, updated_at = NOW() \
         WHERE client_id = $2",
    )
    .bind(&new_hash)
    .bind(client_id)
    .execute(db)
    .await?;

    Ok(RotateSecretResponse {
        client_id: client_id.to_string(),
        client_secret: creds.client_secret,
        message: "Secret rotated. Store it now — it will not be shown again.".into(),
    })
}

/// Return request counts and the 50 most-recent records for a developer.
pub async fn get_request_stats(client_id: &str, db: &sqlx::PgPool) -> anyhow::Result<RequestStats> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM api_requests WHERE client_id = $1")
        .bind(client_id)
        .fetch_one(db)
        .await?;

    let requests: Vec<ApiRequestRecord> = sqlx::query_as(
        "SELECT method, path, status_code, idempotency_key, is_idempotent_hit, created_at \
         FROM api_requests WHERE client_id = $1 \
         ORDER BY created_at DESC LIMIT 50",
    )
    .bind(client_id)
    .fetch_all(db)
    .await?;

    Ok(RequestStats {
        total: row.0,
        requests,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_secret_is_deterministic() {
        let h1 = hash_secret("sk_abc123");
        let h2 = hash_secret("sk_abc123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_secret_differs_for_different_inputs() {
        assert_ne!(hash_secret("sk_abc"), hash_secret("sk_xyz"));
    }

    #[test]
    fn generate_credentials_have_correct_prefixes() {
        let creds = generate_credentials();
        assert!(
            creds.client_id.starts_with("cid_"),
            "client_id must start with cid_"
        );
        assert!(
            creds.client_secret.starts_with("sk_"),
            "client_secret must start with sk_"
        );
    }

    #[test]
    fn generate_credentials_are_unique() {
        let a = generate_credentials();
        let b = generate_credentials();
        assert_ne!(a.client_id, b.client_id);
        assert_ne!(a.client_secret, b.client_secret);
    }
}
