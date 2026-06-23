use anyhow::Context;
use chrono::Utc;
use data_encoding::BASE32_NOPAD;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;

use crate::models::auth::{
    ApiRequestRecord, ChallengeClaims, Claims, DeveloperClient, DeveloperInfo,
    DeveloperLoginResult, ForgotPasswordRequest, ForgotPasswordResponse, LoginRequest,
    LoginResponse, MeResponse, NewClientCredentials, RegenerateSaltResponse, RegisterRequest,
    RequestStats, RotateSecretResponse, TokenRequest, TokenResponse, TotpSetupResponse,
};
use crate::services::email;

const TOKEN_EXPIRY_SECS: i64 = 3600;
const BCRYPT_COST: u32 = 12;
const VERIFICATION_TTL_SECS: i64 = 86_400; // 24 h
const CHALLENGE_EXPIRY_SECS: i64 = 300; // 5 min — TOTP challenge window

pub struct EmailConfig<'a> {
    pub smtp_host: &'a str,
    pub smtp_port: u16,
    pub smtp_username: Option<&'a str>,
    pub smtp_password: Option<&'a str>,
    pub email_from: &'a str,
    pub api_base_url: &'a str,
}

/// Hash a high-entropy API client secret with SHA-256.
/// SHA-256 is acceptable here because client secrets are 32 random bytes —
/// they are not user-chosen, so precomputation attacks do not apply.
pub fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a random signing salt (prefix `salt_`).
pub fn generate_salt() -> String {
    let bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    format!("salt_{}", hex::encode(bytes))
}

/// Generate a new random client_id (prefix `cid_`), client_secret (prefix `sk_`), and api_salt.
pub fn generate_credentials() -> NewClientCredentials {
    let client_id = format!("cid_{}", Uuid::new_v4().simple());
    let secret_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    let client_secret = format!("sk_{}", hex::encode(secret_bytes));
    NewClientCredentials {
        client_id,
        client_secret,
        api_salt: generate_salt(),
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
    email_cfg: &EmailConfig<'_>,
) -> anyhow::Result<NewClientCredentials> {
    let creds = generate_credentials();
    let secret_hash = hash_secret(&creds.client_secret);

    let verification_token = Uuid::new_v4().to_string();
    let verification_expires = Utc::now() + chrono::Duration::seconds(VERIFICATION_TTL_SECS);

    // bcrypt is CPU-intensive — run on a blocking thread
    let password = req.password.clone();
    let password_hash = tokio::task::spawn_blocking(move || bcrypt::hash(password, BCRYPT_COST))
        .await
        .context("bcrypt spawn failed")?
        .context("bcrypt hash failed")?;

    let result = sqlx::query(
        "INSERT INTO developer_clients \
         (name, email, client_id, client_secret_hash, password_hash, api_salt, \
          is_email_verified, email_verification_token, email_verification_expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7, $8)",
    )
    .bind(&req.name)
    .bind(req.email.to_lowercase())
    .bind(&creds.client_id)
    .bind(&secret_hash)
    .bind(&password_hash)
    .bind(&creds.api_salt)
    .bind(&verification_token)
    .bind(verification_expires)
    .execute(db)
    .await;

    match result {
        Ok(_) => {
            let verify_url = format!(
                "{}/v1/auth/verify-email?token={}",
                email_cfg.api_base_url, verification_token
            );
            let html = email::verification_html(&req.name, &verify_url);
            email::log_if_err(
                email::send(
                    email_cfg.smtp_host,
                    email_cfg.smtp_port,
                    email_cfg.smtp_username,
                    email_cfg.smtp_password,
                    email_cfg.email_from,
                    &req.email.to_lowercase(),
                    "Confirme seu e-mail — CaaS Developer Portal",
                    &html,
                )
                .await,
                "email_verification_send",
            );
            Ok(creds)
        }
        Err(sqlx::Error::Database(ref e)) if e.code().as_deref() == Some("23505") => {
            Err(anyhow::anyhow!("EMAIL_CONFLICT"))
        }
        Err(e) => Err(e.into()),
    }
}

/// Authenticate a developer with email + password.
/// Returns either a full session or a TOTP challenge when 2FA is enabled.
pub async fn login_developer(
    req: LoginRequest,
    jwt_secret: &str,
    db: &sqlx::PgPool,
) -> anyhow::Result<DeveloperLoginResult> {
    let client: Option<DeveloperClient> =
        sqlx::query_as("SELECT * FROM developer_clients WHERE email = $1 AND is_active = true")
            .bind(req.email.to_lowercase())
            .fetch_optional(db)
            .await?;

    // Always run bcrypt verify to prevent timing-based user enumeration.
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

    if !client.is_email_verified {
        anyhow::bail!("EMAIL_NOT_VERIFIED");
    }

    // If 2FA is enabled issue a short-lived challenge token; the frontend
    // must then call POST /v1/auth/totp/verify-login to get the full JWT.
    if client.totp_enabled {
        let challenge = issue_challenge_token(&client.client_id, jwt_secret)?;
        return Ok(DeveloperLoginResult::TotpChallenge {
            totp_required: true,
            challenge_token: challenge,
        });
    }

    let token_resp = issue_token(&client, jwt_secret)?;
    Ok(DeveloperLoginResult::Success(LoginResponse {
        access_token: token_resp.access_token,
        developer: DeveloperInfo {
            client_id: client.client_id,
            name: client.name,
            email: client.email,
        },
    }))
}

fn issue_challenge_token(client_id: &str, jwt_secret: &str) -> anyhow::Result<String> {
    let now = Utc::now().timestamp();
    let claims = ChallengeClaims {
        sub: client_id.to_string(),
        purpose: "totp_challenge".to_string(),
        exp: now + CHALLENGE_EXPIRY_SECS,
        iat: now,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .context("Failed to sign challenge JWT")
}

fn verify_totp_code(secret_base32: &str, code: &str, email: &str) -> anyhow::Result<bool> {
    let bytes = BASE32_NOPAD
        .decode(secret_base32.to_uppercase().as_bytes())
        .context("Invalid TOTP secret encoding")?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some("CaaS".to_string()),
        email.to_string(),
    )
    .map_err(|e| anyhow::anyhow!("TOTP init: {e}"))?;
    totp.check_current(code).context("TOTP system time error")
}

/// Begin TOTP setup: generate a new secret and persist it (not yet enabled).
pub async fn totp_setup(client_id: &str, db: &sqlx::PgPool) -> anyhow::Result<TotpSetupResponse> {
    let (email,): (String,) =
        sqlx::query_as("SELECT email FROM developer_clients WHERE client_id = $1")
            .bind(client_id)
            .fetch_one(db)
            .await?;

    let secret_bytes: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();
    let secret_base32 = BASE32_NOPAD.encode(&secret_bytes);

    sqlx::query(
        "UPDATE developer_clients SET totp_secret = $1, updated_at = NOW() WHERE client_id = $2",
    )
    .bind(&secret_base32)
    .bind(client_id)
    .execute(db)
    .await?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("CaaS".to_string()),
        email,
    )
    .map_err(|e| anyhow::anyhow!("TOTP init: {e}"))?;

    Ok(TotpSetupResponse {
        otpauth_uri: totp.get_url(),
        totp_enabled: false,
    })
}

/// Confirm a TOTP code and enable 2FA for the account.
pub async fn totp_confirm(client_id: &str, code: &str, db: &sqlx::PgPool) -> anyhow::Result<()> {
    let client: DeveloperClient =
        sqlx::query_as("SELECT * FROM developer_clients WHERE client_id = $1 AND is_active = true")
            .bind(client_id)
            .fetch_one(db)
            .await?;

    let secret = client
        .totp_secret
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TOTP_NOT_INITIALIZED"))?;

    if !verify_totp_code(secret, code, &client.email)? {
        anyhow::bail!("INVALID_TOTP_CODE");
    }

    sqlx::query(
        "UPDATE developer_clients SET totp_enabled = TRUE, updated_at = NOW() WHERE client_id = $1",
    )
    .bind(client_id)
    .execute(db)
    .await?;

    Ok(())
}

/// Verify a TOTP code and disable 2FA.
pub async fn totp_disable(client_id: &str, code: &str, db: &sqlx::PgPool) -> anyhow::Result<()> {
    let client: DeveloperClient =
        sqlx::query_as("SELECT * FROM developer_clients WHERE client_id = $1 AND is_active = true")
            .bind(client_id)
            .fetch_one(db)
            .await?;

    if !client.totp_enabled {
        anyhow::bail!("TOTP_NOT_ENABLED");
    }

    let secret = client
        .totp_secret
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TOTP_NOT_INITIALIZED"))?;

    if !verify_totp_code(secret, code, &client.email)? {
        anyhow::bail!("INVALID_TOTP_CODE");
    }

    sqlx::query(
        "UPDATE developer_clients \
         SET totp_enabled = FALSE, totp_secret = NULL, updated_at = NOW() \
         WHERE client_id = $1",
    )
    .bind(client_id)
    .execute(db)
    .await?;

    Ok(())
}

/// Exchange a TOTP challenge token + code for a full login session.
pub async fn totp_verify_login(
    challenge_token: &str,
    code: &str,
    jwt_secret: &str,
    db: &sqlx::PgPool,
) -> anyhow::Result<LoginResponse> {
    let decoded = decode::<ChallengeClaims>(
        challenge_token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| anyhow::anyhow!("INVALID_CHALLENGE_TOKEN"))?;

    if decoded.claims.purpose != "totp_challenge" {
        anyhow::bail!("INVALID_CHALLENGE_TOKEN");
    }

    let client_id = decoded.claims.sub;

    let client: DeveloperClient =
        sqlx::query_as("SELECT * FROM developer_clients WHERE client_id = $1 AND is_active = true")
            .bind(&client_id)
            .fetch_one(db)
            .await
            .map_err(|_| anyhow::anyhow!("INVALID_CHALLENGE_TOKEN"))?;

    if !client.totp_enabled {
        anyhow::bail!("TOTP_NOT_ENABLED");
    }

    let secret = client
        .totp_secret
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("INVALID_CHALLENGE_TOKEN"))?;

    if !verify_totp_code(secret, code, &client.email)? {
        anyhow::bail!("INVALID_TOTP_CODE");
    }

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
        "SELECT client_id, name, email, is_active, api_salt, totp_enabled, created_at \
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

/// Generate a new signing salt, persist it, and return the plaintext.
pub async fn regenerate_salt(
    client_id: &str,
    db: &sqlx::PgPool,
) -> anyhow::Result<RegenerateSaltResponse> {
    let new_salt = generate_salt();
    sqlx::query(
        "UPDATE developer_clients SET api_salt = $1, updated_at = NOW() WHERE client_id = $2",
    )
    .bind(&new_salt)
    .bind(client_id)
    .execute(db)
    .await?;

    Ok(RegenerateSaltResponse {
        api_salt: new_salt,
        message: "Salt regenerated. Update your integration — the previous salt is now invalid."
            .into(),
    })
}

/// Return total request count and the 50 most recent records for a client.
pub async fn get_request_stats(client_id: &str, db: &sqlx::PgPool) -> anyhow::Result<RequestStats> {
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM api_requests WHERE client_id = $1")
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

    Ok(RequestStats { total, requests })
}

/// Confirm a developer's email address using the token from the verification email.
pub async fn verify_email(token: &str, db: &sqlx::PgPool) -> anyhow::Result<()> {
    let result = sqlx::query(
        "UPDATE developer_clients \
         SET is_email_verified = TRUE, \
             email_verification_token = NULL, \
             email_verification_expires_at = NULL, \
             updated_at = NOW() \
         WHERE email_verification_token = $1 \
           AND email_verification_expires_at > NOW() \
           AND is_email_verified = FALSE",
    )
    .bind(token)
    .execute(db)
    .await?;

    if result.rows_affected() == 0 {
        anyhow::bail!("INVALID_OR_EXPIRED_TOKEN");
    }
    Ok(())
}

/// Reset a developer's password and send a temporary one via email.
pub async fn forgot_password(
    req: &ForgotPasswordRequest,
    db: &sqlx::PgPool,
    email_cfg: &EmailConfig<'_>,
) -> anyhow::Result<ForgotPasswordResponse> {
    let email_lower = req.email.to_lowercase();

    let client: Option<(String, String)> = sqlx::query_as(
        "SELECT client_id, name FROM developer_clients WHERE email = $1 AND is_active = TRUE",
    )
    .bind(&email_lower)
    .fetch_optional(db)
    .await?;

    // Always return success to avoid user enumeration
    if let Some((client_id, name)) = client {
        let temp_password = generate_temp_password();
        let password_clone = temp_password.clone();
        let new_hash =
            tokio::task::spawn_blocking(move || bcrypt::hash(password_clone, BCRYPT_COST))
                .await
                .context("bcrypt spawn")?
                .context("bcrypt hash")?;

        sqlx::query(
            "UPDATE developer_clients SET password_hash = $1, is_email_verified = TRUE, updated_at = NOW() WHERE client_id = $2",
        )
        .bind(&new_hash)
        .bind(&client_id)
        .execute(db)
        .await?;

        let html = email::temp_password_html(&name, &temp_password);
        email::log_if_err(
            email::send(
                email_cfg.smtp_host,
                email_cfg.smtp_port,
                email_cfg.smtp_username,
                email_cfg.smtp_password,
                email_cfg.email_from,
                &email_lower,
                "Sua senha provisória — CaaS Developer Portal",
                &html,
            )
            .await,
            "forgot_password_send",
        );
    }

    Ok(ForgotPasswordResponse {
        message: "Se este e-mail estiver cadastrado, você receberá uma senha provisória em breve."
            .into(),
    })
}

fn generate_temp_password() -> String {
    let suffix: Vec<u8> = (0..8).map(|_| rand::random::<u8>()).collect();
    format!("Tmp@{}", hex::encode(suffix))
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
