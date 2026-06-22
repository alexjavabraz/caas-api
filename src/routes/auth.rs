use axum::{extract::State, routing::post, Json, Router};
use regex::Regex;
use std::sync::OnceLock;
use validator::Validate;

use crate::{
    errors::{ApiError, ApiResult},
    models::auth::{LoginRequest, LoginResponse, NewClientCredentials, RegisterRequest, TokenRequest},
    services::auth,
    AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/token", post(token))
        .route("/register", post(register))
        .route("/developer/login", post(developer_login))
}

// ── Validation helpers ────────────────────────────────────────────────────────

static INJECTION_RE: OnceLock<Regex> = OnceLock::new();

fn injection_re() -> &'static Regex {
    INJECTION_RE.get_or_init(|| {
        // A03 — rejects HTML tags, javascript: URI, event handlers, SQL DDL keywords,
        // path traversal sequences, and numeric HTML entities
        Regex::new(
            r"(?i)(<[^>]+>|javascript:|on\w+=|\b(?:DROP|SELECT|INSERT|UPDATE|DELETE|UNION|EXEC|CREATE|ALTER|TRUNCATE)\b|\.\.[/\\]|&#x)",
        )
        .expect("injection regex")
    })
}

/// A03 — reject name values that contain injection patterns.
fn validate_safe_text(value: &str) -> ApiResult<()> {
    if injection_re().is_match(value) {
        return Err(ApiError::Validation("Input contains invalid characters".into()));
    }
    Ok(())
}

/// A04 — password must contain uppercase, lowercase, digit, and special character.
fn validate_password_strength(password: &str) -> ApiResult<()> {
    let has_upper   = password.chars().any(|c| c.is_uppercase());
    let has_lower   = password.chars().any(|c| c.is_lowercase());
    let has_digit   = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !has_upper || !has_lower || !has_digit || !has_special {
        return Err(ApiError::Validation(
            "Password must contain at least one uppercase letter, one lowercase letter, \
             one digit, and one special character"
                .into(),
        ));
    }
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn token(
    State(state): State<AppState>,
    Json(body): Json<TokenRequest>,
) -> ApiResult<Json<crate::models::auth::TokenResponse>> {
    if body.grant_type != "client_credentials" {
        return Err(ApiError::Validation(
            "grant_type must be 'client_credentials'".into(),
        ));
    }

    let resp = auth::authenticate(&body, &state.config.jwt_secret, &state.db.pool)
        .await
        .map_err(|_| ApiError::Unauthorized)?;

    Ok(Json(resp))
}

async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> ApiResult<Json<NewClientCredentials>> {
    // A07 — structural validation (length, email format)
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    // A03 — injection patterns in free-text name field
    validate_safe_text(&body.name)?;

    // A04 — password complexity
    validate_password_strength(&body.password)?;

    auth::register_developer(body, &state.db.pool)
        .await
        .map_err(|e| {
            if e.to_string() == "EMAIL_CONFLICT" {
                ApiError::Conflict("Email already registered".into())
            } else {
                ApiError::Internal(e)
            }
        })
        .map(Json)
}

async fn developer_login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    // A07 — structural validation
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    auth::login_developer(body, &state.config.jwt_secret, &state.db.pool)
        .await
        // A07 — generic error; never reveal whether email or password was wrong
        .map_err(|_| ApiError::Unauthorized)
        .map(Json)
}
