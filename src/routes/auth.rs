use axum::{
    extract::{Extension, Query, State},
    routing::{get, post},
    Json, Router,
};
use caas_api::validation::{is_safe_text, is_strong_password};
use serde::Deserialize;
use validator::Validate;

use crate::{
    errors::{ApiError, ApiResult},
    models::auth::{
        Claims, ForgotPasswordRequest, ForgotPasswordResponse, LoginRequest, LoginResponse,
        MeResponse, NewClientCredentials, RegenerateSaltResponse, RegisterRequest, RequestStats,
        RotateSecretResponse, TokenRequest,
    },
    services::auth::{self, EmailConfig},
    AppState,
};

#[derive(Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
}

// ── Public routes (no JWT required) ──────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/token", post(token))
        .route("/register", post(register))
        .route("/developer/login", post(developer_login))
        .route("/verify-email", get(verify_email))
        .route("/forgot-password", post(forgot_password))
}

// ── Protected routes (JWT required — merged into protected router) ────────────

pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/auth/me", get(me))
        .route("/auth/rotate-secret", post(rotate_secret))
        .route("/auth/regenerate-salt", post(regenerate_salt_handler))
        .route("/auth/requests", get(get_requests))
}

// ── Validation helpers ────────────────────────────────────────────────────────

fn validate_safe_text(value: &str) -> ApiResult<()> {
    if !is_safe_text(value) {
        return Err(ApiError::Validation(
            "Input contains invalid characters".into(),
        ));
    }
    Ok(())
}

fn validate_password_strength(password: &str) -> ApiResult<()> {
    if !is_strong_password(password) {
        return Err(ApiError::Validation(
            "Password must contain at least one uppercase letter, one lowercase letter, \
             one digit, and one special character"
                .into(),
        ));
    }
    Ok(())
}

// ── Public handlers ───────────────────────────────────────────────────────────

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
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    validate_safe_text(&body.name)?;
    validate_password_strength(&body.password)?;

    let email_cfg = email_config(&state);
    auth::register_developer(body, &state.db.pool, &email_cfg)
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
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    auth::login_developer(body, &state.config.jwt_secret, &state.db.pool)
        .await
        .map_err(|e| {
            if e.to_string() == "EMAIL_NOT_VERIFIED" {
                ApiError::Custom(
                    axum::http::StatusCode::FORBIDDEN,
                    "EMAIL_NOT_VERIFIED".into(),
                    "E-mail not verified. Please check your inbox.".into(),
                )
            } else {
                ApiError::Unauthorized
            }
        })
        .map(Json)
}

async fn verify_email(
    State(state): State<AppState>,
    Query(q): Query<VerifyEmailQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let portal = &state.config.portal_base_url;
    match auth::verify_email(&q.token, &state.db.pool).await {
        Ok(_) => {
            axum::response::Redirect::to(&format!("{}/login?verified=true", portal)).into_response()
        }
        Err(_) => axum::response::Redirect::to(&format!("{}/login?error=token_invalid", portal))
            .into_response(),
    }
}

async fn forgot_password(
    State(state): State<AppState>,
    Json(body): Json<ForgotPasswordRequest>,
) -> ApiResult<Json<ForgotPasswordResponse>> {
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    let email_cfg = email_config(&state);
    auth::forgot_password(&body, &state.db.pool, &email_cfg)
        .await
        .map_err(ApiError::Internal)
        .map(Json)
}

fn email_config(state: &AppState) -> EmailConfig<'_> {
    EmailConfig {
        smtp_host: &state.config.smtp_host,
        smtp_port: state.config.smtp_port,
        smtp_username: state.config.smtp_username.as_deref(),
        smtp_password: state.config.smtp_password.as_deref(),
        email_from: &state.config.email_from,
        portal_base_url: &state.config.portal_base_url,
        api_base_url: &state.config.api_base_url,
    }
}

// ── Protected handlers ────────────────────────────────────────────────────────

async fn me(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<Json<MeResponse>> {
    auth::get_me(&claims.sub, &state.db.pool)
        .await
        .map_err(ApiError::Internal)
        .map(Json)
}

async fn rotate_secret(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<Json<RotateSecretResponse>> {
    auth::rotate_secret(&claims.sub, &state.db.pool)
        .await
        .map_err(ApiError::Internal)
        .map(Json)
}

async fn regenerate_salt_handler(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<Json<RegenerateSaltResponse>> {
    auth::regenerate_salt(&claims.sub, &state.db.pool)
        .await
        .map_err(ApiError::Internal)
        .map(Json)
}

async fn get_requests(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<Json<RequestStats>> {
    auth::get_request_stats(&claims.sub, &state.db.pool)
        .await
        .map_err(ApiError::Internal)
        .map(Json)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use caas_api::validation::{is_safe_text, is_strong_password};

    #[test]
    fn safe_text_accepts_normal_name() {
        assert!(is_safe_text("Alice Wonderland"));
        assert!(is_safe_text("João Silva"));
        assert!(is_safe_text("O'Brien"));
    }

    #[test]
    fn safe_text_rejects_html_tag() {
        assert!(!is_safe_text("<script>alert(1)</script>"));
        assert!(!is_safe_text("<img src=x>"));
    }

    #[test]
    fn safe_text_rejects_javascript_uri() {
        assert!(!is_safe_text("javascript:alert(1)"));
    }

    #[test]
    fn safe_text_rejects_event_handler() {
        assert!(!is_safe_text("foo onmouseover=evil()"));
    }

    #[test]
    fn safe_text_rejects_sql_ddl() {
        assert!(!is_safe_text("'; DROP TABLE users; --"));
        assert!(!is_safe_text("UNION SELECT * FROM secrets"));
    }

    #[test]
    fn safe_text_rejects_path_traversal() {
        assert!(!is_safe_text("../../etc/passwd"));
    }

    #[test]
    fn password_strength_accepts_valid_password() {
        assert!(is_strong_password("Secure#99"));
        assert!(is_strong_password("MyP@ssw0rd!"));
    }

    #[test]
    fn password_strength_rejects_missing_uppercase() {
        assert!(!is_strong_password("secure#99"));
    }

    #[test]
    fn password_strength_rejects_missing_lowercase() {
        assert!(!is_strong_password("SECURE#99"));
    }

    #[test]
    fn password_strength_rejects_missing_digit() {
        assert!(!is_strong_password("Secure#Ab"));
    }

    #[test]
    fn password_strength_rejects_missing_special() {
        assert!(!is_strong_password("Secure99A"));
    }
}
