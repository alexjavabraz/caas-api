use axum::{
    extract::{Extension, Query, State},
    routing::{get, post},
    Json, Router,
};
use caas_api::validation::{is_safe_text, is_strong_password};
use chrono::Utc;
use serde::Deserialize;
use validator::Validate;

use crate::{
    errors::{ApiError, ApiResult},
    models::auth::{
        ChangePasswordRequest, Claims, DeveloperLoginResult, ForgotPasswordRequest,
        ForgotPasswordResponse, LoginRequest, MeResponse, NewClientCredentials,
        RegenerateSaltResponse, RegisterRequest, RequestStats, RotateSecretResponse, TokenRequest,
        TotpConfirmRequest, TotpDisableRequest, TotpSetupResponse, TotpVerifyLoginRequest,
    },
    services::{
        auth::{self, EmailConfig},
        email,
    },
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
        .route("/totp/verify-login", post(totp_verify_login))
}

// ── Protected routes (JWT required — merged into protected router) ────────────

pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/auth/me", get(me))
        .route("/auth/rotate-secret", post(rotate_secret))
        .route("/auth/regenerate-salt", post(regenerate_salt_handler))
        .route("/auth/requests", get(get_requests))
        .route("/auth/totp/setup", post(totp_setup))
        .route("/auth/totp/confirm", post(totp_confirm))
        .route("/auth/totp/disable", post(totp_disable))
        .route("/auth/change-password", post(change_password_handler))
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
) -> ApiResult<Json<DeveloperLoginResult>> {
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    let result = auth::login_developer(body, &state.config.jwt_secret, &state.db.pool)
        .await
        .map_err(|e| {
            if e.to_string() == "EMAIL_NOT_VERIFIED" {
                ApiError::Custom(
                    axum::http::StatusCode::FORBIDDEN,
                    "EMAIL_NOT_VERIFIED",
                    "E-mail not verified. Please check your inbox.".into(),
                )
            } else {
                ApiError::Unauthorized
            }
        })?;

    if let DeveloperLoginResult::Success(ref resp) = result {
        let smtp_host = state.config.smtp_host.clone();
        let smtp_port = state.config.smtp_port;
        let smtp_user = state.config.smtp_username.clone();
        let smtp_pass = state.config.smtp_password.clone();
        let email_from = state.config.email_from.clone();
        let name = resp.developer.name.clone();
        let to = resp.developer.email.clone();
        let time_str = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        tokio::spawn(async move {
            let html = email::login_notification_html(&name, &time_str);
            email::log_if_err(
                email::send(
                    &smtp_host,
                    smtp_port,
                    smtp_user.as_deref(),
                    smtp_pass.as_deref(),
                    &email_from,
                    &to,
                    "Novo acesso à sua conta — CaaS Developer Portal",
                    &html,
                )
                .await,
                "login_notification",
            );
        });
    }

    Ok(Json(result))
}

async fn totp_verify_login(
    State(state): State<AppState>,
    Json(body): Json<TotpVerifyLoginRequest>,
) -> ApiResult<Json<crate::models::auth::LoginResponse>> {
    let resp = auth::totp_verify_login(
        &body.challenge_token,
        &body.code,
        &state.config.jwt_secret,
        &state.db.pool,
    )
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg == "INVALID_TOTP_CODE" || msg == "INVALID_CHALLENGE_TOKEN" {
            ApiError::Unauthorized
        } else {
            ApiError::Internal(e)
        }
    })?;

    let smtp_host = state.config.smtp_host.clone();
    let smtp_port = state.config.smtp_port;
    let smtp_user = state.config.smtp_username.clone();
    let smtp_pass = state.config.smtp_password.clone();
    let email_from = state.config.email_from.clone();
    let name = resp.developer.name.clone();
    let to = resp.developer.email.clone();
    let time_str = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    tokio::spawn(async move {
        let html = email::login_notification_html(&name, &time_str);
        email::log_if_err(
            email::send(
                &smtp_host,
                smtp_port,
                smtp_user.as_deref(),
                smtp_pass.as_deref(),
                &email_from,
                &to,
                "Novo acesso à sua conta — CaaS Developer Portal",
                &html,
            )
            .await,
            "login_notification",
        );
    });

    Ok(Json(resp))
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

async fn totp_setup(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> ApiResult<Json<TotpSetupResponse>> {
    auth::totp_setup(&claims.sub, &state.db.pool)
        .await
        .map_err(ApiError::Internal)
        .map(Json)
}

async fn totp_confirm(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<TotpConfirmRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    auth::totp_confirm(&claims.sub, &body.code, &state.db.pool)
        .await
        .map_err(|e| {
            if e.to_string() == "INVALID_TOTP_CODE" {
                ApiError::Custom(
                    axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                    "INVALID_TOTP_CODE",
                    "Código inválido. Tente novamente.".into(),
                )
            } else {
                ApiError::Internal(e)
            }
        })?;
    Ok(Json(serde_json::json!({ "totp_enabled": true })))
}

async fn totp_disable(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<TotpDisableRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    auth::totp_disable(&claims.sub, &body.code, &state.db.pool)
        .await
        .map_err(|e| {
            if e.to_string() == "INVALID_TOTP_CODE" {
                ApiError::Custom(
                    axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                    "INVALID_TOTP_CODE",
                    "Código inválido. Tente novamente.".into(),
                )
            } else {
                ApiError::Internal(e)
            }
        })?;
    Ok(Json(serde_json::json!({ "totp_enabled": false })))
}

async fn change_password_handler(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<ChangePasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    validate_password_strength(&body.new_password)?;

    auth::change_password(
        &claims.sub,
        &body.current_password,
        &body.new_password,
        &state.db.pool,
    )
    .await
    .map_err(|e| {
        if e.to_string() == "INVALID_CURRENT_PASSWORD" {
            ApiError::Custom(
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_CURRENT_PASSWORD",
                "Senha atual incorreta.".into(),
            )
        } else {
            ApiError::Internal(e)
        }
    })?;

    Ok(Json(
        serde_json::json!({ "message": "Password changed successfully" }),
    ))
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
