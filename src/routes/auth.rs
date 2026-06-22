use axum::{extract::State, routing::post, Json, Router};
use caas_api::validation::{is_safe_text, is_strong_password};
use validator::Validate;

use crate::{
    errors::{ApiError, ApiResult},
    models::auth::{
        LoginRequest, LoginResponse, NewClientCredentials, RegisterRequest, TokenRequest,
    },
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
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    validate_safe_text(&body.name)?;
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
    body.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    auth::login_developer(body, &state.config.jwt_secret, &state.db.pool)
        .await
        .map_err(|_| ApiError::Unauthorized)
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
