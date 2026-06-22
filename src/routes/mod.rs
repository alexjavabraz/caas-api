mod auth;
mod health;
mod tokens;
mod users;

use axum::{middleware, Router};
use crate::{middleware::auth::require_auth, AppState};

pub fn router(state: AppState) -> Router<AppState> {
    let protected = Router::new()
        .nest("/tokens", tokens::router())
        .nest("/users", users::router())
        .route_layer(middleware::from_fn_with_state(state, require_auth));

    Router::new()
        .nest("/auth", auth::router())
        .nest("/health", health::router())
        .merge(protected)
}
