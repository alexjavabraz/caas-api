mod auth;
mod health;
mod tokens;
mod users;

use crate::{
    middleware::{auth::require_auth, idempotency::idempotency, request_tracker::track_request},
    AppState,
};
use axum::{middleware, Router};

pub fn router(state: AppState) -> Router<AppState> {
    let protected = Router::new()
        .nest("/tokens", tokens::router())
        .nest("/users", users::router())
        .merge(auth::protected_router())
        // Innermost: idempotency cache (runs closest to the handler)
        .route_layer(middleware::from_fn_with_state(state.clone(), idempotency))
        // Middle: request tracking (sees final response including cache-hit header)
        .route_layer(middleware::from_fn_with_state(state.clone(), track_request))
        // Outermost: JWT authentication (sets Claims in extensions first)
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .nest("/auth", auth::router())
        .nest("/health", health::router())
        .merge(protected)
}
