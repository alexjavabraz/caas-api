mod auth;
mod health;
mod tokens;
mod users;

use crate::{
    middleware::{
        auth::require_auth, idempotency::idempotency, request_tracker::track_request,
        signature::validate_signature,
    },
    AppState,
};
use axum::{middleware, Router};

pub fn router(state: AppState) -> Router<AppState> {
    let protected = Router::new()
        .nest("/tokens", tokens::router())
        .nest("/users", users::router())
        .merge(auth::protected_router())
        // Innermost: idempotency cache
        .route_layer(middleware::from_fn_with_state(state.clone(), idempotency))
        // Signature validation (buffers + rebuilds body; runs after tracking)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            validate_signature,
        ))
        // Request tracking (records all calls including failed signatures)
        .route_layer(middleware::from_fn_with_state(state.clone(), track_request))
        // Outermost: JWT authentication
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .nest("/auth", auth::router())
        .nest("/health", health::router())
        .merge(protected)
}
