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
    // Business API routes: full middleware stack including signature validation.
    // These are called by integrators (machine-to-machine) who must sign requests.
    let api_routes = Router::new()
        .nest("/tokens", tokens::router())
        .nest("/users", users::router())
        .route_layer(middleware::from_fn_with_state(state.clone(), idempotency))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            validate_signature,
        ))
        .route_layer(middleware::from_fn_with_state(state.clone(), track_request))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Portal management routes: auth only, no signature required.
    // These are called by the developer portal (email+password session), not by integrators.
    let portal_routes = auth::protected_router()
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .nest("/auth", auth::router())
        .nest("/health", health::router())
        .merge(api_routes)
        .merge(portal_routes)
}
