use axum::{Json, Router, routing::get};
use serde_json::{json, Value};

pub fn router() -> Router<crate::AppState> {
    Router::new().route("/", get(health))
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
