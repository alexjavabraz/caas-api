mod config;
mod errors;
mod middleware;
mod models;
mod routes;
mod services;

use axum::http::HeaderValue;
use axum::Router;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;
use crate::services::db::DbService;
use crate::services::rabbitmq::RabbitMqService;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: Arc<DbService>,
    pub mq: Arc<RabbitMqService>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = Arc::new(AppConfig::from_env()?);
    let db = Arc::new(DbService::connect(&config.database_url).await?);
    let mq = Arc::new(RabbitMqService::connect(&config.rabbitmq_url).await?);

    db.run_migrations().await?;

    let state = AppState {
        config: config.clone(),
        db,
        mq,
    };

    let app = Router::new()
        .nest("/v1", routes::router(state.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list([
                    HeaderValue::from_static("https://developers.tokeniza.online"),
                    HeaderValue::from_static("http://localhost:4200"),
                    HeaderValue::from_static("http://localhost"),
                ]))
                .allow_headers(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any),
        )
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("CaaS API listening on {}", addr);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
