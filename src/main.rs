mod config;
mod errors;
mod middleware;
mod models;
mod routes;
mod services;

use anyhow::Context;
use axum::http::HeaderValue;
use axum::Router;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

use sentry::integrations::tracing as sentry_tracing;

use crate::config::AppConfig;
use crate::services::db::DbService;
use crate::services::rabbitmq::RabbitMqService;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: Arc<DbService>,
    pub mq: Arc<RabbitMqService>,
    pub redis: Arc<deadpool_redis::Pool>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let config = Arc::new(AppConfig::from_env()?);

    // Sentry — initialise before the tracing subscriber so the layer is active
    let _sentry_guard = config.sentry_dsn.as_deref().map(|dsn| {
        sentry::init((
            dsn,
            sentry::ClientOptions {
                release: sentry::release_name!(),
                environment: Some(config.environment.clone().into()),
                traces_sample_rate: 1.0,
                ..Default::default()
            },
        ))
    });

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_filter(EnvFilter::from_default_env()),
        )
        .with(sentry_tracing::layer())
        .init();

    let db = Arc::new(DbService::connect(&config.database_url).await?);
    let mq = Arc::new(RabbitMqService::connect(&config.rabbitmq_url).await?);

    let redis_cfg = deadpool_redis::Config::from_url(&config.redis_url);
    let redis = Arc::new(
        redis_cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .context("Failed to create Redis pool")?,
    );

    db.run_migrations().await?;

    let state = AppState {
        config: config.clone(),
        db,
        mq,
        redis,
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
