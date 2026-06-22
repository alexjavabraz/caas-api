use anyhow::Context;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub port: u16,
    pub database_url: String,
    pub rabbitmq_url: String,
    pub jwt_secret: String,
    pub sentry_dsn: Option<String>,
    pub environment: String,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .context("PORT must be a valid port number")?,
            database_url: std::env::var("DATABASE_URL")
                .context("DATABASE_URL is required")?,
            rabbitmq_url: std::env::var("RABBITMQ_URL")
                .context("RABBITMQ_URL is required")?,
            jwt_secret: std::env::var("JWT_SECRET")
                .context("JWT_SECRET is required")?,
            sentry_dsn: std::env::var("SENTRY_DSN").ok(),
            environment: std::env::var("ENVIRONMENT")
                .unwrap_or_else(|_| "development".into()),
        })
    }

    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }
}
