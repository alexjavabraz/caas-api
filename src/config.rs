use anyhow::Context;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub port: u16,
    pub database_url: String,
    pub rabbitmq_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub sentry_dsn: Option<String>,
    pub environment: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub email_from: String,
    pub portal_base_url: String,
    pub api_base_url: String,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .context("PORT must be a valid port number")?,
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL is required")?,
            rabbitmq_url: std::env::var("RABBITMQ_URL").context("RABBITMQ_URL is required")?,
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
            jwt_secret: std::env::var("JWT_SECRET").context("JWT_SECRET is required")?,
            sentry_dsn: std::env::var("SENTRY_DSN").ok(),
            environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".into()),
            smtp_host: std::env::var("SMTP_HOST")
                .unwrap_or_else(|_| "email-smtp.us-east-1.amazonaws.com".into()),
            smtp_port: std::env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".into())
                .parse()
                .unwrap_or(587),
            smtp_username: std::env::var("SMTP_USERNAME").ok(),
            smtp_password: std::env::var("SMTP_PASSWORD").ok(),
            email_from: std::env::var("EMAIL_FROM")
                .unwrap_or_else(|_| "noreply@tokeniza.online".into()),
            portal_base_url: std::env::var("PORTAL_BASE_URL")
                .unwrap_or_else(|_| "https://developers.tokeniza.online".into()),
            api_base_url: std::env::var("API_BASE_URL")
                .unwrap_or_else(|_| "https://caas.tokeniza.online".into()),
        })
    }

    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }
}
