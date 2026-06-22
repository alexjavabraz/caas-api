use anyhow::Context;
use lapin::{Connection, ConnectionProperties, Channel};
use serde::Serialize;
use uuid::Uuid;

pub struct RabbitMqService {
    connection: Connection,
}

impl RabbitMqService {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let conn = Connection::connect(url, ConnectionProperties::default())
            .await
            .context("Failed to connect to RabbitMQ")?;
        tracing::info!("Connected to RabbitMQ");
        Ok(Self { connection: conn })
    }

    pub async fn channel(&self) -> anyhow::Result<Channel> {
        self.connection.create_channel().await.context("Failed to create RabbitMQ channel")
    }

    pub async fn publish<T: Serialize>(
        &self,
        exchange: &str,
        routing_key: &str,
        payload: &T,
    ) -> anyhow::Result<String> {
        let operation_id = Uuid::new_v4().to_string();
        let body = serde_json::to_vec(payload)?;
        let channel = self.channel().await?;

        channel
            .basic_publish(
                exchange,
                routing_key,
                lapin::options::BasicPublishOptions::default(),
                &body,
                lapin::BasicProperties::default()
                    .with_message_id(operation_id.clone().into())
                    .with_content_type("application/json".into()),
            )
            .await?
            .await?;

        Ok(operation_id)
    }
}
