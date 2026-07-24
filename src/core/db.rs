use std::time::Duration;

use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::config::DatabaseConfig;

pub type DbPool = PgPool;

pub async fn create_pool(config: &DatabaseConfig) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.acquire_timeout_seconds))
        .idle_timeout(Some(Duration::from_secs(config.idle_timeout_seconds)))
        .max_lifetime(Some(Duration::from_secs(config.max_lifetime_seconds)))
        .connect(&config.url)
        .await
}
