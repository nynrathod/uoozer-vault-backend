use std::sync::Arc;

use uoozer_vault_backend::{app_state::AppState, config::Settings, core::db, run};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file BEFORE loading settings
    let _ = dotenvy::dotenv();

    // ── Configuration ──────────────────────────────────────────
    let settings = Arc::new(Settings::load()?);

    // ── Tracing / logging ──────────────────────────────────────
    init_tracing(&settings);

    tracing::info!(
        environment = %settings.environment,
        "starting Uoozer Vault backend"
    );

    // ── Database pool ──────────────────────────────────────────
    let db_pool = db::create_pool(&settings.database).await?;
    sqlx::migrate!("./migrations").run(&db_pool).await?;
    tracing::info!("database migrations applied");

    // ── Application state ──────────────────────────────────────
    let state = AppState::new(settings.clone(), db_pool).await?;

    // ── Build & serve ──────────────────────────────────────────
    let addr = settings.server.socket_addr();
    tracing::info!(%addr, "server listening");

    run(state, addr).await?;

    Ok(())
}

fn init_tracing(settings: &Settings) {
    use tracing_subscriber::{EnvFilter, fmt};

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if settings.environment == "production" {
        fmt()
            .with_env_filter(env_filter)
            .json()
            .with_current_span(true)
            .init();
    } else {
        fmt()
            .with_env_filter(env_filter)
            .pretty()
            .with_target(false)
            .init();
    }
}
