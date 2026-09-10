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
    let mut settings = Arc::clone(&settings);
    if settings.jwt_private_key_pem.is_empty() || settings.jwt_private_key_pem == "dev" {
        let dev_key_path = std::path::Path::new("dev_jwt_key.pem");
        let pem = match std::fs::read_to_string(dev_key_path) {
            Ok(existing) => {
                tracing::info!("reusing persisted dev JWT signing key");
                existing
            }
            Err(_) => {
                let (pem, _) =
                    uoozer_vault_backend::core::crypto::JwtKeyPair::generate_dev_keypair();
                std::fs::write(dev_key_path, &pem)?;
                tracing::info!("generated and persisted new dev JWT signing key");
                pem
            }
        };
        let mut s =
            Arc::try_unwrap(settings).expect("settings Arc must be uniquely held at startup");
        s.jwt_private_key_pem = pem;
        settings = Arc::new(s);
    }

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
