pub mod app_state;
pub mod config;
pub mod core;
pub mod features;
pub mod storage;

use std::net::SocketAddr;

use app_state::AppState;
use axum::Router;
use tower_http::{
    catch_panic::CatchPanicLayer, compression::CompressionLayer,
    sensitive_headers::SetSensitiveHeadersLayer,
};

pub async fn run(state: AppState, addr: SocketAddr) -> anyhow::Result<()> {
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn build_router(state: AppState) -> Router {
    let cors = state.config.cors.as_cors_layer();

    let public_routes = Router::new()
        .merge(features::auth::routes::public_router())
        .route("/health", axum::routing::get(health_check));

    let protected_routes = Router::new()
        .merge(features::auth::routes::protected_router())
        .merge(features::devices::routes::router())
        .merge(features::folders::routes::router())
        .merge(features::files::routes::router())
        .merge(features::chunks::routes::router())
        .merge(features::sync::routes::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            core::middleware::require_auth,
        ));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(SetSensitiveHeadersLayer::new([
            http::header::AUTHORIZATION,
            http::header::COOKIE,
        ]))
        .layer(CompressionLayer::new())
        // ── Custom Single-Line API Logger ──────────────────
        .layer(axum::middleware::from_fn(core::middleware::api_logger))
        // ────────────────────────────────────────────────────
        .layer(CatchPanicLayer::custom(core::error::handle_panic))
        .layer(cors)
        .with_state(state)
}

async fn health_check() -> &'static str {
    "ok"
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
