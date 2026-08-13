use axum::{Router, routing::get, routing::post};

use super::handlers;
use crate::app_state::AppState;

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/auth/prelogin", post(handlers::prelogin))
        .route("/auth/signup/init", post(handlers::signup_init))
        .route("/auth/signup/complete", post(handlers::signup_complete))
        .route("/auth/login", post(handlers::login))
        .route("/auth/refresh", post(handlers::refresh))
}

pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/auth/logout", post(handlers::logout))
        .route("/auth/password", post(handlers::change_password))
        .route("/auth/keys", get(handlers::get_keys))
}
