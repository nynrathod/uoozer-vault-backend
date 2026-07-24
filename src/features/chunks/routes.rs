use axum::{
    Router,
    routing::{get, post},
};

use super::handlers;
use crate::app_state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/chunks/{version_id}/resume",
            get(handlers::get_resume_info),
        )
        .route("/chunks/verify", post(handlers::verify_chunk))
}
