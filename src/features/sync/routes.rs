use axum::{Router, routing::get};

use super::handlers;
use crate::app_state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/sync/events", get(handlers::sync_stream))
}
