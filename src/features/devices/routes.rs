use axum::{
    Router,
    routing::{get, patch, post},
};

use super::handlers;
use crate::app_state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/devices", get(handlers::list_devices))
        .route("/devices/sessions", get(handlers::list_sessions))
        .route("/devices/{device_id}", patch(handlers::update_device_name))
        .route("/devices/{device_id}/revoke", post(handlers::revoke_device))
}
