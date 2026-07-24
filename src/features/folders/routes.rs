use axum::{
    Router,
    routing::{get, post},
};

use super::handlers;
use crate::app_state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/folders",
            post(handlers::create_folder).get(handlers::list_folders),
        )
        .route(
            "/folders/{folder_id}",
            get(handlers::get_folder)
                .patch(handlers::update_folder)
                .delete(handlers::delete_folder),
        )
}
