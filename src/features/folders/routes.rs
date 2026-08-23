use axum::{
    Router,
    routing::{get, post},
};

use super::handlers;
use crate::{app_state::AppState, features::files::handlers::create_share};

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/folders",
            post(handlers::create_folder).get(handlers::list_folders),
        )
        .route("/folders/bulk", post(handlers::create_folders_bulk))
        .route(
            "/folders/{folder_id}",
            get(handlers::get_folder)
                .patch(handlers::update_folder)
                .delete(handlers::delete_folder),
        )
        .route("/folders/{folder_id}/shares", post(create_share))
}
