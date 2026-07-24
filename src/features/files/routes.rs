use axum::{
    Router,
    routing::{get, post},
};

use super::handlers;
use crate::app_state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/files",
            post(handlers::create_file).get(handlers::list_files),
        )
        .route(
            "/files/{file_id}",
            get(handlers::get_file).delete(handlers::delete_file),
        )
        .route("/files/{file_id}/complete", post(handlers::complete_upload))
        .route(
            "/files/{file_id}/download",
            get(handlers::get_download_manifest),
        )
        .route("/files/{file_id}/versions", get(handlers::list_versions))
        .route(
            "/files/{file_id}/versions/{version_id}/restore",
            post(handlers::restore_version),
        )
}
