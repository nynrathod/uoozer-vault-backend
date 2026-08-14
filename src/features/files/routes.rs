use axum::{
    Router,
    body::Body,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use super::handlers;
use crate::app_state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/files",
            post(handlers::create_file)
                .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB for chunk plans
                .get(handlers::list_files),
        )
        .route(
            "/files/{file_id}",
            get(handlers::get_file)
                .patch(handlers::update_file)
                .delete(handlers::delete_file),
        )
        .route("/files/bulk-delete", post(handlers::bulk_delete))
        .route(
            "/files/{file_id}/versions",
            post(handlers::create_version)
                .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB for chunk plans
                .get(handlers::list_versions),
        )
        .route("/files/{file_id}/complete", post(handlers::complete_upload))
        .route(
            "/files/{file_id}/download",
            get(handlers::get_download_manifest),
        )
        .route(
            "/files/{file_id}/versions/{version_id}/restore",
            post(handlers::restore_version),
        )
}
