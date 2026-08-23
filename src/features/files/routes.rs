use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use super::handlers;
use crate::app_state::AppState;

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/shares/{share_id}", get(handlers::get_share))
        .route(
            "/shares/{share_id}/files/{file_id}",
            get(handlers::get_shared_file_manifest),
        )
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/files/precheck", get(handlers::precheck_upload))
        .route("/files/bulk-init", post(handlers::bulk_init_uploads))
        .route(
            "/files/bulk-complete",
            post(handlers::bulk_complete_uploads),
        )
        .route(
            "/files/cleanup-orphans",
            post(handlers::cleanup_orphaned_uploads),
        )
        .route("/files/bulk-cancel", post(handlers::bulk_cancel_uploads))
        .route(
            "/files",
            post(handlers::create_file)
                .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
                .get(handlers::list_files),
        )
        .route(
            "/files/{file_id}",
            get(handlers::get_file)
                .patch(handlers::update_file)
                .delete(handlers::delete_file),
        )
        .route("/files/bulk-delete", post(handlers::bulk_delete))
        .route("/files/{file_id}/restore", post(handlers::restore_file))
        .route(
            "/files/{file_id}/permanent",
            axum::routing::delete(handlers::permanent_delete_file),
        )
        .route(
            "/files/{file_id}/versions",
            post(handlers::create_version)
                .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
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
        .route(
            "/files/{file_id}/versions/{version_id}/cancel",
            post(handlers::cancel_upload),
        )
        .route("/files/{file_id}/shares", post(handlers::create_share))
        .route("/shares", get(handlers::list_shares))
        .route(
            "/shares/{share_id}",
            axum::routing::delete(handlers::revoke_share),
        )
}
