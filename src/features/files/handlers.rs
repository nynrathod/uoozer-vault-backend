use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use http::StatusCode;
use serde::Deserialize;
use uuid::Uuid;

use crate::app_state::AppState;
use crate::core::error::AppError;
use crate::core::middleware::AuthenticatedUser;

use super::dto::*;
use super::service::FileService;

#[derive(Deserialize)]
pub struct ListFilesQuery {
    pub folder_id: Option<Uuid>,
}

pub async fn create_file(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<CreateFileRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(state.db);
    let resp = svc.create_file(user.user_id, req).await?;
    Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn get_file(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(state.db);
    let file = svc.get_file(user.user_id, file_id).await?;
    Ok(Json(file))
}

pub async fn list_files(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListFilesQuery>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(state.db);
    let files = svc.list_files(user.user_id, q.folder_id).await?;
    Ok(Json(files))
}

pub async fn complete_upload(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<CompleteUploadRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(state.db);
    svc.complete_upload(user.user_id, req).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_download_manifest(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(state.db);
    let manifest = svc
        .get_download_manifest(user.user_id, file_id, None)
        .await?;
    Ok(Json(manifest))
}

pub async fn delete_file(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(state.db);
    svc.delete_file(user.user_id, file_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_versions(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(state.db);
    let versions = svc.list_versions(user.user_id, file_id).await?;
    Ok(Json(versions))
}

pub async fn restore_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((file_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(state.db);
    svc.restore_version(user.user_id, file_id, version_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
