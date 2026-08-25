use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use http::{HeaderMap, StatusCode, header};
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use super::dto::{BulkCompleteUploadRequest, BulkCreateFilesRequest, BulkCreateFilesResponse};
use crate::app_state::AppState;
use crate::core::error::AppError;
use crate::core::middleware::AuthenticatedUser;

use super::dto::*;
use super::service::FileService;

#[derive(Deserialize)]
pub struct ListFilesQuery {
    pub folder_id: Option<Uuid>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    pub trashed: Option<bool>,
}

#[derive(Deserialize)]
pub struct PrecheckQuery {
    pub plaintext_blake3: String,
    pub total_size: i64,
}

fn default_limit() -> i64 {
    100
}

#[derive(Deserialize)]
pub struct DownloadQuery {
    pub version_id: Option<Uuid>,
}

pub async fn create_file(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<CreateFileRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = FileService::new(&state);
    let resp = svc.create_file(user.user_id, user.device_id, req).await?;
    Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn create_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
    Json(req): Json<CreateFileRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = FileService::new(&state);
    let resp = svc
        .create_version(user.user_id, user.device_id, file_id, req)
        .await?;
    Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn get_file(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let file = svc.get_file(user.user_id, file_id).await?;
    Ok(Json(file))
}

pub async fn list_files(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListFilesQuery>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let files = svc
        .list_files(
            user.user_id,
            q.folder_id,
            q.limit,
            q.offset,
            q.trashed.unwrap_or(false),
        )
        .await?;
    Ok(Json(files))
}

pub async fn update_file(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
    Json(req): Json<UpdateFileRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let file = svc.update_file(user.user_id, file_id, req).await?;
    Ok(Json(file))
}

pub async fn complete_upload(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(_file_id): Path<Uuid>,
    Json(req): Json<CompleteUploadRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    svc.complete_upload(user.user_id, user.device_id, req)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_download_manifest(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
    Query(q): Query<DownloadQuery>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let manifest = svc
        .get_download_manifest(user.user_id, file_id, q.version_id)
        .await?;
    Ok(Json(manifest))
}

pub async fn delete_file(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    svc.delete_file(user.user_id, user.device_id, file_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_versions(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let versions = svc.list_versions(user.user_id, file_id).await?;
    Ok(Json(versions))
}

pub async fn restore_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((file_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    svc.restore_version(user.user_id, user.device_id, file_id, version_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn bulk_delete(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<BulkDeleteRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    svc.bulk_delete(user.user_id, user.device_id, req).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn restore_file(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    svc.restore_file(user.user_id, file_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn permanent_delete_file(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(file_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    svc.permanently_delete_file(user.user_id, file_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Pre-checks dedup and quota before client wastes time encrypting.
pub async fn precheck_upload(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<PrecheckQuery>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let resp = svc
        .precheck_upload(user.user_id, q.plaintext_blake3, q.total_size)
        .await?;
    Ok(Json(resp))
}

/// Cleans up orphaned chunks and DB records when an upload is cancelled.
pub async fn cancel_upload(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((file_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    svc.cancel_upload(user.user_id, file_id, version_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn cleanup_orphaned_uploads(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let deleted = svc.cleanup_orphaned_versions(24).await?;
    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

pub async fn bulk_cancel_uploads(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<BulkCancelRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let cancelled = svc.bulk_cancel_uploads(user.user_id, req.uploads).await?;
    Ok(Json(serde_json::json!({ "cancelled": cancelled })))
}

pub async fn bulk_init_uploads(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<BulkCreateFilesRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = FileService::new(&state);
    let results = svc
        .bulk_init_uploads(user.user_id, user.device_id, req.files)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(BulkCreateFilesResponse { results }),
    ))
}

pub async fn bulk_complete_uploads(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<BulkCompleteUploadRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let resp = svc
        .bulk_complete_uploads(user.user_id, user.device_id, req.uploads)
        .await?;
    Ok(Json(resp))
}

pub async fn create_share(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(item_id): Path<Uuid>,
    Json(req): Json<CreateShareRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let share_id = svc.create_share(user.user_id, item_id, req).await?;
    Ok((StatusCode::CREATED, Json(CreateShareResponse { share_id })))
}

pub async fn get_share(
    State(state): State<AppState>,
    Path(share_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let is_authenticated = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| state.jwt_keys.verify_access_token(token).is_ok())
        .unwrap_or(false);

    let svc = FileService::new(&state);
    let share = svc.get_share(share_id, is_authenticated).await?;
    Ok(Json(share))
}

pub async fn get_shared_file_manifest(
    State(state): State<AppState>,
    Path((share_id, file_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let is_authenticated = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|token| state.jwt_keys.verify_access_token(token).is_ok())
        .unwrap_or(false);

    let svc = FileService::new(&state);
    let manifest = svc
        .get_shared_file_manifest(share_id, file_id, is_authenticated)
        .await?;
    Ok(Json(manifest))
}

pub async fn revoke_share(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(share_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    svc.revoke_share(user.user_id, share_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_shares(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let shares = svc.list_shares(user.user_id).await?;
    Ok(Json(ListSharesResponse { shares }))
}

pub async fn delete_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((file_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    svc.delete_version(user.user_id, file_id, version_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn empty_trash(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AppError> {
    let svc = FileService::new(&state);
    let count = svc.empty_trash(user.user_id).await?;
    Ok(Json(serde_json::json!({ "deleted": count })))
}
