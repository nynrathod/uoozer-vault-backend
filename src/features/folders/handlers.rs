use super::dto::BulkCreateFoldersRequest;
use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use http::StatusCode;
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use crate::app_state::AppState;
use crate::core::error::AppError;
use crate::core::middleware::AuthenticatedUser;

use super::dto::*;
use super::service::FolderService;

#[derive(Deserialize)]
pub struct ListFoldersQuery {
    pub parent_folder_id: Option<Uuid>,
    pub trashed: Option<bool>,
}

pub async fn create_folder(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<CreateFolderRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = FolderService::new(state.db.clone());
    let folder = svc.create_folder(user.user_id, req, &state).await?;
    Ok((StatusCode::CREATED, Json(folder)))
}

pub async fn get_folder(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(folder_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FolderService::new(state.db);
    let folder = svc.get_folder(user.user_id, folder_id).await?;
    Ok(Json(folder))
}

pub async fn list_folders(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListFoldersQuery>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FolderService::new(state.db);
    let folders = svc
        .list_folders(user.user_id, q.parent_folder_id, q.trashed.unwrap_or(false))
        .await?;
    Ok(Json(folders))
}

pub async fn update_folder(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(folder_id): Path<Uuid>,
    Json(req): Json<UpdateFolderRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = FolderService::new(state.db.clone());
    let folder = svc
        .update_folder(user.user_id, folder_id, req, &state)
        .await?;
    Ok(Json(folder))
}

pub async fn delete_folder(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(folder_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FolderService::new(state.db.clone());
    svc.delete_folder(user.user_id, folder_id, &state).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_folders_bulk(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<BulkCreateFoldersRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = FolderService::new(state.db.clone());
    let folders = svc
        .create_folders_bulk(user.user_id, req.folders, &state)
        .await?;
    Ok((StatusCode::CREATED, Json(folders)))
}

pub async fn get_folder_file_tree(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(folder_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FolderService::new(state.db);
    let tree = svc.get_folder_file_tree(user.user_id, folder_id).await?;
    Ok(Json(tree))
}

pub async fn permanent_delete_folder(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(folder_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FolderService::new(state.db.clone());
    svc.permanent_delete_folder(user.user_id, folder_id, &state)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn restore_folder(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(folder_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FolderService::new(state.db.clone());
    svc.restore_folder(user.user_id, folder_id, &state).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn move_folder(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(folder_id): Path<Uuid>,
    Json(req): Json<MoveFolderRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = FolderService::new(state.db.clone());
    svc.move_folder(user.user_id, folder_id, req.parent_folder_id, &state)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
