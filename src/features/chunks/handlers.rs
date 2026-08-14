use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use uuid::Uuid;

use crate::app_state::AppState;
use crate::core::error::AppError;
use crate::core::middleware::AuthenticatedUser;

use super::dto::*;
use super::service::ChunkService;

pub async fn get_resume_info(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(version_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = ChunkService::new(state.db, state.storage.clone());
    let info = svc.get_resume_info(user.user_id, version_id).await?;
    Ok(Json(info))
}

pub async fn verify_chunk(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<VerifyChunkRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = ChunkService::new(state.db, state.storage.clone());
    let resp = svc.verify_chunk(user.user_id, req).await?;
    Ok(Json(resp))
}
