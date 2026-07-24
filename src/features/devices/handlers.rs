use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use http::StatusCode;
use uuid::Uuid;
use validator::Validate;

use crate::app_state::AppState;
use crate::core::error::AppError;
use crate::core::middleware::AuthenticatedUser;

use super::service::DeviceService;

pub async fn list_devices(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AppError> {
    let svc = DeviceService::new(state.db);
    let devices = svc.list_devices(user.user_id, user.device_id).await?;
    Ok(Json(devices))
}

pub async fn list_sessions(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AppError> {
    let svc = DeviceService::new(state.db);
    let sessions = svc.list_sessions(user.user_id, user.session_id).await?;
    Ok(Json(sessions))
}

pub async fn revoke_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(device_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let svc = DeviceService::new(state.db);
    svc.revoke_device(user.user_id, device_id, user.device_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(serde::Deserialize, Validate)]
pub struct UpdateDeviceNameRequest {
    #[validate(length(min = 1, max = 200))]
    pub device_name: String,
}

pub async fn update_device_name(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(device_id): Path<Uuid>,
    Json(req): Json<UpdateDeviceNameRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = DeviceService::new(state.db);
    svc.update_device_name(user.user_id, device_id, &req.device_name)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
