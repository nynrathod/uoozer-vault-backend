use axum::Json;
use axum::body::to_bytes;
use axum::extract::State;
use axum::http::StatusCode;
use validator::Validate;

use crate::app_state::AppState;
use crate::core::error::AppError;
use crate::core::extractors::{extract_client_ip, extract_user_agent};
use crate::core::middleware::AuthenticatedUser;

use super::dto::{
    LoginRequest, LogoutRequest, PasswordChangeRequest, PreloginRequest, RefreshRequest,
    SignupCompleteRequest, SignupInitRequest,
};
use super::service::AuthService;

pub async fn prelogin(
    State(state): State<AppState>,
    Json(req): Json<PreloginRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    req.validate()?;
    let svc = AuthService::new(&state);
    let resp = svc.prelogin(&req.email).await?;
    Ok((StatusCode::OK, Json(serde_json::to_value(resp).unwrap())))
}

pub async fn signup_init(
    State(state): State<AppState>,
    Json(req): Json<SignupInitRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    req.validate()?;
    let svc = AuthService::new(&state);
    let resp = svc.signup_init(&req.email).await?;
    Ok((StatusCode::OK, Json(serde_json::to_value(resp).unwrap())))
}

pub async fn signup_complete(
    State(state): State<AppState>,
    Json(req): Json<SignupCompleteRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let svc = AuthService::new(&state);
    let resp = svc.signup_complete(req).await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(resp).unwrap()),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    raw_req: axum::extract::Request,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let ip = extract_client_ip(&raw_req);
    let ua = extract_user_agent(&raw_req);

    let bytes = to_bytes(raw_req.into_body(), 1024 * 1024)
        .await
        .map_err(|_| AppError::BadRequest("failed to read body".to_string()))?;
    let req: LoginRequest = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid JSON: {}", e)))?;

    let svc = AuthService::new(&state);
    let resp = svc.login(req, ip, ua).await?;
    Ok((StatusCode::OK, Json(serde_json::to_value(resp).unwrap())))
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let svc = AuthService::new(&state);
    let resp = svc.refresh(&req.refresh_token).await?;
    Ok((StatusCode::OK, Json(serde_json::to_value(resp).unwrap())))
}

pub async fn logout(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<LogoutRequest>,
) -> Result<StatusCode, AppError> {
    let svc = AuthService::new(&state);
    svc.logout(
        user.user_id,
        user.session_id,
        user.device_id,
        req.revoke_device.unwrap_or(false),
        req.refresh_token,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_password(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<PasswordChangeRequest>,
) -> Result<StatusCode, AppError> {
    req.validate()?;
    let svc = AuthService::new(&state);
    svc.change_password(user.user_id, user.device_id, req)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
