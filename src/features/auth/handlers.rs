use axum::{
    body::to_bytes,
    extract::{Json as AxumJson, Request, State},
    http::StatusCode,
    response::IntoResponse,
};
use validator::Validate;

use crate::app_state::AppState;
use crate::core::error::AppError;
use crate::core::extractors::{extract_client_ip, extract_user_agent};
use crate::core::middleware::AuthenticatedUser;

use super::dto::*;
use super::service::AuthService;

// ── Prelogin ──────────────────────────────────────────────────

pub async fn prelogin(
    State(state): State<AppState>,
    AxumJson(req): AxumJson<PreloginRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = AuthService::new(&state);
    let resp = svc.prelogin(&req.email).await?;
    Ok((StatusCode::OK, AxumJson(resp)))
}

// ── Signup Init ───────────────────────────────────────────────

pub async fn signup_init(
    State(state): State<AppState>,
    AxumJson(req): AxumJson<SignupInitRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = AuthService::new(&state);
    let resp = svc.signup_init(&req.email).await?;
    Ok((StatusCode::OK, AxumJson(resp)))
}

// ── Signup Complete ───────────────────────────────────────────

pub async fn signup_complete(
    State(state): State<AppState>,
    AxumJson(req): AxumJson<SignupCompleteRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = AuthService::new(&state);
    let resp = svc.signup_complete(req).await?;
    Ok((StatusCode::CREATED, AxumJson(resp)))
}

// ── Login ─────────────────────────────────────────────────────

pub async fn login(
    State(state): State<AppState>,
    raw_req: Request,
) -> Result<impl IntoResponse, AppError> {
    let ip = extract_client_ip(&raw_req);
    let ua = extract_user_agent(&raw_req);

    let bytes = to_bytes(raw_req.into_body(), 1024 * 1024)
        .await
        .map_err(|_| AppError::BadRequest("failed to read body".to_string()))?;

    let req: LoginRequest = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid JSON: {}", e)))?;

    req.validate()?;

    let svc = AuthService::new(&state);
    let resp = svc.login(req, ip, ua).await?;
    Ok((StatusCode::OK, AxumJson(resp)))
}

// ── Refresh ───────────────────────────────────────────────────

pub async fn refresh(
    State(state): State<AppState>,
    AxumJson(req): AxumJson<RefreshRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = AuthService::new(&state);
    let resp = svc.refresh(&req.refresh_token).await?;
    Ok((StatusCode::OK, AxumJson(resp)))
}

// ── Logout ────────────────────────────────────────────────────

pub async fn logout(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    AxumJson(req): AxumJson<LogoutRequest>,
) -> Result<impl IntoResponse, AppError> {
    let svc = AuthService::new(&state);
    svc.logout(
        user.user_id,
        user.device_id,
        user.session_id,
        req.refresh_token,
        req.revoke_device.unwrap_or(false),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Password Change ───────────────────────────────────────────

pub async fn change_password(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    AxumJson(req): AxumJson<PasswordChangeRequest>,
) -> Result<impl IntoResponse, AppError> {
    req.validate()?;
    let svc = AuthService::new(&state);
    svc.change_password(user.user_id, user.device_id, req)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
