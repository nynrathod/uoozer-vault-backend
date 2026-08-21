use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use std::net::IpAddr;

use crate::app_state::AppState;
use crate::core::error::AppError;

use crate::core::extractors::extract_client_ip;
use std::time::Instant;

pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = auth_header.ok_or(AppError::Unauthorized)?;

    let claims = state.jwt_keys.verify_access_token(token)?;

    // Rate limit per user ID instead of IP to prevent NAT collisions
    state.api_rate_limiter.check(&claims.sub.to_string())?;

    let is_active: Option<bool> = sqlx::query_scalar(
        "SELECT (d.revoked_at IS NULL AND u.disabled_at IS NULL) 
         FROM devices d 
         JOIN users u ON d.user_id = u.user_id 
         WHERE d.device_id = $1 AND d.user_id = $2",
    )
    .bind(claims.did)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await?;

    if is_active != Some(true) {
        return Err(AppError::Unauthorized);
    }

    let session_active: Option<bool> = sqlx::query_scalar(
        "SELECT (revoked_at IS NULL) FROM sessions WHERE session_id = $1 AND user_id = $2",
    )
    .bind(claims.sid)
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await?;

    if session_active != Some(true) {
        return Err(AppError::Unauthorized);
    }

    req.extensions_mut().insert(AuthenticatedUser {
        user_id: claims.sub,
        device_id: claims.did,
        session_id: claims.sid,
    });

    Ok(next.run(req).await)
}

pub async fn api_logger(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let ip = extract_client_ip(&req)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let start = Instant::now();

    let response = next.run(req).await;

    let latency = start.elapsed();
    let status = response.status().as_u16();
    let latency_ms = latency.as_secs_f64() * 1000.0;

    let now = chrono::Local::now();
    let time_str = now.format("%H:%M:%S").to_string();

    println!(
        "{} | {:>3} | {:>8.3}ms | {} | {:<4} | {}",
        time_str, status, latency_ms, ip, method, path
    );

    response
}

pub async fn add_security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;

    let headers = response.headers_mut();
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        header::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    response
}

pub async fn rate_limit_auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let ip = extract_client_ip(&req)
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    state.auth_rate_limiter.check(ip)?;
    Ok(next.run(req).await)
}

#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedUser {
    pub user_id: uuid::Uuid,
    pub device_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
}

pub struct IpRateLimiter {
    inner: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
}

impl IpRateLimiter {
    pub fn new(per_minute: u32) -> Self {
        let quota = Quota::per_minute(std::num::NonZeroU32::new(per_minute).unwrap());
        Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        }
    }

    pub fn check(&self, ip: IpAddr) -> Result<(), AppError> {
        self.inner.check_key(&ip).map_err(|_| AppError::RateLimited)
    }
}

pub struct UserRateLimiter {
    inner: Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>,
}

impl UserRateLimiter {
    pub fn new(per_minute: u32) -> Self {
        let quota = Quota::per_minute(std::num::NonZeroU32::new(per_minute).unwrap());
        Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        }
    }

    pub fn check(&self, user_id: &str) -> Result<(), AppError> {
        self.inner
            .check_key(&user_id.to_string())
            .map_err(|_| AppError::RateLimited)
    }
}
