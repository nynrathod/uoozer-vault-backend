//! Custom Axum extractors.

use axum::{
    extract::{FromRequestParts, Request},
    http::request::Parts,
};

use crate::core::error::AppError;
use crate::core::middleware::AuthenticatedUser;

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedUser>()
            .copied()
            .ok_or(AppError::Unauthorized)
    }
}

pub fn extract_client_ip(req: &Request) -> Option<std::net::IpAddr> {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| {
            req.headers()
                .get("x-appengine-user-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse().ok())
        })
}

pub fn extract_user_agent(req: &Request) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}
