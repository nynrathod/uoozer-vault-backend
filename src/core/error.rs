use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

/// Unified application error.
/// Every error path in the system funnels through here.
#[derive(Debug, Error)]
pub enum AppError {
    // ── 400 Bad Request ───────────────────────────────────────
    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("refresh token is invalid or expired")]
    InvalidRefreshToken,

    #[error("refresh token reuse detected — session revoked for security")]
    RefreshTokenReuse,

    #[error("device has been revoked")]
    DeviceRevoked,

    // ── 401 Unauthorized ──────────────────────────────────────
    #[error("authentication required")]
    Unauthorized,

    #[error("authentication token is expired")]
    TokenExpired,

    // ── 403 Forbidden ─────────────────────────────────────────
    #[error("you do not have access to this resource")]
    Forbidden,

    // ── 404 Not Found ─────────────────────────────────────────
    #[error("resource not found")]
    NotFound,

    // ── 409 Conflict ──────────────────────────────────────────
    #[error("resource already exists: {0}")]
    Conflict(String),

    // ── 429 Too Many Requests ─────────────────────────────────
    #[error("rate limit exceeded")]
    RateLimited,

    // ── 500 Internal Server Error ─────────────────────────────
    #[error("internal server error")]
    Internal(#[from] anyhow::Error),

    // ── 503 Service Unavailable ───────────────────────────────
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    // ── Not implemented (skeleton endpoints) ──────────────────
    #[error("this endpoint is not yet implemented")]
    NotImplemented,
}

impl AppError {
    /// Map to HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) | Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::InvalidCredentials
            | Self::InvalidRefreshToken
            | Self::RefreshTokenReuse
            | Self::DeviceRevoked
            | Self::Unauthorized
            | Self::TokenExpired => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotImplemented => StatusCode::NOT_IMPLEMENTED,
        }
    }

    /// Stable error code for client-side handling.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::Validation(_) => "VALIDATION_ERROR",
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::InvalidRefreshToken => "INVALID_REFRESH_TOKEN",
            Self::RefreshTokenReuse => "REFRESH_TOKEN_REUSE",
            Self::DeviceRevoked => "DEVICE_REVOKED",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::Forbidden => "FORBIDDEN",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::RateLimited => "RATE_LIMITED",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            Self::NotImplemented => "NOT_IMPLEMENTED",
        }
    }

    /// Whether the error detail should be exposed to the client.
    /// Internal errors never leak detail.
    fn is_client_safe(&self) -> bool {
        !matches!(self, Self::Internal(_) | Self::ServiceUnavailable(_))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.error_code();

        let message = if self.is_client_safe() {
            self.to_string()
        } else {
            "an internal error occurred".to_string()
        };

        // Log internal errors with full detail; client errors at debug level.
        if status.is_server_error() {
            tracing::error!(error = ?self, status = %status, "server error");
        } else {
            tracing::debug!(error = %self, code, status = %status, "client error");
        }

        let body = Json(json!({
            "error": {
                "code": code,
                "message": message,
            }
        }));

        (status, body).into_response()
    }
}

/// Convert sqlx errors to AppError with appropriate mapping.
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => Self::NotFound,
            sqlx::Error::Database(ref db_err) if db_err.code().as_deref() == Some("23505") => {
                // Unique constraint violation
                Self::Conflict("resource already exists".to_string())
            }
            sqlx::Error::Database(ref db_err) if db_err.code().as_deref() == Some("23503") => {
                // Foreign key violation
                Self::BadRequest("referenced resource does not exist".to_string())
            }
            _ => {
                tracing::error!(error = ?err, "database error");
                Self::Internal(anyhow::anyhow!(err))
            }
        }
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(err: validator::ValidationErrors) -> Self {
        Self::Validation(err.to_string())
    }
}

/// Panic handler for tower-http CatchPanicLayer.
pub fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    tracing::error!(panic = ?err, "handler panicked");

    let body = Json(json!({
        "error": {
            "code": "INTERNAL_ERROR",
            "message": "an internal error occurred",
        }
    }));

    (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
}

/// Convenience type alias.
pub type AppResult<T> = Result<T, AppError>;
