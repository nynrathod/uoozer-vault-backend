use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    pub device_id: Uuid,
    pub device_name: String,
    pub device_pubkey: String, // base64
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub is_revoked: bool,
    pub is_current: bool,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub session_id: Uuid,
    pub device_id: Uuid,
    pub device_name: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub is_current: bool,
    pub is_revoked: bool,
}
