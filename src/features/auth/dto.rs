use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct PreloginRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct PreloginResponse {
    pub salt: String,
    pub argon2_params: serde_json::Value,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SignupInitRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct SignupInitResponse {
    pub signup_token: String,
    pub salt: String,
    pub argon2_params: serde_json::Value,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SignupCompleteRequest {
    pub signup_token: String,
    #[validate(length(min = 1, max = 100))]
    pub full_name: String,
    #[validate(length(min = 1))]
    pub auth_key: String,
    #[validate(length(min = 1))]
    pub recovery_auth_key: String,
    pub wrapped_dek: String,
    pub wrapped_dek_nonce: String,
    pub recovery_wrapped_dek: String,
    pub recovery_wrapped_dek_nonce: String,
    pub identity_pubkey: String,
    pub device_pubkey: String,
    pub device_name: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub full_name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 1))]
    pub auth_key: String,
    pub device_pubkey: String,
    pub device_name: String,
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PasswordChangeRequest {
    #[validate(length(min = 1))]
    pub new_auth_key: String,
    pub new_wrapped_dek: String,
    pub new_wrapped_dek_nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub revoke_device: Option<bool>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KeyBundleResponse {
    pub wrapped_dek: String,
    pub wrapped_dek_nonce: String,
    pub recovery_wrapped_dek: String,
    pub recovery_wrapped_dek_nonce: String,
}
