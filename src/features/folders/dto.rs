use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateFolderRequest {
    /// Encrypted folder metadata blob (XChaCha20-Poly1305 ciphertext).
    pub encrypted_metadata: String, // base64
    pub metadata_nonce: String, // base64, 24 bytes

    /// Parent folder UUID. None = root level.
    pub parent_folder_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct FolderResponse {
    pub folder_id: Uuid,
    pub parent_folder_id: Option<Uuid>,
    pub encrypted_metadata: String, // base64
    pub metadata_nonce: String,     // base64
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateFolderRequest {
    pub encrypted_metadata: String,
    pub metadata_nonce: String,
    /// New parent folder (for move operations). None = root.
    pub parent_folder_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct MoveFolderRequest {
    pub parent_folder_id: Option<Uuid>,
}
