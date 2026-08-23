use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct CreateFolderRequest {
    /// Encrypted folder metadata blob (XChaCha20-Poly1305 ciphertext).
    pub encrypted_metadata: String, // base64
    pub metadata_nonce: String, // base64, 24 bytes

    /// Parent folder UUID. None = root level.
    pub parent_folder_id: Option<Uuid>,

    #[serde(default)]
    pub folder_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct FolderResponse {
    pub folder_id: Uuid,
    pub parent_folder_id: Option<Uuid>,
    pub encrypted_metadata: String, // base64
    pub metadata_nonce: String,     // base64
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct BulkCreateFoldersRequest {
    #[validate(length(min = 1, max = 500))]
    pub folders: Vec<CreateFolderRequest>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for FolderResponse {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;

        let encrypted_metadata: Vec<u8> = row.try_get("encrypted_metadata")?;
        let metadata_nonce: Vec<u8> = row.try_get("metadata_nonce")?;

        Ok(Self {
            folder_id: row.try_get("folder_id")?,
            parent_folder_id: row.try_get("parent_folder_id")?,
            encrypted_metadata: crate::core::crypto::encode_b64(&encrypted_metadata),
            metadata_nonce: crate::core::crypto::encode_b64(&metadata_nonce),
            deleted_at: row.try_get("deleted_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
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
