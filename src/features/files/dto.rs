use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

pub use crate::storage::dto::{ChunkUploadUrl, DownloadChunkInfo};

// ── Create file (initiate upload) ─────────────────────────────

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct CreateFileRequest {
    /// None = root level. Some(id) = inside folder.
    pub folder_id: Option<Uuid>,

    /// Encrypted file metadata (filename, mime type, etc.) — XChaCha20-Poly1305 ciphertext.
    pub encrypted_metadata: String,
    /// 24-byte nonce for metadata encryption.
    pub metadata_nonce: String,

    /// Plaintext BLAKE3 hash of the entire file (client-computed).
    /// Used for same-user dedup: if a file with the same hash exists,
    /// the server returns the existing file_id and skips upload.
    pub plaintext_blake3: String, // base64, 32 bytes

    pub total_size: i64,
    pub total_chunks: i32,

    /// secretstream header (24 bytes) for this version.
    pub encryption_header: String, // base64

    /// Chunk plan: each chunk's index, size, and ciphertext BLAKE3 hash.
    #[validate(length(min = 1, message = "at least one chunk is required"))]
    pub chunks: Vec<ChunkPlan>,

    pub wrapped_file_key: String,
    pub wrapped_file_key_nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateShareRequest {
    pub item_type: String,
    pub encrypted_payload: String,
    pub encrypted_nonce: String,
    pub encryption_header: Option<String>,
    pub item_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct CreateShareResponse {
    pub share_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct GetShareResponse {
    pub share_id: Uuid,
    pub item_type: String,
    pub encrypted_payload: String,
    pub encrypted_nonce: String,
    pub encryption_header: Option<String>,
    pub chunks: Option<Vec<DownloadChunkInfo>>,
    pub total_size: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChunkPlan {
    pub chunk_index: i32,
    pub segment_index: i32,
    pub chunk_size: i64,
    pub chunk_blake3: String, // base64, 32 bytes (ciphertext hash)
}

#[derive(Debug, Serialize)]
pub struct CreateFileResponse {
    pub file_id: Uuid,
    pub version_id: Uuid,
    pub deduplicated: bool,
    pub upload_urls: Vec<ChunkUploadUrl>,
}

// ── File info ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FileResponse {
    pub file_id: Uuid,
    pub folder_id: Option<Uuid>,
    pub encrypted_metadata: String,
    pub metadata_nonce: String,
    pub total_size: i64,
    pub current_version_id: Option<Uuid>,
    pub is_uploading: bool,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub wrapped_file_key: Option<String>,
    pub wrapped_file_key_nonce: Option<String>,
    pub encryption_header: Option<String>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for FileResponse {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;

        let encrypted_metadata: Vec<u8> = row.try_get("encrypted_metadata")?;
        let metadata_nonce: Vec<u8> = row.try_get("metadata_nonce")?;

        let wrapped_file_key: Option<Vec<u8>> = row.try_get("wrapped_file_key").ok();
        let wrapped_file_key_nonce: Option<Vec<u8>> = row.try_get("wrapped_file_key_nonce").ok();
        let encryption_header: Option<Vec<u8>> = row.try_get("encryption_header").ok();

        Ok(Self {
            file_id: row.try_get("file_id")?,
            folder_id: row.try_get("folder_id")?,
            encrypted_metadata: crate::core::crypto::encode_b64(&encrypted_metadata),
            metadata_nonce: crate::core::crypto::encode_b64(&metadata_nonce),
            total_size: row.try_get("total_size")?,
            current_version_id: row.try_get("current_version_id")?,
            is_uploading: row.try_get("is_uploading")?,
            deleted_at: row.try_get("deleted_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            wrapped_file_key: wrapped_file_key.map(|k| crate::core::crypto::encode_b64(&k)),
            wrapped_file_key_nonce: wrapped_file_key_nonce
                .map(|k| crate::core::crypto::encode_b64(&k)),
            encryption_header: encryption_header.map(|h| crate::core::crypto::encode_b64(&h)),
        })
    }
}

// ── Update file (rename / move) ───────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateFileRequest {
    pub encrypted_metadata: Option<String>,
    pub metadata_nonce: Option<String>,
    pub folder_id: Option<Option<Uuid>>, // None = don't change, Some(None) = move to root
}

// ── Complete upload ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CompleteUploadRequest {
    pub version_id: Uuid,
    pub r2_etags: std::collections::HashMap<i32, String>, // chunk_index -> etag
}

// ── Download ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DownloadManifestResponse {
    pub file_id: Uuid,
    pub version_id: Uuid,
    pub encryption_header: String, // base64
    pub total_size: i64,
    pub total_chunks: i32,
    pub chunks: Vec<DownloadChunkInfo>,
    pub wrapped_file_key: String,
    pub wrapped_file_key_nonce: String,
}

// ── Versions ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FileVersionResponse {
    pub version_id: Uuid,
    pub version_number: i32,
    pub total_size: i64,
    pub total_chunks: i32,
    pub is_active: bool,
    pub is_uploading: bool,
    pub created_at: DateTime<Utc>,
    pub created_by_device_id: Uuid,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for FileVersionResponse {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            version_id: row.try_get("version_id")?,
            version_number: row.try_get("version_number")?,
            total_size: row.try_get("total_size")?,
            total_chunks: row.try_get("total_chunks")?,
            is_active: row.try_get("is_active")?,
            is_uploading: row.try_get("is_uploading")?,
            created_at: row.try_get("created_at")?,
            created_by_device_id: row.try_get("created_by_device_id")?,
        })
    }
}

// ── List with pagination ──────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ListFilesResponse {
    pub files: Vec<FileResponse>,
    pub total: i64,
}

#[derive(Debug, serde::Deserialize)]
pub struct BulkDeleteRequest {
    pub file_ids: Vec<uuid::Uuid>,
    pub folder_ids: Vec<uuid::Uuid>,
}

#[derive(Debug, serde::Deserialize)]
pub struct BulkCancelRequest {
    pub uploads: Vec<CancelTarget>,
}

#[derive(Debug, serde::Deserialize)]
pub struct CancelTarget {
    pub file_id: Uuid,
    pub version_id: Uuid,
}

#[derive(Debug, Deserialize, Validate)]
pub struct BulkCreateFilesRequest {
    #[validate(length(min = 1, max = 100))]
    pub files: Vec<CreateFileRequest>,
}

#[derive(Debug, Serialize)]
pub struct BulkCreateFilesResponse {
    pub results: Vec<CreateFileResponse>,
}

#[derive(Debug, Deserialize)]
pub struct BulkCompleteUploadItem {
    pub file_id: Uuid,
    pub version_id: Uuid,
    pub r2_etags: std::collections::HashMap<i32, String>,
    pub plaintext_blake3: String,
    pub encryption_header: String,
    pub chunk_hashes: std::collections::HashMap<i32, String>,
    pub wrapped_file_key: String,
    pub wrapped_file_key_nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct BulkCompleteUploadRequest {
    pub uploads: Vec<BulkCompleteUploadItem>,
}

#[derive(Debug, Serialize)]
pub struct BulkCompleteUploadResponse {
    pub completed: Vec<Uuid>,
    pub failed: Vec<Uuid>,
}
