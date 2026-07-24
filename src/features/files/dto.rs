use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

// ── Create file (initiate upload) ─────────────────────────────

#[derive(Debug, Deserialize, Validate)]
pub struct CreateFileRequest {
    pub folder_id: Option<Uuid>,

    /// Encrypted file metadata (filename, mime type, etc.)
    pub encrypted_metadata: String,
    pub metadata_nonce: String, // base64, 24 bytes

    /// Plaintext BLAKE3 hash of the entire file (client-computed).
    /// Used for same-user dedup: if a file with the same hash exists,
    /// the server returns the existing file_id and skips upload.
    pub plaintext_blake3: String, // base64, 32 bytes

    pub total_size: i64,
    pub total_chunks: i32,

    /// secretstream header (24 bytes) for this version.
    pub encryption_header: String, // base64

    /// Chunk plan: each chunk's index, size, and ciphertext BLAKE3 hash.
    pub chunks: Vec<ChunkPlan>,
}

#[derive(Debug, Deserialize)]
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
    pub deduplicated: bool, // true if existing chunks were reused
    pub upload_urls: Vec<ChunkUploadUrl>,
}

#[derive(Debug, Serialize)]
pub struct ChunkUploadUrl {
    pub chunk_index: i32,
    pub segment_index: i32,
    pub presigned_url: String,
    pub r2_key: String,
    pub already_uploaded: bool,
}

// ── File info ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct FileResponse {
    pub file_id: Uuid,
    pub folder_id: Option<Uuid>,
    pub encrypted_metadata: String,
    pub metadata_nonce: String,
    pub total_size: i64,
    pub current_version_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
}

#[derive(Debug, Serialize)]
pub struct DownloadChunkInfo {
    pub chunk_index: i32,
    pub segment_index: i32,
    pub chunk_size: i64,
    pub presigned_url: String,
}
