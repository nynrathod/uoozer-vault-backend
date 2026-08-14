use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct VerifyChunkRequest {
    pub version_id: Uuid,
    pub chunk_index: i32,
    pub r2_etag: String,
}

#[derive(Debug, Serialize)]
pub struct ChunkStatusResponse {
    pub chunk_id: Uuid,
    pub version_id: Uuid,
    pub chunk_index: i32,
    pub segment_index: i32,
    pub uploaded: bool,
    pub r2_etag: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResumeInfoResponse {
    pub version_id: Uuid,
    pub total_chunks: i32,
    pub uploaded_chunks: Vec<i32>,
    pub missing_chunks: Vec<i32>,
    /// Fresh presigned PUT URLs for missing chunks.
    /// `None` if R2 is not configured (dev/test mode).
    pub upload_urls: Option<Vec<crate::storage::dto::ChunkUploadUrl>>,
}
