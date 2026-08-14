use serde::Serialize;

/// Presigned PUT URL for a single chunk upload.
#[derive(Debug, Serialize, Clone)]
pub struct ChunkUploadUrl {
    pub chunk_index: i32,
    pub segment_index: i32,
    pub presigned_url: String,
    pub r2_key: String,
    pub already_uploaded: bool,
}

/// Presigned GET URL for a single chunk download.
#[derive(Debug, Serialize)]
pub struct DownloadChunkInfo {
    pub chunk_index: i32,
    pub segment_index: i32,
    pub chunk_size: i64,
    pub presigned_url: String,
}
