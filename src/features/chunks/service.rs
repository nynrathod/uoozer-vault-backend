use sqlx::PgPool;
use uuid::Uuid;

use crate::core::error::AppError;

use super::dto::*;

pub struct ChunkService {
    db: PgPool,
}

impl ChunkService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn get_resume_info(
        &self,
        _user_id: Uuid,
        _version_id: Uuid,
    ) -> Result<ResumeInfoResponse, AppError> {
        // Full implementation will query file_chunks for the version,
        // compare uploaded_at IS NOT NULL, and return missing indices.
        Err(AppError::NotImplemented)
    }

    pub async fn verify_chunk(
        &self,
        _user_id: Uuid,
        _req: VerifyChunkRequest,
    ) -> Result<ChunkStatusResponse, AppError> {
        // Full implementation will:
        // 1. Fetch the chunk from R2 (or trust client + verify later)
        // 2. Compute BLAKE3 on ciphertext
        // 3. Compare against stored chunk_blake3
        // 4. If match: set uploaded_at = now(), store r2_etag
        // 5. If mismatch: return error
        Err(AppError::NotImplemented)
    }
}
