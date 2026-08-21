use sqlx::PgPool;
use uuid::Uuid;

use crate::core::error::AppError;
use crate::storage::StorageService;
use crate::storage::dto::ChunkUploadUrl;

use super::dto::*;

pub struct ChunkService {
    db: PgPool,
    storage: StorageService,
}

impl ChunkService {
    pub fn new(db: PgPool, storage: StorageService) -> Self {
        Self { db, storage }
    }

    /// Get resume info for a partially-uploaded version.
    pub async fn get_resume_info(
        &self,
        user_id: Uuid,
        version_id: Uuid,
    ) -> Result<ResumeInfoResponse, AppError> {
        let version: Option<(i32,)> = sqlx::query_as(
            "SELECT v.total_chunks FROM file_versions v JOIN files f ON f.file_id = v.file_id
             WHERE v.version_id = $1 AND f.user_id = $2 AND f.deleted_at IS NULL",
        )
        .bind(version_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?;

        let total_chunks = version.ok_or(AppError::NotFound)?.0;

        let chunks: Vec<(i32, bool)> = sqlx::query_as(
            "SELECT chunk_index, (uploaded_at IS NOT NULL) AS uploaded FROM file_chunks WHERE version_id = $1 ORDER BY chunk_index",
        )
        .bind(version_id).fetch_all(&self.db).await?;

        let uploaded_chunks: Vec<i32> = chunks
            .iter()
            .filter(|(_, up)| *up)
            .map(|(i, _)| *i)
            .collect();
        let missing_chunks: Vec<i32> = chunks
            .iter()
            .filter(|(_, up)| !*up)
            .map(|(i, _)| *i)
            .collect();

        let upload_urls = if self.storage.is_configured() {
            let mut urls = Vec::new();
            for &chunk_idx in &missing_chunks {
                let chunk: Option<(i32, String)> = sqlx::query_as(
                    "SELECT segment_index, r2_key FROM file_chunks WHERE version_id = $1 AND chunk_index = $2",
                )
                .bind(version_id).bind(chunk_idx).fetch_optional(&self.db).await?;

                if let Some((segment_index, r2_key)) = chunk {
                    let presigned_url = self.storage.presign_put(&r2_key).await?;
                    urls.push(ChunkUploadUrl {
                        chunk_index: chunk_idx,
                        segment_index,
                        presigned_url,
                        r2_key,
                        already_uploaded: false,
                    });
                }
            }
            Some(urls)
        } else {
            None
        };

        Ok(ResumeInfoResponse {
            version_id,
            total_chunks,
            uploaded_chunks,
            missing_chunks,
            upload_urls,
        })
    }

    /// Verify a single chunk after upload.
    pub async fn verify_chunk(
        &self,
        user_id: Uuid,
        req: VerifyChunkRequest,
    ) -> Result<ChunkStatusResponse, AppError> {
        let chunk: Option<(Uuid, i32, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
            "SELECT c.chunk_id, c.segment_index, c.r2_key, c.r2_etag, c.uploaded_at
             FROM file_chunks c JOIN file_versions v ON v.version_id = c.version_id JOIN files f ON f.file_id = v.file_id
             WHERE c.version_id = $1 AND c.chunk_index = $2 AND f.user_id = $3 AND f.deleted_at IS NULL",
        )
        .bind(req.version_id).bind(req.chunk_index).bind(user_id)
        .fetch_optional(&self.db).await?;

        let (chunk_id, segment_index, r2_key, existing_etag, _uploaded_at) =
            chunk.ok_or(AppError::NotFound)?;

        if let Some(existing) = &existing_etag {
            if existing == &req.r2_etag {
                return Ok(ChunkStatusResponse {
                    chunk_id,
                    version_id: req.version_id,
                    chunk_index: req.chunk_index,
                    segment_index,
                    uploaded: true,
                    r2_etag: Some(req.r2_etag),
                });
            }
        }

        if self.storage.is_configured() {
            let head_etag = self.storage.head_object(&r2_key).await?;
            match head_etag {
                Some(etag) => {
                    let normalized_head = etag.trim_matches('"');
                    let normalized_client = req.r2_etag.trim_matches('"');
                    if normalized_head != normalized_client {
                        tracing::warn!(chunk_index = req.chunk_index, head_etag = %etag, client_etag = %req.r2_etag, "etag mismatch during chunk verification");
                    }
                }
                None => {
                    return Err(AppError::BadRequest(
                        "chunk not found in storage — upload may have failed".into(),
                    ));
                }
            }
        }

        sqlx::query("UPDATE file_chunks SET uploaded_at = now(), r2_etag = $1 WHERE chunk_id = $2")
            .bind(&req.r2_etag)
            .bind(chunk_id)
            .execute(&self.db)
            .await?;

        Ok(ChunkStatusResponse {
            chunk_id,
            version_id: req.version_id,
            chunk_index: req.chunk_index,
            segment_index,
            uploaded: true,
            r2_etag: Some(req.r2_etag),
        })
    }

    pub async fn precheck_version_completeness(
        &self,
        user_id: Uuid,
        version_id: Uuid,
    ) -> Result<CompletenessResponse, AppError> {
        let version: Option<(i32,)> = sqlx::query_as(
            "SELECT v.total_chunks FROM file_versions v 
         JOIN files f ON f.file_id = v.file_id 
         WHERE v.version_id = $1 AND f.user_id = $2 AND f.deleted_at IS NULL",
        )
        .bind(version_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?;

        let total_chunks = version.ok_or(AppError::NotFound)?.0;

        let missing_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM file_chunks WHERE version_id = $1 AND uploaded_at IS NULL",
        )
        .bind(version_id)
        .fetch_one(&self.db)
        .await?;

        let uploaded_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM file_chunks WHERE version_id = $1 AND uploaded_at IS NOT NULL",
        )
        .bind(version_id)
        .fetch_one(&self.db)
        .await?;

        Ok(CompletenessResponse {
            version_id,
            total_chunks,
            uploaded_chunks: uploaded_count as i32,
            missing_chunks: missing_count as i32,
            is_complete: missing_count == 0,
        })
    }
}
