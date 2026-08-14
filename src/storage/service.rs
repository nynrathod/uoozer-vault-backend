//! High-level storage orchestration: presigning URLs, batch deletion.
//! Wraps R2Client so file/chunk modules never touch R2 directly.

use std::sync::Arc;

use uuid::Uuid;

use crate::core::error::AppError;
use crate::storage::dto::{ChunkUploadUrl, DownloadChunkInfo};
use crate::storage::r2::R2Client;

#[derive(Clone)]
pub struct StorageService {
    r2: Option<Arc<R2Client>>,
}

impl StorageService {
    pub fn new(r2: Option<Arc<R2Client>>) -> Self {
        Self { r2 }
    }

    /// Returns true if R2 storage is configured and available.
    pub fn is_configured(&self) -> bool {
        self.r2.is_some()
    }

    /// Returns the R2 client or an error if storage is not configured.
    fn require_r2(&self) -> Result<&Arc<R2Client>, AppError> {
        self.r2
            .as_ref()
            .ok_or_else(|| AppError::ServiceUnavailable("storage is not configured".into()))
    }

    /// R2 key layout: `{user_id}/{file_id}/{version_id}/{segment_index}/{chunk_index}`
    pub fn chunk_key(
        user_id: Uuid,
        file_id: Uuid,
        version_id: Uuid,
        segment_index: i32,
        chunk_index: i32,
    ) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            user_id, file_id, version_id, segment_index, chunk_index
        )
    }

    /// Generates presigned PUT URLs for a set of chunks.
    pub async fn generate_upload_urls(
        &self,
        user_id: Uuid,
        file_id: Uuid,
        version_id: Uuid,
        chunks: &[(i32, i32)],
    ) -> Result<Vec<ChunkUploadUrl>, AppError> {
        self.require_r2()?; // Fail early
        let mut upload_urls = Vec::with_capacity(chunks.len());

        for &(chunk_index, segment_index) in chunks {
            let r2_key = Self::chunk_key(user_id, file_id, version_id, segment_index, chunk_index);
            let presigned_url = self.presign_put(&r2_key).await?;

            upload_urls.push(ChunkUploadUrl {
                chunk_index,
                segment_index,
                presigned_url,
                r2_key,
                already_uploaded: false,
            });
        }

        Ok(upload_urls)
    }

    /// Generates presigned GET URLs for downloading chunks.
    pub async fn generate_download_urls(
        &self,
        chunks: &[(i32, i32, i64, String)],
    ) -> Result<Vec<DownloadChunkInfo>, AppError> {
        self.require_r2()?;
        let mut result = Vec::with_capacity(chunks.len());

        for (chunk_index, segment_index, chunk_size, r2_key) in chunks {
            let presigned_url = self.presign_get(r2_key).await?;
            result.push(DownloadChunkInfo {
                chunk_index: *chunk_index,
                segment_index: *segment_index,
                chunk_size: *chunk_size,
                presigned_url,
            });
        }

        Ok(result)
    }

    /// Presigns a single PUT URL.
    pub async fn presign_put(&self, key: &str) -> Result<String, AppError> {
        let r2 = self.require_r2()?;
        r2.presign_put(key).await
    }

    /// Presigns a single GET URL.
    pub async fn presign_get(&self, key: &str) -> Result<String, AppError> {
        let r2 = self.require_r2()?;
        r2.presign_get(key).await
    }

    /// HEADs an object in storage to verify existence and get ETag.
    pub async fn head_object(&self, key: &str) -> Result<Option<String>, AppError> {
        let r2 = self.require_r2()?;
        r2.head_object(key).await
    }

    /// Best-effort batch deletion of R2 objects.
    pub async fn delete_objects_best_effort(&self, keys: &[String]) {
        if let Some(r2) = &self.r2 {
            if !keys.is_empty() {
                if let Err(e) = r2.delete_objects(keys).await {
                    tracing::error!(error = ?e, "failed to batch delete R2 objects");
                }
            }
        }
    }
}
