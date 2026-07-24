use sqlx::{PgPool, Pool, Postgres};
use uuid::Uuid;

use crate::core::error::AppError;

use super::dto::*;

pub struct FileService {
    db: Pool<Postgres>,
}

impl FileService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    // ── Create file + initiate upload ────────────────────────
    //
    // Full implementation will:
    // 1. Check for same-user dedup via plaintext_blake3
    // 2. If dedup hit: return existing file_id, no upload needed
    // 3. If new: insert file + file_version + file_chunks rows
    // 4. Generate presigned R2 PUT URLs for each chunk
    // 5. Return upload manifest
    //
    // For now: skeleton that returns NotImplemented.
    pub async fn create_file(
        &self,
        _user_id: Uuid,
        _req: CreateFileRequest,
    ) -> Result<CreateFileResponse, AppError> {
        Err(AppError::NotImplemented)
    }

    pub async fn get_file(&self, _user_id: Uuid, _file_id: Uuid) -> Result<FileResponse, AppError> {
        Err(AppError::NotImplemented)
    }

    pub async fn list_files(
        &self,
        _user_id: Uuid,
        _folder_id: Option<Uuid>,
    ) -> Result<Vec<FileResponse>, AppError> {
        Err(AppError::NotImplemented)
    }

    pub async fn complete_upload(
        &self,
        _user_id: Uuid,
        _req: CompleteUploadRequest,
    ) -> Result<(), AppError> {
        Err(AppError::NotImplemented)
    }

    pub async fn get_download_manifest(
        &self,
        _user_id: Uuid,
        _file_id: Uuid,
        _version_id: Option<Uuid>,
    ) -> Result<DownloadManifestResponse, AppError> {
        Err(AppError::NotImplemented)
    }

    pub async fn delete_file(&self, _user_id: Uuid, _file_id: Uuid) -> Result<(), AppError> {
        Err(AppError::NotImplemented)
    }

    pub async fn list_versions(
        &self,
        _user_id: Uuid,
        _file_id: Uuid,
    ) -> Result<Vec<serde_json::Value>, AppError> {
        Err(AppError::NotImplemented)
    }

    pub async fn restore_version(
        &self,
        _user_id: Uuid,
        _file_id: Uuid,
        _version_id: Uuid,
    ) -> Result<(), AppError> {
        Err(AppError::NotImplemented)
    }
}
