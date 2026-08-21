use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;
use sqlx::PgPool;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::app_state::{AppState, SyncEvent};
use crate::core::crypto;
use crate::core::error::AppError;
use crate::features::audit;
use crate::features::folders::service::FolderService;
use crate::storage::StorageService;

use super::dto::*;

/// Maximum chunks per file — prevents abuse via oversized chunk plans.
const MAX_CHUNKS_PER_FILE: i32 = 50_000;
/// Maximum file size allowed (500 GB — generous POC limit).
const MAX_FILE_SIZE: i64 = 500 * 1024 * 1024 * 1024;

pub struct FileService {
    db: PgPool,
    storage: StorageService,
    sse_channels: Arc<DashMap<Uuid, broadcast::Sender<SyncEvent>>>,
}

impl FileService {
    pub fn new(state: &AppState) -> Self {
        Self {
            db: state.db.clone(),
            storage: state.storage.clone(),
            sse_channels: state.sse_channels.clone(),
        }
    }

    fn broadcast(&self, user_id: Uuid, event: SyncEvent) {
        if let Some(tx) = self.sse_channels.get(&user_id) {
            let _ = tx.send(event);
        }
    }

    pub async fn create_file(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        req: CreateFileRequest,
    ) -> Result<CreateFileResponse, AppError> {
        self.validate_create_request(&req).await?;

        let current_usage: i64 = sqlx::query_scalar(
            "SELECT CAST(COALESCE(SUM(total_size), 0) AS BIGINT) FROM files WHERE user_id = $1 AND deleted_at IS NULL"
        )
        .bind(user_id)
        .fetch_one(&self.db)
        .await?;

        const USER_STORAGE_QUOTA_BYTES: i64 = 100 * 1024 * 1024;
        if current_usage + req.total_size > USER_STORAGE_QUOTA_BYTES {
            return Err(AppError::BadRequest(format!(
                "storage quota exceeded. limit: {} bytes, used: {} bytes",
                USER_STORAGE_QUOTA_BYTES, current_usage
            )));
        }

        if let Some(folder_id) = req.folder_id {
            FolderService::new(self.db.clone())
                .verify_folder_ownership(folder_id, user_id)
                .await?;
        }

        let existing: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT f.file_id, f.current_version_id
             FROM files f
             JOIN file_versions v ON f.current_version_id = v.version_id
             WHERE f.user_id = $1
               AND f.folder_id IS NOT DISTINCT FROM $3
               AND f.plaintext_blake3 = $2
               AND f.deleted_at IS NULL
               AND v.is_active = true",
        )
        .bind(user_id)
        .bind(&crypto::decode_b64(&req.plaintext_blake3)?)
        .bind(req.folder_id)
        .fetch_optional(&self.db)
        .await?;

        if let Some((existing_file_id, existing_version_id)) = existing {
            tracing::info!(user_id = %user_id, file_id = %existing_file_id, "dedup hit — skipping upload");
            return Ok(CreateFileResponse {
                file_id: existing_file_id,
                version_id: existing_version_id,
                deduplicated: true,
                upload_urls: vec![],
            });
        }

        if !self.storage.is_configured() {
            return Err(AppError::ServiceUnavailable(
                "storage is not configured".into(),
            ));
        }

        let encrypted_metadata = crypto::decode_b64(&req.encrypted_metadata)?;
        let metadata_nonce = crypto::decode_b64(&req.metadata_nonce)?;
        let plaintext_blake3 = crypto::decode_b64(&req.plaintext_blake3)?;
        let encryption_header = crypto::decode_b64(&req.encryption_header)?;

        let file_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();

        let mut tx = self.db.begin().await?;

        sqlx::query(
            "INSERT INTO files (file_id, user_id, folder_id, encrypted_metadata, metadata_nonce, plaintext_blake3, total_size, current_version_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)",
        )
        .bind(file_id).bind(user_id).bind(req.folder_id)
        .bind(&encrypted_metadata).bind(&metadata_nonce)
        .bind(&plaintext_blake3).bind(req.total_size)
        .execute(&mut *tx).await?;

        sqlx::query(
            "INSERT INTO file_versions (version_id, file_id, version_number, encryption_header, total_size, total_chunks, plaintext_blake3, created_by_device_id, is_active)
             VALUES ($1, $2, 1, $3, $4, $5, $6, $7, false)",
        )
        .bind(version_id).bind(file_id).bind(&encryption_header)
        .bind(req.total_size).bind(req.total_chunks)
        .bind(&plaintext_blake3).bind(device_id)
        .execute(&mut *tx).await?;

        sqlx::query("UPDATE files SET current_version_id = $1 WHERE file_id = $2")
            .bind(version_id)
            .bind(file_id)
            .execute(&mut *tx)
            .await?;

        for chunk in &req.chunks {
            let chunk_blake3 = crypto::decode_b64(&chunk.chunk_blake3)?;
            let r2_key = StorageService::chunk_key(
                user_id,
                file_id,
                version_id,
                chunk.segment_index,
                chunk.chunk_index,
            );

            sqlx::query(
                "INSERT INTO file_chunks (version_id, chunk_index, segment_index, chunk_size, chunk_blake3, r2_key)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(version_id).bind(chunk.chunk_index).bind(chunk.segment_index)
            .bind(chunk.chunk_size).bind(&chunk_blake3).bind(&r2_key)
            .execute(&mut *tx).await?;
        }

        audit::log(&mut *tx, Some(user_id), Some(device_id), "file_upload_initiated",
            &serde_json::json!({ "file_id": file_id, "version_id": version_id, "total_size": req.total_size, "total_chunks": req.total_chunks })
        ).await?;

        tx.commit().await?;

        let chunk_indices: Vec<(i32, i32)> = req
            .chunks
            .iter()
            .map(|c| (c.chunk_index, c.segment_index))
            .collect();
        let upload_urls = self
            .storage
            .generate_upload_urls(user_id, file_id, version_id, &chunk_indices)
            .await?;

        Ok(CreateFileResponse {
            file_id,
            version_id,
            deduplicated: false,
            upload_urls,
        })
    }

    pub async fn create_version(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        file_id: Uuid,
        req: CreateFileRequest,
    ) -> Result<CreateFileResponse, AppError> {
        self.validate_create_request(&req).await?;

        let current_usage: i64 = sqlx::query_scalar(
            "SELECT CAST(COALESCE(SUM(total_size), 0) AS BIGINT) FROM files WHERE user_id = $1 AND deleted_at IS NULL"
        )
        .bind(user_id).fetch_one(&self.db).await?;

        const USER_STORAGE_QUOTA_BYTES: i64 = 100 * 1024 * 1024;
        if current_usage + req.total_size > USER_STORAGE_QUOTA_BYTES {
            return Err(AppError::BadRequest(format!(
                "storage quota exceeded. limit: {} bytes, used: {} bytes",
                USER_STORAGE_QUOTA_BYTES, current_usage
            )));
        }

        let file_owner: Option<(Uuid,)> = sqlx::query_as(
            "SELECT file_id FROM files WHERE file_id = $1 AND user_id = $2 AND deleted_at IS NULL",
        )
        .bind(file_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?;

        if file_owner.is_none() {
            return Err(AppError::NotFound);
        }

        let plaintext_blake3 = crypto::decode_b64(&req.plaintext_blake3)?;

        let current_version: Option<Uuid> = sqlx::query_scalar(
            "SELECT v.version_id FROM file_versions v WHERE v.file_id = $1 AND v.is_active = true AND v.plaintext_blake3 = $2",
        )
        .bind(file_id).bind(&plaintext_blake3).fetch_optional(&self.db).await?;

        if let Some(existing_version_id) = current_version {
            return Ok(CreateFileResponse {
                file_id,
                version_id: existing_version_id,
                deduplicated: true,
                upload_urls: vec![],
            });
        }

        if !self.storage.is_configured() {
            return Err(AppError::ServiceUnavailable(
                "storage is not configured".into(),
            ));
        }

        let encryption_header = crypto::decode_b64(&req.encryption_header)?;
        let version_id = Uuid::new_v4();

        let mut tx = self.db.begin().await?;

        let next_version_number: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version_number), 0) + 1 FROM file_versions WHERE file_id = $1",
        )
        .bind(file_id)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO file_versions (version_id, file_id, version_number, encryption_header, total_size, total_chunks, plaintext_blake3, created_by_device_id, is_active)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false)",
        )
        .bind(version_id).bind(file_id).bind(next_version_number)
        .bind(&encryption_header).bind(req.total_size).bind(req.total_chunks)
        .bind(&plaintext_blake3).bind(device_id)
        .execute(&mut *tx).await?;

        for chunk in &req.chunks {
            let chunk_blake3 = crypto::decode_b64(&chunk.chunk_blake3)?;
            let r2_key = StorageService::chunk_key(
                user_id,
                file_id,
                version_id,
                chunk.segment_index,
                chunk.chunk_index,
            );

            sqlx::query(
                "INSERT INTO file_chunks (version_id, chunk_index, segment_index, chunk_size, chunk_blake3, r2_key)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(version_id).bind(chunk.chunk_index).bind(chunk.segment_index)
            .bind(chunk.chunk_size).bind(&chunk_blake3).bind(&r2_key)
            .execute(&mut *tx).await?;
        }

        audit::log(&mut *tx, Some(user_id), Some(device_id), "file_version_upload_initiated",
            &serde_json::json!({ "file_id": file_id, "version_id": version_id, "version_number": next_version_number })
        ).await?;

        tx.commit().await?;

        let chunk_indices: Vec<(i32, i32)> = req
            .chunks
            .iter()
            .map(|c| (c.chunk_index, c.segment_index))
            .collect();
        let upload_urls = self
            .storage
            .generate_upload_urls(user_id, file_id, version_id, &chunk_indices)
            .await?;

        Ok(CreateFileResponse {
            file_id,
            version_id,
            deduplicated: false,
            upload_urls,
        })
    }

    pub async fn get_file(&self, user_id: Uuid, file_id: Uuid) -> Result<FileResponse, AppError> {
        let file = sqlx::query_as::<_, FileResponse>(
            "SELECT f.file_id, f.folder_id, f.encrypted_metadata, f.metadata_nonce,
                    f.total_size, f.current_version_id, f.deleted_at, -- FIX: Added f.deleted_at
                    (f.current_version_id IS NOT NULL AND NOT COALESCE(
                        (SELECT v.is_active FROM file_versions v WHERE v.version_id = f.current_version_id), false
                    )) AS is_uploading,
                    f.created_at, f.updated_at
             FROM files f
             WHERE f.file_id = $1 AND f.user_id = $2 AND f.deleted_at IS NULL",
        )
        .bind(file_id).bind(user_id).fetch_optional(&self.db).await?;

        file.ok_or(AppError::NotFound)
    }

    pub async fn list_files(
        &self,
        user_id: Uuid,
        folder_id: Option<Uuid>,
        limit: i64,
        offset: i64,
        trashed: bool,
    ) -> Result<ListFilesResponse, AppError> {
        let limit = limit.clamp(1, 1000);
        let offset = offset.max(0);

        if trashed {
            let total: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM files WHERE user_id = $1 AND folder_id IS NOT DISTINCT FROM $2 AND deleted_at IS NOT NULL",
            )
            .bind(user_id).bind(folder_id).fetch_one(&self.db).await?;

            let files = sqlx::query_as::<_, FileResponse>(
                "SELECT f.file_id, f.folder_id, f.encrypted_metadata, f.metadata_nonce,
                        f.total_size, f.current_version_id, f.deleted_at,
                        (f.current_version_id IS NOT NULL AND NOT COALESCE(
                            (SELECT v.is_active FROM file_versions v WHERE v.version_id = f.current_version_id), false
                        )) AS is_uploading,
                        f.created_at, f.updated_at
                 FROM files f
                 WHERE f.user_id = $1 AND f.folder_id IS NOT DISTINCT FROM $2 AND f.deleted_at IS NOT NULL
                 ORDER BY f.updated_at DESC LIMIT $3 OFFSET $4",
            )
            .bind(user_id).bind(folder_id).bind(limit).bind(offset)
            .fetch_all(&self.db).await?;

            Ok(ListFilesResponse { files, total })
        } else {
            let total: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM files WHERE user_id = $1 AND folder_id IS NOT DISTINCT FROM $2 AND deleted_at IS NULL",
            )
            .bind(user_id).bind(folder_id).fetch_one(&self.db).await?;

            let files = sqlx::query_as::<_, FileResponse>(
                "SELECT f.file_id, f.folder_id, f.encrypted_metadata, f.metadata_nonce,
                        f.total_size, f.current_version_id, f.deleted_at,
                        (f.current_version_id IS NOT NULL AND NOT COALESCE(
                            (SELECT v.is_active FROM file_versions v WHERE v.version_id = f.current_version_id), false
                        )) AS is_uploading,
                        f.created_at, f.updated_at
                 FROM files f
                 WHERE f.user_id = $1 AND f.folder_id IS NOT DISTINCT FROM $2 AND f.deleted_at IS NULL
                 ORDER BY f.updated_at DESC LIMIT $3 OFFSET $4",
            )
            .bind(user_id).bind(folder_id).bind(limit).bind(offset)
            .fetch_all(&self.db).await?;

            Ok(ListFilesResponse { files, total })
        }
    }

    pub async fn update_file(
        &self,
        user_id: Uuid,
        file_id: Uuid,
        req: UpdateFileRequest,
    ) -> Result<FileResponse, AppError> {
        let exists: Option<(Uuid,)> = sqlx::query_as(
            "SELECT file_id FROM files WHERE file_id = $1 AND user_id = $2 AND deleted_at IS NULL",
        )
        .bind(file_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?;

        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        if let Some(nonce) = &req.metadata_nonce {
            let nonce_bytes = crypto::decode_b64(nonce)?;
            if nonce_bytes.len() != 24 {
                return Err(AppError::BadRequest(
                    "metadata nonce must be 24 bytes".into(),
                ));
            }
        }

        if req.encrypted_metadata.is_some() != req.metadata_nonce.is_some() {
            return Err(AppError::BadRequest(
                "encrypted_metadata and metadata_nonce must both be provided together".into(),
            ));
        }

        if let Some(Some(new_folder_id)) = req.folder_id {
            FolderService::new(self.db.clone())
                .verify_folder_ownership(new_folder_id, user_id)
                .await?;
        }

        let encrypted_metadata = match &req.encrypted_metadata {
            Some(m) => Some(crypto::decode_b64(m)?),
            None => None,
        };
        let metadata_nonce = match &req.metadata_nonce {
            Some(n) => Some(crypto::decode_b64(n)?),
            None => None,
        };

        let file = sqlx::query_as::<_, FileResponse>(
            "UPDATE files SET
                encrypted_metadata = COALESCE($1, encrypted_metadata),
                metadata_nonce = COALESCE($2, metadata_nonce),
                folder_id = CASE WHEN $3::boolean THEN $4 ELSE folder_id END,
                updated_at = now()
             WHERE file_id = $5 AND user_id = $6 AND deleted_at IS NULL
             RETURNING file_id, folder_id, encrypted_metadata, metadata_nonce,
                       total_size, current_version_id,
                       (current_version_id IS NOT NULL AND NOT COALESCE(
                           (SELECT v.is_active FROM file_versions v WHERE v.version_id = current_version_id), false
                       )) AS is_uploading,
                       created_at, updated_at",
        )
        .bind(encrypted_metadata.as_ref())
        .bind(metadata_nonce.as_ref())
        .bind(req.folder_id.is_some())
        .bind(req.folder_id.and_then(|f| f))
        .bind(file_id).bind(user_id)
        .fetch_one(&self.db).await?;

        self.broadcast(
            user_id,
            SyncEvent {
                event_type: "updated".into(),
                resource_type: "file".into(),
                resource_id: file_id,
                payload: serde_json::json!({}),
            },
        );

        Ok(file)
    }

    pub async fn get_download_manifest(
        &self,
        user_id: Uuid,
        file_id: Uuid,
        version_id: Option<Uuid>,
    ) -> Result<DownloadManifestResponse, AppError> {
        if !self.storage.is_configured() {
            return Err(AppError::ServiceUnavailable(
                "storage is not configured".into(),
            ));
        }

        let file: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT file_id, current_version_id FROM files WHERE file_id = $1 AND user_id = $2 AND deleted_at IS NULL",
        )
        .bind(file_id).bind(user_id).fetch_optional(&self.db).await?;

        let (_, current_version_id) = file.ok_or(AppError::NotFound)?;

        let target_version_id =
            match version_id {
                Some(vid) => {
                    let exists: Option<(Uuid,)> = sqlx::query_as(
                    "SELECT v.version_id FROM file_versions v JOIN files f ON f.file_id = v.file_id
                     WHERE v.version_id = $1 AND f.user_id = $2 AND v.is_active = true",
                )
                .bind(vid).bind(user_id).fetch_optional(&self.db).await?;
                    if exists.is_none() {
                        return Err(AppError::NotFound);
                    }
                    vid
                }
                None => current_version_id.ok_or(AppError::BadRequest(
                    "file upload is not complete — no active version".into(),
                ))?,
            };

        let version: (Vec<u8>, i64, i32) = sqlx::query_as(
            "SELECT encryption_header, total_size, total_chunks FROM file_versions WHERE version_id = $1",
        )
        .bind(target_version_id).fetch_one(&self.db).await?;

        let chunks: Vec<(i32, i32, i64, String)> = sqlx::query_as(
            "SELECT chunk_index, segment_index, chunk_size, r2_key FROM file_chunks WHERE version_id = $1 ORDER BY chunk_index",
        )
        .bind(target_version_id).fetch_all(&self.db).await?;

        let chunk_infos = self.storage.generate_download_urls(&chunks).await?;

        Ok(DownloadManifestResponse {
            file_id,
            version_id: target_version_id,
            encryption_header: crypto::encode_b64(&version.0),
            total_size: version.1,
            total_chunks: version.2,
            chunks: chunk_infos,
        })
    }

    pub async fn list_versions(
        &self,
        user_id: Uuid,
        file_id: Uuid,
    ) -> Result<Vec<FileVersionResponse>, AppError> {
        let exists: Option<(Uuid,)> = sqlx::query_as(
            "SELECT file_id FROM files WHERE file_id = $1 AND user_id = $2 AND deleted_at IS NULL",
        )
        .bind(file_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?;

        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        let versions = sqlx::query_as::<_, FileVersionResponse>(
            "SELECT version_id, version_number, total_size, total_chunks, is_active,
                    NOT is_active AS is_uploading, created_at, created_by_device_id
             FROM file_versions WHERE file_id = $1 ORDER BY version_number DESC",
        )
        .bind(file_id)
        .fetch_all(&self.db)
        .await?;

        Ok(versions)
    }

    pub async fn restore_version(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<(), AppError> {
        let mut tx = self.db.begin().await?;

        let version: Option<(Uuid, bool)> = sqlx::query_as(
            "SELECT v.version_id, v.is_active FROM file_versions v JOIN files f ON f.file_id = v.file_id
             WHERE v.version_id = $1 AND f.file_id = $2 AND f.user_id = $3 AND f.deleted_at IS NULL FOR UPDATE",
        )
        .bind(version_id).bind(file_id).bind(user_id).fetch_optional(&mut *tx).await?;

        let (_, is_already_active) = version.ok_or(AppError::NotFound)?;
        if is_already_active {
            return Ok(());
        }

        sqlx::query("UPDATE file_versions SET is_active = false WHERE file_id = $1")
            .bind(file_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("UPDATE file_versions SET is_active = true WHERE version_id = $1")
            .bind(version_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "UPDATE files SET current_version_id = $1, updated_at = now() WHERE file_id = $2",
        )
        .bind(version_id)
        .bind(file_id)
        .execute(&mut *tx)
        .await?;

        audit::log(
            &mut *tx,
            Some(user_id),
            Some(device_id),
            "file_version_restored",
            &serde_json::json!({ "file_id": file_id, "version_id": version_id }),
        )
        .await?;

        tx.commit().await?;

        self.broadcast(
            user_id,
            SyncEvent {
                event_type: "version_restored".into(),
                resource_type: "file".into(),
                resource_id: file_id,
                payload: serde_json::json!({ "version_id": version_id }),
            },
        );

        Ok(())
    }

    async fn validate_create_request(&self, req: &CreateFileRequest) -> Result<(), AppError> {
        if crate::core::crypto::decode_b64(&req.encrypted_metadata).is_err() {
            return Err(AppError::BadRequest(
                "invalid base64 encoding for encrypted_metadata".into(),
            ));
        }

        let metadata_nonce = crypto::decode_b64(&req.metadata_nonce)?;
        if metadata_nonce.len() != 24 {
            return Err(AppError::BadRequest(
                "metadata nonce must be 24 bytes (XChaCha20-Poly1305)".into(),
            ));
        }

        let plaintext_blake3 = crypto::decode_b64(&req.plaintext_blake3)?;
        if plaintext_blake3.len() != 32 {
            return Err(AppError::BadRequest(
                "plaintext_blake3 must be 32 bytes".into(),
            ));
        }

        let encryption_header = crypto::decode_b64(&req.encryption_header)?;
        if encryption_header.len() != 24 {
            return Err(AppError::BadRequest(
                "encryption header must be 24 bytes (secretstream)".into(),
            ));
        }

        if req.total_chunks <= 0 || req.total_chunks > MAX_CHUNKS_PER_FILE {
            return Err(AppError::BadRequest("invalid total_chunks".into()));
        }
        if req.chunks.len() as i32 != req.total_chunks {
            return Err(AppError::BadRequest(
                "chunks array length does not match total_chunks".into(),
            ));
        }
        if req.total_size <= 0 || req.total_size > MAX_FILE_SIZE {
            return Err(AppError::BadRequest("invalid total_size".into()));
        }

        let mut total_ciphertext_size: i64 = 0;
        for (i, chunk) in req.chunks.iter().enumerate() {
            if chunk.chunk_index != i as i32 {
                return Err(AppError::BadRequest(
                    "chunk indices must be sequential starting from 0".into(),
                ));
            }
            if chunk.chunk_size <= 0 {
                return Err(AppError::BadRequest(format!(
                    "chunk {} size must be positive",
                    i
                )));
            }
            total_ciphertext_size += chunk.chunk_size;

            let chunk_hash = crypto::decode_b64(&chunk.chunk_blake3)?;
            if chunk_hash.len() != 32 {
                return Err(AppError::BadRequest(format!(
                    "chunk {} blake3 must be 32 bytes",
                    i
                )));
            }
        }

        let expected_ciphertext_size = req.total_size + (req.total_chunks as i64 * 17);
        if total_ciphertext_size != expected_ciphertext_size {
            return Err(AppError::BadRequest(format!(
                "chunk sizes do not match total file size. expected {}, got {}",
                expected_ciphertext_size, total_ciphertext_size
            )));
        }

        Ok(())
    }

    pub async fn complete_upload(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        req: CompleteUploadRequest,
    ) -> Result<(), AppError> {
        let mut tx = self.db.begin().await?;

        let version: Option<(Uuid, bool, Uuid)> = sqlx::query_as(
            "SELECT v.version_id, v.is_active, f.user_id FROM file_versions v JOIN files f ON f.file_id = v.file_id
             WHERE v.version_id = $1 AND f.user_id = $2 AND f.deleted_at IS NULL FOR UPDATE",
        )
        .bind(req.version_id).bind(user_id).fetch_optional(&mut *tx).await?;

        let (_, is_active, _) = version.ok_or(AppError::NotFound)?;
        if is_active {
            return Ok(());
        }

        let chunks: Vec<(i32, String, Option<String>, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
            "SELECT chunk_index, r2_key, r2_etag, uploaded_at FROM file_chunks WHERE version_id = $1 ORDER BY chunk_index",
        )
        .bind(req.version_id).fetch_all(&mut *tx).await?;

        if chunks.is_empty() {
            return Err(AppError::BadRequest("no chunks found for version".into()));
        }

        for (chunk_index, _, _, uploaded_at) in &chunks {
            if let Some(etag) = req.r2_etags.get(chunk_index) {
                if uploaded_at.is_none() {
                    sqlx::query(
                        "UPDATE file_chunks SET uploaded_at = now(), r2_etag = $1 WHERE version_id = $2 AND chunk_index = $3",
                    )
                    .bind(etag).bind(req.version_id).bind(chunk_index)
                    .execute(&mut *tx).await?;
                }
            }
        }

        let unuploaded_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM file_chunks WHERE version_id = $1 AND uploaded_at IS NULL",
        )
        .bind(req.version_id)
        .fetch_one(&mut *tx)
        .await?;

        if unuploaded_count > 0 {
            let missing: Vec<i32> = sqlx::query_scalar(
                "SELECT chunk_index FROM file_chunks WHERE version_id = $1 AND uploaded_at IS NULL ORDER BY chunk_index"
            )
            .bind(req.version_id).fetch_all(&mut *tx).await?;

            tx.commit().await?;

            return Err(AppError::BadRequest(format!(
                "missing chunks: {:?}",
                missing
            )));
        }

        sqlx::query(
            "UPDATE file_versions SET is_active = false
             WHERE file_id = (SELECT file_id FROM file_versions WHERE version_id = $1) AND is_active = true AND version_id != $1",
        )
        .bind(req.version_id).execute(&mut *tx).await?;

        sqlx::query("UPDATE file_versions SET is_active = true WHERE version_id = $1")
            .bind(req.version_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "UPDATE files SET current_version_id = $1, updated_at = now() WHERE file_id = (SELECT file_id FROM file_versions WHERE version_id = $1)",
        )
        .bind(req.version_id).execute(&mut *tx).await?;

        audit::log(
            &mut *tx,
            Some(user_id),
            Some(device_id),
            "file_upload_completed",
            &serde_json::json!({ "version_id": req.version_id }),
        )
        .await?;

        tx.commit().await?;

        let file_id: Uuid =
            sqlx::query_scalar("SELECT file_id FROM file_versions WHERE version_id = $1")
                .bind(req.version_id)
                .fetch_one(&self.db)
                .await?;

        self.broadcast(
            user_id,
            SyncEvent {
                event_type: "uploaded".into(),
                resource_type: "file".into(),
                resource_id: file_id,
                payload: serde_json::json!({ "version_id": req.version_id }),
            },
        );

        Ok(())
    }

    pub async fn delete_file(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        file_id: Uuid,
    ) -> Result<(), AppError> {
        let mut tx = self.db.begin().await?;

        let affected = sqlx::query(
            "UPDATE files SET deleted_at = now(), updated_at = now() WHERE file_id = $1 AND user_id = $2 AND deleted_at IS NULL",
        )
        .bind(file_id).bind(user_id).execute(&mut *tx).await?.rows_affected();

        if affected == 0 {
            return Err(AppError::NotFound);
        }

        audit::log(
            &mut *tx,
            Some(user_id),
            Some(device_id),
            "file_deleted_to_trash",
            &serde_json::json!({ "file_id": file_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn restore_file(&self, user_id: Uuid, file_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE files SET deleted_at = NULL, updated_at = now() WHERE file_id = $1 AND user_id = $2 AND deleted_at IS NOT NULL")
            .bind(file_id).bind(user_id).execute(&self.db).await?;
        Ok(())
    }

    pub async fn permanently_delete_file(
        &self,
        user_id: Uuid,
        file_id: Uuid,
    ) -> Result<(), AppError> {
        let r2_keys: Vec<String> = sqlx::query_scalar(
            "SELECT c.r2_key FROM file_chunks c JOIN file_versions v ON c.version_id = v.version_id WHERE v.file_id = $1",
        )
        .bind(file_id).fetch_all(&self.db).await?;

        sqlx::query("DELETE FROM files WHERE file_id = $1 AND user_id = $2")
            .bind(file_id)
            .bind(user_id)
            .execute(&self.db)
            .await?;

        self.storage.delete_objects_best_effort(&r2_keys).await;
        Ok(())
    }

    pub async fn bulk_delete(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        req: BulkDeleteRequest,
    ) -> Result<(), AppError> {
        let mut tx = self.db.begin().await?;
        let mut r2_keys_to_delete = Vec::new();

        if !req.file_ids.is_empty() {
            let chunk_keys: Vec<String> = sqlx::query_scalar(
                "SELECT c.r2_key FROM file_chunks c JOIN file_versions v ON c.version_id = v.version_id JOIN files f ON v.file_id = f.file_id
                 WHERE f.file_id = ANY($1) AND f.user_id = $2",
            )
            .bind(&req.file_ids).bind(user_id).fetch_all(&mut *tx).await?;

            r2_keys_to_delete.extend(chunk_keys);

            sqlx::query("UPDATE files SET deleted_at = now(), updated_at = now() WHERE file_id = ANY($1) AND user_id = $2")
                .bind(&req.file_ids).bind(user_id).execute(&mut *tx).await?;
        }

        if !req.folder_ids.is_empty() {
            let all_folder_ids =
                FolderService::get_descendant_folder_ids(&mut *tx, &req.folder_ids, user_id)
                    .await?;

            let files_in_folders: Vec<Uuid> = sqlx::query_scalar(
                "SELECT file_id FROM files WHERE folder_id = ANY($1) AND user_id = $2 AND deleted_at IS NULL",
            )
            .bind(&all_folder_ids).bind(user_id).fetch_all(&mut *tx).await?;

            if !files_in_folders.is_empty() {
                let chunk_keys: Vec<String> = sqlx::query_scalar(
                    "SELECT c.r2_key FROM file_chunks c JOIN file_versions v ON c.version_id = v.version_id JOIN files f ON v.file_id = f.file_id
                     WHERE f.file_id = ANY($1) AND f.user_id = $2",
                )
                .bind(&files_in_folders).bind(user_id).fetch_all(&mut *tx).await?;

                r2_keys_to_delete.extend(chunk_keys);

                sqlx::query("UPDATE files SET deleted_at = now(), updated_at = now() WHERE file_id = ANY($1) AND user_id = $2")
                    .bind(&files_in_folders).bind(user_id).execute(&mut *tx).await?;
            }

            FolderService::soft_delete_many(&mut *tx, &all_folder_ids, user_id).await?;
        }

        audit::log(
            &mut *tx,
            Some(user_id),
            Some(device_id),
            "bulk_delete",
            &serde_json::json!({ "file_ids": req.file_ids, "folder_ids": req.folder_ids }),
        )
        .await?;

        tx.commit().await?;

        self.storage
            .delete_objects_best_effort(&r2_keys_to_delete)
            .await;

        Ok(())
    }

    /// Pre-checks dedup and quota before client wastes time encrypting.
    pub async fn precheck_upload(
        &self,
        user_id: Uuid,
        plaintext_blake3: String,
        total_size: i64,
    ) -> Result<serde_json::Value, AppError> {
        // 1. Check Quota
        let current_usage: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(total_size), 0) AS BIGINT) FROM files WHERE user_id = $1 AND deleted_at IS NULL"
    )
    .bind(user_id)
    .fetch_one(&self.db)
    .await?;

        const USER_STORAGE_QUOTA_BYTES: i64 = 100 * 1024 * 1024;
        if current_usage + total_size > USER_STORAGE_QUOTA_BYTES {
            return Err(AppError::BadRequest("storage quota exceeded".into()));
        }

        // 2. Check Dedup
        let hash_bytes = crate::core::crypto::decode_b64(&plaintext_blake3)?;
        let existing: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT f.file_id, f.current_version_id FROM files f 
         JOIN file_versions v ON f.current_version_id = v.version_id 
         WHERE f.user_id = $1 AND v.plaintext_blake3 = $2 AND f.deleted_at IS NULL AND v.is_active = true"
    )
    .bind(user_id)
    .bind(&hash_bytes)
    .fetch_optional(&self.db)
    .await?;

        Ok(serde_json::json!({
            "allowed": true,
            "deduplicated": existing.is_some(),
            "existing_file_id": existing.map(|(f, _)| f),
            "existing_version_id": existing.map(|(_, v)| v),
        }))
    }

    /// Cleans up orphaned chunks and DB records when an upload is cancelled.
    pub async fn cancel_upload(
        &self,
        user_id: Uuid,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<(), AppError> {
        let mut tx = self.db.begin().await?;

        let r2_keys: Vec<String> =
            sqlx::query_scalar("SELECT c.r2_key FROM file_chunks c WHERE c.version_id = $1")
                .bind(version_id)
                .fetch_all(&mut *tx)
                .await?;

        sqlx::query("DELETE FROM file_chunks WHERE version_id = $1")
            .bind(version_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM file_versions WHERE version_id = $1 AND is_active = false")
            .bind(version_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "DELETE FROM files WHERE file_id = $1 AND user_id = $2 AND current_version_id = $3",
        )
        .bind(file_id)
        .bind(user_id)
        .bind(version_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        self.storage.delete_objects_best_effort(&r2_keys).await;

        Ok(())
    }

    pub async fn bulk_cancel_uploads(
        &self,
        user_id: Uuid,
        uploads: Vec<crate::features::files::dto::CancelTarget>,
    ) -> Result<usize, AppError> {
        let mut cancelled = 0usize;
        for target in uploads {
            match self
                .cancel_upload(user_id, target.file_id, target.version_id)
                .await
            {
                Ok(()) => cancelled += 1,
                Err(e) => tracing::warn!(error = ?e, "failed to cancel individual upload"),
            }
        }
        Ok(cancelled)
    }

    pub async fn cleanup_orphaned_versions(
        &self,
        older_than_hours: i64,
    ) -> Result<usize, AppError> {
        let cutoff = Utc::now() - chrono::Duration::hours(older_than_hours);

        let r2_keys: Vec<String> = sqlx::query_scalar(
            r#"
        SELECT c.r2_key
        FROM file_chunks c
        JOIN file_versions v ON c.version_id = v.version_id
        WHERE v.is_active = false
          AND v.created_at < $1
          AND NOT EXISTS (
            SELECT 1 FROM files f WHERE f.current_version_id = v.version_id
          )
        "#,
        )
        .bind(cutoff)
        .fetch_all(&self.db)
        .await?;

        let key_count = r2_keys.len();
        self.storage.delete_objects_best_effort(&r2_keys).await;

        let result = sqlx::query(
            r#"
        DELETE FROM file_versions
        WHERE is_active = false
          AND created_at < $1
          AND NOT EXISTS (
            SELECT 1 FROM files f WHERE f.current_version_id = file_versions.version_id
          )
        "#,
        )
        .bind(cutoff)
        .execute(&self.db)
        .await?;

        tracing::info!(
            deleted_versions = result.rows_affected(),
            deleted_r2_objects = key_count,
            "orphaned upload cleanup completed"
        );

        Ok(result.rows_affected() as usize)
    }

    pub async fn verify_download_completeness(
        &self,
        user_id: Uuid,
        file_id: Uuid,
        version_id: Option<Uuid>,
    ) -> Result<bool, AppError> {
        let target_version_id = match version_id {
            Some(vid) => vid,
            None => {
                let row: Option<(Option<Uuid>,)> = sqlx::query_as(
                "SELECT current_version_id FROM files WHERE file_id = $1 AND user_id = $2 AND deleted_at IS NULL",
            )
            .bind(file_id)
            .bind(user_id)
            .fetch_optional(&self.db)
            .await?;
                row.ok_or(AppError::NotFound)?
                    .0
                    .ok_or(AppError::BadRequest("no active version".into()))?
            }
        };

        let missing: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM file_chunks WHERE version_id = $1 AND uploaded_at IS NULL",
        )
        .bind(target_version_id)
        .fetch_one(&self.db)
        .await?;

        Ok(missing == 0)
    }
}
