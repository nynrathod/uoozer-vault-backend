use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::app_state::SyncEvent;
use crate::core::crypto;
use crate::core::error::AppError;
use crate::features::audit;

use super::dto::*;

pub struct FolderService {
    db: PgPool,
}

impl FolderService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn create_folder(
        &self,
        user_id: Uuid,
        req: CreateFolderRequest,
        state: &crate::app_state::AppState,
    ) -> Result<FolderResponse, AppError> {
        let encrypted_metadata = crypto::decode_b64(&req.encrypted_metadata)?;
        let metadata_nonce = crypto::decode_b64(&req.metadata_nonce)?;

        if metadata_nonce.len() != 24 {
            return Err(AppError::BadRequest(
                "metadata nonce must be 24 bytes".to_string(),
            ));
        }

        // Verify parent folder exists and belongs to user.
        if let Some(parent_id) = req.parent_folder_id {
            self.verify_folder_ownership(parent_id, user_id).await?;
        }

        let folder_id = Uuid::new_v4();

        let row: (Uuid, Option<Uuid>, Vec<u8>, Vec<u8>, DateTime<Utc>, DateTime<Utc>) =
            sqlx::query_as(
                r#"
                INSERT INTO folders (folder_id, user_id, parent_folder_id, encrypted_metadata, metadata_nonce)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, created_at, updated_at
                "#,
            )
            .bind(folder_id)
            .bind(user_id)
            .bind(req.parent_folder_id)
            .bind(&encrypted_metadata)
            .bind(&metadata_nonce)
            .fetch_one(&self.db)
            .await?;

        let resp = FolderResponse {
            folder_id: row.0,
            parent_folder_id: row.1,
            encrypted_metadata: crypto::encode_b64(&row.2),
            metadata_nonce: crypto::encode_b64(&row.3),
            created_at: row.4,
            updated_at: row.5,
        };

        // Broadcast sync event to other devices.
        state.broadcast_sync(
            user_id,
            SyncEvent {
                event_type: "created".to_string(),
                resource_type: "folder".to_string(),
                resource_id: resp.folder_id,
                payload: serde_json::to_value(&resp).unwrap_or_default(),
                timestamp: Utc::now(),
            },
        );

        audit::log(
            &self.db,
            user_id,
            None,
            "folder_created",
            &serde_json::json!({ "folder_id": folder_id }),
        )
        .await
        .ok();

        Ok(resp)
    }

    pub async fn get_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
    ) -> Result<FolderResponse, AppError> {
        let row: (Uuid, Option<Uuid>, Vec<u8>, Vec<u8>, DateTime<Utc>, DateTime<Utc>) =
            sqlx::query_as(
                r#"
                SELECT folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, created_at, updated_at
                FROM folders
                WHERE folder_id = $1 AND user_id = $2 AND deleted_at IS NULL
                "#,
            )
            .bind(folder_id)
            .bind(user_id)
            .fetch_one(&self.db)
            .await?;

        Ok(FolderResponse {
            folder_id: row.0,
            parent_folder_id: row.1,
            encrypted_metadata: crypto::encode_b64(&row.2),
            metadata_nonce: crypto::encode_b64(&row.3),
            created_at: row.4,
            updated_at: row.5,
        })
    }

    pub async fn list_folders(
        &self,
        user_id: Uuid,
        parent_folder_id: Option<Uuid>,
    ) -> Result<Vec<FolderResponse>, AppError> {
        let rows: Vec<(Uuid, Option<Uuid>, Vec<u8>, Vec<u8>, DateTime<Utc>, DateTime<Utc>)> =
            sqlx::query_as(
                r#"
                SELECT folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, created_at, updated_at
                FROM folders
                WHERE user_id = $1 AND deleted_at IS NULL AND parent_folder_id IS NOT DISTINCT FROM $2
                ORDER BY created_at ASC
                "#,
            )
            .bind(user_id)
            .bind(parent_folder_id)
            .fetch_all(&self.db)
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| FolderResponse {
                folder_id: row.0,
                parent_folder_id: row.1,
                encrypted_metadata: crypto::encode_b64(&row.2),
                metadata_nonce: crypto::encode_b64(&row.3),
                created_at: row.4,
                updated_at: row.5,
            })
            .collect())
    }

    pub async fn update_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        req: UpdateFolderRequest,
        state: &crate::app_state::AppState,
    ) -> Result<FolderResponse, AppError> {
        self.verify_folder_ownership(folder_id, user_id).await?;

        let encrypted_metadata = crypto::decode_b64(&req.encrypted_metadata)?;
        let metadata_nonce = crypto::decode_b64(&req.metadata_nonce)?;

        if metadata_nonce.len() != 24 {
            return Err(AppError::BadRequest(
                "metadata nonce must be 24 bytes".to_string(),
            ));
        }

        // Verify new parent if moving.
        if let Some(parent_id) = req.parent_folder_id {
            if parent_id == folder_id {
                return Err(AppError::BadRequest(
                    "cannot move folder into itself".to_string(),
                ));
            }
            self.verify_folder_ownership(parent_id, user_id).await?;
        }

        let row: (Uuid, Option<Uuid>, Vec<u8>, Vec<u8>, DateTime<Utc>, DateTime<Utc>) =
            sqlx::query_as(
                r#"
                UPDATE folders
                SET encrypted_metadata = $1,
                    metadata_nonce = $2,
                    parent_folder_id = $3,
                    updated_at = now()
                WHERE folder_id = $4 AND user_id = $5 AND deleted_at IS NULL
                RETURNING folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, created_at, updated_at
                "#,
            )
            .bind(&encrypted_metadata)
            .bind(&metadata_nonce)
            .bind(req.parent_folder_id)
            .bind(folder_id)
            .bind(user_id)
            .fetch_one(&self.db)
            .await?;

        let resp = FolderResponse {
            folder_id: row.0,
            parent_folder_id: row.1,
            encrypted_metadata: crypto::encode_b64(&row.2),
            metadata_nonce: crypto::encode_b64(&row.3),
            created_at: row.4,
            updated_at: row.5,
        };

        state.broadcast_sync(
            user_id,
            SyncEvent {
                event_type: "updated".to_string(),
                resource_type: "folder".to_string(),
                resource_id: resp.folder_id,
                payload: serde_json::to_value(&resp).unwrap_or_default(),
                timestamp: Utc::now(),
            },
        );

        Ok(resp)
    }

    pub async fn delete_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        state: &crate::app_state::AppState,
    ) -> Result<(), AppError> {
        self.verify_folder_ownership(folder_id, user_id).await?;

        // Soft delete (cascades to children via FK ON DELETE CASCADE — but we use
        // soft delete so we do it manually for all descendants).
        sqlx::query(
            r#"
            WITH RECURSIVE descendants AS (
                SELECT folder_id FROM folders WHERE folder_id = $1 AND user_id = $2
                UNION ALL
                SELECT f.folder_id FROM folders f
                INNER JOIN descendants d ON f.parent_folder_id = d.folder_id
                WHERE f.user_id = $2 AND f.deleted_at IS NULL
            )
            UPDATE folders SET deleted_at = now(), updated_at = now()
            WHERE folder_id IN (SELECT folder_id FROM descendants)
            "#,
        )
        .bind(folder_id)
        .bind(user_id)
        .execute(&self.db)
        .await?;

        state.broadcast_sync(
            user_id,
            SyncEvent {
                event_type: "deleted".to_string(),
                resource_type: "folder".to_string(),
                resource_id: folder_id,
                payload: serde_json::json!({}),
                timestamp: Utc::now(),
            },
        );

        audit::log(
            &self.db,
            user_id,
            None,
            "folder_deleted",
            &serde_json::json!({ "folder_id": folder_id }),
        )
        .await
        .ok();

        Ok(())
    }

    async fn verify_folder_ownership(
        &self,
        folder_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM folders WHERE folder_id = $1 AND user_id = $2 AND deleted_at IS NULL)",
        )
        .bind(folder_id)
        .bind(user_id)
        .fetch_one(&self.db)
        .await?;

        if !exists {
            return Err(AppError::NotFound);
        }
        Ok(())
    }
}
