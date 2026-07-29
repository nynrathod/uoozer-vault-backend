use sqlx::PgPool;
use uuid::Uuid;

use crate::app_state::{AppState, SyncEvent};
use crate::core::crypto;
use crate::core::error::AppError;

use super::dto::{CreateFolderRequest, FolderResponse, UpdateFolderRequest};

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
        state: &AppState,
    ) -> Result<FolderResponse, AppError> {
        let metadata_nonce = crypto::decode_b64(&req.metadata_nonce)?;
        if metadata_nonce.len() != 24 {
            return Err(AppError::BadRequest(
                "metadata nonce must be 24 bytes".to_string(),
            ));
        }

        let encrypted_metadata = crypto::decode_b64(&req.encrypted_metadata)?;

        if let Some(parent_id) = req.parent_folder_id {
            self.verify_folder_ownership(parent_id, user_id).await?;
        }

        let folder_id = Uuid::new_v4();
        let folder = sqlx::query_as::<_, FolderResponse>(
            "INSERT INTO folders (folder_id, user_id, parent_folder_id, encrypted_metadata, metadata_nonce) VALUES ($1, $2, $3, $4, $5) RETURNING folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, created_at, updated_at",
        )
        .bind(folder_id)
        .bind(user_id)
        .bind(req.parent_folder_id)
        .bind(&encrypted_metadata)
        .bind(&metadata_nonce)
        .fetch_one(&self.db)
        .await?;

        state.broadcast_sync(
            user_id,
            SyncEvent {
                event_type: "created".to_string(),
                resource_type: "folder".to_string(),
                resource_id: folder.folder_id,
                payload: serde_json::to_value(&folder).unwrap_or_default(),
            },
        );

        Ok(folder)
    }

    pub async fn get_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
    ) -> Result<FolderResponse, AppError> {
        self.verify_folder_ownership(folder_id, user_id).await?;

        let folder = sqlx::query_as::<_, FolderResponse>(
            "SELECT folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, created_at, updated_at FROM folders WHERE folder_id = $1 AND deleted_at IS NULL",
        )
        .bind(folder_id)
        .fetch_one(&self.db)
        .await?;

        Ok(folder)
    }

    pub async fn list_folders(
        &self,
        user_id: Uuid,
        parent_folder_id: Option<Uuid>,
    ) -> Result<Vec<FolderResponse>, AppError> {
        let folders = sqlx::query_as::<_, FolderResponse>(
            "SELECT folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, created_at, updated_at FROM folders WHERE user_id = $1 AND parent_folder_id IS NOT DISTINCT FROM $2 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .bind(parent_folder_id)
        .fetch_all(&self.db)
        .await?;

        Ok(folders)
    }

    pub async fn update_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        req: UpdateFolderRequest,
        state: &AppState,
    ) -> Result<FolderResponse, AppError> {
        self.verify_folder_ownership(folder_id, user_id).await?;

        let metadata_nonce = crypto::decode_b64(&req.metadata_nonce)?;
        if metadata_nonce.len() != 24 {
            return Err(AppError::BadRequest(
                "metadata nonce must be 24 bytes".to_string(),
            ));
        }

        let encrypted_metadata = crypto::decode_b64(&req.encrypted_metadata)?;

        if let Some(new_parent) = req.parent_folder_id {
            if new_parent == folder_id {
                return Err(AppError::BadRequest(
                    "cannot move folder into itself".to_string(),
                ));
            }
            self.verify_folder_ownership(new_parent, user_id).await?;
        }

        let folder = sqlx::query_as::<_, FolderResponse>(
            "UPDATE folders SET encrypted_metadata = $1, metadata_nonce = $2, parent_folder_id = $3, updated_at = now() WHERE folder_id = $4 AND deleted_at IS NULL RETURNING folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, created_at, updated_at",
        )
        .bind(&encrypted_metadata)
        .bind(&metadata_nonce)
        .bind(req.parent_folder_id)
        .bind(folder_id)
        .fetch_one(&self.db)
        .await?;

        state.broadcast_sync(
            user_id,
            SyncEvent {
                event_type: "updated".to_string(),
                resource_type: "folder".to_string(),
                resource_id: folder.folder_id,
                payload: serde_json::to_value(&folder).unwrap_or_default(),
            },
        );

        Ok(folder)
    }

    pub async fn delete_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        state: &AppState,
    ) -> Result<(), AppError> {
        self.verify_folder_ownership(folder_id, user_id).await?;

        sqlx::query("UPDATE folders SET deleted_at = now() WHERE folder_id = $1")
            .bind(folder_id)
            .execute(&self.db)
            .await?;

        state.broadcast_sync(
            user_id,
            SyncEvent {
                event_type: "deleted".to_string(),
                resource_type: "folder".to_string(),
                resource_id: folder_id,
                payload: serde_json::json!({}),
            },
        );

        Ok(())
    }

    async fn verify_folder_ownership(
        &self,
        folder_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        let exists: Option<(Uuid,)> = sqlx::query_as(
            "SELECT folder_id FROM folders WHERE folder_id = $1 AND user_id = $2 AND deleted_at IS NULL",
        )
        .bind(folder_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await?;

        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        Ok(())
    }
}
