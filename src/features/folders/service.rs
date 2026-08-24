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

    /// Checks if `new_parent_id` is `folder_id` itself or any of its descendants.
    async fn is_descendant_or_self(
        &self,
        folder_id: Uuid,
        new_parent_id: Uuid,
    ) -> Result<bool, AppError> {
        let is_cycle: bool = sqlx::query_scalar(
            r#"
            WITH RECURSIVE descendants AS (
                SELECT folder_id FROM folders WHERE folder_id = $1 AND deleted_at IS NULL
                UNION ALL
                SELECT f.folder_id FROM folders f
                INNER JOIN descendants d ON f.parent_folder_id = d.folder_id
                WHERE f.deleted_at IS NULL
            )
            SELECT EXISTS(SELECT 1 FROM descendants WHERE folder_id = $2)
            "#,
        )
        .bind(folder_id)
        .bind(new_parent_id)
        .fetch_one(&self.db)
        .await?;

        Ok(is_cycle)
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
            "INSERT INTO folders (folder_id, user_id, parent_folder_id, encrypted_metadata, metadata_nonce) VALUES ($1, $2, $3, $4, $5) 
             RETURNING folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, deleted_at, created_at, updated_at",
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
                seq: 0,
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
            "SELECT folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, deleted_at, created_at, updated_at FROM folders WHERE folder_id = $1 AND deleted_at IS NULL",
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
        trashed: bool,
    ) -> Result<Vec<FolderResponse>, AppError> {
        if trashed {
            let folders = sqlx::query_as::<_, FolderResponse>(
                "SELECT folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, deleted_at, created_at, updated_at 
                 FROM folders 
                 WHERE user_id = $1 AND parent_folder_id IS NOT DISTINCT FROM $2 AND deleted_at IS NOT NULL",
            )
            .bind(user_id).bind(parent_folder_id).fetch_all(&self.db).await?;

            Ok(folders)
        } else {
            let folders = sqlx::query_as::<_, FolderResponse>(
                "SELECT folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, deleted_at, created_at, updated_at 
                 FROM folders 
                 WHERE user_id = $1 AND parent_folder_id IS NOT DISTINCT FROM $2 AND deleted_at IS NULL",
            )
            .bind(user_id).bind(parent_folder_id).fetch_all(&self.db).await?;

            Ok(folders)
        }
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
            if self.is_descendant_or_self(folder_id, new_parent).await? {
                return Err(AppError::BadRequest(
                    "cannot move folder into itself or its own descendant".to_string(),
                ));
            }
            self.verify_folder_ownership(new_parent, user_id).await?;
        }

        let folder = sqlx::query_as::<_, FolderResponse>(
            "UPDATE folders SET encrypted_metadata = $1, metadata_nonce = $2, parent_folder_id = $3, updated_at = now() 
             WHERE folder_id = $4 AND deleted_at IS NULL 
             RETURNING folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, deleted_at, created_at, updated_at",
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
                seq: 0,
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

        let mut tx = self.db.begin().await?;

        let all_folder_ids =
            Self::get_descendant_folder_ids(&mut *tx, &[folder_id], user_id).await?;

        sqlx::query(
            "UPDATE files SET deleted_at = now(), updated_at = now() 
             WHERE folder_id = ANY($1) AND user_id = $2 AND deleted_at IS NULL",
        )
        .bind(&all_folder_ids)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        Self::soft_delete_many(&mut *tx, &all_folder_ids, user_id).await?;

        state.broadcast_sync(
            user_id,
            SyncEvent {
                seq: 0,
                event_type: "deleted".to_string(),
                resource_type: "folder".to_string(),
                resource_id: folder_id,
                payload: serde_json::json!({}),
            },
        );

        tx.commit().await?;
        Ok(())
    }

    pub async fn permanent_delete_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        state: &AppState,
    ) -> Result<(), AppError> {
        let exists: Option<(Uuid,)> =
            sqlx::query_as("SELECT folder_id FROM folders WHERE folder_id = $1 AND user_id = $2")
                .bind(folder_id)
                .bind(user_id)
                .fetch_optional(&self.db)
                .await?;

        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        let all_folder_ids: Vec<Uuid> = sqlx::query_scalar(
            r#"
            WITH RECURSIVE descendants AS (
                SELECT folder_id FROM folders WHERE folder_id = $1
                UNION ALL
                SELECT f.folder_id FROM folders f
                INNER JOIN descendants d ON f.parent_folder_id = d.folder_id
            )
            SELECT folder_id FROM descendants
            "#,
        )
        .bind(folder_id)
        .fetch_all(&self.db)
        .await?;

        let mut tx = self.db.begin().await?;

        let r2_keys: Vec<String> = sqlx::query_scalar(
            "SELECT c.r2_key FROM file_chunks c 
             JOIN file_versions v ON c.version_id = v.version_id 
             JOIN files f ON v.file_id = f.file_id 
             WHERE f.folder_id = ANY($1) AND f.user_id = $2",
        )
        .bind(&all_folder_ids)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM files WHERE folder_id = ANY($1) AND user_id = $2")
            .bind(&all_folder_ids)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("DELETE FROM folders WHERE folder_id = ANY($1) AND user_id = $2")
            .bind(&all_folder_ids)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        state.storage.delete_objects_best_effort(&r2_keys).await;

        Ok(())
    }

    pub async fn verify_folder_ownership(
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

    pub async fn get_descendant_folder_ids<'e, E>(
        executor: E,
        folder_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, AppError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        if folder_ids.is_empty() {
            return Ok(Vec::new());
        }

        let ids: Vec<Uuid> = sqlx::query_scalar(
            r#"
            WITH RECURSIVE descendants AS (
                SELECT folder_id FROM folders
                WHERE folder_id = ANY($1) AND user_id = $2 AND deleted_at IS NULL
                UNION ALL
                SELECT f.folder_id FROM folders f
                INNER JOIN descendants d ON f.parent_folder_id = d.folder_id
                WHERE f.deleted_at IS NULL
            )
            SELECT folder_id FROM descendants
            "#,
        )
        .bind(folder_ids)
        .bind(user_id)
        .fetch_all(executor)
        .await?;

        Ok(ids)
    }

    pub async fn soft_delete_many<'e, E>(
        executor: E,
        folder_ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<(), AppError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        if folder_ids.is_empty() {
            return Ok(());
        }

        sqlx::query(
            "UPDATE folders SET deleted_at = now() WHERE folder_id = ANY($1) AND user_id = $2",
        )
        .bind(folder_ids)
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    pub async fn create_folders_bulk(
        &self,
        user_id: Uuid,
        reqs: Vec<CreateFolderRequest>,
        state: &AppState,
    ) -> Result<Vec<FolderResponse>, AppError> {
        let mut tx = self.db.begin().await?;
        let mut results = Vec::with_capacity(reqs.len());

        for req in reqs {
            let metadata_nonce = crypto::decode_b64(&req.metadata_nonce)?;
            if metadata_nonce.len() != 24 {
                return Err(AppError::BadRequest(
                    "metadata nonce must be 24 bytes".into(),
                ));
            }
            let encrypted_metadata = crypto::decode_b64(&req.encrypted_metadata)?;

            let folder_id = req.folder_id.unwrap_or_else(Uuid::new_v4);

            let folder = sqlx::query_as::<_, FolderResponse>(
                "INSERT INTO folders (folder_id, user_id, parent_folder_id, encrypted_metadata, metadata_nonce) VALUES ($1, $2, $3, $4, $5) 
                 RETURNING folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, deleted_at, created_at, updated_at",
            )
            .bind(folder_id)
            .bind(user_id)
            .bind(req.parent_folder_id)
            .bind(&encrypted_metadata)
            .bind(&metadata_nonce)
            .fetch_one(&mut *tx)
            .await?;

            state.broadcast_sync(
                user_id,
                SyncEvent {
                    seq: 0,
                    event_type: "created".to_string(),
                    resource_type: "folder".to_string(),
                    resource_id: folder.folder_id,
                    payload: serde_json::to_value(&folder).unwrap_or_default(),
                },
            );
            results.push(folder);
        }

        tx.commit().await?;
        Ok(results)
    }

    pub async fn get_folder_file_tree(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
    ) -> Result<Vec<crate::features::folders::dto::FlatTreeNode>, AppError> {
        self.verify_folder_ownership(folder_id, user_id).await?;

        let rows: Vec<(
            Uuid,
            Option<Uuid>,
            String,
            Vec<u8>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<i64>,
        )> = sqlx::query_as(
            r#"
            WITH RECURSIVE folder_tree AS (
                SELECT folder_id, parent_folder_id, encrypted_metadata, metadata_nonce
                FROM folders 
                WHERE folder_id = $1 AND user_id = $2 AND deleted_at IS NULL
                
                UNION ALL
                
                SELECT f.folder_id, f.parent_folder_id, f.encrypted_metadata, f.metadata_nonce
                FROM folders f
                JOIN folder_tree ft ON f.parent_folder_id = ft.folder_id
                WHERE f.deleted_at IS NULL
            )
            SELECT folder_id as id, 
                   CASE WHEN folder_id = $1 THEN NULL ELSE parent_folder_id END as parent_id, 
                   'folder' as node_type, 
                   encrypted_metadata, 
                   metadata_nonce, 
                   NULL::bytea as wrapped_file_key, 
                   NULL::bytea as wrapped_file_key_nonce, 
                   NULL::bigint as total_size
            FROM folder_tree
            
            UNION ALL
            
            SELECT f.file_id as id, 
                   f.folder_id as parent_id, 
                   'file' as node_type, 
                   f.encrypted_metadata, 
                   f.metadata_nonce, 
                   v.wrapped_file_key, 
                   v.wrapped_file_key_nonce, 
                   f.total_size
            FROM files f
            JOIN file_versions v ON f.current_version_id = v.version_id
            WHERE f.folder_id IN (SELECT folder_id FROM folder_tree) AND f.deleted_at IS NULL
            "#,
        )
        .bind(folder_id)
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, parent_id, node_type, meta, nonce, key, key_nonce, size)| {
                    crate::features::folders::dto::FlatTreeNode {
                        id,
                        parent_id,
                        node_type,
                        encrypted_metadata: crate::core::crypto::encode_b64(&meta),
                        metadata_nonce: crate::core::crypto::encode_b64(&nonce),
                        wrapped_file_key: key.map(|k| crate::core::crypto::encode_b64(&k)),
                        wrapped_file_key_nonce: key_nonce
                            .map(|k| crate::core::crypto::encode_b64(&k)),
                        total_size: size,
                    }
                },
            )
            .collect())
    }

    pub async fn restore_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        state: &AppState,
    ) -> Result<(), AppError> {
        let mut tx = self.db.begin().await?;

        let all_folder_ids: Vec<Uuid> = sqlx::query_scalar(
            r#"
            WITH RECURSIVE descendants AS (
                SELECT folder_id FROM folders WHERE folder_id = $1 AND user_id = $2
                UNION ALL
                SELECT f.folder_id FROM folders f
                INNER JOIN descendants d ON f.parent_folder_id = d.folder_id
                WHERE f.user_id = $2
            )
            SELECT folder_id FROM descendants
            "#,
        )
        .bind(folder_id)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE files SET deleted_at = NULL, updated_at = now() 
             WHERE folder_id = ANY($1) AND user_id = $2 AND deleted_at IS NOT NULL",
        )
        .bind(&all_folder_ids)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE folders SET deleted_at = NULL, updated_at = now() 
             WHERE folder_id = ANY($1) AND user_id = $2 AND deleted_at IS NOT NULL",
        )
        .bind(&all_folder_ids)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        state.broadcast_sync(
            user_id,
            SyncEvent {
                seq: 0,
                event_type: "restored".to_string(),
                resource_type: "folder".to_string(),
                resource_id: folder_id,
                payload: serde_json::json!({}),
            },
        );

        tx.commit().await?;
        Ok(())
    }
}
