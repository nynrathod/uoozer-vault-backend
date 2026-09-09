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

        // Prevent moving into self or any descendant (cycle detection)
        if let Some(new_parent) = req.parent_folder_id {
            if new_parent == folder_id {
                return Err(AppError::BadRequest(
                    "cannot move folder into itself".to_string(),
                ));
            }
            if self.is_descendant_or_self(folder_id, new_parent).await? {
                return Err(AppError::BadRequest(
                    "cannot move folder into itself or its own descendant".to_string(),
                ));
            }
            self.verify_folder_ownership(new_parent, user_id).await?;
        }

        let folder = sqlx::query_as::<_, FolderResponse>(
            "UPDATE folders SET encrypted_metadata = $1, metadata_nonce = $2, parent_folder_id = $3, updated_at = now() 
             WHERE folder_id = $4 AND user_id = $5 AND deleted_at IS NULL 
             RETURNING folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, deleted_at, created_at, updated_at",
        )
        .bind(&encrypted_metadata)
        .bind(&metadata_nonce)
        .bind(req.parent_folder_id)
        .bind(folder_id)
        .bind(user_id)
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
        let mut tx = self.db.begin().await?;

        let exists: Option<Uuid> = sqlx::query_scalar(
            "SELECT folder_id FROM folders
         WHERE folder_id = $1 AND user_id = $2 AND deleted_at IS NULL
         FOR UPDATE",
        )
        .bind(folder_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        let subtree: Vec<Uuid> = sqlx::query_scalar(
            r#"
        WITH RECURSIVE tree AS (
            SELECT folder_id FROM folders WHERE folder_id = $1 AND user_id = $2
            UNION
            SELECT f.folder_id FROM folders f
            JOIN tree t ON f.parent_folder_id = t.folder_id
            WHERE f.user_id = $2
        )
        SELECT folder_id FROM tree
        "#,
        )
        .bind(folder_id)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE folders SET deleted_at = now(), updated_at = now()
         WHERE folder_id = ANY($1) AND deleted_at IS NULL",
        )
        .bind(&subtree)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE files SET deleted_at = now(), updated_at = now()
         WHERE folder_id = ANY($1) AND deleted_at IS NULL",
        )
        .bind(&subtree)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

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
        Ok(())
    }

    pub async fn restore_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        state: &AppState,
    ) -> Result<(), AppError> {
        let mut tx = self.db.begin().await?;

        let trash_time: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT deleted_at FROM folders
         WHERE folder_id = $1 AND user_id = $2 AND deleted_at IS NOT NULL
         FOR UPDATE",
        )
        .bind(folder_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let trash_time = trash_time.ok_or(AppError::NotFound)?;

        sqlx::query(
            r#"
    WITH RECURSIVE tree AS (
        SELECT folder_id FROM folders WHERE folder_id = $1 AND user_id = $2
        UNION
        SELECT f.folder_id FROM folders f
        JOIN tree t ON f.parent_folder_id = t.folder_id
        WHERE f.user_id = $2
    )
    UPDATE folders SET deleted_at = NULL, updated_at = now()
    WHERE folder_id IN (SELECT folder_id FROM tree) AND deleted_at = $3
    "#,
        )
        .bind(folder_id)
        .bind(user_id)
        .bind(trash_time)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
    WITH RECURSIVE tree AS (
        SELECT folder_id FROM folders WHERE folder_id = $1 AND user_id = $2
        UNION
        SELECT f.folder_id FROM folders f
        JOIN tree t ON f.parent_folder_id = t.folder_id
        WHERE f.user_id = $2
    )
    UPDATE files SET deleted_at = NULL, updated_at = now()
    WHERE folder_id IN (SELECT folder_id FROM tree) AND deleted_at = $3
    "#,
        )
        .bind(folder_id)
        .bind(user_id)
        .bind(trash_time)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
        WITH RECURSIVE chain AS (
            SELECT parent_folder_id AS folder_id FROM folders
            WHERE folder_id = $1 AND parent_folder_id IS NOT NULL
            UNION
            SELECT f.parent_folder_id FROM folders f
            JOIN chain c ON f.folder_id = c.folder_id AND f.parent_folder_id IS NOT NULL
        )
        UPDATE folders SET deleted_at = NULL, updated_at = now()
        WHERE folder_id IN (SELECT folder_id FROM chain) AND deleted_at IS NOT NULL
        "#,
        )
        .bind(folder_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

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
        Ok(())
    }

    pub async fn permanent_delete_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        state: &AppState,
    ) -> Result<(), AppError> {
        let mut tx = self.db.begin().await?;

        let row: Option<Option<chrono::DateTime<chrono::Utc>>> = sqlx::query_scalar(
            "SELECT deleted_at FROM folders
         WHERE folder_id = $1 AND user_id = $2
         FOR UPDATE",
        )
        .bind(folder_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(deleted_at) = row else {
            return Err(AppError::NotFound);
        };
        let was_trashed = deleted_at.is_some();

        let subtree: Vec<Uuid> = sqlx::query_scalar(
            r#"
        WITH RECURSIVE tree AS (
            SELECT folder_id FROM folders WHERE folder_id = $1 AND user_id = $2
            UNION
            SELECT f.folder_id FROM folders f
            JOIN tree t ON f.parent_folder_id = t.folder_id
            WHERE f.user_id = $2
        )
        SELECT folder_id FROM tree
        "#,
        )
        .bind(folder_id)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;

        let file_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT file_id FROM files WHERE folder_id = ANY($1) AND user_id = $2",
        )
        .bind(&subtree)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;

        let (_, keys) =
            crate::features::files::service::hard_delete_files(&mut tx, &file_ids, Some(user_id))
                .await?;

        sqlx::query(
            "UPDATE item_shares SET revoked_at = now()
         WHERE item_type = 'folder' AND item_id = ANY($1) AND revoked_at IS NULL",
        )
        .bind(&subtree)
        .execute(&mut *tx)
        .await?;

        let folders_deleted =
            sqlx::query("DELETE FROM folders WHERE folder_id = ANY($1) AND user_id = $2")
                .bind(&subtree)
                .bind(user_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();

        crate::features::audit::log(
            &mut *tx,
            Some(user_id),
            None,
            "folder_purged",
            &serde_json::json!({
                "folder_id": folder_id,
                "folders": folders_deleted,
                "files": file_ids.len(),
                "objects": keys.len(),
                "was_trashed": was_trashed,
            }),
        )
        .await?;

        tx.commit().await?;

        let key_count = keys.len();
        let storage = state.storage.clone();
        tokio::spawn(async move {
            storage.delete_objects_best_effort(&keys).await;
        });

        state.broadcast_sync(
            user_id,
            SyncEvent {
                seq: 0,
                event_type: "purged".to_string(),
                resource_type: "folder".to_string(),
                resource_id: folder_id,
                payload: serde_json::json!({
                    "folders": folders_deleted,
                    "files": file_ids.len(),
                    "objects": key_count,
                }),
            },
        );
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
        "UPDATE folders SET deleted_at = now() WHERE folder_id = ANY($1) AND user_id = $2 AND deleted_at IS NULL",
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

    /// Moves a folder to a different parent. Prevents cycles (moving into
    /// self/descendant). Does NOT require re-encrypting metadata.
    pub async fn move_folder(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        target_parent_folder_id: Option<Uuid>,
        state: &AppState,
    ) -> Result<FolderResponse, AppError> {
        self.verify_folder_ownership(folder_id, user_id).await?;

        // Prevent moving into self
        if let Some(target) = target_parent_folder_id {
            if target == folder_id {
                return Err(AppError::BadRequest(
                    "cannot move folder into itself".to_string(),
                ));
            }
            // Prevent moving into a descendant (cycle detection)
            if self.is_descendant_or_self(folder_id, target).await? {
                return Err(AppError::BadRequest(
                    "cannot move folder into itself or its own descendant".to_string(),
                ));
            }
            // Verify target parent ownership
            self.verify_folder_ownership(target, user_id).await?;
        }

        let folder = sqlx::query_as::<_, FolderResponse>(
            "UPDATE folders SET parent_folder_id = $1, updated_at = now()
             WHERE folder_id = $2 AND user_id = $3 AND deleted_at IS NULL
             RETURNING folder_id, parent_folder_id, encrypted_metadata, metadata_nonce, deleted_at, created_at, updated_at",
        )
        .bind(target_parent_folder_id)
        .bind(folder_id)
        .bind(user_id)
        .fetch_one(&self.db)
        .await?;

        state.broadcast_sync(
            user_id,
            SyncEvent {
                seq: 0,
                event_type: "moved".to_string(),
                resource_type: "folder".to_string(),
                resource_id: folder_id,
                payload: serde_json::json!({ "parent_folder_id": target_parent_folder_id }),
            },
        );

        Ok(folder)
    }

    pub async fn get_folder_path(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
    ) -> Result<Vec<FolderResponse>, AppError> {
        self.verify_folder_ownership(folder_id, user_id).await?;
        let folders = sqlx::query_as::<_, FolderResponse>(
            r#"
            WITH RECURSIVE ancestors AS (
                SELECT folder_id, parent_folder_id, encrypted_metadata, metadata_nonce,
                       deleted_at, created_at, updated_at, 0 AS depth
                FROM folders
                WHERE folder_id = $1 AND user_id = $2 AND deleted_at IS NULL
                UNION
                SELECT f.folder_id, f.parent_folder_id, f.encrypted_metadata, f.metadata_nonce,
                       f.deleted_at, f.created_at, f.updated_at, a.depth + 1
                FROM folders f
                JOIN ancestors a ON f.folder_id = a.parent_folder_id
                WHERE f.user_id = $2
            )
            SELECT folder_id, parent_folder_id, encrypted_metadata, metadata_nonce,
                   deleted_at, created_at, updated_at
            FROM ancestors
            ORDER BY depth DESC
            "#,
        )
        .bind(folder_id)
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;
        Ok(folders)
    }
}
