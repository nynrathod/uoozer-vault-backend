use crate::storage::StorageService;
use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;
use tracing::info;

pub struct CleanupService {
    db: PgPool,
    storage: StorageService,
}

impl CleanupService {
    pub fn new(db: PgPool, storage: StorageService) -> Self {
        Self { db, storage }
    }

    pub async fn cleanup_orphaned_versions(
        &self,
        older_than_hours: i64,
    ) -> Result<usize, sqlx::Error> {
        let cutoff = Utc::now() - chrono::Duration::hours(older_than_hours);

        let r2_keys: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT c.r2_key
            FROM file_chunks c
            JOIN file_versions v ON c.version_id = v.version_id
            WHERE v.is_active = false
              AND v.created_at < $1
              AND NOT EXISTS (
                SELECT 1 FROM files f
                WHERE f.current_version_id = v.version_id
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
                SELECT 1 FROM files f
                WHERE f.current_version_id = file_versions.version_id
              )
            "#,
        )
        .bind(cutoff)
        .execute(&self.db)
        .await?;

        info!(
            deleted_versions = result.rows_affected(),
            deleted_r2_objects = key_count,
            "orphaned upload cleanup completed"
        );

        Ok(result.rows_affected() as usize)
    }

    pub async fn retry_pending_storage_deletions(&self) -> Result<usize, sqlx::Error> {
        if !self.storage.is_configured() {
            return Ok(0);
        }
        const BATCH: i64 = 500;
        let keys: Vec<String> = sqlx::query_scalar(
            "SELECT r2_key FROM pending_storage_deletions ORDER BY created_at LIMIT $1",
        )
        .bind(BATCH)
        .fetch_all(&self.db)
        .await?;
        if keys.is_empty() {
            return Ok(0);
        }

        if let Err(e) = self.storage.delete_objects(&keys).await {
            tracing::warn!(error = ?e, count = keys.len(),
            "pending storage deletion attempt failed — retrying next cycle");
            sqlx::query(
                "UPDATE pending_storage_deletions
             SET attempts = attempts + 1, last_attempt_at = now(), last_error = $2
             WHERE r2_key = ANY($1)",
            )
            .bind(&keys)
            .bind(e.to_string())
            .execute(&self.db)
            .await?;
            return Ok(0);
        }

        let mut gone: Vec<String> = Vec::new();
        for key in &keys {
            match self.storage.head_object(key).await {
                Ok(None) => gone.push(key.clone()),
                Ok(Some(_)) => tracing::warn!(key, "object survived delete — will retry"),
                Err(_) => {}
            }
        }
        if gone.is_empty() {
            return Ok(0);
        }
        let res = sqlx::query("DELETE FROM pending_storage_deletions WHERE r2_key = ANY($1)")
            .bind(&gone)
            .execute(&self.db)
            .await?;
        Ok(res.rows_affected() as usize)
    }

    pub async fn run_periodic_cleanup(self, interval_minutes: u64, older_than_hours: i64) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_minutes * 60));
        loop {
            interval.tick().await;
            if let Err(e) = self.cleanup_orphaned_versions(older_than_hours).await {
                tracing::error!(error = ?e, "orphaned version cleanup failed");
            }
            if let Err(e) = self.retry_pending_storage_deletions().await {
                tracing::error!(error = ?e, "pending storage deletion retry failed");
            }
        }
    }
}
