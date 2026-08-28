use sqlx::Error;
use uuid::Uuid;

/// Log a security-relevant audit event.
///
/// This function is designed to work both within a transaction
/// (passing `&mut *tx`) and standalone (passing `&pool`).
///
/// The audit log is append-only — there is no UPDATE or DELETE path.
pub async fn log<'e, E>(
    executor: E,
    user_id: Option<Uuid>,
    device_id: Option<Uuid>,
    event_type: &str,
    metadata: &serde_json::Value,
) -> Result<(), Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO audit_logs (user_id, device_id, event_type, event_metadata) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(event_type)
    .bind(metadata)
    .execute(executor)
    .await?;
    Ok(())
}

/// Query audit logs for a user (paginated).
pub async fn list_for_user(
    db: &sqlx::PgPool,
    user_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<sqlx::types::Json<serde_json::Value>>, Error> {
    let limit = limit.clamp(1, 500);
    let offset = offset.max(0);

    sqlx::query_scalar(
        "SELECT event_metadata FROM audit_logs
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT $2 OFFSET $3",
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
}
