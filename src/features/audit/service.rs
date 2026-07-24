use sqlx::{Executor, PgPool, Postgres};
use uuid::Uuid;

/// Log a security-relevant audit event.
///
/// This function is designed to work both within a transaction
/// (passing `&mut *tx`) and standalone (passing `&pool`).
///
/// The audit log is append-only — there is no UPDATE or DELETE path.
pub async fn log<'e, E>(
    executor: E,
    user_id: Uuid,
    device_id: Option<Uuid>,
    event_type: &str,
    metadata: &serde_json::Value,
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO audit_logs (user_id, device_id, event_type, event_metadata)
        VALUES ($1, $2, $3, $4)
        "#,
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
    db: &PgPool,
    user_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        SELECT json_build_object(
            'audit_id', audit_id,
            'event_type', event_type,
            'event_metadata', event_metadata,
            'device_id', device_id,
            'ip_address', ip_address::text,
            'created_at', created_at
        )
        FROM audit_logs
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
}
