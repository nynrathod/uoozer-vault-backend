use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::core::crypto;
use crate::core::error::AppError;
use crate::features::audit;

use super::dto::*;

pub struct DeviceService {
    db: PgPool,
}

impl DeviceService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn list_devices(
        &self,
        user_id: Uuid,
        current_device_id: Uuid,
    ) -> Result<Vec<DeviceResponse>, AppError> {
        let rows: Vec<(
            Uuid,
            String,
            Vec<u8>,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
        )> = sqlx::query_as(
            r#"
                SELECT device_id, device_name, device_pubkey, created_at, last_seen_at, revoked_at
                FROM devices
                WHERE user_id = $1
                ORDER BY created_at DESC
                "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, name, pubkey, created, last_seen, revoked)| DeviceResponse {
                    device_id: id,
                    device_name: name,
                    device_pubkey: crypto::encode_b64(&pubkey),
                    created_at: created,
                    last_seen_at: last_seen,
                    is_revoked: revoked.is_some(),
                    is_current: id == current_device_id,
                },
            )
            .collect())
    }

    pub async fn list_sessions(
        &self,
        user_id: Uuid,
        current_session_id: Uuid,
    ) -> Result<Vec<SessionResponse>, AppError> {
        let rows: Vec<(
            Uuid,
            Uuid,
            String,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<std::net::IpAddr>,
            Option<String>,
            Option<DateTime<Utc>>,
        )> = sqlx::query_as(
            r#"
            SELECT s.session_id, s.device_id, d.device_name,
                   s.issued_at, s.expires_at, s.ip_address, s.user_agent, s.revoked_at
            FROM sessions s
            JOIN devices d ON d.device_id = s.device_id
            WHERE s.user_id = $1
            ORDER BY s.issued_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(sid, did, dname, issued, expires, ip, ua, revoked)| SessionResponse {
                    session_id: sid,
                    device_id: did,
                    device_name: dname,
                    issued_at: issued,
                    expires_at: expires,
                    ip_address: ip.map(|i| i.to_string()),
                    user_agent: ua,
                    is_current: sid == current_session_id,
                    is_revoked: revoked.is_some(),
                },
            )
            .collect())
    }

    pub async fn revoke_device(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        current_device_id: Uuid,
    ) -> Result<(), AppError> {
        if device_id == current_device_id {
            return Err(AppError::BadRequest(
                "cannot revoke the current device — use logout instead".to_string(),
            ));
        }

        let mut tx = self.db.begin().await?;

        let affected = sqlx::query(
            r#"
            UPDATE devices
            SET revoked_at = now()
            WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(device_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(AppError::NotFound);
        }

        // Revoke all sessions for this device.
        sqlx::query(
            r#"
            UPDATE sessions
            SET revoked_at = now(), revoked_reason = 'device_revoked'
            WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(device_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        audit::log(
            &mut *tx,
            Some(user_id),
            Some(device_id),
            "device_revoked",
            &serde_json::json!({ "revoked_from_device": current_device_id }),
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn update_device_name(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        new_name: &str,
    ) -> Result<(), AppError> {
        let affected = sqlx::query(
            r#"
            UPDATE devices SET device_name = $1, last_seen_at = now()
            WHERE device_id = $2 AND user_id = $3 AND revoked_at IS NULL
            "#,
        )
        .bind(new_name)
        .bind(device_id)
        .bind(user_id)
        .execute(&self.db)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }
}
