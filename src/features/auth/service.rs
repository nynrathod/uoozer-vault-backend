use std::sync::Arc;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::app_state::AppState;
use crate::config::Settings;
use crate::core::crypto::{self, JwtKeyPair};
use crate::core::error::AppError;
use crate::features::audit;

use super::dto::*;

/// In-memory pending signup store.
/// Maps signup_token -> (email, salt, argon2_params, expires_at).
/// TTL: 10 minutes. For production at scale, move to Redis.
type PendingSignups = Arc<dashmap::DashMap<String, PendingSignup>>;

#[derive(Clone)]
struct PendingSignup {
    email: String,
    email_normalized: String,
    salt: Vec<u8>,
    argon2_params: serde_json::Value,
    expires_at: chrono::DateTime<chrono::Utc>,
}

pub struct AuthService {
    db: PgPool,
    config: Arc<Settings>,
    jwt_keys: Arc<JwtKeyPair>,
    pending_signups: PendingSignups,
}

impl AuthService {
    pub fn new(state: &AppState) -> Self {
        Self {
            db: state.db.clone(),
            config: state.config.clone(),
            jwt_keys: state.jwt_keys.clone(),
            pending_signups: Arc::new(dashmap::DashMap::new()),
        }
    }

    // ── Prelogin (anti-enumeration) ──────────────────────────

    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse, AppError> {
        let normalized = email.to_lowercase().trim().to_string();

        let row: Option<(Vec<u8>, serde_json::Value)> =
            sqlx::query_as("SELECT salt, argon2_params FROM users WHERE email_normalized = $1")
                .bind(&normalized)
                .fetch_optional(&self.db)
                .await?;

        let (salt, params) = match row {
            Some((salt, params)) => (salt, params),
            None => {
                // Anti-enumeration: return deterministic fake salt derived
                // from the email + server pepper. Response is identical
                // to a real user's response, preventing enumeration.
                tracing::debug!(
                    email_normalized = %normalized,
                    "prelogin for unknown email — returning fake salt"
                );
                let fake_salt = crypto::deterministic_fake_salt(
                    &normalized,
                    self.config.prelogin_pepper.as_bytes(),
                );
                (
                    fake_salt.to_vec(),
                    crypto::argon2_params_json(&self.config.argon2),
                )
            }
        };

        Ok(PreloginResponse {
            salt: crypto::encode_b64(&salt),
            argon2_params: params,
        })
    }

    // ── Signup Init ──────────────────────────────────────────

    pub async fn signup_init(&self, email: &str) -> Result<SignupInitResponse, AppError> {
        let normalized = email.to_lowercase().trim().to_string();

        // Check if email is already registered.
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email_normalized = $1)")
                .bind(&normalized)
                .fetch_one(&self.db)
                .await?;

        if exists {
            return Err(AppError::Conflict("email already registered".to_string()));
        }

        // Generate salt and params.
        let salt = crypto::generate_salt();
        let params = crypto::argon2_params_json(&self.config.argon2);
        let signup_token = Uuid::new_v4().to_string();

        // Store pending signup with 10-minute TTL.
        self.pending_signups.insert(
            signup_token.clone(),
            PendingSignup {
                email: email.to_string(),
                email_normalized: normalized,
                salt: salt.to_vec(),
                argon2_params: params.clone(),
                expires_at: Utc::now() + chrono::Duration::minutes(10),
            },
        );

        Ok(SignupInitResponse {
            signup_token,
            salt: crypto::encode_b64(&salt),
            argon2_params: params,
        })
    }

    // ── Signup Complete ──────────────────────────────────────

    pub async fn signup_complete(
        &self,
        req: SignupCompleteRequest,
    ) -> Result<AuthResponse, AppError> {
        // Look up pending signup.
        let pending = self
            .pending_signups
            .get(&req.signup_token)
            .ok_or(AppError::BadRequest(
                "invalid or expired signup token".to_string(),
            ))?;

        if Utc::now() > pending.expires_at {
            drop(pending);
            self.pending_signups.remove(&req.signup_token);
            return Err(AppError::BadRequest("signup token expired".to_string()));
        }

        let pending = pending.clone();
        drop(self.pending_signups.remove(&req.signup_token));

        // Decode and validate base64 inputs.
        let wrapped_dek = crypto::decode_b64(&req.wrapped_dek)?;
        let wrapped_dek_nonce = crypto::decode_b64(&req.wrapped_dek_nonce)?;
        let recovery_wrapped_dek = crypto::decode_b64(&req.recovery_wrapped_dek)?;
        let recovery_wrapped_dek_nonce = crypto::decode_b64(&req.recovery_wrapped_dek_nonce)?;
        let identity_pubkey = crypto::decode_b64(&req.identity_pubkey)?;
        let device_pubkey = crypto::decode_b64(&req.device_pubkey)?;

        if identity_pubkey.len() != 32 {
            return Err(AppError::BadRequest(
                "identity public key must be 32 bytes (Ed25519)".to_string(),
            ));
        }
        if device_pubkey.len() != 32 {
            return Err(AppError::BadRequest(
                "device public key must be 32 bytes (Ed25519)".to_string(),
            ));
        }
        if wrapped_dek_nonce.len() != 24 || recovery_wrapped_dek_nonce.len() != 24 {
            return Err(AppError::BadRequest(
                "nonce must be 24 bytes (XChaCha20-Poly1305)".to_string(),
            ));
        }

        // Hash the Auth Key and Recovery Auth Key with bcrypt.
        let auth_key_hash = crypto::hash_auth_key(&req.auth_key, self.config.bcrypt.cost)?;
        let recovery_auth_key_hash =
            crypto::hash_auth_key(&req.recovery_auth_key, self.config.bcrypt.cost)?;

        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let refresh_jti = Uuid::new_v4();

        let mut tx = self.db.begin().await?;

        // Insert user.
        sqlx::query(
            r#"
            INSERT INTO users (
                user_id, email, email_normalized,
                salt, argon2_params,
                auth_key_hash, recovery_auth_key_hash,
                wrapped_dek, wrapped_dek_nonce,
                recovery_wrapped_dek, recovery_wrapped_dek_nonce,
                identity_pubkey
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
        )
        .bind(user_id)
        .bind(&pending.email)
        .bind(&pending.email_normalized)
        .bind(&pending.salt)
        .bind(&pending.argon2_params)
        .bind(&auth_key_hash)
        .bind(&recovery_auth_key_hash)
        .bind(&wrapped_dek)
        .bind(&wrapped_dek_nonce)
        .bind(&recovery_wrapped_dek)
        .bind(&recovery_wrapped_dek_nonce)
        .bind(&identity_pubkey)
        .execute(&mut *tx)
        .await?;

        // Insert device.
        sqlx::query(
            r#"
            INSERT INTO devices (device_id, user_id, device_name, device_pubkey)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(device_id)
        .bind(user_id)
        .bind(&req.device_name)
        .bind(&device_pubkey)
        .execute(&mut *tx)
        .await?;

        // Generate refresh token.
        let refresh_token = self.jwt_keys.sign_refresh_token(
            user_id,
            session_id,
            device_id,
            refresh_jti,
            &self.config.jwt,
        )?;

        let refresh_hash = crypto::hash_refresh_token(&refresh_token);
        let now = Utc::now();
        let expires_at =
            now + chrono::Duration::seconds(self.config.jwt.refresh_ttl_seconds as i64);

        // Insert session.
        sqlx::query(
            r#"
            INSERT INTO sessions (
                session_id, user_id, device_id,
                refresh_token_hash, refresh_token_jti,
                expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(session_id)
        .bind(user_id)
        .bind(device_id)
        .bind(&refresh_hash)
        .bind(refresh_jti)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        // Audit log.
        audit::log(
            &mut *tx,
            user_id,
            Some(device_id),
            "signup",
            &serde_json::json!({}),
        )
        .await?;

        tx.commit().await?;

        // Generate access token.
        let access_token =
            self.jwt_keys
                .sign_access_token(user_id, session_id, device_id, &self.config.jwt)?;

        Ok(AuthResponse {
            access_token,
            refresh_token,
            expires_in: self.config.jwt.access_ttl_seconds,
            user_id,
            device_id,
        })
    }

    // ── Login ────────────────────────────────────────────────

    pub async fn login(
        &self,
        req: LoginRequest,
        ip: Option<std::net::IpAddr>,
        user_agent: Option<String>,
    ) -> Result<AuthResponse, AppError> {
        let normalized = req.email.to_lowercase().trim().to_string();

        // Fetch user.
        let user: Option<(Uuid, String, String, Vec<u8>, serde_json::Value)> = sqlx::query_as(
            r#"
            SELECT user_id, auth_key_hash, recovery_auth_key_hash, salt, argon2_params
            FROM users
            WHERE email_normalized = $1 AND disabled_at IS NULL
            "#,
        )
        .bind(&normalized)
        .fetch_optional(&self.db)
        .await?;

        let (user_id, auth_key_hash, recovery_auth_key_hash, _salt, _params) = match user {
            Some(row) => row,
            None => {
                // Run a dummy bcrypt verify to equalize timing.
                let _ = crypto::verify_auth_key(&req.auth_key, DUMMY_BCRYPT_HASH);
                return Err(AppError::InvalidCredentials);
            }
        };

        // Verify Auth Key against both the password-derived hash and the
        // recovery-derived hash. This allows login via either credential.
        let is_password_login = crypto::verify_auth_key(&req.auth_key, &auth_key_hash);
        let is_recovery_login = crypto::verify_auth_key(&req.auth_key, &recovery_auth_key_hash);

        if !is_password_login && !is_recovery_login {
            // Log failed login attempt.
            audit::log(
                &self.db,
                user_id,
                None,
                "login_failed",
                &serde_json::json!({ "reason": "invalid_auth_key" }),
            )
            .await
            .ok();
            return Err(AppError::InvalidCredentials);
        }

        let device_pubkey = crypto::decode_b64(&req.device_pubkey)?;
        if device_pubkey.len() != 32 {
            return Err(AppError::BadRequest(
                "device public key must be 32 bytes".to_string(),
            ));
        }

        let mut tx = self.db.begin().await?;

        // Device handling.
        let device_id = match req.device_id {
            Some(existing_id) => {
                // Verify the device belongs to this user and pubkey matches.
                let stored_pubkey: Option<Vec<u8>> = sqlx::query_scalar(
                    "SELECT device_pubkey FROM devices WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL",
                )
                .bind(existing_id)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;

                match stored_pubkey {
                    Some(ref stored) if stored == &device_pubkey => existing_id,
                    _ => {
                        // Mismatched or unknown device — create new.
                        let new_id = Uuid::new_v4();
                        sqlx::query(
                            r#"
                            INSERT INTO devices (device_id, user_id, device_name, device_pubkey)
                            VALUES ($1, $2, $3, $4)
                            "#,
                        )
                        .bind(new_id)
                        .bind(user_id)
                        .bind(&req.device_name)
                        .bind(&device_pubkey)
                        .execute(&mut *tx)
                        .await?;
                        new_id
                    }
                }
            }
            None => {
                let new_id = Uuid::new_v4();
                sqlx::query(
                    r#"
                    INSERT INTO devices (device_id, user_id, device_name, device_pubkey)
                    VALUES ($1, $2, $3, $4)
                    "#,
                )
                .bind(new_id)
                .bind(user_id)
                .bind(&req.device_name)
                .bind(&device_pubkey)
                .execute(&mut *tx)
                .await?;
                new_id
            }
        };

        // Create session.
        let session_id = Uuid::new_v4();
        let refresh_jti = Uuid::new_v4();
        let refresh_token = self.jwt_keys.sign_refresh_token(
            user_id,
            session_id,
            device_id,
            refresh_jti,
            &self.config.jwt,
        )?;
        let refresh_hash = crypto::hash_refresh_token(&refresh_token);
        let now = Utc::now();
        let expires_at =
            now + chrono::Duration::seconds(self.config.jwt.refresh_ttl_seconds as i64);

        sqlx::query(
            r#"
            INSERT INTO sessions (
                session_id, user_id, device_id,
                refresh_token_hash, refresh_token_jti,
                expires_at, user_agent, ip_address
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(session_id)
        .bind(user_id)
        .bind(device_id)
        .bind(&refresh_hash)
        .bind(refresh_jti)
        .bind(expires_at)
        .bind(user_agent.as_deref())
        .bind(ip)
        .execute(&mut *tx)
        .await?;

        // Update device last_seen.
        sqlx::query("UPDATE devices SET last_seen_at = now() WHERE device_id = $1")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;

        let event_type = if is_recovery_login {
            "login_via_recovery_key"
        } else {
            "login"
        };

        audit::log(
            &mut *tx,
            user_id,
            Some(device_id),
            event_type,
            &serde_json::json!({}),
        )
        .await?;

        tx.commit().await?;

        let access_token =
            self.jwt_keys
                .sign_access_token(user_id, session_id, device_id, &self.config.jwt)?;

        Ok(AuthResponse {
            access_token,
            refresh_token,
            expires_in: self.config.jwt.access_ttl_seconds,
            user_id,
            device_id,
        })
    }

    // ── Refresh ──────────────────────────────────────────────

    pub async fn refresh(&self, refresh_token: &str) -> Result<AuthResponse, AppError> {
        // Verify JWT signature and expiry.
        let claims = self.jwt_keys.verify_refresh_token(refresh_token)?;

        let mut tx = self.db.begin().await?;

        // Fetch the session by jti.
        let session: Option<(Uuid, Uuid, Uuid, Option<Uuid>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT session_id, user_id, device_id, rotated_to, revoked_reason
            FROM sessions
            WHERE refresh_token_jti = $1
            FOR UPDATE
            "#,
        )
        .bind(claims.jti)
        .fetch_optional(&mut *tx)
        .await?;

        let (session_id, user_id, device_id, rotated_to, revoked_reason) = match session {
            Some(s) => s,
            None => return Err(AppError::InvalidRefreshToken),
        };

        // Check if session is revoked.
        if revoked_reason.is_some() {
            return Err(AppError::InvalidRefreshToken);
        }

        // Check session_id matches JWT claim.
        if session_id != claims.sid {
            return Err(AppError::InvalidRefreshToken);
        }

        // ── Reuse detection ──────────────────────────────────
        // If this token was already rotated (rotated_to IS NOT NULL),
        // someone is replaying an old refresh token. Revoke the entire
        // session chain immediately.
        if rotated_to.is_some() {
            tracing::warn!(
                user_id = %user_id,
                session_id = %session_id,
                "refresh token reuse detected — revoking session chain"
            );

            // Revoke the entire chain.
            sqlx::query(
                r#"
                UPDATE sessions
                SET revoked_at = now(), revoked_reason = 'reuse_detected'
                WHERE session_id = $1 OR rotated_to = $1
                "#,
            )
            .bind(session_id)
            .execute(&mut *tx)
            .await?;

            // Also revoke the device.
            sqlx::query("UPDATE devices SET revoked_at = now() WHERE device_id = $1")
                .bind(device_id)
                .execute(&mut *tx)
                .await?;

            audit::log(
                &mut *tx,
                user_id,
                Some(device_id),
                "refresh_token_reuse_detected",
                &serde_json::json!({ "session_id": session_id }),
            )
            .await?;

            tx.commit().await?;
            return Err(AppError::RefreshTokenReuse);
        }

        // Verify the refresh token hash matches.
        let stored_hash: String =
            sqlx::query_scalar("SELECT refresh_token_hash FROM sessions WHERE session_id = $1")
                .bind(session_id)
                .fetch_one(&mut *tx)
                .await?;

        let provided_hash = crypto::hash_refresh_token(refresh_token);
        let is_valid: bool =
            subtle::ConstantTimeEq::ct_eq(stored_hash.as_bytes(), provided_hash.as_bytes()).into();

        if !is_valid {
            return Err(AppError::InvalidRefreshToken);
        }

        // ── Rotate: create new session, mark old as rotated ───
        let new_session_id = Uuid::new_v4();
        let new_jti = Uuid::new_v4();
        let new_refresh_token = self.jwt_keys.sign_refresh_token(
            user_id,
            new_session_id,
            device_id,
            new_jti,
            &self.config.jwt,
        )?;
        let new_hash = crypto::hash_refresh_token(&new_refresh_token);
        let now = Utc::now();
        let expires_at =
            now + chrono::Duration::seconds(self.config.jwt.refresh_ttl_seconds as i64);

        // Insert new session.
        sqlx::query(
            r#"
            INSERT INTO sessions (
                session_id, user_id, device_id,
                refresh_token_hash, refresh_token_jti,
                expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(new_session_id)
        .bind(user_id)
        .bind(device_id)
        .bind(&new_hash)
        .bind(new_jti)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        // Mark old session as rotated (not revoked — it's legitimately consumed).
        sqlx::query(
            r#"
            UPDATE sessions
            SET rotated_to = $1
            WHERE session_id = $2
            "#,
        )
        .bind(new_session_id)
        .bind(session_id)
        .execute(&mut *tx)
        .await?;

        audit::log(
            &mut *tx,
            user_id,
            Some(device_id),
            "token_refreshed",
            &serde_json::json!({
                "old_session": session_id,
                "new_session": new_session_id
            }),
        )
        .await?;

        tx.commit().await?;

        let access_token = self.jwt_keys.sign_access_token(
            user_id,
            new_session_id,
            device_id,
            &self.config.jwt,
        )?;

        Ok(AuthResponse {
            access_token,
            refresh_token: new_refresh_token,
            expires_in: self.config.jwt.access_ttl_seconds,
            user_id,
            device_id,
        })
    }

    // ── Logout ───────────────────────────────────────────────

    pub async fn logout(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        session_id: Uuid,
        refresh_token: Option<String>,
        revoke_device: bool,
    ) -> Result<(), AppError> {
        let mut tx = self.db.begin().await?;

        if revoke_device {
            // Revoke the entire device and all its sessions.
            sqlx::query(
                r#"
                UPDATE devices SET revoked_at = now() WHERE device_id = $1 AND user_id = $2
                "#,
            )
            .bind(device_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                r#"
                UPDATE sessions
                SET revoked_at = now(), revoked_reason = 'device_logout'
                WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL
                "#,
            )
            .bind(device_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

            audit::log(
                &mut *tx,
                user_id,
                Some(device_id),
                "device_revoked",
                &serde_json::json!({ "via": "logout" }),
            )
            .await?;
        } else {
            // Just revoke the current session.
            sqlx::query(
                r#"
                UPDATE sessions
                SET revoked_at = now(), revoked_reason = 'logout'
                WHERE session_id = $1 AND user_id = $2
                "#,
            )
            .bind(session_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

            // If a refresh token was provided, also try to revoke by jti
            // (in case the session_id in the access token differs).
            if let Some(rt) = refresh_token {
                if let Ok(claims) = self.jwt_keys.verify_refresh_token(&rt) {
                    sqlx::query(
                        r#"
                        UPDATE sessions
                        SET revoked_at = now(), revoked_reason = 'logout'
                        WHERE refresh_token_jti = $1 AND user_id = $2
                        "#,
                    )
                    .bind(claims.jti)
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await?;
                }
            }

            audit::log(
                &mut *tx,
                user_id,
                Some(device_id),
                "logout",
                &serde_json::json!({}),
            )
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    // ── Password Change ──────────────────────────────────────

    pub async fn change_password(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        req: PasswordChangeRequest,
    ) -> Result<(), AppError> {
        let new_auth_key_hash = crypto::hash_auth_key(&req.new_auth_key, self.config.bcrypt.cost)?;

        let new_wrapped_dek = crypto::decode_b64(&req.new_wrapped_dek)?;
        let new_wrapped_dek_nonce = crypto::decode_b64(&req.new_wrapped_dek_nonce)?;

        if new_wrapped_dek_nonce.len() != 24 {
            return Err(AppError::BadRequest(
                "nonce must be 24 bytes (XChaCha20-Poly1305)".to_string(),
            ));
        }

        let mut tx = self.db.begin().await?;

        sqlx::query(
            r#"
            UPDATE users
            SET auth_key_hash = $1,
                wrapped_dek = $2,
                wrapped_dek_nonce = $3,
                updated_at = now()
            WHERE user_id = $4
            "#,
        )
        .bind(&new_auth_key_hash)
        .bind(&new_wrapped_dek)
        .bind(&new_wrapped_dek_nonce)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        audit::log(
            &mut *tx,
            user_id,
            Some(device_id),
            "password_changed",
            &serde_json::json!({}),
        )
        .await?;

        tx.commit().await?;
        Ok(())
    }
}

/// A dummy bcrypt hash used for timing equalization on unknown-email logins.
/// This is a valid bcrypt hash of a random value; verifying against it
/// takes the same time as verifying a real hash, preventing timing attacks.
const DUMMY_BCRYPT_HASH: &str = "$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
