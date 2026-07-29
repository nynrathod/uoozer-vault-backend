use std::sync::Arc;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::app_state::AppState;
use crate::config::Settings;
use crate::core::crypto;
use crate::core::error::AppError;
use crate::features::audit;

use super::dto::{
    AuthResponse, LoginRequest, PasswordChangeRequest, PreloginResponse, SignupCompleteRequest,
    SignupInitResponse,
};

pub struct AuthService {
    db: PgPool,
    config: Arc<Settings>,
    jwt_keys: Arc<crypto::JwtKeyPair>,
    pending_signups: Arc<dashmap::DashMap<String, crate::app_state::PendingSignup>>,
}

impl AuthService {
    pub fn new(state: &AppState) -> Self {
        Self {
            db: state.db.clone(),
            config: state.config.clone(),
            jwt_keys: state.jwt_keys.clone(),
            pending_signups: state.pending_signups.clone(),
        }
    }

    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse, AppError> {
        let normalized = email.to_lowercase().trim().to_string();

        let user: Option<(Vec<u8>, serde_json::Value,)> = sqlx::query_as(
            "SELECT salt, argon2_params FROM users WHERE email_normalized = $1 AND disabled_at IS NULL"
        )
        .bind(&normalized)
        .fetch_optional(&self.db)
        .await?;

        let (salt, params) = match user {
            Some((s, p)) => (s, p),
            None => {
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

    pub async fn signup_init(&self, email: &str) -> Result<SignupInitResponse, AppError> {
        let normalized = email.to_lowercase().trim().to_string();

        let exists: Option<(Uuid,)> =
            sqlx::query_as("SELECT user_id FROM users WHERE email_normalized = $1")
                .bind(&normalized)
                .fetch_optional(&self.db)
                .await?;

        if exists.is_some() {
            return Err(AppError::Conflict("email already registered".to_string()));
        }

        let salt = crypto::generate_salt();
        let params = crypto::argon2_params_json(&self.config.argon2);
        let signup_token = Uuid::new_v4().to_string();

        self.pending_signups.insert(
            signup_token.clone(),
            crate::app_state::PendingSignup {
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

    pub async fn signup_complete(
        &self,
        req: SignupCompleteRequest,
    ) -> Result<AuthResponse, AppError> {
        let pending = self
            .pending_signups
            .get(&req.signup_token)
            .ok_or(AppError::BadRequest(
                "invalid or expired signup token".to_string(),
            ))?
            .clone();

        if pending.expires_at < Utc::now() {
            drop(pending);
            self.pending_signups.remove(&req.signup_token);
            return Err(AppError::BadRequest("signup token expired".to_string()));
        }

        let pending = pending.clone();
        drop(self.pending_signups.remove(&req.signup_token));

        let identity_pubkey = crypto::decode_b64(&req.identity_pubkey)?;
        let device_pubkey = crypto::decode_b64(&req.device_pubkey)?;
        let wrapped_dek = crypto::decode_b64(&req.wrapped_dek)?;
        let wrapped_dek_nonce = crypto::decode_b64(&req.wrapped_dek_nonce)?;
        let recovery_wrapped_dek = crypto::decode_b64(&req.recovery_wrapped_dek)?;
        let recovery_wrapped_dek_nonce = crypto::decode_b64(&req.recovery_wrapped_dek_nonce)?;

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

        let auth_key_hash = crypto::hash_auth_key(&req.auth_key, self.config.bcrypt.cost)?;
        let recovery_auth_key_hash =
            crypto::hash_auth_key(&req.recovery_auth_key, self.config.bcrypt.cost)?;

        let mut tx = self.db.begin().await?;

        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let refresh_jti = Uuid::new_v4();
        let expires_at =
            Utc::now() + chrono::Duration::seconds(self.config.jwt.refresh_ttl_seconds as i64);

        sqlx::query(
            "INSERT INTO users (user_id, email, email_normalized, salt, argon2_params, auth_key_hash, recovery_auth_key_hash, wrapped_dek, wrapped_dek_nonce, recovery_wrapped_dek, recovery_wrapped_dek_nonce, identity_pubkey) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
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

        sqlx::query(
            "INSERT INTO devices (device_id, user_id, device_name, device_pubkey) VALUES ($1, $2, $3, $4)"
        )
        .bind(device_id)
        .bind(user_id)
        .bind(&req.device_name)
        .bind(&device_pubkey)
        .execute(&mut *tx)
        .await?;

        let refresh_token = self.jwt_keys.sign_refresh_token(
            user_id,
            session_id,
            device_id,
            refresh_jti,
            &self.config.jwt,
        )?;

        let refresh_hash = crypto::hash_refresh_token(&refresh_token);

        sqlx::query(
            "INSERT INTO sessions (session_id, user_id, device_id, refresh_token_hash, refresh_token_jti, expires_at) VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(session_id)
        .bind(user_id)
        .bind(device_id)
        .bind(&refresh_hash)
        .bind(refresh_jti)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        audit::log(
            &mut *tx,
            Some(user_id),
            Some(device_id),
            "signup_complete",
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
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt.access_ttl_seconds,
        })
    }

    pub async fn login(
        &self,
        req: LoginRequest,
        ip: Option<std::net::IpAddr>,
        user_agent: Option<String>,
    ) -> Result<AuthResponse, AppError> {
        let normalized = req.email.to_lowercase().trim().to_string();

        if crypto::decode_b64(&req.auth_key).is_err() {
            return Err(AppError::BadRequest("invalid base64 encoding".to_string()));
        }
        if crypto::decode_b64(&req.device_pubkey).is_err() {
            return Err(AppError::BadRequest("invalid base64 encoding".to_string()));
        }

        let user: Option<(
            Uuid,
            String,
            String,
            Option<chrono::DateTime<chrono::Utc>>,
        )> = sqlx::query_as(
            "SELECT user_id, auth_key_hash, recovery_auth_key_hash, disabled_at FROM users WHERE email_normalized = $1"
        )
        .bind(&normalized)
        .fetch_optional(&self.db)
        .await?;

        let user = match user {
            Some(u) => u,
            None => {
                let _ = bcrypt::verify(&req.auth_key, DUMMY_BCRYPT_HASH);
                return Err(AppError::InvalidCredentials);
            }
        };

        let (user_id, auth_key_hash, recovery_auth_key_hash, disabled_at) = user;

        if disabled_at.is_some() {
            return Err(AppError::Forbidden);
        }

        let valid_auth = crypto::verify_auth_key(&req.auth_key, &auth_key_hash);
        let valid_recovery = crypto::verify_auth_key(&req.auth_key, &recovery_auth_key_hash);

        if !valid_auth && !valid_recovery {
            let _ = audit::log(
                &self.db,
                Some(user_id),
                None,
                "login_failed",
                &serde_json::json!({ "reason": "invalid_credentials" }),
            )
            .await;
            return Err(AppError::InvalidCredentials);
        }

        let device_pubkey = crypto::decode_b64(&req.device_pubkey)?;
        if device_pubkey.len() != 32 {
            return Err(AppError::BadRequest(
                "device public key must be 32 bytes".to_string(),
            ));
        }

        let mut tx = self.db.begin().await?;

        let device_id = match req.device_id {
            Some(existing_id) => {
                let existing_device: Option<(Uuid, Vec<u8>)> = sqlx::query_as(
                    "SELECT device_id, device_pubkey FROM devices WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL"
                )
                .bind(existing_id)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;

                match existing_device {
                    Some((id, pubkey)) => {
                        if pubkey != device_pubkey {
                            let new_id = Uuid::new_v4();
                            sqlx::query(
                                "INSERT INTO devices (device_id, user_id, device_name, device_pubkey) VALUES ($1, $2, $3, $4)"
                            )
                            .bind(new_id)
                            .bind(user_id)
                            .bind(&req.device_name)
                            .bind(&device_pubkey)
                            .execute(&mut *tx)
                            .await?;
                            new_id
                        } else {
                            sqlx::query(
                                "UPDATE devices SET last_seen_at = now() WHERE device_id = $1",
                            )
                            .bind(id)
                            .execute(&mut *tx)
                            .await?;
                            id
                        }
                    }
                    None => {
                        let new_id = Uuid::new_v4();
                        sqlx::query(
                            "INSERT INTO devices (device_id, user_id, device_name, device_pubkey) VALUES ($1, $2, $3, $4)"
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
                    "INSERT INTO devices (device_id, user_id, device_name, device_pubkey) VALUES ($1, $2, $3, $4)"
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

        let session_id = Uuid::new_v4();
        let refresh_jti = Uuid::new_v4();
        let expires_at =
            Utc::now() + chrono::Duration::seconds(self.config.jwt.refresh_ttl_seconds as i64);

        let refresh_token = self.jwt_keys.sign_refresh_token(
            user_id,
            session_id,
            device_id,
            refresh_jti,
            &self.config.jwt,
        )?;

        let refresh_hash = crypto::hash_refresh_token(&refresh_token);

        sqlx::query(
            "INSERT INTO sessions (session_id, user_id, device_id, refresh_token_hash, refresh_token_jti, expires_at, user_agent, ip_address) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
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

        audit::log(
            &mut *tx,
            Some(user_id),
            Some(device_id),
            "login_success",
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
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt.access_ttl_seconds,
        })
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<AuthResponse, AppError> {
        let claims = self.jwt_keys.verify_refresh_token(refresh_token)?;

        let session: Option<(
            Uuid,
            Uuid,
            Uuid,
            String,
            Option<String>,
            Option<Uuid>,
        )> = sqlx::query_as(
            "SELECT session_id, user_id, device_id, refresh_token_hash, revoked_reason, rotated_to FROM sessions WHERE refresh_token_jti = $1"
        )
        .bind(claims.jti)
        .fetch_optional(&self.db)
        .await?;

        let session = match session {
            Some(s) => s,
            None => return Err(AppError::InvalidRefreshToken),
        };

        let (session_id, user_id, device_id, stored_hash, revoked_reason, rotated_to) = session;

        if revoked_reason.is_some() {
            return Err(AppError::InvalidRefreshToken);
        }

        if session_id != claims.sid {
            return Err(AppError::InvalidRefreshToken);
        }

        if rotated_to.is_some() {
            let current_session_id = claims.sid;
            let next_session_id = rotated_to.unwrap();

            // 1. Revoke the entire chain (both the old session and the new one it rotated to)
            sqlx::query(
                "UPDATE sessions
                         SET revoked_at = now(), revoked_reason = 'reuse_detected'
                         WHERE session_id = $1 OR session_id = $2",
            )
            .bind(current_session_id)
            .bind(next_session_id)
            .execute(&self.db)
            .await?;

            // 2. Log the security event to the audit table
            audit::log(
                &self.db,
                Some(claims.sub),
                Some(claims.did),
                "refresh_token_reuse",
                &serde_json::json!({ "session_id": current_session_id.to_string() }),
            )
            .await
            .ok();

            return Err(AppError::RefreshTokenReuse);
        }

        let provided_hash = crypto::hash_refresh_token(refresh_token);
        let matches =
            subtle::ConstantTimeEq::ct_eq(stored_hash.as_bytes(), provided_hash.as_bytes());
        if !bool::from(matches) {
            return Err(AppError::InvalidRefreshToken);
        }

        let new_session_id = Uuid::new_v4();
        let new_refresh_jti = Uuid::new_v4();
        let new_expires_at =
            Utc::now() + chrono::Duration::seconds(self.config.jwt.refresh_ttl_seconds as i64);

        let new_refresh_token = self.jwt_keys.sign_refresh_token(
            user_id,
            new_session_id,
            device_id,
            new_refresh_jti,
            &self.config.jwt,
        )?;

        let new_hash = crypto::hash_refresh_token(&new_refresh_token);

        let mut tx = self.db.begin().await?;

        sqlx::query(
            "INSERT INTO sessions (session_id, user_id, device_id, refresh_token_hash, refresh_token_jti, expires_at) VALUES ($1, $2, $3, $4, $5, $6)"
        )
        .bind(new_session_id)
        .bind(user_id)
        .bind(device_id)
        .bind(&new_hash)
        .bind(new_refresh_jti)
        .bind(new_expires_at)
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE sessions SET rotated_to = $1 WHERE session_id = $2")
            .bind(new_session_id)
            .bind(session_id)
            .execute(&mut *tx)
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
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt.access_ttl_seconds,
        })
    }

    pub async fn logout(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        device_id: Uuid,
        revoke_device: bool,
        refresh_token: Option<String>,
    ) -> Result<(), AppError> {
        if revoke_device {
            let mut tx = self.db.begin().await?;
            sqlx::query(
                "UPDATE devices SET revoked_at = now() WHERE device_id = $1 AND user_id = $2",
            )
            .bind(device_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

            sqlx::query("UPDATE sessions SET revoked_at = now(), revoked_reason = 'device_revoked' WHERE device_id = $1")
                .bind(device_id)
                .execute(&mut *tx)
                .await?;

            audit::log(
                &mut *tx,
                Some(user_id),
                Some(device_id),
                "device_revoked",
                &serde_json::json!({}),
            )
            .await?;

            tx.commit().await?;
        } else {
            sqlx::query("UPDATE sessions SET revoked_at = now(), revoked_reason = 'logged_out' WHERE session_id = $1")
                .bind(session_id)
                .execute(&self.db)
                .await?;

            if let Some(rt) = refresh_token {
                if let Ok(claims) = self.jwt_keys.verify_refresh_token(&rt) {
                    sqlx::query("UPDATE sessions SET revoked_at = now(), revoked_reason = 'logged_out' WHERE refresh_token_jti = $1")
                        .bind(claims.jti)
                        .execute(&self.db)
                        .await?;
                }
            }
        }

        Ok(())
    }

    pub async fn change_password(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        req: PasswordChangeRequest,
    ) -> Result<(), AppError> {
        let new_wrapped_dek_nonce = crypto::decode_b64(&req.new_wrapped_dek_nonce)?;
        if new_wrapped_dek_nonce.len() != 24 {
            return Err(AppError::BadRequest("nonce must be 24 bytes".to_string()));
        }

        let new_wrapped_dek = crypto::decode_b64(&req.new_wrapped_dek)?;
        let new_auth_key_hash = crypto::hash_auth_key(&req.new_auth_key, self.config.bcrypt.cost)?;

        let mut tx = self.db.begin().await?;

        sqlx::query(
            "UPDATE users SET auth_key_hash = $1, wrapped_dek = $2, wrapped_dek_nonce = $3, updated_at = now() WHERE user_id = $4"
        )
        .bind(&new_auth_key_hash)
        .bind(&new_wrapped_dek)
        .bind(&new_wrapped_dek_nonce)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        audit::log(
            &mut *tx,
            Some(user_id),
            Some(device_id),
            "password_changed",
            &serde_json::json!({}),
        )
        .await?;

        tx.commit().await?;

        Ok(())
    }
}

const DUMMY_BCRYPT_HASH: &str = "$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
