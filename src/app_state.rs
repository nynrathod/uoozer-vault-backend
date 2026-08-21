use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::config::Settings;
use crate::core::crypto::JwtKeyPair;
use crate::core::db::DbPool;
use crate::core::middleware::{IpRateLimiter, UserRateLimiter};
use crate::storage::StorageService;
use crate::storage::r2::R2Client;

#[derive(Debug, Clone)]
pub struct PendingSignup {
    pub email: String,
    pub email_normalized: String,
    pub salt: Vec<u8>,
    pub argon2_params: serde_json::Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncEvent {
    pub seq: u64,
    pub event_type: String,
    pub resource_type: String,
    pub resource_id: Uuid,
    pub payload: serde_json::Value,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Settings>,
    pub db: DbPool,
    pub jwt_keys: Arc<JwtKeyPair>,
    pub r2: Option<Arc<R2Client>>,
    pub storage: StorageService,
    pub sse_channels: Arc<DashMap<Uuid, broadcast::Sender<SyncEvent>>>,
    pub auth_rate_limiter: Arc<IpRateLimiter>,
    pub api_rate_limiter: Arc<UserRateLimiter>,
    pub pending_signups: Arc<DashMap<String, PendingSignup>>,
    pub event_seq: Arc<AtomicU64>,
}

impl AppState {
    pub async fn new(config: Arc<Settings>, db: DbPool) -> anyhow::Result<Self> {
        let jwt_keys =
            if config.jwt_private_key_pem.is_empty() || config.jwt_private_key_pem == "dev" {
                let (_, keypair) = crate::core::crypto::JwtKeyPair::generate_dev_keypair();
                Arc::new(keypair)
            } else {
                Arc::new(crate::core::crypto::JwtKeyPair::from_pem(
                    &config.jwt_private_key_pem,
                )?)
            };

        let r2 = if config.r2.is_configured() {
            Some(Arc::new(R2Client::new(&config.r2).await?))
        } else {
            None
        };

        let storage = StorageService::new(r2.clone());

        let sse_channels = Arc::new(DashMap::new());
        let auth_rate_limiter = Arc::new(IpRateLimiter::new(config.rate_limit.auth_per_minute));
        let api_rate_limiter = Arc::new(UserRateLimiter::new(config.rate_limit.api_per_minute));

        Ok(Self {
            config,
            db,
            jwt_keys,
            r2,
            storage,
            sse_channels,
            auth_rate_limiter,
            api_rate_limiter,
            pending_signups: Arc::new(DashMap::new()),
            event_seq: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn sse_channel(&self, user_id: Uuid) -> broadcast::Sender<SyncEvent> {
        self.sse_channels
            .entry(user_id)
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(100);
                tx
            })
            .clone()
    }

    pub fn maybe_cleanup_sse_channel(&self, user_id: Uuid) {
        if let Some(entry) = self.sse_channels.get(&user_id) {
            if entry.receiver_count() == 0 {
                drop(entry);
                self.sse_channels.remove(&user_id);
            }
        }
    }

    pub fn broadcast_sync(&self, user_id: Uuid, mut event: SyncEvent) {
        let seq = self
            .event_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        event.seq = seq;
        if let Some(tx) = self.sse_channels.get(&user_id) {
            let _ = tx.send(event);
        }
    }
}
