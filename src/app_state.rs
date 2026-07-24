use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::config::Settings;
use crate::core::crypto::JwtKeyPair;
use crate::core::db::DbPool;
use crate::storage::r2::R2Client;

/// SSE event payload broadcast to a user's connected devices.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncEvent {
    pub event_type: String,
    pub resource_type: String,
    pub resource_id: Uuid,
    pub payload: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Shared application state, cloned into every request handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Settings>,
    pub db: DbPool,
    pub jwt_keys: Arc<JwtKeyPair>,
    pub r2: Option<Arc<R2Client>>,
    /// Per-user broadcast channels for SSE sync.
    /// Keyed by user_id. Each channel fans out to all of that user's
    /// connected devices.
    pub sse_channels: Arc<DashMap<Uuid, broadcast::Sender<SyncEvent>>>,
}

impl AppState {
    pub async fn new(config: Arc<Settings>, db: DbPool) -> anyhow::Result<Self> {
        // ── JWT keys ──────────────────────────────────────────
        let jwt_keys =
            if config.jwt_private_key_pem.is_empty() || config.jwt_private_key_pem == "dev" {
                tracing::warn!(
                    "JWT_PRIVATE_KEY_PEM not set — generating ephemeral Ed25519 keypair. \
                 All tokens will be invalidated on restart. THIS MUST NOT HAPPEN IN PRODUCTION."
                );
                let (_, keypair) = JwtKeyPair::generate_dev_keypair();
                keypair
            } else {
                JwtKeyPair::from_pem(&config.jwt_private_key_pem)?
            };

        // ── R2 client ────────────────────────────────────────
        let r2 = if config.r2.is_configured() {
            Some(Arc::new(R2Client::new(&config.r2).await?))
        } else {
            tracing::warn!("R2 not configured — file storage endpoints will return 503");
            None
        };

        // ── SSE channels ─────────────────────────────────────
        let sse_channels = Arc::new(DashMap::new());

        Ok(Self {
            config,
            db,
            jwt_keys: Arc::new(jwt_keys),
            r2,
            sse_channels,
        })
    }

    /// Get or create the broadcast channel for a user.
    pub fn sse_channel(&self, user_id: Uuid) -> broadcast::Sender<SyncEvent> {
        self.sse_channels
            .entry(user_id)
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(256);
                tx
            })
            .clone()
    }

    /// Remove the channel if no subscribers remain.
    pub fn maybe_cleanup_sse_channel(&self, user_id: Uuid) {
        if let Some(entry) = self.sse_channels.get(&user_id) {
            if entry.receiver_count() == 0 {
                drop(entry);
                self.sse_channels.remove(&user_id);
            }
        }
    }

    /// Broadcast a sync event to all of a user's connected devices.
    pub fn broadcast_sync(&self, user_id: Uuid, event: SyncEvent) {
        if let Some(tx) = self.sse_channels.get(&user_id) {
            // Err is fine — means no active subscribers.
            let _ = tx.send(event);
        }
    }
}
