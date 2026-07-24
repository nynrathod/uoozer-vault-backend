use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SyncEventSse {
    pub event: String,
    pub data: serde_json::Value,
}
