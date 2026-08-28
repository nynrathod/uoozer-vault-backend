use base64::Engine;
use serde_json::{Value, json};
use uuid::Uuid;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

pub fn random_b64(len: usize) -> String {
    let buf: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
    B64.encode(buf)
}

pub fn random_uuid() -> Uuid {
    Uuid::new_v4()
}

// ── Auth Factories ──────────────────────────────────────────

pub fn signup_complete_req(email: &str) -> Value {
    json!({
        "email": email,
        "signup_token": "FILLED_BY_TEST",
        "full_name": "Test User",
        "auth_key": random_b64(32),
        "recovery_auth_key": random_b64(32),
        "wrapped_dek": random_b64(64),
        "wrapped_dek_nonce": random_b64(24), // 24 bytes for XChaCha20
        "recovery_wrapped_dek": random_b64(64),
        "recovery_wrapped_dek_nonce": random_b64(24),
        "identity_pubkey": random_b64(32), // 32 bytes for Ed25519
        "device_pubkey": random_b64(32),
        "device_name": "Test Device"
    })
}

pub fn login_req(email: &str, auth_key: &str) -> Value {
    json!({
        "email": email,
        "auth_key": auth_key,
        "device_pubkey": random_b64(32),
        "device_name": "Test Device"
    })
}

pub fn login_req_with_device(
    email: &str,
    auth_key: &str,
    device_id: Uuid,
    device_pubkey: &str,
) -> Value {
    json!({
        "email": email,
        "auth_key": auth_key,
        "device_pubkey": device_pubkey,
        "device_name": "Test Device",
        "device_id": device_id
    })
}

pub fn change_password_req() -> Value {
    json!({
        "new_auth_key": random_b64(32),
        "new_wrapped_dek": random_b64(64),
        "new_wrapped_dek_nonce": random_b64(24)
    })
}

// ── Folder Factories ────────────────────────────────────────

pub fn create_folder_req(parent: Option<Uuid>) -> Value {
    json!({
        "encrypted_metadata": random_b64(48),
        "metadata_nonce": random_b64(24),
        "parent_folder_id": parent
    })
}

pub fn update_folder_req() -> Value {
    json!({
        "encrypted_metadata": random_b64(48),
        "metadata_nonce": random_b64(24),
        "parent_folder_id": null
    })
}

pub fn create_folder_with_name(parent: Option<Uuid>, name: &str) -> Value {
    let name_bytes = name.as_bytes();
    let metadata = format!("{{\"name\":\"{}\"}}", name);
    json!({
        "encrypted_metadata": B64.encode(metadata.as_bytes()),
        "metadata_nonce": random_b64(24),
        "parent_folder_id": parent
    })
}

// ── File Factories ──────────────────────────────────────────

pub fn create_file_req(folder_id: Option<Uuid>) -> Value {
    json!({
        "folder_id": folder_id,
        "encrypted_metadata": random_b64(48),
        "metadata_nonce": random_b64(24),
        "plaintext_blake3": random_b64(32),
        "total_size": 1024,
        "total_chunks": 1,
        "encryption_header": random_b64(24),
        "chunks": [{
            "chunk_index": 0,
            "segment_index": 0,
            "chunk_size": 1024 + 17,
            "chunk_blake3": random_b64(32),
        }],
				"wrapped_file_key": random_b64(32),
        "wrapped_file_key_nonce": random_b64(24)
    })
}

pub fn create_file_req_with_size(
    folder_id: Option<Uuid>,
    total_size: i64,
    total_chunks: i32,
) -> Value {
    let base_chunk_size = total_size / total_chunks as i64;
    let remainder = total_size % total_chunks as i64;

    let chunks: Vec<Value> = (0..total_chunks)
        .map(|i| {
            let mut size = base_chunk_size + 17;
            if i == 0 {
                size += remainder;
            }
            json!({
                "chunk_index": i,
                "segment_index": 0,
                "chunk_size": size,
                "chunk_blake3": random_b64(32),
            })
        })
        .collect();

    json!({
        "folder_id": folder_id,
        "encrypted_metadata": random_b64(48),
        "metadata_nonce": random_b64(24),
        "plaintext_blake3": random_b64(32),
        "total_size": total_size,
        "total_chunks": total_chunks,
        "encryption_header": random_b64(24),
        "chunks": chunks,
        "wrapped_file_key": random_b64(32),
        "wrapped_file_key_nonce": random_b64(24)
    })
}

pub fn create_file_req_with_hash(folder_id: Option<Uuid>, plaintext_blake3: String) -> Value {
    json!({
        "folder_id": folder_id,
        "encrypted_metadata": random_b64(48),
        "metadata_nonce": random_b64(24),
        "plaintext_blake3": plaintext_blake3,
        "total_size": 1024,
        "total_chunks": 1,
        "encryption_header": random_b64(24),
        "chunks": [{
            "chunk_index": 0,
            "segment_index": 0,
            "chunk_size": 1024 + 17,
            "chunk_blake3": random_b64(32),
        }],
        "wrapped_file_key": random_b64(32),
        "wrapped_file_key_nonce": random_b64(24)
    })
}

pub fn create_file_req_with_metadata(
    folder_id: Option<Uuid>,
    metadata: &str,
    plaintext_blake3: &str,
    total_size: i64,
    total_chunks: i32,
) -> Value {
    let chunks: Vec<Value> = (0..total_chunks)
        .map(|i| {
            json!({
                "chunk_index": i,
                "segment_index": 0,
                "chunk_size": (total_size / total_chunks as i64) + 17,
                "chunk_blake3": random_b64(32),
            })
        })
        .collect();

    json!({
        "folder_id": folder_id,
        "encrypted_metadata": B64.encode(metadata.as_bytes()),
        "metadata_nonce": random_b64(24),
        "plaintext_blake3": plaintext_blake3,
        "total_size": total_size,
        "total_chunks": total_chunks,
        "encryption_header": random_b64(24),
        "chunks": chunks,
        "wrapped_file_key": random_b64(32),
        "wrapped_file_key_nonce": random_b64(24)
    })
}

pub fn create_large_file_req(folder_id: Option<Uuid>, size_mb: i64) -> Value {
    let total_size = size_mb * 1024 * 1024;
    let chunk_size = 4 * 1024 * 1024;
    let total_chunks = (total_size / chunk_size) as i32;
    create_file_req_with_size(folder_id, total_size, total_chunks)
}

pub fn create_file_with_bad_metadata(
    folder_id: Option<Uuid>,
    bad_field: &str,
    bad_value: &str,
) -> Value {
    let mut req = create_file_req(folder_id);
    req[bad_field] = json!(bad_value);
    req
}

pub fn create_file_with_chunk_mismatch(folder_id: Option<Uuid>) -> Value {
    let mut req = create_file_req(folder_id);
    req["total_chunks"] = json!(5);
    req
}

pub fn create_file_with_bad_chunk_size(folder_id: Option<Uuid>) -> Value {
    let mut req = create_file_req(folder_id);
    req["total_size"] = json!(1024);
    req["chunks"][0]["chunk_size"] = json!(2048);
    req
}

pub fn create_file_with_bad_nonce(folder_id: Option<Uuid>) -> Value {
    let mut req = create_file_req(folder_id);
    req["metadata_nonce"] = json!(random_b64(10));
    req
}

pub fn create_file_with_bad_hash(folder_id: Option<Uuid>) -> Value {
    let mut req = create_file_req(folder_id);
    req["plaintext_blake3"] = json!(random_b64(10));
    req
}

pub fn create_file_with_bad_header(folder_id: Option<Uuid>) -> Value {
    let mut req = create_file_req(folder_id);
    req["encryption_header"] = json!(random_b64(10));
    req
}

// ── Bulk Factories ──────────────────────────────────────────

pub fn bulk_create_files_req(count: usize) -> Value {
    let files: Vec<Value> = (0..count).map(|_| create_file_req(None)).collect();
    json!({ "files": files })
}

pub fn bulk_delete_req(file_ids: Vec<Uuid>, folder_ids: Vec<Uuid>) -> Value {
    json!({
        "file_ids": file_ids,
        "folder_ids": folder_ids
    })
}

pub fn bulk_cancel_req(uploads: Vec<(Uuid, Uuid)>) -> Value {
    let items: Vec<Value> = uploads
        .iter()
        .map(|(f, v)| json!({ "file_id": f, "version_id": v }))
        .collect();
    json!({ "uploads": items })
}

// ── Signup Edge Case Factories ──────────────────────────────

pub fn signup_short_pubkey(email: &str) -> Value {
    let mut payload = signup_complete_req(email);
    payload["identity_pubkey"] = json!(random_b64(16));
    payload
}

pub fn signup_bad_nonce(email: &str) -> Value {
    let mut payload = signup_complete_req(email);
    payload["wrapped_dek_nonce"] = json!(random_b64(10));
    payload
}

pub fn signup_bad_b64(email: &str) -> Value {
    let mut payload = signup_complete_req(email);
    payload["identity_pubkey"] = json!("!!!not_valid_base64!!!");
    payload
}

// ── Helper for creating file directly in DB ──────────────────

pub async fn create_file_directly(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    folder_id: Option<Uuid>,
    is_active: bool,
) -> Uuid {
    let file_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    let device_id: Uuid =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap();

    sqlx::query(
        "INSERT INTO files (file_id, user_id, folder_id, encrypted_metadata, metadata_nonce, plaintext_blake3, total_size, current_version_id)
         VALUES ($1, $2, $3, $4, $5, $6, 1024, NULL)",
    )
    .bind(file_id)
    .bind(user_id)
    .bind(folder_id)
    .bind(vec![0u8; 48])
    .bind(vec![0u8; 24])
    .bind(vec![0u8; 32])
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO file_versions (version_id, file_id, version_number, encryption_header, total_size, total_chunks, plaintext_blake3, created_by_device_id, is_active)
         VALUES ($1, $2, 1, $3, 1024, 1, $4, $5, $6)",
    )
    .bind(version_id)
    .bind(file_id)
    .bind(vec![0u8; 24])
    .bind(vec![0u8; 32])
    .bind(device_id)
    .bind(is_active)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query("UPDATE files SET current_version_id = $1 WHERE file_id = $2")
        .bind(version_id)
        .bind(file_id)
        .execute(pool)
        .await
        .unwrap();

    file_id
}
