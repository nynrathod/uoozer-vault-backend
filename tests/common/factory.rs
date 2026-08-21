use base64::Engine;
use serde_json::{Value, json};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

pub fn random_b64(len: usize) -> String {
    let buf: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
    B64.encode(buf)
}

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
    device_id: uuid::Uuid,
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

pub fn create_folder_req(parent: Option<uuid::Uuid>) -> Value {
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

pub fn change_password_req() -> Value {
    json!({
        "new_auth_key": random_b64(32),
        "new_wrapped_dek": random_b64(64),
        "new_wrapped_dek_nonce": random_b64(24)
    })
}

pub fn signup_short_pubkey(email: &str) -> Value {
    let mut payload = signup_complete_req(email);
    payload["identity_pubkey"] = json!(random_b64(16)); // Invalid length
    payload
}

pub fn signup_bad_nonce(email: &str) -> Value {
    let mut payload = signup_complete_req(email);
    payload["wrapped_dek_nonce"] = json!(random_b64(10)); // Invalid length
    payload
}

pub fn signup_bad_b64(email: &str) -> Value {
    let mut payload = signup_complete_req(email);
    payload["identity_pubkey"] = json!("!!!not_valid_base64!!!");
    payload
}

pub fn create_file_req(folder_id: Option<uuid::Uuid>) -> Value {
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
        }]
    })
}

pub fn update_file_req() -> Value {
    json!({
        "encrypted_metadata": random_b64(48),
        "metadata_nonce": random_b64(24),
    })
}

pub fn create_file_req_with_hash(folder_id: Option<uuid::Uuid>, plaintext_blake3: String) -> Value {
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
        }]
    })
}
