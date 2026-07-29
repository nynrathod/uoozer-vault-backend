use uoozer_vault_backend::core::crypto;

#[test]
fn salt_generation_produces_16_bytes() {
    let salt = crypto::generate_salt();
    assert_eq!(salt.len(), 16, "Salt must be exactly 16 bytes");
}

#[test]
fn deterministic_fake_salt_is_deterministic() {
    let pepper = b"test_pepper";
    let salt1 = crypto::deterministic_fake_salt("alice@example.com", pepper);
    let salt2 = crypto::deterministic_fake_salt("alice@example.com", pepper);
    assert_eq!(
        salt1, salt2,
        "Same email + pepper must produce identical salt"
    );
}

#[test]
fn deterministic_fake_salt_differs_for_different_emails() {
    let pepper = b"test_pepper";
    let salt1 = crypto::deterministic_fake_salt("alice@example.com", pepper);
    let salt2 = crypto::deterministic_fake_salt("bob@example.com", pepper);
    assert_ne!(salt1, salt2);
}

#[test]
fn deterministic_fake_salt_normalizes_case() {
    let pepper = b"test_pepper";
    let upper = crypto::deterministic_fake_salt("Alice@Example.COM", pepper);
    let lower = crypto::deterministic_fake_salt("alice@example.com", pepper);
    assert_eq!(upper, lower);
}

#[test]
fn auth_key_hash_and_verify_roundtrip() {
    let auth_key = "dGVzdF9hdXRoX2tleV9mb3JfdW5pdF90ZXN0cw==";
    let cost = 4;
    let hash = crypto::hash_auth_key(auth_key, cost).expect("bcrypt hash failed");
    assert!(crypto::verify_auth_key(auth_key, &hash));
    assert!(!crypto::verify_auth_key("wrong_key", &hash));
}

#[test]
fn refresh_token_hash_is_deterministic() {
    let token = "some-refresh-token-string";
    let hash1 = crypto::hash_refresh_token(token);
    let hash2 = crypto::hash_refresh_token(token);
    assert_eq!(hash1, hash2);
    assert_ne!(crypto::hash_refresh_token("different-token"), hash1);
}

#[test]
fn blake3_verify_correct_hash() {
    let data = b"hello world";
    let hash = blake3::hash(data);
    assert!(crypto::verify_blake3(data, hash.as_bytes()));
}

#[test]
fn blake3_verify_tampered_data_fails() {
    let data = b"hello world";
    let hash = blake3::hash(data);
    assert!(!crypto::verify_blake3(b"hello WORLD", hash.as_bytes()));
}

#[test]
fn blake3_verify_tampered_hash_fails() {
    let data = b"hello world";
    let mut hash = *blake3::hash(data).as_bytes();
    hash[0] ^= 0xFF;
    assert!(!crypto::verify_blake3(data, &hash));
}

#[test]
fn blake3_verify_large_input_1mb() {
    let data = vec![0x42u8; 1024 * 1024]; // 1MB
    let hash = blake3::hash(&data);
    assert!(crypto::verify_blake3(&data, hash.as_bytes()));
}

#[test]
fn base64_decode_encode_roundtrip() {
    let original = b"some binary data \x00\x01\x02\xff";
    let encoded = crypto::encode_b64(original);
    let decoded = crypto::decode_b64(&encoded).expect("decode failed");
    assert_eq!(decoded, original);
}

#[test]
fn base64_decode_invalid_input_returns_error() {
    let result = crypto::decode_b64("!!!invalid!!!");
    assert!(result.is_err());
}

#[test]
fn jwt_dev_keypair_signs_and_verifies() {
    use uoozer_vault_backend::config::JwtConfig;

    let (pem, keypair) = crypto::JwtKeyPair::generate_dev_keypair();

    let jwt_config = JwtConfig {
        issuer: "uoozer-vault".to_string(),
        access_ttl_seconds: 900,
        refresh_ttl_seconds: 2592000,
    };

    let user_id = uuid::Uuid::new_v4();
    let session_id = uuid::Uuid::new_v4();
    let device_id = uuid::Uuid::new_v4();

    let token = keypair
        .sign_access_token(user_id, session_id, device_id, &jwt_config)
        .expect("sign failed");

    let claims = keypair.verify_access_token(&token).expect("verify failed");
    assert_eq!(claims.sub, user_id);
    assert_eq!(claims.sid, session_id);
    assert_eq!(claims.did, device_id);
    assert_eq!(claims.typ, "access");
}

#[test]
fn jwt_tampered_token_fails_verification() {
    use uoozer_vault_backend::config::JwtConfig;

    let (pem, keypair) = crypto::JwtKeyPair::generate_dev_keypair();
    let jwt_config = JwtConfig {
        issuer: "uoozer-vault".to_string(),
        access_ttl_seconds: 900,
        refresh_ttl_seconds: 2592000,
    };

    let user_id = uuid::Uuid::new_v4();
    let session_id = uuid::Uuid::new_v4();
    let device_id = uuid::Uuid::new_v4();

    let mut token = keypair
        .sign_access_token(user_id, session_id, device_id, &jwt_config)
        .expect("sign failed");

    let last_char = token.pop().unwrap();
    token.push(if last_char == 'A' { 'B' } else { 'A' });

    let result = keypair.verify_access_token(&token);
    assert!(result.is_err());
}
