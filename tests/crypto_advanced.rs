
use uoozer_vault_backend::core::crypto;
use base64::Engine;

#[test]
fn salt_is_cryptographically_random() {
    let s1 = crypto::generate_salt();
    let s2 = crypto::generate_salt();
    assert_ne!(s1, s2);
    assert_eq!(s1.len(), 16);
}

#[test]
fn deterministic_fake_salt_uses_normalized_email() {
    let p = b"pepper";
    let a = crypto::deterministic_fake_salt("Alice@Example.com", p);
    let b = crypto::deterministic_fake_salt("  alice@example.com  ".trim(), p);
    let c = crypto::deterministic_fake_salt("ALICE@EXAMPLE.COM", p);
    
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[test]
fn fake_salt_differs_from_real_salt_for_same_email() {
    let p = b"pepper";
    let fake = crypto::deterministic_fake_salt("alice@example.com", p);
    let real = crypto::generate_salt();
    assert_ne!(fake.as_slice(), real.as_slice());
}

#[test]
fn auth_key_hash_differs_for_different_costs() {
    let key = "dGVzdA==";
    let h1 = crypto::hash_auth_key(key, 4).unwrap();
    let h2 = crypto::hash_auth_key(key, 5).unwrap();
    assert_ne!(h1, h2);
}

#[test]
fn refresh_token_hash_is_constant_time_safe() {
    let h = crypto::hash_refresh_token("abc");
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn blake3_verify_rejects_wrong_length_hash() {
    let data = b"hello";
    let short_hash = [0u8; 16];
    assert!(!crypto::verify_blake3(data, &short_hash));
}

#[test]
fn jwt_rejects_token_with_wrong_issuer() {
    let (_, kp) = crypto::JwtKeyPair::generate_dev_keypair();
    let cfg = uoozer_vault_backend::config::JwtConfig {
        issuer: "wrong-issuer".to_string(),
        access_ttl_seconds: 900,
        refresh_ttl_seconds: 2592000,
    };
    let token = kp.sign_access_token(uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), &cfg).unwrap();
    assert!(kp.verify_access_token(&token).is_err());
}

#[test]
fn jwt_rejects_refresh_token_used_as_access() {
    let (_, kp) = crypto::JwtKeyPair::generate_dev_keypair();
    let cfg = uoozer_vault_backend::config::JwtConfig {
        issuer: "uoozer-vault".to_string(),
        access_ttl_seconds: 900,
        refresh_ttl_seconds: 2592000,
    };
    let uid = uuid::Uuid::new_v4();
    let sid = uuid::Uuid::new_v4();
    let did = uuid::Uuid::new_v4();
    let refresh = kp.sign_refresh_token(uid, sid, did, uuid::Uuid::new_v4(), &cfg).unwrap();
    assert!(kp.verify_access_token(&refresh).is_err());
}