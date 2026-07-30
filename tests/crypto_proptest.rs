use proptest::prelude::*;
use uoozer_vault_backend::core::crypto;

#[test]
fn base64_never_panics_on_random_input() {
    proptest!(|(random_input in ".{0, 100}")| {
        // The server must NEVER panic on weird base64 inputs. It should just error.
        let _ = crypto::decode_b64(&random_input);
    });
}

#[test]
fn blake3_verification_never_panics() {
    proptest!(|(random_data in prop::collection::vec(any::<u8>(), 0..1024))| {
        let hash = blake3::hash(&random_data);
        // Tampered hash (flip a bit)
        let mut tampered = *hash.as_bytes();
        if !tampered.is_empty() {
            tampered[0] ^= 0xFF;
        }

        let _ = crypto::verify_blake3(&random_data, &tampered);
    });
}

#[test]
fn jwt_signing_never_panics() {
    proptest!(|(_ in 0..100)| {
        let user_id = uuid::Uuid::new_v4();
        let session_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();

        let (_, keypair) = crypto::JwtKeyPair::generate_dev_keypair();
        let jwt_config = uoozer_vault_backend::config::JwtConfig {
            issuer: "test".to_string(),
            access_ttl_seconds: 900,
            refresh_ttl_seconds: 2592000,
        };

        if let Ok(token) = keypair.sign_access_token(user_id, session_id, device_id, &jwt_config) {
            let _ = keypair.verify_access_token(&token);
        }
    });
}
