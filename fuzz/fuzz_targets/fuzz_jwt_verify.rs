#![no_main]
use libfuzzer_sys::fuzz_target;
use uoozer_vault_backend::core::crypto;

// Throws random strings at the JWT verifier to ensure it NEVER panics,
// only returns errors.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let (_, keypair) = crypto::JwtKeyPair::generate_dev_keypair();
        let _ = keypair.verify_access_token(s);
        let _ = keypair.verify_refresh_token(s);
    }
});
