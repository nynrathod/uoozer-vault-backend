use proptest::prelude::*;
use uoozer_vault_backend::core::crypto;

proptest! {
    #[test]
    fn fake_salt_never_panics_on_arbitrary_email(email in ".{0,500}") {
        let _ = crypto::deterministic_fake_salt(&email, b"pepper");
    }

    #[test]
    fn base64_decode_handles_any_input(s in ".{0,200}") {
        let _ = crypto::decode_b64(&s);
    }

    #[test]
    fn blake3_verify_does_not_panic_on_short_hash(data in prop::collection::vec(any::<u8>(), 0..100)) {
        let mut short = vec![0u8; 10];
        let _ = crypto::verify_blake3(&data, &short);
    }
}
