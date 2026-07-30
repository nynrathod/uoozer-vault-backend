#![no_main]
use libfuzzer_sys::fuzz_target;
use uoozer_vault_backend::core::crypto;

// This will throw millions of random strings at your base64 decoder.
// If your code panics on ANY input, the fuzzer will stop and show you the exact string that crashed it.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = crypto::decode_b64(s);
    }
});
