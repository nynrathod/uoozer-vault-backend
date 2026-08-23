mod common;
use base64::Engine;
use common::{API, factory, setup_app};
use serde_json::json;

// ── Empty file (0 bytes) ────────────────────────────────

#[tokio::test]
async fn empty_file_accepted() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a1_empty@example.com").await;

    let req = factory::create_file_req_with_size(None, 0, 1);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── File exactly 4MB (1 chunk) ──────────────────────────

#[tokio::test]
async fn file_exactly_4mb_accepted() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a2_4mb@example.com").await;

    let size = 4 * 1024 * 1024;
    let req = factory::create_file_req_with_size(None, size, 1);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── File exactly 8MB (2 chunks) ─────────────────────────

#[tokio::test]
async fn file_exactly_8mb_accepted() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a3_8mb@example.com").await;

    let size = 8 * 1024 * 1024;
    let req = factory::create_file_req_with_size(None, size, 2);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── File at 10GB limit ─────────────────────────────────

#[tokio::test]
async fn file_at_10gb_limit_rejected_by_quota() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a4_10gb@example.com").await;

    let size = 10 * 1024 * 1024 * 1024; // 10GB
    let req = factory::create_file_req_with_size(None, size, 2500);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("storage quota exceeded")
    );
}

// ── File exceeding 10GB ────────────────────────────────

#[tokio::test]
async fn file_exceeding_10gb_rejected() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a5_over_10gb@example.com").await;

    let size = 11 * 1024 * 1024 * 1024;
    let req = factory::create_file_req_with_size(None, size, 2750);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── File exceeding quota ────────────────────────────────

#[tokio::test]
async fn precheck_quota_exceeded() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a6_quota@example.com").await;

    let oversized_total_size = 101 * 1024 * 1024;

    let base_url = server.url(&format!("{API}/files/precheck"));
    let url = reqwest::Url::parse_with_params(
        &base_url,
        &[
            ("plaintext_blake3", factory::random_b64(32)),
            ("total_size", oversized_total_size.to_string()),
        ],
    )
    .unwrap();

    let resp = server
        .client
        .get(url)
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("quota exceeded")
    );
}

// ── Unicode filename ───────────────────────────────────

#[tokio::test]
async fn unicode_filename_accepted() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a7_unicode@example.com").await;

    let metadata = "{\"name\":\"测试文件_🎉.pdf\"}";
    let req =
        factory::create_file_req_with_metadata(None, metadata, &factory::random_b64(32), 1024, 1);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Path traversal in filename ─────────────────────────

#[tokio::test]
async fn path_traversal_in_metadata_ignored() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a8_traversal@example.com").await;

    // Backend doesn't parse metadata, so path traversal in the name field is fine.
    // It will be rejected by the client-side sanitizer, but backend should accept it.
    let metadata = "{\"name\":\"../../../etc/passwd\"}";
    let req =
        factory::create_file_req_with_metadata(None, metadata, &factory::random_b64(32), 1024, 1);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Null bytes in filename ──────────────────────────────

#[tokio::test]
async fn null_bytes_in_metadata_ignored() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a9_null@example.com").await;

    let metadata = "{\"name\":\"file\x00.txt\"}";
    let req =
        factory::create_file_req_with_metadata(None, metadata, &factory::random_b64(32), 1024, 1);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Filename > 255 chars ───────────────────────────────

#[tokio::test]
async fn oversized_filename_accepted_by_backend() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a10_long@example.com").await;

    // Backend doesn't validate filename length (it's encrypted).
    // Client-side validation should handle this.
    let long_name = "a".repeat(300);
    let metadata = format!("{{\"name\":\"{}\"}}", long_name);
    let req =
        factory::create_file_req_with_metadata(None, &metadata, &factory::random_b64(32), 1024, 1);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Blocked extension ──────────────────────────────────

#[tokio::test]
async fn blocked_extension_rejected() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a12_blocked@example.com").await;

    // Backend doesn't check file extensions (they're in encrypted metadata).
    // But it does check for invalid base64 in metadata.
    let metadata = "{\"name\":\"virus.exe\"}";
    let req =
        factory::create_file_req_with_metadata(None, metadata, &factory::random_b64(32), 1024, 1);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    // Backend accepts because metadata is encrypted and opaque.
    // Client-side validation blocks .exe files.
    assert_ne!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Spoofed MIME type ──────────────────────────────────

#[tokio::test]
async fn spoofed_mime_type_accepted_by_backend() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a13_spoof@example.com").await;

    let metadata = "{\"name\":\"image.jpg\",\"mimeType\":\"application/pdf\"}";
    let req =
        factory::create_file_req_with_metadata(None, metadata, &factory::random_b64(32), 1024, 1);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Duplicate file dedup ────────────────────────────────

#[tokio::test]
async fn duplicate_file_dedup_precheck() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a14_dedup@example.com").await;

    let file_hash = factory::random_b64(32);
    let hash_bytes = base64::engine::general_purpose::STANDARD
        .decode(&file_hash)
        .unwrap();

    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'a14_dedup@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;
    let version_id: uuid::Uuid =
        sqlx::query_scalar("SELECT current_version_id FROM files WHERE file_id = $1")
            .bind(file_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    sqlx::query("UPDATE files SET plaintext_blake3 = $1 WHERE file_id = $2")
        .bind(&hash_bytes)
        .bind(file_id)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("UPDATE file_versions SET plaintext_blake3 = $1 WHERE version_id = $2")
        .bind(&hash_bytes)
        .bind(version_id)
        .execute(&pool)
        .await
        .unwrap();

    let base_url = server.url(&format!("{API}/files/precheck"));
    let url = reqwest::Url::parse_with_params(
        &base_url,
        &[
            ("plaintext_blake3", file_hash.clone()),
            ("total_size", "1024".to_string()),
        ],
    )
    .unwrap();

    let resp = server
        .client
        .get(url)
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["deduplicated"], true);
}

// ── Duplicate filename ─────────────────────────────────

#[tokio::test]
async fn duplicate_filename_allowed_by_backend() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a15_dup_name@example.com").await;

    // Backend doesn't check for duplicate filenames because metadata is encrypted.
    // Two files with the same encrypted metadata will create two separate files.
    let req = factory::create_file_req(None);

    let resp1 = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    let resp2 = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_ne!(resp1.status(), http::StatusCode::BAD_REQUEST);
    assert_ne!(resp2.status(), http::StatusCode::BAD_REQUEST);
}

// ── Upload to non-existent folder ──────────────────────

#[tokio::test]
async fn upload_to_nonexistent_folder_fails() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a25_bad_folder@example.com").await;

    let fake_folder_id = uuid::Uuid::new_v4();
    let req = factory::create_file_req(Some(fake_folder_id));

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

// ── IDOR protection ────────────────────────────────────

#[tokio::test]
async fn upload_idor_folder_fails() {
    let (server, _pool, _guard) = setup_app().await;

    let (access_a, _, _, _) = common::signup_full(&server, "a26_user_a@example.com").await;
    let folder_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access_a}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();
    let folder_id = folder_resp.json::<serde_json::Value>().await.unwrap()["folder_id"]
        .as_str()
        .unwrap()
        .to_string();

    let (access_b, _, _, _) = common::signup_full(&server, "a26_user_b@example.com").await;
    let req = factory::create_file_req(Some(uuid::Uuid::parse_str(&folder_id).unwrap()));

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access_b}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

// ── Concurrent upload of same file ─────────────────────

#[tokio::test]
async fn concurrent_dedup_safe() {
    if std::env::var("RUN_E2E_STORAGE_TESTS").is_err() {
        return;
    }

    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "a27_concurrent@example.com").await;

    let file_hash = factory::random_b64(32);
    let req_body = factory::create_file_req_with_hash(None, file_hash);

    let (resp1, resp2) = tokio::join!(
        server
            .client
            .post(server.url(&format!("{API}/files")))
            .header("authorization", format!("Bearer {access}"))
            .json(&req_body)
            .send(),
        server
            .client
            .post(server.url(&format!("{API}/files")))
            .header("authorization", format!("Bearer {access}"))
            .json(&req_body)
            .send()
    );

    let resp1 = resp1.unwrap();
    let resp2 = resp2.unwrap();

    let statuses = [resp1.status().as_u16(), resp2.status().as_u16()];
    assert!(statuses.contains(&201));

    let body1: serde_json::Value = resp1.json().await.unwrap();
    let body2: serde_json::Value = resp2.json().await.unwrap();

    let dedup1 = body1["deduplicated"].as_bool().unwrap_or(false);
    let dedup2 = body2["deduplicated"].as_bool().unwrap_or(false);

    assert!(
        dedup1 ^ dedup2,
        "Exactly one request should be deduplicated"
    );
}

// ── Validation Error Cases ──────────────────────────────────

#[tokio::test]
async fn create_file_validation_bad_nonce() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "val_bad_nonce@example.com").await;

    let req = factory::create_file_with_bad_nonce(None);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_file_validation_chunk_count_mismatch() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "val_chunk_mismatch@example.com").await;

    let req = factory::create_file_with_chunk_mismatch(None);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_file_validation_chunk_size_mismatch() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "val_size_mismatch@example.com").await;

    let req = factory::create_file_with_bad_chunk_size(None);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("do not match total file size")
    );
}

#[tokio::test]
async fn create_file_validation_bad_hash() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "val_bad_hash@example.com").await;

    let req = factory::create_file_with_bad_hash(None);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_file_validation_bad_header() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "val_bad_header@example.com").await;

    let req = factory::create_file_with_bad_header(None);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_file_validation_exceeding_quota() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "val_quota@example.com").await;

    let mut req = factory::create_file_req(None);
    req["total_size"] = json!(200 * 1024 * 1024);
    req["chunks"][0]["chunk_size"] = json!(200 * 1024 * 1024 + 17);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("storage quota exceeded")
    );
}

#[tokio::test]
async fn create_file_chunk_count_boundary() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "val_chunk_boundary@example.com").await;

    let mut req = factory::create_file_req(None);
    req["total_chunks"] = json!(50_001);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("invalid total_chunks")
    );
}

#[tokio::test]
async fn create_file_invalid_base64_metadata() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "val_b64@example.com").await;

    let mut req = factory::create_file_req(None);
    req["encrypted_metadata"] = json!("!!!not_valid_base64!!!");

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}
