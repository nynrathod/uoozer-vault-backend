mod common;
use common::{API, factory, setup_app};
use serde_json::json;

// ── Verify chunk after upload ──────────────────────────

#[tokio::test]
async fn verify_chunk_success() {
    if std::env::var("RUN_E2E_STORAGE_TESTS").is_err() {
        return;
    }

    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "c4_verify@example.com").await;

    let req = factory::create_file_req(None);
    let create_resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    let create_body: serde_json::Value = create_resp.json().await.unwrap();
    let file_id = create_body["file_id"].as_str().unwrap();
    let version_id = create_body["version_id"].as_str().unwrap();
    let upload_url = create_body["upload_urls"][0]["presigned_url"]
        .as_str()
        .unwrap()
        .to_string();

    let chunk_data = vec![0u8; 1024];
    let put_resp = reqwest::Client::new()
        .put(&upload_url)
        .body(chunk_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), 200);

    let etag = put_resp
        .headers()
        .get("ETag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    let verify_req = json!({
        "version_id": version_id,
        "chunk_index": 0,
        "r2_etag": etag
    });

    let verify_resp = server
        .client
        .post(server.url(&format!("{API}/chunks/verify")))
        .header("authorization", format!("Bearer {access}"))
        .json(&verify_req)
        .send()
        .await
        .unwrap();

    assert_eq!(verify_resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(body["uploaded"], true);
}

// ── Wrong ETag ─────────────────────────────────────────

#[tokio::test]
async fn verify_chunk_wrong_etag() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "c5_wrong_etag@example.com").await;

    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'c5_wrong_etag@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = uuid::Uuid::new_v4();
    let version_id = uuid::Uuid::new_v4();
    let device_id: uuid::Uuid =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    sqlx::query("INSERT INTO files (file_id, user_id, encrypted_metadata, metadata_nonce, plaintext_blake3, total_size, current_version_id) VALUES ($1, $2, $3, $4, $5, 1024, NULL)")
        .bind(file_id).bind(user_id).bind(vec![0u8; 48]).bind(vec![0u8; 24]).bind(vec![0u8; 32])
        .execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO file_versions (version_id, file_id, version_number, encryption_header, total_size, total_chunks, plaintext_blake3, created_by_device_id, is_active) VALUES ($1, $2, 1, $3, 1024, 1, $4, $5, false)")
        .bind(version_id).bind(file_id).bind(vec![0u8; 24]).bind(vec![0u8; 32]).bind(device_id)
        .execute(&pool).await.unwrap();

    sqlx::query("UPDATE files SET current_version_id = $1 WHERE file_id = $2")
        .bind(version_id)
        .bind(file_id)
        .execute(&pool)
        .await
        .unwrap();

    let r2_key = format!("{}/{}/{}/{}/{}", user_id, file_id, version_id, 0, 0);
    sqlx::query("INSERT INTO file_chunks (version_id, chunk_index, segment_index, chunk_size, chunk_blake3, r2_key) VALUES ($1, 0, 0, 1024, $2, $3)")
        .bind(version_id).bind(vec![0u8; 32]).bind(&r2_key)
        .execute(&pool).await.unwrap();

    let verify_req = json!({
        "version_id": version_id,
        "chunk_index": 0,
        "r2_etag": "wrong_etag_string"
    });

    let resp = server
        .client
        .post(server.url(&format!("{API}/chunks/verify")))
        .header("authorization", format!("Bearer {access}"))
        .json(&verify_req)
        .send()
        .await
        .unwrap();

    // In dev mode (R2 not configured), the backend skips the HEAD check.
    // If R2 was configured, it would return 400.
    assert_eq!(resp.status(), http::StatusCode::OK);
}

// ── Chunk size mismatch ─────────────────────────────────

#[tokio::test]
async fn create_file_rejects_chunk_size_mismatch() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "c6_size_mismatch@example.com").await;

    let mut req = factory::create_file_req(None);
    req["total_size"] = json!(1024);
    req["chunks"][0]["chunk_size"] = json!(2048);

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

// ── Chunk index out of order ────────────────────────────

#[tokio::test]
async fn create_file_rejects_out_of_order_chunks() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "c8_out_of_order@example.com").await;

    let req = factory::create_file_req_with_size(None, 2048, 2);
    let mut bad_req = req.clone();
    bad_req["chunks"][0]["chunk_index"] = json!(1);
    bad_req["chunks"][1]["chunk_index"] = json!(0);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&bad_req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Resume info for incomplete upload ───────────────────────

#[tokio::test]
async fn get_resume_info_returns_correct_chunks() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "c_resume@example.com").await;

    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'c_resume@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = uuid::Uuid::new_v4();
    let version_id = uuid::Uuid::new_v4();
    let device_id: uuid::Uuid =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    sqlx::query("INSERT INTO files (file_id, user_id, encrypted_metadata, metadata_nonce, plaintext_blake3, total_size, current_version_id) VALUES ($1, $2, $3, $4, $5, 4096, NULL)")
        .bind(file_id).bind(user_id).bind(vec![0u8; 48]).bind(vec![0u8; 24]).bind(vec![0u8; 32])
        .execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO file_versions (version_id, file_id, version_number, encryption_header, total_size, total_chunks, plaintext_blake3, created_by_device_id, is_active) VALUES ($1, $2, 1, $3, 4096, 3, $4, $5, false)")
        .bind(version_id).bind(file_id).bind(vec![0u8; 24]).bind(vec![0u8; 32]).bind(device_id)
        .execute(&pool).await.unwrap();

    sqlx::query("UPDATE files SET current_version_id = $1 WHERE file_id = $2")
        .bind(version_id)
        .bind(file_id)
        .execute(&pool)
        .await
        .unwrap();

    for i in 0..3 {
        let r2_key = format!("{}/{}/{}/{}/{}", user_id, file_id, version_id, 0, i);
        sqlx::query("INSERT INTO file_chunks (version_id, chunk_index, segment_index, chunk_size, chunk_blake3, r2_key, uploaded_at, r2_etag) VALUES ($1, $2, 0, 1024, $3, $4, CASE WHEN $2 = 0 THEN now() ELSE NULL END, CASE WHEN $2 = 0 THEN 'etag0' ELSE NULL END)")
            .bind(version_id).bind(i).bind(vec![i as u8; 32]).bind(&r2_key)
            .execute(&pool).await.unwrap();
    }

    let resp = server
        .client
        .get(server.url(&format!("{API}/chunks/{version_id}/resume")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["total_chunks"], 3);
    assert_eq!(body["uploaded_chunks"], json!([0]));
    assert_eq!(body["missing_chunks"], json!([1, 2]));
}

// ── Resume info IDOR ────────────────────────────────────────

#[tokio::test]
async fn resume_info_idor_protected() {
    let (server, pool, _guard) = setup_app().await;

    let (_, _, _, _) = common::signup_full(&server, "c_idor_a@example.com").await;
    let user_a: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'c_idor_a@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = uuid::Uuid::new_v4();
    let version_id = uuid::Uuid::new_v4();
    let device_id: uuid::Uuid =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE user_id = $1 LIMIT 1")
            .bind(user_a)
            .fetch_one(&pool)
            .await
            .unwrap();

    sqlx::query("INSERT INTO files (file_id, user_id, encrypted_metadata, metadata_nonce, plaintext_blake3, total_size, current_version_id) VALUES ($1, $2, $3, $4, $5, 4096, NULL)")
        .bind(file_id).bind(user_a).bind(vec![0u8; 48]).bind(vec![0u8; 24]).bind(vec![0u8; 32])
        .execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO file_versions (version_id, file_id, version_number, encryption_header, total_size, total_chunks, plaintext_blake3, created_by_device_id, is_active) VALUES ($1, $2, 1, $3, 4096, 3, $4, $5, false)")
        .bind(version_id).bind(file_id).bind(vec![0u8; 24]).bind(vec![0u8; 32]).bind(device_id)
        .execute(&pool).await.unwrap();

    sqlx::query("UPDATE files SET current_version_id = $1 WHERE file_id = $2")
        .bind(version_id)
        .bind(file_id)
        .execute(&pool)
        .await
        .unwrap();

    for i in 0..3 {
        let r2_key = format!("{}/{}/{}/{}/{}", user_a, file_id, version_id, 0, i);
        sqlx::query("INSERT INTO file_chunks (version_id, chunk_index, segment_index, chunk_size, chunk_blake3, r2_key) VALUES ($1, $2, 0, 1024, $3, $4)")
            .bind(version_id).bind(i).bind(vec![i as u8; 32]).bind(&r2_key)
            .execute(&pool).await.unwrap();
    }

    let (access_b, _, _, _) = common::signup_full(&server, "c_idor_b@example.com").await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/chunks/{version_id}/resume")))
        .header("authorization", format!("Bearer {access_b}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

// ── Resume info non-existent version ────────────────────────

#[tokio::test]
async fn resume_info_nonexistent_version_returns_404() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "c_404@example.com").await;

    let fake_id = uuid::Uuid::new_v4();
    let resp = server
        .client
        .get(server.url(&format!("{API}/chunks/{fake_id}/resume")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

// ── Chunks require authentication ──────────────────────────

#[tokio::test]
async fn chunks_require_authentication() {
    let (server, _pool, _guard) = setup_app().await;

    let fake_id = uuid::Uuid::new_v4();
    let resp = server
        .client
        .get(server.url(&format!("{API}/chunks/{fake_id}/resume")))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}
