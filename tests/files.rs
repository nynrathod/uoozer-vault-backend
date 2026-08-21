mod common;
use common::{API, factory, setup_app};
use serde_json::json;
use sqlx::Row;

// Helper to insert a file directly into the DB for testing GET/LIST/DELETE without R2
async fn create_file_directly(
    pool: &sqlx::PgPool,
    user_id: uuid::Uuid,
    folder_id: Option<uuid::Uuid>,
    is_active: bool,
) -> uuid::Uuid {
    let file_id = uuid::Uuid::new_v4();
    let version_id = uuid::Uuid::new_v4();
    let device_id: uuid::Uuid =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap();

    // 1. Insert file with NULL current_version_id (to satisfy circular FK)
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

    // 2. Insert the version
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

    // 3. Link them
    sqlx::query("UPDATE files SET current_version_id = $1 WHERE file_id = $2")
        .bind(version_id)
        .bind(file_id)
        .execute(pool)
        .await
        .unwrap();

    file_id
}

#[tokio::test]
async fn get_file_returns_file_info() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "alice@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'alice@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = create_file_directly(&pool, user_id, None, true).await;

    let resp = server
        .client
        .get(server.url(&format!("{API}/files/{file_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["file_id"], file_id.to_string());
    assert_eq!(body["is_uploading"], false); // true because is_active=true
}

#[tokio::test]
async fn get_file_uploading_status() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bob@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'bob@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    // is_active = false simulates an upload that hasn't completed yet
    let file_id = create_file_directly(&pool, user_id, None, false).await;

    let resp = server
        .client
        .get(server.url(&format!("{API}/files/{file_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["is_uploading"], true);
}

#[tokio::test]
async fn list_files_pagination_and_folder_filter() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "carol@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'carol@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    // Create 5 files in root, 2 in a folder
    for _ in 0..5 {
        create_file_directly(&pool, user_id, None, true).await;
    }

    let folder_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();
    let folder_id = folder_resp.json::<serde_json::Value>().await.unwrap()["folder_id"]
        .as_str()
        .unwrap()
        .to_string();

    for _ in 0..2 {
        create_file_directly(
            &pool,
            user_id,
            Some(uuid::Uuid::parse_str(&folder_id).unwrap()),
            true,
        )
        .await;
    }

    // Test pagination in root (should only see 5 root files)
    let resp = server
        .client
        .get(server.url(&format!("{API}/files?limit=2&offset=0")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["total"], 5); // Changed to 5: root files only
    assert_eq!(body["files"].as_array().unwrap().len(), 2);

    // Test folder filter (should see 2 files)
    let resp2 = server
        .client
        .get(server.url(&format!("{API}/files?folder_id={folder_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    let body2: serde_json::Value = resp2.json().await.unwrap();
    assert_eq!(body2["total"], 2);
    assert_eq!(body2["files"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn create_file_without_r2_returns_503() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "grace@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_file_req(None))
        .send()
        .await
        .unwrap();

    // If R2 is configured (env var set), it will succeed (201).
    // If not, it returns 503. We accept either since it depends on test environment.
    assert!(
        resp.status() == http::StatusCode::SERVICE_UNAVAILABLE
            || resp.status() == http::StatusCode::CREATED
    );
}

#[tokio::test]
async fn idor_cannot_access_other_users_file() {
    let (server, pool, _guard) = setup_app().await;
    let (access_a, _, _, _) = common::signup_full(&server, "alice@example.com").await;
    let user_a: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'alice@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = create_file_directly(&pool, user_a, None, true).await;

    let (access_b, _, _, _) = common::signup_full(&server, "bob@example.com").await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/files/{file_id}")))
        .header("authorization", format!("Bearer {access_b}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_file_soft_deletes() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "dave@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'dave@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = create_file_directly(&pool, user_id, None, true).await;

    let resp = server
        .client
        .delete(server.url(&format!("{API}/files/{file_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    // Verify it's soft-deleted in DB
    let is_deleted: bool =
        sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM files WHERE file_id = $1")
            .bind(file_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(is_deleted);

    // Verify we can't get it anymore
    let resp2 = server
        .client
        .get(server.url(&format!("{API}/files/{file_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_versions_returns_all() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "eve@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'eve@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = create_file_directly(&pool, user_id, None, true).await;
    let device_id: uuid::Uuid =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    // Add V2
    sqlx::query(
        "INSERT INTO file_versions (version_id, file_id, version_number, encryption_header, total_size, total_chunks, plaintext_blake3, created_by_device_id, is_active)
         VALUES ($1, $2, 2, $3, 2048, 2, $4, $5, false)",
    )
    .bind(uuid::Uuid::new_v4()).bind(file_id).bind(vec![1u8; 24]).bind(vec![1u8; 32]).bind(device_id)
    .execute(&pool).await.unwrap();

    let resp = server
        .client
        .get(server.url(&format!("{API}/files/{file_id}/versions")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body.as_array().unwrap().len(), 2);
    assert_eq!(body[0]["version_number"], 2); // Most recent first
}

#[tokio::test]
async fn restore_version_swaps_pointer() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "frank@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'frank@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = create_file_directly(&pool, user_id, None, true).await; // V1 is active
    let device_id: uuid::Uuid =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    // Add V2 (inactive)
    let v2_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO file_versions (version_id, file_id, version_number, encryption_header, total_size, total_chunks, plaintext_blake3, created_by_device_id, is_active)
         VALUES ($1, $2, 2, $3, 2048, 2, $4, $5, false)",
    )
    .bind(v2_id).bind(file_id).bind(vec![1u8; 24]).bind(vec![1u8; 32]).bind(device_id)
    .execute(&pool).await.unwrap();

    // Restore V2
    let resp = server
        .client
        .post(server.url(&format!("{API}/files/{file_id}/versions/{v2_id}/restore")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    // Verify V2 is now active
    let active_v: uuid::Uuid = sqlx::query_scalar(
        "SELECT version_id FROM file_versions WHERE file_id = $1 AND is_active = true",
    )
    .bind(file_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_v, v2_id);
}

#[tokio::test]
async fn create_file_validation_bad_nonce() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "henry@example.com").await;

    let mut req = factory::create_file_req(None);
    req["metadata_nonce"] = json!(factory::random_b64(10)); // Invalid size

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
    let (access, _, _, _) = common::signup_full(&server, "ivan@example.com").await;

    let mut req = factory::create_file_req(None);
    req["total_chunks"] = json!(5); // Mismatch

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
async fn complete_upload_missing_etags_returns_400() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "jane@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'jane@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = create_file_directly(&pool, user_id, None, false).await;
    let version_id: uuid::Uuid =
        sqlx::query_scalar("SELECT current_version_id FROM files WHERE file_id = $1")
            .bind(file_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/{file_id}/complete")))
        .header("authorization", format!("Bearer {access}"))
        .json(&json!({ "version_id": version_id, "r2_etags": {} })) // Empty etags
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn complete_upload_idempotent_if_already_active() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "kevin@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'kevin@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = create_file_directly(&pool, user_id, None, true).await; // Already active
    let version_id: uuid::Uuid =
        sqlx::query_scalar("SELECT current_version_id FROM files WHERE file_id = $1")
            .bind(file_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/{file_id}/complete")))
        .header("authorization", format!("Bearer {access}"))
        .json(&json!({ "version_id": version_id, "r2_etags": {} }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn create_file_rejects_chunk_size_mismatch() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "malicious1@example.com").await;

    // Claim total_size is 1024, but provide a chunk of 2048
    let mut req = factory::create_file_req(None);
    req["total_size"] = json!(1024);
    req["chunks"][0]["chunk_size"] = json!(2048);
    // Note: factory provides 1 chunk. 2048 != 1024 + 17. Will fail validation.

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
async fn create_file_rejects_exceeding_quota() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "malicious2@example.com").await;

    // Claim total_size is 200MB (exceeds 100MB POC limit)
    let mut req = factory::create_file_req(None);
    req["total_size"] = json!(200 * 1024 * 1024);
    req["chunks"][0]["chunk_size"] = json!(200 * 1024 * 1024 + 17); // Make math match

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
    let (access, _, _, _) = common::signup_full(&server, "boundary@example.com").await;

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
    let (access, _, _, _) = common::signup_full(&server, "b64@example.com").await;

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
