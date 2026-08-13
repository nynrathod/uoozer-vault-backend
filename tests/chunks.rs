mod common;
use common::{API, setup_app};
use serde_json::json;
use sqlx::Row;

async fn setup_version(
    pool: &sqlx::PgPool,
    user_id: uuid::Uuid,
    is_active: bool,
) -> (uuid::Uuid, uuid::Uuid) {
    let file_id = uuid::Uuid::new_v4();
    let version_id = uuid::Uuid::new_v4();
    let device_id: uuid::Uuid =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap();

    // 1. Insert file with NULL current_version_id
    sqlx::query(
        "INSERT INTO files (file_id, user_id, encrypted_metadata, metadata_nonce, plaintext_blake3, total_size, current_version_id)
         VALUES ($1, $2, $3, $4, $5, 4096, NULL)",
    )
    .bind(file_id).bind(user_id).bind(vec![0u8; 48]).bind(vec![0u8; 24]).bind(vec![0u8; 32])
    .execute(pool).await.unwrap();

    // 2. Insert the version
    sqlx::query(
        "INSERT INTO file_versions (version_id, file_id, version_number, encryption_header, total_size, total_chunks, plaintext_blake3, created_by_device_id, is_active)
         VALUES ($1, $2, 1, $3, 4096, 3, $4, $5, $6)",
    )
    .bind(version_id).bind(file_id).bind(vec![0u8; 24]).bind(vec![0u8; 32]).bind(device_id).bind(is_active)
    .execute(pool).await.unwrap();

    // 3. Link them
    sqlx::query("UPDATE files SET current_version_id = $1 WHERE file_id = $2")
        .bind(version_id)
        .bind(file_id)
        .execute(pool)
        .await
        .unwrap();

    // Insert 3 chunks, only chunk 0 is uploaded
    for i in 0..3 {
        let r2_key = format!("{}/{}/{}/{}/{}", user_id, file_id, version_id, 0, i);
        sqlx::query(
            "INSERT INTO file_chunks (version_id, chunk_index, segment_index, chunk_size, chunk_blake3, r2_key, uploaded_at, r2_etag)
             VALUES ($1, $2, 0, 1024, $3, $4, CASE WHEN $2 = 0 THEN now() ELSE NULL END, CASE WHEN $2 = 0 THEN 'etag0' ELSE NULL END)",
        )
        .bind(version_id).bind(i).bind(vec![i as u8; 32]).bind(&r2_key)
        .execute(pool).await.unwrap();
    }

    (file_id, version_id)
}

#[tokio::test]
async fn get_resume_info_returns_correct_chunks() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "alice@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'alice@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let (_, version_id) = setup_version(&pool, user_id, false).await;

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

    // If R2 is configured, it should return 2 URLs. If not, it should be null.
    // This makes the test pass in both standard `cargo test` and E2E environments.
    if body["upload_urls"].is_null() {
        // R2 not configured, this is correct
    } else {
        // R2 is configured, verify it generated URLs for the 2 missing chunks
        assert_eq!(body["upload_urls"].as_array().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn get_resume_info_nonexistent_version_returns_404() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bob@example.com").await;

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

#[tokio::test]
async fn resume_info_idor_protected() {
    let (server, pool, _guard) = setup_app().await;

    let (_, _, _, _) = common::signup_full(&server, "alice@example.com").await;
    let user_a: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'alice@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let (_, version_id) = setup_version(&pool, user_a, false).await;

    let (access_b, _, _, _) = common::signup_full(&server, "bob@example.com").await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/chunks/{version_id}/resume")))
        .header("authorization", format!("Bearer {access_b}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

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
