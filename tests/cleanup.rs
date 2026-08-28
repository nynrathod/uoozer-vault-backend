mod common;
use common::setup_app;

#[tokio::test]
async fn cleanup_deletes_orphaned_versions_only() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "cleanup@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'cleanup@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let active_file = common::factory::create_file_directly(&pool, user_id, None, true).await;

    let orphan_version = uuid::Uuid::new_v4();
    let orphan_file = uuid::Uuid::new_v4();
    let device_id: uuid::Uuid =
        sqlx::query_scalar("SELECT device_id FROM devices WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    sqlx::query("INSERT INTO files (file_id, user_id, encrypted_metadata, metadata_nonce, plaintext_blake3, total_size, current_version_id) VALUES ($1, $2, $3, $4, $5, 1024, NULL)")
        .bind(orphan_file).bind(user_id).bind(vec![0u8; 48]).bind(vec![0u8; 24]).bind(vec![0u8; 32])
        .execute(&pool).await.unwrap();

    sqlx::query("INSERT INTO file_versions (version_id, file_id, version_number, encryption_header, total_size, total_chunks, plaintext_blake3, created_by_device_id, is_active) VALUES ($1, $2, 1, $3, 1024, 1, $4, $5, false)")
        .bind(orphan_version).bind(orphan_file).bind(vec![0u8; 24]).bind(vec![0u8; 32]).bind(device_id)
        .execute(&pool).await.unwrap();

    sqlx::query(
        "UPDATE file_versions SET created_at = now() - interval '2 days' WHERE version_id = $1",
    )
    .bind(orphan_version)
    .execute(&pool)
    .await
    .unwrap();

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/cleanup-orphans")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);

    let active_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files WHERE file_id = $1")
        .bind(active_file)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(active_count, 1);

    let orphan_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM file_versions WHERE version_id = $1")
            .bind(orphan_version)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(orphan_count, 0);
}

use common::API;
