mod common;
use common::{API, factory, setup_app};

// ── Delete already-deleted file ────────────────────────

#[tokio::test]
async fn delete_already_deleted_file_returns_success() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "i10_idempotent@example.com").await;

    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'i10_idempotent@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;

    let resp1 = server
        .client
        .delete(server.url(&format!("{API}/files/{file_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), http::StatusCode::NO_CONTENT);

    let resp2 = server
        .client
        .delete(server.url(&format!("{API}/files/{file_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp2.status(), http::StatusCode::NO_CONTENT);

    let is_deleted: bool =
        sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM files WHERE file_id = $1")
            .bind(file_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(is_deleted);
}

// ── Delete non-existent file ────────────────────────────────

#[tokio::test]
async fn delete_nonexistent_file_returns_404() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "i_nonexist@example.com").await;

    let fake_id = uuid::Uuid::new_v4();

    let resp = server
        .client
        .delete(server.url(&format!("{API}/files/{fake_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

// ── Restore from trash ──────────────────────────────────────

#[tokio::test]
async fn restore_file_from_trash() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "i_restore@example.com").await;

    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'i_restore@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;

    let _ = server
        .client
        .delete(server.url(&format!("{API}/files/{file_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/{file_id}/restore")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    let is_deleted: bool =
        sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM files WHERE file_id = $1")
            .bind(file_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!is_deleted);
}

// ── Permanent delete ───────────────────────────────────────

#[tokio::test]
async fn permanent_delete_file() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "i_perm@example.com").await;

    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'i_perm@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;

    let resp = server
        .client
        .delete(server.url(&format!("{API}/files/{file_id}/permanent")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files WHERE file_id = $1")
        .bind(file_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

// ── Delete requires auth ────────────────────────────────────

#[tokio::test]
async fn delete_requires_auth() {
    let (server, _pool, _guard) = setup_app().await;

    let fake_id = uuid::Uuid::new_v4();

    let resp = server
        .client
        .delete(server.url(&format!("{API}/files/{fake_id}")))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}
