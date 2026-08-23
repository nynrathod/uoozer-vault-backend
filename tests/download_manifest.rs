mod common;
use common::{API, factory, setup_app};

// ── Missing chunks ──────────────────────────────────────

#[tokio::test]
async fn download_missing_chunks_returns_error() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "h3_missing@example.com").await;

    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'h3_missing@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;

    let resp = server
        .client
        .get(server.url(&format!("{API}/files/{file_id}/download")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    // Should return 503 or 404 because storage is not configured in test
    // or because chunks are missing
    assert!(
        resp.status() == http::StatusCode::SERVICE_UNAVAILABLE
            || resp.status() == http::StatusCode::NOT_FOUND
    );
}

// ── Download specific version ──────────────────────────

#[tokio::test]
async fn download_specific_version() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "h11_version@example.com").await;

    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'h11_version@example.com'")
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

    // Try to download with specific version_id
    let resp = server
        .client
        .get(server.url(&format!(
            "{API}/files/{file_id}/download?version_id={version_id}"
        )))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    // Should return 503 if storage not configured, or 200 if it is
    assert!(
        resp.status() == http::StatusCode::SERVICE_UNAVAILABLE
            || resp.status() == http::StatusCode::OK
    );
}

// ── Download non-existent file ──────────────────────────────

#[tokio::test]
async fn download_nonexistent_file_returns_404() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "h_404@example.com").await;

    let fake_id = uuid::Uuid::new_v4();

    let resp = server
        .client
        .get(server.url(&format!("{API}/files/{fake_id}/download")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

// ── Download IDOR protection ───────────────────────────────

#[tokio::test]
async fn download_idor_protected() {
    let (server, pool, _guard) = setup_app().await;

    let (access_a, _, _, _) = common::signup_full(&server, "h_idor_a@example.com").await;
    let user_a: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'h_idor_a@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = factory::create_file_directly(&pool, user_a, None, true).await;

    let (access_b, _, _, _) = common::signup_full(&server, "h_idor_b@example.com").await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/files/{file_id}/download")))
        .header("authorization", format!("Bearer {access_b}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

// ── Download requires auth ──────────────────────────────────

#[tokio::test]
async fn download_requires_auth() {
    let (server, _pool, _guard) = setup_app().await;

    let fake_id = uuid::Uuid::new_v4();

    let resp = server
        .client
        .get(server.url(&format!("{API}/files/{fake_id}/download")))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

// ── Download deleted file ──────────────────────────────────

#[tokio::test]
async fn download_deleted_file_returns_404() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "h_deleted@example.com").await;

    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'h_deleted@example.com'")
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
        .get(server.url(&format!("{API}/files/{file_id}/download")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}
