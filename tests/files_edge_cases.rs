mod common;
use common::{API, factory, setup_app};
use serde_json::json;

#[tokio::test]
async fn create_file_with_zero_chunks_returns_400() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "zero@example.com").await;

    let mut req = factory::create_file_req(None);
    req["total_chunks"] = json!(0);
    req["chunks"] = json!([]);

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
async fn restore_already_active_version_is_idempotent() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "restore@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'restore@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;
    let active_version: uuid::Uuid =
        sqlx::query_scalar("SELECT current_version_id FROM files WHERE file_id = $1")
            .bind(file_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let resp = server
        .client
        .post(server.url(&format!(
            "{API}/files/{file_id}/versions/{active_version}/restore"
        )))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_active_version_returns_400() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "delver@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'delver@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;
    let active_version: uuid::Uuid =
        sqlx::query_scalar("SELECT current_version_id FROM files WHERE file_id = $1")
            .bind(file_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let resp = server
        .client
        .delete(server.url(&format!("{API}/files/{file_id}/versions/{active_version}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn empty_trash_returns_count() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "trash@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'trash@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let f1 = factory::create_file_directly(&pool, user_id, None, true).await;
    let f2 = factory::create_file_directly(&pool, user_id, None, true).await;
    let _f3 = factory::create_file_directly(&pool, user_id, None, true).await;
    for f in [f1, f2] {
        sqlx::query("UPDATE files SET deleted_at = now() WHERE file_id = $1")
            .bind(f)
            .execute(&pool)
            .await
            .unwrap();
    }

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/empty-trash")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], 2);
}

#[tokio::test]
async fn list_files_rejects_excessive_limit() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "limit@example.com").await;

    let resp = server
        .client
        .get(server.url(&format!("{API}/files?limit=10000")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["files"].as_array().unwrap().len() <= 1000);
}

#[tokio::test]
async fn download_with_nonexistent_version_returns_404() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "dl404@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'dl404@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;
    let fake_version = uuid::Uuid::new_v4();

    let resp = server
        .client
        .get(server.url(&format!(
            "{API}/files/{file_id}/download?version_id={fake_version}"
        )))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}
