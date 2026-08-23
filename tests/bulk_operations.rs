mod common;
use common::{API, factory, setup_app};
use serde_json::json;
use uuid::Uuid;

// ── Bulk file initialization ───────────────────────────

#[tokio::test]
async fn bulk_init_uploads_success() {
    if std::env::var("RUN_E2E_STORAGE_TESTS").is_err() {
        return;
    }

    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bulk_init@example.com").await;

    let req = factory::bulk_create_files_req(3);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/bulk-init")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["results"].as_array().unwrap().len(), 3);
}

// ── Bulk quota exceeded ────────────────────────────────

#[tokio::test]
async fn bulk_init_quota_exceeded() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bulk_quota@example.com").await;

    let file_req = factory::create_file_req_with_size(None, 50 * 1024 * 1024, 1);
    let req = json!({
        "files": [file_req, file_req.clone(), file_req.clone()]
    });

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/bulk-init")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Bulk with some invalid files ───────────────────────

#[tokio::test]
async fn bulk_init_with_invalid_file() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bulk_invalid@example.com").await;

    let valid_file = factory::create_file_req(None);
    let mut invalid_file = factory::create_file_req(None);
    invalid_file["metadata_nonce"] = json!(factory::random_b64(10));

    let req = json!({
        "files": [valid_file, invalid_file]
    });

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/bulk-init")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Bulk delete large batch ────────────────────────────

#[tokio::test]
async fn bulk_delete_large_batch() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bulk_delete@example.com").await;

    let user_id: Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'bulk_delete@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let mut file_ids = Vec::new();
    for _ in 0..150 {
        let file_id = factory::create_file_directly(&pool, user_id, None, true).await;
        file_ids.push(file_id);
    }

    let req = factory::bulk_delete_req(file_ids.clone(), vec![]);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/bulk-delete")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    for file_id in &file_ids {
        let is_deleted: bool =
            sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM files WHERE file_id = $1")
                .bind(file_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(is_deleted);
    }
}

// ── Bulk delete mixed (files + folders) ─────────────────────

#[tokio::test]
async fn bulk_delete_mixed_files_and_folders() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bulk_mixed@example.com").await;

    let user_id: Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'bulk_mixed@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;

    let folder_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();
    let folder_id = Uuid::parse_str(
        folder_resp.json::<serde_json::Value>().await.unwrap()["folder_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let req = factory::bulk_delete_req(vec![file_id], vec![folder_id]);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/bulk-delete")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    let file_deleted: bool =
        sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM files WHERE file_id = $1")
            .bind(file_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(file_deleted);

    let folder_deleted: bool =
        sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM folders WHERE folder_id = $1")
            .bind(folder_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(folder_deleted);
}

// ── Bulk delete empty list ─────────────────────────────────

#[tokio::test]
async fn bulk_delete_empty_list() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bulk_empty@example.com").await;

    let req = factory::bulk_delete_req(vec![], vec![]);

    let resp = server
        .client
        .post(server.url(&format!("{API}/files/bulk-delete")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);
}
