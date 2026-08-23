mod common;
use base64::Engine;
use common::{API, factory, setup_app};
use serde_json::json;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

// ── Cancel during chunk upload ──────────────────────────

#[tokio::test]
async fn cancel_upload_cleans_db() {
    if std::env::var("RUN_E2E_STORAGE_TESTS").is_err() {
        return;
    }

    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "f3_cancel@example.com").await;

    let req = factory::create_file_req(None);
    let create_resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(create_resp.status(), 201);
    let create_body: serde_json::Value = create_resp.json().await.unwrap();
    let file_id = uuid::Uuid::parse_str(create_body["file_id"].as_str().unwrap()).unwrap();
    let version_id = uuid::Uuid::parse_str(create_body["version_id"].as_str().unwrap()).unwrap();

    let cancel_resp = server
        .client
        .post(server.url(&format!(
            "{API}/files/{file_id}/versions/{version_id}/cancel"
        )))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(cancel_resp.status(), http::StatusCode::NO_CONTENT);

    let chunk_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM file_chunks WHERE version_id = $1")
            .bind(version_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(chunk_count, 0);

    let version_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM file_versions WHERE version_id = $1")
            .bind(version_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(version_count, 0);

    let file_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files WHERE file_id = $1")
        .bind(file_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(file_count, 0);

    let get_resp = server
        .client
        .get(server.url(&format!("{API}/files/{file_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), http::StatusCode::NOT_FOUND);
}

// ── Cancel during completion ───────────────────────────

#[tokio::test]
async fn cancel_after_partial_upload() {
    if std::env::var("RUN_E2E_STORAGE_TESTS").is_err() {
        return;
    }

    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "f4_partial@example.com").await;

    let chunk_data_0 = vec![0u8; 1024];
    let chunk_data_1 = vec![1u8; 1024];
    let chunk_data_2 = vec![2u8; 1024];

    let req_body = json!({
        "encrypted_metadata": B64.encode(vec![0u8; 48]),
        "metadata_nonce": B64.encode(vec![0u8; 24]),
        "plaintext_blake3": B64.encode(vec![0u8; 32]),
        "total_size": (1024 * 3) as i64,
        "total_chunks": 3,
        "encryption_header": B64.encode(vec![0u8; 24]),
        "chunks": [
            { "chunk_index": 0, "segment_index": 0, "chunk_size": (chunk_data_0.len() + 17) as i64, "chunk_blake3": B64.encode(blake3::hash(&chunk_data_0).as_bytes()) },
            { "chunk_index": 1, "segment_index": 0, "chunk_size": (chunk_data_1.len() + 17) as i64, "chunk_blake3": B64.encode(blake3::hash(&chunk_data_1).as_bytes()) },
            { "chunk_index": 2, "segment_index": 0, "chunk_size": (chunk_data_2.len() + 17) as i64, "chunk_blake3": B64.encode(blake3::hash(&chunk_data_2).as_bytes()) }
        ]
    });

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let create_resp: serde_json::Value = resp.json().await.unwrap();
    let file_id = create_resp["file_id"].as_str().unwrap();
    let version_id = create_resp["version_id"].as_str().unwrap();
    let url_0 = create_resp["upload_urls"][0]["presigned_url"]
        .as_str()
        .unwrap()
        .to_string();

    let put_resp = reqwest::Client::new()
        .put(&url_0)
        .body(chunk_data_0.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), 200);

    let cancel_resp = server
        .client
        .post(server.url(&format!(
            "{API}/files/{file_id}/versions/{version_id}/cancel"
        )))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(cancel_resp.status(), http::StatusCode::NO_CONTENT);

    let chunk_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM file_chunks WHERE version_id = $1")
            .bind(version_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(chunk_count, 0);
}

// ── Cancel after all chunks uploaded ────────────────────

#[tokio::test]
async fn cancel_after_all_chunks_uploaded() {
    if std::env::var("RUN_E2E_STORAGE_TESTS").is_err() {
        return;
    }

    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "f5_all_uploaded@example.com").await;

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

    let cancel_resp = server
        .client
        .post(server.url(&format!(
            "{API}/files/{file_id}/versions/{version_id}/cancel"
        )))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(cancel_resp.status(), http::StatusCode::NO_CONTENT);

    let file_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM files WHERE file_id = $1")
        .bind(file_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(file_count, 0);
}

// ── Cancel then re-upload ──────────────────────────────

#[tokio::test]
async fn cancel_then_reupload_same_file() {
    if std::env::var("RUN_E2E_STORAGE_TESTS").is_err() {
        return;
    }

    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "f10_reupload@example.com").await;

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

    let cancel_resp = server
        .client
        .post(server.url(&format!(
            "{API}/files/{file_id}/versions/{version_id}/cancel"
        )))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(cancel_resp.status(), http::StatusCode::NO_CONTENT);

    let req2 = factory::create_file_req(None);
    let create_resp2 = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req2)
        .send()
        .await
        .unwrap();

    assert_eq!(create_resp2.status(), http::StatusCode::CREATED);

    let create_body2: serde_json::Value = create_resp2.json().await.unwrap();
    let new_file_id = create_body2["file_id"].as_str().unwrap();

    assert_ne!(file_id, new_file_id);
}

// ── Bulk cancel ─────────────────────────────────────────

#[tokio::test]
async fn bulk_cancel_uploads() {
    if std::env::var("RUN_E2E_STORAGE_TESTS").is_err() {
        return;
    }

    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "f7_bulk_cancel@example.com").await;

    let mut uploads = Vec::new();
    for _ in 0..3 {
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
        let file_id = uuid::Uuid::parse_str(create_body["file_id"].as_str().unwrap()).unwrap();
        let version_id =
            uuid::Uuid::parse_str(create_body["version_id"].as_str().unwrap()).unwrap();
        uploads.push((file_id, version_id));
    }

    let cancel_req = factory::bulk_cancel_req(uploads.clone());
    let cancel_resp = server
        .client
        .post(server.url(&format!("{API}/files/bulk-cancel")))
        .header("authorization", format!("Bearer {access}"))
        .json(&cancel_req)
        .send()
        .await
        .unwrap();

    assert_eq!(cancel_resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = cancel_resp.json().await.unwrap();
    assert_eq!(body["cancelled"], 3);
}
