mod common;
use common::{API, factory, setup_app};
use serde_json::json;
use uuid::Uuid;

// ── Empty folder upload ────────────────────────────────

#[tokio::test]
async fn create_empty_folder_succeeds() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "b1_empty@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::CREATED);
}

// ── Bulk folder creation ────────────────────────────────

#[tokio::test]
async fn bulk_create_folders_success() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "b3_bulk@example.com").await;

    let folders: Vec<serde_json::Value> =
        (0..5).map(|_| factory::create_folder_req(None)).collect();

    let resp = server
        .client
        .post(server.url(&format!("{API}/folders/bulk")))
        .header("authorization", format!("Bearer {access}"))
        .json(&json!({ "folders": folders }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body.as_array().unwrap().len(), 5);
}

// ── Nested folder creation ──────────────────────────────

#[tokio::test]
async fn create_nested_folder_10_levels() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "b4_nested@example.com").await;

    let mut parent_id: Option<Uuid> = None;

    for _ in 0..10 {
        let resp = server
            .client
            .post(server.url(&format!("{API}/folders")))
            .header("authorization", format!("Bearer {access}"))
            .json(&factory::create_folder_req(parent_id))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), http::StatusCode::CREATED);
        let body: serde_json::Value = resp.json().await.unwrap();
        parent_id = Some(Uuid::parse_str(body["folder_id"].as_str().unwrap()).unwrap());
    }
}

// ── Duplicate folder name ──────────────────────────────

#[tokio::test]
async fn duplicate_folder_name_allowed() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "b6_dup_name@example.com").await;

    // Backend doesn't check for duplicate names (metadata is encrypted).
    // Two folders with the same encrypted metadata will create two separate folders.
    let req = factory::create_folder_req(None);

    let resp1 = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    let resp2 = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp1.status(), http::StatusCode::CREATED);
    assert_eq!(resp2.status(), http::StatusCode::CREATED);
}

// ── Same filename in different subfolders ───────────────

#[tokio::test]
async fn same_filename_in_different_subfolders() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "b7_same_name@example.com").await;

    let folder1_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();
    let folder1_id = Uuid::parse_str(
        folder1_resp.json::<serde_json::Value>().await.unwrap()["folder_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let folder2_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();
    let folder2_id = Uuid::parse_str(
        folder2_resp.json::<serde_json::Value>().await.unwrap()["folder_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let req = factory::create_file_req(None);

    let resp1 = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&{
            let mut r = req.clone();
            r["folder_id"] = json!(folder1_id);
            r
        })
        .send()
        .await
        .unwrap();

    let resp2 = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&{
            let mut r = req.clone();
            r["folder_id"] = json!(folder2_id);
            r
        })
        .send()
        .await
        .unwrap();

    assert_ne!(resp1.status(), http::StatusCode::BAD_REQUEST);
    assert_ne!(resp2.status(), http::StatusCode::BAD_REQUEST);
}

// ── Folder move edge cases ──────────────────────────────────

#[tokio::test]
async fn move_folder_into_itself_returns_400() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "b_move_self@example.com").await;

    let create_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();

    let create_body = create_resp.json::<serde_json::Value>().await.unwrap();
    let folder_id = Uuid::parse_str(create_body["folder_id"].as_str().unwrap()).unwrap();

    let mut payload = factory::update_folder_req();
    payload["parent_folder_id"] = json!(folder_id);

    let resp = server
        .client
        .patch(server.url(&format!("{API}/folders/{folder_id}")))
        .header("authorization", format!("Bearer {access}"))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn move_folder_into_descendant_returns_400() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "b_move_desc@example.com").await;

    let root_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();
    let root_id = Uuid::parse_str(
        root_resp.json::<serde_json::Value>().await.unwrap()["folder_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let child_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(Some(root_id)))
        .send()
        .await
        .unwrap();
    let child_id = Uuid::parse_str(
        child_resp.json::<serde_json::Value>().await.unwrap()["folder_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    let mut payload = factory::update_folder_req();
    payload["parent_folder_id"] = json!(child_id);

    let resp = server
        .client
        .patch(server.url(&format!("{API}/folders/{root_id}")))
        .header("authorization", format!("Bearer {access}"))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Folder under non-existent parent ───────────────────────

#[tokio::test]
async fn create_folder_under_nonexistent_parent_returns_404() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "b_bad_parent@example.com").await;

    let fake_parent = Uuid::new_v4();

    let resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(Some(fake_parent)))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

// ── IDOR protection for folders ────────────────────────────

#[tokio::test]
async fn access_other_users_folder_returns_404() {
    let (server, _pool, _guard) = setup_app().await;

    let (access_a, _, _, _) = common::signup_full(&server, "b_idor_a@example.com").await;
    let create_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access_a}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();

    let create_body = create_resp.json::<serde_json::Value>().await.unwrap();
    let folder_id = create_body["folder_id"].as_str().unwrap();

    let (access_b, _, _, _) = common::signup_full(&server, "b_idor_b@example.com").await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/folders/{folder_id}")))
        .header("authorization", format!("Bearer {access_b}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

// ── Folder rename ───────────────────────────────────────────

#[tokio::test]
async fn rename_folder_updates_metadata() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "b_rename@example.com").await;

    let create_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();
    let create_body = create_resp.json::<serde_json::Value>().await.unwrap();
    let folder_id = create_body["folder_id"].as_str().unwrap();

    let update_payload = factory::update_folder_req();

    let resp = server
        .client
        .patch(server.url(&format!("{API}/folders/{folder_id}")))
        .header("authorization", format!("Bearer {access}"))
        .json(&update_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(
        body["encrypted_metadata"],
        update_payload["encrypted_metadata"]
    );
    assert_eq!(body["metadata_nonce"], update_payload["metadata_nonce"]);
}

// ── Authentication required ─────────────────────────────────

#[tokio::test]
async fn folders_require_authentication() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}
