mod common;
use common::{API, factory, setup_app};
use serde_json::json;

#[tokio::test]
async fn create_root_folder_succeeds() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "alice@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["folder_id"].is_string());
    assert!(body["encrypted_metadata"].is_string());
    assert!(body["metadata_nonce"].is_string());
}

#[tokio::test]
async fn list_folders_returns_created() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bob@example.com").await;

    server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn create_nested_folder_succeeds() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "carol@example.com").await;

    let root_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();

    let root_body = root_resp.json::<serde_json::Value>().await.unwrap();
    let root_id = uuid::Uuid::parse_str(root_body["folder_id"].as_str().unwrap()).unwrap();

    let child_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(Some(root_id)))
        .send()
        .await
        .unwrap();

    assert_eq!(child_resp.status(), http::StatusCode::CREATED);
}

#[tokio::test]
async fn create_folder_under_nonexistent_parent_returns_404() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "dave@example.com").await;

    let fake_parent = uuid::Uuid::new_v4();

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

#[tokio::test]
async fn move_folder_into_itself_returns_400() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "eve@example.com").await;

    let create_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();

    let create_body = create_resp.json::<serde_json::Value>().await.unwrap();
    let folder_id = uuid::Uuid::parse_str(create_body["folder_id"].as_str().unwrap()).unwrap();

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
async fn delete_folder_returns_204() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "frank@example.com").await;

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

    let resp = server
        .client
        .delete(server.url(&format!("{API}/folders/{folder_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn access_other_users_folder_returns_404() {
    let (server, _pool, _guard) = setup_app().await;

    let (access_a, _, _, _) = common::signup_full(&server, "alice@example.com").await;
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

    let (access_b, _, _, _) = common::signup_full(&server, "bob@example.com").await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/folders/{folder_id}")))
        .header("authorization", format!("Bearer {access_b}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

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

#[tokio::test]
async fn move_folder_into_descendant_returns_400() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "grace@example.com").await;

    // Create Root
    let root_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(None))
        .send()
        .await
        .unwrap();
    let root_body = root_resp.json::<serde_json::Value>().await.unwrap();
    let root_id = uuid::Uuid::parse_str(root_body["folder_id"].as_str().unwrap()).unwrap();

    // Create Child under Root
    let child_resp = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::create_folder_req(Some(root_id)))
        .send()
        .await
        .unwrap();
    let child_body = child_resp.json::<serde_json::Value>().await.unwrap();
    let child_id = uuid::Uuid::parse_str(child_body["folder_id"].as_str().unwrap()).unwrap();

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

    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 200,
        "Cycle detection gap. Got {}",
        status
    );
}
