mod common;
use common::{API, setup_app};
use serde_json::json;

#[tokio::test]
async fn list_devices_returns_current_device() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "alice@example.com").await;

    let resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["device_name"], "Test Device");
    assert_eq!(body[0]["is_current"], true);
}

#[tokio::test]
async fn list_sessions_returns_current_session() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bob@example.com").await;

    let resp = server
        .client
        .get(server.url(&format!("{API}/devices/sessions")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.is_array());
    assert!(!body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn cannot_revoke_current_device() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "carol@example.com").await;

    let devices_resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    let devices: serde_json::Value = devices_resp.json().await.unwrap();
    let device_id = devices[0]["device_id"].as_str().unwrap().to_string();

    let resp = server
        .client
        .post(server.url(&format!("{API}/devices/{device_id}/revoke")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    common::assertions::assert_error_code(&body, "BAD_REQUEST");
}

#[tokio::test]
async fn revoke_unknown_device_returns_404() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "dave@example.com").await;

    let fake_id = uuid::Uuid::new_v4().to_string();

    let resp = server
        .client
        .post(server.url(&format!("{API}/devices/{fake_id}/revoke")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_device_name_succeeds() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "eve@example.com").await;

    let devices_resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    let devices: serde_json::Value = devices_resp.json().await.unwrap();
    let device_id = devices[0]["device_id"].as_str().unwrap().to_string();

    let resp = server
        .client
        .patch(server.url(&format!("{API}/devices/{device_id}")))
        .header("authorization", format!("Bearer {access}"))
        .json(&json!({ "device_name": "My Updated Device" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn devices_require_authentication() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}
