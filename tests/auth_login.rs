mod common;
use base64::Engine;
use common::{API, factory, setup_app};
use serde_json::json;

#[tokio::test]
async fn login_with_password_auth_key_succeeds() {
    let (server, _pool, _guard) = setup_app().await;
    let (_access, _refresh, email, auth_key) =
        common::signup_full(&server, "alice@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&factory::login_req(&email, &auth_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
}

#[tokio::test]
async fn login_with_recovery_auth_key_succeeds() {
    let (server, _pool, _guard) = setup_app().await;
    let (_access, _refresh, email, _auth_key) =
        common::signup_full(&server, "bob@example.com").await;

    let fake_recovery_key = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&factory::login_req(&email, &fake_recovery_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_unknown_email_returns_401() {
    let (server, _pool, _guard) = setup_app().await;
    let auth_key = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&factory::login_req("nobody@example.com", &auth_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_wrong_auth_key_returns_401() {
    let (server, _pool, _guard) = setup_app().await;
    let (_access, _refresh, email, _auth_key) =
        common::signup_full(&server, "charlie@example.com").await;

    let wrong_key = base64::engine::general_purpose::STANDARD.encode([99u8; 32]);

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&factory::login_req(&email, &wrong_key))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_invalid_base64_returns_400() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&json!({
            "email": "alice@example.com",
            "auth_key": "!!!not_valid_base64!!!",
            "device_name": "Test Device",
            "device_pubkey": base64::engine::general_purpose::STANDARD.encode([5u8; 32])
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn login_creates_audit_log_entry() {
    let (server, pool, _guard) = setup_app().await;
    let (_access, _refresh, email, auth_key) =
        common::signup_full(&server, "dave@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&factory::login_req(&email, &auth_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);

    let user_id: uuid::Uuid = sqlx::query_scalar("SELECT user_id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap();

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert!(count >= 2, "Login must create an audit_log entry");
}

#[tokio::test]
async fn login_existing_device_with_matching_pubkey_updates_last_seen() {
    let (server, _pool, _guard) = setup_app().await;
    let (_access, _refresh, email, auth_key) =
        common::signup_full(&server, "eve@example.com").await;

    // First login (during signup flow, a device is created)
    let login1 = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&factory::login_req(&email, &auth_key))
        .send()
        .await
        .unwrap();

    let body1 = login1.json::<serde_json::Value>().await.unwrap();
    let access1 = body1["access_token"].as_str().unwrap();

    // Get device ID
    let devices_resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {access1}"))
        .send()
        .await
        .unwrap();
    let devices = devices_resp.json::<serde_json::Value>().await.unwrap();
    let device_id = uuid::Uuid::parse_str(devices[0]["device_id"].as_str().unwrap()).unwrap();
    let device_pubkey = devices[0]["device_pubkey"].as_str().unwrap().to_string();

    // Second login with same device_id and pubkey
    let login2 = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&factory::login_req_with_device(
            &email,
            &auth_key,
            device_id,
            &device_pubkey,
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(login2.status(), 200);
}
