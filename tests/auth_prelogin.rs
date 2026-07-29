mod common;
use common::{API, setup_app};
use serde_json::json;

#[tokio::test]
async fn prelogin_unknown_email_returns_fake_salt() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/prelogin")))
        .json(&json!({ "email": "nobody@example.com" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["salt"].is_string());
    assert!(body["argon2_params"].is_object());
}

#[tokio::test]
async fn prelogin_same_unknown_email_twice_returns_identical_salt() {
    let (server, _pool, _guard) = setup_app().await;

    let email = "nobody@example.com";

    let resp1 = server
        .client
        .post(server.url(&format!("{API}/auth/prelogin")))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap();
    let salt1: String = resp1.json::<serde_json::Value>().await.unwrap()["salt"]
        .as_str()
        .unwrap()
        .to_string();

    let resp2 = server
        .client
        .post(server.url(&format!("{API}/auth/prelogin")))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap();
    let salt2: String = resp2.json::<serde_json::Value>().await.unwrap()["salt"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(salt1, salt2);
}

#[tokio::test]
async fn prelogin_known_email_returns_real_salt() {
    let (server, _pool, _guard) = setup_app().await;
    common::signup_full(&server, "alice@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/prelogin")))
        .json(&json!({ "email": "alice@example.com" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["salt"].is_string());
}

#[tokio::test]
async fn prelogin_malformed_email_returns_400() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/prelogin")))
        .json(&json!({ "email": "not-an-email" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn prelogin_case_insensitive() {
    let (server, _pool, _guard) = setup_app().await;
    common::signup_full(&server, "alice@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/prelogin")))
        .json(&json!({ "email": "ALICE@EXAMPLE.COM" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
}
