mod common;
use common::{API, factory, setup_app};
use serde_json::json;

#[tokio::test]
async fn signup_happy_path() {
    let (server, _pool, _guard) = setup_app().await;

    let init_resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/init")))
        .json(&json!({ "email": "alice@example.com" }))
        .send()
        .await
        .unwrap();

    assert_eq!(init_resp.status(), http::StatusCode::OK);
    let init_body: serde_json::Value = init_resp.json().await.unwrap();
    let signup_token = init_body["signup_token"].as_str().unwrap().to_string();

    let mut payload = factory::signup_complete_req("alice@example.com");
    payload["signup_token"] = json!(signup_token);

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/complete")))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::CREATED);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].is_number());
}

#[tokio::test]
async fn signup_duplicate_email_returns_409() {
    let (server, _pool, _guard) = setup_app().await;
    common::signup_full(&server, "bob@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/init")))
        .json(&json!({ "email": "bob@example.com" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::CONFLICT);
    let body: serde_json::Value = resp.json().await.unwrap();
    common::assertions::assert_error_code(&body, "CONFLICT");
}

#[tokio::test]
async fn signup_invalid_token_returns_400() {
    let (server, _pool, _guard) = setup_app().await;

    let mut payload = factory::signup_complete_req("charlie@example.com");
    payload["signup_token"] = json!("invalid-token-not-in-pending-store");

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/complete")))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn signup_short_pubkey_returns_400() {
    let (server, _pool, _guard) = setup_app().await;

    let init_resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/init")))
        .json(&json!({ "email": "dave@example.com" }))
        .send()
        .await
        .unwrap();
    let token = init_resp.json::<serde_json::Value>().await.unwrap()["signup_token"]
        .as_str()
        .unwrap()
        .to_string();

    let mut payload = factory::signup_short_pubkey("dave@example.com");
    payload["signup_token"] = json!(token);

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/complete")))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();
    common::assertions::assert_error_code(&body, "BAD_REQUEST");
}

#[tokio::test]
async fn signup_bad_nonce_returns_400() {
    let (server, _pool, _guard) = setup_app().await;

    let init_resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/init")))
        .json(&json!({ "email": "eve@example.com" }))
        .send()
        .await
        .unwrap();
    let token = init_resp.json::<serde_json::Value>().await.unwrap()["signup_token"]
        .as_str()
        .unwrap()
        .to_string();

    let mut payload = factory::signup_bad_nonce("eve@example.com");
    payload["signup_token"] = json!(token);

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/complete")))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn signup_invalid_base64_returns_400() {
    let (server, _pool, _guard) = setup_app().await;

    let init_resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/init")))
        .json(&json!({ "email": "frank@example.com" }))
        .send()
        .await
        .unwrap();
    let token = init_resp.json::<serde_json::Value>().await.unwrap()["signup_token"]
        .as_str()
        .unwrap()
        .to_string();

    let mut payload = factory::signup_bad_b64("frank@example.com");
    payload["signup_token"] = json!(token);

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/complete")))
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn signup_missing_field_returns_422() {
    let (server, _pool, _guard) = setup_app().await;

    let payload = json!({
        "email": "grace@example.com",
        "signup_token": "some-token",
        "recovery_auth_key": "abc",
        "wrapped_dek": "abc",
        "wrapped_dek_nonce": "abc",
        "recovery_wrapped_dek": "abc",
        "recovery_wrapped_dek_nonce": "abc",
        "identity_pubkey": "abc",
        "device_pubkey": "abc",
        "device_name": "Test"
        // Missing auth_key
    });

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/complete")))
        .json(&payload)
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 422,
        "Missing field should return 400 or 422, got {}",
        status
    );
}

#[tokio::test]
async fn signup_concurrent_same_email_no_race() {
    let (server, _pool, _guard) = setup_app().await;

    let init1 = server
        .client
        .post(server.url(&format!("{API}/auth/signup/init")))
        .json(&json!({ "email": "hank@example.com" }))
        .send()
        .await
        .unwrap();

    let init2 = server
        .client
        .post(server.url(&format!("{API}/auth/signup/init")))
        .json(&json!({ "email": "hank@example.com" }))
        .send()
        .await
        .unwrap();

    // Both init requests succeed (token generated), but only one can complete
    assert_eq!(init1.status(), 200);
    assert_eq!(init2.status(), 200);

    let token1 = init1.json::<serde_json::Value>().await.unwrap()["signup_token"]
        .as_str()
        .unwrap()
        .to_string();
    let token2 = init2.json::<serde_json::Value>().await.unwrap()["signup_token"]
        .as_str()
        .unwrap()
        .to_string();

    let mut p1 = factory::signup_complete_req("hank@example.com");
    p1["signup_token"] = json!(token1);

    let mut p2 = factory::signup_complete_req("hank@example.com");
    p2["signup_token"] = json!(token2);

    let (r1, r2) = tokio::join!(
        server
            .client
            .post(server.url(&format!("{API}/auth/signup/complete")))
            .json(&p1)
            .send(),
        server
            .client
            .post(server.url(&format!("{API}/auth/signup/complete")))
            .json(&p2)
            .send()
    );

    let r1 = r1.unwrap();
    let r2 = r2.unwrap();

    let statuses = [r1.status().as_u16(), r2.status().as_u16()];
    assert!(statuses.contains(&201), "One signup should succeed");
    assert!(
        statuses.contains(&409) || statuses.contains(&400),
        "The other should fail"
    );
}
