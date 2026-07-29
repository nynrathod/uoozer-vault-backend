mod common;
use common::{API, assertions, setup_app};
use serde_json::json;

#[tokio::test]
async fn validation_error_format() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/prelogin")))
        .json(&json!({ "email": "not-an-email" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.unwrap();

    assertions::assert_error_envelope(&body);
    assertions::assert_error_code(&body, "VALIDATION_ERROR");

    insta::assert_json_snapshot!("validation_error", body, {
        ".error.message" => "[message]"
    });
}

#[tokio::test]
async fn unauthorized_error_format() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.unwrap();

    assertions::assert_error_envelope(&body);
    assertions::assert_error_code(&body, "UNAUTHORIZED");

    insta::assert_json_snapshot!("unauthorized_error", body, {
        ".error.message" => "[message]"
    });
}

#[tokio::test]
async fn conflict_error_format() {
    let (server, _pool, _guard) = setup_app().await;
    common::signup_full(&server, "alice@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/init")))
        .json(&json!({ "email": "alice@example.com" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::CONFLICT);
    let body: serde_json::Value = resp.json().await.unwrap();

    assertions::assert_error_envelope(&body);
    assertions::assert_error_code(&body, "CONFLICT");

    insta::assert_json_snapshot!("conflict_error", body, {
        ".error.message" => "[message]"
    });
}

#[tokio::test]
async fn not_found_error_format() {
    let (server, _pool, _guard) = setup_app().await;

    let (access, _, _, _) = common::signup_full(&server, "alice@example.com").await;
    let fake_id = uuid::Uuid::new_v4();

    let resp = server
        .client
        .get(server.url(&format!("{API}/folders/{fake_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json().await.unwrap();

    assertions::assert_error_envelope(&body);
    assertions::assert_error_code(&body, "NOT_FOUND");
}
