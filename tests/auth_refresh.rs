mod common;
use common::{API, setup_app};
use serde_json::json;

#[tokio::test]
async fn refresh_happy_path_rotates_token() {
    let (server, _pool, _guard) = setup_app().await;
    let (_, refresh_token, _, _) = common::signup_full(&server, "alice@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/refresh")))
        .json(&json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());

    let new_refresh = body["refresh_token"].as_str().unwrap();
    assert_ne!(new_refresh, refresh_token);
}

#[tokio::test]
async fn refresh_replay_old_token_revokes_entire_chain() {
    let (server, pool, _guard) = setup_app().await;
    let (_, refresh_token_1, _, _) = common::signup_full(&server, "bob@example.com").await;

    let resp1 = server
        .client
        .post(server.url(&format!("{API}/auth/refresh")))
        .json(&json!({ "refresh_token": refresh_token_1 }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp1.status(), http::StatusCode::OK);
    let refresh_token_2: String = resp1.json::<serde_json::Value>().await.unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp2 = server
        .client
        .post(server.url(&format!("{API}/auth/refresh")))
        .json(&json!({ "refresh_token": refresh_token_1 }))
        .send()
        .await
        .unwrap();

    assert!(
        resp2.status() == 401,
        "Replayed old refresh token must be rejected"
    );

    let resp3 = server
        .client
        .post(server.url(&format!("{API}/auth/refresh")))
        .json(&json!({ "refresh_token": refresh_token_2 }))
        .send()
        .await
        .unwrap();

    assert!(
        resp3.status() == 401,
        "Entire refresh chain must be revoked on reuse"
    );

    let reuse_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'refresh_token_reuse'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(reuse_count > 0);
}

#[tokio::test]
async fn refresh_tampered_jwt_returns_401() {
    let (server, _pool, _guard) = setup_app().await;
    let (_, refresh_token, _, _) = common::signup_full(&server, "carol@example.com").await;

    let mut tampered = refresh_token;
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/refresh")))
        .json(&json!({ "refresh_token": tampered }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_garbage_string_returns_401() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/refresh")))
        .json(&json!({ "refresh_token": "not.a.real.jwt" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}
