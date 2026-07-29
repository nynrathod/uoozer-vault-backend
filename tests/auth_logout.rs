mod common;
use common::{API, setup_app};
use serde_json::json;

#[tokio::test]
async fn logout_revokes_current_session() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "alice@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/logout")))
        .header("authorization", format!("Bearer {access}"))
        .json(&json!({ "revoke_device": false }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    let resp2 = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp2.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_revoke_device_kills_all_sessions() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, refresh, _, _) = common::signup_full(&server, "bob@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/logout")))
        .header("authorization", format!("Bearer {access}"))
        .json(&json!({ "revoke_device": true }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    let refresh_resp = server
        .client
        .post(server.url(&format!("{API}/auth/refresh")))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();

    assert_eq!(refresh_resp.status(), http::StatusCode::UNAUTHORIZED);

    let devices_resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(devices_resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_without_auth_returns_401() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/logout")))
        .json(&json!({ "revoke_device": false }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}
