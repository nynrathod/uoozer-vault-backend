mod common;
use common::{API, setup_app};

#[tokio::test]
async fn missing_auth_header_returns_401() {
    let (server, _pool, _guard) = setup_app().await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_auth_header_returns_401() {
    let (server, _pool, _guard) = setup_app().await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", "NotBearer some-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn garbage_jwt_returns_401() {
    let (server, _pool, _guard) = setup_app().await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", "Bearer garbage.not.a.jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn tampered_jwt_returns_401() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "alice@example.com").await;

    let mut tampered = access;
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });

    let resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {tampered}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoked_session_token_returns_401() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "bob@example.com").await;

    server
        .client
        .post(server.url(&format!("{API}/auth/logout")))
        .header("authorization", format!("Bearer {access}"))
        .json(&serde_json::json!({ "revoke_device": false }))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_alg_none_returns_401() {
    let (server, _pool, _guard) = setup_app().await;
    let fake_jwt =
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.";
    let resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {fake_jwt}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}
