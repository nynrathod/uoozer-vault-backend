mod common;
use common::{API, factory, setup_app};
use serde_json::json;

#[tokio::test]
async fn change_password_succeeds_and_invalidates_old_key() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _refresh, email, old_auth_key) =
        common::signup_full(&server, "alice@example.com").await;

    // Change password
    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/password")))
        .header("authorization", format!("Bearer {access}"))
        .json(&factory::change_password_req())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NO_CONTENT);

    // Try logging in with OLD auth key
    let old_login = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&factory::login_req(&email, &old_auth_key))
        .send()
        .await
        .unwrap();

    assert_eq!(old_login.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_password_unauthorized_fails() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/password")))
        .json(&factory::change_password_req())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_password_bad_nonce_fails() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _refresh, _email, _old_auth_key) =
        common::signup_full(&server, "bob@example.com").await;

    let mut req = factory::change_password_req();
    req["new_wrapped_dek_nonce"] = json!(factory::random_b64(10)); // Invalid nonce length

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/password")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}
