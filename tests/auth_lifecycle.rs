mod common;
use common::{API, setup_app};
use sqlx::Row;

#[tokio::test]
async fn disabled_user_cannot_login() {
    let (server, pool, _guard) = setup_app().await;
    let (_, _, email, auth_key) = common::signup_full(&server, "banned@example.com").await;

    // Disable user in DB directly (simulating admin action)
    sqlx::query("UPDATE users SET disabled_at = now() WHERE email = $1")
        .bind(&email)
        .execute(&pool)
        .await
        .unwrap();

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&common::factory::login_req(&email, &auth_key))
        .send()
        .await
        .unwrap();

    // Must be 401 or 403. 401 is better for anti-enumeration, but 403 is acceptable.
    assert!(resp.status() == 401 || resp.status() == 403);
}

#[tokio::test]
async fn disabled_user_token_invalidated() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, email, _) = common::signup_full(&server, "banned2@example.com").await;

    // Ban the user
    sqlx::query("UPDATE users SET disabled_at = now() WHERE email = $1")
        .bind(&email)
        .execute(&pool)
        .await
        .unwrap();

    // Try to use the existing access token
    let resp = server
        .client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}