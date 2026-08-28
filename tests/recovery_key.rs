mod common;
use base64::Engine;
use common::{API, setup_app};
use serde_json::json;

#[tokio::test]
async fn recovery_auth_key_login_succeeds() {
    let (server, _pool, _guard) = setup_app().await;
    let (_, _, email, auth_key) = common::signup_full(&server, "rec@example.com").await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&common::factory::login_req(&email, &auth_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let wrong = base64::engine::general_purpose::STANDARD.encode([99u8; 32]);
    let resp2 = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&common::factory::login_req(&email, &wrong))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 401);
}


#[tokio::test]
async fn password_change_preserves_recovery_key_access() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, email, _) = common::signup_full(&server, "rec2@example.com").await;

    let _ = server
        .client
        .post(server.url(&format!("{API}/auth/password")))
        .header("authorization", format!("Bearer {access}"))
        .json(&common::factory::change_password_req())
        .send()
        .await
        .unwrap();

    let original_hash: String =
        sqlx::query_scalar("SELECT recovery_auth_key_hash FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .unwrap();

    let hash_before: String =
        sqlx::query_scalar("SELECT recovery_auth_key_hash FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .unwrap();

    let _ = server
        .client
        .post(server.url(&format!("{API}/auth/password")))
        .header("authorization", format!("Bearer {access}"))
        .json(&common::factory::change_password_req())
        .send()
        .await
        .unwrap();

    let hash_after: String =
        sqlx::query_scalar("SELECT recovery_auth_key_hash FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(hash_before, hash_after);
    assert!(!hash_after.is_empty());
}
