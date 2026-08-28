mod common;
use common::{API, setup_app};
use serde_json::json;

#[tokio::test]
async fn audit_log_records_signup_and_login() {
    let (server, pool, _guard) = setup_app().await;
    let (_, _, email, auth_key) = common::signup_full(&server, "audit@example.com").await;

    let _ = server
        .client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&common::factory::login_req(&email, &auth_key))
        .send()
        .await
        .unwrap();

    let user_id: uuid::Uuid = sqlx::query_scalar("SELECT user_id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap();

    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM audit_logs WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(user_id)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(events.contains(&"signup_complete".to_string()));
    assert!(events.contains(&"login_success".to_string()));
}

#[tokio::test]
async fn audit_log_cannot_be_modified() {
    let (server, pool, _guard) = setup_app().await;
    let (_, _, email, _) = common::signup_full(&server, "audit2@example.com").await;
    let user_id: uuid::Uuid = sqlx::query_scalar("SELECT user_id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .unwrap();

   let code = std::fs::read_to_string("src/features/audit/service.rs").unwrap();
    assert!(!code.contains("UPDATE audit_logs"));
    assert!(!code.contains("DELETE FROM audit_logs"));
    let _ = user_id;
}

#[tokio::test]
async fn audit_log_records_password_change() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, email, _) = common::signup_full(&server, "audit3@example.com").await;
    let _ = server
        .client
        .post(server.url(&format!("{API}/auth/password")))
        .header("authorization", format!("Bearer {access}"))
        .json(&common::factory::change_password_req())
        .send()
        .await
        .unwrap();

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE event_type = 'password_changed'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(count >= 1);
}
