mod common;
use common::{API, setup_app};
use serde_json::json;

#[tokio::test]
async fn device_revocation_creates_audit_entry() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, email, auth_key) = common::signup_full(&server, "dev1@example.com").await;

    let _login_resp = server.client
        .post(server.url(&format!("{API}/auth/login")))
        .json(&json!({
            "email": email,
            "auth_key": auth_key,
            "device_pubkey": common::factory::random_b64(32),
            "device_name": "Second Device"
        }))
        .send().await.unwrap();

    let devices: serde_json::Value = server.client
        .get(server.url(&format!("{API}/devices")))
        .header("authorization", format!("Bearer {access}"))
        .send().await.unwrap().json().await.unwrap();

    let second_device_id = devices.as_array().unwrap().iter()
        .find(|d| d["device_name"] == "Second Device")
        .map(|d| d["device_id"].as_str().unwrap().to_string())
        .expect("Second device should exist");

    let _ = server.client
        .post(server.url(&format!("{API}/devices/{second_device_id}/revoke")))
        .header("authorization", format!("Bearer {access}"))
        .send().await.unwrap();

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'device_revoked'"
    ).fetch_one(&pool).await.unwrap();
    assert!(count >= 1);
}