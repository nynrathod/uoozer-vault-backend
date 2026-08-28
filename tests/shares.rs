mod common;
use common::{API, factory, setup_app};
use serde_json::json;

async fn create_share_for_file(
    server: &common::TestServer,
    access: &str,
    file_id: uuid::Uuid,
) -> uuid::Uuid {
    let payload = json!({
        "item_type": "file",
        "encrypted_payload": factory::random_b64(64),
        "encrypted_nonce": factory::random_b64(24),
        "encryption_header": factory::random_b64(24),
        "item_id": file_id,
        "access_type": "public"
    });
    let resp = server
        .client
        .post(server.url(&format!("{API}/files/{file_id}/shares")))
        .header("authorization", format!("Bearer {access}"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    resp.json::<serde_json::Value>().await.unwrap()["share_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn revoked_share_returns_404() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "share1@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'share1@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;

    let share_id = create_share_for_file(&server, &access, file_id).await;

    let _ = server
        .client
        .delete(server.url(&format!("{API}/shares/{share_id}")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(server.url(&format!("{API}/shares/{share_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn expired_share_returns_404() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "share2@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'share2@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;

    let payload = json!({
        "item_type": "file",
        "encrypted_payload": factory::random_b64(64),
        "encrypted_nonce": factory::random_b64(24),
        "encryption_header": factory::random_b64(24),
        "item_id": file_id,
        "access_type": "public",
        "expires_at": "2020-01-01T00:00:00Z"
    });
    let resp = server
        .client
        .post(server.url(&format!("{API}/files/{file_id}/shares")))
        .header("authorization", format!("Bearer {access}"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    let share_id = resp.json::<serde_json::Value>().await.unwrap()["share_id"]
        .as_str()
        .unwrap()
        .parse::<uuid::Uuid>()
        .unwrap();

    let resp = server
        .client
        .get(server.url(&format!("{API}/shares/{share_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cannot_revoke_other_users_share() {
    let (server, pool, _guard) = setup_app().await;
    let (access_a, _, _, _) = common::signup_full(&server, "share3_a@example.com").await;
    let user_a: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'share3_a@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let file_id = factory::create_file_directly(&pool, user_a, None, true).await;
    let share_id = create_share_for_file(&server, &access_a, file_id).await;

    let (access_b, _, _, _) = common::signup_full(&server, "share3_b@example.com").await;
    let resp = server
        .client
        .delete(server.url(&format!("{API}/shares/{share_id}")))
        .header("authorization", format!("Bearer {access_b}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn restricted_share_requires_auth() {
    let (server, pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "share4@example.com").await;
    let user_id: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'share4@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let file_id = factory::create_file_directly(&pool, user_id, None, true).await;

    let payload = json!({
        "item_type": "file",
        "encrypted_payload": factory::random_b64(64),
        "encrypted_nonce": factory::random_b64(24),
        "encryption_header": factory::random_b64(24),
        "item_id": file_id,
        "access_type": "restricted"
    });
    let resp = server
        .client
        .post(server.url(&format!("{API}/files/{file_id}/shares")))
        .header("authorization", format!("Bearer {access}"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    let share_id = resp.json::<serde_json::Value>().await.unwrap()["share_id"]
        .as_str()
        .unwrap()
        .parse::<uuid::Uuid>()
        .unwrap();

    let resp = server
        .client
        .get(server.url(&format!("{API}/shares/{share_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_shares_returns_only_own_shares() {
    let (server, pool, _guard) = setup_app().await;
    let (access_a, _, _, _) = common::signup_full(&server, "share5_a@example.com").await;
    let user_a: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'share5_a@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let file_id = factory::create_file_directly(&pool, user_a, None, true).await;
    let _ = create_share_for_file(&server, &access_a, file_id).await;

    let (access_b, _, _, _) = common::signup_full(&server, "share5_b@example.com").await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/shares")))
        .header("authorization", format!("Bearer {access_b}"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["shares"].as_array().unwrap().len(), 0);
}
