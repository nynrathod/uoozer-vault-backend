mod common;
use common::{API, factory, setup_app};
use serde_json::json;

#[tokio::test]
async fn concurrent_refresh_does_not_create_duplicate_sessions() {
    let (server, pool, _guard) = setup_app().await;
    let (_, refresh_token, _, _) = common::signup_full(&server, "race@example.com").await;

    let mut handles = vec![];
    for _ in 0..5 {
        let token = refresh_token.clone();
        let url = server.url(&format!("{API}/auth/refresh"));
        handles.push(tokio::spawn(async move {
            reqwest::Client::new()
                .post(&url)
                .json(&json!({ "refresh_token": token }))
                .send()
                .await
                .unwrap()
        }));
    }

    let mut statuses = vec![];
    for h in handles {
        let resp = h.await.unwrap();
        statuses.push(resp.status().as_u16());
    }

    let successes = statuses.iter().filter(|&&s| s == 200).count();
    assert_eq!(successes, 1, "Only one refresh should succeed");

    let reuse_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'refresh_token_reuse'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(reuse_count >= 1);
}
