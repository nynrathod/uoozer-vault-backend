mod common;
use base64::Engine; // <--- THIS IS THE MISSING IMPORT
use common::{API, factory, setup_app};

#[tokio::test]
async fn auth_rate_limit_blocks_brute_force() {
    let (server, _pool, _guard) = setup_app().await;
    let auth_key = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);

    // In config/default.toml, auth_per_minute is 10.
    // We send 20 requests to guarantee we trigger the 429 Too Many Requests.
    let mut hit_429 = false;
    for i in 0..20 {
        let resp = server
            .client
            .post(server.url(&format!("{API}/auth/login")))
            .json(&factory::login_req(
                &format!("brute_{i}@example.com"),
                &auth_key,
            ))
            .send()
            .await
            .unwrap();

        if resp.status() == http::StatusCode::TOO_MANY_REQUESTS {
            hit_429 = true;
            break;
        }
    }
    assert!(
        hit_429,
        "Rate limiter must trigger 429 after exceeding the configured limit"
    );
}

#[tokio::test]
async fn rate_limit_isolated_per_ip() {
    let (server, _pool, _guard) = setup_app().await;
    let mut hit_429 = false;
    for i in 0..15 {
        let resp = server
            .client
            .post(server.url(&format!("{API}/auth/prelogin")))
            .header("x-forwarded-for", "10.0.0.1")
            .json(&serde_json::json!({ "email": format!("ip1_{i}@example.com") }))
            .send()
            .await
            .unwrap();
        if resp.status() == 429 {
            hit_429 = true;
        }
    }
    assert!(hit_429, "First IP should be rate limited");

    // Second IP should NOT be limited yet
    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/prelogin")))
        .header("x-forwarded-for", "10.0.0.2")
        .json(&serde_json::json!({ "email": "ip2@example.com" }))
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 429, "Second IP should not be rate limited");
}
