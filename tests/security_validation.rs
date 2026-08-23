mod common;
use common::{API, setup_app};

// ── MIME sniffing prevention ──────────────────────────

#[tokio::test]
async fn x_content_type_options_header_present() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .get(server.url("/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
}

// ── Clickjacking prevention ────────────────────────────

#[tokio::test]
async fn x_frame_options_header_present() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .get(server.url("/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
}

// ── Referrer-Policy header ──────────────────────────────────

#[tokio::test]
async fn referrer_policy_header_present() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .get(server.url("/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "strict-origin-when-cross-origin"
    );
}

// ── IDOR on file access ────────────────────────────────

#[tokio::test]
async fn idor_file_access_blocked() {
    let (server, pool, _guard) = setup_app().await;

    let (_access_a, _, _, _) = common::signup_full(&server, "k1_idor_a@example.com").await;
    let user_a: uuid::Uuid =
        sqlx::query_scalar("SELECT user_id FROM users WHERE email = 'k1_idor_a@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let file_id = common::factory::create_file_directly(&pool, user_a, None, true).await;

    let (access_b, _, _, _) = common::signup_full(&server, "k1_idor_b@example.com").await;

    let resp = server
        .client
        .get(server.url(&format!("{API}/files/{file_id}")))
        .header("authorization", format!("Bearer {access_b}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

// ── API rate limiting ──────────────────────────────────

#[tokio::test]
async fn api_rate_limit_triggered() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "k7_rate@example.com").await;

    let mut hit_429 = false;

    for _ in 0..20 {
        let resp = server
            .client
            .get(server.url(&format!("{API}/files")))
            .header("authorization", format!("Bearer {access}"))
            .send()
            .await
            .unwrap();

        if resp.status() == http::StatusCode::TOO_MANY_REQUESTS {
            hit_429 = true;
            break;
        }
    }

    assert!(hit_429, "API rate limiter must trigger 429");
}

// ── Auth rate limiting ─────────────────────────────────

#[tokio::test]
async fn auth_rate_limit_triggered() {
    let (server, _pool, _guard) = setup_app().await;

    let mut hit_429 = false;

    // In config/default.toml, auth_per_minute is 10.
    // Send 15 requests to trigger rate limit.
    for _ in 0..15 {
        let resp = server
            .client
            .post(server.url(&format!("{API}/auth/prelogin")))
            .json(&serde_json::json!({ "email": "rate_test@example.com" }))
            .send()
            .await
            .unwrap();

        if resp.status() == http::StatusCode::TOO_MANY_REQUESTS {
            hit_429 = true;
            break;
        }
    }

    assert!(hit_429, "Auth rate limiter must trigger 429");
}

// ── CSRF - JWT-based, no cookies ────────────────────────

#[tokio::test]
async fn no_cookies_used_for_auth() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .get(server.url("/health"))
        .send()
        .await
        .unwrap();

    assert!(resp.headers().get("set-cookie").is_none());
}

// ── SQL Injection prevention ────────────────────────────

#[tokio::test]
async fn sql_injection_in_email_prevented() {
    let (server, pool, _guard) = setup_app().await;

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/prelogin")))
        .json(&serde_json::json!({
            "email": "'; DROP TABLE users; --"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

// ── XSS in filenames - backend doesn't parse ───────────

#[tokio::test]
async fn xss_in_filename_ignored_by_backend() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "k3_xss@example.com").await;

    let metadata = "{\"name\":\"<script>alert('xss')</script>\"}";
    let req = common::factory::create_file_req_with_metadata(
        None,
        metadata,
        &common::factory::random_b64(32),
        1024,
        1,
    );

    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req)
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), http::StatusCode::BAD_REQUEST);
}

// ── Security headers on API responses ───────────────────────

#[tokio::test]
async fn security_headers_on_api_responses() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "k_headers@example.com").await;

    let resp = server
        .client
        .get(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "strict-origin-when-cross-origin"
    );
}
