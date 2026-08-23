use reqwest::Client;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use uoozer_vault_backend::app_state::AppState;
use uoozer_vault_backend::build_router;
use uoozer_vault_backend::config::Settings;

pub const API: &str = "/api/v1";

pub struct TestServer {
    pub client: Client,
    pub addr: SocketAddr,
}

impl TestServer {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

/// This guard holds a Postgres advisory lock.
/// It prevents parallel test runners (like nextest) from deadlocking.
pub struct TestGuard {
    _conn: sqlx::pool::PoolConnection<sqlx::Postgres>,
}

impl Drop for TestGuard {
    fn drop(&mut self) {
        // Connection drops here, automatically releasing the advisory lock
    }
}

pub async fn setup_app() -> (TestServer, PgPool, TestGuard) {
    dotenvy::from_filename(".env.test").ok();

    let db_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:admin@localhost:5432/uoozer_vault".to_string());

    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("JWT_PRIVATE_KEY_PEM", "dev");
        std::env::set_var(
            "PRELOGIN_PEPPER",
            "test_pepper_only_for_tests_DO_NOT_USE_IN_PROD",
        );
    }

    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to test DB");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let mut lock_conn = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(20240101)")
        .execute(&mut *lock_conn)
        .await
        .expect("Failed to acquire advisory lock");

    sqlx::query(
        "TRUNCATE TABLE audit_logs, file_chunks, file_versions, files, folders, sessions, devices, users CASCADE"
    )
    .execute(&pool)
    .await
    .expect("Failed to truncate tables");

    let mut settings = Settings::load().expect("Failed to load Settings");

    settings.argon2.m_cost = 4096;
    settings.argon2.t_cost = 1;
    settings.bcrypt.cost = 4;

    settings.rate_limit.auth_per_minute = 5;
    settings.rate_limit.api_per_minute = 10;

    // If this env var is set, use real MinIO for E2E tests
    if std::env::var("RUN_E2E_STORAGE_TESTS").is_ok() {
        settings.r2.access_key_id = "minioadmin".to_string();
        settings.r2.secret_access_key = "minioadmin".to_string();
        settings.r2.bucket = "uoozer-vault".to_string();
        settings.r2.endpoint = "http://localhost:9000".to_string();
    } else {
        settings.r2.access_key_id = String::new();
        settings.r2.secret_access_key = String::new();
    }

    let settings = Arc::new(settings);
    let state = AppState::new(settings, pool.clone())
        .await
        .expect("Failed to create AppState");

    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    (
        TestServer { client, addr },
        pool,
        TestGuard { _conn: lock_conn },
    )
}

pub async fn signup_full(server: &TestServer, email: &str) -> (String, String, String, String) {
    use serde_json::json;

    let init_resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/init")))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap();
    assert_eq!(init_resp.status(), http::StatusCode::OK);
    let init_body: serde_json::Value = init_resp.json().await.unwrap();
    let token = init_body["signup_token"].as_str().unwrap().to_string();

    let mut payload = factory::signup_complete_req(email);
    payload["signup_token"] = json!(token);

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/signup/complete")))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::CREATED);

    let body: serde_json::Value = resp.json().await.unwrap();
    let access = body["access_token"].as_str().unwrap().to_string();
    let refresh = body["refresh_token"].as_str().unwrap().to_string();
    let auth_key = payload["auth_key"].as_str().unwrap().to_string();

    (access, refresh, email.to_string(), auth_key)
}

#[allow(dead_code)]
pub mod assertions;

#[allow(dead_code)]
pub mod factory;
