use std::net::SocketAddr;

use figment::{Figment, providers::Format, providers::Toml};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    #[serde(default = "default_environment")]
    pub environment: String,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub argon2: Argon2Config,
    pub bcrypt: BcryptConfig,
    pub cors: CorsConfig,
    pub rate_limit: RateLimitConfig,
    pub r2: R2Config,
    #[serde(default = "default_pepper")]
    pub prelogin_pepper: String,
    #[serde(default)]
    pub jwt_private_key_pem: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl ServerConfig {
    pub fn socket_addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .expect("invalid server bind address")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_url")]
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub issuer: String,
    pub access_ttl_seconds: u64,
    pub refresh_ttl_seconds: u64,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Argon2Config {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub output_len: usize,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct BcryptConfig {
    pub cost: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
}

impl CorsConfig {
    pub fn as_cors_layer(&self) -> tower_http::cors::CorsLayer {
        use tower_http::cors::{Any, CorsLayer};

        let origins: Vec<_> = self
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();

        if origins.is_empty() {
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        } else {
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::PATCH,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::ACCEPT,
                    "x-request-id".parse().unwrap(),
                    "x-refresh-token".parse().unwrap(),
                    "x-device-id".parse().unwrap(),
                ])
                .expose_headers([
                    "x-request-id".parse().unwrap(),
                    "x-refresh-token".parse().unwrap(),
                ])
                .allow_credentials(true)
                .max_age(std::time::Duration::from_secs(600))
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub auth_per_minute: u32,
    pub api_per_minute: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct R2Config {
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: String,
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default = "default_presign_ttl")]
    pub presign_ttl_seconds: u64,
}

impl R2Config {
    pub fn is_configured(&self) -> bool {
        !self.access_key_id.is_empty()
            && !self.secret_access_key.is_empty()
            && !self.bucket.is_empty()
    }

    pub fn full_endpoint(&self) -> String {
        if !self.endpoint.is_empty() {
            self.endpoint.clone()
        } else {
            format!("https://{}.r2.cloudflarestorage.com", self.account_id)
        }
    }
}

impl Settings {
    pub fn load() -> Result<Self, figment::Error> {
        use figment::providers::Env;

        // 1. Load base config from TOML and UOOZER_ prefixed env vars
        let mut settings: Settings = Figment::from(Toml::file("config/default.toml"))
            .merge(Env::prefixed("UOOZER_").split("__"))
            .extract()?;

        // 2. Explicitly map standard universal env vars (No hardcoding values,
        // just mapping the standard names to our struct fields)
        if let Ok(val) = std::env::var("DATABASE_URL") {
            settings.database.url = val;
        }
        if let Ok(val) = std::env::var("CORS_ALLOWED_ORIGINS") {
            settings.cors.allowed_origins = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = std::env::var("PRELOGIN_PEPPER") {
            settings.prelogin_pepper = val;
        }
        if let Ok(val) = std::env::var("JWT_PRIVATE_KEY_PEM") {
            settings.jwt_private_key_pem = val;
        }
        if let Ok(val) = std::env::var("R2_ACCOUNT_ID") {
            settings.r2.account_id = val;
        }
        if let Ok(val) = std::env::var("R2_ACCESS_KEY_ID") {
            settings.r2.access_key_id = val;
        }
        if let Ok(val) = std::env::var("R2_SECRET_ACCESS_KEY") {
            settings.r2.secret_access_key = val;
        }
        if let Ok(val) = std::env::var("R2_BUCKET") {
            settings.r2.bucket = val;
        }
        if let Ok(val) = std::env::var("R2_ENDPOINT") {
            settings.r2.endpoint = val;
        }

        Ok(settings)
    }
}

fn default_environment() -> String {
    "development".to_string()
}

fn default_db_url() -> String {
    "postgres://vault:vault@localhost:5432/uoozer_vault".to_string()
}

fn default_pepper() -> String {
    "default_dev_pepper_change_me".to_string()
}

fn default_presign_ttl() -> u64 {
    300
}
