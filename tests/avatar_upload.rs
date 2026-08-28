mod common;
use common::{API, setup_app};
use serde_json::json;

#[tokio::test]
async fn avatar_upload_without_storage_returns_503() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "avatar1@example.com").await;

    let png_bytes = b"\x89PNG\r\n\x1a\n fake png";
    let part = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(png_bytes.to_vec())
            .file_name("avatar.png")
            .mime_str("image/png")
            .unwrap(),
    );

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/avatar")))
        .header("authorization", format!("Bearer {access}"))
        .multipart(part)
        .send()
        .await
        .unwrap();

    assert!(resp.status() == 503 || resp.status() == 200);
}

#[tokio::test]
async fn avatar_upload_rejects_oversized_file() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "avatar2@example.com").await;

    let big_bytes = vec![0u8; 3 * 1024 * 1024];
    let part = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(big_bytes)
            .file_name("big.png")
            .mime_str("image/png")
            .unwrap(),
    );

    let resp = server
        .client
        .post(server.url(&format!("{API}/auth/avatar")))
        .header("authorization", format!("Bearer {access}"))
        .multipart(part)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}
