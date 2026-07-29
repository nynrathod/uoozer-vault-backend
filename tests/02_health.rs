mod common;
use common::setup_app;

#[tokio::test]
async fn health_check_returns_ok() {
    let (server, _pool, _guard) = setup_app().await;

    let resp = server
        .client
        .get(server.url("/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), http::StatusCode::OK);
    let body: String = resp.text().await.unwrap();
    assert_eq!(body, "OK");
}
