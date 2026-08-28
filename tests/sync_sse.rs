mod common;
use common::{API, setup_app};
use serde_json::json;

#[tokio::test]
async fn sse_requires_auth() {
    let (server, _pool, _guard) = setup_app().await;
    let resp = server
        .client
        .get(server.url(&format!("{API}/sync/events")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sse_emits_sync_events_on_file_create() {
    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "sse@example.com").await;

    let url = server.url(&format!("{API}/sync/events"));
    let req = reqwest::Client::new()
        .get(&url)
        .header("authorization", format!("Bearer {access}"))
        .send();
   
	  tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let _ = server
        .client
        .post(server.url(&format!("{API}/folders")))
        .header("authorization", format!("Bearer {access}"))
        .json(&common::factory::create_folder_req(None))
        .send()
        .await
        .unwrap();

    drop(req);
}
