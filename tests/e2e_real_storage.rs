mod common;
use base64::Engine;
use common::{API, setup_app};

#[tokio::test]
async fn real_file_upload_and_download_cycle() {
    // Only run this test if the env var is set
    if std::env::var("RUN_E2E_STORAGE_TESTS").is_err() {
        println!("Skipping E2E storage test. Set RUN_E2E_STORAGE_TESTS=true to run.");
        return;
    }

    let (server, _pool, _guard) = setup_app().await;
    let (access, _, _, _) = common::signup_full(&server, "e2e@example.com").await;

    // 1. Create real 1MB file bytes (simulating an encrypted file)
    let file_bytes = vec![0x42u8; 1024 * 1024]; // 1MB of 'B's

    // 2. Calculate real BLAKE3 hashes
    let b64 = base64::engine::general_purpose::STANDARD;
    let file_hash = blake3::hash(&file_bytes);
    let chunk_hash = blake3::hash(&file_bytes); // 1 chunk = whole file

    let req_body = serde_json::json!({
        "folder_id": null,
        "encrypted_metadata": b64.encode(vec![0u8; 48]),
        "metadata_nonce": b64.encode(vec![0u8; 24]),
        "plaintext_blake3": b64.encode(file_hash.as_bytes()),
        "total_size": file_bytes.len() as i64,
        "total_chunks": 1,
        "encryption_header": b64.encode(vec![0u8; 24]),
        "chunks": [{
            "chunk_index": 0,
            "segment_index": 0,
            "chunk_size": (file_bytes.len() + 17) as i64,
            "chunk_blake3": b64.encode(chunk_hash.as_bytes()),
        }]
    });

    // 3. Initiate Upload (Backend gives us presigned URL)
    let resp = server
        .client
        .post(server.url(&format!("{API}/files")))
        .header("authorization", format!("Bearer {access}"))
        .json(&req_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let create_resp: serde_json::Value = resp.json().await.unwrap();
    let version_id = create_resp["version_id"].as_str().unwrap().to_string();
    let upload_url = create_resp["upload_urls"][0]["presigned_url"]
        .as_str()
        .unwrap()
        .to_string();

    // 4. Upload actual file bytes DIRECTLY to MinIO
    let put_resp = reqwest::Client::new()
        .put(&upload_url)
        .body(file_bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), 200);

    // Get the ETag from MinIO's response
    let etag = put_resp
        .headers()
        .get("ETag")
        .unwrap()
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    // 5. Tell Backend the upload is complete
    // NOTE: The route requires the file_id in the URL!
    let file_id = create_resp["file_id"].as_str().unwrap(); // Extract file_id first

    let complete_resp = server
        .client
        .post(server.url(&format!("{API}/files/{file_id}/complete")))
        .header("authorization", format!("Bearer {access}"))
        .json(&serde_json::json!({
            "version_id": version_id,
            "r2_etags": { "0": etag }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(complete_resp.status(), 204);

    // 6. Request Download Manifest (Backend gives us download URL)
    // (file_id is already extracted above, so we can just use it here)
    let dl_resp = server
        .client
        .get(server.url(&format!("{API}/files/{file_id}/download")))
        .header("authorization", format!("Bearer {access}"))
        .send()
        .await
        .unwrap();
    assert_eq!(dl_resp.status(), 200);

    let dl_manifest: serde_json::Value = dl_resp.json().await.unwrap();
    let dl_url = dl_manifest["chunks"][0]["presigned_url"].as_str().unwrap();

    // 7. Download actual file bytes DIRECTLY from MinIO
    let get_resp = reqwest::Client::new().get(dl_url).send().await.unwrap();
    assert_eq!(get_resp.status(), 200);

    let downloaded_bytes = get_resp.bytes().await.unwrap();

    // 8. Verify the downloaded bytes match the uploaded bytes exactly!
    assert_eq!(downloaded_bytes.to_vec(), file_bytes);
    println!("✅ E2E SUCCESS: Real file uploaded and downloaded perfectly!");
}
