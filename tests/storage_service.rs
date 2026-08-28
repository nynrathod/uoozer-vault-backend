use uoozer_vault_backend::storage::StorageService;
use uuid::Uuid;

#[test]
fn chunk_key_format_is_correct() {
    let user_id = Uuid::new_v4();
    let file_id = Uuid::new_v4();
    let version_id = Uuid::new_v4();
    let key = StorageService::chunk_key(user_id, file_id, version_id, 2, 5);
    let parts: Vec<&str> = key.split('/').collect();
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0], user_id.to_string());
    assert_eq!(parts[1], file_id.to_string());
    assert_eq!(parts[2], version_id.to_string());
    assert_eq!(parts[3], "2");
    assert_eq!(parts[4], "5");
}

#[test]
fn chunk_key_never_contains_filename() {
    let key = StorageService::chunk_key(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 0, 0);
    assert!(!key.contains("file"));
    assert!(!key.contains("name"));
    assert!(!key.contains("."));
    assert!(!key.contains("\\"));
}

#[tokio::test]
async fn storage_service_without_r2_is_not_configured() {
    let svc = StorageService::new(None);
    assert!(!svc.is_configured());
    assert!(svc.presign_put("any").await.is_err());
}
