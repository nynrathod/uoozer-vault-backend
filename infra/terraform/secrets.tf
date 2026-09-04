# ── Secret Manager: creates EMPTY secret containers only ──
# Terraform state NEVER contains secret values.
# You fill values manually AFTER terraform apply.
# Cloud Run reads them at runtime via IAM.

resource "google_secret_manager_secret" "database_url" {
  secret_id = "database-url"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "jwt_private_key" {
  secret_id = "jwt-private-key"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "prelogin_pepper" {
  secret_id = "prelogin-pepper"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "r2_access_key_id" {
  secret_id = "r2-access-key-id"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "r2_secret_access_key" {
  secret_id = "r2-secret-access-key"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret" "r2_bucket_name" {
  secret_id = "r2-bucket-name"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

# NOTE: r2-account-id is NOT a secret — it appears in every presigned URL
# the app hands to the browser. It's set as a plain env var in CI.