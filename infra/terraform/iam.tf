# Service account the Cloud Run service runs as
resource "google_service_account" "backend" {
  account_id   = "vault-backend"
  display_name = "Uoozer Vault Backend Service Account"
  depends_on   = [google_project_service.apis]
}

# Runtime SA reads secret values at startup
resource "google_project_iam_member" "backend_secret_access" {
  project    = var.project_id
  role       = "roles/secretmanager.secretAccessor"
  member     = "serviceAccount:${google_service_account.backend.email}"
  depends_on = [google_project_service.apis]
}

# Cloud Run's service agent must pull images from Artifact Registry
# (without this, deployment fails with "image pull permission denied")
data "google_project" "this" {}

resource "google_project_iam_member" "cloudrun_artifact_reader" {
  project    = var.project_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:service-${data.google_project.this.number}@serverless-robot-prod.iam.gserviceaccount.com"
  depends_on = [google_project_service.apis]
}