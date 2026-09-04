# Workload Identity Pool for GitHub Actions
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions Pool"
  depends_on                = [google_project_service.apis]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub Provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  # Locks this provider to YOUR repo only — any other repo's token is rejected.
  # Also satisfies Google's requirement that mapped attributes be referenced.
  attribute_condition = "assertion.repository == '${var.github_owner}/${var.github_repo}'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# SA that GitHub Actions impersonates
resource "google_service_account" "github_actions" {
  account_id   = "github-actions-deployer"
  display_name = "GitHub Actions Deployer"
  depends_on   = [google_project_service.apis]
}

# Only THIS repo's GitHub Actions can impersonate the deployer SA
resource "google_service_account_iam_member" "github_workload_identity" {
  service_account_id = google_service_account.github_actions.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_owner}/${var.github_repo}"
  depends_on         = [google_iam_workload_identity_pool_provider.github]
}

# Deployer may deploy Cloud Run services that run as the backend SA
resource "google_service_account_iam_member" "github_act_as_backend" {
  service_account_id = google_service_account.backend.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.github_actions.email}"
}

# Deploy permissions (least privilege)
resource "google_project_iam_member" "github_deployer" {
  project    = var.project_id
  role       = "roles/run.admin"
  member     = "serviceAccount:${google_service_account.github_actions.email}"
  depends_on = [google_project_service.apis]
}

resource "google_project_iam_member" "github_artifact" {
  project    = var.project_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.github_actions.email}"
  depends_on = [google_project_service.apis]
}

# Read-only secret metadata so `gcloud run deploy --set-secrets` can validate refs
resource "google_project_iam_member" "github_secret_viewer" {
  project    = var.project_id
  role       = "roles/secretmanager.viewer"
  member     = "serviceAccount:${google_service_account.github_actions.email}"
  depends_on = [google_project_service.apis]
}