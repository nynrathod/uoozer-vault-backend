# Enable required GCP APIs
# (cloudkms removed — unused; iamcredentials added — needed for WIF token exchange)
resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "storage.googleapis.com",
    "artifactregistry.googleapis.com",
  ])

  service                    = each.value
  disable_on_destroy         = false
  disable_dependent_services = false
}