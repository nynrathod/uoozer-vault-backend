resource "google_artifact_registry_repository" "backend" {
  location      = var.region
  repository_id = "uoozer-vault-prod"
  description   = "Docker images for Uoozer Vault backend"
  format        = "DOCKER"
  depends_on    = [google_project_service.apis]
}