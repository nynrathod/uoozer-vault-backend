output "artifact_registry" {
  description = "Artifact Registry repo for Docker images"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.backend.repository_id}"
}

output "workload_identity_provider" {
  description = "WIF provider for GitHub Actions"
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "github_actions_service_account" {
  description = "Service account email for GitHub Actions"
  value       = google_service_account.github_actions.email
}

# backend_url removed — CI deploys the service. Get the URL after first deploy:
# gcloud run services describe uoozer-vault-backend --region us-central1 --format 'value(status.url)'