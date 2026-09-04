variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "uoozer-vault-prod"
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "github_owner" {
  description = "GitHub username/org for Workload Identity Federation"
  type        = string
}

variable "github_repo" {
  description = "GitHub repo name for Workload Identity Federation"
  type        = string
  default     = "uoozer-vault-backend"
}