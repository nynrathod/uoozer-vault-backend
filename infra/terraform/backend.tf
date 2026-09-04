terraform {
  backend "gcs" {
    bucket = "uoozer-vault-tfstate-prod"
    prefix = "terraform/state"
  }
}