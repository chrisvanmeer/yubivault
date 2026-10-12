terraform {
  # Works with both Terraform and OpenTofu (>= 1.3). terraform_data is used for
  # the manual rotation triggers, so no external provider is needed for that.
  required_version = ">= 1.3.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}
