terraform {
  # Works with both Terraform and OpenTofu (>= 1.3).
  required_version = ">= 1.3.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.0"
    }
  }
}
