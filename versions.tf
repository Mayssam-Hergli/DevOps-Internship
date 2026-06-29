# versions.tf
# Strict version pinning -> reproducible deployments (cahier: "déploiement reproductible").
# Bump these deliberately, never float them.

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60" # 5.60+ ships the unused-access analyzer config block
    }
  }

  # Sprint 1 uses local state. Switch to an encrypted S3 backend + DynamoDB lock
  # once the secure logging bucket exists (that lands with Epic 4 / AWS Config).
  #
  # backend "s3" {
  #   bucket         = "zerotrust-tfstate-<account_id>"
  #   key            = "zero-trust/terraform.tfstate"
  #   region         = "eu-west-1"
  #   dynamodb_table = "zerotrust-tflock"
  #   encrypt        = true
  # }
}
