# providers.tf

provider "aws" {
  region = var.aws_region

  # Every resource we create is tagged -> auditability + lets Security Hub /
  # Config suppression rules later filter by Environment (anticipates Bug 3).
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Sprint      = "S1-IAM-LeastPrivilege"
      Owner       = var.owner_tag
    }
  }
}

# Resolve the current account id / caller without hardcoding anything.
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}
