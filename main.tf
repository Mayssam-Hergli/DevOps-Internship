# main.tf - Sprint 1 (Epic 1: IAM Least Privilege) wiring.

locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

# US 1.1 (MH-5) - Audit via IAM Access Analyzer
module "access_analyzer" {
  source = "./modules/iam-access-analyzer"

  name_prefix            = local.name_prefix
  unused_access_age_days = var.unused_access_age_days

  # Exclude obvious test noise from the unused report (keeps the audit signal-rich).
  unused_access_exclusion_tags = [
    { Environment = "sandbox" }
  ]

  # Approved cross-account principals go here so they are documented, not flagged.
  documented_external_principals = {}
}

# US 1.2 (MH-6) - Restrictive, MFA/IP-conditioned roles + permissions boundary
module "least_privilege" {
  source = "./modules/iam-least-privilege"

  name_prefix         = local.name_prefix
  account_id          = data.aws_caller_identity.current.account_id
  partition           = data.aws_partition.current.partition
  trusted_cidrs       = var.trusted_cidrs
  max_mfa_age_seconds = var.max_mfa_age_seconds
}
