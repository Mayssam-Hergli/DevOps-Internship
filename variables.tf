# variables.tf

variable "aws_region" {
  description = "Primary region (matches the object diagram)."
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Project slug used for naming + tagging."
  type        = string
  default     = "zerotrust"
}

variable "environment" {
  description = "Deployment environment (dev|staging|prod)."
  type        = string
  default     = "dev"
}

variable "owner_tag" {
  description = "Owner tag value for traceability."
  type        = string
  default     = "security-team"
}

# ---- US 1.1 : Access Analyzer -------------------------------------------------
variable "unused_access_age_days" {
  description = "Generate an unused-access finding after this many days of non-use. AC asks for 30."
  type        = number
  default     = 30
}

# ---- US 1.2 : Least-privilege conditions -------------------------------------
variable "trusted_cidrs" {
  description = <<-EOT
    Source IP ranges allowed to assume the privileged roles (aws:SourceIp condition).
    Set to your VPN/office egress. Empty list = no IP restriction (NOT recommended for prod).
  EOT
  type        = list(string)
  default     = [] # e.g. ["197.0.0.0/24"]
}

variable "max_mfa_age_seconds" {
  description = "Reject role assumption if the MFA used is older than this (aws:MultiFactorAuthAge)."
  type        = number
  default     = 3600 # 1 hour
}
