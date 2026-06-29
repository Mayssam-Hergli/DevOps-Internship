# modules/iam-least-privilege/variables.tf

variable "name_prefix" {
  description = "Prefix for IAM resource names."
  type        = string
}

variable "account_id" {
  description = "Current AWS account id."
  type        = string
}

variable "partition" {
  description = "AWS partition (aws, aws-cn, aws-us-gov)."
  type        = string
  default     = "aws"
}

variable "trusted_cidrs" {
  description = "Source IP allowlist for assuming roles (aws:SourceIp). Empty = no IP restriction."
  type        = list(string)
  default     = []
}

variable "max_mfa_age_seconds" {
  description = "Reject assumption if MFA older than this (aws:MultiFactorAuthAge)."
  type        = number
  default     = 3600
}
