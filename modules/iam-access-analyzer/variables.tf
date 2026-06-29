# modules/iam-access-analyzer/variables.tf

variable "name_prefix" {
  description = "Prefix for analyzer names, e.g. zerotrust-dev."
  type        = string
}

variable "unused_access_age_days" {
  description = "Days of non-use before an unused-access finding is generated."
  type        = number
  default     = 30
}

variable "unused_access_exclusion_tags" {
  description = "List of {key=value} tag maps whose resources are excluded from unused-access analysis."
  type        = list(map(string))
  default     = []
}

variable "documented_external_principals" {
  description = <<-EOT
    Map of label => principal ARN for cross-account access that is reviewed and approved.
    These get an archive rule so they are documented but no longer flagged as active findings.
    Example: { partner_audit = "arn:aws:iam::222222222222:root" }
  EOT
  type        = map(string)
  default     = {}
}
