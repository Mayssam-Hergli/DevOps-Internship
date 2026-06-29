# outputs.tf

output "external_analyzer_arn" {
  description = "External-access analyzer ARN (US 1.1)."
  value       = module.access_analyzer.external_analyzer_arn
}

output "unused_analyzer_arn" {
  description = "Unused-access analyzer ARN (US 1.1)."
  value       = module.access_analyzer.unused_analyzer_arn
}

output "permissions_boundary_arn" {
  description = "Permissions boundary applied to all roles (US 1.2)."
  value       = module.least_privilege.permissions_boundary_arn
}

output "role_arns" {
  description = "Assumable least-privilege roles (US 1.2)."
  value       = module.least_privilege.role_arns
}
