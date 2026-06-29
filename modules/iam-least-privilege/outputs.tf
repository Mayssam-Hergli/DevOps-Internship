# modules/iam-least-privilege/outputs.tf

output "permissions_boundary_arn" {
  description = "ARN of the permissions boundary applied to every role."
  value       = aws_iam_policy.permissions_boundary.arn
}

output "role_arns" {
  description = "Assumable role ARNs by persona."
  value = {
    security_auditor = aws_iam_role.security_auditor.arn
    soc_analyst      = aws_iam_role.soc_analyst.arn
  }
}
