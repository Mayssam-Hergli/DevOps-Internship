# modules/iam-access-analyzer/outputs.tf

output "external_analyzer_arn" {
  description = "ARN of the external-access analyzer."
  value       = aws_accessanalyzer_analyzer.external_access.arn
}

output "unused_analyzer_arn" {
  description = "ARN of the unused-access analyzer."
  value       = aws_accessanalyzer_analyzer.unused_access.arn
}

output "analyzer_names" {
  description = "Both analyzer names (handy for the audit script)."
  value = {
    external = aws_accessanalyzer_analyzer.external_access.analyzer_name
    unused   = aws_accessanalyzer_analyzer.unused_access.analyzer_name
  }
}
