# modules/iam-access-analyzer/main.tf
# US 1.1 (MH-5) - Audit des roles et politiques IAM existants.
#
# Two analyzers, account-level zone of trust (single sandbox account):
#   1. External access  -> finds resources shared publicly / cross-account  (free)
#   2. Unused access    -> finds roles/users/permissions unused for N days  (paid per principal)
#
# Together they satisfy the AC:
#   - "rapport des permissions non utilisees sur les 30 derniers jours"  -> unused analyzer (age=30)
#   - "acces publics ou cross-account non justifies identifies"          -> external analyzer

resource "aws_accessanalyzer_analyzer" "external_access" {
  analyzer_name = "${var.name_prefix}-external-access"
  type          = "ACCOUNT"

  tags = {
    UserStory = "US1.1"
    Purpose   = "external-and-public-access-audit"
  }
}

resource "aws_accessanalyzer_analyzer" "unused_access" {
  analyzer_name = "${var.name_prefix}-unused-access"
  type          = "ACCOUNT_UNUSED_ACCESS"

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age_days # AC: 30 days

      # Exclude resources explicitly tagged as intentionally broad, so the
      # report stays signal-rich (pre-empts the same noise problem as Bug 3).
      dynamic "analysis_rule" {
        for_each = length(var.unused_access_exclusion_tags) > 0 ? [1] : []
        content {
          exclusion {
            resource_tags = var.unused_access_exclusion_tags
          }
        }
      }
    }
  }

  tags = {
    UserStory = "US1.1"
    Purpose   = "unused-permission-audit"
  }
}

# Archive rule = the "documented and validated exception" mechanism the cahier
# requires. Cross-account access that is justified gets auto-archived so it stops
# polluting the active findings list, while remaining on record.
resource "aws_accessanalyzer_archive_rule" "documented_exceptions" {
  for_each = var.documented_external_principals

  analyzer_name = aws_accessanalyzer_analyzer.external_access.analyzer_name
  rule_name     = "documented-${each.key}"

  filter {
    criteria = "principal.AWS"
    eq       = [each.value]
  }
}
