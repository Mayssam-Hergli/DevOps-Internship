# modules/iam-least-privilege/main.tf
# US 1.2 (MH-6) - Creation de politiques IAM restrictives.
#
# Design choices (Zero Trust):
#   - Humans assume ROLES, no long-lived IAM users / access keys.
#   - Every assumption requires MFA, recent MFA, and (optionally) a trusted source IP.
#   - Every role carries a PERMISSIONS BOUNDARY that caps privilege and protects
#     the security services themselves from being disabled.
#   - Permission policies contain NO bare wildcard ("*") action.

locals {
  account_id = var.account_id
  partition  = var.partition

  # ---- Reusable assume-role conditions (the AC: aws:MultiFactorAuthPresent + aws:SourceIp) ----
  base_assume_conditions = concat(
    [
      {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      },
      {
        test     = "NumericLessThan"
        variable = "aws:MultiFactorAuthAge"
        values   = [tostring(var.max_mfa_age_seconds)]
      }
    ],
    length(var.trusted_cidrs) > 0 ? [
      {
        test     = "IpAddress"
        variable = "aws:SourceIp"
        values   = var.trusted_cidrs
      }
    ] : []
  )
}

# -----------------------------------------------------------------------------
# Permissions boundary - the privilege ceiling for ALL roles below.
# It allows broad action (the ONE documented + validated wildcard exception per
# the cahier) but hard-DENIES privilege escalation and tampering with security
# controls. This is what makes least privilege safe to roll out (see Bug 1 runbook).
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "permissions_boundary" {
  # Ceiling: allow everything that is not explicitly denied below.
  statement {
    sid       = "AllowedCeiling"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }

  # Block creation of long-lived credentials -> force role-based access.
  statement {
    sid       = "DenyIamUsersAndKeys"
    effect    = "Deny"
    actions   = ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"]
    resources = ["*"]
  }

  # Prevent privilege escalation: no one may detach/alter their own boundary.
  statement {
    sid    = "ProtectPermissionsBoundary"
    effect = "Deny"
    actions = [
      "iam:DeleteRolePermissionsBoundary",
      "iam:PutRolePermissionsBoundary",
      "iam:DeleteUserPermissionsBoundary",
      "iam:PutUserPermissionsBoundary",
    ]
    resources = ["*"]
    # ...except the security-engineer applying THE approved boundary (handled by
    # its own policy condition). Boundary deny wins, so escalation is blocked.
  }

  # Protect the security stack: detection/posture/compliance can't be disabled.
  statement {
    sid    = "ProtectSecurityServices"
    effect = "Deny"
    actions = [
      "guardduty:DeleteDetector",
      "guardduty:DisassociateFromMasterAccount",
      "guardduty:StopMonitoringMembers",
      "guardduty:UpdateDetector",
      "securityhub:DisableSecurityHub",
      "securityhub:DeleteInsight",
      "securityhub:DisableImportFindingsForProduct",
      "config:DeleteConfigurationRecorder",
      "config:StopConfigurationRecorder",
      "config:DeleteDeliveryChannel",
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "accessanalyzer:DeleteAnalyzer",
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey",
      "kms:DisableKeyRotation",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "permissions_boundary" {
  name        = "${var.name_prefix}-permissions-boundary"
  description = "Privilege ceiling: blocks escalation + protects security services. Applied to every role."
  policy      = data.aws_iam_policy_document.permissions_boundary.json
  tags        = { UserStory = "US1.2", Purpose = "permissions-boundary" }
}

# -----------------------------------------------------------------------------
# ROLE 1 - Security Auditor (Security Administrator / IT Auditor personas).
# Read-only. This is the role used to RUN the US 1.1 audit script.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "auditor_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
    dynamic "condition" {
      for_each = local.base_assume_conditions
      content {
        test     = condition.value.test
        variable = condition.value.variable
        values   = condition.value.values
      }
    }
  }
}

data "aws_iam_policy_document" "auditor_permissions" {
  # Read-only audit surface. Prefixed wildcards (iam:Get*) are scoped, NOT the
  # banned bare "*" action.
  statement {
    sid    = "ReadOnlyAudit"
    effect = "Allow"
    actions = [
      "iam:Get*",
      "iam:List*",
      "iam:GenerateServiceLastAccessedDetails",
      "iam:GetServiceLastAccessedDetails",
      "access-analyzer:Get*",
      "access-analyzer:List*",
      "cloudtrail:LookupEvents",
      "config:Describe*",
      "config:Get*",
    ]
    resources = ["*"] # read/list APIs are not resource-scopable; action set is tightly bounded.
  }
}

resource "aws_iam_role" "security_auditor" {
  name                 = "${var.name_prefix}-security-auditor"
  assume_role_policy   = data.aws_iam_policy_document.auditor_trust.json
  permissions_boundary = aws_iam_policy.permissions_boundary.arn
  max_session_duration = 3600
  tags                 = { UserStory = "US1.2", Persona = "SecurityAdministrator/ITAuditor" }
}

resource "aws_iam_role_policy" "security_auditor" {
  name   = "audit-readonly"
  role   = aws_iam_role.security_auditor.id
  policy = data.aws_iam_policy_document.auditor_permissions.json
}

# -----------------------------------------------------------------------------
# ROLE 2 - SOC Analyst. Detection/posture read access (used from Epic 2 on).
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "soc_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
    dynamic "condition" {
      for_each = local.base_assume_conditions
      content {
        test     = condition.value.test
        variable = condition.value.variable
        values   = condition.value.values
      }
    }
  }
}

data "aws_iam_policy_document" "soc_permissions" {
  statement {
    sid    = "DetectionAndPostureRead"
    effect = "Allow"
    actions = [
      "guardduty:Get*",
      "guardduty:List*",
      "securityhub:Get*",
      "securityhub:List*",
      "securityhub:Describe*",
      "securityhub:BatchUpdateFindings", # triage workflow status only
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "soc_analyst" {
  name                 = "${var.name_prefix}-soc-analyst"
  assume_role_policy   = data.aws_iam_policy_document.soc_trust.json
  permissions_boundary = aws_iam_policy.permissions_boundary.arn
  max_session_duration = 3600
  tags                 = { UserStory = "US1.2", Persona = "SOCAnalyst" }
}

resource "aws_iam_role_policy" "soc_analyst" {
  name   = "soc-detection-read"
  role   = aws_iam_role.soc_analyst.id
  policy = data.aws_iam_policy_document.soc_permissions.json
}
