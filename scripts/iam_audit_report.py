#!/usr/bin/env python3
"""
iam_audit_report.py  --  US 1.1 (MH-5) deliverable.

Generates the IAM audit report required by the acceptance criteria:
  * Unused permissions over the last N (default 30) days   -> from the unused-access analyzer
  * Public / cross-account external access                 -> from the external-access analyzer
  * Customer-managed policies using the banned wildcard "*" action (feeds US 1.2)

Run it with the security-auditor role (read-only). Output is a timestamped
Markdown report you can attach to the sprint review / Jira MH-5.

Usage:
    python3 iam_audit_report.py --region eu-west-1
    python3 iam_audit_report.py --region eu-west-1 --out report.md
"""
import argparse
import datetime as dt
import json
import sys

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    sys.exit("boto3 is required:  pip install boto3")


def discover_analyzers(client):
    """Return {'external': arn, 'unused': arn} by inspecting analyzer types."""
    found = {}
    paginator = client.get_paginator("list_analyzers")
    for page in paginator.paginate():
        for a in page.get("analyzers", []):
            if a["type"] == "ACCOUNT":
                found["external"] = a["arn"]
            elif a["type"] == "ACCOUNT_UNUSED_ACCESS":
                found["unused"] = a["arn"]
    return found


def active_findings(client, analyzer_arn):
    """All ACTIVE findings for an analyzer (v2 findings API)."""
    results = []
    paginator = client.get_paginator("list_findings_v2")
    for page in paginator.paginate(
        analyzerArn=analyzer_arn,
        filter={"status": {"eq": ["ACTIVE"]}},
    ):
        results.extend(page.get("findings", []))
    return results


def scan_wildcard_policies(iam):
    """Customer-managed policies whose default version grants Action '*'."""
    flagged = []
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):  # Local = customer managed
        for pol in page["Policies"]:
            ver = iam.get_policy_version(
                PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"]
            )["PolicyVersion"]["Document"]
            stmts = ver.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]
            for s in stmts:
                if s.get("Effect") != "Allow":
                    continue
                actions = s.get("Action", [])
                actions = [actions] if isinstance(actions, str) else actions
                if "*" in actions:
                    flagged.append(pol["PolicyName"])
                    break
    return flagged


def md_table(headers, rows):
    if not rows:
        return "_None found._\n"
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out) + "\n"


def build_report(region):
    aa = boto3.client("accessanalyzer", region_name=region)
    iam = boto3.client("iam", region_name=region)

    analyzers = discover_analyzers(aa)
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# IAM Audit Report (US 1.1 / MH-5)",
        f"_Generated: {now} -- region: {region}_\n",
        "## 1. Unused permissions (least-privilege candidates)",
    ]

    if "unused" in analyzers:
        rows = []
        for f in active_findings(aa, analyzers["unused"]):
            rows.append([
                f.get("findingType", "?"),
                (f.get("resource") or "?").split("/")[-1],
                f.get("findingDetails", [{}])[0].get("unusedAction", {}).get("action", "")
                if f.get("findingDetails") else "",
                f.get("updatedAt", ""),
            ])
        lines.append(md_table(
            ["Type", "Principal", "Sample unused action", "Last updated"], rows))
    else:
        lines.append("_Unused-access analyzer not found. Deploy the Terraform first._\n")

    lines.append("## 2. External / public / cross-account access")
    if "external" in analyzers:
        rows = []
        for f in active_findings(aa, analyzers["external"]):
            rows.append([
                f.get("resourceType", "?"),
                (f.get("resource") or "?").split(":")[-1],
                "PUBLIC" if f.get("isPublic") else "cross-account",
            ])
        lines.append(md_table(["Resource type", "Resource", "Exposure"], rows))
    else:
        lines.append("_External-access analyzer not found. Deploy the Terraform first._\n")

    lines.append("## 3. Policies using banned wildcard action `*` (feeds US 1.2)")
    flagged = scan_wildcard_policies(iam)
    lines.append(md_table(["Customer-managed policy"], [[p] for p in flagged]))

    lines.append(
        "\n---\n*Next action:* archive justified external findings via the "
        "`documented_external_principals` Terraform var; rewrite wildcard policies "
        "into scoped actions (US 1.2)."
    )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Generate the US 1.1 IAM audit report.")
    ap.add_argument("--region", default="eu-west-1")
    ap.add_argument("--out", default="iam_audit_report.md")
    args = ap.parse_args()

    try:
        report = build_report(args.region)
    except (ClientError, BotoCoreError) as e:
        sys.exit(f"AWS error: {e}")

    with open(args.out, "w") as fh:
        fh.write(report)
    print(f"Report written to {args.out}")


if __name__ == "__main__":
    main()
