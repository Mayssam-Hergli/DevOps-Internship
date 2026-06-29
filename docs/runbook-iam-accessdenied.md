# Runbook -- Bug 1 (MH-13 / MH-28): Legitimate access blocked after Least Privilege

**Symptom.** After tightening an IAM policy (US 1.2), an application, role, or
developer starts getting `AccessDenied` on an action they legitimately need
(commonly S3, DynamoDB, KMS).

**Root cause.** The new restrictive policy omits a specific action or a *dependent*
action (e.g. `kms:GenerateDataKey` behind an S3 `PutObject` on an encrypted bucket).

> Golden rule: fix it by **adding the one missing scoped action**, never by
> re-introducing a wildcard. Re-opening `"*"` reintroduces the vulnerability the
> sprint just removed.

---

## Step 1 - Find the exact denied call in CloudTrail

CloudTrail records every `AccessDenied`. Pick the path that matches your setup.

**A. CloudTrail delivered to CloudWatch Logs** -- Logs Insights query:

```
fields @timestamp, userIdentity.arn, eventSource, eventName, errorCode, requestParameters
| filter errorCode = "AccessDenied" or errorCode = "Client.UnauthorizedOperation"
| sort @timestamp desc
| limit 50
```

**B. CloudTrail delivered to S3** -- Athena query:

```sql
SELECT eventtime, useridentity.arn, eventsource, eventname, errorcode, errormessage
FROM cloudtrail_logs
WHERE errorcode = 'AccessDenied'
  AND eventtime > to_iso8601(current_timestamp - interval '2' hour)
ORDER BY eventtime DESC
LIMIT 50;
```

**C. Quick check** -- CloudTrail console > Event history > filter
`Error code = AccessDenied`.

You are looking for three things in the matching event:
`eventSource` (the service), `eventName` (the API action), and the resource ARN in
`requestParameters`.

## Step 2 - Map the API call to the IAM action

`eventSource` + `eventName` translate to the IAM action. Examples:

| eventSource | eventName | Missing IAM action |
|---|---|---|
| s3.amazonaws.com | PutObject | `s3:PutObject` (+ `kms:GenerateDataKey` if SSE-KMS) |
| dynamodb.amazonaws.com | Query | `dynamodb:Query` |
| kms.amazonaws.com | Decrypt | `kms:Decrypt` |

If the resource is KMS-encrypted, expect a paired `kms:GenerateDataKey` /
`kms:Decrypt` requirement -- this is the most common hidden dependency (and is
exactly Bug 2 in the cahier).

## Step 3 - Confirm with the IAM Policy Simulator (optional, no blast radius)

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<acct>:role/<role> \
  --action-names s3:PutObject \
  --resource-arns arn:aws:s3:::<bucket>/<key>
```

`implicitDeny` confirms the missing grant.

## Step 4 - Add the minimal scoped action

Edit the role's policy document in `modules/iam-least-privilege` -- add the
specific action, scoped to the specific resource ARN:

```hcl
statement {
  sid       = "AllowAppPutObjects"
  effect    = "Allow"
  actions   = ["s3:PutObject"]
  resources = ["arn:aws:s3:::my-app-bucket/*"]   # scoped, never "*"
}
# If the bucket uses SSE-KMS, also grant on the specific key:
statement {
  sid       = "AllowDataKeyForBucket"
  effect    = "Allow"
  actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
  resources = ["arn:aws:kms:eu-west-1:<acct>:key/<key-id>"]
}
```

Then `terraform plan` (review the diff is purely additive) and `terraform apply`.

## Step 5 - Re-test and verify

Re-run the failing action. Re-run the simulator from Step 3 -> expect `allowed`.

---

## Prevention (do this once, avoid the whole class of bug)

- **Generate policies from real usage.** IAM Access Analyzer can build a
  least-privilege policy from CloudTrail history, so you start from what the
  workload actually calls:
  `aws accessanalyzer start-policy-generation ...` then `get-generated-policy`.
- **Stage the rollout.** The permissions boundary stays broad while role policies
  tighten, so a missed action degrades gracefully instead of hard-breaking prod.
- **Alarm on denials.** A CloudWatch metric filter on `AccessDenied` -> SNS gives
  you the signal in minutes (this reuses the Epic 4 EventBridge->SNS pipeline).
