---
type: Playbook
title: Threat findings (GuardDuty, security CloudWatch alarms)
description: 'Triage GuardDuty and security alarm findings: who, what, when, expected or not; containment the operator runs.'
tags:
- threat
- guardduty
- incident
sources:
- id: types
  resource: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
  title: GuardDuty finding types
  author: aws-documentation
- id: role-sessions
  resource: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
  title: Revoke IAM role temporary security credentials
  author: aws-documentation
- id: identity-center-revoke
  resource: https://docs.aws.amazon.com/singlesignon/latest/userguide/revoke-user-permissions.html
  title: Revoke user access in IAM Identity Center
  author: aws-documentation
- id: identity-center-portal
  resource: https://docs.aws.amazon.com/singlesignon/latest/userguide/end-active-sessions.html
  title: View and end active sessions for workforce users
  author: aws-documentation
generated:
  by: remedigenius-ce/0.3.0
  at: '2026-10-21T00:00:00Z'
---

# Threat findings (GuardDuty, security CloudWatch alarms)

GuardDuty detects behavior, not configuration. High `event_count`, recent last-seen, unknown IPs/ASNs and
sensitive resources raise urgency. `*/AnomalousBehavior*` findings compare against the principal's baseline:
a legitimate user running a new tool, script or Terraform also triggers them.

**Triage questions (answer from evidence first; ask the user only what you cannot see):**
1. Who: principal, access key, user agent, source IP / ASN / country (`context.actor`).
2. What: API calls, target resource, volume; is the resource sensitive (tags, goals)?
3. When: first/last seen; still ongoing?
4. Expected? The user, CI, or a known tool? Ask once and record the answer with `rgtriage decide`.

**Read-only investigation:**
- `rgtriage aws cloudtrail lookup_events --params '{"LookupAttributes":[{"AttributeKey":"AccessKeyId","AttributeValue":"AKIA..."}],"MaxResults":50}' --region <r>`
- `rgtriage aws guardduty get_findings --params '{"DetectorId":"...","FindingIds":["..."]}'` for full detail.
- `lookup_events` returns management events only (90 days). S3 object-level data events are not included; say so.

**Containment options (operator decides and runs; never automatic):**
First establish the credential type, affected scope and evidence of unauthorized activity. A person not yet
answering a confirmation question is not evidence of compromise. Preserve evidence and keep the verdict open.
For confirmed unauthorized activity or an applicable incident-response policy:
- IAM key: `aws iam update-access-key --user-name U --access-key-id K --status Inactive`
- Ordinary assumed role: prevent new unauthorized assumptions and use the AWS role-session revocation procedure
  for already issued sessions. Revocation may affect other users of the role; review that blast radius.
- Identity Center: permission-set roles require the Identity Center procedure, not editing the managed role
  as an ordinary IAM role. Review the prepared user-scoped deny procedure and its SCP/account prerequisites
  to contain existing permissions; separately address assignments and new sign-in. Do not assume SCP coverage
  applies to the management account. Ending an access-portal session does not end existing AWS role sessions.
  If the necessary control is unavailable, escalate to the incident owner and report containment pending.
- Waiting for a temporary credential to expire is not active containment. Removing an assignment does not
  prove previously issued sessions lost access. Do not present either as sufficient incident remediation.
- EC2: attach an isolation security group with no rules; snapshot volumes for forensics first.
- S3: add a temporary bucket-policy Deny for the suspicious principal.

**Verification:** propose an independent read of the deployed control, including its affected principal,
accounts, conditions and effective time. Label policy-readback as configuration evidence, not proof that every
session or possible access path has been tested. The operator's authorized incident process must confirm effective
containment and continuing monitoring. No events in a bounded log window, finding archival, disappearance from
a new scan, or starting with an empty CE store proves revocation or safety. Keep verification pending when
evidence is incomplete. Never test by collecting or using the suspected actor's credentials.

**Close-out:** expected activity with corroborating evidence and human approval →
`rgtriage decide <ref> false_positive --reason "..."`. A partial timeline still leaves unknown activity;
do not promise that one confirmation automatically closes the incident. For recurring benign
patterns, propose a narrowly scoped suppression rule in IaC (`aws_guardduty_filter` with `action = "ARCHIVE"`,
criteria on finding type + principal + resource).

**Related:** [guardduty findings](/remedigenius/sources/guardduty.md) · [cloudwatch findings](/remedigenius/sources/cloudwatch.md) · [where to look](/remedigenius/guides/where-to-look.md) · [how the desk works](/remedigenius/guides/how-the-desk-works.md)
