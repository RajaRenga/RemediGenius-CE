---
name: rg-investigate
description: Investigate suspicious activity - GuardDuty threats, security alarms, unexpected API calls, credential or role misuse - with read-only AWS evidence (CloudTrail, IAM, EC2, S3) and conclude expected vs compromise, with actors and a timeline. Not for checking whether a configuration finding is accurate (rg-triage) or writing fixes (rg-iac-fix).
license: Apache-2.0
---
# Investigate a threat or alert

Goal: decide **expected activity vs. possible compromise** fast, with evidence, and tell the user
what to do next. Use when the question is about *activity*: who did it, was it expected, is it still happening.
A question about how something is *configured* ("who can assume this role?") belongs to `rg-triage`.

Stop when the verdict is supported or the missing evidence is named. Most cases need 2–5 AWS reads; read more only
for a contradiction, a new indicator or a broader request, and say why. Pass the finding's `account` and `region` on
every read; IAM, STS and Organizations events are in us-east-1. Evidence guide:
`remedigenius/guides/evidence-detection-and-history.md`.

## Steps
1. `rg_triage action=show ref=<ref>` — read actor (principal, access key, IP, ASN, country, API),
   event count, first/last seen, resource, related findings.
   Load `rg_triage action=playbook name=threat-response` before proposing containment; use the returned
   guidance and provider references. Distinguish long-lived IAM keys, ordinary assumed roles, Identity Center
   permission-set sessions and root credentials. A temporary access-key identifier is not a long-lived IAM key.
2. Pull the evidence that answers "who/what/when" (pick only what is needed):
   - Recent calls by that key: `rg_triage action=aws service=cloudtrail operation=lookup_events
     parameters={"LookupAttributes":[{"AttributeKey":"AccessKeyId","AttributeValue":"<key>"}],"MaxResults":50}`
   - By user name (root shows as `root`): `AttributeKey: Username`.
   - On a resource: `AttributeKey: ResourceName`, value = bucket/instance id.
   - IAM context: `iam get_user`, `iam list_access_keys`, `iam get_access_key_last_used`; what the principal could
     do comes from policy documents or `iam simulate_principal_policy`, never from policy names.
   - EC2 context: `ec2 describe_instances`, `ec2 describe_security_groups`.
   - Full GuardDuty record: `guardduty get_findings` with DetectorId and FindingIds from the native id
     (`arn:...:detector/<DetectorId>/finding/<FindingId>`).
3. Read CloudTrail fields that decide the case: `userAgent` (Terraform? console browser? aws-cli? SDK
   in a script?), `sourceIPAddress` (matches the user's other activity?), `sessionCredentialFromConsole`,
   `mfaAuthenticated`, error codes, time pattern.
4. Keep **could** (what configuration allows) apart from **did** (what logs show). Exfiltration, lateral movement
   and "before the history" questions usually end at an evidence boundary: say "not established", name it, and give
   the next step from `remedigenius/guides/beyond-the-desk.md` (an Athena or CloudTrail Lake query for the operator to
   run, S3 data events, flow logs, Detective, AWS Security Incident Response for an active incident). Attack-path
   reasoning is a hypothesis unless a read or an AWS exposure finding supports it.
5. Conclude in this shape:
   ```
   Verdict: likely expected | suspicious | compromise indicators | can't tell yet
   Evidence: 3 bullets with times, IPs, user agents, APIs (observed, quoted from the reads)
   Inferred: your reasoning, labelled as such; no timeline or intent that no read showed
   Gaps: what you could not see (e.g. S3 data events are not in lookup_events; 90-day limit)
   Do now: the exact commands the operator should run (containment, e.g. deactivate/delete the exposed key, revoke sessions) or "nothing", and the long-term fix (load rg-iac-fix when code is involved). Name the playbook you followed.
   ```
<!-- PROTECTED_START -->
6. If only the user can confirm ("was this you running terraform at 14:02 UTC?"), ask once. Propose
   the decision (`false_positive` + reason if expected; `investigating` otherwise) and record it with
   `decide` only after the user confirms. Never record decisions in unattended/scheduled runs.
<!-- PROTECTED_END -->

## Rules
<!-- PROTECTED_START -->
- Read-only. Containment commands are shown for the operator to run, never executed by you.
- A missing confirmation is not evidence of compromise. State a conditional response for confirmed unauthorized
  activity; do not prescribe disabling a user merely because they have not answered. Human confirmation alone
  does not erase contradictory evidence or establish that all activity in a partial timeline was authorized.
- Preventing new sessions and containing existing sessions are separate steps. Use the credential-specific
  procedure in the threat-response playbook; never recommend simply waiting for a suspicious session to expire.
- State a positive, independent proof for each proposed security change. No later events, finding disappearance,
  finding archival and a rescan alone cannot prove session revocation or successful incident containment.
  Report unproven changes as verification pending; do not automatically close the incident or suppress findings.
<!-- PROTECTED_END -->
- `lookup_events` covers management events for 90 days in one region per call. It cannot return S3
  `GetObject`/`PutObject` data events or establish object-read volume. For those, name the required
  enabled data-event trail/Lake or S3 access logs and query that source in place; if absent, state the gap.
- AnomalousBehavior findings flag deviations from a baseline: a person's new tool also triggers
  them. Don't call it an attack without corroboration; don't dismiss it without checking the actor.
- Root activity: console sessions with MFA from the user's usual IP are different from access-key
  calls from an unknown ASN. Either way recommend reducing root use (playbook root-account).
- Always cite the sources your conclusion relies on: the finding ref (native id), the playbook you followed (e.g. root-account, threat-response), and any concept or knowledge used. Never invent a citation.
