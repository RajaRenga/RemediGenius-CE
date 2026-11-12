---
name: rg-onboard
description: Onboard AWS accounts for triage - authenticated readers, regional service membership, actual collection coverage and reviewed role setup; set business context and scheduled alerts.
license: Apache-2.0
---
# Onboarding and access

The triage profile is `triage.yaml` in the rgtriage home folder (path shown by `rg_triage action=doctor`).
It is the operator's file; you explain and propose edits, the operator saves them (or you write a
proposed copy under the proposals folder for them to move).

## 1. Check what works
For managed AWS MCP transport and connection failures, read `rg-capabilities/references/aws-connection.md`.
The desk can reuse the configured audit role without exposing credentials or general script tools to the agent.
For documentation, Terraform guidance and document-source connections, load `rg-capabilities`. Start with the
capability needed for the user's task; use Knowledge → Sources and native Hermes onboarding, then prove one real
read in a fresh chat. Those connections do not extend the AWS account coverage described below.

`rg_triage action=doctor` → identity per account, and per source/region: `ok`, `not_enabled`,
`denied`, `error`, plus recommendations. Explain blind spots in plain terms:
- Security Hub off → no posture checks (CIS/FSBP). GuardDuty off → no threat detection.
- Inspector off → no CVE findings. Config off → no change history (and Config.1 fails).
- `denied` → inspect the affected account, region and API. Check identity policy, SCPs, permission boundaries and
  resource policies. Adding SecurityAudit or redeploying a reader cannot override an explicit deny. Do not recommend
  a policy reapply unless evidence identifies a missing grant; preserve intentionally prohibited regions as gaps.
- `iam simulate_principal_policy` or Access Analyzer `check_*` denied → check whether the read role has the evaluation
  grant and whether an explicit restriction blocks it. A missing grant needs a reviewed template update; a denial
  alone does not prove the role is old.
- An AWS read refused with "Several accounts are readable" → pass `account`; a read in the wrong account is not
  evidence about this one.
- Health `SubscriptionRequired` → Health API needs Business support; Health events still arrive via Security Hub.

## 2. Other AWS accounts (onboarding is automatic after one setup step)
`rg_triage action=onboarding` → organization, whether this account is the Security Hub / GuardDuty / Inspector
registered delegated administrators, regional service member views, and every known account as **authenticated**,
**findings-only access** (member view, read role unavailable) or **not covered**, plus filled-in next steps.

Authentication does not prove complete service coverage. Use the scan's account/region/service coverage matrix.
Report discovery errors as unknown; never say there is no administrator just because ListMembers was denied.
Distinguish Organizations delegation from invitation-based member relationships and from successful collection.
Explain findings-only access separately from the member role needed for CloudTrail, IAM and resource investigation.

When accounts are missing, give the user the exact command from `next_steps`. Do not invent values; the desk fills in
the desk identity ARN and organization id. Tell them:
- Run it once, with management-account (or StackSets delegated administrator) credentials, from the release folder.
- It deploys `RemediGeniusReadOnly` (SecurityAudit + ViewOnlyAccess + explicit membership discovery + IAM policy simulation and Access Analyzer policy
  checks, denies secret/object/KMS reads) to every account,
  including accounts added later (auto-deployment).
- Inspect existing roles and their owning stacks first; AccessDenied does not prove a role is missing. The runtime
  caller must allow AssumeRole, and each target must trust that runtime identity, not its audit role. An unresolved
  AROA principal can indicate deleted-role trust. Review SCPs/boundaries and the discovery policy in docs/MULTI-ACCOUNT.md.
  Existing audit roles need the discovery supplement too; Python updates do not change IAM. The next scan tries every
  account where the role works. Offer to run `scan` once they say it is deployed, then run
  `onboarding` again to confirm.
- StackSets skip the management account; deploy the template there as a normal stack if it should be covered.

For a complete customer-specific review packet, direct the operator to docs/ACCESS-QUICKSTART.md in the matching
source checkout. `tools/prepare_access.py` consumes their onboarding JSON and explicitly selected target accounts,
then writes offline trust/policy files and deployment instructions. It does not change AWS. Support per-account
stacks, organization StackSets, and StackSets delegated deployment without assuming the security administrator
is also authorized to deploy StackSets. Keep the generated account identifiers and role ARNs private.

Separate administrator accounts can be configured with read roles; every configured region must be checked.
Include the Security Hub home region explicitly. Existing membership and service enablement determine the actual
findings view; delegation is optional for direct member reads. If the account is not in an organization, follow the standalone step in
`next_steps` (one stack per account, then list it under `accounts:` with its `role_arn`).
<!-- PROTECTED_START -->
You never deploy roles or run the command yourself; you are read-only.
The tool blocks every non-read AWS call even if the credentials could write.
<!-- PROTECTED_END -->

## 2a. Confirm the scope once
Discover this installation's landscape; never assume the account count, region list, organization membership
or delegated-administrator arrangement from a tutorial or previous test. A standalone account is valid.
Configured accounts and per-account region overrides are the approved collection scope. Discovery can add
readable organization accounts; enabled-region footprint discovery identifies gaps but does not authorize
silently collecting every region. If Organizations or regional discovery is denied, preserve configured scope
and report unknown coverage instead of inventing an organization or treating all other regions as clean.
The board's "Inspected:" line and `footprint` say which regions are enabled and which hold resources outside the scan.
Show authenticated accounts, actual service coverage, findings-only access, uncovered accounts and unscanned regions.
Ask once: "Are these all your accounts and regions that matter?" Record the answer as a Note concept
(`knowledge/notes/scope.md`: what is in scope, what is deliberately out, who confirmed, the date) and call
`rg_triage action=remember path=<draft>`. If they want more regions, show the `regions:` change for `triage.yaml`.

## 2b. Connect a code repository (so fixes can become pull requests)
If the user wants fixes opened as pull requests, or asks to connect their repo or GitHub: call `rg_triage action=github op=status`, then send
them to the **GitHub tab** in this console (left menu) and say what they will do there: click **Connect GitHub** (two clicks on github.com:
create the app, then install it on only the repository they choose), then pick the repository, the development branch and the human
reviewers. The page shows which protections are in place and what is still missing, and has Reconnect and Disconnect buttons.
- You cannot connect GitHub for them, and never ask for tokens, keys or passwords in chat; the connection is made on that page.
- Pull requests need branch protection on GitHub (a required review, no force push). On a repository that cannot have it (for example a
  private repository on GitHub's free plan) the page says so and the desk stays read-and-propose only.
- Once connected, `op=refresh` re-reads their development branch after they change the repository.

## 3. Business context in ten minutes (changes priorities)
When the board says "Business context: N of 5 basics set", offer this. Prefill from read-only evidence, then ask the
user to confirm in a few short answers; each confirmed fact becomes a draft plus `remember` (one click each):
1. Accounts: `organizations list_accounts` (management or delegated account) or the configured accounts. Ask which
   are production / mission critical → Account concepts.
2. Critical applications: `resourcegroupstaggingapi get_tag_keys`, then `get_tag_values` for keys like `app`,
   `Application`, `Project`, `service`. Suggest the values behind the most findings; ask for the top 1–3 →
   Application concepts with `match_tags`.
3. Owners: `owner`/`team` tag values and CODEOWNERS in the configured IaC repositories (`read_file`); ask for a
   contact per application → Team concepts.
4. IaC locations: `rg_triage action=doctor` lists them; if none, show the `iac_paths` change for `triage.yaml`.
5. One policy: offer "no SSH from the internet" or "production buckets never public" → Policy concept.
Keep it to these five; more can come later. Do not ask about anything the evidence already answers.

## 3b. Business context, the long form
Business context lives in the knowledge base (load `rg-knowledge`). Start from `rg_triage action=knowledge view=gaps`
and ask briefly, one question at a time, only what changes ranking:
- Which accounts are production / mission critical? → an Account concept draft.
- Which applications matter most, how are their resources tagged, who owns them? → Application and Team drafts.
- Top 1–3 goals in plain words (e.g. "protect customer PII in S3") → a Security Goal draft.
Write drafts under the proposals folder's `knowledge/` and tell the user to approve them in the dashboard
**Knowledge** tab (or to use its Add form directly); approved concepts apply at the next `scan`.
`triage.yaml` keeps the technical settings: regions, `iac_paths` (local clones of Terraform/CloudFormation/CDK repos),
`environment_tag_keys`, sources and limits. Show any YAML change for the user to save.

## 4. Bring findings to the user without being asked
- Every new session opens with the attention board (plugin), refreshed in the background when stale.
- Scheduled alert with no model cost (Hermes cron runs the script; empty output = silent):
  `hermes -p <profile> cron create "every 2h" --name security-watch --no-agent --script rgtriage-watch.py --deliver <telegram|local|...>`
  (`rgtriage watch` prints only NEW P1/P2 findings.) The installer creates the script.
- Daily briefing with the agent (uses the model):
  `hermes -p <profile> cron create "0 8 * * 1-5" "Brief me on the security attention board" --skill rg-triage --deliver <target>`
Creating schedules changes the user's system: show the command and let the user run it or confirm.
