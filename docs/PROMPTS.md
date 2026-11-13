# Prompt pack

Starting points for the `remedigenius` profile in Hermes chat — the dashboard Chat tab, or
`/chat?profile=remedigenius`. These are example requests, not scripted answers. The desk reads your committed
scan, so what it can say depends on your sources, permissions and knowledge. For exact coverage use
`/triage coverage`, never a paraphrase. [Response contract](RESPONSE-CONTRACT.md) · [Limits](LIMITS.md)

## Morning triage

| Prompt | What you get |
| --- | --- |
| `What needs my attention?` | P1-first queue: grouped issues, scoring reasons, what changed since the last scan, blind spots, one next step. |
| `Brief me in 150 words.` | The same briefing, compressed: scan time, priority counts, the top issue, the material gap, one next step. |
| `What changed since the last scan?` | New, resolved and re-scored issues with the observation times. |
| `What are the top 3 P1 issues, and why?` | The three highest-ranked issues with the written scoring reasons — not a re-ranking. |
| `Show me just the S3 issues.` | A short numbered list filtered to one resource type or topic, instead of the whole board. |
| `Show the board card.` | The compact 46-column card: counts, priority bars, coverage, fixes in flight, next step. |
| `/triage` | The attention board without a model call. |
| `/triage coverage` | The deterministic account/region/source report. Denied, disabled, partial and unavailable scopes stay visible. No model call. |

A quiet board isn't proof an account is safe — check the coverage line first.

## Coverage and blind spots

| Prompt | What you get |
| --- | --- |
| `Which accounts and regions can you read?` | Authenticated accounts, findings-only access, uncovered accounts and unscanned regions — from stored onboarding evidence. |
| `Which sources are off or denied?` | The exact per-source status table: `ok`, `not_enabled`, `denied`, `not_available`, `partial`, `error` kept separate. |
| `Is this account clean?` | An honest no: a quiet board means nothing was reported where the desk looked. It names the coverage gaps instead of a clean bill. |
| `What can't you see?` | The blind spots: disabled sources, unreadable accounts, regions with resources outside the scan, and what each would take to fix. |

## Explain or verify a finding — or any configuration

| Prompt | What you get |
| --- | --- |
| `Why is this issue P1? Show the evidence.` | The finding details and the written scoring reason, with the source observations. |
| `Is this finding real? Verify it live.` | The decisive read-only checks from the evidence guide, then a verdict: confirmed, contradicted, or not confirmed — with what would settle it. |
| `Who can assume <role name>?` | The trust policy read live, principal by principal, with the conditions that actually apply. Works without a finding. |
| `Can <principal> do <action>?` | An IAM policy simulation including SCPs, plus the policy documents behind it — not a guess from the policy name. |
| `Which roles trust outsiders?` | A list-then-read pass over role trust policies; external principals named with the exact trust statement. |
| `Is this bucket public?` | The public-access block, bucket policy and ACL reads, with the field values quoted. |
| `Is this actually exploitable, or just a policy gap?` | An evidence-backed distinction between what configuration allows (could) and what logs show (did). Verification stays pending until supported. |

## Investigate activity

| Prompt | What you get |
| --- | --- |
| `investigate <issue id>` | Bounded read-only CloudTrail/IAM/GuardDuty reads and a verdict that separates reported activity from configuration risk. |
| `Was this expected activity or a compromise?` | Actor, user agent, source IP and timing from the logs; a verdict of likely expected, suspicious, compromise indicators, or can't tell yet — and what only you can confirm. |
| `What did this access key do recently?` | CloudTrail management events for the key (90-day window, one region per call), with the data-event limit stated. |
| `Show the timeline for this finding.` | The finding's committed history: first/last seen, observations and decisions, from durable storage. |

Investigation is read-only. CE never applies cloud remediation.

## Propose a fix (you review it)

| Prompt | What you get |
| --- | --- |
| `Propose a fix for this issue. Check for matching IaC first.` | A reviewed procedure, or a proposed IaC change when matching code is found in your configured repositories. Without IaC, the operator CLI/console fix plus a snippet to bring the resource under code. |
| `fix <issue id> — our Terraform is in /data/iac/infra` | Code location, diff and `terraform validate` result; rollback notes. You apply it through your own change process. |
| `What would this fix break?` | The computed blast radius from observed traffic, and the safe-to-fix verdict — named breaks, not a prose guess. |
| `Plan a fix for the whole issue group.` | A typed intent plan (one owner, capped targets) judged by the desk's deterministic gates; every gate result shown verbatim. Nothing executes. |
| `Who needs to act, and what closes this?` | The closure route per finding: owner, how the change reaches AWS, and the proof that closes it. |
| `Open a task for me to review.` | A human-owned Kanban card with investigation, fix and verification context. No agent ever works the card. |
| `Open a PR for this fix.` | With GitHub connected and your approval: validation on a copy, a feature branch, one PR into your development branch. It can't approve or merge. |

## Teach the desk your organization

| Prompt | What you get |
| --- | --- |
| `Set up business context.` | The ten-minute setup: accounts, critical applications, owners, IaC locations and one policy — each answer becomes a draft you approve in the Knowledge tab. |
| `Who owns payments-db?` | An answer from reviewed knowledge with the concept it used; if nobody knows yet, it asks you once and drafts the answer for review. |
| `Use our ownership and business-criticality rules.` | Priorities informed by reviewed organization knowledge, with citations. |
| `That bucket is a public website — accept the risk.` | A recorded risk acceptance, after you approve the prompt. Matching findings leave the board until the expiry you set. |
| `What knowledge would change priorities?` | The ranked gaps: unowned P1/P2 resources, accounts without a criticality, missing teams — and which concept type fills each. |
| `Search the knowledge base for <topic>.` | Matching concepts with their trust tier; unreviewed material is labelled as such. Imported references and your own concepts alike. |

Maintain applications, accounts, teams and accepted risks in the Knowledge tab.

## Onboard and connect

| Prompt | What you get |
| --- | --- |
| `Help me onboard the other accounts.` | The onboarding report — organization, administrators, authenticated vs uncovered accounts — and the exact reviewed StackSet commands to deploy the read roles. It never deploys them itself. |
| `Connect our GitHub repository.` | A walk-through of the GitHub tab: create the app, install it on one repository, pick the branch and reviewers. Two clicks on github.com; no tokens in chat. |
| `Add eu-central-1 to the scan.` | The proposed `regions:` change for triage.yaml, for you to save — scope changes are confirmed once and recorded. |
| `Alert me when new P1/P2 findings appear.` | The scheduled watch command (no model cost; silent when nothing is new) for you to run or confirm. |

## History and trends

| Prompt | What you get |
| --- | --- |
| `Show the history of this finding.` | Current facts and committed history from durable storage — observations, decisions and verification attempts, with timestamps. |
| `What's the finding trend over 30 days?` | Bounded Athena aggregates (trend plus coverage) with query and snapshot provenance. Needs the analytics connection configured; a disabled or denied connection is reported as a gap, never as zero findings. |

## Share what worked

Tried a prompt that helped — or one that didn't? Post it in
[Discussions](https://github.com/RajaRenga/RemediGenius-CE/discussions) (redact account ids, ARNs and bucket
names), or open a [first-run friction issue](https://github.com/RajaRenga/RemediGenius-CE/issues/new/choose).
Real prompts from real accounts are how this pack grows.