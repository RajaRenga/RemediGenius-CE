# Prompt pack — copy, paste, adapt

Starting points for the `remedigenius` profile in Hermes chat (dashboard **Chat** tab, or
`/chat?profile=remedigenius`). These are example requests, not scripted answers: the desk reads your
committed scan, and what it can say depends on your sources, permissions and knowledge. Exact coverage
always comes from `/triage coverage`, never from a paraphrase. [Response contract](RESPONSE-CONTRACT.md) ·
[Limits](LIMITS.md)

## Morning triage

| Prompt | What you get |
| --- | --- |
| `What needs my attention?` | P1-first queue: grouped issues, scoring reasons, what changed since the last scan, blind spots, one next step. |
| `What changed since the last scan?` | New, resolved and re-scored issues with the observation times. |
| `/triage coverage` | The deterministic account/region/source report. Denied, disabled, partial and unavailable scopes stay visible. No model call. |
| `/triage` | The attention board without a model call. |

A quiet board is not proof an account is safe: check the coverage line first.

## Investigate one issue

| Prompt | What you get |
| --- | --- |
| `Why is this issue P1? Show the evidence.` | The finding details and the written scoring reason, with the source observations. |
| `investigate <issue id>` | Bounded read-only CloudTrail/IAM/GuardDuty reads and a verdict that separates reported activity from configuration risk. |
| `Is this actually exploitable, or just a policy gap?` | An evidence-backed distinction; verification stays pending until supported. |

Investigation is read-only. CE never applies cloud remediation.

## Propose a fix (human review required)

| Prompt | What you get |
| --- | --- |
| `Propose a fix for this issue. Check for matching IaC first.` | A reviewed procedure, or a proposed IaC change when matching code is found in your configured repositories. |
| `fix <issue id> — our Terraform is in /data/iac/infra` | Code location, diff and `terraform validate` result; rollback notes. You apply it through your own change process. |
| `Open a task for me to review.` | A human-owned Kanban card with investigation, fix and verification context. |

With GitHub configured **and explicit authorization**, CE can open a fix PR. It cannot approve or merge it.

## Teach the desk your organization

| Prompt | What you get |
| --- | --- |
| `Who owns payments-db?` | An answer from reviewed knowledge with the concept it used; if nobody knows yet, it asks you once and drafts the answer for review. |
| `Use our ownership and business-criticality rules.` | Priorities informed by reviewed organization knowledge, with citations. |
| `That bucket is a public website — accept the risk.` | A recorded risk acceptance, after you approve the prompt. |

Maintain applications, accounts, teams and accepted risks in the dashboard **Knowledge** tab.

## Share what worked

Tried a prompt that helped — or one that failed? Post it in
[Discussions](https://github.com/RajaRenga/RemediGenius-CE/discussions) (redact account ids, ARNs and bucket
names), or open a [first-run friction issue](https://github.com/RajaRenga/RemediGenius-CE/issues/new/choose).
Real prompts from real accounts are how this pack grows.