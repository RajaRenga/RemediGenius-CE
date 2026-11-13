# Start here

RemediGenius-CE adds one Hermes profile, `remedigenius`, that opens every conversation on your AWS security
attention board. You talk to it the way you'd talk to a colleague who has already read the findings:

- "what needs attention?" → P1 first, what changed since the last scan, the blind spots, one next step
- "investigate 3f9c2a7b1d04" → bounded read-only CloudTrail/IAM/GuardDuty reads and a verdict
- "fix 8e41d0c9a6b2 — our Terraform is in /data/iac/infra" → code location, a diff, `terraform validate`, rollback
- "that bucket is a public website, accept the risk" → recorded once you approve the prompt
- "who owns payments-db?" → answered from the knowledge base with the concept it used; if nobody knows yet, it
  asks you once and drafts the answer for review
- `/triage` → the board without a model call

## Choose a path

Hermes supplies the model connection, conversations, skills, scheduling and approvals. CE adds deterministic
ranking, explicit coverage gaps, durable evidence and decisions, and reviewable IaC proposals. The payoff is a
repeatable triage workflow whose evidence lives in your storage and whose decisions you can look up later. A
generic AWS chat can answer one-off questions; CE keeps the queue and the reasoning across sessions. It doesn't
add detectors, replace your AWS security services, or tell you an account is secure.

| | Docker workstation | AWS Spot |
| --- | --- | --- |
| Runs on | your machine (Docker Desktop or Linux Docker) | one Spot instance in your account |
| AWS access | your AWS profile, or (recommended) a read-only role you name | a read-only audit role created by the stack |
| Durable storage | a folder on your machine (`~/RemediGenius-CE`) | a private S3 bucket created by the stack |
| Dashboard | `http://127.0.0.1:9125` | SSM port-forward to `http://127.0.0.1:9125` |
| Guide | [docs/WORKSTATION.md](docs/WORKSTATION.md) | [deploy/aws-single/README.md](deploy/aws-single/README.md) |

Already running Hermes 0.23.1? Start with [docs/LOCAL-HERMES.md](docs/LOCAL-HERMES.md): check compatibility,
reuse your model configuration, connect an AWS profile and run the first scan. On other versions, the pinned
Docker workstation runs alongside your existing install without changing it.

## What "ready" means

- The dashboard opens on the `remedigenius` profile with a model configured (validated: `deepseek-v4.1-flash`).
  Without a working model key the desk still scans, but it can't chat. Never paste a key into chat.
- The first scan has run — about 3 minutes after start, then every 6 hours. `/triage` shows it.
- `rgtriage doctor` reports durable storage healthy (a commit watermark, no buffered raw objects). If it says
  degraded or blocked, read [docs/RECOVERY.md](docs/RECOVERY.md) before you rely on an answer.
- Coverage lines say which sources were read. "Not enabled" or "access denied" is a blind spot, not a clean result.
- In an Organization, the `Accounts:` line says how many accounts are read fully, findings-only, or not covered.
  Other accounts need one read-only role, deployed once as a StackSet. Ask the agent "help me onboard the other
  accounts" (or run `rgtriage onboarding`) for the filled-in command; they're picked up at the next scan, no
  restart. See [docs/MULTI-ACCOUNT.md](docs/MULTI-ACCOUNT.md).

## Before you rely on it

Read [docs/LIMITS.md](docs/LIMITS.md) for what is and isn't covered and what reaches your model provider. Then
tell the desk what matters: open the Knowledge tab. *Overview → What the desk is missing* lists the gaps that
change priorities — unowned P1/P2 resources, accounts without a description. Add applications, accounts, teams
and accepted risks, import your runbooks and policies, and approve what the agent drafts
([docs/KNOWLEDGE.md](docs/KNOWLEDGE.md)). IaC repository paths and regions stay in `triage.yaml`.