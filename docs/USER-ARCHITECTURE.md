# RemediGenius CE: the operator's architecture reference

RemediGenius adds an AWS security triage desk to Hermes. Hermes handles conversations, model calls,
skills and messaging. The desk collects and ranks evidence, checks access, preserves history and
validates proposed IaC changes. You supply AWS access, a model endpoint and the decisions about your environment.

Start with the [interactive diagram index](diagrams/user-reference/index.html). Download the HTML files
to open them locally; GitHub's source viewer does not run the diagrams. Each diagram has editable JSON
and source references pinned to the implementation it describes.

**Version scope:** this reference describes development commit `dcc2abd` after v0.9.0. The existing
compute/storage architecture is already released; the expanded regional/delegated coverage and
`prepare_access.py` onboarding packet are newer work. Use the matching checkout and templates for
those features. These documents do not certify a new release or extend the earlier live-test results.

## 1. Choose where to run it

| Option | Good starting point | Dependencies and boundary |
| --- | --- | --- |
| [Existing Hermes](LOCAL-HERMES.md) | You already run Hermes and want a dedicated profile | Hermes **0.23.1**, a separate desk Python environment, AWS profile and local durable storage. Desk subprocess and Hermes share the user's credential environment. |
| [Docker workstation](WORKSTATION.md) | Local trial with a container boundary | Docker Desktop/Linux containers, pinned image, desk runtime and persistent local storage. Keep the workstation and gateway running for background work. |
| [AWS Spot](../deploy/aws-single/README.md) | An always-available private desk while compute is enabled | One EC2 Spot instance, S3, Glue, IAM, SSM, outbound network access, model configuration; Terraform provisions the stack. |

The AWS path is the subject of the [infrastructure diagram](diagrams/user-reference/infrastructure.html).
It does not require a separate agent in every AWS account, a Kubernetes cluster, Spark, or an external
database server. PyIceberg and Arrow run in the desk process. The standard EC2 deployment also configures
managed AWS MCP investigation and bounded Athena reports; collection and fact commits do not depend on Athena.

Use the pinned versions supplied by the matching release: Hermes 0.23.1, PyIceberg 0.12.0 and
PyArrow 23.0.1. A model is needed for conversational investigation, but `doctor` and deterministic
collection can run without one. The CE installer does not enable paid AWS security services for you.

## 2. What you operate and what CE operates

| Responsibility | Operator supplies or maintains | CE/Hermes does |
| --- | --- | --- |
| Deployment | Provisioning credentials, subnet, reviewed Terraform plan, version selection | Installs the pinned runtime, service units and storage wiring |
| Network | Working egress to required AWS, model and package endpoints; SSM access | Binds the dashboard to loopback; standard stack opens no inbound security-group ports |
| AWS access | Actual runtime identity, selected accounts/regions, target trusts, SCP/boundary review | Assumes scoped readers and reports coverage/access failures |
| Security services | Enablement, account associations, regional configuration and service charges | Reads available findings; does not create detectors or repair delegation |
| Model | Endpoint, credentials, cost and data-handling choice | Hermes performs inference and invokes restricted desk tools |
| Data | Retention, encryption/access policy, recovery ownership and budget | Writes raw evidence, durable facts, readable exports and checkpoints |
| Business context | Owners, application criticality, goals and reviewed exceptions | Applies that context to ranking and explains its reasons |
| Remediation | Review proposals, approve desk decisions, merge and deploy through your process | Finds candidate IaC, proposes changes and runs isolated validation |

Provisioning credentials are not runtime credentials. On EC2 the host identity can use its private
storage, model secret and allowed role assumptions. Audit/member readers inspect assessed AWS resources.
The analytics role has a separate warehouse/query-results purpose. None of this means Hermes receives
your provisioning identity. See [IAM](IAM.md) and [connection boundaries](AWS-CONNECTIONS.md).

The container deployment keeps AWS credentials in the desk, restricts the agent's tools and uses a
Unix socket command allowlist. The isolated validation user runs checks on scratch copies without AWS
credentials. **Native existing-Hermes installation does not provide this process credential isolation.**

## 3. Day-one access for different AWS landscapes

For the exact credential boundary and role-assumption sequence, see [How CE permissions work](PERMISSIONS.md).

Use [Connect your AWS landscape](ACCESS-QUICKSTART.md) for the complete procedure and
[the account-access diagram](diagrams/user-reference/account-access.html) for the trust paths.

1. Install one supported deployment and select your initial account and regions. For a small first
   trial, disable organization discovery until you have reviewed the intended scope.
2. Run `rgtriage onboarding --json` **as the desk runtime**. A successful administrator login on your
   laptop says nothing about the EC2 role's permissions.
3. On the matching development checkout, run `tools/prepare_access.py` against that report and an
   explicit target-account list. It creates an offline private review packet; it makes no AWS calls.
4. Your deployment operator reviews caller policy, exact target trust and discovery grants, then
   deploys through the existing owning stacks or the supplied change-set/StackSet procedure.
5. Configure reader ARNs and regions, then repeat onboarding and scan as the runtime. Inspect every
   required account/region/service scope, including missing, disabled, denied and partial results.

| Landscape | Access arrangement | What still needs checking |
| --- | --- | --- |
| Single account | Local audit role, or your explicit native/workstation read role | Service enablement and regional coverage |
| Organization without security delegation | One runtime; member readers in selected accounts | Both caller AssumeRole permission and target trust, plus organization restrictions |
| Central security account | Reader in that administrator account for associated findings | Per-service membership, home/linked regions and direct member investigation access |
| Different administrators for different services | Configure each required administrator reader and regions | Security Hub, GuardDuty and Inspector are separate relationships |
| Unrelated accounts | Explicit readers and exact trusts per account | Use normal stacks; do not assume organization discovery or service-managed StackSets |

Organization inventory, security-service delegation and resource investigation are three different
capabilities. An account can be known but unreadable. Central findings can be available while IAM,
CloudTrail or resource configuration reads in the member are denied. A security delegated administrator
is not automatically a StackSets delegated administrator. Do not broaden runtime permissions to
deployment administration just to make onboarding convenient.

The collector evaluates regional service routes and retains explicit gaps. It avoids redundant direct
collection only where the central route establishes complete coverage; incomplete or failed routes
need fallback where member access exists. Include the Security Hub aggregation home region in scope.
There is no promise that every service, region or account is covered simply because one role assumed
successfully. The validation record states the live and simulated limits.

## 4. Compute and storage are separate

The instance hosts the desk service, Hermes container, validation service and scan timer. Its SQLite
cache and local scratch work are disposable after durable commits. S3 and Glue retain the data used
to rebuild a replacement. This is separation of lifecycle and authority, not a claim of zero data
on local disk or a distributed multi-writer service.

`deploy/aws-single` is the simple community stack. Set its `running` input to `false` and apply the
reviewed plan to park compute; **do not destroy the entire stack to park it**. Provide your own
deployment settings; sample configuration does not establish account access.

Keep **one active writer per namespace**. Confirm the old writer has stopped before replacement.
While compute is parked, durable files remain readable but there is no background collection, chat
or checkpointing. Storage, retained objects and other enabled AWS services can still cost money.

On replacement, the host retrieves the release source and runtime, restores checkpointed homes,
rebuilds the desk cache from durable facts and starts services. Restore only targets an empty home;
lineage checks prevent an unrelated fresh machine from overwriting a checkpoint it never restored.
See [Recovery](RECOVERY.md) before manual intervention.

## 5. Follow the data

The [data-lifecycle diagram](diagrams/user-reference/data-lifecycle.html) separates evidence,
pending work, committed facts and human-readable results.

| Location | What it contains | How users should treat it |
| --- | --- | --- |
| AWS source services | Live findings, configuration and original log stores | Authority for current AWS state; CE reads bounded evidence rather than migrating all data |
| `raw/` | Gzipped collected response pages and evidence references | Sensitive source evidence; content-addressed within scope/date partitions |
| `warehouse/` + Glue catalog | Iceberg facts, history and current-state tables | Durable desk authority; query with supported readers, never hand-edit Parquet or metadata |
| Local SQLite/outbox | Cached views and uncommitted work | Rebuildable after commits; pending local-only work is not durable |
| `exports/<installation>/` | Latest pointer, per-scan manifest, board HTML, findings and coverage JSON | Downloadable scan snapshots; derived output, not another source of truth |
| `state/` checkpoints | Hermes home, configuration, GitHub state and reviewed knowledge | Private backups; may include conversations, imports and model configuration/secrets |
| `analytics-results/` | Athena query outputs | Private derived data governed by query/output access |
| `source/` | Deployment source archive | Boot input; not the evidence store |

To inspect a committed scan without running Hermes, download `exports/<installation>/latest.json`,
follow its manifest key, then retrieve `board.html`, `findings.json` and `coverage.json`. The manifest
contains hashes, snapshot IDs, watermark and raw references. The pointer is published last, so a
failed export upload does not advertise an incomplete new export. Later decisions do not rewrite an
old scan export; inspect the running desk or the next scan for those decisions.

Iceberg provides structured, snapshot-based tables on object storage, history queries and a recovery
foundation without an always-running database. It is not a live AWS synchronization engine and does
not automatically compact away all repeated observations. Raw evidence is confirmed before associated
facts are trusted. Batch IDs make retry/replay idempotent; separate scans can retain unchanged
observations, and raw objects can repeat across date partitions. Readable exports deliberately add a
small second representation. [Storage](STORAGE.md) and [schema](SCHEMA.md) describe these contracts.

Keep application S3 objects, database contents and complete log archives in their AWS services.
Enable bounded flow-log/CloudTrail usage evidence only when needed and after reviewing its permissions
and query costs. Collecting a finding does not require copying all resources related to that finding.

Raw expiry defaults to 90 days. Iceberg snapshot retention defaults to 14 days with at least five
snapshots retained; expiring snapshots is **not** age-based deletion of historical fact rows. Facts
and exports currently have no automatic age-based row/export deletion. Never attach a blanket expiry
rule to active warehouse files. Align evidence retention, replay requirements and your budget.

## 6. Freshness and control flow

A scan discovers access, collects selected scopes, normalizes and ranks findings, records coverage,
commits facts, then publishes views/exports. The standard AWS timer starts three minutes after boot
and then uses `scan_interval_hours` (default six). Session startup can request a stale-data refresh;
on-demand scans and targeted reads are separate ways to obtain newer evidence.

Check scan age **and** the scope's coverage/completeness. Health marks six-hour-old scans stale;
changing the timer does not make inaccessible evidence fresh. Source observation time, ingestion time
and commit time have distinct meanings. A successful read today proves only what that scoped read
could see. An empty board is not proof that all accounts are secure.

The [control-flow diagram](diagrams/user-reference/control-flow.html) shows an investigation followed
by a human-approved desk decision. Hermes selects tools; the desk validates commands and permissions;
AWS returns evidence or an access gap. The agent explains the evidence and asks for approval where
required. A decision such as accepted risk changes desk records, not AWS resources. The desk reports
durable success only after commit; otherwise the action is local/pending and must not be treated as saved.

For fixes, the desk locates relevant IaC, the agent writes a proposal, and the validator checks a scratch
copy. Validation is not `terraform plan`, deployment success or proof of remediation. You review and
deploy through your workflow; later evidence establishes whether the issue is resolved.

## 7. Customize without losing the boundaries

Use the [customization reference](CUSTOMIZATION.md) for exact settings, activation steps and checks.
Start with accounts/regions, business context, model and schedule. Add repository integration, usage
evidence or an API only when the first scan is understandable and its coverage is explicit.

The optional [Hermes native HTTP recipe](HERMES-API-OPTIONS.md) lets another workflow ask the agent
to investigate. CE does not expose that listener by default. Use a dedicated restricted profile,
strong secret-injected authentication and private access. A run waiting for approval must be shown
to a human; do not automatically approve because the API caller authenticated. This remains one
operator/organization per installation, not a multi-tenant service or a generic CE MCP export.

## 8. Know what leaves the environment

Self-hosting does not imply local inference. Conversation content, returned finding details, resource
identifiers, relevant IaC and knowledge can reach the selected model provider. The agent cannot browse
the raw store, but derived tool responses may contain sensitive configuration from it. Choose the
endpoint and provider policy accordingly. Optional managed MCP and GitHub integrations have their own
data paths. Read [Data flow and privacy](DATA-FLOW.md) before connecting a production estate.

## 9. Operate and recover

| Symptom | First check | Interpretation/action |
| --- | --- | --- |
| Empty or unexpectedly small board | Account/region/source coverage and caps | Resolve scope or access gaps before interpreting zero findings |
| Recent scan, missing member evidence | Runtime onboarding report and target trust | Central visibility does not substitute for member resource reads |
| Pending/local-only decision | Storage health and outbox | Restore storage access; do not claim durability from a chat acknowledgement alone |
| Export older than committed scan | Report/export status | Facts can be committed while derivative publication failed; next successful scan retries |
| Storage outage | Buffer usage (default 256 MB) | Collection buffers within limits, then pauses; abrupt loss can lose uncommitted work |
| Spot replacement loses recent chat/context | Checkpoint age and restore status | Homes checkpoint normally every 120 seconds; newest uncheckpointed changes can be lost |
| Investigation fails but collection works | Managed MCP runtime/permissions or configured transport | Separate paths; failures do not justify silently bypassing the guard |
| No scheduled activity | Compute/gateway state and scan timer | Nothing runs while the relevant runtime is stopped |

Monitor compute, S3 growth/requests, Glue, Athena, model usage and optional source-service charges.
The 100 MiB Athena historical-report cutoff is a per-query limit, not a total spending budget.
Protect Terraform state and backups. Use [Recovery](RECOVERY.md),
[Troubleshooting](TROUBLESHOOTING.md) and [Limits](LIMITS.md) for operational detail.

## Implementation references

| Contract | Primary implementation |
| --- | --- |
| Runtime services and timers | [host.py](../deploy/aws-single/host.py), [Terraform](../deploy/aws-single/main.tf) |
| Command boundary | [server.py](../rgtriage/server.py), [Hermes plugin](../profiles/remedigenius/plugins/rg-triage/__init__.py) |
| Discovery and collection | [accounts.py](../rgtriage/accounts.py), [collect.py](../rgtriage/collect.py), [scan orchestration](../rgtriage/cli.py) |
| Durable commit and exports | [commit.py](../rgtriage/commit.py), [repository.py](../rgtriage/repository.py), [exports.py](../rgtriage/exports.py) |
| Configuration | [config.py](../rgtriage/config.py), [profile merge](../deploy/aws-single/host.py) |
| Access packet | [prepare_access.py](../tools/prepare_access.py), [member role](../deploy/aws-single/member-read-role.yaml) |

The diagrams are logical maps, not measured timing or scale benchmarks. All four have editable JSON
beside the HTML. See their [maintenance notes](diagrams/user-reference/README.md) when the implementation changes.
