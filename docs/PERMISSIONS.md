# How CE permissions work

Open the [permission map](diagrams/user-reference/permission-map.html) and
[step-by-step read flow](diagrams/user-reference/read-control-flow.html). These diagrams describe
the containerized AWS deployment. [Native existing Hermes](LOCAL-HERMES.md) shares the user's
credential environment and does not provide the same process isolation.

## Deployment credentials stay with the operator

Terraform provisions the installation's host/audit policies and instance profile. The community
[CloudFormation member template](../deploy/aws-single/member-read-role.yaml) provisions target readers.
The operator reviews and applies these changes using deployment credentials; those credentials are
never supplied to Hermes. [The access quickstart](ACCESS-QUICKSTART.md) generates the exact review
packet for the customer's identities, organization and selected accounts.

An instance profile connects an IAM role to EC2. It does not create a second administrator identity.
IAM roles are AWS authorization objects, not servers; no agent runs in the target accounts.

| Identity/process | Where it exists | Authorized purpose |
| --- | --- | --- |
| Hermes | Docker container on the desk EC2 host | Conversations and restricted desk tools; no AWS credentials |
| Desk | Host service on that EC2 instance | Guarded collection/investigation, credential handling and durable CE state |
| Host role / instance profile | IAM in the desk account, attached to EC2 | SSM agent connectivity, own-storage access, configured model-secret access and approved role assumptions |
| Audit role | IAM in the desk account | Read local security/configuration evidence and evaluate policies |
| Member reader | IAM in each selected target account | Read target evidence under its IAM policies and organization restrictions |
| Analytics role | IAM in the desk account | Read the CE warehouse, run bounded queries and write query results |

## One investigation, step by step

1. The operator asks Hermes about a finding or resource.
2. Hermes sends a fixed tool request across the Unix socket. Its container cannot reach instance
   metadata through the configured networking rules.
3. The desk selects the configured account and reader ARN. Using the host identity, it asks STS to
   assume that role. Cross-account access requires caller permission and target trust.
4. STS returns temporary reader credentials or an authorization failure. It does not create a role
   or modify IAM. The credentials remain in the desk process.
5. The desk performs the guarded read in the selected region and records evidence or an explicit gap.
6. Hermes receives a bounded result with provenance, not AWS access keys or session tokens.

Each target assumption starts from the host identity. The local audit role does not hop to members.
Reader roles explicitly deny onward `sts:AssumeRole`. An IAM role exists once per account; service
enablement, findings, membership and effective regional permissions must still be checked per region.
See [AWS cross-account authorization](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html).

## What read-only means here

The assessed-account readers use SecurityAudit and ViewOnlyAccess, supplemented by discovery and
policy-evaluation permissions. CE adds explicit denies for secret values, application data and
onward role assumption. The desk also rejects assessed-resource mutations and sensitive read
operations through its software guard. These readers are not deployment or IAM administration roles.
The shared supplement includes `cloudformation:DescribeChangeSet` so an investigation can verify what
a reported deployment changed. This permits a metadata read, not creating or executing a change set.
Existing installations must review/apply the updated template; installing Python alone does not add the grant.

The host is **not globally read-only**. It writes CE's own S3 evidence/checkpoints and Glue tables,
and bootstrap retrieves the configured model secret. Hermes receives the model credential for inference;
that is not an AWS credential. Analytics can start queries and write private query results. These
operational grants are separate from permissions to change assessed application infrastructure.
The host also needs the template's grant on its own bucket's `exports/*` prefix for readable scan exports.
An older role can commit Iceberg facts successfully while exports report `AccessDenied`; inspect both statuses.

The supported tools do not grant IAM administration, attach administrator policies, change trust or
pass privileged roles. Approving a triage decision changes CE records, not AWS permissions. IaC
proposals use isolated validation; operators deploy through their existing delivery process.

This is a permission boundary, not a guarantee against every host compromise, software vulnerability
or later policy change. Administrators remain trusted, and AWS-managed policy updates can change
effective access. Keep the credentials out of the agent, review IAM changes and periodically verify
the runtime. IAM policy simulation is useful evidence, but it is not a comprehensive escalation audit
or a substitute for successful scoped reads.

## Existing roles, SCPs and custom names

Do not replace an existing role because a standard name collides. Inspect its trust and owning stack.
If it serves another runtime, create a CE reader with another `MemberRoleName` using the same template,
add that exact ARN to the runtime's allowed assumptions and configure it explicitly in `triage.yaml`.
No custom role implementation is necessary. Preserve the older role and its clients.

The default common-name caller grant permits that reader name within the host's organization. It is
not an exact account allowlist: an administrator can make another matching account reader reachable
by explicitly trusting the runtime. Deployment targets remain separately selected. Use reviewed
caller policies if your organization requires an exact-account boundary.

SCPs apply even when an SSO role is named AdministratorAccess. A regional SCP can block CloudFormation
in one region while permitting it elsewhere. Run the reader-role deployment in an allowed region;
the IAM role remains global. This does not authorize changing or bypassing the SCP. During collection,
reads in prohibited regions must remain visible as denied coverage. A successful AssumeRole does not
mean every regional API is accessible.

SSO profile names can become stale after organization/account assignments change. If login succeeds
but credential retrieval says `ForbiddenException`, check the user's current account/permission-set
assignments. Refreshing the token cannot restore an assignment that no longer exists. Human SSO
access is still not proof that the desk's runtime role has access.

## Verify the real runtime, including alternate reader names

After deploying reviewed access, run the bounded probe **on the runtime host**:

```sh
python tools/runtime_access_check.py \
  --audit-role YOUR_LOCAL_AUDIT_ROLE_ARN \
  --expected-runtime-role YOUR_HOST_ROLE_ARN \
  --profile /path/to/triage.yaml \
  --regions us-east-1 us-east-2 eu-central-1 \
  --output /private/path/runtime-access.json
```

The optional `--profile` retains explicit reader ARNs, including alternate names. Every supplied
account must have a reader ARN; workstation `aws_profile` credentials are rejected. The probe overrides
collection caps and tests every supplied account in the requested regions. `--expected-runtime-role`
rejects a different assumed role, preventing an administrator session from being mistaken for runtime
proof. Both options are post-v0.9.0 additions; use the matching source checkout.

The proof writes only its local report: no scan commit, model call or production checkpoint. It uses
bounded source collection plus IAM/CloudTrail reads. Read the account/region/source outcomes rather
than treating the process exit code or authenticated-account count as full coverage. See
[Limits](LIMITS.md) for what this does and does not prove.

## Terraform provider cache

When operating from PowerShell on a workstation with an existing shared cache, set both variables
before **every** Terraform operation, including plan, show and apply:

```powershell
$env:TF_PLUGIN_CACHE_DIR = (Join-Path $env:LOCALAPPDATA 'terraform-plugin-cache')
$env:TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE = 'true'
```

Use your own cache path on other systems. The cache avoids repeated provider downloads/copies; it
does not eliminate working-directory metadata, state or saved-plan files. Preserve the repository's
provider version and review lock-file changes, particularly platform checksum changes. Keep private
plans/state and account-specific variables outside tracked files.
