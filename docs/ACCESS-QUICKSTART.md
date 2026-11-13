# Connect your AWS landscape

For where Hermes runs, instance-profile permissions, role assumption and its limits, see
[How CE permissions work](PERMISSIONS.md), including existing-role collisions and regional SCPs.

See the [account-access diagram](diagrams/user-reference/account-access.html) for caller/target trust
and delegated findings versus member investigations; the [operator reference](USER-ARCHITECTURE.md)
places access setup in the full deployment and data flow.

Use this procedure after installing the desk with [existing Hermes](LOCAL-HERMES.md),
[Docker](WORKSTATION.md), or [Spot](../deploy/aws-single/README.md). You don't need account IDs or roles
from another deployment. The preparation tool uses Python's standard library and makes **no AWS calls**.

**Availability:** this generator and the updated templates are development-branch additions after v0.9.0.
They are not in the already-published v0.9.0 assets. Use the matching source checkout containing this guide;
do not mix its commands with older templates. They are included in the next source/Spot package build.

## 1. Choose your starting point

| Your AWS setup | What you need |
| --- | --- |
| One account, bundled Spot installation | Local audit role is provisioned by Terraform; check discovery permissions when upgrading |
| Existing Hermes/workstation | Use your chosen AWS profile; prefer an explicit read role in triage.yaml instead of administrator credentials |
| Organization without delegation | One runtime identity, member read roles in selected target accounts |
| One security administrator | A reader in that account for associated findings; member roles for investigations |
| Separate security administrators | Configure each administrator's reader ARN and regions; no need to relocate Hermes |
| Unrelated accounts/no organization | Exact caller/target trust per account, normal CloudFormation stacks; no StackSet |

Security findings access does not automatically grant CloudTrail/IAM/resource access. Security-service delegation
does not grant StackSets administration. Enabling Security Hub, GuardDuty or Inspector is a separate choice.

## 2. Identify the actual runtime and its current access

In the desk's credential environment, run:

```sh
rgtriage onboarding --json > onboarding.json
```

For native Hermes, activate the environment/profile that runs rgtriage. For containers, run the command in the
desk environment using the deployment's documented command route; do not substitute your laptop's administrator
credentials. Move the JSON report to a private working directory if preparing the packet on another computer.

Review `reader_arn`, organization, member-role name, role checks and discovery errors. The trusted caller is the
runtime IAM role/user, not the local audit role or an STS session ARN. Check the full IAM path for SSO roles.
If the report cannot resolve the exact ARN, verify it in IAM and supply `--runtime-arn` below. Unknown organization
status must be resolved first; the tool will not silently remove an organization trust restriction.

## 3. Generate your review packet

From the matching source checkout, select the accounts that need a member read role. Replace example IDs/region.
The bundled Spot installation's own account already has a local audit role and normally does not need another role.

```sh
python tools/prepare_access.py --report onboarding.json --accounts 111122223333 444455556666 --region us-east-1 --output .rgce/access-review
```

This defaults to a **normal stack/change set per account**, suitable for standalone accounts or small organizations.
For a service-managed StackSet, additionally supply an approved root/OU:

```sh
python tools/prepare_access.py --report onboarding.json --accounts 111122223333 444455556666 --region us-east-1 --ou ou-abcd-12345678 --output .rgce/access-review-stackset
```

Add `--delegated-stacksets` only when deployment will use an actual StackSets delegated administrator. The generated
commands then include `--call-as DELEGATED_ADMIN`. The management account gets a separate normal-stack command.
StackSet scope is the intersection of the selected accounts and OU/root. Automatic deployment to future accounts
is disabled; enabling broader OU auto-deployment is a separate reviewed decision.

Output contains:

- `README.md`: customer-specific procedure and checks.
- `scope.json`: exact runtime and selected targets.
- `caller-policy.json`: scoped AssumeRole permission for the runtime; compare with existing grants before adding it.
- `target-trust.json`, `parameters.json`, `member-read-role.yaml`: exact trust and target-role deployment definition.
- `reader-discovery-policy.json`: supplement for existing local audit/separate administrator readers.
- `commands.txt`: deployment commands, with target-identity checks and review warnings.
- `targets.json`: explicit StackSet targets, when selected.

The script never applies these files or overwrites an existing packet. Keep them private and outside version control.
It currently supports the commercial AWS partition; GovCloud/China need separately reviewed templates.

## 4. Review and deploy using deployment credentials

Read the packet README, then inspect existing target roles and their owning stacks. AccessDenied does not establish
that a role is absent. Update the owning deployment rather than creating a duplicate named role. Check stale
principal IDs, SCPs, permissions boundaries and both sides of AssumeRole.

The member template grants `SecurityAudit`, `ViewOnlyAccess`, discovery and evaluation permissions with explicit
data/secret denies. Existing local audit roles also need the discovery supplement, including `inspector2:ListMembers`.
The bundled Spot host normally already has its organization-constrained caller grant; avoid duplicating it.
See [the full permission contract](MULTI-ACCOUNT.md#exactly-which-roles-and-permissions).

After approval, a deployment operator runs the reviewed commands from inside the output directory, with the correct
target/management credentials. Normal-stack commands prepare change sets without executing them. The StackSet
instance command actually deploys roles. Hermes and the desk never receive these deployment permissions.

## 5. Verify as the runtime, not the deployment operator

Configure target reader ARNs and scan regions in triage.yaml. Include the Security Hub home region if using
aggregation; configure separate administrator accounts explicitly when organization discovery cannot find them.
Then return to the runtime credential environment:

```sh
rgtriage onboarding --json
rgtriage scan
```

Success means the intended identities authenticate **and** the expected account/region/service reads succeed.
Review disabled, denied, unavailable and partial scopes. A quiet board or successful AssumeRole alone is not proof.
The optional [runtime access probe](../tools/runtime_access_check.py) checks bounded collection without committing
a production scan. Validation limits distinguish live tests from controlled scenarios.

For delegated findings-only access, start with the working administrator reader and add member roles later. The desk
must keep investigation gaps visible until those roles work. No architecture change or agent per account is required.
