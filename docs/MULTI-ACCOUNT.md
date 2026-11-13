# Multiple AWS accounts

Start with [Connect your AWS landscape](ACCESS-QUICKSTART.md) for the step-by-step procedure and the offline
`tools/prepare_access.py` packet generator. This document is the detailed permission and behavior contract.

Run one desk for one organization. Keep Hermes, the compute/storage separation and S3/Iceberg unchanged.
Delegation is optional: direct member roles work without it. The desk never enables services or appoints administrators.

## Access models

| Environment | Findings | Investigation |
| --- | --- | --- |
| No security administrator | Read each account through its member role | Same member role |
| Security Hub, GuardDuty or Inspector administrator | Associated members, per service and region | Member role still needed for CloudTrail, IAM and resource configuration |
| Separate administrators for different services | Configure a reader in each administrator account; reachable discovered readers are inspected too | Member roles in target accounts |

Organization registration, trusted service access and service member relationships are separate evidence.
Invitation-based GuardDuty/Security Hub relationships can exist without organization delegation. Config delegation
does not confer Security Hub/GuardDuty/Inspector administration; Config collection remains direct per account.

## Exactly which roles and permissions

| Identity | Location | Permissions |
| --- | --- | --- |
| Runtime/host role | Desk account | Assume the local audit role and approved member roles; installation storage grants stay separate |
| Audit/read role | Desk account or separately configured administrator | `SecurityAudit`, `ViewOnlyAccess`, discovery supplement below, existing evaluation and deny policies |
| `RemediGeniusReadOnly` | Each account needing investigation | Supplied member-role template, trusting the runtime identity |
| Deployment operator | Management account or StackSets delegated administrator | Provision/update the reviewed roles; never assign deployment permissions to Hermes |

The exact discovery supplement is [reader-discovery-policy.json](../deploy/aws-single/reader-discovery-policy.json):

- Organizations: `DescribeOrganization`, `ListAccounts`, `ListDelegatedAdministrators`, `ListDelegatedServicesForAccount`.
- Security Hub: `ListMembers`, `ListFindingAggregators`, `GetFindingAggregator`.
- GuardDuty: `ListDetectors`, `ListMembers`.
- Inspector: `inspector2:ListMembers`.

Our real runtime test found that `SecurityAudit` and `ViewOnlyAccess` alone did not permit Inspector membership
discovery. The supplement is included in the proposed single/static Terraform audit role and the member CloudFormation
template. Existing installations need a reviewed deployment; updating Python does not change IAM.

[member-read-role.yaml](../deploy/aws-single/member-read-role.yaml) contains the complete target trust and policies.
It also allows IAM simulation and Access Analyzer policy evaluation. Explicit denies block secret values, SSM
parameter values, S3 object bodies, KMS decryption, table reads and onward role assumption. Optional log/Athena
evidence needs separate scoped permissions. SCPs, boundaries and resource policies can still deny reads.

### Both sides of role assumption

The runtime must allow `sts:AssumeRole` on approved member-role ARNs. Each target must trust that exact IAM role ARN,
with `aws:PrincipalOrgID` for an organization. The bundled Spot caller policy restricts the common role name to its
own organization with `aws:ResourceOrgID` and `aws:PrincipalOrgID`.

Trust the identity the desk's AWS calls actually use, not its local audit role: the audit role denies onward
assumption. Which identity that is depends on the deployment:

| Deployment | Runtime identity to trust (`TrustedPrincipalArn`) | `sts:AssumeRole` caller grant |
| --- | --- | --- |
| Spot | The instance role (Terraform output `instance_role`) | Bundled, organization-scoped |
| Docker workstation started with `--read-role-arn` | That read role's ARN | Attach the caller policy below to the role |
| Workstation without a read role, or existing Hermes | The AWS profile's IAM user or role ARN | The profile's identity must allow it |

Identity Center trusts need the full IAM role path, not an STS session ARN.

The quickstart's workstation read role carries only `SecurityAudit` and `ViewOnlyAccess`, which do not include
`sts:AssumeRole`. To read member accounts, attach a caller policy like this one (replace the account ids and
organization id), and deploy the member roles with `TrustedPrincipalArn` set to the read role's ARN:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::111122223333:role/RemediGeniusReadOnly",
        "arn:aws:iam::444455556666:role/RemediGeniusReadOnly"
      ],
      "Condition": {"StringEquals": {"aws:ResourceOrgID": "o-xxxxxxxxxx"}}
    }
  ]
}
```

`tools/prepare_access.py` generates this as `caller-policy.json` for the exact runtime and selected accounts;
prefer the generated packet over hand-writing it. Without the caller grant, member reads fail with `AccessDenied`
even when the member roles exist and trust the desk.

`AccessDenied` does not prove a role is missing. Check caller permission, trust, SCPs and boundaries. An unresolved
`AROA...` principal ID can refer to a deleted role; recreating its name does not repair the old trust binding.

## Installation and upgrade procedure

1. Choose the permanent runtime identity. Run `rgtriage onboarding --json` under that identity. Review the private
   report's `reader_arn`, organization, regions, role checks and discovery errors.
2. Inventory existing roles and their owning deployments. Update an existing owning stack; don't create a second
   named role or deploy a StackSet over a conflicting existing role.
3. Review the caller policy, target trust, discovery supplement and target accounts/OUs. Keep `MemberRoleName`,
   `organization.member_role_name` and the caller policy consistent.
4. Prefer the quickstart generator for an explicit account/OU intersection with automatic deployment disabled. The
   alternative below deliberately covers an approved OU and **automatically deploys to future accounts in it**; use it
   only if that broader lifecycle is your reviewed policy. After the runtime role exists, use deployment credentials
   for a new StackSet:

```sh
aws cloudformation create-stack-set --stack-set-name remedigenius-ce-read \
  --template-body file://deploy/aws-single/member-read-role.yaml \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=TrustedPrincipalArn,ParameterValue=<runtime-iam-role-arn> \
               ParameterKey=OrganizationId,ParameterValue=<organization-id> \
               ParameterKey=MemberRoleName,ParameterValue=RemediGeniusReadOnly
aws cloudformation create-stack-instances --stack-set-name remedigenius-ce-read \
  --deployment-targets OrganizationalUnitIds=<approved-ou-id> --regions <one-region>
```

StackSets delegated administrators add `--call-as DELEGATED_ADMIN` to both commands. IAM roles are global: deploy
in one region, not every scan region. Auto-deployment covers new accounts in targeted OUs. StackSets skip the
management account; deploy a normal stack there if it's in scope. Exclude existing conflicting roles until reconciled.

5. Update the local audit role discovery policy through its owning Terraform stack, and separately configured
   administrator readers through their own deployments. Review plans/change sets before applying.
6. Run onboarding and a bounded scan under the runtime role. Verify account/region/service results, including denied,
   disabled, partial and unavailable scopes. Authentication alone is not proof of complete coverage.

## Discovery and collection behavior

Every scan authenticates configured readers, lists the organization when permitted, reads its administrator registry,
and checks member lists in every configured region of every reachable reader. Newly discovered readers are inspected
too. Role probing is bounded to 500 accounts per scan; remaining accounts stay visibly uncovered.

The report distinguishes authenticated accounts, potential findings-only access and uncovered accounts. The historical
JSON field `full_read` remains for compatibility but now means authenticated. The scan's `coverage_matrix` records
actual results by account, region and service. Discovery denial means unknown, not no delegation. An unreadable
Organizations API does not prove the account is standalone.

Administrator reads run first. Only successful, untruncated collection replaces a member read for the same service
and region. Denial, a disabled service or truncation retains direct fallback when a member role is available.

Security Hub discovery records home region, linking mode and linked/excluded regions. Include the home region in
the configured reader regions when using aggregation. An aggregator alone does not prove that each account or
service is enabled, and other regional reads are not suppressed based solely on its presence. Product exclusion is
disabled for aggregated, member-wide or unknown Hub query scope, and after truncated direct reads. Normalization
and deduplication still merge repeated native findings.

GuardDuty and Inspector are regional. Separate administrators do not require moving compute:

```yaml
regions: [us-east-1, us-east-2, eu-central-1]
organization:
  discover: true
  member_role_name: RemediGeniusReadOnly
accounts:
  - name: desk
    account_id: "111122223333"
    role_arn: arn:aws:iam::111122223333:role/DeskAudit
  - name: security-administrator
    account_id: "444455556666"
    role_arn: arn:aws:iam::444455556666:role/RemediGeniusReadOnly
    regions: [us-east-1, us-east-2]
```

Authorize the runtime to assume both roles. Outside an organization, configure explicit role ARNs and caller grants;
leave `OrganizationId` empty in the target template. `organization.discover: false` limits collection to configured
accounts. Automatic discovery never enables regions or changes security services.

## Read-only runtime proof

On the actual runtime host:

```sh
python tools/runtime_access_check.py --audit-role <existing-audit-role-arn> \
  --regions us-east-1 us-east-2 eu-central-1 --output /tmp/runtime-access.json
```

This requires an assumed-role identity and reads bounded findings plus CloudTrail/IAM probes. It does not invoke
the model, commit a scan, read secrets or change permissions. The report contains private identifiers.
See [Limits](LIMITS.md) for what this does and does not prove.