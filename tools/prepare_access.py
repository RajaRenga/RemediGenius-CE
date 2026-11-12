"""Prepare an offline, customer-specific AWS access review packet. Never calls AWS.

First run `rgtriage onboarding --json > onboarding.json` under the intended runtime identity.
Then run this script with explicit target accounts. Deploy only after reviewing the generated README.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def prepare(report, *, accounts, region, output, runtime_arn=None, ou=None, delegated=False):
    runtime = runtime_arn or report.get('reader_arn', '')
    if not re.fullmatch(r'arn:aws:iam::\d{12}:(role|user)/[A-Za-z0-9+=,.@_/-]+', runtime):
        raise ValueError('Supply a verified IAM runtime role/user ARN, including its path; not an STS session ARN.')
    org = report.get('organization_id', '')
    if org and not re.fullmatch(r'o-[a-z0-9]{10,32}', org):
        raise ValueError('Invalid organization ID in report.')
    if report.get('mode') not in ('organization', 'standalone'):
        raise ValueError('Organization status is unknown. Resolve onboarding errors before preparing trust.')
    if report['mode'] == 'organization' and not org:
        raise ValueError('Organization report must contain its organization ID.')
    if not accounts or any(not re.fullmatch(r'\d{12}', a) for a in accounts):
        raise ValueError('Select explicit 12-digit target account IDs.')
    accounts = sorted(set(accounts))
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+', region):
        raise ValueError('Invalid AWS region.')
    role = report.get('member_role_name', 'RemediGeniusReadOnly')
    if not re.fullmatch(r'[A-Za-z0-9+=,.@_-]{1,64}', role):
        raise ValueError('Invalid member role name.')
    if ou and (not org or not re.fullmatch(r'(r-[a-z0-9]{4,32}|ou-[a-z0-9]{4,32}-[a-z0-9]{8,32})', ou)):
        raise ValueError('StackSets require a verified organization and root/OU ID.')
    if delegated and not ou:
        raise ValueError('--delegated-stacksets requires --ou.')
    management = report.get('management_account', '')
    targets = [a for a in accounts if a != management]
    if ou and not targets:
        raise ValueError('Management-account-only scope needs normal stacks, not a StackSet.')
    if output.exists() and any(output.iterdir()):
        raise ValueError('Output directory must be empty; existing review files are never overwritten.')
    output.mkdir(parents=True, exist_ok=True)
    params = [{'ParameterKey':'TrustedPrincipalArn','ParameterValue':runtime},
              {'ParameterKey':'OrganizationId','ParameterValue':org},
              {'ParameterKey':'MemberRoleName','ParameterValue':role}]
    trust = {'Effect':'Allow','Principal':{'AWS':runtime},'Action':'sts:AssumeRole'}
    caller = {'Effect':'Allow','Action':'sts:AssumeRole',
              'Resource':[f'arn:aws:iam::{account}:role/{role}' for account in accounts]}
    if org:
        trust['Condition'] = {'StringEquals':{'aws:PrincipalOrgID':org}}
        caller['Condition'] = {'StringEquals':{'aws:ResourceOrgID':org}}
    documents = {'parameters.json':params,
                 'target-trust.json':{'Version':'2012-10-17','Statement':[trust]},
                 'caller-policy.json':{'Version':'2012-10-17','Statement':[caller]},
                 'scope.json':{'runtime_arn':runtime,'target_accounts':accounts,'deployment_region':region,
                               'organization_id':org,'member_role_name':role}}
    if ou:
        documents['targets.json'] = {'OrganizationalUnitIds':[ou], 'AccountFilterType':'INTERSECTION',
                                     'Accounts':targets}
    for filename, value in documents.items():
        (output/filename).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    for filename in ('member-read-role.yaml','reader-discovery-policy.json'):
        shutil.copyfile(ROOT/'deploy/aws-single'/filename, output/filename)
    commands = []
    if ou:
        call_as = ' --call-as DELEGATED_ADMIN' if delegated else ''
        commands += [
            '# Use management-account or StackSets delegated-administrator deployment credentials.',
            '# Automatic deployment is OFF: only the explicit reviewed accounts in targets.json are selected.',
            'aws cloudformation create-stack-set --stack-set-name remedigenius-ce-read '
            '--template-body file://member-read-role.yaml --permission-model SERVICE_MANAGED '
            '--auto-deployment Enabled=false --capabilities CAPABILITY_NAMED_IAM '
            f'--parameters file://parameters.json --region {region}{call_as}',
            '# WARNING: the following command deploys IAM roles. Run only after approval and collision checks.',
            'aws cloudformation create-stack-instances --stack-set-name remedigenius-ce-read '
            f'--deployment-targets file://targets.json --regions {region} --region {region}{call_as}', '']
    for account in accounts if not ou else [a for a in accounts if a == management]:
        commands += [f'# Authenticate with deployment credentials for account {account}.',
            f'# Verify the following returns exactly {account} before proceeding:',
            'aws sts get-caller-identity --query Account --output text',
            '# For a NEW role only; for an existing stack use its name and change-set-type UPDATE.',
            'aws cloudformation create-change-set --stack-name remedigenius-ce-read '
            '--change-set-name reviewed-read-access --change-set-type CREATE '
            '--template-body file://member-read-role.yaml --capabilities CAPABILITY_NAMED_IAM '
            f'--parameters file://parameters.json --region {region}',
            '# Review the change set in CloudFormation. Execution is deliberately not included.', '']
    (output/'commands.txt').write_text('\n'.join(commands)+'\n',encoding='utf-8')
    (output/'README.md').write_text(f'''# Private AWS access review — not applied

Runtime: `{runtime}`. Member role: `{role}`. Selected accounts: {', '.join(accounts)}.
This packet was generated offline. It does not verify role existence, ownership, SCPs, boundaries or credentials.

1. Confirm the runtime IAM ARN, full role path, organization and selected accounts in scope.json. Human SSO access
   is not automatically runtime access. Trust the runtime caller, not the local audit role that denies onward assumption.
2. In each target, inspect the existing role and its owning deployment. AccessDenied does not prove absence.
   Update the owning stack or reconcile/import an unmanaged role; do not deploy over an existing named role.
   An unresolved AROA principal can be stale deleted-role trust. Inspect before replacing it.
3. Compare caller-policy.json with existing runtime grants. Add only missing access through the owning IaC.
   The bundled Spot host normally already has the organization-constrained common-role grant.
4. The target template attaches SecurityAudit + ViewOnlyAccess, read-only discovery, evaluation permissions and
   explicit data/secret denies. Review target-trust.json and member-read-role.yaml. No delegation is required.
5. Add reader-discovery-policy.json to the local audit role and any separate administrator readers through their
   owning deployment if missing. Existing roles do not gain permissions when Python is upgraded.
6. From THIS directory, review commands.txt. Use deployment credentials for the stated target account or StackSets
   administrator. A Security Hub/GuardDuty delegate is not necessarily a StackSets delegate. Normal-stack commands
   create reviewable change sets; the StackSet instance command actually deploys roles and needs prior approval.
7. Configure scan regions, the Security Hub home region, and explicit reader role ARNs for separate administrators
   or standalone accounts. IAM roles deploy once per account; security service coverage is regional.
8. After approved deployment, run `rgtriage onboarding --json`, then `rgtriage scan`, under the intended runtime
   credentials. Review every account/region/service result. Authentication alone is not complete coverage.

For StackSets, targets.json intersects the chosen OU/root with the explicit account list and excludes the management
account. Accounts outside that OU will not deploy. Auto-deployment is disabled to avoid granting future accounts
unreviewed access. Broader OU auto-deployment is a separate approval. The management account uses a normal stack.

For standalone accounts the organization condition is absent; exact caller trust and target ARNs still apply.
This tool currently supports the commercial aws partition. GovCloud/China require separately reviewed templates.
No security services, delegation, permissions, storage or compute were changed by generating this packet.
Keep it private: it contains your account IDs and role ARNs. Do not publish it or commit it to Git.
''',encoding='utf-8')
    return {'output':str(output),'target_count':len(accounts),'mode':'stackset' if ou else 'per-account','aws_changes':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--accounts',nargs='+',required=True)
    parser.add_argument('--region',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--runtime-arn')
    parser.add_argument('--ou')
    parser.add_argument('--delegated-stacksets',action='store_true')
    args=parser.parse_args()
    try:
        raw=args.report.read_bytes()
        report=json.loads(raw.decode('utf-16' if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig'))
        result=prepare(report, accounts=args.accounts,
            region=args.region,output=args.output,runtime_arn=args.runtime_arn,ou=args.ou,delegated=args.delegated_stacksets)
    except (ValueError,OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result))


if __name__=='__main__':
    main()
