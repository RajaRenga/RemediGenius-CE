"""Read-only access proof. Run ON the runtime host, never with administrator workstation credentials.

Writes only the local JSON report. No scan commit, model call, IAM mutation, or secret read.
Example: python tools/runtime_access_check.py --audit-role <existing-role-arn>
         --regions us-east-1 us-east-2 eu-central-1 --output /tmp/runtime-access.json
The report contains account identifiers: keep it private.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rgtriage import accounts, aws, collect, config


def proof_profile(audit_role, regions, runtime_account, supplied=None):
    """Retain explicit customer readers, but bound the proof and use only host credentials."""
    supplied = supplied or {}
    readers = [dict(a) for a in supplied.get('accounts', [])]
    if any(a.get('aws_profile') for a in readers):
        raise ValueError('Runtime proof cannot use workstation AWS profiles; supply role_arn readers.')
    if any(not a.get('role_arn') for a in readers):
        raise ValueError('Every supplied account needs an explicit reader role_arn.')
    readers = [a for a in readers if str(a.get('account_id')) != runtime_account]
    readers.insert(0, {'name':'runtime', 'account_id':runtime_account, 'role_arn':audit_role})
    for account in readers:
        account['regions'] = list(regions)
    return config.normalize({'name':'runtime-access-proof', 'regions':list(regions),
        'organization':dict(supplied.get('organization', {})),
        'sources':['securityhub','guardduty','inspector','config','accessanalyzer','cloudwatch'],
        'max_findings_per_source':10, 'detail_limits':{k:10 for k in collect.SEVERITIES}, 'rollup_limit':5,
        'accounts':readers})


def check(audit_role, regions, *, profile_path=None, expected_runtime_role=None):
    host = aws.session_for({})
    identity = host.client('sts').get_caller_identity()
    if ':assumed-role/' not in identity['Arn']:
        raise ValueError('Run this proof with the runtime instance role, not an IAM user.')
    if expected_runtime_role:
        expected_account = expected_runtime_role.split(':')[4]
        expected_name = expected_runtime_role.rsplit('/', 1)[-1]
        if identity['Account'] != expected_account or identity['Arn'].split(':assumed-role/', 1)[1].split('/')[0] != expected_name:
            raise ValueError('Caller does not match the expected runtime role; refusing operator-credential proof.')
    profile = proof_profile(audit_role, regions, identity['Account'],
                            config.load(profile_path) if profile_path else None)
    report = accounts.discover(profile)
    findings, coverage = collect.collect(profile, routes=report['routes'])
    probes=[]
    for account in profile['accounts']:
        try:
            session=aws.session_for(account)
            for region in account['regions']:
                for service,operation,params in [('cloudtrail','lookup_events',{'MaxResults':1}),
                                                 ('iam','get_account_summary',{})]:
                    try:
                        getattr(aws.client(session,service,region),operation)(**params)
                        result='ok'
                    except Exception as exc:
                        result=aws.error_code(exc)
                    probes.append({'account_id':account['account_id'],'region':region,'service':service,'status':result})
        except Exception as exc:
            probes.append({'account_id':account.get('account_id'),'status':aws.error_code(exc)})
    return {'runtime_identity':identity['Arn'],'audit_role':audit_role,'regions':regions,
            'discovery':report,'coverage':coverage,'investigation_reads':probes,'finding_count':len(findings),
            'matrix':accounts.coverage_matrix(report,profile,coverage),
            'limits':'Bounded finding samples; access proof, not a complete production scan. No durable writes.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit-role',required=True)
    parser.add_argument('--regions',nargs='+',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profile',type=Path,help='Triage YAML with explicit reader ARNs, including custom role names; no aws_profile credentials.')
    parser.add_argument('--expected-runtime-role',help='Expected IAM runtime role ARN; reject a different assumed role.')
    args=parser.parse_args()
    result=check(args.audit_role,args.regions,profile_path=args.profile,expected_runtime_role=args.expected_runtime_role)
    args.output.write_text(json.dumps(result,indent=2,default=str),encoding='utf-8')
    print(json.dumps({'authenticated_accounts':len(result['discovery']['full_read']),
                      'known_accounts':result['discovery']['known_accounts'],
                      'routes':len(result['discovery']['routes']), 'finding_count':result['finding_count'],
                      'coverage_statuses':{s:sum(c['status']==s for c in result['matrix'])
                          for s in sorted({c['status'] for c in result['matrix']})}}))


if __name__=='__main__':
    main()
