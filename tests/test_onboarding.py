"""Account onboarding: organization, delegated administrator detection, read-role probes, coverage and next steps."""
from botocore.exceptions import ClientError

from rgtriage import accounts, collect, config, digest

discover = accounts.discover  # the real function; conftest stubs the module attribute for every other test

PRIMARY = "111111111111"
A, B, C = "222222222222", "333333333333", "444444444444"
ORG = "o-exampleorg1"


def denied(code="AccessDeniedException", op="ListAccounts"):
    return ClientError({"Error": {"Code": code, "Message": "no"}}, op)


class Pages:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_):
        return iter(self.pages)


class Client:
    def __init__(self, env, account_id=PRIMARY):
        self.env = env
        self.account_id = account_id

    def get_caller_identity(self):
        return {"Account": self.account_id, "Arn": f"arn:aws:sts::{self.account_id}:assumed-role/desk-host/i-0abc"}

    def get_role(self, RoleName):
        return {"Role": {"Arn": f"arn:aws:iam::{PRIMARY}:role/aws-reserved/sso.amazonaws.com/{RoleName}"}}

    def describe_organization(self):
        if not self.env.get("org"):
            raise denied("AWSOrganizationsNotInUseException", "DescribeOrganization")
        return {"Organization": {"Id": ORG, "MasterAccountId": "999999999999"}}

    def get_paginator(self, op):
        if op == "list_finding_aggregators":
            return Pages([{"FindingAggregators": []}])
        if op == "list_delegated_administrators":
            return Pages([{"DelegatedAdministrators": []}])
        assert op == "list_accounts"
        if self.env.get("list_accounts") is None:
            raise denied()
        return Pages([{"Accounts": [{"Id": i, "Name": n, "Status": "ACTIVE"} for i, n in self.env["list_accounts"].items()]}])


class Session:
    def __init__(self, env, account_id=PRIMARY):
        self.env = env
        self.account_id = account_id

    def client(self, name, **_):
        return Client(self.env, self.account_id)


def setup(monkeypatch, env, admin=None, readable=()):
    monkeypatch.setattr(accounts.aws, "session_for", lambda account, region=None: Session(env, account.get('account_id', PRIMARY)))
    monkeypatch.setattr(accounts, "_members", lambda session, service, region: (admin or {}).get(service, []))
    probed = []

    def probe(account_id, role_name, profile_name=None):
        probed.append(account_id)
        return (account_id, "ok", "", Session(env)) if account_id in readable else (account_id, "no_role", "AccessDenied", None)
    profile = config.normalize({"name": "t", "accounts": [{"name": "desk", "role_arn": f"arn:aws:iam::{PRIMARY}:role/desk-audit"}]})
    return profile, probe, probed


def test_delegated_admin_without_account_listing(monkeypatch):
    env = {"org": True, "list_accounts": None}
    admin = {"securityhub": [A, B, C], "guardduty": [A, B], "inspector": [A, B, C, PRIMARY]}
    profile, probe, probed = setup(monkeypatch, env, admin, readable={A})
    report = discover(profile, None, probe)
    assert report["mode"] == "organization" and report["organization_id"] == ORG
    assert report["account_list"] == "admin_members"
    assert sorted(probed) == [A, B, C]  # members named by the administrator views are probed; the desk's own account is not
    assert report["full_read"] == [PRIMARY, A] and report["findings_only"] == [B, C] and report["not_covered"] == []
    assert profile["accounts"][0]["admin_regions"]["inspector"] == ["us-east-1"]
    added = profile["accounts"][1]
    assert added["account_id"] == A and added["role_arn"] == f"arn:aws:iam::{A}:role/RemediGeniusReadOnly" and added["discovered"]
    assert report["reader_arn"] == f"arn:aws:iam::{PRIMARY}:role/aws-reserved/sso.amazonaws.com/desk-host"  # path kept
    assert accounts.skip_pairs(report) == set()  # discovery is not successful collection
    assert any(r['source'] == 'guardduty' and A in r['members'] for r in report['routes'])
    steps = "\n".join(accounts.next_steps(report))
    assert "create-stack-set" in steps and f"ParameterValue=arn:aws:iam::{PRIMARY}:role/aws-reserved/sso.amazonaws.com/desk-host" in steps and ORG in steps
    assert "cannot list the organization's accounts" in steps
    assert "not the Security Hub" not in steps


def test_member_account_without_admin_rights_lists_the_organization(monkeypatch):
    env = {"org": True, "list_accounts": {A: "Payments Prod", B: "Sandbox", PRIMARY: "Security"}}
    profile, probe, probed = setup(monkeypatch, env, readable={A})
    report = discover(profile, None, probe)
    assert sorted(probed) == [A, B]
    assert report["full_read"] == [PRIMARY, A] and report["not_covered"] == [B] and report["findings_only"] == []
    assert profile["accounts"][1]["name"] == "payments-prod"
    assert "delegated_admin" not in profile["accounts"][0]
    steps = "\n".join(accounts.next_steps(report))
    assert "No associated Security Hub / GuardDuty / Inspector member view was observed" in steps


def test_standalone_account_is_quiet(monkeypatch):
    profile, probe, probed = setup(monkeypatch, {"org": False})
    report = discover(profile, None, probe)
    assert report["mode"] == "standalone" and probed == []
    assert accounts.summary_lines(report) == []
    assert "not in an AWS Organization" in accounts.next_steps(report)[0]


def test_new_role_is_reported_once(monkeypatch):
    env = {"org": True, "list_accounts": {A: "a", B: "b"}}
    profile, probe, _ = setup(monkeypatch, env, readable={A, B})
    first = discover(profile, {"full_read": [A]}, probe)
    assert first["newly_readable"] == [B]
    profile, probe, _ = setup(monkeypatch, env, readable={A, B})
    assert discover(profile, first, probe)["newly_readable"] == []
    assert "Newly onboarded this scan" in "\n".join(accounts.summary_lines(first))


def test_configured_accounts_are_not_probed_and_discovery_can_be_disabled(monkeypatch):
    env = {"org": True, "list_accounts": {A: "a", B: "b"}}
    profile, probe, probed = setup(monkeypatch, env, readable={A, B})
    profile["accounts"].append({"name": "pinned", "account_id": A, "role_arn": "x", "regions": ["us-east-1"],
                                "criticality": "mission_critical"})
    discover(profile, None, probe)
    assert probed == [B]
    profile, probe, probed = setup(monkeypatch, env, readable={A, B})
    profile["organization"]["discover"] = False
    report = discover(profile, None, probe)
    assert probed == [] and report["not_covered"] == [A, B]


def test_collect_skips_reads_the_administrator_already_covers(monkeypatch):
    calls = []
    monkeypatch.setitem(collect.COLLECTORS, "guardduty", lambda s, account, region, opts: (calls.append(account["account_id"]) or [], {}))
    profile = config.normalize({"name": "t", "sources": ["guardduty"], "accounts": [
        {"name": "desk", "account_id": PRIMARY, "_session": object()},
        {"name": "member", "account_id": A, "_session": object()}]})
    collect.collect(profile, routes=[{'source':'guardduty','reader_account':PRIMARY,'region':'us-east-1','members':[A]}])
    assert calls == [PRIMARY]
    assert all("_session" not in a for a in profile["accounts"])  # probe sessions are used once, never stored


def test_board_shows_account_coverage():
    report = {"mode": "organization", "admin": {"securityhub": [A, B]}, "full_read": [PRIMARY, A],
              "findings_only": [B], "not_covered": [], "member_role_name": "RemediGeniusReadOnly", "newly_readable": []}
    scan = {"scanned_at": "2026-10-21T00:00:00", "profile": {"name": "t"}, "issues": [], "findings": [],
            "coverage": [{"source": "securityhub", "account": "desk", "region": "us-east-1", "status": "ok", "count": 0}],
            "changes": {}, "onboarding": report}
    board = digest.markdown(scan)
    assert "Accounts: 2 authenticated · 1 findings-only access" in board and "rgtriage onboarding" in board
    failed = {"mode": "unknown", "admin": {}, "notes": ["account discovery failed: boom"]}
    assert accounts.summary_lines(failed) == ["Accounts: account discovery failed: boom"]


def test_account_listed_by_id_uses_the_member_role():
    profile = config.normalize({"accounts": [{"name": "desk"}, {"account_id": A, "criticality": "mission_critical"}],
                                "organization": {"member_role_name": "CustomRead"}})
    assert "role_arn" not in profile["accounts"][0]
    assert profile["accounts"][1]["role_arn"] == f"arn:aws:iam::{A}:role/CustomRead"


def test_membership_is_discovered_for_each_region_and_separate_reader(monkeypatch):
    profile, probe, _ = setup(monkeypatch, {'org': True, 'list_accounts': {PRIMARY:'desk',A:'other',B:'member'}})
    profile['accounts'].append({'name':'other', 'account_id':A, 'regions':['us-east-1','us-east-2']})
    profile['accounts'][0]['regions'] = ['us-east-1','us-east-2']
    def members(session, source, region):
        return [B] if session.account_id == A and source == 'guardduty' and region == 'us-east-2' else []
    monkeypatch.setattr(accounts, '_members', members)
    report = discover(profile, probe=probe)
    assert report['routes'] == [{'source':'guardduty','reader_account':A,'region':'us-east-2','members':[B]}]
    assert report['findings_only'] == [B]
    assert len([c for c in report['discovery_checks'] if c['source']=='guardduty']) == 4


def test_configured_identity_mismatch_is_not_authenticated(monkeypatch):
    profile, probe, _ = setup(monkeypatch, {'org':True,'list_accounts':{PRIMARY:'desk',A:'other'}})
    profile['accounts'].append({'name':'wrong','account_id':A,'regions':['us-east-1']})
    monkeypatch.setattr(accounts.aws, 'session_for', lambda *a,**k: Session({'org':True,'list_accounts':{A:'other'}}))
    report = discover(profile, probe=probe)
    assert report['authenticated_accounts'] == [PRIMARY]
    assert A in report['not_covered']
    assert any(c.get('error')=='ValueError' for c in report['role_checks'])


def test_routing_falls_back_on_denial_truncation_and_different_region(monkeypatch):
    for outcome in ('denied','truncated','complete'):
        calls=[]
        def collector(session, account, region, opts):
            calls.append((account['account_id'],region))
            if account['account_id']==PRIMARY and outcome=='denied':
                raise denied()
            return [], {'truncated':account['account_id']==PRIMARY and outcome=='truncated'}
        monkeypatch.setitem(collect.COLLECTORS,'guardduty',collector)
        profile=config.normalize({'sources':['guardduty'],'regions':['us-east-1','us-east-2'],'accounts':[
            {'name':'desk','account_id':PRIMARY,'_session':object()},
            {'name':'member','account_id':A,'_session':object()}]})
        _, coverage=collect.collect(profile,routes=[{'source':'guardduty','reader_account':PRIMARY,
                                                   'region':'us-east-1','members':[A]}])
        assert (A,'us-east-2') in calls
        assert ((A,'us-east-1') in calls) == (outcome!='complete')
        member=next(c for c in coverage if c['account_id']==A and c['region']=='us-east-1')
        assert bool(member.get('via_account')) == (outcome=='complete')


def test_legacy_skip_cannot_hide_member_reads(monkeypatch):
    calls=[]
    monkeypatch.setitem(collect.COLLECTORS,'guardduty',lambda s,a,r,o:(calls.append(a['account_id']) or [],{}))
    profile=config.normalize({'sources':['guardduty'],'accounts':[{'account_id':A,'_session':object()}]})
    collect.collect(profile,skip={('guardduty',A)})
    assert calls==[A]


def test_membership_failure_is_unknown_not_proof_of_no_administrator(monkeypatch):
    profile, probe, _=setup(monkeypatch,{'org':True,'list_accounts':{PRIMARY:'desk'}})
    def fail(*args):
        raise denied()
    monkeypatch.setattr(accounts,'_members',fail)
    report=discover(profile,probe=probe)
    assert not report['routes']
    assert all(c['status']=='unknown' for c in report['discovery_checks'])


def test_hub_product_exclusion_requires_known_local_query_scope(monkeypatch):
    class Hub:
        def describe_hub(self): return {}
        def list_finding_aggregators(self):
            return {'FindingAggregators':[{'FindingAggregatorArn':'aggregate'}] if aggregated else []}
        def get_paginator(self, op): return self
        def paginate(self, **kwargs):
            filters.append(kwargs['Filters'])
            class Result(list):
                resume_token = None
            return Result([{'Findings':[]}])
    monkeypatch.setattr(collect.aws,'client',lambda *args:Hub())
    for aggregated, member_scope, membership_known in [(False,False,True),(True,False,True),(False,True,True),(False,False,False)]:
        filters=[]
        account={'membership_status':{'securityhub':{'us-east-1':'ok' if membership_known else 'unknown'}},
                 'admin_regions':{'securityhub':['us-east-1'] if member_scope else []}}
        _,meta=collect.collect_securityhub(None,account,'us-east-1',
            {'exclude_products':['Inspector'],'detail_limits':{'HIGH':10}})
        expected=['Inspector'] if membership_known and not aggregated and not member_scope else []
        assert meta['excluded_products']==expected
        assert all(bool(f.get('ProductName'))==bool(expected) for f in filters)


def test_inspector_administrator_scope_is_regional(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(collect.aws,'client',lambda *args:SimpleNamespace(
        batch_get_account_status=lambda:{'accounts':[{'state':{'status':'ENABLED'}}]}))
    scopes=[]
    monkeypatch.setattr(collect,'_aggregate',lambda client,kind,key,limit,account_id:scopes.append(account_id) or [])
    monkeypatch.setattr(collect,'paginate_ex',lambda *args,**kwargs:([],False))
    account={'account_id':PRIMARY,'admin_regions':{'inspector':['us-east-1']}}
    for region, expected in [('us-east-1',''),('us-east-2',PRIMARY)]:
        scopes.clear()
        _,meta=collect.collect_inspector(None,account,region,{'detail_limits':{}})
        assert set(scopes)=={expected}
        assert meta['org_wide']==(region=='us-east-1')


def test_matrix_does_not_turn_authentication_or_membership_into_success():
    profile=config.normalize({'sources':['guardduty'],'regions':['us-east-1','us-east-2'],
                              'accounts':[{'account_id':PRIMARY}]})
    report={'full_read':[PRIMARY],'findings_only':[A],'not_covered':[B]}
    matrix=accounts.coverage_matrix(report,profile,[{'source':'guardduty','account_id':PRIMARY,
        'region':'us-east-1','status':'ok','truncated':True}])
    assert next(c for c in matrix if c['account_id']==PRIMARY and c['region']=='us-east-1')['status']=='partial'
    assert next(c for c in matrix if c['account_id']==PRIMARY and c['region']=='us-east-2')['status']=='not_scanned'
    assert all(c['status']=='unavailable' for c in matrix if c['account_id'] in [A,B])


def test_discovery_policy_is_read_only_and_includes_live_missing_permission():
    import json
    from pathlib import Path
    policy=json.loads(Path('deploy/aws-single/reader-discovery-policy.json').read_text())
    actions=policy['Statement'][0]['Action']
    assert 'inspector2:ListMembers' in actions
    assert all(a.split(':')[1].startswith(('List','Describe','Get')) for a in actions)


def test_hub_home_and_linking_configuration_are_preserved_without_inferred_members(monkeypatch):
    profile,probe,_=setup(monkeypatch,{'org':True,'list_accounts':{PRIMARY:'desk'}})
    profile['accounts'][0]['regions']=['us-east-1','us-east-2']
    class Hub:
        def get_paginator(self,operation):
            assert operation=='list_finding_aggregators'
            return Pages([{'FindingAggregators':[{'FindingAggregatorArn':'example'}]}])
        def get_finding_aggregator(self,**kwargs):
            return {'FindingAggregationRegion':'us-east-1','RegionLinkingMode':'ALL_REGIONS_EXCEPT_SPECIFIED',
                    'Regions':['eu-central-1']}
    monkeypatch.setattr(accounts.aws,'client',lambda *args:Hub())
    report=discover(profile,probe=probe)
    assert len(report['aggregations'])==2
    assert all(a['home_region']=='us-east-1' and a['regions']==['eu-central-1']
               and a['linking_mode']=='ALL_REGIONS_EXCEPT_SPECIFIED' for a in report['aggregations'])
    assert report['routes']==[]  # linking configuration is not membership evidence
