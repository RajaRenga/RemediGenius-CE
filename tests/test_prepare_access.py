import json

import pytest

from tools.prepare_access import prepare

RUNTIME='arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/example/Reader'
MANAGEMENT='111122223333'
MEMBER='444455556666'


def report(mode='organization'):
    return {'mode':mode,'reader_arn':RUNTIME,'organization_id':'o-exampleorg1' if mode=='organization' else '',
            'management_account':MANAGEMENT,'member_role_name':'CustomReader'}


def test_standalone_packet_has_exact_trust_and_no_organization_condition(tmp_path):
    result=prepare(report('standalone'),accounts=[MEMBER],region='us-east-1',output=tmp_path)
    trust=json.loads((tmp_path/'target-trust.json').read_text())['Statement'][0]
    caller=json.loads((tmp_path/'caller-policy.json').read_text())['Statement'][0]
    assert trust['Principal']['AWS']==RUNTIME and 'Condition' not in trust
    assert caller['Resource']==[f'arn:aws:iam::{MEMBER}:role/CustomReader']
    assert 'execute-change-set' not in (tmp_path/'commands.txt').read_text()
    assert result['aws_changes'] is False


def test_stackset_scope_is_explicit_and_management_is_separate(tmp_path):
    prepare(report(),accounts=[MANAGEMENT,MEMBER],region='us-east-1',output=tmp_path,
            ou='r-abcd',delegated=True)
    targets=json.loads((tmp_path/'targets.json').read_text())
    commands=(tmp_path/'commands.txt').read_text()
    assert targets=={'OrganizationalUnitIds':['r-abcd'],'AccountFilterType':'INTERSECTION','Accounts':[MEMBER]}
    assert commands.count('--call-as DELEGATED_ADMIN')==2
    assert '--auto-deployment Enabled=false' in commands
    assert f'credentials for account {MANAGEMENT}' in commands
    assert 'create-change-set' in commands


@pytest.mark.parametrize('update',[
    {'mode':'unknown'}, {'reader_arn':'arn:aws:sts::111122223333:assumed-role/Reader/session'},
    {'member_role_name':'Read;write'}, {'organization_id':''}])
def test_unsafe_or_unverified_report_is_rejected(tmp_path,update):
    value={**report(),**update}
    with pytest.raises(ValueError):
        prepare(value,accounts=[MEMBER],region='us-east-1',output=tmp_path)
    assert not list(tmp_path.iterdir())


def test_existing_packet_is_never_overwritten(tmp_path):
    (tmp_path/'notes.txt').write_text('customer review')
    with pytest.raises(ValueError):
        prepare(report(),accounts=[MEMBER],region='us-east-1',output=tmp_path)
    assert (tmp_path/'notes.txt').read_text()=='customer review'
