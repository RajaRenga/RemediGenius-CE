import pytest
from types import SimpleNamespace

from tools import runtime_access_check
from tools.runtime_access_check import proof_profile


def test_custom_reader_is_preserved_and_every_account_uses_requested_regions():
    profile = proof_profile('arn:aws:iam::111122223333:role/Audit', ['us-east-1', 'eu-central-1'],
                            '111122223333', {'accounts':[
                                {'account_id':'444455556666','role_arn':'arn:aws:iam::444455556666:role/CustomReader',
                                 'regions':['us-west-2']}], 'max_findings_per_source':999999})
    assert profile['accounts'][1]['role_arn'].endswith('/CustomReader')
    assert all(a['regions']==['us-east-1','eu-central-1'] for a in profile['accounts'])
    assert profile['max_findings_per_source']==10


def test_workstation_credentials_cannot_replace_runtime_proof():
    with pytest.raises(ValueError, match='workstation'):
        proof_profile('arn:aws:iam::111122223333:role/Audit', ['us-east-1'], '111122223333',
                      {'accounts':[{'account_id':'444455556666','aws_profile':'administrator',
                                    'role_arn':'arn:aws:iam::444455556666:role/Reader'}]})


def test_wrong_assumed_role_is_rejected_before_collection(monkeypatch):
    sts = SimpleNamespace(get_caller_identity=lambda: {
        'Account':'111122223333', 'Arn':'arn:aws:sts::111122223333:assumed-role/Administrator/session'})
    monkeypatch.setattr(runtime_access_check.aws, 'session_for', lambda _: SimpleNamespace(client=lambda _: sts))
    with pytest.raises(ValueError, match='expected runtime role'):
        runtime_access_check.check('arn:aws:iam::111122223333:role/Audit', ['us-east-1'],
                                   expected_runtime_role='arn:aws:iam::111122223333:role/Runtime')
