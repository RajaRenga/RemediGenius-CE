"""Crash, rebuild and outage proofs on a real local Iceberg catalog (roadmap CE-15).

These are on-disk tests against the local profile. They are not a claim about AWS: the optional AWS profile test is
skipped unless RGTRIAGE_AWS_STORAGE_TEST is set and a disposable Glue database and warehouse are configured.
"""
from __future__ import annotations

import os
import json
from datetime import datetime, timezone

import pytest

from rgtriage import cache as cache_module
from rgtriage import commit, contracts, current, health, iceberg_store, rawstore, recovery, repository, scanview

NOW = "2026-06-15T10:00:00Z"
SCOPE = contracts.Scope(account="111122223333", region="us-east-1", source="inspector")


def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("RGTRIAGE_HOME", str(tmp_path))
    profile = {"name": "desk", "regions": ["us-east-1"],
               "storage": {"profile": "local", "namespace": "remedigenius", "installation_id": "installation-test"}}
    storage_profile = contracts.StorageProfile(kind="local", namespace="remedigenius",
                                               warehouse=str(tmp_path / "warehouse"), catalog="sql",
                                               catalog_uri=str(tmp_path / "catalog.db"))
    storage = iceberg_store.IcebergStore.open(storage_profile)
    storage.ensure_tables()
    cache_path = tmp_path / "cache" / "desk.sqlite3"
    cache = cache_module.Cache(cache_path, timeout=1)
    cache.set_identity("installation-test", "remedigenius", epoch="epoch-1")
    raw = rawstore.RawStore(rawstore.FolderBackend(tmp_path / "raw"))
    repo = repository.Repository(cache, raw, storage, profile, storage_profile, cache_existed=True)
    return repo, storage, cache, raw, storage_profile, cache_path


def finding(n: int = 1) -> dict:
    return {"key": f"key{n}", "source": "inspector", "native_id": f"n{n}", "product": "Inspector",
            "account": "111122223333", "region": "us-east-1", "title": f"Finding {n}", "description": "d",
            "severity": "HIGH", "category": "vulnerability", "type": "PACKAGE_VULNERABILITY",
            "control_id": "CVE-2024-1", "resource": {"type": "AwsEc2Instance", "id": f"i-{n}", "name": f"i-{n}", "tags": {}},
            "first_seen": NOW, "last_seen": NOW, "workflow": "NEW", "priority": "P2", "score": 60,
            "reasons": [], "signals": {}, "context": {}}


def scan(n: int = 1, at: str = NOW) -> dict:
    item = finding(n)
    return {"version": "0.5.0", "scanned_at": at, "profile": {"name": "test"}, "findings": [item],
            "issues": [{"issue_key": f"issue-{n}", "finding_keys": [item["key"]], "top_key": item["key"], "priority": "P2"}],
            "coverage": [{"source": "inspector", "account": "desk", "account_id": "111122223333",
                          "region": "us-east-1", "status": "ok", "count": 1, "total": 1, "truncated": False,
                          "completeness": "ok"}],
            "fixes": [], "changes": {"new": 0}}


def test_committed_scan_and_decision_survive_deleting_the_cache(tmp_path, monkeypatch):
    repo, storage, cache, raw, storage_profile, path = setup(tmp_path, monkeypatch)
    repo.save_scan(scan(1))
    row = storage.scan_rows('findings')[0]
    assert row['ocsf']['time'].year == 2026
    assert row['ocsf']['finding_info']['first_seen_time'].year == 2026
    assert health.snapshot(repo)['readable_export']['state'] == 'ready'
    repo.decide("key1", "fixing", "on it", by="owner")
    installation = cache.installation_id()
    cache.close()
    for suffix in ("", "-wal", "-shm"):
        path.with_name(path.name + suffix).unlink(missing_ok=True)

    fresh = cache_module.Cache(path, timeout=1)
    fresh_repo = repository.Repository(fresh, raw, storage, repo.profile, storage_profile, cache_existed=False)
    report = fresh_repo.recover(empty_disk=True, installation_id=installation)
    assert report.state in ("recovering", "healthy")
    assert len(storage.scan_rows("current_findings")) == 1
    assert len(storage.scan_rows("current_decisions")) == 1
    rebuilt = fresh_repo.load_latest()
    assert rebuilt["findings"][0]["key"] == "key1"
    assert rebuilt["coverage"] == scan(1)["coverage"]
    assert rebuilt["issues"][0]["issue_key"] == "issue-1"
    assert rebuilt["issues"][0]["decision"]["status"] == "fixing"
    assert rebuilt["scanned_at"] == NOW
    assert report.needs_scan is False
    assert fresh_repo.load_decisions()["key1"]["status"] == "fixing"


def test_an_uncommitted_scan_is_reported_as_needing_a_rerun(tmp_path, monkeypatch):
    repo, storage, cache, raw, storage_profile, path = setup(tmp_path, monkeypatch)
    payload = finding(1)
    page = raw.put_json({"Findings": []}, scope=SCOPE, operation="ListFindings", observed_at=NOW)
    event = contracts.Event(event_id=contracts.observation_event_id("installation-test", SCOPE, NOW,
                                                                     contracts.payload_hash(payload)),
                            kind="observation", installation_id="installation-test", epoch="epoch-1", sequence=0,
                            scope=SCOPE, observed_at=NOW, ingested_at=NOW, payload_hash=contracts.payload_hash(payload),
                            raw_ref=page.ref)
    cache.stage_facts([(event, payload)])
    assert cache.pending_count() == 1
    assert storage.scan_rows("current_findings") == []
    cache.close()
    for suffix in ("", "-wal", "-shm"):
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    fresh = cache_module.Cache(path, timeout=1)
    fresh_repo = repository.Repository(fresh, raw, storage, repo.profile, storage_profile, cache_existed=False)
    report = fresh_repo.recover(empty_disk=True, installation_id="installation-test")
    assert report.needs_scan is True
    assert storage.scan_rows("current_findings") == []


def test_a_commit_without_acknowledgement_is_not_duplicated(tmp_path, monkeypatch):
    repo, storage, cache, raw, storage_profile, path = setup(tmp_path, monkeypatch)
    repo.save_scan(scan(1))
    payload = finding(2)
    page = raw.put_json({"Findings": []}, scope=SCOPE, operation="ListFindings", observed_at=NOW)
    event = contracts.Event(event_id=contracts.observation_event_id("installation-test", SCOPE, NOW,
                                                                     contracts.payload_hash(payload)),
                            kind="observation", installation_id="installation-test", epoch="epoch-1", sequence=0,
                            scope=SCOPE, observed_at=NOW, ingested_at=NOW, payload_hash=contracts.payload_hash(payload),
                            raw_ref=page.ref)
    cache.stage_facts([(event, payload)])
    first = repo.committer.commit_pending(ack=False)
    assert first.status == "committed-not-acked"
    assert len(storage.scan_rows("findings")) == 2
    report = repo.recover()
    assert report.state in ("healthy", "degraded")
    assert len(storage.scan_rows("findings")) == 2  # no duplicate
    assert cache.pending_count() == 0


def test_maintenance_during_commits_keeps_every_row(tmp_path, monkeypatch):
    repo, storage, cache, raw, storage_profile, path = setup(tmp_path, monkeypatch)
    repo.save_scan(scan(1))
    before = len(storage.scan_rows("findings"))
    maintenance = storage.maintenance()
    assert maintenance["at"]
    repo.save_scan(scan(2, at="2026-06-15T11:00:00Z"))
    assert len(storage.scan_rows("findings")) == before + 1


def test_health_names_the_state_and_every_contract_field(tmp_path, monkeypatch):
    repo, storage, cache, raw, storage_profile, path = setup(tmp_path, monkeypatch)
    repo.save_scan(scan(1))
    value = health.snapshot(repo, checkpoint_age_seconds=12)
    assert value["state"] == "recovering"  # Facts alone do not prove dashboard readiness.
    assert value["view_readiness"]["state"] == "ready"
    assert value["dashboard"]["state"] == "not_ready"
    assert value["outbox_events"] == 0 and value["unresolved_operations"] == 0
    assert health.fields_ok(value) == []
    cache.stage_event(contracts.Event(
        event_id=contracts.operation_event_id(), kind="decision", installation_id="installation-test",
        epoch="epoch-1", sequence=0, scope=contracts.Scope(account="", region="", source="desk"),
        observed_at=NOW, ingested_at=NOW, payload_hash=contracts.payload_hash({"x": 1})), {"x": 1})
    assert health.snapshot(repo)["state"] == "degraded"


class DownStorage:
    def scan_rows(self, *args, **kwargs):
        raise RuntimeError("Glue is unreachable")


def test_an_unreachable_store_is_blocked_not_healthy(tmp_path, monkeypatch):
    repo, storage, cache, raw, storage_profile, path = setup(tmp_path, monkeypatch)
    repo.save_scan(scan(1))
    repo.storage = DownStorage()
    value = health.snapshot(repo)
    assert value["state"] == "blocked" and "unreachable" in value["reason"]


@pytest.mark.skipif(not os.environ.get("RGTRIAGE_AWS_STORAGE_TEST"),
                    reason="set RGTRIAGE_AWS_STORAGE_TEST=1 with a disposable Glue database and warehouse")
def test_optional_aws_profile_is_a_real_run_only_when_enabled(tmp_path):
    from rgtriage import config

    store = iceberg_store.from_env(config.load())
    store.ensure_tables()
    assert store.profile.kind == "aws"


def fresh_repository(repo, path):
    installation = repo.cache.installation_id()
    repo.close()
    for suffix in ("", "-wal", "-shm"):
        path.with_name(path.name + suffix).unlink(missing_ok=True)
    cache = cache_module.Cache(path, timeout=1)
    result = repository.Repository(cache, repo.raw, repo.storage, repo.profile, repo.storage_profile, cache_existed=False)
    return result, installation


def test_complete_generation_restores_without_exports_or_collection(tmp_path, monkeypatch):
    repo, storage, cache, raw, profile, path = setup(tmp_path, monkeypatch)
    original = scan()
    original['coverage'] += [{'account': 'other', 'region': 'us-west-2', 'source': 'health',
                             'status': 'not_available', 'note': 'synthetic unavailable API'}]
    repo.save_scan(original)
    fresh, installation = fresh_repository(repo, path)
    monkeypatch.setattr(scanview, '_legacy', lambda *a: pytest.fail('Exports are not required for a committed generation'))
    result = fresh.recover(installation_id=installation)
    assert result.state == 'healthy' and not result.needs_scan
    assert fresh.load_latest() == original
    assert scanview.materialize(fresh, scanview.read_descriptor(storage)) == original


def test_empty_findings_still_restore_scope_and_timestamp(tmp_path, monkeypatch):
    repo, storage, cache, raw, profile, path = setup(tmp_path, monkeypatch)
    original = scan()
    original['findings'] = []
    original['issues'] = []
    original['coverage'][0].update(status='denied', count=0, total=0)
    repo.save_scan(original)
    fresh, installation = fresh_repository(repo, path)
    result = fresh.recover(installation_id=installation)
    assert result.state == 'healthy' and not result.needs_scan
    assert fresh.load_latest() == original


def test_legacy_export_is_verified_then_promoted_without_rescan(tmp_path, monkeypatch):
    repo, storage, cache, raw, profile, path = setup(tmp_path, monkeypatch)
    original = scan()
    repo.save_scan(original)
    storage.overwrite_rows('current_scan', [])  # Emulate a pre-manifest installation.
    fresh, installation = fresh_repository(repo, path)
    result = fresh.recover(installation_id=installation)
    assert result.state == 'healthy', result.reason
    restored = fresh.load_latest()
    for name in ['findings', 'issues', 'coverage', 'scanned_at']:
        assert restored[name] == original[name]
    assert scanview.read_descriptor(storage)['version'] == 1
    assert 'Legacy' in restored['recovery_note']


def test_corrupted_legacy_export_blocks_readiness(tmp_path, monkeypatch):
    repo, storage, cache, raw, profile, path = setup(tmp_path, monkeypatch)
    repo.save_scan(scan())
    storage.overwrite_rows('current_scan', [])
    for file in tmp_path.glob('exports/*/scans/*/coverage.json'):
        file.write_text('{}', encoding='utf-8')
    fresh, installation = fresh_repository(repo, path)
    result = fresh.recover(installation_id=installation)
    assert result.state == 'blocked'
    assert 'hash mismatch' in result.reason
    assert fresh.load_latest() is None
    assert fresh.health()['state'] == 'blocked'


def test_failed_generation_publication_keeps_previous_view(tmp_path, monkeypatch):
    repo, storage, cache, raw, profile, path = setup(tmp_path, monkeypatch)
    original = scan()
    repo.save_scan(original)
    write = storage.overwrite_rows
    def fail_manifest(name, *args, **kwargs):
        if name == 'current_scan':
            raise OSError('simulated interruption before publication')
        return write(name, *args, **kwargs)
    monkeypatch.setattr(storage, 'overwrite_rows', fail_manifest)
    with pytest.raises(RuntimeError, match='previous generation retained'):
        repo.save_scan(scan(2, at='2026-06-15T11:00:00Z'))
    assert repo.load_latest() == original
    monkeypatch.setattr(storage, 'overwrite_rows', write)
    fresh, installation = fresh_repository(repo, path)
    result = fresh.recover(installation_id=installation)
    assert result.state == 'degraded'
    assert fresh.load_latest() == original
    assert fresh.health()['view_readiness']['state'] == 'previous_generation'


def test_snapshot_maintenance_preserves_serving_generation(tmp_path, monkeypatch):
    from datetime import timedelta
    repo, storage, cache, raw, profile, path = setup(tmp_path, monkeypatch)
    original = scan()
    repo.save_scan(original)
    desc = scanview.read_descriptor(storage)
    for _ in range(3):
        storage.overwrite_rows('current_findings', storage.scan_rows('current_findings'))
    storage.maintenance_settings = iceberg_store.MaintenanceSettings(snapshot_retention_days=0, min_snapshots=1)
    storage.maintenance(now=datetime.now(timezone.utc)+timedelta(days=30))
    assert storage.table('current_findings').snapshot_by_id(desc['snapshots']['current_findings']) is not None
    assert scanview.materialize(repo, desc) == original


def test_dashboard_generation_and_hash_are_required_for_ready(tmp_path, monkeypatch):
    from rgtriage import cli
    from decimal import Decimal
    repo, storage, cache, raw, profile, path = setup(tmp_path, monkeypatch)
    original = scan()
    original['findings'][0]['reasons'] = ['test finding']
    original['issues'][0].update(title='Synthetic issue', product='Inspector', severity='HIGH',
        control_id='', type='', finding_count=1, resources=['i-1'], resource_count=1,
        accounts=['desk'], reasons=['test issue'], score=60)
    original['onboarding'] = {'observed_at': datetime(2026, 6, 15, 10, tzinfo=timezone.utc),
                            'metric': Decimal('1.25')}
    expected = contracts.jsonable(original)
    repo.save_scan(original)
    assert repo.health()['state'] == 'recovering'
    cli.write_outputs(original)
    assert repo.health()['state'] == 'healthy'
    assert repo.health()['dashboard']['state'] == 'ready'
    status = json.loads((tmp_path/'status.json').read_text(encoding='utf-8'))
    assert status['scanned_at'] == NOW
    assert status['generation'] == scanview.fingerprint(expected)
    (tmp_path/'board.html').write_text('<html>incomplete</html>', encoding='utf-8')
    assert repo.health()['state'] == 'recovering'
    assert repo.health()['dashboard']['state'] == 'not_ready'
    # Local Hermes uses direct CLI subprocesses rather than `serve`; it must restore too.
    from rgtriage import store
    fresh, _ = fresh_repository(repo, path)
    monkeypatch.setattr(repository.Repository, 'open', classmethod(lambda cls: fresh))
    monkeypatch.setattr(store, '_REPOSITORY', None)
    monkeypatch.setenv('RGTRIAGE_DURABLE', '1')
    cli.main(['digest', '--coverage'])
    assert fresh.load_latest() == expected
    assert fresh.health()['state'] == 'healthy'
