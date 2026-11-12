"""Readable derivatives must never advertise an incomplete upload."""
import hashlib
import json

import pytest

from rgtriage import contracts, exports


def test_pointer_is_published_last_and_survives_failed_upload(monkeypatch):
    monkeypatch.setattr(exports.digest, 'html_report', lambda scan: '<html>board</html>')
    profile = contracts.StorageProfile('aws', 'test', 's3://example/warehouse', 'glue')
    mark = {'installation_id': 'test-installation'}
    objects = {}
    class S3:
        fail = False
        def put_object(self, **kwargs):
            if self.fail and kwargs['Key'].endswith('coverage.json'):
                raise OSError('interrupted upload')
            objects[kwargs['Key']] = kwargs['Body']
    client = S3()
    first = {'scanned_at': '2026-11-11T00:00:00Z'}
    exports.publish(first, mark, [], {'scan_runs': 123}, profile, client=client)
    pointer_key = 'exports/test-installation/latest.json'
    assert list(objects)[-1] == pointer_key
    pointer_bytes = objects[pointer_key]
    pointer = json.loads(pointer_bytes)
    manifest_bytes = objects[pointer['manifest']]
    assert hashlib.sha256(manifest_bytes).hexdigest() == pointer['manifest_sha256']
    manifest = json.loads(manifest_bytes)
    assert manifest['snapshots']['scan_runs'] == 123
    for item in manifest['files'].values():
        assert hashlib.sha256(objects[item['key']]).hexdigest() == item['sha256']
    client.fail = True
    with pytest.raises(OSError):
        exports.publish({'scanned_at': '2026-11-11T01:00:00Z'}, mark, [], {}, profile, client=client)
    assert objects[pointer_key] == pointer_bytes
    client.fail = False
    exports.publish(first, mark, [], {'scan_runs': 123}, profile, client=client)
    assert objects[pointer_key] == pointer_bytes
