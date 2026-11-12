"""Readable derivatives of one committed scan; facts remain authoritative in Iceberg."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from . import contracts, digest


def publish(scan, watermark, raw_refs, snapshots, storage_profile, *, client=None):
    """Publish files, manifest, then latest pointer. A failed upload never advances latest."""
    installation = str(watermark['installation_id'])
    if not re.fullmatch(r'[A-Za-z0-9_-]+', installation):
        raise ValueError('Unsafe export installation identifier')
    scan_id = hashlib.sha256(contracts.canonical_json(scan).encode()).hexdigest()[:24]
    prefix = f'exports/{installation}/scans/{scan_id}'
    encode = lambda value: (json.dumps(contracts.jsonable(value), indent=2, sort_keys=True) + '\n').encode()
    files = {
        'board.html': digest.html_report(scan).encode('utf-8'),
        'findings.json': encode({'scanned_at': scan['scanned_at'], 'findings': scan.get('findings', []),
                                 'issues': scan.get('issues', [])}),
        'coverage.json': encode({'scanned_at': scan['scanned_at'], 'coverage': scan.get('coverage', []),
                                'partial': bool(scan.get('partial')), 'stored_overflow': scan.get('stored_overflow', 0)}),
    }
    refs = {ref.key: ref.as_dict() for ref in raw_refs if ref is not None}
    manifest = {'format': 'remedigenius-readable-scan/1', 'scan_id': scan_id,
                'view_generation': hashlib.sha256(contracts.canonical_json(scan).encode()).hexdigest(),
                'counts': {name: len(scan.get(name, [])) for name in ('findings', 'issues', 'coverage')},
                'installation_id': installation, 'scanned_at': scan['scanned_at'],
                'watermark': watermark, 'snapshots': snapshots,
                'raw_evidence': list(refs.values()),
                'evidence_note': 'References identify evidence at commit time; objects may expire under retention policy.',
                'files': {name: {'key': f'{prefix}/{name}', 'sha256': hashlib.sha256(body).hexdigest(),
                                 'bytes': len(body)} for name, body in files.items()}}
    manifest_body = encode(manifest)
    pointer = encode({'format': manifest['format'], 'scan_id': scan_id, 'scanned_at': scan['scanned_at'],
                      'manifest': f'{prefix}/manifest.json',
                      'manifest_sha256': hashlib.sha256(manifest_body).hexdigest()})
    if storage_profile.kind == 'aws':
        if client is None:
            import boto3
            client = boto3.client('s3')
        bucket = storage_profile.warehouse[5:].split('/', 1)[0]
        def write(key, body):
            client.put_object(Bucket=bucket, Key=key, Body=body,
                              ContentType='text/html; charset=utf-8' if key.endswith('.html') else 'application/json')
        location = f's3://{bucket}/exports/{installation}/latest.json'
    else:
        root = Path(storage_profile.warehouse).parent
        def write(key, body):
            path = root / key
            path.parent.mkdir(parents=True, exist_ok=True)
            temp = path.with_name(path.name + f'.{os.getpid()}.tmp')
            temp.write_bytes(body)
            os.replace(temp, path)
        location = str(root / f'exports/{installation}/latest.json')
    for name, body in files.items():
        write(f'{prefix}/{name}', body)
    write(f'{prefix}/manifest.json', manifest_body)
    write(f'exports/{installation}/latest.json', pointer)
    return {'state': 'ready', 'location': location, 'scan_id': scan_id, 'scanned_at': scan['scanned_at']}
