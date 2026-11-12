"""Inspect tracked files and release zip/wheel contents without printing matched secrets."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_ACCOUNTS = {'000000000000', '111111111111', '111122223333', '222222222222',
                    '222233334444', '333333333333', '444444444444', '444455556666', '123456789012',
                    '999900001111', '999999999999', '999988887777'}
SECRET_PATTERNS = [rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', rb'\bgh[pousr]_[A-Za-z0-9]{30,}\b',
                   rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/]{30,}']
EXAMPLE_KEYS = {b'AKIAIOSFODNN7EXAMPLE', b'AKIAABCDEFGHIJKLMNOP'}  # AWS docs / redaction fixtures


def inspect(name: str, data: bytes) -> list[str]:
    problems = []
    parts = Path(name).parts
    base = Path(name).name.lower()
    if any(p in {'.rgce', '.aws', '.terraform', '__pycache__', '.git'} for p in parts) or base in {
            '.env', 'local.json', 'terraform.tfstate', 'terraform.tfstate.backup', 'remedigenius-login.json'}:
        problems.append('private-state filename')
    for pattern in SECRET_PATTERNS:
        if any(match not in EXAMPLE_KEYS for match in re.findall(pattern, data)):
            problems.append('credential pattern')
    ids = {v.decode() for v in re.findall(rb'(?<![A-Za-z0-9])\d{12}(?![A-Za-z0-9])', data)}
    if ids - EXAMPLE_ACCOUNTS:
        problems.append('unreviewed account-like identifier')
    if re.search(rb'(?i)[A-Z]:[\\/]Users[\\/](?!YOUR|USER|example|test)[A-Za-z][^\s"<>]*', data):
        problems.append('personal workstation path')
    return sorted(set(problems))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path)
    args = parser.parse_args()
    names = sorted(set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')))
    sources = [('tracked', [(n, (ROOT/n).read_bytes()) for n in names if n and (ROOT/n).is_file()])]
    if args.release:
        for path in sorted(args.release.iterdir()):
            if path.suffix in {'.zip', '.whl'}:
                with zipfile.ZipFile(path) as archive:
                    sources.append((path.name, [(n, archive.read(n)) for n in archive.namelist() if not n.endswith('/')]))
    reports = []
    for label, files in sources:
        failures = [{'file': name, 'controls': issues} for name, data in files if (issues := inspect(name, data))]
        reports.append({'source': label, 'files': len(files), 'failures': failures,
                        'controls': ['credential patterns', 'account identifiers (documented examples allowed)',
                                     'private state filenames', 'personal workstation paths'],
                        'result': 'FAIL' if failures else 'PASS'})
    print(json.dumps(reports, indent=2))
    raise SystemExit(1 if any(r['failures'] for r in reports) else 0)


if __name__ == '__main__':
    main()
