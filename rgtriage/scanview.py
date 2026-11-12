"""A complete serving generation, committed last; no duplicate finding/evidence store."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import contracts

VERSION = 1
COVERAGE_FIELDS = {"region", "source", "status", "count", "total", "truncated", "completeness", "note"}


class IncompleteView(RuntimeError):
    pass


def fingerprint(value):
    return hashlib.sha256(contracts.canonical_json(value).encode()).hexdigest()


def scope(row):
    return (str(row.get("account_id") or row.get("account") or ""), row["region"], row["source"])


def descriptor(repo, scan, mark, coverage_snapshot, run_id):
    """Store grouping/metadata once, referencing the existing full finding payloads and coverage facts."""
    snapshots = {"current_findings": repo.storage.last_snapshot_id("current_findings"),
                 "coverage": coverage_snapshot}
    specs = [{"scope": list(scope(row)), "fields": [k for k in row if k in COVERAGE_FIELDS],
              "extra": {k: v for k, v in row.items() if k not in COVERAGE_FIELDS}}
             for row in scan.get("coverage", [])]
    return {"version": VERSION, "installation_id": mark["installation_id"], "watermark": mark,
            "run_id": run_id, "snapshots": snapshots,
            "metadata": {k: v for k, v in scan.items() if k not in ("findings", "coverage")},
            "finding_keys": [f["key"] for f in scan.get("findings", [])], "coverage_specs": specs,
            "counts": {k: len(scan.get(k, [])) for k in ("findings", "issues", "coverage")},
            "sha256": fingerprint(scan)}


def materialize(repo, desc):
    if desc.get("version") != VERSION or desc.get("installation_id") != repo.cache.installation_id():
        raise IncompleteView("unsupported or foreign scan generation")
    refs = desc["snapshots"]
    if (desc["watermark"]["namespace"] != repo.storage_profile.namespace
            or (refs.get("current_findings") is None and desc["finding_keys"])
            or (refs.get("coverage") is None and desc["coverage_specs"])):
        raise IncompleteView("generation lacks pinned inputs or belongs to another namespace")
    findings = repo.storage.scan_rows("current_findings", snapshot_id=refs["current_findings"])
    indexed = {row["finding_key"]: json.loads(row["payload"]) for row in findings}
    if len(indexed) != len(findings) or set(indexed) != set(desc["finding_keys"]):
        raise IncompleteView("finding membership does not match the committed generation")
    from pyiceberg.expressions import And, EqualTo
    rows = (repo.storage.table("coverage").scan(snapshot_id=refs["coverage"], row_filter=And(
                EqualTo("run_id", desc["run_id"]), EqualTo("installation_id", desc["installation_id"]))).to_arrow().to_pylist()
            if refs.get("coverage") is not None else [])
    rows = [row for row in rows if row.get("run_id") == desc["run_id"]
            and row.get("installation_id") == desc["installation_id"]]
    indexed_cov = {scope(row): row for row in rows}
    if len(indexed_cov) != len(rows) or set(indexed_cov) != {tuple(s["scope"]) for s in desc["coverage_specs"]}:
        raise IncompleteView("coverage membership does not match the committed generation")
    coverage = [{**spec["extra"], **{k: indexed_cov[tuple(spec["scope"])][k] for k in spec["fields"]}}
                for spec in desc["coverage_specs"]]
    scan = {**desc["metadata"], "findings": [indexed[k] for k in desc["finding_keys"]], "coverage": coverage}
    if any(len(scan.get(k, [])) != n for k, n in desc["counts"].items()) or fingerprint(scan) != desc["sha256"]:
        raise IncompleteView("scan generation count/hash mismatch")
    return scan


def publish(repo, scan, mark, coverage_snapshot, run_id):
    desc = descriptor(repo, scan, mark, coverage_snapshot, run_id)
    materialize(repo, desc)  # Positive verification before the atomic publication point.
    repo.storage.overwrite_rows("current_scan", [{"installation_id": desc["installation_id"],
        "scan_id": desc["sha256"], "format_version": VERSION, "descriptor": contracts.canonical_json(desc)}],
        snapshot_properties={"ce.current": "complete-scan", "ce.scan_id": desc["sha256"]})
    return desc


def read_descriptor(storage):
    rows = storage.scan_rows("current_scan")
    if not rows:
        return None
    if len(rows) != 1 or rows[0]["format_version"] != VERSION:
        raise IncompleteView("unsupported complete-scan manifest")
    desc = json.loads(rows[0]["descriptor"])
    if rows[0]["scan_id"] != desc.get("sha256") or rows[0]["installation_id"] != desc.get("installation_id"):
        raise IncompleteView("scan manifest identity mismatch")
    return desc


def _legacy(repo):
    """Upgrade a pre-manifest scan only after checking exports against committed Iceberg facts."""
    installation = repo.cache.installation_id()
    prefix = f"exports/{installation}/"
    if not installation or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in installation):
        raise IncompleteView("invalid installation identity")
    profile = repo.storage_profile
    if profile.kind == "aws":
        import boto3
        client = boto3.client("s3", region_name=repo.storage.region)
        bucket = profile.warehouse[5:].split("/", 1)[0]
        def read(key):
            return client.get_object(Bucket=bucket, Key=key)["Body"].read()
    else:
        root = Path(profile.warehouse).parent
        def read(key):
            return (root / key).read_bytes()

    def checked(key, digest=None):
        if not key.startswith(prefix) or ".." in key.split("/") or "\\" in key:
            raise IncompleteView("export reference escapes installation")
        body = read(key)
        if digest and hashlib.sha256(body).hexdigest() != digest:
            raise IncompleteView("export hash mismatch")
        return json.loads(body)

    pointer = checked(prefix + "latest.json")
    manifest = checked(pointer["manifest"], pointer["manifest_sha256"])
    if manifest.get("format") != "remedigenius-readable-scan/1" or manifest.get("installation_id") != installation:
        raise IncompleteView("unsupported or foreign export manifest")
    if any(manifest[k] != pointer[k] for k in ("scan_id", "scanned_at")):
        raise IncompleteView("export pointer/generation mismatch")
    files = {}
    for name in ("findings.json", "coverage.json"):
        ref = manifest["files"][name]
        files[name] = checked(ref["key"], ref["sha256"])
        if files[name]["scanned_at"] != manifest["scanned_at"]:
            raise IncompleteView("export mixes scan observation times")
    stamp = manifest["scanned_at"]
    runs = repo.storage.scan_rows("scan_runs", snapshot_id=manifest["snapshots"]["scan_runs"])
    candidates = [r for r in runs if r["installation_id"] == installation
                  and r["started_at"] == contracts.parse_time(stamp)]
    if len(candidates) != 1:
        raise IncompleteView("export does not identify one committed scan")
    run = candidates[0]
    # An older export is not a substitute for a newer committed scan.
    latest = repo.storage.scan_rows("scan_runs")
    if any(r["installation_id"] == installation and r["started_at"] > run["started_at"] for r in latest):
        raise IncompleteView("legacy export lags committed scan; complete reconstruction unavailable")
    scan = {"version": "0.5.0", "profile": {"name": repo.profile.get("name", "AWS")},
            **files["findings.json"], **files["coverage.json"], "changes": {}, "fixes": [],
            "recovery_note": "Legacy export restored; original profile/change/fix metadata was not preserved in this format."}
    if len(scan["findings"]) != run["findings_count"] or len(scan["issues"]) != run["issues_count"]:
        raise IncompleteView("legacy export counts disagree with committed scan")
    keys = {f["key"] for f in scan["findings"]}
    if len(keys) != len(scan["findings"]):
        raise IncompleteView("duplicate finding keys in legacy export")
    for issue in scan["issues"]:
        if issue.get("top_key") not in keys or not set(issue.get("finding_keys", [])).issubset(keys):
            raise IncompleteView("legacy grouping references missing findings")
    # Full finding payload comparison, allowing later durable decisions to be overlaid separately.
    current = [json.loads(row["payload"]) for row in repo.storage.scan_rows("current_findings")]
    without_decision = lambda rows: sorted((fingerprint({k: v for k, v in f.items() if k != "decision"}) for f in rows))
    if without_decision(current) != without_decision(scan["findings"]):
        raise IncompleteView("legacy findings disagree with current committed facts")
    order = {finding["key"]: i for i, finding in enumerate(files["findings.json"]["findings"])}
    scan["findings"] = sorted(current, key=lambda f: order[f["key"]])
    # The descriptor's exact hash and materialization also verify every coverage value, alias and count.
    desc = descriptor(repo, scan, manifest["watermark"], manifest["snapshots"].get("coverage"), run["run_id"])
    materialize(repo, desc)
    return scan, desc


def restore(repo):
    desc = read_descriptor(repo.storage)
    if desc is None:
        if not repo.storage.scan_rows("scan_runs"):
            return None, None
        scan, desc = _legacy(repo)
        # Promote verified legacy metadata, not its facts, into the normal complete-view manifest.
        desc = publish(repo, scan, desc["watermark"], desc["snapshots"]["coverage"], desc["run_id"])
    else:
        scan = materialize(repo, desc)
    # Human decisions have their own durable stream; never roll them back to scan time.
    decisions = repo.load_decisions()
    for finding in scan["findings"]:
        if finding["key"] in decisions:
            finding["decision"] = decisions[finding["key"]]
    for issue in scan["issues"]:
        decision = next((decisions[k] for k in [issue.get("top_key"), *issue.get("finding_keys", [])] if k in decisions), None)
        if decision:
            issue["decision"] = decision
    return scan, desc
