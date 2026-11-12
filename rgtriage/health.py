"""Storage health for operators (roadmap CE-15).

The names are part of the storage contract (`contracts.HEALTH_FIELDS`). Health is read-only: it never commits,
rebuilds or reconciles. A degraded state names the reason instead of hiding it.
"""
from __future__ import annotations

from . import contracts
import json


def snapshot(repository, *, checkpoint_age_seconds: float | None = None) -> dict:
    cache = repository.cache
    state = cache.health()
    try:
        operations = len(repository.storage.scan_rows("current_operations"))
        storage_error = ""
    except Exception as exc:
        operations, storage_error = 0, f"{type(exc).__name__}: {exc}"[:300]
    backlog = repository.raw.buffer_status()
    mark = state.get("commit_watermark")
    conflicts = state.get("conflicts", 0)
    outbox = state.get("outbox_events", 0)
    decisions = state.get("undurable_decisions", 0)
    status = "healthy"
    reason = storage_error
    if storage_error:
        status = "blocked"
    elif outbox or decisions or backlog.get("objects"):
        status, reason = "degraded", (f"{outbox} event(s) not yet durable, {decisions} decision(s) not yet durable, "
                                      f"{backlog.get('objects', 0)} raw object(s) buffered")
    elif conflicts:
        status, reason = "degraded", f"{conflicts} conflicting event id(s) quarantined"
    elif not mark:
        status, reason = "recovering", "no committed fact yet"
    scan = repository.load_latest() or {}
    readiness = json.loads(cache.get_meta("view_readiness", "{}") or "{}")
    if readiness.get("state") == "blocked":
        status, reason = "blocked", readiness.get("reason", "complete scan recovery failed")
    elif readiness.get("state") == "previous_generation" and status != "blocked":
        status, reason = "degraded", readiness["reason"]
    elif not scan or readiness.get("state") != "ready":
        if status == "healthy":
            status, reason = "recovering", "complete scan view is not ready"
    from . import config, scanview
    import hashlib
    dashboard = {"state": "not_ready"}
    try:
        rendered = json.loads((config.home() / "status.json").read_text(encoding="utf-8"))
        if (scan and rendered.get("generation") == scanview.fingerprint(scan)
                and rendered.get("board_sha256") == hashlib.sha256((config.home() / "board.html").read_bytes()).hexdigest()):
            dashboard = {"state": "ready", "generation": rendered["generation"]}
    except (OSError, ValueError):
        pass
    if status == "healthy" and dashboard["state"] != "ready":
        status, reason = "recovering", "committed view available; dashboard projection is not ready"
    scanned = scan.get('scanned_at')
    try:
        age = max(0, (contracts.utc_now() - contracts.parse_time(scanned)).total_seconds())
    except (ValueError, TypeError, contracts.ContractError):
        age = None
    freshness = {'state': 'unknown' if age is None else 'stale' if age >= 6 * 3600 else 'recent',
                 'scanned_at': scanned, 'age_seconds': age,
                 'note': 'Storage health does not establish AWS freshness. Recent means a recent scan, not live verification.',
                 'coverage': [{'source': c.get('source'), 'account': c.get('account'), 'region': c.get('region'),
                               'status': c.get('status'), 'truncated': bool(c.get('truncated'))}
                              for c in scan.get('coverage', [])]}
    return {
        "installation_id": state.get("installation_id"), "namespace": state.get("namespace"),
        "epoch": state.get("epoch"), "state": status, "commit_watermark": mark,
        "commit_age_seconds": state.get("commit_age_seconds"), "outbox_events": outbox,
        "undurable_decisions": decisions, "raw_backlog": backlog.get("objects", 0),
        "raw_backlog_bytes": backlog.get("bytes", 0), "buffer_limit_bytes": backlog.get("limit_bytes", 0),
        "last_maintenance": cache.get_meta("last_maintenance", "") or "",
        "checkpoint_age_seconds": checkpoint_age_seconds, "unresolved_operations": operations, "reason": reason,
        "conflicts": conflicts, "batches": state.get("batches", {}),
        "freshness": freshness,
        "view_readiness": readiness or {"state": "recovering"},
        "dashboard": dashboard,
        "readable_export": json.loads(cache.get_meta('readable_export', '{}') or '{}'),
    }


def fields_ok(health: dict) -> list[str]:
    missing = [name for name in contracts.HEALTH_FIELDS if name not in health]
    return missing
