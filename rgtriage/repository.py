"""The desk repository: one place that reads the cache and writes committed facts (roadmap CE-09).

Commands keep their existing output shapes, but a scan stages observations, coverage and its run into the outbox and
commits them to Iceberg; a decision is committed before it is acknowledged. The legacy JSON files are detected and
refused on a durable installation: v0.5.0 is a fresh-install release and does not import them.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from . import cache as cache_module
from . import collection, commit, contracts, current, iceberg_store, rawstore, recovery, store


class LegacyState(RuntimeError):
    """An old JSON desk state was found; this release starts fresh."""


class Repository:
    def __init__(self, cache: cache_module.Cache, raw: rawstore.RawStore, storage: iceberg_store.IcebergStore,
                 profile: dict, storage_profile: contracts.StorageProfile, *, cache_existed: bool = True):
        self.cache = cache
        self.raw = raw
        self.storage = storage
        self.profile = profile
        self.storage_profile = storage_profile
        self.cache_existed = cache_existed
        self.committer = commit.Committer(cache, raw, storage)
        self.current = current.CurrentState(storage, cache)

    @classmethod
    def open(cls, profile: dict | None = None, *, region: str | None = None) -> "Repository":
        from . import config

        profile = profile or config.load()
        storage_profile = contracts.storage_profile(profile, config.home())
        region = region or (profile.get("regions") or ["us-east-1"])[0]
        storage = iceberg_store.IcebergStore.open(storage_profile, region=region,
                                                  maintenance=(profile.get("storage") or {}).get("maintenance"))
        cache_path = cache_module.default_path()
        existed = cache_path.exists()
        cache = cache_module.Cache(timeout=10)
        configured = str((profile.get("storage") or {}).get("installation_id") or "")
        if configured and cache.installation_id() != configured:
            cache.set_identity(configured, storage_profile.namespace)
        raw = rawstore.from_config(profile, storage_profile, home=config.home())
        repository = cls(cache, raw, storage, profile, storage_profile, cache_existed=existed)
        repository.refuse_legacy_state()
        return repository

    def refuse_legacy_state(self) -> None:
        old = [path for path in (store.latest_path(), store.config.home() / "decisions.json") if path.exists()]
        if not old:
            return
        if self.cache.get_view("latest_scan") or self.cache.watermark():
            return  # a durable install may still have a stray file; never import it
        names = ", ".join(path.name for path in old)
        raise LegacyState(f"Found the v0.4 JSON desk state ({names}). v0.5.0 is a fresh-install release and does not "
                          "import it: move or delete the old desk state folder, then start again. The Hermes home and "
                          "your triage.yaml are kept.")

    # ---------------------------------------------------------------- scan
    def save_scan(self, scan: dict, run: collection.CollectionRun | None = None) -> dict:
        scan = contracts.jsonable(scan)
        observed = scan.get("scanned_at") or contracts.format_time(contracts.utc_now())
        ingested = contracts.format_time(contracts.utc_now())
        scope = contracts.Scope(account="", region="", source="desk")
        scan_payload = {"run_id": f"scan-{event_stamp(observed)}", "started_at": observed, "completed_at": observed,
                        "status": "complete" if not scan.get("partial") else "partial",
                        "accounts": sorted({f.get("account", "") for f in scan.get("findings", []) if f.get("account")}),
                        "regions": sorted({f.get("region", "") for f in scan.get("findings", []) if f.get("region")}),
                        "sources": sorted({f.get("source", "") for f in scan.get("findings", []) if f.get("source")}),
                        "findings_count": len(scan.get("findings", [])),
                        "issues_count": len(scan.get("issues", [])), "truncated": bool(scan.get("stored_overflow"))}
        facts: list[tuple[contracts.Event, dict]] = []
        scan_hash = contracts.payload_hash(scan_payload)
        scan_ref = self._scan_ref(scan_payload, run, observed)
        facts.append((self._event(scan_payload, scope, "scan_run", observed, ingested, scan_hash, scan_ref), scan_payload))
        for entry in scan.get("coverage", []):
            coverage_scope = contracts.Scope(account=str(entry.get("account_id") or entry.get("account") or ""),
                                             region=str(entry.get("region") or ""), source=str(entry.get("source") or ""))
            payload = {"run_id": scan_payload["run_id"], "account_id": coverage_scope.account,
                       "region": coverage_scope.region, "source": coverage_scope.source,
                       "status": entry.get("status", ""), "count": entry.get("count"), "total": entry.get("total"),
                       "truncated": entry.get("truncated"), "completeness": entry.get("completeness"),
                       "note": entry.get("note")}
            digest = contracts.payload_hash(payload)
            facts.append((self._event(payload, coverage_scope, "coverage", observed, ingested, digest, scan_ref),
                          payload))
        for finding in scan.get("findings", []):
            origin = finding.get("collected_from") or [finding.get("source"), finding.get("account"),
                                                       finding.get("region")]
            finding_scope = contracts.Scope(account=str(origin[1] or ""), region=str(origin[2] or ""),
                                            source=str(origin[0] or ""))
            ref = self._raw_for(finding_scope, run, finding)
            digest = contracts.payload_hash(finding)
            facts.append((self._event(finding, finding_scope, "observation", observed, ingested, digest, ref), finding))
        for row in scan.get("evidence", []):
            kind = str(row.get("_kind") or "")
            if kind not in ("flow_log", "trail_event"):
                continue
            payload = {k: v for k, v in row.items() if k != "_kind"}
            source = "flowlogs" if kind == "flow_log" else "trailevents"
            ev_scope = contracts.Scope(account=str(payload.get("account_id") or ""),
                                       region=str(payload.get("region") or ""), source=source)
            ref = run.result_refs.get(f"{ev_scope.account}/{ev_scope.region}/{ev_scope.source}/") if run is not None else None
            digest = contracts.payload_hash(payload)
            facts.append((self._event(payload, ev_scope, kind, observed, ingested, digest, ref), payload))
        # Do not replace the serving view with an uncommitted or partially published scan.
        self.cache.stage_facts(facts)
        result = self.committer.commit_pending(max_batch=max(500, len(facts)))
        mark = self.cache.watermark()
        if result.durable and mark:
            from . import scanview
            try:
                self.current.refresh_from_scan(scan, self.load_decisions(), mark)
                desc = scanview.publish(self, scan, mark.as_dict(),
                    self.storage.snapshot_for_batch("coverage", result.batch_id), scan_payload["run_id"])
                self.current.rebuild_cache(mark)
                self.cache.put_view("latest_scan", scan, watermark=mark.as_dict())
                self.cache.set_meta("view_readiness", json.dumps({"state": "ready", "scan_id": desc["sha256"]}))
            except Exception as exc:
                self.cache.set_meta("view_readiness", json.dumps({"state": "blocked", "reason": str(exc)[:300]}))
                raise RuntimeError("Facts committed but complete scan publication failed; previous generation retained") from exc
        if result.durable and mark:
            from . import exports
            try:
                snapshots = {name: self.storage.snapshot_for_batch(name, result.batch_id) for name in result.tables}
                snapshots["current_scan"] = self.storage.last_snapshot_id("current_scan")
                snapshots["current_findings"] = self.storage.last_snapshot_id("current_findings")
                published = exports.publish(scan, mark.as_dict(), [event.raw_ref for event, _ in facts],
                                            snapshots, self.storage_profile)
            except Exception as exc:
                # Export is a derivative: never roll back or misreport a committed scan.
                published = {'state': 'unavailable', 'scanned_at': scan.get('scanned_at'),
                             'error': type(exc).__name__, 'retry': 'The next successful scan retries publication.'}
            self.cache.set_meta('readable_export', json.dumps(published))
        return result.as_dict()

    def _scan_ref(self, payload: dict, run: collection.CollectionRun | None, observed: str) -> contracts.RawRef | None:
        if run is not None and run.result_refs:
            return next(iter(run.result_refs.values()))
        scope = contracts.Scope(account="", region="", source="desk")
        return self.raw.put_json(payload, scope=scope, operation="ScanRun", observed_at=observed).ref

    def _event(self, payload: dict, scope: contracts.Scope, kind: str, observed: str, ingested: str,
               digest: str, raw_ref: contracts.RawRef | None = None) -> contracts.Event:
        event_id = contracts.observation_event_id(self.cache.installation_id(), scope, observed, digest, kind)
        return contracts.Event(event_id=event_id, kind=kind, installation_id=self.cache.installation_id(),
                               epoch=self.cache.epoch(), sequence=0, scope=scope, observed_at=observed,
                               ingested_at=ingested, payload_hash=digest, raw_ref=raw_ref)

    def _raw_for(self, scope: contracts.Scope, run: collection.CollectionRun | None,
                 finding: dict) -> contracts.RawRef:
        if run is not None:
            key = f"{scope.account}/{scope.region}/{scope.source}/"
            if key in run.result_refs:
                return run.result_refs[key]
        return self.raw.put_json({"finding": finding}, scope=scope, operation="Observation",
                                 observed_at=contracts.format_time(contracts.utc_now())).ref

    # ---------------------------------------------------------------- reads and decisions
    def load_latest(self) -> dict | None:
        view = self.cache.get_view("latest_scan")
        if view:
            return view["payload"]
        return None  # Missing recovery is never a fabricated empty-coverage scan.

    def write_latest(self, scan: dict) -> None:
        mark = self.cache.watermark()
        self.cache.put_view("latest_scan", scan, watermark=mark.as_dict() if mark else None)

    def load_decisions(self) -> dict:
        view = self.cache.get_view("current_decisions")
        rows = view["payload"] if view else self.storage.scan_rows("current_decisions")
        return {str(row.get("finding_key")): {"status": row.get("status"), "reason": row.get("reason"),
                                              "by": row.get("by"), "at": row.get("at")}
                for row in rows if row.get("finding_key")}

    def decide(self, key: str, status: str, reason: str, by: str = "operator", fix: dict | None = None) -> dict:
        if status not in store.DECISION_STATUSES:
            raise ValueError(f"status must be one of {', '.join(store.DECISION_STATUSES)}")
        payload = {"finding_key": key, "status": status, "reason": reason, "by": by,
                   "decided_at": contracts.format_time(contracts.utc_now()), "fix": fix}
        event = contracts.Event(event_id=contracts.operation_event_id(), kind="decision",
                                installation_id=self.cache.installation_id(), epoch=self.cache.epoch(), sequence=0,
                                scope=contracts.Scope(account="", region="", source="desk"),
                                observed_at=payload["decided_at"], ingested_at=payload["decided_at"],
                                payload_hash=contracts.payload_hash(payload))
        result = self.committer.commit_decision(event, payload)
        scan = self.load_latest()
        if scan is not None:
            decision = {"status": status, "reason": reason, "by": by, "at": payload["decided_at"]}
            if fix:
                decision["fix"] = fix
            for finding in scan.get("findings", []):
                if finding.get("key") == key:
                    finding["decision"] = decision
            for issue in scan.get("issues", []):
                if issue.get("top_key") == key or key in (issue.get("finding_keys") or []):
                    issue["decision"] = decision
            self.write_latest(scan)
        mark = self.cache.watermark()
        if mark:
            decisions = self.load_decisions()
            decisions[key] = {"status": status, "reason": reason, "by": by, "at": payload["decided_at"], "fix": fix}
            if scan is not None:
                self.current.refresh_from_scan(scan, decisions, mark)
            self.persist_decisions(decisions, mark)
        if not result.durable:
            raise RuntimeError(f"saved locally, not yet durable: {result.error or result.status}")
        return {"status": status, "reason": reason, "by": by, "at": payload["decided_at"], "fix": fix}

    def persist_decisions(self, decisions: dict, mark: contracts.Watermark | None = None) -> None:
        """Keep the current-decision view aligned with the decision facts already committed."""
        mark = mark or self.cache.watermark()
        rows = [{"finding_key": key, "status": value.get("status"), "reason": value.get("reason"),
                 "by": value.get("by"), "at": value.get("at")} for key, value in decisions.items()]
        from .current import _plain

        self.cache.put_view("current_decisions", _plain(rows), watermark=mark.as_dict() if mark else None)

    def load_onboarding(self) -> dict | None:
        view = self.cache.get_view("onboarding")
        return view["payload"] if view else None

    def save_onboarding(self, report: dict, profile: dict) -> None:
        readable = {a["account_id"]: a["name"] for a in profile["accounts"] if a.get("discovered")}
        self.cache.put_view("onboarding", {**report, "readable": readable})

    # ---------------------------------------------------------------- recovery and health
    def recover(self, *, empty_disk: bool | None = None, installation_id: str | None = None) -> recovery.RecoveryReport:
        if empty_disk is None:
            empty_disk = not self.cache_existed
        configured = installation_id or str((self.profile.get("storage") or {}).get("installation_id") or "")
        report = recovery.Recovery(self.cache, self.storage, self.current, self.committer, self.raw).recover(
            empty_disk=empty_disk, installation_id=configured or None,
            namespace=self.storage_profile.namespace)
        if report.state == "blocked":
            self.cache.set_meta("view_readiness", json.dumps({"state": "blocked", "reason": report.reason}))
            return report
        from . import scanview
        try:
            scan, desc = scanview.restore(self)
            if scan is not None:
                self.cache.put_view("latest_scan", scan, watermark=desc["watermark"])
                self.cache.set_meta("view_readiness", json.dumps({"state": "ready", "scan_id": desc["sha256"]}))
                report.rebuilt["complete_scan"] = desc["counts"]
                report.needs_scan = False
                report.state = "degraded" if report.outbox_events or report.unresolved_operations else "healthy"
                report.reason = "complete committed scan restored; freshness is reported separately"
                latest = self.storage.scan_rows("scan_runs")
                if any(row["installation_id"] == self.cache.installation_id()
                       and row["started_at"] > contracts.parse_time(scan["scanned_at"]) for row in latest):
                    report.state = "degraded"
                    report.reason = "serving previous complete generation; newer scan facts lack a complete view"
                    self.cache.set_meta("view_readiness", json.dumps({"state": "previous_generation",
                        "scan_id": desc["sha256"], "reason": report.reason}))
            else:
                self.cache.set_meta("view_readiness", json.dumps({"state": "empty", "reason": "no committed scan"}))
        except Exception as exc:
            report.state, report.reason = "blocked", f"complete scan recovery failed: {type(exc).__name__}: {exc}"[:500]
            self.cache.set_meta("view_readiness", json.dumps({"state": "blocked", "reason": report.reason}))
        return report

    def health(self) -> dict:
        from . import health

        return health.snapshot(self)

    def close(self) -> None:
        self.cache.close()


def event_stamp(value: str) -> str:
    try:
        return contracts.parse_time(value).strftime("%Y%m%dT%H%M%SZ")
    except contracts.ContractError:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
