"""The write-ahead, hash-chained execution receipt log (roadmap CE-29).

Every intended API call is recorded here *before* it is made, with the target's pre-state, so a Spot interruption
mid-wave leaves a chain that a restarted executor can reconcile against live state: finish what is recorded as
intended-but-absent, or roll back what is present-but-unverified. Each record carries the previous record's hash;
an edited or dropped receipt breaks the chain and the run stops being quotable.

The chain head lives in cache meta so appending is O(1); durability comes from committing the record through the
normal outbox to the `execution_receipts` table. Callers must treat a non-durable record as "not yet written":
the executor may not make the call until the receipt is durable.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from . import contracts

GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(body: dict) -> str:
    return hashlib.sha256(contracts.canonical_json(body).encode()).hexdigest()


class RunLog:
    """Append-only chain for one run. `cache` supplies the head; `commit` makes a record durable."""

    def __init__(self, cache, run_id: str, commit=None):
        self.cache = cache
        self.run_id = run_id
        self.commit = commit
        self.records: list[dict] = []

    def _head(self) -> tuple[str, int]:
        raw = self.cache.get_meta(f"runlog:{self.run_id}")
        if not raw:
            return GENESIS, 0
        sha, seq = raw.rsplit(":", 1)
        return sha, int(seq)

    def record(self, kind: str, *, target: str = "", durable: bool = True, **data) -> dict:
        """Write-ahead: build and stage the receipt first; the caller makes the call only when durable."""
        sha, seq = self._head()
        body = {"run_id": self.run_id, "seq": seq + 1, "kind": kind, "target": target,
                "recorded_at": data.pop("recorded_at", None) or _now(), **data}
        record = {**body, "prev_sha256": sha}
        record["sha256"] = digest(record)
        payload = {"run_id": self.run_id, "seq": record["seq"], "kind": kind, "target": target,
                   "prev_sha256": sha, "sha256": record["sha256"], "body": body,
                   "recorded_at": body["recorded_at"]}
        scope = contracts.Scope(account="", region="", source="executor")
        event = contracts.Event(event_id=contracts.observation_event_id(
            self.cache.installation_id(), scope, body["recorded_at"], record["sha256"], "execution_receipt"),
            kind="execution_receipt", installation_id=self.cache.installation_id(), epoch=self.cache.epoch(),
            sequence=0, scope=scope, observed_at=body["recorded_at"], ingested_at=_now(),
            payload_hash=contracts.payload_hash(payload))
        self.cache.stage_event(event, payload)
        result = None
        if durable and self.commit is not None:
            result = self.commit(event, payload)
            if not result.durable:
                return {"record": record, "durable": False, "commit": result.as_dict()}
        self.cache.set_meta(f"runlog:{self.run_id}", f"{record['sha256']}:{record['seq']}")
        self.records.append(record)
        return {"record": record, "durable": True, "commit": result.as_dict() if result else None}

    def verify(self, records: list[dict]) -> tuple[bool, str]:
        return verify_chain(records)


def verify_chain(records: list[dict]) -> tuple[bool, str]:
    """Re-check a chain as read back from storage: order, previous hash and body hash."""
    previous = GENESIS
    for record in records:
        body = {k: v for k, v in record.items() if k not in ("sha256", "prev_sha256")}
        if record.get("prev_sha256") != previous:
            return False, f"record {record.get('seq')} does not follow its predecessor"
        if digest({**body, "prev_sha256": previous}) != record.get("sha256"):
            return False, f"record {record.get('seq')} was edited after it was written"
        previous = record["sha256"]
    return True, ""


def change_pack(records: list[dict], *, plan: dict | None = None, approval: dict | None = None) -> dict:
    """One page per run: what was approved, what ran, what was verified, what was rolled back."""
    kinds = {}
    for record in records:
        kinds.setdefault(record.get("kind", ""), 0)
        kinds[record.get("kind", "")] += 1
    ok, problem = verify_chain(records) if records else (True, "")
    return {"run_id": records[0]["run_id"] if records else "",
            "plan_digest": (plan or {}).get("digest", ""), "approval": approval or {},
            "records": len(records), "kinds": kinds,
            "stopped": [r for r in records if r.get("kind") in ("stopped", "rollback", "halted")],
            "verified": [r for r in records if r.get("kind") == "verify"],
            "chain_ok": ok, "chain_problem": problem}
