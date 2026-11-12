"""The write-ahead hash-chained execution receipt log (roadmap CE-29)."""
from rgtriage import runlog


class Result:
    def __init__(self, durable):
        self.durable = durable

    def as_dict(self):
        return {"status": "committed" if self.durable else "not-durable", "durable": self.durable}


class FakeCache:
    def __init__(self):
        self.meta, self.staged = {}, []

    def get_meta(self, key, default=None):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value

    def installation_id(self):
        return "inst-1"

    def epoch(self):
        return "epoch-1"

    def stage_event(self, event, payload):
        self.staged.append((event, payload))
        return "new"


def _log(durable=True):
    cache = FakeCache()
    return cache, runlog.RunLog(cache, "run-1", commit=lambda event, payload: Result(durable))


def test_records_chain_and_verify():
    cache, log = _log()
    first = log.record("plan_received", plan_sha256="a" * 64)
    second = log.record("intended_call", target="sg-1", op="authorize", cidr="10.20.0.0/16")
    third = log.record("api_call", target="sg-1", op="authorize")
    records = [r["record"] for r in (first, second, third)]
    assert [r["seq"] for r in records] == [1, 2, 3]
    assert records[1]["prev_sha256"] == records[0]["sha256"]
    assert records[0]["prev_sha256"] == runlog.GENESIS
    ok, problem = runlog.verify_chain(records)
    assert ok and problem == ""
    assert [event.kind for event, _ in cache.staged] == ["execution_receipt"] * 3


def test_an_edited_receipt_breaks_the_chain():
    _, log = _log()
    records = [log.record("intended_call", target="sg-1", op="authorize")["record"],
               log.record("api_call", target="sg-1", op="authorize")["record"]]
    records[0]["op"] = "revoke"  # someone rewrote history
    ok, problem = runlog.verify_chain(records)
    assert ok is False and "edited" in problem


def test_a_dropped_receipt_breaks_the_chain():
    _, log = _log()
    records = [log.record("a")["record"], log.record("b")["record"], log.record("c")["record"]]
    ok, problem = runlog.verify_chain([records[0], records[2]])
    assert ok is False and "predecessor" in problem


def test_a_receipt_that_is_not_durable_does_not_advance_the_chain():
    cache = FakeCache()
    log = runlog.RunLog(cache, "run-1", commit=lambda event, payload: Result(False))
    failed = log.record("intended_call", target="sg-1")
    assert failed["durable"] is False and log.records == []
    ok = runlog.RunLog(cache, "run-1", commit=lambda event, payload: Result(True))
    again = ok.record("intended_call", target="sg-1")
    assert again["record"]["seq"] == 1, "the interrupted intent keeps its place in the chain"
    assert cache.get_meta("runlog:run-1").startswith(again["record"]["sha256"])


def test_change_pack_summarises_a_run_and_its_stops():
    _, log = _log()
    log.record("plan_received", plan_sha256="b" * 64)
    log.record("intended_call", target="sg-1")
    log.record("rollback", target="sg-1", restored_exactly=True)
    pack = runlog.change_pack(log.records, plan={"digest": "b" * 64}, approval={"by": "owner"})
    assert pack["records"] == 3 and pack["kinds"]["rollback"] == 1
    assert len(pack["stopped"]) == 1 and pack["chain_ok"] is True
    assert pack["plan_digest"] == "b" * 64
