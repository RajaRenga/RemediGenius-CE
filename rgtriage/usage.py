"""Usage evidence: VPC flow logs and CloudTrail events as durable, bounded facts (roadmap CE-25).

These are not findings. They answer "who actually uses this rule" and "who created or changed it", which is what
turns a model's guess about blast radius into a list of named sources. Both sources are opt-in in the profile
(`sources: [..., flowlogs, trailevents]`) because they cost money and, in multi-account estates, usually live in a
central log-archive account.

Flow logs are aggregated at collect time: one row per (day, interface, source, destination port, protocol, action)
with a flow count. The impact gate needs per-source usage, and per-flow rows would grow with traffic instead of
with scope. S3-delivered flow logs and CloudTrail data events are read through Athena when `evidence.athena` is
configured, with a bytes-scanned cap per query; without it the coverage record names them as not read, never as
clean.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from botocore.exceptions import BotoCoreError, ClientError

from . import aws
from .collection import CollectionPaused

FLOW_FIELDS_V2 = ("version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
                  "packets", "bytes", "start", "end", "action", "log-status")
LOOKUP_PAGE = 50
ATHENA_POLL_SECONDS = 1.0
ATHENA_POLLS = 60


class _Disabled(Exception):
    pass


class _Budget(Exception):
    """An Athena query would scan more than the configured byte cap."""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- flow logs

def flow_field_order(log_format: str | None) -> list[str]:
    """The flow log's own field order; a custom format is honoured, an absent one falls back to version 2."""
    fields = (log_format or "").split()
    return fields or list(FLOW_FIELDS_V2)


def parse_flow_message(message: str, fields: list[str]) -> dict:
    parts = message.split()
    if len(parts) != len(fields):
        return {}
    return dict(zip(fields, parts))


def normalise_flow(record: dict, account_id: str, region: str, log_format: str, route: str) -> dict | None:
    """One flow record to the aggregated-row shape; None when the record carries no usable endpoints."""
    try:
        srcaddr, dstaddr = record.get("srcaddr") or "", record.get("dstaddr") or ""
        dstport = int(record.get("dstport") or -1)
        protocol = int(record.get("protocol") or -1)
        start, end = int(record.get("start") or 0), int(record.get("end") or 0)
    except (TypeError, ValueError):
        return None
    if not record.get("interface-id") or not srcaddr or dstport < 0 or start <= 0:
        return None
    return {"_kind": "flow_log", "account_id": account_id, "region": region,
            "day": datetime.fromtimestamp(start, timezone.utc).date().isoformat(),
            "interface_id": record["interface-id"], "srcaddr": srcaddr, "dstaddr": dstaddr or None,
            "srcport": _int_or_none(record.get("srcport")), "dstport": dstport, "protocol": protocol,
            "action": record.get("action") or "UNKNOWN", "flows": 1,
            "first_seen": datetime.fromtimestamp(start, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_seen": datetime.fromtimestamp(max(end, start), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "log_format": log_format or " ".join(FLOW_FIELDS_V2), "route": route}


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def aggregate_flows(rows: list[dict]) -> list[dict]:
    """Collapse per-flow rows into per-(day, interface, source, port, protocol, action) counts."""
    out: dict[tuple, dict] = {}
    for row in rows:
        key = (row["day"], row["interface_id"], row["srcaddr"], row["dstport"], row["protocol"], row["action"])
        seen = out.get(key)
        if seen is None:
            out[key] = {**row, "flows": 1}
            continue
        seen["flows"] += row.get("flows", 1)
        seen["first_seen"] = min(seen["first_seen"], row["first_seen"])
        seen["last_seen"] = max(seen["last_seen"], row["last_seen"])
    return sorted(out.values(), key=lambda r: (r["day"], r["interface_id"], r["srcaddr"], r["dstport"]))


def athena_rows(session, region: str, sql: str, database: str, workgroup: str, max_bytes: int,
                poll: float = ATHENA_POLL_SECONDS) -> list[dict]:
    """Run one bounded Athena query and return its rows as plain dicts; refuse to pay for an oversized scan."""
    client = aws.client(session, "athena", region)
    args = {"QueryString": sql, "QueryExecutionContext": {"Database": database}}
    if workgroup:
        args["WorkGroup"] = workgroup
    query_id = client.start_query_execution(**args)["QueryExecutionId"]
    for _ in range(ATHENA_POLLS):
        state = client.get_query_execution(QueryExecutionId=query_id)["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(poll)
    else:
        raise _Disabled("the Athena query did not finish in time; the source is reported as not read")
    execution = client.get_query_execution(QueryExecutionId=query_id)["QueryExecution"]
    if execution["Status"]["State"] != "SUCCEEDED":
        raise _Disabled(f"Athena query {execution['Status']['State']}: "
                        f"{execution['Status'].get('StateChangeReason', '')}"[:200])
    scanned = int(execution.get("Statistics", {}).get("DataScannedInBytes") or 0)
    if scanned > max_bytes:
        raise _Budget(f"the query scanned {scanned} bytes, over the {max_bytes} byte cap")
    rows, token = [], None
    while True:
        page = client.get_query_results(QueryExecutionId=query_id, MaxResults=1000, **({"NextToken": token} if token else {}))
        header = [c.get("Name") or "" for c in page["ResultSet"]["Rows"][0]["Data"]]
        for line in page["ResultSet"]["Rows"][1:]:
            rows.append({name: (cell.get("VarCharValue") or "") for name, cell in zip(header, line["Data"])})
        token = page.get("NextToken")
        if not token:
            return rows


def read_flow_logs(session, account, region, opts) -> tuple[list[dict], dict]:
    ec2 = aws.client(session, "ec2", region)
    logs = [f for f in ec2.describe_flow_logs().get("FlowLogs", []) if f.get("TrafficType") in ("ACCEPT", "ALL", None)]
    if not logs:
        raise _Disabled("no VPC flow logs are turned on in this region; usage of a rule here is unknown, not unused")
    athena = opts.get("athena") or {}
    rows: list[dict] = []
    routes: set[str] = set()
    for flow in logs[: int(opts.get("max_flow_logs", 25))]:
        fmt = flow_field_order(flow.get("LogFormat"))
        destination = flow.get("LogDestinationType") or "cloud-watch-logs"
        if destination == "s3":
            if not athena.get("database"):
                raise _Disabled("S3-delivered flow logs need evidence.athena.database in the profile; not read")
            table = athena.get("flow_log_table") or "vpc_flow_logs"
            sql = (f"SELECT * FROM {table} WHERE account_id = '{account.get('account_id', '')}' "
                   f"AND region = '{region}' LIMIT {int(opts['max_rows'])}")
            for item in athena_rows(session, region, sql, athena["database"], athena.get("workgroup", ""),
                                    opts["max_bytes"]):
                row = normalise_flow(item, account.get("account_id", ""), region,
                                     flow.get("LogFormat") or "", "s3_athena")
                if row:
                    rows.append(row)
            routes.add("s3_athena")
            continue
        client = aws.client(session, "logs", region)
        start_ms = int((datetime.now(timezone.utc) - timedelta(days=int(opts["days"]))).timestamp() * 1000)
        token, seen = None, 0
        while seen < int(opts["max_rows"]):
            page = client.get_log_events(logGroupName=flow.get("LogGroupName", ""), startTime=start_ms,
                                         startFromHead=True, limit=min(1000, int(opts["max_rows"]) - seen),
                                         **({"nextToken": token} if token else {}))
            events = page.get("events", [])
            for event in events:
                row = normalise_flow(parse_flow_message(event.get("message", ""), fmt),
                                     account.get("account_id", ""), region, flow.get("LogFormat") or "",
                                     "cloudwatch_logs")
                if row:
                    rows.append(row)
            seen += len(events)
            nxt = page.get("nextForwardToken")
            if not nxt or nxt == token or not events:
                break
            token = nxt
        routes.add("cloudwatch_logs")
    return aggregate_flows(rows), {"truncated": len(rows) >= int(opts["max_rows"]),
                                   "note": "routes: " + ", ".join(sorted(routes))}


# --------------------------------------------------------------------------- cloudtrail

def read_trail_events(session, account, region, opts) -> tuple[list[dict], dict]:
    client = aws.client(session, "cloudtrail", region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=int(opts["days"]))
    rows, token, note = [], None, ""
    while len(rows) < int(opts["max_rows"]):
        page = client.lookup_events(StartTime=start, EndTime=end, MaxResults=LOOKUP_PAGE,
                                    **({"NextToken": token} if token else {}))
        for event in page.get("Events", []):
            detail = {}
            try:
                detail = json.loads(event.get("CloudTrailEvent") or "{}")
            except ValueError:
                detail = {}
            identity = detail.get("userIdentity") or {}
            rows.append({"_kind": "trail_event", "account_id": account.get("account_id", ""), "region": region,
                         "event_time": event.get("EventTime") or now_iso(),
                         "event_name": event.get("EventName") or "", "event_source": event.get("EventSource"),
                         "actor_arn": identity.get("arn"), "user_name": event.get("Username"),
                         "source_ip": detail.get("sourceIPAddress"),
                         "user_agent": detail.get("userAgent"),
                         "mfa_authenticated": bool((identity.get("sessionContext") or {}).get("attributes", {}).get("mfaAuthenticated")) or None,
                         "event_kind": "management",
                         "resource_ids": [r.get("ResourceName") for r in event.get("Resources", []) if r.get("ResourceName")],
                         "request_params": detail.get("requestParameters"), "error_code": event.get("ErrorCode"),
                         "route": "lookup_events"})
        token = page.get("NextToken")
        if not token:
            break
    athena = opts.get("athena") or {}
    if athena.get("database") and athena.get("trail_table"):
        sql = (f"SELECT * FROM {athena['trail_table']} WHERE eventtype = 'AwsApiCall' "
               f"AND account = '{account.get('account_id', '')}' LIMIT {int(opts['max_rows'])}")
        for item in athena_rows(session, region, sql, athena["database"], athena.get("workgroup", ""),
                                opts["max_bytes"]):
            rows.append({"_kind": "trail_event", "account_id": account.get("account_id", ""), "region": region,
                         "event_time": item.get("eventtime") or now_iso(), "event_name": item.get("eventname", ""),
                         "event_source": item.get("eventsource"), "actor_arn": item.get("useridentity.arn"),
                         "user_name": item.get("useridentity.username"), "source_ip": item.get("sourceipaddress"),
                         "user_agent": item.get("useragent"), "mfa_authenticated": None, "event_kind": "data",
                         "resource_ids": [item["resources.name"]] if item.get("resources.name") else [],
                         "request_params": item.get("requestparameters"), "error_code": item.get("errorcode"),
                         "route": "s3_athena"})
    else:
        note = "CloudTrail data events (bucket and object reads) are not in lookup_events; configure evidence.athena.trail_table to read them"
    return rows, {"truncated": len(rows) >= int(opts["max_rows"]), "note": note}


EVIDENCE_COLLECTORS = {"flowlogs": read_flow_logs, "trailevents": read_trail_events}


# --------------------------------------------------------------------------- driver

def run_evidence(source, session, account, region, opts, run=None):
    entry = {"source": source, "account": account["name"], "account_id": account.get("account_id", ""),
             "region": region}
    scope = run.scope(account, region, source) if run is not None else None
    try:
        if run is not None:
            run.begin_scope(scope)
        rows, meta = EVIDENCE_COLLECTORS[source](session, account, region, opts)
        entry.update(status="ok", count=len(rows), **meta)
        if run is not None:
            run.record_result(scope, rows, meta)
            run.complete_scope(scope, count=len(rows), truncated=bool(entry.get("truncated")),
                               note=entry.get("note", ""))
        return rows, entry
    except CollectionPaused as exc:
        entry.update(status="paused", count=0, note=str(exc)[:240])
        if run is not None:
            run.fail_scope(scope, "error", str(exc))
    except _Disabled as exc:
        entry.update(status="not_enabled", count=0, note=str(exc))
        if run is not None:
            run.fail_scope(scope, "not_enabled", str(exc))
    except _Budget as exc:
        entry.update(status="over_budget", count=0, note=str(exc))
        if run is not None:
            run.fail_scope(scope, "error", str(exc))
    except aws.WriteBlocked as exc:
        entry.update(status="error", count=0, note=str(exc))
        if run is not None:
            run.fail_scope(scope, "error", str(exc))
    except ClientError as exc:
        code = aws.error_code(exc)
        status = "denied" if "AccessDenied" in code or code in ("UnauthorizedOperation", "AuthorizationError") else (
            "not_enabled" if code in ("InvalidAccessException", "SubscriptionRequiredException",
                                      "ResourceNotFoundException", "NoSuchConfigurationRecorderException") else "error")
        entry.update(status=status, count=0, note=f"{code}: {str(exc)[:240]}")
        if run is not None:
            run.fail_scope(scope, status, f"{code}: {str(exc)[:240]}")
    except BotoCoreError as exc:
        entry.update(status="error", count=0, note=str(exc)[:240])
        if run is not None:
            run.fail_scope(scope, "error", str(exc))
    return [], entry


def collect_evidence(profile: dict, sources: list[str] | None = None, progress=None, run=None):
    """Read the configured evidence sources for every account and region; never blocks a scan."""
    wanted = [s for s in (sources if sources is not None else profile.get("sources") or []) if s in EVIDENCE_COLLECTORS]
    if not wanted:
        return [], []
    ev = profile.get("evidence") or {}
    opts = {"days": int(ev.get("days", 90)), "max_rows": int(ev.get("max_rows_per_scope", 20000)),
            "max_bytes": int(ev.get("flow_log_max_bytes", 10_000_000_000)),
            "max_flow_logs": int(ev.get("max_flow_logs_per_region", 25)), "athena": ev.get("athena") or {}}
    rows: list[dict] = []
    coverage: list[dict] = []
    jobs = []
    for account in profile["accounts"]:
        session = account.get("_session") or aws.session_for(account)
        for source in wanted:
            for region in account["regions"]:
                jobs.append((source, session, account, region))
    with ThreadPoolExecutor(max_workers=4) as pool:
        for found, entry in pool.map(lambda job: run_evidence(*job, opts, run), jobs):
            if progress:
                progress(entry)
            rows.extend(found)
            coverage.append(entry)
    return rows, coverage
