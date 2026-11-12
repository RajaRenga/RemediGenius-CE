"""Usage evidence collectors: parsing, aggregation, caps and coverage statuses (roadmap CE-25)."""
import json

import pytest
from botocore.exceptions import ClientError

from rgtriage import usage

FLOW_V2 = " ".join(usage.FLOW_FIELDS_V2)


def _message(src, dst, sport, dport, start, action="ACCEPT", iface="eni-1"):
    return f"2 111122223333 {iface} {src} {dst} {sport} {dport} 6 10 1000 {start} {start + 30} {action} OK"


class FakeEC2:
    def __init__(self, flows):
        self.flows = flows

    def describe_flow_logs(self, **_):
        return {"FlowLogs": self.flows}


class FakeLogs:
    def __init__(self, pages):
        self.pages, self.i = pages, 0

    def get_log_events(self, **kwargs):
        if self.i >= len(self.pages):
            return {"events": [], "nextForwardToken": kwargs.get("nextToken", "end")}
        events, token = self.pages[self.i]
        self.i += 1
        return {"events": [{"message": m} for m in events], "nextForwardToken": token}


class FakeSession:
    def __init__(self, clients):
        self.clients = clients

    def client(self, service, region_name=None, **_):
        return self.clients[service]


def _session(ec2, logs=None, cloudtrail=None, athena=None):
    clients = {"ec2": ec2}
    if logs:
        clients["logs"] = logs
    if cloudtrail:
        clients["cloudtrail"] = cloudtrail
    if athena:
        clients["athena"] = athena
    return FakeSession(clients)


def test_flow_messages_parse_and_aggregate_per_source_port_and_day():
    ec2 = FakeEC2([{"LogGroupName": "/vpc/flow", "LogDestinationType": "cloud-watch-logs", "LogFormat": FLOW_V2,
                    "TrafficType": "ALL"}])
    logs = FakeLogs([([_message("10.20.4.17", "10.0.1.9", 51000, 22, 1_700_000_000),
                       _message("10.20.4.17", "10.0.1.9", 51001, 22, 1_700_000_900),
                       _message("198.51.100.7", "10.0.1.9", 40000, 22, 1_700_001_000)], "t2"),
                     ([_message("198.51.100.7", "10.0.1.9", 40001, 22, 1_700_001_100)], "t2")])
    rows, meta = usage.read_flow_logs(_session(ec2, logs=logs), {"account_id": "111122223333"}, "us-east-1",
                                      {"days": 30, "max_rows": 100, "max_bytes": 10**9, "athena": {}})
    by_source = {(r["srcaddr"], r["dstport"]): r for r in rows}
    assert by_source[("10.20.4.17", 22)]["flows"] == 2, "same source and port collapse into one counted row"
    assert by_source[("198.51.100.7", 22)]["flows"] == 2
    assert all(r["route"] == "cloudwatch_logs" and r["_kind"] == "flow_log" for r in rows)
    assert all(r["action"] == "ACCEPT" for r in rows)
    assert meta["truncated"] is False


def test_custom_log_format_is_honoured_not_assumed():
    fmt = "version interface-id srcaddr dstaddr dstport action start end"
    ec2 = FakeEC2([{"LogGroupName": "/vpc/custom", "LogDestinationType": "cloud-watch-logs", "LogFormat": fmt,
                    "TrafficType": "ACCEPT"}])
    logs = FakeLogs([(["2 eni-9 10.30.1.5 10.0.2.2 22 ACCEPT 1700000000 1700000030"], "same")])
    rows, _ = usage.read_flow_logs(_session(ec2, logs=logs), {"account_id": "1"}, "eu-west-1",
                                   {"days": 30, "max_rows": 10, "max_bytes": 10**9, "athena": {}})
    assert rows[0]["interface_id"] == "eni-9" and rows[0]["srcaddr"] == "10.30.1.5" and rows[0]["dstport"] == 22
    assert rows[0]["srcport"] is None, "a format without srcport yields null, not a guessed value"


def test_s3_flow_logs_without_an_athena_route_are_a_named_blind_spot():
    ec2 = FakeEC2([{"LogGroupName": "", "LogDestinationType": "s3", "LogDestination": "s3://archive/vpc",
                    "LogFormat": FLOW_V2, "TrafficType": "ALL"}])
    rows, entry = usage.run_evidence("flowlogs", _session(ec2), {"name": "a", "account_id": "1"}, "us-east-1",
                                     {"days": 30, "max_rows": 10, "max_bytes": 10**9, "athena": {}})
    assert rows == []
    assert entry["status"] == "not_enabled" and "evidence.athena" in entry["note"]


def test_athena_route_refuses_a_scan_over_the_byte_cap():
    class FakeAthena:
        def start_query_execution(self, **_):
            return {"QueryExecutionId": "q1"}

        def get_query_execution(self, **_):
            return {"QueryExecution": {"Status": {"State": "SUCCEEDED"},
                                       "Statistics": {"DataScannedInBytes": 5 * 10**10}}}

    ec2 = FakeEC2([{"LogGroupName": "", "LogDestinationType": "s3", "LogFormat": FLOW_V2, "TrafficType": "ALL"}])
    rows, entry = usage.run_evidence("flowlogs", _session(ec2, athena=FakeAthena()),
                                     {"name": "a", "account_id": "1"}, "us-east-1",
                                     {"days": 30, "max_rows": 10, "max_bytes": 10**9,
                                      "athena": {"database": "logs", "flow_log_table": "vpc_flow_logs"}})
    assert rows == [] and entry["status"] == "over_budget" and "byte cap" in entry["note"]


class FakeTrail:
    def __init__(self, events):
        self.events = events

    def lookup_events(self, **_):
        return {"Events": self.events}


def test_trail_events_keep_actor_agent_and_resources_and_name_the_data_event_gap():
    detail = {"userIdentity": {"arn": "arn:aws:sts::1:assumed-role/Admin/alice"}, "userAgent": "aws-cli/2.38.4",
              "sourceIPAddress": "203.0.113.9", "requestParameters": {"groupId": "sg-1"}}
    trail = FakeTrail([{"EventTime": "2026-05-02T22:41:00Z", "EventName": "AuthorizeSecurityGroupIngress",
                        "EventSource": "ec2.amazonaws.com", "Username": "alice",
                        "Resources": [{"ResourceName": "sg-1"}], "CloudTrailEvent": json.dumps(detail)}])
    rows, meta = usage.read_trail_events(_session(FakeEC2([]), cloudtrail=trail), {"account_id": "1"}, "us-east-1",
                                         {"days": 90, "max_rows": 50, "max_bytes": 10**9, "athena": {}})
    assert rows[0]["event_name"] == "AuthorizeSecurityGroupIngress"
    assert rows[0]["actor_arn"].endswith("Admin/alice") and rows[0]["user_agent"].startswith("aws-cli")
    assert rows[0]["resource_ids"] == ["sg-1"] and rows[0]["event_kind"] == "management"
    assert "data events" in meta["note"], "the gap is named, never presented as complete"


def test_denied_reads_are_coverage_not_silence():
    class DeniedEC2(FakeEC2):
        def describe_flow_logs(self, **_):
            raise ClientError({"Error": {"Code": "AccessDeniedException"}}, "DescribeFlowLogs")

    rows, entry = usage.run_evidence("flowlogs", _session(DeniedEC2([])), {"name": "a", "account_id": "1"},
                                     "us-east-1", {"days": 30, "max_rows": 10, "max_bytes": 10**9, "athena": {}})
    assert rows == [] and entry["status"] == "denied"


def test_evidence_sources_stay_opt_in():
    rows, coverage = usage.collect_evidence({"accounts": [{"name": "a", "account_id": "1", "regions": ["us-east-1"]}],
                                             "sources": ["securityhub"], "evidence": {}}, None)
    assert rows == [] and coverage == [], "nothing is read unless the profile asks for it"


def test_no_flow_logs_is_unknown_not_unused():
    rows, entry = usage.run_evidence("flowlogs", _session(FakeEC2([])), {"name": "a", "account_id": "1"},
                                     "us-east-1", {"days": 30, "max_rows": 10, "max_bytes": 10**9, "athena": {}})
    assert rows == [] and entry["status"] == "not_enabled" and "unknown, not unused" in entry["note"]


@pytest.mark.parametrize("line,fields,ok", [
    (_message("10.0.0.1", "10.0.0.2", 1, 22, 100), usage.FLOW_FIELDS_V2, True),
    ("short line", usage.FLOW_FIELDS_V2, False),
])
def test_parse_flow_message_rejects_ragged_lines(line, fields, ok):
    assert bool(usage.parse_flow_message(line, list(fields))) is ok
