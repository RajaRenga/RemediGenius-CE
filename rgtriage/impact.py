"""Downstream impact: replay observed traffic against a proposed rule set (roadmap CE-26).

The blast radius of a fix is computed, not written by the model. Every observed accepted flow is replayed against
the simulated post-change rules; whatever loses connectivity is named by source and port, and internal sources are
separated from external scanners. A gap in coverage yields "unknown", never "safe".

Rules are plain tuples (protocol, from_port, to_port, cidr) as read from the live resource; the caller owns the
live read and the flow-row filtering (interface to group), this module only judges.
"""
from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone

from . import aws

WORLD = {"0.0.0.0/0", "::/0"}
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def canonical(obj) -> str:
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def state_digest(rules) -> str:
    return hashlib.sha256(canonical(sorted(tuple(r) for r in rules)).encode()).hexdigest()


def is_rfc1918(value: str) -> bool:
    """Explicit RFC 1918 test: Python's is_private also counts documentation ranges, which are not internal."""
    try:
        net = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(net.version == r.version and net in r for r in RFC1918)


def is_private_network(value: str) -> bool:
    """The same test for a CIDR: a range is private when its whole space sits inside RFC 1918."""
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return any(net.version == r.version and net.subnet_of(r) for r in RFC1918)


def classify(source: str, ranges: list[dict]) -> str:
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return "external"
    for item in ranges:
        try:
            if address in ipaddress.ip_network(item["cidr"], strict=False):
                return "internal_known"
        except (ValueError, KeyError):
            continue
    return "internal_unknown" if is_rfc1918(source) else "external"


def allowed(rules, source: str, port: int) -> bool:
    try:
        address = ipaddress.ip_address(source)
    except ValueError:
        return False
    for proto, low, high, cidr in rules:
        if proto not in ("tcp", "-1") or low is None or not (low <= port <= (high or low)):
            continue
        try:
            if address in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def simulate(rules, calls: list[dict]) -> list[tuple]:
    """Apply add/remove calls to a rule set; adds are expected before removes so there is no lock-out window."""
    after = {tuple(r) for r in rules}
    for call in calls:
        rule = (call["proto"], call["port"], call["port"], call["cidr"])
        (after.add if call["op"] == "authorize" else after.discard)(rule)
    return sorted(after)


def summarise(flows: list[dict]) -> dict:
    out: dict[str, dict] = {}
    for flow in flows:
        bucket = out.setdefault(str(flow["port"]), {"internal_known": [], "internal_unknown": [],
                                                    "external_count": 0, "external_flows": 0})
        if flow["class"] == "external":
            bucket["external_count"] += 1
            bucket["external_flows"] += flow["flows"]
        else:
            bucket[flow["class"]].append({"source": flow["source"], "flows": flow["flows"],
                                          "last_seen": flow.get("last_seen", "")})
    return out


def build_packet(finding: dict, flow_rows: list[dict], trail_rows: list[dict], rules, ranges: list[dict],
                 *, untrusted: dict | None = None, window_days: int = 30, attached: dict | None = None) -> dict:
    """One evidence packet per finding: state, who uses it, who changed it, and resource text fenced as untrusted."""
    flows = []
    for row in flow_rows:
        if row.get("action") != "ACCEPT":
            continue
        flows.append({"source": row["srcaddr"], "port": row["dstport"], "flows": row.get("flows", 1),
                      "class": classify(row["srcaddr"], ranges), "last_seen": row.get("last_seen", "")})
    packet = {"finding": {"key": finding.get("key", ""), "title": finding.get("title", ""),
                          "account": finding.get("account", ""), "region": finding.get("region", ""),
                          "resource": finding.get("resource", {})},
              "window_days": window_days, "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "state": {"rules": [list(r) for r in rules]}, "state_sha256": state_digest(rules),
              "attached": attached or {}, "traffic_by_port": summarise(flows),
              "change_history": [{"at": r.get("event_time", ""), "event": r.get("event_name", ""),
                                  "actor": r.get("actor_arn", "")} for r in trail_rows],
              "ranges_cited": [r["path"] for r in ranges],
              "coverage": {"flow_rows": len(flow_rows), "trail_rows": len(trail_rows),
                           "sources": len({f["source"] for f in flows})},
              "untrusted_text": untrusted or {},
              "_flows": flows}
    return packet


def model_view(packet: dict) -> dict:
    """What a model may see: no per-source flow dump, untrusted text clearly fenced."""
    return {k: v for k, v in packet.items() if k != "_flows"}


def replay(packet: dict, calls: list[dict], accepted=(), prefix: str = "") -> dict:
    """Who loses access if these calls run? Internal losses block unless a person accepted them by name.

    `prefix` is the target identity the gate shows a person; an acceptance only matches the name as displayed.
    """
    before = [tuple(r) for r in packet["state"]["rules"]]
    after = simulate(before, calls)
    lost = [f for f in packet["_flows"] if allowed(before, f["source"], f["port"])
            and not allowed(after, f["source"], f["port"])]
    internal = [f for f in lost if f["class"] != "external"]
    external = [f for f in lost if f["class"] == "external"]
    named = [f"{prefix}{f['source']}:{f['port']} ({f['flows']} flows)" for f in internal]
    return {"would_break": named,
            "accepted_breaks": [n for n in named if n in set(accepted)],
            "blocking": [n for n in named if n not in set(accepted)],
            "expected": ([f"{len(external)} external source(s) lose access (scanners unless coverage says otherwise)"]
                         if external else []),
            "rules_after": after}


def gate_impact(targets: list[dict], packets: dict, accepted=()) -> dict:
    """The impact gate over every target of a plan: it passes only when no unaccepted internal source loses access."""
    blocking, expected, per_target = [], [], {}
    for target in targets:
        packet = packets.get(target["target"])
        if packet is None:
            blocking.append(f"{target['target']}: no evidence packet, so impact is unknown")
            continue
        result = replay(packet, target.get("calls", []), accepted, prefix=f"{target['target']} ")
        per_target[target["target"]] = result
        blocking += result["blocking"]
        expected += [f"{target['target']}: {note}" for note in result["expected"]]
    return {"name": "impact", "passed": not blocking,
            "detail": {"would_break": blocking, "expected": expected, "per_target": per_target}}


def verdict(packet: dict, standard_calls: list[dict], ranges: list[dict]) -> dict:
    """The board's safe-to-fix line: would the class's standard fix break observed use, and how good is the evidence?"""
    result = replay(packet, standard_calls)
    covered = packet["coverage"]["flow_rows"] > 0
    return {"safe_to_fix": not result["would_break"] and covered,
            "would_break": result["would_break"], "expected": result["expected"],
            "coverage": {**packet["coverage"], "window_days": packet["window_days"],
                         "state_sha256": packet["state_sha256"]},
            "ranges_cited": [r["path"] for r in ranges],
            "basis": ("replayed observed flows against the simulated rules" if covered
                      else "no flow-log coverage in the window: unknown, not safe")}


def live_packet(session, finding: dict, flow_rows: list[dict], trail_rows: list[dict], ranges: list[dict],
                *, window_days: int = 30) -> dict:
    """Build one packet with two guarded reads: the live rules and the interfaces that carry them.

    Flow rows come from the stored evidence (CE-25); only the configuration is read live, so a verdict always names
    the state it was judged on. Resource text travels fenced as untrusted: tags and descriptions reach the model as
    data, never as instructions.
    """
    region = str(finding.get("region") or "")
    resource_id = str((finding.get("resource") or {}).get("id") or "")
    client = aws.client(session, "ec2", region)
    group = client.describe_security_groups(GroupIds=[resource_id])["SecurityGroups"][0]
    rules = [(perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort"), r["CidrIp"])
             for perm in group.get("IpPermissions", []) for r in perm.get("IpRanges", [])]
    interfaces = client.describe_network_interfaces(
        Filters=[{"Name": "group-id", "Values": [resource_id]}])["NetworkInterfaces"]
    owned = {eni["NetworkInterfaceId"] for eni in interfaces}
    flows = [row for row in flow_rows if row.get("interface_id") in owned]
    trails = [row for row in trail_rows if resource_id in (row.get("resource_ids") or [])]
    attached = {"interfaces": sorted(owned)}
    for eni in interfaces:
        instance = (eni.get("Attachment") or {}).get("InstanceId")
        if instance:
            attached["instance"] = instance
            break
    return build_packet(finding, flows, trails, rules, ranges,
                        untrusted={"security_group_description": group.get("Description", "")},
                        window_days=window_days, attached=attached)
