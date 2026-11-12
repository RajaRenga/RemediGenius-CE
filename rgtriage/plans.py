"""Typed remediation plans: a declarative intent registry judged by deterministic gates (roadmap CE-27).

The model writes an intent and its parameters; it never writes API calls. A declaration states the plan fields,
the target shape, which attributes a rollback snapshot must capture, the policy predicate and how calls compile.
Adding a finding class is adding a reviewed declaration (plus a playbook and eval cases); the gates, the compiler
and the executor do not change. Two declarations ship: `narrow_ingress` (ported from the prototype) and `imdsv2`,
which exists so the registry is not shaped by one example.

Rollback is snapshot-restore, not declared inverses: a declaration lists the attributes to capture, and Release B's
executor restores exactly those and re-reads to confirm. Hand-written inverse operations are where bugs hide.
"""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field

from . import contracts, impact

PLAN_SCHEMA = "remedi.plan/v1"
BASE_KEYS = ("schema", "intent", "finding_ids", "targets", "rationale")
DEFAULT_TARGET_CAP = 20
WORLD = impact.WORLD


@dataclass(frozen=True)
class Declaration:
    intent: str
    fields: tuple           # plan-level field names beyond BASE_KEYS
    target_keys: tuple      # per-target field names; "region" and the resource id are always required
    capture: tuple          # resource attributes a rollback snapshot must capture
    description: str
    impact_kind: str = "replay"        # "replay" replays observed flows; "metric" names an external signal
    impact_note: str = ""
    test_only: bool = False

    def policy(self, plan: dict, packets: dict, ranges: list[dict]) -> tuple[list[str], list[str]]:
        raise NotImplementedError

    def compile(self, plan: dict, target: dict) -> list[dict]:
        raise NotImplementedError

    def standard(self, packet: dict, ranges: list[dict]) -> list[dict]:
        """The class's standard fix, used for the board's safe-to-fix verdict before any plan exists."""
        raise NotImplementedError


def _approved_networks(ranges: list[dict]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out = []
    for item in ranges:
        try:
            out.append(ipaddress.ip_network(item["cidr"], strict=False))
        except (ValueError, KeyError):
            continue
    return out


class NarrowIngress(Declaration):
    def policy(self, plan, packets, ranges):
        problems, notes = [], []
        if plan.get("protocol") != "tcp" or not isinstance(plan.get("port"), int):
            problems.append("narrow_ingress changes one tcp port and nothing else")
        if not set(plan.get("remove_cidrs", [])) <= WORLD:
            problems.append(f"may only remove world ranges, got {plan.get('remove_cidrs')}")
        approved = _approved_networks(ranges)
        port = plan.get("port")
        for target in plan.get("targets", []):
            packet = packets.get(target.get("group_id"))
            observed = {f["source"] for f in (packet or {}).get("_flows", []) if f["port"] == port
                        and f["class"] != "external"}
            for add in target.get("add_cidrs", []):
                cidr = add.get("cidr", "")
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    problems.append(f"{target.get('group_id')}: {cidr} is not a CIDR")
                    continue
                if str(net) in WORLD or not impact.is_private_network(cidr):
                    problems.append(f"{target.get('group_id')}: {cidr} widens exposure (not a private range)")
                elif any(net == r or net.subnet_of(r) for r in approved):
                    notes.append(f"{target.get('group_id')}: {cidr} is a reviewed range")
                elif net.prefixlen == 32 and str(net.network_address) in observed:
                    notes.append(f"{target.get('group_id')}: {cidr} keeps an observed internal source that is not "
                                 f"in reviewed knowledge; confirm its owner")
                else:
                    problems.append(f"{target.get('group_id')}: {cidr} is neither a reviewed range nor an observed "
                                    f"internal /32")
                if not str(add.get("reason") or ""):
                    problems.append(f"{target.get('group_id')}: every added range needs a reason")
        return problems, notes

    def compile(self, plan, target):
        adds = [{"op": "authorize", "region": target["region"], "group_id": target["group_id"],
                 "proto": plan["protocol"], "port": plan["port"], "cidr": a["cidr"]}
                for a in target.get("add_cidrs", [])]
        removes = [{"op": "revoke", "region": target["region"], "group_id": target["group_id"],
                    "proto": plan["protocol"], "port": plan["port"], "cidr": c} for c in plan.get("remove_cidrs", [])]
        return adds + removes  # add the narrow rules first: no lock-out window between the two

    def standard(self, packet, ranges):
        """The standard fix: keep every reviewed range working, then remove the world rule. Adds before removes."""
        port = _world_port(packet)
        if port is None:
            return []
        adds = [{"op": "authorize", "proto": "tcp", "port": port, "cidr": r["cidr"]} for r in ranges]
        removes = [{"op": "revoke", "proto": "tcp", "port": port, "cidr": cidr}
                   for proto, low, high, cidr in packet["state"]["rules"]
                   if proto == "tcp" and low is not None and low <= port <= (high or low) and cidr in WORLD]
        return adds + removes


def _world_port(packet: dict) -> int | None:
    for proto, low, _high, cidr in packet["state"]["rules"]:
        if proto == "tcp" and cidr in WORLD and low in (22, 3389):
            return low
    return None


class ImdsV2(Declaration):
    def policy(self, plan, packets, ranges):
        problems = []
        for target in plan.get("targets", []):
            if target.get("http_tokens") != "required":
                problems.append(f"{target.get('instance_id')}: imdsv2 only enforces http_tokens=required")
            if target.get("add_cidrs") or plan.get("remove_cidrs"):
                problems.append("imdsv2 changes no network rules")
        return problems, []

    def compile(self, plan, target):
        return [{"op": "modify_instance_metadata_options", "region": target["region"],
                 "instance_id": target["instance_id"], "http_tokens": "required"}]

    def standard(self, packet, ranges):
        return [{"op": "modify_instance_metadata_options", "http_tokens": "required"}]


DECLARATIONS: dict[str, Declaration] = {
    "narrow_ingress": NarrowIngress(
        intent="narrow_ingress", fields=("protocol", "port", "remove_cidrs"),
        target_keys=("region", "group_id", "add_cidrs"), capture=("security_group_rules",),
        description="Replace world access on one tcp port with reviewed ranges and observed internal /32s"),
    "imdsv2": ImdsV2(
        intent="imdsv2", fields=(), target_keys=("region", "instance_id", "http_tokens"),
        capture=("metadata_options",), impact_kind="metric",
        impact_note="judged by the CloudWatch MetadataNoToken metric after the change, not by flow logs",
        description="Require IMDSv2 on instances; reverts to optional", test_only=True),
}


def plan_digest(plan: dict) -> str:
    return hashlib.sha256(contracts.canonical_json(plan).encode()).hexdigest()


# --------------------------------------------------------------------------- gates

def gate_schema(plan, decl: Declaration, cap: int = DEFAULT_TARGET_CAP) -> dict:
    problems = []
    if not isinstance(plan, dict):
        return {"name": "schema", "passed": False, "detail": {"problems": ["plan is not an object"]}}
    allowed_keys = set(BASE_KEYS) | set(decl.fields)
    extra = set(plan) - allowed_keys
    missing = (set(BASE_KEYS) | set(decl.fields)) - set(plan)
    if extra:
        problems.append(f"unknown fields: {sorted(extra)}")
    if missing:
        problems.append(f"missing fields: {sorted(missing)}")
    if plan.get("schema") != PLAN_SCHEMA:
        problems.append(f"schema must be {PLAN_SCHEMA}")
    if plan.get("intent") != decl.intent:
        problems.append(f"intent must be {decl.intent} for this declaration")
    targets = plan.get("targets")
    if not isinstance(targets, list) or not targets:
        problems.append("targets must be a non-empty list")
    elif len(targets) > cap:
        problems.append(f"plan carries {len(targets)} targets; the cap is {cap} so one approval stays one screen")
    else:
        for target in targets:
            if not isinstance(target, dict) or set(target) - set(decl.target_keys):
                problems.append(f"bad target entry: {target}")
            elif not {"region"} <= set(target) or not any(k in target for k in decl.target_keys if k != "region"):
                problems.append(f"target needs a region and a resource id: {target}")
    return {"name": "schema", "passed": not problems, "detail": {"problems": problems}}


def gate_scope(plan, findings_by_id: dict, decl: Declaration) -> dict:
    problems = []
    resources = set()
    for key in plan.get("finding_ids", []):
        finding = findings_by_id.get(key)
        if finding is None:
            problems.append(f"{key} is not a known finding")
            continue
        resources.add((str(finding.get("region", "")), str((finding.get("resource") or {}).get("id", ""))))
    if not resources:
        problems.append("plan names no known finding")
    for target in plan.get("targets", []):
        identity = (str(target.get("region", "")), str(target.get("group_id") or target.get("instance_id") or ""))
        if identity not in resources:
            problems.append(f"{identity[1]} in {identity[0]} is not the resource of any named finding")
    return {"name": "scope", "passed": not problems, "detail": {"problems": problems, "resources": sorted(resources)}}


def gate_policy(plan, packets: dict, ranges: list[dict], decl: Declaration) -> dict:
    problems, notes = decl.policy(plan, packets, ranges)
    return {"name": "policy", "passed": not problems, "detail": {"problems": problems, "notes": notes}}


def gate_impact(plan, packets: dict, decl: Declaration, accepted=()) -> dict:
    if decl.impact_kind == "metric":
        return {"name": "impact", "passed": True,
                "detail": {"would_break": [], "expected": [], "note": decl.impact_note,
                           "per_target": {t.get("group_id") or t.get("instance_id"): {"note": decl.impact_note}
                                          for t in plan.get("targets", [])}}}
    targets = [{"target": t.get("group_id") or t.get("instance_id"), "calls": decl.compile(plan, t)}
               for t in plan.get("targets", [])]
    return impact.gate_impact(targets, packets, accepted)


def run_gates(plan, findings: list[dict], packets: dict, ranges: list[dict], accepted=(),
              cap: int = DEFAULT_TARGET_CAP) -> list[dict]:
    """Schema, scope, policy, impact: each gate judges the plan, nothing trusts it. Stops at the first failure."""
    decl = DECLARATIONS.get(str(plan.get("intent") or "")) if isinstance(plan, dict) else None
    if decl is None:
        return [{"name": "schema", "passed": False,
                 "detail": {"problems": [f"unknown intent {str(plan.get('intent') or '')!r}; known: "
                                         f"{sorted(k for k, v in DECLARATIONS.items() if not v.test_only)}"]}}]
    gates = [gate_schema(plan, decl, cap)]
    if not gates[-1]["passed"]:
        return gates
    gates.append(gate_scope(plan, {f.get("key"): f for f in findings}, decl))
    if not gates[-1]["passed"]:
        return gates
    gates.append(gate_policy(plan, packets, ranges, decl))
    if not gates[-1]["passed"]:
        return gates
    gates.append(gate_impact(plan, packets, decl, accepted))
    return gates


def declaration_for(plan: dict) -> Declaration | None:
    return DECLARATIONS.get(str(plan.get("intent") or ""))


# --------------------------------------------------------------------------- slicing

def owner_of(finding: dict) -> str:
    owner = (finding.get("owner") or {}).get("title")
    return str(owner or finding.get("account") or "unknown")


def slice_findings(findings: list[dict], cap: int = DEFAULT_TARGET_CAP) -> list[dict]:
    """Cut the estate into plan-sized slices: one issue group per owner, capped, so approval stays one screen."""
    from . import prioritize

    groups: dict[tuple, list] = {}
    for finding in findings:
        groups.setdefault((prioritize.group_key(finding), owner_of(finding)), []).append(finding)
    slices = []
    for (group, owner), members in sorted(groups.items()):
        members.sort(key=lambda f: -int(f.get("score") or 0))
        for start in range(0, len(members), cap):
            chunk = members[start:start + cap]
            slices.append({"group": group, "owner": owner, "part": start // cap + 1,
                           "parts": (len(members) + cap - 1) // cap, "findings": chunk})
    return slices
