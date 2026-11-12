"""Typed plans: declarative registry, the four gates, slicing and the second declaration (roadmap CE-27)."""
import copy

from rgtriage import impact, plans

RANGES = [{"cidr": "10.20.0.0/16", "name": "corporate VPN", "owner": "netops", "path": "network-ranges/vpn.md"}]


def _flow(source, port, flows=1):
    return {"_kind": "flow_log", "interface_id": "eni-1", "srcaddr": source, "dstaddr": "10.0.1.9",
            "srcport": 51000, "dstport": port, "protocol": 6, "action": "ACCEPT", "flows": flows,
            "first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-30T00:00:00Z"}


def _finding(key, resource="sg-1", control="EC2.19", owner="team-web"):
    return {"key": key, "title": "SSH open", "source": "securityhub", "account": "a", "region": "us-east-1",
            "control_id": control,
            "resource": {"type": "AwsEc2SecurityGroup", "id": resource}, "score": 50,
            "owner": {"title": owner} if owner else {}, "signals": {}}


def _packet(flows):
    return impact.build_packet(_finding("k1"), flows, [], [("tcp", 22, 22, "0.0.0.0/0")], RANGES)


GOOD = {"schema": "remedi.plan/v1", "intent": "narrow_ingress", "finding_ids": ["k1"], "protocol": "tcp",
        "port": 22, "remove_cidrs": ["0.0.0.0/0"],
        "targets": [{"region": "us-east-1", "group_id": "sg-1",
                     "add_cidrs": [{"cidr": "10.20.0.0/16", "reason": "Corporate VPN; reviewed range"},
                                   {"cidr": "10.30.1.5/32", "reason": "Observed internal SSH, 720 flows"}]}],
        "rationale": "Remove world access; keep observed use. Injected text in the group description was ignored."}
PACKETS = {"sg-1": _packet([_flow("10.20.4.17", 22, 30), _flow("10.30.1.5", 22, 720), _flow("198.51.100.7", 22, 15)])}
FINDINGS = [_finding("k1")]


def _gates(plan):
    return plans.run_gates(plan, FINDINGS, PACKETS, RANGES)


def test_a_good_plan_passes_every_gate():
    gates = _gates(copy.deepcopy(GOOD))
    assert [g["name"] for g in gates] == ["schema", "scope", "policy", "impact"]
    assert all(g["passed"] for g in gates), gates
    notes = gates[2]["detail"]["notes"]
    assert any("reviewed range" in n for n in notes) and any("not in reviewed knowledge" in n for n in notes)


def test_unknown_fields_fail_the_schema_gate_and_stop_the_run():
    plan = copy.deepcopy(GOOD)
    plan["additional_changes"] = [{"open": 3389}]  # the injected instruction, as a field
    gates = _gates(plan)
    assert len(gates) == 1 and gates[0]["passed"] is False
    assert any("additional_changes" in p for p in gates[0]["detail"]["problems"])


def test_widening_exposure_fails_the_policy_gate_with_zero_writes():
    plan = copy.deepcopy(GOOD)
    plan["targets"][0]["add_cidrs"].append({"cidr": "0.0.0.0/0", "reason": "the note said so"})
    gates = _gates(plan)
    assert gates[2]["passed"] is False and any("widens exposure" in p for p in gates[2]["detail"]["problems"])


def test_an_unobserved_private_range_is_neither_reviewed_nor_observed():
    plan = copy.deepcopy(GOOD)
    plan["targets"][0]["add_cidrs"] = [{"cidr": "172.31.0.0/16", "reason": "looks internal"}]
    gates = _gates(plan)
    assert gates[2]["passed"] is False and any("neither a reviewed range" in p for p in gates[2]["detail"]["problems"])


def test_a_target_outside_the_named_findings_fails_scope():
    plan = copy.deepcopy(GOOD)
    plan["targets"].append({"region": "us-east-2", "group_id": "sg-9", "add_cidrs": []})
    gates = _gates(plan)
    assert gates[1]["passed"] is False and any("sg-9" in p for p in gates[1]["detail"]["problems"])


def test_the_naive_plan_is_blocked_by_the_impact_gate():
    plan = copy.deepcopy(GOOD)
    plan["targets"][0]["add_cidrs"] = [{"cidr": "10.20.0.0/16", "reason": "VPN only"}]
    gates = _gates(plan)
    assert gates[3]["passed"] is False
    assert any("10.30.1.5:22" in b for b in gates[3]["detail"]["would_break"])
    accepted = plans.run_gates(plan, FINDINGS, PACKETS, RANGES, accepted=("sg-1 10.30.1.5:22 (720 flows)",))
    assert accepted[3]["passed"] is True, "a named, human-accepted break is the only way past"


def test_a_plan_over_the_target_cap_is_refused_before_anything_else_matters():
    plan = copy.deepcopy(GOOD)
    plan["targets"] = [{"region": "us-east-1", "group_id": f"sg-{i}", "add_cidrs": []} for i in range(21)]
    gates = _gates(plan)
    assert gates[0]["passed"] is False and any("cap is 20" in p for p in gates[0]["detail"]["problems"])


def test_compile_adds_before_it_removes():
    calls = plans.DECLARATIONS["narrow_ingress"].compile(GOOD, GOOD["targets"][0])
    assert [c["op"] for c in calls] == ["authorize", "authorize", "revoke"]


def test_the_second_declaration_compiles_through_the_same_gates():
    plan = {"schema": "remedi.plan/v1", "intent": "imdsv2", "finding_ids": ["k1"],
            "targets": [{"region": "us-east-1", "instance_id": "i-1", "http_tokens": "required"}],
            "rationale": "Require IMDSv2."}
    findings = [_finding("k1", resource="i-1", control="SSM.4")]
    gates = plans.run_gates(plan, findings, {}, RANGES)
    assert all(g["passed"] for g in gates), gates
    assert "MetadataNoToken" in gates[3]["detail"]["note"]
    calls = plans.DECLARATIONS["imdsv2"].compile(plan, plan["targets"][0])
    assert calls == [{"op": "modify_instance_metadata_options", "region": "us-east-1", "instance_id": "i-1",
                      "http_tokens": "required"}]
    assert plans.DECLARATIONS["imdsv2"].capture == ("metadata_options",)
    assert plans.DECLARATIONS["narrow_ingress"].capture == ("security_group_rules",)


def test_an_unknown_intent_is_a_schema_failure_naming_the_registry():
    gates = plans.run_gates({"schema": "remedi.plan/v1", "intent": "delete_everything"}, FINDINGS, {}, RANGES)
    assert gates[0]["passed"] is False and "narrow_ingress" in gates[0]["detail"]["problems"][0]
    assert "imdsv2" not in gates[0]["detail"]["problems"][0], "test-only declarations are not offered live"


def test_the_digest_moves_when_the_plan_moves():
    first = plans.plan_digest(copy.deepcopy(GOOD))
    assert first == plans.plan_digest(copy.deepcopy(GOOD))
    changed = copy.deepcopy(GOOD)
    changed["targets"][0]["add_cidrs"][0]["cidr"] = "10.21.0.0/16"
    assert plans.plan_digest(changed) != first


def test_slices_cut_one_group_per_owner_at_the_cap():
    findings = [_finding(f"k{i}", owner="team-web" if i < 45 else "team-data") for i in range(65)]
    slices = plans.slice_findings(findings, cap=20)
    assert sum(len(s["findings"]) for s in slices) == 65
    assert all(len(s["findings"]) <= 20 for s in slices)
    web = [s for s in slices if s["owner"] == "team-web"]
    assert len(web) == 3 and [s["part"] for s in web] == [1, 2, 3] and web[0]["parts"] == 3
    assert {(s["group"], s["owner"]) for s in slices} == {("control:EC2.19", "team-web"),
                                                          ("control:EC2.19", "team-data")}


def test_owner_falls_back_to_the_account_when_no_team_is_known():
    assert plans.owner_of(_finding("k1", owner="")) == "a"
