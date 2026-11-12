"""Closure: routes, delivery methods, replies-as-data and drift as its own finding (roadmap CE-30)."""
from rgtriage import closure


def _finding(control="EC2.19", owner="team-web", exposure=False, priority="P2", iac=None, key="k1"):
    return {"key": key, "title": "t", "control_id": control, "category": "posture", "account": "a",
            "region": "us-east-1", "priority": priority, "score": 40,
            "owner": {"title": owner} if owner else {},
            "signals": {"public_exposure": exposure} if exposure else {},
            "resource": {"type": "AwsEc2SecurityGroup", "id": "sg-1"},
            "context": {"iac": iac} if iac else {}}


def _trail(agent="aws-cli/2.38.4", resource="sg-1", at="2026-05-02T22:41:00Z"):
    return [{"event_time": at, "event_name": "AuthorizeSecurityGroupIngress", "user_agent": agent,
             "actor_arn": "arn:aws:sts::1:assumed-role/Admin/alice", "resource_ids": [resource]}]


def test_machine_route_needs_the_class_opted_in():
    opted = {"execution": {"classes": ["EC2.19"]}}
    route, why = closure.route_for(_finding(), opted)
    assert route == "machine" and "opted in" in why
    route, _ = closure.route_for(_finding(), {})
    assert route == "team", "without the opt-in list nothing is a machine fix, however reversible it looks"


def test_identity_findings_route_to_the_individual():
    route, why = closure.route_for(_finding(control="IAM.6"), {})
    assert route == "individual" and "credential" in why


def test_an_unowned_public_p1_is_a_business_decision():
    route, why = closure.route_for(_finding(owner="", exposure=True, priority="P1"), {})
    assert route == "business" and "decision owner" in why


def test_delivery_follows_the_evidence_not_the_preference():
    assert closure.delivery_for(_finding(), _trail("console.amazonaws.com"))[0] == "console"
    assert closure.delivery_for(_finding(), _trail("aws-cli/2.38.4"))[0] == "cli"
    assert closure.delivery_for(_finding(), _trail("terraform/1.5.7"))[0] == "pipeline"
    assert closure.delivery_for(_finding(iac={"confidence": "high", "path": "main.tf"}), [])[0] == "iac"
    assert closure.delivery_for(_finding(), [])[0] == "board"


def test_a_business_item_carries_a_decision_date_and_containment():
    item = closure.item_for(_finding(owner="", exposure=True, priority="P1"), "business", "board",
                            {"control": "EC2.19"})
    assert item["decision_due"] and item["meanwhile"]
    assert item["status"] == "open"


def test_a_reply_claims_but_never_closes():
    item = closure.item_for(_finding(), "team", "iac", {"control": "EC2.19"})
    claimed = closure.apply_reply(item, "done, merged yesterday", by="owner")
    assert claimed["status"] == "claimed" and len(claimed["replies"]) == 1
    again = closure.apply_reply(claimed, "really", by="owner")
    assert again["status"] == "claimed", "a second reply does not close anything either"


def test_closure_needs_a_passing_proof_and_the_evidence_it_ran_on():
    item = closure.item_for(_finding(), "team", "iac", {"control": "EC2.19"})
    refused = closure.close_on_proof(item, True, "")
    assert refused["status"] == "open" and "never on a reply" in refused["close_refused"]
    refused = closure.close_on_proof(item, False, "sha256:x")
    assert refused["status"] == "open"
    closed = closure.close_on_proof(item, True, "sha256:proof")
    assert closed["status"] == "closed" and closed["evidence"] == "sha256:proof"


def test_iac_owned_but_console_changed_is_drift_on_its_own():
    finding = _finding(iac={"confidence": "high", "path": "main.tf"})
    drift = closure.drift_findings([finding], _trail("console.amazonaws.com"))
    assert len(drift) == 1 and drift[0]["category"] == "drift" and drift[0]["key"] == "drift-k1"
    assert drift[0]["context"]["drift"]["user_agent"] == "console.amazonaws.com"


def test_a_pipeline_change_on_an_iac_resource_is_not_drift():
    finding = _finding(iac={"confidence": "high", "path": "main.tf"})
    assert closure.drift_findings([finding], _trail("terraform/1.5.7")) == []
    assert closure.drift_findings([_finding()], _trail("console.amazonaws.com")) == [], "no IaC, no drift claim"


def test_the_board_connector_needs_no_configuration_and_writes_nothing():
    connector = closure.CONNECTORS["board"]()
    assert connector.notify({"key": "k1"}, "please review")["delivered"] == "board"
    assert connector.write_status({"key": "k1"}, "claimed")["via"] == "board"
