"""Closure: route every finding to whoever must act, and close it only on evidence (roadmap CE-30).

Most findings do not end with an API call; they end with a person enrolling a device, a team merging a change or a
business owner saying yes. Three things are kept apart so one design handles all of them: who must act (route), how
the change is delivered (method), and what proves it is done (proof). The proof never varies: a finding closes on
evidence, never on a reply.

The method that owns a resource fixes it — a Terraform-managed resource never gets console steps, because the next
apply would undo them. A mismatch is itself a finding: a resource built by IaC but last changed in the console is
drift, and is raised on its own.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

ROUTES = ("machine", "individual", "team", "business")
INDIVIDUAL_CONTROLS = {"IAM.4", "IAM.6", "IAM.9", "IAM.1", "IAM.5", "IAM.3", "IAM.21", "IAM.2"}
MACHINE_CONTROLS = {"EC2.19", "EC2.53", "S3.8", "S3.1", "S3.2", "S3.3", "CloudTrail.1", "GuardDuty.1", "Config.1"}
CONSOLE_AGENTS = ("console", "aws-internal", "signer", "browser")
PIPELINE_AGENTS = ("terraform", "cloudformation", "atlantis", "spacelift", "github-actions", "gitlab")


class ConnectorNotConfigured(RuntimeError):
    """No connector for this verb; the board still carries the item, so the run continues without it."""


class Connector:
    """Fixed verbs only: find owner, ask or notify, open or update ticket, watch run, write status back."""

    name = "base"

    def find_owner(self, item: dict) -> dict:
        raise ConnectorNotConfigured(f"{self.name} cannot find owners")

    def notify(self, item: dict, message: str) -> dict:
        raise ConnectorNotConfigured(f"{self.name} cannot notify")

    def open_ticket(self, item: dict) -> dict:
        raise ConnectorNotConfigured(f"{self.name} cannot open tickets")

    def watch_run(self, item: dict) -> dict:
        raise ConnectorNotConfigured(f"{self.name} cannot watch runs")

    def write_status(self, item: dict, status: str) -> dict:
        raise ConnectorNotConfigured(f"{self.name} cannot write status")


class BoardConnector(Connector):
    """The default: the item lives on the board and in chat. No outbound write, so nothing can be sent twice."""

    name = "board"

    def find_owner(self, item):
        return {"owner": item.get("owner") or "", "via": "board"}

    def notify(self, item, message):
        return {"delivered": "board", "item": item.get("key", ""), "message": message}

    def write_status(self, item, status):
        return {"item": item.get("key", ""), "status": status, "via": "board"}


CONNECTORS = {"board": BoardConnector}


def route_for(finding: dict, profile: dict, known: dict | None = None) -> tuple[str, str]:
    """Who must act. The machine route needs the class opted in; nothing executes without that list."""
    control = str(finding.get("control_id") or "")
    opted = set((profile.get("execution") or {}).get("classes") or [])
    if control in MACHINE_CONTROLS and control in opted:
        return "machine", f"{control} has a reviewed intent and is opted in for execution"
    if control in INDIVIDUAL_CONTROLS or finding.get("category") == "identity":
        return "individual", "an identity owner must act on their own credential or console access"
    owner = (finding.get("owner") or {}).get("title")
    if owner or (known or {}).get("repositories"):
        return "team", f"the owning team ({owner or 'from knowledge'}) merges the change"
    if finding.get("signals", {}).get("public_exposure") and finding.get("priority") in ("P1", "P2"):
        return "business", "a public, business-critical exposure needs a named decision owner, not a silent fix"
    return "team", "no owner on record: route to the account's team and ask them to confirm ownership"


def delivery_for(finding: dict, trail_rows: list[dict], known: dict | None = None) -> tuple[str, str]:
    """How the change is delivered, inferred from evidence and confirmed once in reviewed knowledge."""
    resource_id = (finding.get("resource") or {}).get("id", "")
    events = [r for r in trail_rows if resource_id and resource_id in (r.get("resource_ids") or [])]
    iac = (finding.get("context") or {}).get("iac") or {}
    if iac.get("confidence") == "high" or (known or {}).get("repository_for_resource"):
        return "iac", "the resource is deployed from a connected repository; the fix is a pull request"
    agents = [str(r.get("user_agent") or "").lower() for r in events]
    if any(a for a in agents if any(p in a for p in PIPELINE_AGENTS)):
        return "pipeline", "the last changes came from a managed pipeline; the PR is watched, not applied by hand"
    if any(a for a in agents if any(c in a for c in CONSOLE_AGENTS)):
        return "console", "the resource is console-managed: exact console steps, plus an optional import block"
    if agents:
        return "cli", "the resource is changed by CLI or SDK: commands with the real ids, and the undo"
    return "board", "no change history in the window: the board carries the steps until evidence says otherwise"


def item_for(finding: dict, route: str, method: str, proof: dict, *, business_days: int = 30) -> dict:
    now = datetime.now(timezone.utc)
    item = {"key": finding.get("key", ""), "title": finding.get("title", ""), "route": route, "method": method,
            "owner": (finding.get("owner") or {}).get("title", ""), "status": "open",
            "account": finding.get("account", ""), "region": finding.get("region", ""),
            "proof": proof, "opened_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "replies": []}
    if route == "business":
        item["decision_due"] = (now + timedelta(days=business_days)).strftime("%Y-%m-%d")
        item["meanwhile"] = "containment that needs no decision (an alarm, or an SCP stopping new cases)"
    return item


def apply_reply(item: dict, reply: str, by: str) -> dict:
    """Replies are data: "done" moves an item to claimed, never to closed."""
    item = {**item, "status": "claimed" if item["status"] == "open" else item["status"]}
    item["replies"] = item.get("replies", []) + [{"by": by, "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                  "text": reply}]
    return item


def close_on_proof(item: dict, proof_passed: bool, evidence: str) -> dict:
    """The one rule that never varies: closure needs a passing proof and the evidence it ran on."""
    if not proof_passed or not evidence:
        return {**item, "status": item.get("status", "open"),
                "close_refused": "a finding closes on evidence, never on a reply"}
    return {**item, "status": "closed", "closed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence": evidence}


def drift_findings(findings: list[dict], trail_rows: list[dict]) -> list[dict]:
    """A resource built by IaC but last changed in the console is drift, and is raised on its own."""
    out = []
    for finding in findings:
        resource_id = (finding.get("resource") or {}).get("id", "")
        iac = (finding.get("context") or {}).get("iac") or {}
        if not resource_id or iac.get("confidence") != "high":
            continue
        changes = [r for r in trail_rows if resource_id in (r.get("resource_ids") or [])]
        if not changes:
            continue
        last = max(changes, key=lambda r: str(r.get("event_time") or ""))
        agent = str(last.get("user_agent") or "").lower()
        if any(c in agent for c in CONSOLE_AGENTS):
            out.append({"key": f"drift-{finding.get('key', '')}", "source": "desk", "category": "drift",
                        "title": f"{resource_id} is deployed from IaC but was last changed in the console",
                        "priority": "P3", "score": 0, "account": finding.get("account", ""),
                        "region": finding.get("region", ""),
                        "resource": finding.get("resource", {}),
                        "context": {"drift": {"last_event": last.get("event_name"), "at": last.get("event_time"),
                                              "user_agent": last.get("user_agent"),
                                              "iac": iac.get("path") or iac.get("repo")}},
                        "reasons": ["IaC-owned resource changed outside the repository: the next apply reverts it"],
                        "signals": {}, "remediation": {}, "owner": finding.get("owner")})
    return out
