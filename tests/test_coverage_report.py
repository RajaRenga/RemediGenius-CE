from rgtriage import digest


def test_complete_coverage_keeps_late_account_and_partial_source():
    rows = [{"account": f"account-{n:02}", "region": "us-east-1", "source": "guardduty",
             "status": "not_enabled"} for n in range(14)]
    rows += [{"account": "last-account", "region": "eu-central-1", "source": "securityhub",
              "status": "ok", "truncated": True},
             {"account": "last-account", "region": "us-east-2", "source": "config", "status": "denied"}]
    report = digest.coverage_report({"scanned_at": "2026-11-12T14:00:00Z", "coverage": rows})
    assert "last-account/us-east-2 — denied: config" in report
    assert "last-account/eu-central-1 — partial: securityhub" in report
    assert "14 not_enabled" in report and "1 partial" in report and "1 denied" in report
    assert report.count("- account-") == 14
    assert "| config | 0 | 0 | 1 | 0 | 0 | 0 | 1 |" in report
    assert "| guardduty | 0 | 14 | 0 | 0 | 0 | 0 | 14 |" in report
    assert "| securityhub | 0 | 0 | 0 | 0 | 1 | 0 | 1 |" in report
    assert rows[-2]["status"] == "ok"  # Presentation must not rewrite stored source evidence.


def test_denied_and_unrecorded_scopes_are_not_counted_as_disabled():
    rows = [{"account": "demo", "region": region, "source": "securityhub", "status": status}
            for region, status in [("us-east-1", "ok"), ("eu-central-1", "denied"),
                                   ("us-east-2", "not_enabled")]]
    rows.append({"account": "demo", "region": "us-east-1", "source": "health", "status": "not_available"})
    report = digest.coverage_report({"scanned_at": "2026-01-01T00:00:00Z", "coverage": rows})
    assert "| securityhub | 1 | 1 | 1 | 0 | 0 | 0 | 3 |" in report
    assert "| health | 0 | 0 | 0 | 1 | 0 | 0 | 1 |" in report
    assert "demo/eu-central-1: securityhub" in report
    assert "0 partial" in report and "partial IS a supported status" in report
