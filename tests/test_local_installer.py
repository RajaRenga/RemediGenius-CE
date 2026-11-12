"""Offline adoption checks: incompatible installs fail before profile mutation."""
import importlib.util
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def installer():
    spec = importlib.util.spec_from_file_location("local_installer", ROOT / "tools/install_local_hermes.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("version", ["0.21.7", "0.22.0", "0.23.1-dev", "unknown", "0.23.10", "0.23.1+local"])
def test_incompatible_hermes_cannot_install(installer, monkeypatch, tmp_path, version):
    monkeypatch.setattr(installer.sys, "argv", ["installer", "--rgtriage-home", str(tmp_path / "desk")])
    monkeypatch.setattr(installer.subprocess, "run", lambda *a, **k:
                        subprocess.CompletedProcess(a, 0, stdout=f"Hermes {version}", stderr=""))
    with pytest.raises(SystemExit, match="No profile was changed"):
        installer.main()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("name", ["default", "../other", "a/b", "a\\b", "", "C:desk"])
def test_profile_name_rejected_before_running_hermes(installer, monkeypatch, name):
    def unexpected(*a, **k):
        pytest.fail("must not execute Hermes for invalid target")
    monkeypatch.setattr(installer.subprocess, "run", unexpected)
    with pytest.raises(SystemExit, match="dedicated profile"):
        installer.preflight("hermes", name)


def test_check_only_does_not_install_or_call_aws(installer, monkeypatch, tmp_path, capsys):
    calls = []
    def version(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=(
            "Hermes Agent v0.23.1 (2026.9.24) · upstream 3b421578\n"
            "Install directory: /opt/hermes\nInstall method: docker\nPython: 3.14.7\nOpenAI SDK: 2.24.0\n"), stderr="")
    monkeypatch.setattr(installer.subprocess, "run", version)
    monkeypatch.setattr(installer.sys, "argv", ["installer", "--check", "--hermes", "test-hermes",
                                               "--rgtriage-home", str(tmp_path / "desk")])
    installer.main()
    assert calls == [["test-hermes", "--version"]]
    assert list(tmp_path.iterdir()) == []
    assert "runtime behavior have not been checked" in capsys.readouterr().out


def test_merge_restricts_api_without_replacing_model(installer, tmp_path):
    path = tmp_path / "config.yaml"
    original = {"model": {"provider": "existing", "default": "my-model"},
                "platform_toolsets": {"api_server": ["terminal", "file"]}}
    path.write_text(yaml.safe_dump(original), encoding="utf-8")
    installer.merge_config(path, model_from_template=False)
    merged = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert merged["display"]["streaming"] is False and merged["display"]["show_reasoning"] is False
    assert merged["streaming"]["enabled"] is False
    assert merged["model"] == original["model"]
    assert merged["platform_toolsets"]["api_server"] == ["skills", "clarify", "file", "rg_triage"]
    backups = list(tmp_path.glob("config.yaml.bak-*"))
    assert len(backups) == 1
    assert yaml.safe_load(backups[0].read_text(encoding="utf-8")) == original


def test_distribution_matches_local_installer_pin(installer):
    manifest = yaml.safe_load((ROOT / "profiles/remedigenius/distribution.yaml").read_text(encoding="utf-8"))
    assert manifest["hermes_requires"] == f"=={installer.SUPPORTED_HERMES}"


@pytest.mark.parametrize("error", [OSError("not executable"), subprocess.TimeoutExpired("hermes", 20)])
def test_launcher_failure_has_actionable_message(installer, monkeypatch, error):
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(installer.subprocess, "run", fail)
    with pytest.raises(SystemExit, match="Cannot run Hermes"):
        installer.preflight("hermes", "remedigenius")


def test_local_install_bootstraps_first_scan_tables_and_preserves_existing_view(installer, tmp_path, monkeypatch):
    from rgtriage import repository

    monkeypatch.setenv("RGTRIAGE_HOME", str(tmp_path))
    monkeypatch.setenv("RGTRIAGE_CONFIG", str(tmp_path / "triage.yaml"))
    (tmp_path / "triage.yaml").write_text(yaml.safe_dump({
        "name": "first-run", "regions": ["eu-west-1"], "accounts": [],
        "storage": {"profile": "local", "namespace": "first_run", "installation_id": "first-run"},
    }))
    installer.initialize_storage(tmp_path)
    repo = repository.Repository.open()
    assert repo.load_latest() is None
    assert repo.load_decisions() == {}  # previously raised NoSuchTableError on the first direct CLI scan
    snapshot = {"version": "0.9.1", "scanned_at": "2026-01-01T00:00:00Z", "profile": {"name": "first-run"},
                "findings": [], "issues": [], "coverage": [], "fixes": [], "changes": {"new": 0}}
    repo.save_scan(snapshot)
    repo.close()
    installer.initialize_storage(tmp_path)
    restored = repository.Repository.open()
    assert restored.load_latest() == snapshot
    restored.close()
