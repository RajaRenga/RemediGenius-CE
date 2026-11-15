"""The marketplace review fixes: model-written proposals must never choose which provider code gets downloaded and run,
and the validation tools must never see model or cloud keys. Covers the provider guard, the lock-file/plugin-dir init
lockdown, the allowlisted environment, and the plugin's approval routing for validate."""
import importlib.util
from pathlib import Path

import pytest

from rgtriage import github, validators
from test_rgtriage import home  # noqa: F401  (fixture: RGTRIAGE_HOME in a temp folder)
from test_validation_isolation import run_validate, world  # noqa: F401  (fixtures and helper)

PLUGIN = Path(__file__).resolve().parents[1] / "profiles" / "remedigenius" / "plugins" / "rg-triage" / "__init__.py"

BASE = b'terraform {\n  required_providers {\n    aws = {\n      source = "hashicorp/aws"\n    }\n  }\n}\n\nresource "aws_s3_bucket" "b" {}\n'
EVIL = BASE.replace(b"hashicorp/aws", b"evil.example/x/y")
LOCK = 'provider "registry.terraform.io/hashicorp/aws" {\n  version = "5.0.0"\n}\n'


@pytest.fixture
def plugin(tmp_path, monkeypatch):
    monkeypatch.setenv("RGTRIAGE_HOME", str(tmp_path))
    spec = importlib.util.spec_from_file_location("rg_triage_plugin_lockdown", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def no_plugin_dir(monkeypatch):
    monkeypatch.delenv("RGTRIAGE_TF_PLUGIN_DIR", raising=False)


# ---------------------------------------------------------------- allowlisted environment

def test_model_provider_keys_never_reach_the_tools(monkeypatch):
    for name in ("OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "GITHUB_TOKEN",
                 "AWS_SECRET_ACCESS_KEY", "MY_PASSWORD", "MODEL_API_KEY", "SOME_RANDOM_VAR"):
        monkeypatch.setenv(name, "x")
    monkeypatch.setenv("TF_VAR_region", "us-east-1")
    env = validators.clean_env()
    assert not [k for k in env if k.upper().endswith(("_API_KEY", "_TOKEN", "_PASSWORD")) or k.upper().startswith(("AWS_", "GITHUB_")) or k == "SOME_RANDOM_VAR"]
    # Windows upper-cases environment keys; the value must survive either way.
    assert any(k.upper() == "TF_VAR_REGION" and v == "us-east-1" for k, v in env.items())
    assert env["TF_IN_AUTOMATION"] == "1" and any(k.upper() == "PATH" for k in env)


# ---------------------------------------------------------------- the provider guard

def test_guard_refuses_added_or_changed_provider_requirements():
    assert validators.provider_guard({"main.tf": BASE}, {"main.tf": EVIL})
    assert validators.provider_guard({}, {"new.tf": BASE})  # a new file cannot introduce a terraform block
    assert validators.provider_guard({"main.tf": b"locals {\n  a = 1\n}\n"}, {"main.tf": BASE})


def test_guard_refuses_lock_file_changes():
    assert validators.provider_guard({}, {".terraform.lock.hcl": LOCK.encode()})
    assert validators.provider_guard({"m/.terraform.lock.hcl": LOCK.encode()}, {"m/.terraform.lock.hcl": b"provider \"x\" {}\n"})


def test_guard_covers_json_syntax_too():
    base = b'{"terraform": {"required_providers": {"aws": {"source": "hashicorp/aws"}}}}'
    evil = base.replace(b"hashicorp/aws", b"evil.example/x/y")
    assert validators.provider_guard({"main.tf.json": base}, {"main.tf.json": evil})
    assert validators.provider_guard({}, {"new.tf.json": base})
    benign = b'{"resource": {"aws_s3_bucket": {"b": {"bucket": "x"}}}}'
    assert validators.provider_guard({"main.tf.json": base}, {"main.tf.json": base, "r.tf.json": benign}) == []


def test_guard_allows_benign_changes_and_reformatting():
    changed = BASE.replace(b'resource "aws_s3_bucket" "b" {}', b'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}')
    assert validators.provider_guard({"main.tf": BASE}, {"main.tf": changed}) == []
    reformatted = BASE.replace(b"  required_providers {", b"required_providers   {")
    assert validators.provider_guard({"main.tf": BASE}, {"main.tf": reformatted}) == []
    assert validators.provider_guard({"main.tf": BASE}, {"notes.md": b"# hello"}) == []


def test_guard_cannot_be_fooled_by_braces_in_strings_or_comments():
    # A naive brace matcher stops at the "}" inside the string and would see identical blocks in both files.
    base = b'terraform {\n  note = "}"\n  required_providers {\n    aws = { source = "hashicorp/aws" }\n  }\n}\n'
    assert validators.provider_guard({"main.tf": base}, {"main.tf": base.replace(b"hashicorp/aws", b"evil.example/x/y")})
    commented = b'# terraform {\n#   required_providers { aws = { source = "hashicorp/aws" } }\n# }\n'
    assert validators.provider_guard({"main.tf": commented}, {"main.tf": commented.replace(b"# ", b"")})
    in_string = b'locals {\n  doc = "terraform { required_providers { aws = { source = \\"hashicorp/aws\\" } } }"\n}\n'
    assert validators.provider_guard({"main.tf": in_string}, {"main.tf": in_string.replace(b"hashicorp/aws", b"evil/x")}) == []


# ---------------------------------------------------------------- init lockdown

def test_no_lock_file_and_no_plugin_dir_refuses_before_running_anything(tmp_path, monkeypatch, no_plugin_dir):
    calls = []
    monkeypatch.setattr(validators, "_run", lambda cmd, cwd, env: calls.append(cmd) or (0, ""))
    ok, lines = validators.terraform_module(tmp_path, which=lambda name: "terraform")
    assert not ok and calls == [] and "refusing to download providers" in lines[0]


def test_vetted_plugin_dir_is_used_and_no_lock_file_is_needed(tmp_path, monkeypatch):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    monkeypatch.setenv("RGTRIAGE_TF_PLUGIN_DIR", str(plugins))
    calls = []
    monkeypatch.setattr(validators, "_run", lambda cmd, cwd, env: calls.append(cmd) or (0, ""))
    ok, _ = validators.terraform_module(tmp_path, which=lambda name: "terraform")
    assert ok and calls[0][1] == "init" and f"-plugin-dir={plugins}" in calls[0]


def test_locked_requirements_init_readonly(tmp_path, monkeypatch, no_plugin_dir):
    (tmp_path / validators.LOCK_FILE).write_text(LOCK)
    calls = []

    def fake_run(cmd, cwd, env):
        calls.append(cmd)
        return (0, "provider[registry.terraform.io/hashicorp/aws]") if cmd[1] == "providers" else (0, "")

    monkeypatch.setattr(validators, "_run", fake_run)
    ok, _ = validators.terraform_module(tmp_path, which=lambda name: "terraform")
    assert ok and [c[1] for c in calls[:3]] == ["get", "providers", "init"] and "-lockfile=readonly" in calls[2]


def test_unlocked_requirements_are_refused_without_installing(tmp_path, monkeypatch, no_plugin_dir):
    (tmp_path / validators.LOCK_FILE).write_text(LOCK)
    calls = []

    def fake_run(cmd, cwd, env):
        calls.append(cmd)
        return (0, "provider[registry.terraform.io/hashicorp/aws]\nprovider[registry.terraform.io/evil/x]") if cmd[1] == "providers" else (0, "")

    monkeypatch.setattr(validators, "_run", fake_run)
    ok, lines = validators.terraform_module(tmp_path, which=lambda name: "terraform")
    assert not ok and "registry.terraform.io/evil/x" in lines[0] and [c[1] for c in calls] == ["get", "providers"]


def test_child_module_install_failure_fails_closed(tmp_path, monkeypatch, no_plugin_dir):
    (tmp_path / validators.LOCK_FILE).write_text(LOCK)
    calls = []
    monkeypatch.setattr(validators, "_run", lambda cmd, cwd, env: calls.append(cmd) or ((1, "module source unreachable") if cmd[1] == "get" else (0, "")))
    ok, lines = validators.terraform_module(tmp_path, which=lambda name: "terraform")
    assert not ok and "cannot install the module's child modules" in lines[0] and [c[1] for c in calls] == ["get"]


def test_requirement_listing_failure_fails_closed(tmp_path, monkeypatch, no_plugin_dir):
    (tmp_path / validators.LOCK_FILE).write_text(LOCK)
    monkeypatch.setattr(validators, "_run", lambda cmd, cwd, env: (1, "module not installed") if cmd[1] == "providers" else (0, ""))
    ok, lines = validators.terraform_module(tmp_path, which=lambda name: "terraform")
    assert not ok and "cannot list the provider requirements" in lines[0]


def test_validate_tree_refuses_without_a_lock_file(tmp_path, monkeypatch, no_plugin_dir):
    (tmp_path / "main.tf").write_text("locals {\n  a = 1\n}\n")
    monkeypatch.setattr(validators, "_run", lambda *a: pytest.fail("ran terraform without a lock file"))
    rows = validators.validate_tree(tmp_path, ["main.tf"], which=lambda name: "terraform")
    assert rows[0]["check"] == "terraform . init" and rows[0]["result"] == "fail" and "refusing" in rows[0]["detail"]


# ---------------------------------------------------------------- wiring: cli validate and github publish

def test_cli_validate_refuses_provider_changing_proposals(world):
    (world["module"] / "main.tf").write_bytes(BASE)
    evil = world["props"] / "evil.tf"
    evil.write_bytes(EVIL)
    message = run_validate(world, f"{evil}=main.tf")
    assert "DENIED" in message and "required_providers" in message and world["captured"] == {}


def test_cli_validate_refuses_lock_file_overlays(world):
    lock = world["props"] / "newlock"
    lock.write_text(LOCK)
    message = run_validate(world, f"{lock}=.terraform.lock.hcl")
    assert "DENIED" in message and "lock file" in message and world["captured"] == {}


def test_publish_validation_refuses_provider_changes_before_any_tool_runs(tmp_path, monkeypatch):
    (tmp_path / "main.tf").write_bytes(BASE)
    monkeypatch.setattr(github._validators, "check_tree", lambda *a: pytest.fail("validated a provider-changing proposal"))
    rows = github._default_validate(tmp_path, {"main.tf": EVIL})
    assert rows[0]["check"] == "provider guard" and rows[0]["result"] == "fail"


# ---------------------------------------------------------------- the plugin's approval routing

def test_validate_requires_approval_naming_module_and_locked_providers(plugin, tmp_path):
    module = tmp_path / "iac"
    module.mkdir()
    (module / validators.LOCK_FILE).write_text(LOCK)
    result = plugin.on_pre_tool_call("rg_triage", {"action": "validate", "module": str(module), "files": ["p/a.tf=main.tf"]})
    assert result["action"] == "approve" and result["rule_key"] == "rg_triage:validate"
    assert str(module) in result["message"] and "registry.terraform.io/hashicorp/aws" in result["message"]
    assert "p/a.tf=main.tf" in result["message"]


def test_validate_without_a_lock_file_says_init_will_refuse(plugin, tmp_path):
    result = plugin.on_pre_tool_call("rg_triage", {"action": "validate", "module": str(tmp_path), "files": []})
    assert result["action"] == "approve" and "none locked" in result["message"]


def test_publish_approval_names_the_lockfile_only_validation(plugin):
    result = plugin.on_pre_tool_call("rg_triage", {"action": "github", "op": "publish", "ref": "x", "files": ["a=b"]})
    assert result["action"] == "approve" and "lock file" in result["message"] and "required_providers" in result["message"]
