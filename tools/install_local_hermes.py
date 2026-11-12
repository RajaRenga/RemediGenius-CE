#!/usr/bin/env python3
"""Install RemediGenius Community Edition (RemediGenius-CE) into an existing local Hermes.

Creates (or updates) a Hermes profile that reuses the model settings of one of your
existing profiles, then adds the RemediGenius-CE SOUL, skills and the rg-triage plugin.

    python tools/install_local_hermes.py --clone-from default
    hermes -p remedigenius chat

Run it with the Python that has the desk package dependencies (the plugin reuses it).
Writes the dedicated profile, desk home and shared Knowledge dashboard plugin/configuration.
The profile config.yaml is merged and the previous file kept as a timestamped backup.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "profiles" / "remedigenius"
TOOLSETS = ["skills", "clarify", "file", "rg_triage"]
SUPPORTED_HERMES = "0.23.1"
WATCH_SCRIPT = '''"""Hermes cron script: print new P1/P2 security findings; print nothing when there is nothing new."""
import os, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
env = dict(os.environ, RGTRIAGE_HOME={home!r}, PYTHONPATH={src!r} + os.pathsep + os.environ.get("PYTHONPATH", ""),
           PYTHONIOENCODING="utf-8", RGTRIAGE_DURABLE="1")
proc = subprocess.run([{python!r}, "-m", "rgtriage", "watch", "--min-priority", "P2"], env=env,
                      capture_output=True, text=True, encoding="utf-8", errors="replace")
sys.stdout.write(proc.stdout)
if proc.returncode:
    sys.stdout.write("rgtriage watch failed: " + proc.stderr[-800:])
'''


def hermes_root() -> Path:
    if os.environ.get("HERMES_ROOT"):
        return Path(os.environ["HERMES_ROOT"])
    if os.environ.get("HERMES_HOME"):
        active = Path(os.environ["HERMES_HOME"])
        return active.parent.parent if active.parent.name == 'profiles' else active
    if os.name == "nt" and os.environ.get("LOCALAPPDATA") and (Path(os.environ["LOCALAPPDATA"]) / "hermes").exists():
        return Path(os.environ["LOCALAPPDATA"]) / "hermes"
    return Path.home() / ".hermes"


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    print("+ " + " ".join(cmd))
    return subprocess.run(cmd, text=True, capture_output=True, encoding="utf-8", errors="replace")


def preflight(hermes: str, profile: str) -> None:
    """Fail before modifying a profile; never contact AWS or print provider configuration."""
    if profile.lower() == "default" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", profile):
        raise SystemExit("Choose a dedicated profile name (letters, digits, hyphen or underscore), not default.")
    try:
        result = subprocess.run([hermes, "--version"], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        raise SystemExit("Cannot run Hermes. Supply --hermes PATH or use docs/WORKSTATION.md.") from None
    version = re.search(r"^Hermes(?: Agent)?(?: version)?\s+v?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)(?![\w.])",
                        result.stdout + "\n" + result.stderr, re.MULTILINE)
    if result.returncode or not version or version.group(1) != SUPPORTED_HERMES:
        raise SystemExit(f"This CE release targets Hermes {SUPPORTED_HERMES}; the installed version could not be "
                         "confirmed as that exact version. Keep your existing Hermes and use the pinned "
                         "Docker workstation (docs/WORKSTATION.md). No profile was changed.")
    from importlib.util import find_spec
    missing = [name for name in ("boto3", "yaml", "pyiceberg", "pyarrow") if find_spec(name) is None]
    if missing:
        raise SystemExit("Missing desk dependencies: " + ", ".join(missing) + ". Run: python -m pip install -e .")
    print(f"Preflight passed: Hermes {SUPPORTED_HERMES}, desk dependencies available. "
          "AWS access, model access and runtime behavior have not been checked.")


def merge_config(path: Path, model_from_template: bool) -> None:
    current = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    current = current or {}
    if path.exists():
        backup = path.with_name(f"config.yaml.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)
        print(f"  backed up {path.name} -> {backup.name}")
    template = yaml.safe_load((SOURCE / "config.yaml").read_text(encoding="utf-8"))
    if model_from_template:
        current["model"] = template["model"]
    plugins = current.setdefault("plugins", {}) or {}
    current["plugins"] = plugins
    enabled = plugins.setdefault("enabled", []) or []
    for name in ("rg-triage", "rg-knowledge"):
        if name not in enabled:
            enabled.append(name)
    plugins["enabled"] = enabled
    pts = current.setdefault("platform_toolsets", {}) or {}
    for platform, toolsets in template["platform_toolsets"].items():
        pts[platform] = list(toolsets)
    current["platform_toolsets"] = pts
    agent = current.setdefault("agent", {}) or {}
    agent["max_turns"] = max(int(agent.get("max_turns") or 0), template["agent"]["max_turns"])
    current["agent"] = agent
    kanban = current.setdefault("kanban", {}) or {}
    kanban.update(template["kanban"])  # Kanban cards are for people: no worker agents, no automatic splitting
    current["kanban"] = kanban
    display = current.setdefault("display", {}) or {}
    display.update(template["display"])
    current["display"] = display
    streaming = current.setdefault("streaming", {}) or {}
    streaming.update(template["streaming"])
    current["streaming"] = streaming
    path.write_text(yaml.safe_dump(current, sort_keys=False, allow_unicode=True), encoding="utf-8")


def initialize_storage(home: Path) -> None:
    """Use the desk service's bootstrap before a subprocess-only Hermes starts its first scan."""
    env = dict(os.environ, RGTRIAGE_HOME=str(home), RGTRIAGE_CONFIG=str(home / "triage.yaml"),
               PYTHONPATH=str(REPO))
    script = ("from rgtriage.repository import Repository; r=Repository.open(); "
              "report=r.recover(); r.close(); "
              "assert report.state != 'blocked', report.reason")
    result = subprocess.run([sys.executable, "-c", script], env=env, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError("Durable storage initialization failed; installation is incomplete. "
                           "Check the configured storage and dependencies before scanning. "
                           + result.stderr[-400:])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", default="remedigenius", help="Hermes profile name to create/update")
    ap.add_argument("--clone-from", default="default", help="existing profile whose model/provider settings to reuse")
    ap.add_argument("--hermes", default=shutil.which("hermes") or "hermes")
    ap.add_argument("--rgtriage-home", default=os.environ.get("RGTRIAGE_HOME") or str(Path.home() / ".rgtriage"))
    ap.add_argument("--aws-profile", default=None, help="AWS CLI profile for the initial triage.yaml")
    ap.add_argument("--region", default=None)
    ap.add_argument("--check", action="store_true", help="check compatibility without installing or calling AWS")
    args = ap.parse_args()

    preflight(args.hermes, args.profile)
    if args.check:
        return

    try:
        import boto3  # noqa: F401
    except ImportError:
        sys.exit(f"{sys.executable} has no boto3. Run: {sys.executable} -m pip install boto3 PyYAML")

    root = hermes_root()
    profile_home = root / "profiles" / args.profile
    created = False
    if not profile_home.exists():
        result = run([args.hermes, "profile", "create", args.profile, "--clone-from", args.clone_from, "--no-alias",
                      "--description", "AWS security triage desk: prioritized findings, read-only investigation, IaC fix proposals."])
        if result.returncode != 0 or not profile_home.exists():
            sys.exit(f"profile create failed:\n{result.stdout}\n{result.stderr}")
        created = True
    print(f"Profile folder: {profile_home}")

    backup = profile_home / 'remedigenius-backups' / str(time.time_ns())
    for relative in ['SOUL.md', 'config.yaml', 'plugins/rg-triage', 'scripts/rgtriage-watch.py'] + [
            'skills/' + item.name for item in (SOURCE / 'skills').iterdir()]:
        existing = profile_home / relative
        if existing.exists():
            target = backup / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if existing.is_dir():
                shutil.copytree(existing, target, ignore=shutil.ignore_patterns('__pycache__'))
            else:
                shutil.copy2(existing, target)
    shared_tab = root / 'plugins' / 'rg-knowledge'
    if shared_tab.exists():
        shutil.copytree(shared_tab, backup / 'shared-rg-knowledge', ignore=shutil.ignore_patterns('__pycache__'))
    print(f"  previous managed files backed up under {backup}")

    shutil.copy2(SOURCE / "SOUL.md", profile_home / "SOUL.md")
    for skill in (SOURCE / "skills").iterdir():
        dest = profile_home / "skills" / skill.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(skill, dest)
    plugin_dest = profile_home / "plugins" / "rg-triage"
    if plugin_dest.exists():
        shutil.rmtree(plugin_dest)
    shutil.copytree(SOURCE / "plugins" / "rg-triage", plugin_dest, ignore=shutil.ignore_patterns("__pycache__", "local.json"))
    home = Path(args.rgtriage_home).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    (home / "proposals").mkdir(exist_ok=True)
    (plugin_dest / "local.json").write_text(json.dumps({"python": sys.executable, "src": str(REPO), "home": str(home), "durable": True}, indent=1),
                                            encoding="utf-8")
    merge_config(profile_home / "config.yaml", model_from_template=False)
    scripts = profile_home / "scripts"
    scripts.mkdir(exist_ok=True)
    (scripts / "rgtriage-watch.py").write_text(WATCH_SCRIPT.format(home=str(home), src=str(REPO), python=sys.executable),
                                               encoding="utf-8")
    tab = root / "plugins" / "rg-knowledge"
    if tab.exists():
        shutil.rmtree(tab)
    shutil.copytree(SOURCE / "dashboard-plugins" / "rg-knowledge", tab, ignore=shutil.ignore_patterns("__pycache__", "local.json"))
    (tab / "local.json").write_text(json.dumps({"python": sys.executable, "src": str(REPO), "home": str(home),
                                                "proposals": str(home / "proposals"), "inbox": str(home / "knowledge-inbox"),
                                                "files": str(home / "knowledge-files"), "profile": args.profile,
                                                "improve": str(home / "rg-improve"), "package": str(SOURCE)}, indent=1),
                                    encoding="utf-8")
    for folder in ("proposals/knowledge", "knowledge-inbox", "knowledge-files", "rg-improve", "rg-traces"):
        (home / folder).mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(tab))
    from improve.runner import apply_approved  # approved skill improvements survive re-installs of the same release
    for item in apply_approved(home / "rg-improve", SOURCE / "skills", profile_home / "skills"):
        print(f"  approved skill improvement {item['skill']}: {'applied' if item['applied'] else item.get('reason')}")
    print("  installed SOUL.md, skills rg-*, plugin rg-triage, scripts/rgtriage-watch.py, dashboard Knowledge tab")

    env = dict(os.environ, RGTRIAGE_HOME=str(home), PYTHONPATH=str(REPO))
    # The dashboard serves user plugins only when they are enabled at its launch scope too.
    enabled = run([args.hermes, "-p", "default", "plugins", "enable", "rg-knowledge"])
    print("  enabled the Knowledge tab for the dashboard" if enabled.returncode == 0 else
          f"  could not enable rg-knowledge at the default scope: {enabled.stdout[-200:]} {enabled.stderr[-200:]}")
    seeded = subprocess.run([sys.executable, "-m", "rgtriage", "knowledge-edit", "seed"], env=env, text=True, capture_output=True)
    if seeded.returncode:
        sys.exit("Knowledge initialization failed; installation is incomplete. Check the desk dependencies and retry.")
    print(f"  knowledge bundle: {home / 'knowledge'}")
    if not (home / "triage.yaml").exists():
        cmd = [sys.executable, "-m", "rgtriage", "init"]
        if args.aws_profile:
            cmd += ["--profile", args.aws_profile]
        if args.region:
            cmd += ["--region", args.region]
        result = subprocess.run(cmd, env=env, text=True, capture_output=True)
        if result.returncode:
            sys.exit("AWS configuration initialization failed; installation is incomplete. Check your AWS "
                     "profile/login, then retry with --aws-profile and --region. No scan has run.")
        print(f"  AWS configuration: {home / 'triage.yaml'}")
    else:
        print(f"  keeping existing {home / 'triage.yaml'}")

    try:
        initialize_storage(home)
    except RuntimeError as exc:
        sys.exit(str(exc))
    print("  durable storage initialized/recovered; no AWS scan was started")

    print(f"""
Done{' (new profile)' if created else ''}.
  1. Check access:       {sys.executable} -m rgtriage --durable doctor     (set RGTRIAGE_HOME={home})
  2. Collect findings:   {sys.executable} -m rgtriage --durable scan       (same RGTRIAGE_HOME)
  3. Start the desk:     hermes -p {args.profile} chat   -> it opens with your attention board
  Kanban: the desk files cards in triage for people. If this Hermes runs a gateway, keep its dispatcher from
     splitting them with agents: hermes config set kanban.auto_decompose false   (shared setting, so not changed here)
  4. Optional alerts:    hermes -p {args.profile} cron create "every 2h" --name security-watch --no-agent --script rgtriage-watch.py --deliver local
""")


if __name__ == "__main__":
    main()
