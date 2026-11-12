"""Seed the synthetic tutorial into a NEW external local desk home; never calls AWS."""
import argparse
import json
import os
import sys
from pathlib import Path

import yaml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    args = parser.parse_args()
    home = args.home.expanduser().resolve()
    checkout = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(checkout))
    if home == checkout or checkout in home.parents:
        parser.error("Choose a private demo home outside the repository checkout.")
    if home.exists():
        parser.error("Demo home already exists; choose a new directory. Existing data is never replaced.")
    scan = json.loads(Path(__file__).with_name("scan.json").read_text(encoding="utf-8"))
    os.environ["RGTRIAGE_HOME"] = str(home)
    os.environ["RGTRIAGE_CONFIG"] = str(home / "triage.yaml")
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    from rgtriage import cli, config, repository

    home.mkdir(parents=True)
    profile = config.normalize({"name": scan["profile"]["name"], "accounts": [],
                                "regions": ["us-east-1", "eu-central-1"],
                                "organization": {"discover": False},
                                "storage": {"profile": "local", "namespace": "coverage_demo"}})
    (home / "triage.yaml").write_text(yaml.safe_dump(profile), encoding="utf-8")
    repo = repository.Repository.open(profile)
    try:
        result = repo.save_scan(scan)
        if not result.get("durable"):
            raise RuntimeError("Synthetic snapshot was not durably committed")
        cli.write_outputs(scan)
    finally:
        repo.close()
    print("Seeded SYNTHETIC coverage demo. No AWS observations; do not scan this demo profile.")


if __name__ == "__main__":
    main()
