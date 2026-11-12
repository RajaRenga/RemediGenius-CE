# Add RemediGenius Community Edition to an existing Hermes

Add a dedicated `remedigenius` profile and reuse your working model configuration. This release targets
**Hermes 0.23.1**. The installer checks that version before changing profiles. For other versions, keep
your existing Hermes and use the [pinned Docker workstation](WORKSTATION.md). A version match is not
clean-install certification; see the validation results and limits.

Start from the matching CE source release or checkout; the wheel alone does not include this installer.
Use a separate Python 3.11–3.13 environment for the desk (Hermes may use its own newer Python), and an AWS CLI
profile with read-only access to the intended account. PyArrow 23.0.1 and PyIceberg 0.12.0 stay pinned. For SSO, first run
`aws sso login --profile YOUR_PROFILE`. Prefer a profile that assumes a dedicated read role.

```sh
python -m pip install -e .
python tools/install_local_hermes.py --check
python tools/install_local_hermes.py --clone-from default --aws-profile YOUR_PROFILE --region us-east-1
python -m rgtriage --durable doctor
python -m rgtriage --durable scan
hermes -p remedigenius chat
```

Hermes 0.23.1 executes chat turns in the profile's gateway. Restart that gateway after updating CE's
plugins or connection settings; changing an environment variable only in a new chat client does not
reconfigure an already running gateway. For isolated testing, use a separate Hermes home and its own
gateway. Do not point a second gateway at the same home.

`--check` checks the Hermes version and desk dependencies without installing or calling AWS. It does
not test model access or runtime behavior. Installation initializes `~/.rgtriage/triage.yaml` from your
AWS identity. Before scanning, inspect that file to confirm account, regions and organization scope;
set `organization.discover: false` to begin with only the configured account. The installer does not
create roles or enable paid AWS security services. `doctor` and `scan` make AWS reads; neither needs a model.

With `--rgtriage-home`, set `RGTRIAGE_HOME` to that folder for every CLI command (PowerShell:
`$env:RGTRIAGE_HOME = 'C:/path/to/desk'`; shell: `export RGTRIAGE_HOME=/path/to/desk`).

A successful first board shows scan time, source coverage and ranked issues. Missing, denied and capped
sources are gaps; an empty board is not proof of security. Ask why one issue matters, then investigate it.
IaC repositories, knowledge, GitHub and schedules can be added after this first result.

`--clone-from` uses Hermes's profile cloning behavior to reuse a working provider setup. The installer
adds SOUL, skills, plugin and tool restrictions, keeping a timestamped backup of `config.yaml`. It also
installs and enables a **shared** Knowledge dashboard plugin in the Hermes root. Reinstall replaces CE
skills and plugin files; existing managed files and the shared Knowledge plugin are copied to
`<profile>/remedigenius-backups/<timestamp>/` before replacement. Failed knowledge or AWS initialization
exits unsuccessfully; some profile files
may already exist. Correct the login/dependency issue and rerun. Installation does not run a scan.

## Differences from the containerized paths

- The desk runs as a subprocess using the local credential environment. The desk read guard restricts
  AWS calls, but **this path does not isolate AWS credentials from Hermes**. For separate credential
  boundaries use the [Docker workstation](WORKSTATION.md).
- The default desk home is `~/.rgtriage`. Raw evidence and Iceberg facts use the local storage profile;
  SQLite is a rebuildable cache. Back up the whole home and Hermes profile, not only SQLite. The old
  `durable checkpoint --home desk=...` recipe is not a substitute for fact storage. See [STORAGE.md](STORAGE.md)
  and [RECOVERY.md](RECOVERY.md) for S3/Glue and recovery. Writes to CE's own evidence storage are separate
  from read-only investigation of assessed AWS resources.
- Optional alerts: `hermes -p remedigenius cron create "every 2h" --name security-watch --no-agent --script rgtriage-watch.py --deliver local`.
  Hermes cron runs only while a Hermes gateway is running for that profile.

## Update, rollback and uninstall

Stop the profile gateway and scheduled collection before updating. Back up the desk home and the profile,
check out the next supported CE release, reinstall its dependencies and rerun the same installer command.
Existing `triage.yaml`, model configuration and durable facts are retained. Inspect the backup path printed
by the installer before resuming. Installation is recoverable by rerunning; it is not an atomic transaction.

To roll back an unsuccessful profile update, stop its gateway, restore the managed files from the printed
backup and reinstall the previous CE package. Do not roll back durable tables by restoring an old SQLite cache.

To uninstall, remove this profile's security-watch job and stop its gateway, then run
`hermes profile delete remedigenius` and confirm the named profile. Keep a profile backup outside that folder
first if conversations matter. The separate desk home is retained. Disable the shared `rg-knowledge` plugin
at the default scope only if no other CE profile uses it; restore its previous copy from the backup if replacing
an older installation. Remove the CE package from its dedicated Python environment when no profile uses it.

For workflow callers, see [native API options](HERMES-API-OPTIONS.md). The installer does not enable a listener.
