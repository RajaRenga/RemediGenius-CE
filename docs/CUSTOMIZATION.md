# Customize your RemediGenius desk

Read the [operator architecture](USER-ARCHITECTURE.md) first. This guide describes the post-v0.9.0
development checkout; use matching code and templates. Keep private configuration out of Git.

## Find the configuration that actually runs

Native mode reads `RGTRIAGE_CONFIG` when set, otherwise `triage.yaml` under `RGTRIAGE_HOME`
(default `~/.rgtriage`). Standard EC2 stores it at `/data/rgconfig/triage.yaml`; the desk cache is
`/data/rgtriage`. Use `sudo rgdesk ...` inside the EC2 SSM session for desk commands. Do not edit a
laptop copy and assume the EC2 runtime reads it. For Docker, use the paths and mounts in
[the workstation guide](WORKSTATION.md).

Before editing, keep a private backup. Make a small change, run `doctor` in the same runtime,
then scan or invoke the affected feature and inspect its result. YAML must retain the installation's
existing storage identity and role wiring. Restart the relevant service when changing its environment
or Hermes configuration. A Terraform change needs a reviewed plan/apply, not just a YAML edit.

## Supported customization points

| Need | Setting / interface | Apply and verify |
| --- | --- | --- |
| Choose accounts | `accounts` entries: `account_id`, `role_arn`, optional `aws_profile`, `external_id`, `regions` | Review IAM with [access onboarding](ACCESS-QUICKSTART.md); rerun onboarding and scan as the actual runtime |
| Restrict discovery | `organization.discover`, `organization.member_role_name` | Set discovery false for an explicit starting scope; inspect authenticated accounts and known-but-unreadable scopes |
| Choose regions | Top-level `regions`; account-level override | Include intended service regions and aggregation home region; verify coverage for each |
| Select sources | `sources` | Rescan and inspect coverage; enabling a source here does not enable the AWS service |
| Bound detail volume | `max_findings_per_source` (500), `max_stored_findings` (20,000), `detail_limits` | Check truncation, total counts and board changes; larger caps raise API/storage/processing cost |
| Explain business priorities | Reviewed Application, Account, Security Goal and Risk Exception concepts in Knowledge | Review/activate concepts, rescan and inspect cited ranking reasons and exception expiry |
| Provide simple fallback context | `applications`, `goals`, account `criticality`, `environment_tag_keys` | Supported criticality values: `mission_critical`, `business_critical`, `non_critical`, `test_development`; verify reasons rather than guessing a score |
| Locate IaC | `iac_paths`; optional configured GitHub mirror | Host/container paths must resolve; ask for a finding's fix location and inspect confidence before editing |
| Connect GitHub | Operator setup in [GitHub guide](GITHUB.md) | Verify repository scope and App permissions; keys remain in the desk, publication requires approval |
| Change model | Hermes provider configuration; EC2 `model_name`, `model_base_url`, `model_secret_arn` | Use the platform's secret mechanism, restart/reconfigure the gateway as required, test a short investigation and review data egress |
| Change AWS scan cadence | Terraform `scan_interval_hours` (1–168, default 6) | Review/apply plan; verify timer and next scan timestamp. YAML does not own this systemd timer |
| Change alerts | Terraform `watch_deliver`, or native Hermes security-watch cron recipe | Configure the delivery channel in Hermes; verify gateway is running and a test notification reaches the intended destination |
| Change investigation transport | `aws_investigation.transport`: `direct` or `managed_mcp` | Native normalization defaults to direct; standard EC2 initializes managed MCP. Test a scoped read; retain the desk guard |
| Historical reports | `athena_analytics.enabled`; deployment-managed role/workgroup/database/runtime | Use fixed reports and review scan statistics; changing a YAML role does not create its permissions |
| Optional usage evidence | `sources` adds `flowlogs` / `trailevents`; `evidence` window, row/byte caps and Athena table configuration | Follow [AWS capabilities](AWS-CAPABILITIES.md); validate log coverage and query costs before expanding scope |
| Bound outage buffering | `storage.buffer_limit_mb` (256) | Size for disk and acceptable uncommitted exposure; inspect storage/outbox health |
| Tune table maintenance | `storage.maintenance`: snapshot retention, minimum snapshots, file size and interval | Read [Storage](STORAGE.md); verify maintenance status and recovery requirements; this is not historical-row retention |
| Change raw retention | Terraform `raw_retention_days` (90; 0 retains) | Review lifecycle plan; expired evidence cannot be retrieved merely because its reference remains |
| Size or park AWS compute | Terraform `spot_instance_types`, `container_memory_mb`, `running` | Review/apply; preserve one writer. `running=false` parks compute without using full-stack destroy |
| Integrate a workflow | Restricted native Hermes HTTP profile and secret-injected API key | Follow [API recipe](HERMES-API-OPTIONS.md); test unauthorized rejection, tool scope and human approval |

Default `detail_limits` are CRITICAL 1,000, HIGH 1,000, MEDIUM 300, LOW 100 and INFORMATIONAL 0.
These are retrieval bounds, not a guarantee that every service uses an identical pagination method.
Coverage remains the way to interpret an incomplete result.

## Which configuration survives a replacement?

EC2 checkpoints the configuration home along with other durable homes. On first boot, `host.py`
initializes storage, the local reader and configured members from deployment settings. With a restored
profile, its merge adds newly listed member accounts; it does not rewrite existing account entries or
other profile fields. Changing a Terraform region or an existing reader therefore does not by itself
guarantee the restored `triage.yaml` will change. Review the effective profile and deliberately reconcile
those settings. Analytics role/workgroup/database/runtime values are refreshed from deployment settings;
explicit investigation transport and analytics enablement choices are preserved by default initialization.

Keep infrastructure changes in the owning Terraform configuration and align the effective profile with
the resulting resources. Keep business context in reviewed knowledge or the supported profile fields.
After a replacement, verify both the effective profile and the latest scan; do not assume that applying
Terraform rewrites every operator setting or that every manually edited field survives bootstrap.
See [upgrading](UPGRADING.md) for migration and backup requirements.

## Changes that require engineering and release validation

Adding an AWS source, allowing new tool commands, changing IAM boundaries, exposing new network
listeners, changing table schemas, enabling multiple writers, altering scoring algorithms or upgrading
pinned dependencies is not routine end-user configuration. Those changes need implementation review
and appropriate runtime validation. User-editable skills and prompts cannot grant missing AWS access
and must not bypass the desk's read guard or human approval gates.

Do not hand-edit Iceberg objects, copy only SQLite as a backup, embed keys in YAML/tfvars, or reuse one
installation for unrelated customers. Use a separate installation per organization and retain the
single-writer contract. Customization should preserve the ability to explain which identity read which
scope, when it was observed, and whether the result is durably committed.
