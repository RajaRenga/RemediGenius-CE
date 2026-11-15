# rg-triage

The Hermes plugin half of [RemediGenius Community Edition](https://github.com/RajaRenga/RemediGenius-CE):
a read-only AWS security triage desk. It gives the agent one structured tool over the `rgtriage`
engine, shows the attention board at session start, and adds `/triage` and `/rate`.

This plugin is one piece of the desk. The full installation — profile, skills, dashboard tabs and
the engine — is described in the [repository README](https://github.com/RajaRenga/RemediGenius-CE#readme).
Installing this plugin alone adds the tools to an existing Hermes; it expects the
`remedigenius-community` package (pinned in `plugin.yaml`) to be importable.

## What it registers

- Tools: `rg_triage` (scan, list, show, card, rate, doctor, onboarding, knowledge — all read-only)
  and `rg_analytics` (read the desk's own redacted traces).
- Slash commands: `/triage`, `/rate`.
- Hooks: board summary before the first model call, redaction of traces, answer formatting.

## What this changes in your Hermes profile

Wherever this plugin is enabled, it changes how the agent behaves:

- **Approvals.** `decide`, `remember`, `github publish` and `validate` go through Hermes's approval
  prompt before they run. The `validate` prompt names the module and the providers `terraform init`
  may install (only ones already in the module's `.terraform.lock.hcl`).
- **Write guard.** `write_file` and `patch` are blocked everywhere except the desk's proposals folder.
  The agent drafts changes; it never edits your repositories directly.
- **Streaming.** The plugin holds streaming for every reply (`hold_stream`): critical reports are
  rendered from desk evidence and redacted before you see them, not streamed token by token.
- **Local traces, on by default.** Every turn (messages and tool results, redacted) is written to a
  local trace under `rg-traces` in the state home (see below), kept 30 days, read by `rgtriage improve`
  and the analytics tab. Nothing is sent anywhere. Set `RGTRIAGE_TRACES=off` to disable it entirely.
- **Read guard.** Credential stores (`~/.aws`, `~/.ssh`, keys, `.env`, Terraform state) and whole-home
  or drive-root searches are blocked.

## What it does on your machine

- Runs `python -m rgtriage …` as a subprocess, or talks to a running desk over a local socket.
  The engine reads AWS through the credentials you configure (a read-only role is the documented
  setup) and never writes to AWS. Every fix is a proposal a person reviews.
- Reads and writes its own state in a per-profile home (`rgtriage` under your Hermes home), so two
  Hermes profiles never share one desk. Installs that already have state under `~/.rgtriage` keep
  using it until you move it; `RGTRIAGE_HOME` or the installer's `local.json` override both. A
  proposals folder for drafted IaC changes lives beside the state.
- Validation (`validate`, and the check before `github publish`) runs `terraform init/validate/fmt`,
  tflint and cfn-lint on a scratch copy — never plan or apply. Model-written proposals cannot add or
  change `terraform {}` / `required_providers` blocks or `.terraform.lock.hcl`; `init` installs only
  providers already in the module's lock file, or from an operator-vetted `RGTRIAGE_TF_PLUGIN_DIR`
  (no registry access in that mode). The tools run with an allowlisted environment, so model and
  cloud keys never reach them or the providers they load.
- Optional environment overrides: `RGTRIAGE_PYTHON`, `RGTRIAGE_SRC`, `RGTRIAGE_HOME`,
  `RGTRIAGE_SOCKET`, `RGTRIAGE_PROPOSALS`, `RGTRIAGE_STALE_HOURS`, `RGTRIAGE_TRACES`,
  `RGTRIAGE_TRACES_DIR`, `RGTRIAGE_TF_PLUGIN_DIR`. None are required.
- The plugin holds no AWS or model credentials. The model key belongs to your Hermes profile;
  findings and chat go to the model provider you configure.
- No telemetry, no network calls of its own, no self-update.

## Limits

- No detectors of its own: it works with what Security Hub, GuardDuty, Inspector and your other
  AWS services already report.
- AWS only, and early software: see [docs/LIMITS.md](https://github.com/RajaRenga/RemediGenius-CE/blob/main/docs/LIMITS.md).

Apache-2.0.
