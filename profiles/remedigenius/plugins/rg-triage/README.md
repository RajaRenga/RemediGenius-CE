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

## What it does on your machine

- Runs `python -m rgtriage …` as a subprocess, or talks to a running desk over a local socket.
  The engine reads AWS through the credentials you configure (a read-only role is the documented
  setup) and never writes to AWS. Every fix is a proposal a person reviews.
- Reads and writes its own state under `~/.rgtriage` (or `RGTRIAGE_HOME`), plus a proposals folder
  for drafted IaC changes.
- Optional environment overrides: `RGTRIAGE_PYTHON`, `RGTRIAGE_SRC`, `RGTRIAGE_HOME`,
  `RGTRIAGE_SOCKET`, `RGTRIAGE_PROPOSALS`, `RGTRIAGE_STALE_HOURS`. None are required.
- The plugin holds no AWS or model credentials. The model key belongs to your Hermes profile;
  findings and chat go to the model provider you configure.
- No telemetry, no network calls of its own, no self-update.

## Limits

- No detectors of its own: it works with what Security Hub, GuardDuty, Inspector and your other
  AWS services already report.
- AWS only, and early software: see [docs/LIMITS.md](https://github.com/RajaRenga/RemediGenius-CE/blob/main/docs/LIMITS.md).

Apache-2.0.
