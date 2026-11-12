# Serving RemediGenius through native Hermes interfaces

CE targets Hermes 0.23.1. The native interfaces below keep the existing agent and desk architecture.
No endpoint was enabled or exposed during this review.

## Community workflow recipe

Use the pinned 0.23.1 native HTTP implementation with a dedicated
`remedigenius` gateway/profile, `platform_toolsets.api_server: [skills, clarify, file, rg_triage]`, and
an environment-injected `API_SERVER_KEY`. Set `API_SERVER_ENABLED=true`. Keep the default loopback binding
on a host. In a container, binding to `0.0.0.0` internally requires publishing the port to host **127.0.0.1**
only; use a private tunnel for remote callers. The normal CE install does not publish the API port.

For this pin, a separate named-profile gateway requires `gateway.standalone: true` in that profile and
`GATEWAY_MULTIPLEX_PROFILES=false`; start `hermes -p remedigenius gateway run`. This is Hermes's compatibility
mode for a dedicated gateway, not a CE server. Stop that profile's existing gateway first. Multiplexed
gateways require profile-scoped secrets: a process-level key must not be assumed to authenticate another
profile. That multiplexed setup is not the tested community recipe.

The 0.23.1 Docker image supervises `gateway run` with s6. For an intentionally separate foreground
test gateway inside that container, set `HERMES_GATEWAY_NO_SUPERVISE=1`; otherwise the command delegates
to the container supervisor rather than starting the isolated listener. Leave normal CE container
supervision enabled. Do not run two gateways against the same Hermes home.

Send `Authorization: Bearer <your key>` to `/p/remedigenius/v1/chat/completions` with ordinary OpenAI-format
messages. For workflows that may require approval, `POST /p/remedigenius/v1/runs` with `{"input":"..."}`;
save the returned `run_id` and poll `/p/remedigenius/v1/runs/<run_id>`. When status is `waiting_for_approval`,
show the exact action to the operator and submit their choice to `.../<run_id>/approval` as
`{"choice":"once"}` or `{"choice":"deny"}` (include the request ID when supplied). Never automatically
approve a run merely because an API request was authenticated. Native runs also support `.../<run_id>/stop`.

Treat this API key as full access to this single-operator desk. It is not a public multi-tenant API.
Authentication failure returns 401. Read-only investigations remain separate from human-approved triage
decisions; cloud writes remain prohibited by CE's guarded AWS interface.

## HTTP: the recommended no-custom-code agent interface

The running image contains `gateway/platforms/api_server.py` with `/v1/chat/completions`, `/v1/responses`,
`/v1/runs`, `/v1/models`, `/v1/capabilities`, and run approval/status endpoints. A client sends a question;
the agent uses its profile's skills/tools and returns the answer. This is the appropriate built-in path for
another application to ask RemediGenius to investigate or explain evidence.

Setup uses `API_SERVER_ENABLED=true`, a strong `API_SERVER_KEY` supplied through the secret mechanism,
and the Hermes gateway. The documented default listener is loopback port 8642. Use the `remedigenius`
profile and an explicit restricted `platform_toolsets.api_server` entry; do not assume CLI restrictions
cover another platform. Start behind the existing private tunnel and verify authentication rejection,
profile selection, allowed tools and approval behavior before wider access.

The key permits agent work and access to the installation's data. CE remains single-operator and
single-organization; enabling this API does not provide multi-tenant isolation. The standard CE deployment
does not publish this port. Exposure is a separate decision, not required for this MCP release.

## MCP: conversation bridge, not an automatic CE tool export

Hermes offers the official `mcp-serve` plugin: `hermes plugins install mcp-serve`, then
`hermes -p <profile> mcp-serve`. It serves over stdio. The plugin requires Hermes >=0.22.0;
CE's pinned 0.23.1 meets that prerequisite. Installing it is optional, not part of the CE boot path.

Its documented surface lists/reads conversations, polls events, sends through connected messaging channels
and handles approvals. Optional `--tools` exposes a fixed allowlist of Hermes capabilities. That list does
not contain `rg_triage` or `rg_analytics`; it is not a universal exporter of installed plugin tools, nor an
arbitrary "ask the RemediGenius agent" MCP endpoint.

Use native HTTP for full agent requests without custom code. Use native MCP for its supported bridge/tools.
Direct CE tool export needs an upstream-supported export feature or an adapter; do not promise it merely
because Hermes can act as an MCP server. The CE release validation records which interfaces were exercised.

References:
- [API server](https://hermes-agent.nousresearch.com/docs/user-guide/features/api-server)
- [Official MCP Serve](https://hermes-agent.nousresearch.com/docs/plugins/mcp-serve)
- [Programmatic integration](https://hermes-agent.nousresearch.com/docs/developer-guide/programmatic-integration)
