# Useful MCP capabilities for RemediGenius CE

This is unreleased work validated on the current disposable Spot lab. The purpose is to complete a remediation
or knowledge task, not accumulate connections. Existing Hermes MCP discovery, catalog, configuration, tool
selection and authentication remain the integration layer. `rg-capabilities` supplies RemediGenius-specific
routing; `rg-iac-fix`, `rg-onboard` and `SOUL.md` point to it.

## What an individual user gets

The account connection reevaluation is in [AWS connections](AWS-CONNECTIONS.md). Managed AWS MCP is now a
standard bounded desk transport on EC2, not a general-purpose script tool in Hermes. This supersedes the initial
catalog-only assessment below; public Knowledge, Terraform and DeepWiki remain separate native connections.

| Need | Reused capability | Result for the user | Setup |
| --- | --- | --- | --- |
| Understand an AWS finding/control | AWS Knowledge MCP | Current AWS explanation and exact API verification fields with source citations | Native Hermes catalog, no account |
| Propose correct Terraform | HashiCorp official Terraform MCP | Resource arguments for the repository's provider version | Public Registry runtime, no HCP account |
| Use AWS specialist guidance | AWS Knowledge `aws___retrieve_skill` | Relevant AWS-authored skill and references loaded on demand | Enable this read tool explicitly; pinned Hermes excludes it by default |
| Understand Prowler/public code | Existing DeepWiki MCP | Repository navigation and explanation; verify exact code against upstream revision | Native Hermes catalog, no account for public repositories |
| Bring organization knowledge | Existing vendor document MCPs | Selected documents become cited References and unreviewed OKF concepts | Provider sign-in and chosen document scope |

For example, a Terraform question selects Registry search/details, preserves the requested provider version,
then uses AWS documentation for the verification API. A real finding fix continues through the desk's existing
proposal, validation and proof-of-done workflow. An IAM conceptual question can discover `aws-iam`, retrieve it
and its relevant reference, and explain the policy condition without reading any AWS account.

## Dynamic onboarding and use

1. The skill identifies the missing capability and the question it would answer.
2. In **Knowledge → Sources → Manage connections in Hermes**, add the existing vendor/catalog entry to profile
   `remedigenius`. Select the needed read tools and complete provider sign-in there.
3. **Test connection** uses Hermes's native MCP probe. Its tool count proves a handshake, not useful retrieval.
4. Start a fresh chat (or use Hermes's supported MCP reload), ask the representative question shown in Sources,
   and verify the actual tool result, citation and outcome.

The agent uses deferred tool discovery for available connections and retrieves AWS vendor skills on demand.
It does not silently install arbitrary executables or grant itself AWS access. Configuration changes do not
guarantee an existing chat has reloaded its tools. Existing authenticated document providers remain subject to
their own access checks; a disabled/catalog-only entry is not certified.

### AWS Knowledge and on-demand AWS skills

Use the existing Hermes `aws-knowledge` catalog entry. CLI equivalents:

```sh
hermes -p remedigenius mcp install aws-knowledge
hermes -p remedigenius mcp configure aws-knowledge
hermes -p remedigenius mcp test aws-knowledge
```

The selected tools used in this lab are `aws___read_documentation`, `aws___search_documentation`,
`aws___list_regions`, `aws___get_regional_availability` and `aws___retrieve_skill`. Skill retrieval was explicitly
enabled for this evaluation. Search results supply the exact skill name; the agent retrieves only the relevant
skill and linked reference. No broad AWS skill package is copied into the product. Vendor operational procedures
do not grant terminal access, AWS writes or approval authority.

### Optional Terraform runtime on the standard AWS host

Run the reviewed installer on the **CE host**, from the release/source tree:

```sh
sudo bash deploy/aws-single/install-terraform-guidance.sh
```

It extracts HashiCorp's official v1.4.1 binary from a digest-pinned image, installs it in the persistent Hermes
data directory and uses Hermes's existing configuration helper to register `terraform-registry`. Linux x86_64
and the standard `/data/hermes` → `/opt/data` container mount are required. A different existing connection is
preserved and reported for review. An identical connection keeps its enabled/disabled state.

The MCP runs over stdio with a clean environment and a nonexistent home directory, with no AWS/HCP/model
credentials. Both server startup and Hermes tool selection limit it to seven public Registry reads:
`search_provider_docs`, `get_provider_details`, `get_provider_capabilities`, `get_latest_provider_version`,
`search_modules`, `get_module_details`, `get_latest_module_version`.

HCP workspace/run mutation tools are not exposed. Local Terraform validation stays in `rg_triage`, which already
validates a scratch copy without applying. This is an upstream MCP installation, not extracted/reimplemented
Registry API code. AWS's old Terraform MCP is deprecated in favor of HashiCorp's official implementation.

The installer is included in the candidate archive and remains an explicit onboarding choice. After the
shipped connection is enabled, bootstrap restores its runtime after replacement because `installs/` is
excluded from checkpoints. Disabled and custom connections are preserved.

## Validation limits

Managed account reads and bounded Athena reports have deployment checks (see the
[release validation](https://github.com/RajaRenga/RemediGenius-CE/releases/download/v0.9.1/VALIDATION.md)).
Public documentation retrieval does not certify authenticated document providers. Each provider requires its own
sign-in, selected-content retrieval and provenance checks. Tool availability is not evidence of complete account
coverage. Long-duration credential expiry, large-result pagination and forced scan-cap exhaustion remain unverified.

## Upstream sources reviewed

- [AWS MCP catalog](https://awslabs.github.io/mcp/)
- [AWS Terraform MCP migration](https://github.com/awslabs/mcp/blob/main/docs/migration-terraform.md)
- [HashiCorp MCP reference](https://developer.hashicorp.com/terraform/mcp-server/reference)
- [HashiCorp v1.4.1 tool definitions](https://github.com/hashicorp/terraform-mcp-server/blob/v1.4.1/pkg/toolsets/registry.go)
- [AWS skill discovery](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/skills.html)
- [AWS Agent Toolkit skills](https://github.com/aws/agent-toolkit-for-aws/tree/main/skills)
- [HashiCorp skill catalog](https://github.com/hashicorp/agent-skills/blob/main/SKILLS.md)
- [HashiCorp Terraform style skill](https://github.com/hashicorp/agent-skills/blob/main/plugins/terraform/skills/terraform-style-guide/SKILL.md)
