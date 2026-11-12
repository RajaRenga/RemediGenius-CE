# Operator architecture diagrams

Open [the diagram index](index.html), or read the [operator reference](../../USER-ARCHITECTURE.md)
and [customization guide](../../CUSTOMIZATION.md). Download this folder to use the standalone HTML
viewers; GitHub displays their source instead of executing them.

| Question | Diagram | Editable source |
| --- | --- | --- |
| What runs where, and who owns it? | [Infrastructure](infrastructure.html) | [JSON](infrastructure.json) |
| What is collected, committed and retained? | [Data lifecycle](data-lifecycle.html) | [JSON](data-lifecycle.json) |
| Who reads, approves and records a decision? | [Control flow](control-flow.html) | [JSON](control-flow.json) |
| How do accounts and security administrators connect? | [Account access](account-access.html) | [JSON](account-access.json) |
| Where do the instance profile and reader roles live? | [Permission map](permission-map.html) | [JSON](permission-map.json) |
| How does the desk assume a reader and return evidence? | [Read control flow](read-control-flow.html) | [JSON](read-control-flow.json) |

These are logical architecture maps, not measured timelines or physical subnet drawings. Infrastructure
shows the standard AWS deployment; the guide explains native Hermes and Docker differences. Account
access includes post-v0.9.0 development work, not a claim about the published v0.9.0 archive.

Diagram tooling: Archify 3.2.0. Source references pin commit
`dcc2abd7c69e3ab47acc27db58d24476bf04da54` for the original four diagrams; the two permission diagrams pin
`98fb040ea582c9a56cd9fb0373c6bc5e75a87a2e`. `local-only` source links preserve repository-relative evidence
without promising that an unpublished branch commit is reachable on GitHub. The HTML embeds viewer
assets and does not need the CE runtime or AWS credentials.

## Maintain the diagrams

1. Inspect the changed implementation. Update node/edge meaning and exact source ranges in the JSON.
2. Pin `meta.repository.revision` to the committed implementation being documented. Do not cite dirty
   source bytes as though they belonged to that revision.
3. From the repository root, run your Archify checkout's `bin/archify.mjs` with this pattern:

   ```sh
   node <archify-package>/bin/archify.mjs finalize architecture docs/diagrams/user-reference/infrastructure.json docs/diagrams/user-reference/infrastructure.html --repo-root . --quality showcase --out-dir .rgce/user-docs-review/new-review --json
   ```

   Use `dataflow` for data-lifecycle, `sequence` for control-flow and `architecture` for account-access.
   Give subsequent browser reviews a fresh private output directory.
4. Resolve validation errors; inspect layout recommendations. Verify guide links and release labels.
5. Keep machine-specific delivery/browser receipts private under `.rgce/`; publish the JSON, HTML
   and guides. Before publication, scan generated files for private paths, identifiers and credentials.

Regeneration changes diagram bytes even if the application is unchanged. Do not rebuild existing
release artifacts or claim a new runtime validation just because these documentation checks pass.
