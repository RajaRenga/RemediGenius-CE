# Knowledge source onboarding

CE uses Hermes connections to retrieve selected material, and its knowledge workflow to retain References, draft
concepts and require human review. A configured connector is not proof of successful authentication, content retrieval
or reliable answers. See [knowledge management](KNOWLEDGE.md) and [MCP capabilities](MCP-CAPABILITIES.md).

## Bring a source into the desk

1. Connect the provider through Hermes connection management, with access limited to the intended material.
2. Verify a representative document read. Public AWS documentation describes service behavior, not account state.
3. Import selected content through the Knowledge workflow. Retain its canonical source URI and revision where
   available. Source URI fields preserve provenance; they do not fetch the URL.
4. Review References and generated concepts before approval. Imported content and model drafts are unverified.
   Review Team concepts before Applications that refer to those Teams; ambiguous ownership requires review.
5. Confirm approved knowledge is included in your durable knowledge checkpoint before replacing compute.

## Supported boundaries

- Document imports and source/revision metadata support traceability and repeated-import deduplication.
- A changed revision requires review; a source link does not make imported content trusted policy.
- Search is lexical. There is no automatic provider synchronization, revocation propagation or dependent-concept
  invalidation. Reassess approved material when its upstream source changes.
- Authenticated document providers require provider-specific sign-in, scoped access and representative reads.
  Public documentation-tool testing does not certify every connector in the Hermes catalog.
- AWS audit credentials are not general document-ingestion credentials. Keep document access separately scoped.
- Third-party finding ingestion and model explanations do not certify complete AWS remediation coverage.

See [Limits](LIMITS.md) for what is and isn't covered.