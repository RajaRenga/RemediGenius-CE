# Fresh installation or recovery

CE does not require a particular account count, region list or organization layout. Configure a starting
read identity and the allowed regions; account-level region lists override the default. Organization and
service membership discovery identify additional readable accounts and findings-only routes. Standalone
accounts work without Organizations. Discovery failures and regions outside collection remain visible gaps.
See [access quickstart](ACCESS-QUICKSTART.md) and [multi-account setup](MULTI-ACCOUNT.md).

An empty installation has no CE history, decisions, conversation or organization knowledge. Its first scan
still reads AWS's existing findings and their original observation times. Reinstalling CE does not reset
GuardDuty, Security Hub or CloudTrail. Repeated AWS findings after a fresh start are not evidence of a bad cache.

Replacing compute against the same S3/Glue installation restores committed data. That is intentional recovery,
not a fresh installation. A healthy restored snapshot does not guarantee correct model interpretation; compare
claims against deterministic coverage and the evidence cited by the response.

For an independent trial, deploy a separately named installation using the matching release's deployment
instructions and isolated storage/catalog resources. Reuse approved read roles only where their trust permits
the new runtime. Keep the existing installation parked while testing. Do not point two active writers at the
same installation, or delete warehouse files to force a first-run state.

If retiring an installation, first stop writers and retain its deployment configuration, catalog metadata,
Iceberg metadata/data, raw evidence, exports and required checkpoints according to your retention needs.
Copying only readable exports is not a complete recoverable archive. Review checkpoint contents for credentials
and private conversations. Delete resources only through an explicitly reviewed retirement operation; bucket
versioning and retained versions can continue to incur charges. See [storage](STORAGE.md) and [recovery](RECOVERY.md).

For a bounded first-run diagnostic, a disposable local Iceberg store can isolate CE history while using the
same runtime read identity. This tests fresh collection and interpretation, not new S3/Glue provisioning.
