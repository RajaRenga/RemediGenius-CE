# Synthetic coverage demo

This fixture has **no AWS observations, account IDs or customer findings**. Cedar, Maple and Birch
are fictional names. Its timestamp is fixed; it must not be described as current AWS evidence.

| Source | ok | not_enabled | denied | not_available | partial | error | Total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| guardduty | 2 | 2 | 1 | 0 | 0 | 1 | 6 |
| health | 0 | 0 | 0 | 3 | 0 | 0 | 3 |
| securityhub | 1 | 3 | 1 | 0 | 1 | 0 | 6 |

The total is 15 source records over six account/region pairs: 3 ok, 5 disabled, 2 denied,
3 unavailable, 1 partial and 1 error. Cedar/eu-central-1 is denied for both security services.
Maple/us-east-1 Security Hub is truncated; Birch/eu-central-1 GuardDuty failed. Health has only
three recorded regions, not six. Empty findings do not establish safety or delegation.

## Reproduce locally

Install the CE Python dependencies as described in [Local Hermes](../../docs/LOCAL-HERMES.md).
Choose a **new directory outside this checkout**, then run from the repository root:

```powershell
python examples/coverage-demo/seed.py --home C:/private-demos/coverage-demo
$env:RGTRIAGE_HOME = 'C:/private-demos/coverage-demo'
python -m rgtriage --durable digest --coverage
```

The seeder refuses an existing directory and always selects local storage. It does not discover
accounts or collect AWS data. For a real Hermes interaction, install a separate demo profile using
the local installer and point its `--rgtriage-home` at that directory; use your configured model.
Keep schedules disabled, never ask this demonstration to scan, and never attach production credentials
or histories to a public capture. The containerized route provides credential separation; local
Hermes runs in your user environment.

Ask: "This is the synthetic coverage demo. Using stored coverage only, explain the gaps and whether
zero findings means safe. Do not rescan or call AWS." Compare the response with the table above.
Use `/triage coverage` for the exact deterministic report without a model rewrite.

See the [actual dashboard screenshots](../../docs/TUTORIAL.md). A model response to this fixture is
a demonstration of interpretation, not live AWS validation.
