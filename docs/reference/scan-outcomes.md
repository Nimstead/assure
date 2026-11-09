# Scan outcomes

An outcome records what one check concluded. It must be read with its reason, evidence, and collection status.

| Outcome | Meaning |
| --- | --- |
| `vulnerable` | The check found evidence of an affected state |
| `not-vulnerable` | The check had enough evidence to conclude the affected state was absent |
| `not-applicable` | The check does not apply to this inventory |
| `undetermined` | The available evidence cannot support a conclusion |
| `not-run` | The check did not execute |

## Common incomplete reasons

| Reason | Operator action |
| --- | --- |
| `feed-missing`, `no-advisories` | Check advisory feeds and ecosystem coverage |
| `access-denied`, `source-partial` | Check collection permissions and source errors |
| `policy-excluded` | Review local collection policy |
| `pending-reboot` | Complete the approved restart and report again |

Confidence describes evidence strength. Severity describes impact. Priority orders work. A high-confidence result can have low operational priority.

See [scan troubleshooting](../how-to/troubleshoot-scans.md) for recovery steps and [detection confidence](../explanation/detection-confidence.md) for interpretation.
