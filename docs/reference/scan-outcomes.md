# Scan outcomes

An outcome records what one check concluded. It must be read with its reason, evidence, and collection status.

| Outcome | Meaning |
| --- | --- |
| `vulnerable` | The check found evidence of an affected state |
| `not-vulnerable` | The check had enough evidence to conclude the affected state was absent |
| `not-applicable` | The check does not apply to this inventory |
| `undetermined` | The available evidence cannot support a conclusion |
| `not-run` | The check did not execute |

## Confidence grades

| Grade | Meaning |
| --- | --- |
| `confirmed` | Direct collection and the applicable check support the result |
| `reasonable` | Evidence supports the result with a weaker observation or source |
| `unverified` | Missing collection assurance or indirect evidence limits the result |

A grade can be absent. SBOM-derived component verdicts have an unverified ceiling. An SBOM describes build contents without proof of the deployed runtime.

## Incomplete reasons

| Reason | Operator action |
| --- | --- |
| `no-inventory` | Check the agent and submit an inventory |
| `unsupported-platform` | Check platform mapping and advisory coverage |
| `no-collection-document` | Update the agent to report collection status |
| `precondition-unknown` | Correct the source that the check requires |
| `access-denied` | Correct collection permissions |
| `source-partial` | Correct the incomplete source and repeat the scan |
| `empty-list` | Inspect agent collection output for a failed or implausibly empty source |
| `pending-reboot` | Complete the approved restart and report again |
| `release-line` | Check the vendor advisory for this Windows release line |
| `incomparable`, `unreadable-version` | Compare the observation with the vendor advisory manually |
| `feed-missing`, `no-advisories` | Check advisory feeds and ecosystem coverage |
| `other-stream` | Check the advisory for the installed distribution module stream |
| `end-of-life` | Upgrade to a supported release |
| `eol-unknown` | Refresh lifecycle data and check the distribution lifecycle page |
| `kernel-unpackaged` | Identify and patch the source of the running kernel |
| `no-sbom` | Upload a supported SBOM |
| `policy-excluded` | Review the local opt-in scan policy |
| `sbom-unmapped` | Supply supported package URLs for the omitted components |
| `not-reassessed` | Correct the scan blocker. This scan has no evidence to resolve the prior finding |
| `removed` | None: the product is no longer installed, and the list that would show it was read in full. The finding resolves |
| `withdrawn` | None: no live advisory for the product carries this identity any more (withdrawn, or filed again under another ID). The finding resolves |
| `port-filtered` | Check external firewall behavior. Timeout does not prove a closed port |
| `timed-out` | Repeat the check after the target or time-budget issue is resolved |
| `host-lost` | Restore target reachability and repeat the scan |
| `catch-all` | Identify services from the host. Catch-all responses prevent reliable fingerprinting |
| `soft-404` | Inspect the host directly. A successful response for nonexistent paths prevents reliable path checks |
| `backported` | Read the installed distribution package version instead of an upstream banner |
| `safe-mode` | Review target authorization for disruptive checks |
| `legacy-only` | Enable TLS 1.2 or later on the server. Only TLS 1.0/1.1 answered, so the certificate wasn't read |
| `scanner-limited` | Use a scanner whose TLS library supports the required protocol, or inspect the server configuration |

Confidence describes evidence strength. Severity describes impact. Priority orders work. A high-confidence result can have low operational priority.

See [scan troubleshooting](../how-to/troubleshoot-scans.md) for recovery steps and [detection confidence](../explanation/detection-confidence.md) for interpretation.

See [scan report format](scan-report.md) for grouped fields and headline selection. The engine's `proves_absent` predicate is true for not-vulnerable and not-applicable verdicts. It does not itself change a finding's status.
