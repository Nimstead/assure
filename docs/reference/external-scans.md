# External scan reference

The normal external scanner checks exposed TCP ports and TLS on a verified target. The separate network engine adds web-path and banner checks. The external-target UI and scheduled scans use the normal scanner.

## Target operations

All three operations require an organisation admin browser session. Read-only API tokens cannot use these POST endpoints.

| Operation | Input | Successful result |
| --- | --- | --- |
| `POST /api/targets` | JSON `hostname`, 4–253 characters. Optional `criticality`: `low`, `medium`, `high`, or `critical`, default `medium` | `201` with an asset record and ownership-proof fields |
| `POST /api/targets/{target_id}/verify` | Owned external target ID, no body | `200` with the asset record and `verified=true` |
| `POST /api/targets/{target_id}/scan` | Owned external target ID, no body | `200` with `address`, `open`, `resolved`, and `skipped` |

Creation trims whitespace, converts the hostname to lowercase, and removes trailing dots. The accepted name has DNS labels and an alphabetic top-level label. URLs, IP literals, wildcard names, and single-label names are refused.

| Status | Operation-specific condition |
| --- | --- |
| `404` | Target is unavailable to the caller or is not an external asset |
| `403` | The organisation asset quota refuses creation |
| `409` | Duplicate target at creation, or failed verification/scope proof |
| `422` | Invalid hostname or request fields |
| `429` | Manual scans exceed 10 per organisation per hour |

Authentication, origin, two-step sign-in, database, and configured key-backend failures also apply. The scan uses the server's network vantage point. It does not use the operator's browser connection.

## Ownership proof and address selection

The asset response includes `txt_name`, `txt_value`, and `proof_path` for external targets. `verified` reports whether `verified_at` is set.

| Proof | Required response |
| --- | --- |
| DNS name | `_nimstead-verify.<hostname>` TXT contains the organisation/hostname-bound `nimstead-verify=…` value |
| Selected address | `/.well-known/nimstead-verify.txt` returns HTTP `200` with that value within the first 4096 body bytes |

Address proof tries HTTPS on 443, then HTTP on 80. It sends the hostname in Host/SNI and connects to the selected IP. It does not follow redirects or require certificate trust for this proof. Its timeout defaults to five seconds per socket operation, rather than five seconds for the entire proof.

Every resolved address must pass the public-address guard. The explicit development setting `NIMSTEAD_ALLOW_PRIVATE_TARGETS=1` bypasses the non-public-address refusal. Keep that setting disabled in production.

The first returned address is selected and pinned. A scan does not check every address of a name with multiple addresses. Service checks do not begin until DNS and address proof pass. DNS and HTTP(S) proof requests occur during this gate.

The normal scanner repeats proof before every scan. Missing DNS proof clears verification and records an unverified event. Missing address proof records a refusal but keeps the verification timestamp. Both paths can commit the caller's database session. Refused scans return `409` without service checks.

Verified external targets are also scanned during scheduled feed runs. An hourly schedule is configured by the standard deployment. Manual rate limits do not replace that schedule.

## Normal scanner coverage

The service label comes from the configured port. It is not a product fingerprint or an authentication test.

| TCP port | Label | Finding suffix | Configured impact |
| --- | --- | --- | --- |
| 21 | FTP | `FTP` | 7.5 |
| 23 | Telnet | `TELNET` | 9.0 |
| 445 | SMB | `SMB` | 9.0 |
| 1433 | SQL Server | `MSSQL` | 7.5 |
| 2375 | Unencrypted Docker API | `DOCKER` | 10.0 |
| 3306 | MySQL | `MYSQL` | 7.5 |
| 3389 | Remote Desktop | `RDP` | 8.1 |
| 5432 | PostgreSQL | `POSTGRES` | 7.5 |
| 5900 | VNC | `VNC` | 8.8 |
| 6379 | Redis | `REDIS` | 9.8 |
| 9200 | Elasticsearch | `ELASTICSEARCH` | 9.1 |
| 11211 | Memcached | `MEMCACHED` | 7.5 |
| 27017 | MongoDB | `MONGODB` | 9.1 |

Each successful connection produces `NIM-EXPOSED-<suffix>`. Service connections use up to eight workers and a default three-second connection timeout. Refusal, reset, timeout, and other socket failures produce no service finding in the normal scanner.

TLS checks run only on TCP 443 after a successful connection:

| Finding ID | Condition | Configured impact |
| --- | --- | --- |
| `NIM-TLS-EXPIRED` | Certificate expiry is before the current UTC time | 7.5 |
| `NIM-TLS-EXPIRING` | Certificate expires in fewer than 14 days | 4.0 |
| `NIM-TLS-NAME` | Certificate verification error mentions a hostname mismatch | 6.5 |
| `NIM-TLS-UNTRUSTED` | Other certificate trust failure | 5.9 |
| `NIM-TLS-LEGACY` | A TLS 1.0/1.1 handshake succeeds | 5.3 |

An expired certificate suppresses the separate name/untrusted finding. An untestable legacy protocol adds a `skipped` description when TLS trust facts exist. A failed TLS handshake can produce neither a TLS finding nor a skipped description.

TLS socket operations default to five-second timeouts. Several connections can each use that limit. The normal scanner has no overall wall-clock deadline.

The normal scanner performs no UDP checks, logins, exploits, web-path checks, or banner-to-CVE comparisons.

## Priority inputs

The generic scorer uses the configured impact, asset criticality, internet-facing true, fix-available true, KEV false, and no EPSS. Its alternative likelihood is 1.0 for Redis, Elasticsearch, MongoDB, Memcached, and Docker findings. Other exposed-service findings use 0.8. TLS findings use 0.3.

These likelihoods are configured scoring inputs. They are not measured probabilities for the scanned service. See the [priority score reference](risk-score.md) for the calculation.

## Scan counters and finding updates

| Field | Meaning |
| --- | --- |
| `address` | Selected IP string |
| `open` | Number of unique issue IDs returned by the checks, including observed findings whose status remains accepted |
| `resolved` | Number of previously open or accepted findings newly changed to resolved |
| `skipped` | Strings for reported scanner limitations, principally untestable legacy TLS |

Observed resolved findings reopen. Observed accepted findings remain accepted. A previously open or accepted finding resolves when its ID is absent from the check result. The exception is a check the scan skipped: an open legacy-TLS finding stays as it was while legacy TLS couldn't be tested, since an untested check isn't evidence of a fix.

This absence rule also applies when a port is filtered or a TLS check returns no usable facts. A resolved finding therefore does not prove that the service closed or the certificate was repaired. `skipped` is not a complete list of every failed connection or missing observation.

Successful scans update `last_seen`, append finding/scan ledger events, and commit the session. Criticality changes rescore open findings without a network scan. Accepted and resolved findings are excluded from that rescore.

## Related

- [Scan an external target](../how-to/scan-external-target.md)
- [Network engine reference](network-engine.md)
- [Priority score](risk-score.md)
- Source: [`external.py`](../../api/src/nimstead/external.py) and target handlers in [`app.py`](../../api/src/nimstead/app.py)
