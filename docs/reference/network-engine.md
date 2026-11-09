# Network engine reference

`nimstead.engine.network.run()` provides a separate remote-check evaluation path. It does not replace the [normal external scanner](external-scans.md), persist findings, or publish a network-report HTTP endpoint. The repository sandbox calls this entry point.

## Entry points

| Function | Inputs and result |
| --- | --- |
| `run(s, asset, lookup=None, budget=None, safe_mode=True)` | SQLAlchemy session, verified external asset, optional DNS TXT lookup, budget, and safety flag. Returns `(verdicts, report, prober)` |
| `Prober(host, ip, budget=None, safe_mode=True)` | Host/SNI string and pinned IP string. Construction performs no ownership validation or I/O |
| `Prober.observe()` | Probes configured ports and returns an integer-port-to-`Endpoint` map |
| `evaluate(prober, endpoints)` | Returns verdicts, with additional web requests and current-clock TLS evaluation |
| `build_report(host, ip, verdicts, endpoints, skipped, host_lost)` | Returns report data without probes or persistence |
| `parity(verdicts, external_ids)` | Compares vulnerable IDs against a set of normal-scanner finding IDs |

`run()` repeats the normal scanner's scope proof before service probes. Proof can commit a refusal event or clear verification. It can raise `external.ScanRefused`. Database, lookup, configuration, and unexpected probe errors can also propagate.

Direct prober/evaluator use bypasses this scope gate. Callers must prove ownership and address eligibility before those interfaces perform network I/O.

## Budget fields

| Field | Default | Meaning |
| --- | --- | --- |
| `per_host` | `8` | Endpoint worker count |
| `per_endpoint` | `1` | Concurrent `_exchange` connections to the same port within a prober |
| `deadline` | `8.0` | Endpoint observation or web-rule time budget, in seconds |
| `connect` | `3.0` | TCP connection operation timeout, in seconds |

The dataclass does not validate these values. Invalid counts or timeouts can fail later in worker, semaphore, or socket operations.

The deadline is not a hard cancellation guarantee. Operations can overrun their budget. `observe()` marks an endpoint timed out after its observation returns. TLS helpers can perform several connections, each with its own timeout. Direct connection/TLS helpers do not acquire the exchange semaphore.

## Observations and checks

Observed ports include all normal service ports, TCP 443 and 80, and banner ports 21, 22, 25, 110, 143, 2121, and 2222.

| `Endpoint` field | Value |
| --- | --- |
| `port` | Integer port |
| `state` | `open`, `closed`, or `filtered` |
| `banner` | Greeting bytes, default empty |
| `tls` | TLS-fact dictionary or `None` |
| `tls_wrapped` | Whether greeting bytes came through TLS |
| `reflects` | Whether the endpoint echoed the nonce control |
| `timed_out` | Whether initial endpoint observation exceeded its budget |

TLS facts contain `trusted`, `error`, `not_after`, and `legacy`. `not_after` is a Unix timestamp or `None`. Trust and legacy values can each be true, false, or `None`.

Normal exposed-port and TLS verdicts reuse the external scanner's decision helpers. A filtered service port becomes not-run with reason `port-filtered`. An observation over budget becomes not-run with reason `timed-out` for exposed-service/TLS checks.

Built-in web rules request `/.git/config` and `/.env` on HTTP port 80. Each requires HTTP 200, its bytes marker, and a body different from the missing-path control. A successful, nonempty missing-path response produces `soft-404` instead. A failed control request does not itself mark the check incomplete.

Other path responses, including an absent response with no parsed status, currently produce not-vulnerable web verdicts. This result alone does not prove the request succeeded. The HTTP reader is a bounded raw exchange, without redirects or general HTTP body decoding.

Version rules inspect greetings for vsftpd (`CVE-2011-2523`), ProFTPD (`CVE-2015-3306`), and OpenSSH (`CVE-2024-6387`). They can match on any greeting port. Distribution-tagged OpenSSH banners produce `backported`. Reflected controls suppress banner identification with reason `catch-all`.

`safe_mode=True` blocks web rules classified as disruptive. Current built-in web rules have the `probe` classification. Remote verdicts have no grade above reasonable. Banner-to-CVE verdicts have an unverified ceiling.

## Report differences

The report uses most fields from the [host scan-report format](scan-report.md), with these differences:

| Field | Network meaning |
| --- | --- |
| `host` | Target hostname |
| `os` | `external target <ip>` display string |
| `agent_version` | `null` |
| `inventory_read_at` | Report-build UTC timestamp, not a saved agent observation time |
| `engine_version` | Network evaluator version, currently `1` |
| `content_version` | `net.` plus 12 SHA-256 hex characters |
| `inventory_sha256` | Hash of `host|ip|content_version`, rather than endpoint observations |
| `verdicts_sha256` | Ordered verdict digest |
| `vulnerable` | One group per vulnerable verdict, sorted by descending CVSS then product |
| `not_vulnerable` | Rows with only `product` and `grade` |
| `not_applicable` | Integer verdict count |
| `undetermined` | Same incomplete-group shape as host reports |
| `coverage` | `sources`, `families`, and `statements`. No application counts |

`kind`, `applications`, and `attack_paths` are absent. Network coverage sources use open/closed/filtered states. Counts are one for open ports and zero otherwise. The family map contains `network`.

The content identifier hashes service port numbers, TLS warning age, web rule IDs, and version-rule CVE IDs. It excludes rule patterns, predicates, descriptions, and full implementation details. It does not identify a complete rule revision.

`host_lost` is true in `run()` when every initial endpoint is filtered. Headline selection prioritizes vulnerable verdicts, then host loss, then incomplete verdicts, then no known exposure. The report retains coverage limitations even when the headline reports no exposure.

## Parity result

`agree` is a sorted list of shared finding IDs. `explained` lists engine-only `NIM-WEB-` and `CVE-` results. `unexplained` lists other differences. `ok` means the unexplained list is empty, so it can be true with explained differences.

Source: [`network.py`](../../api/src/nimstead/engine/network.py).
