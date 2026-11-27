# Finding API and state reference

Stored findings and engine verdicts serve different purposes. Finding APIs expose persistent workflow state. The [scan report](scan-report.md) separately describes what the evaluator could establish from its inputs.

## Read operations and filters

GET operations accept a user session or an eligible read-only organisation API token. All results are scoped to that organisation.

| Operation | Result |
| --- | --- |
| `GET /api/findings` | Array of full or compact rows |
| `GET /api/findings/count` | Object with integer `total` |
| `GET /api/findings/groups` | Up to 500 group rows |
| `GET /api/findings/{finding_id}` | Full row plus `package_fix`, `owner` (its asset's owner, or `null`) and `ticket` (the tracker ticket its fix is in: `key`, `url`, `state`, `project`; `null` when none reached the tracker, see [tickets](tickets.md)); for a container image also `rebuild` (how it's fixed) and `runs_on` (the hosts that run it); `locations` lists where an application package (PyPI, npm, Maven, Go) sits on the asset, as its agent read it (a jar inside a jar, a venv, a binary; at most 20, empty for a distribution's packages and for SBOM components); `running` says what runs it (see [what runs](#what-runs)). Unavailable IDs return `404` |
| `GET /api/findings.csv` | Streamed CSV attachment |

List, count, group, and CSV operations accept these filters:

| Parameter | Default and behavior |
| --- | --- |
| `status` | `open`. Also accepts `resolved` or `accepted` |
| `priority` | No filter. Comma-separated exact priority strings. Values are not trimmed or enum-validated |
| `asset_id` | No filter. Exact asset ID |
| `q` | No filter. At most 200 characters, applied to lowercase package, vulnerability ID, or hostname through SQL LIKE |
| `fixable` | No filter. True selects a nonnull fixed version or a WinConfig, LinuxConfig, Lifecycle, External, or WinDriver result. False selects the inverse |
| `kev` | No filter. True/false selects the corresponding flag |
| `overdue` | No filter. True selects open findings past their computed deadline. False behaves like no filter. Groups ignore this parameter |
| `owner` | No filter. An owner name selects findings on assets with exactly that owner; an empty value (`owner=`) selects findings on assets with no owner. At most 100 characters |
| `runtime` | No filter. One or more of `listening`, `loaded`, `not_loaded` and `restart`, comma-separated, selects findings in those runtime states (see [what runs](#what-runs)); anything else is `422` |

`q` preserves SQL LIKE wildcards: `%` matches any sequence and `_` matches one character. It is not a literal-substring-only search.

The list defaults to `limit=500`, `offset=0`, `sort=score`, and `view=full`. Limit ranges from 1–5000. Offset is nonnegative. Sort accepts `score`, `package`, `host`, `vuln`, or `newest`. Compact output uses `view=list`.

Score sorts descending. Other name sorts use ascending names, followed by descending score. Newest sorts by descending first-seen time, then score. List ties use hostname and finding ID. Findings can change between requests, so pagination is not a frozen snapshot.

## Full and compact row fields

Every full row contains these fields. Compact rows contain only fields marked yes.

| Field | Value | Compact |
| --- | --- | --- |
| `id`, `asset_id` | Finding and asset ID strings | Yes |
| `hostname`, `ecosystem`, `package` | Identity strings | Yes |
| `asset_kind` | The asset's kind: `host`, `application`, `external`, `device` or `image` (a container image, fixed by a rebuild) | Yes |
| `installed_version` | Compared/normalized version string | Yes |
| `fixed_version` | Known fixed version string or `null` | Yes |
| `vuln_id` | Persistent vulnerability/check identity | Yes |
| `kev` | Known-exploitation boolean | Yes |
| `score`, `priority` | Integer score and priority string | Yes |
| `reasons` | Reason strings. Compact output retains at most one | Yes |
| `runtime` | `listening`, `loaded`, `not_loaded`, `restart` or `null` (unknown): what runs it, see [what runs](#what-runs) | Yes |
| `advisory_ids` | Advisory ID strings | No |
| `summary` | Finding summary string | No |
| `cvss`, `epss` | Numeric values or `null` | No |
| `setting_fix` | Whether a curated WinConfig fix exists | No |
| `plannable` | Whether the ecosystem/package has a supported planning path on this asset; never for anything but a host with an agent | No |
| `rule_evidence` | WinApp proof label, with `pattern` fallback. Other ecosystems use `null` | No |
| `status` | `open`, `accepted`, or `resolved` | No |
| `first_seen`, `last_seen` | UTC timestamps without a timezone suffix | No |
| `resolved_at` | Resolution timestamp or `null`. Can remain populated after acceptance/revocation | No |
| `due` | Open-finding deadline string or `null` | No |

`accepted_until` is stored internally and is not returned in these rows. `plannable` does not establish approval, host opt-in, or successful remediation.

The deadline uses the finding's current priority and the SLA policy at its first-seen time. Unknown priorities use 180 days. Accepted/resolved findings have no computed deadline. Acceptance/revocation responses also return `due=null`; a later list/detail GET computes an open deadline.

The detail-only `package_fix` is `null` or an object with `version` and integer `open`. It uses the highest nonempty fix among currently open findings for the same asset/ecosystem/package. `open` counts those open findings, including ones without fixes. This object does not prove that the selected version fixes every issue.

## What runs

Since 0.14.0 (agent 0.10.0) a Linux agent reads, at each report, which installed packages its running programs have loaded, which of those programs listen on the network, and which run a copy of a package that has since been replaced on disk (DECISIONS 161). For a finding on the host's distribution packages, `runtime` is:

| Value | Meaning |
| --- | --- |
| `listening` | A program listening on a non-loopback address loaded one of the source package's binaries, in a read within the last seven days. A flaw whose CVSS attack vector is network, adjacent or unknown gains 15 points (never moved when known exploited) |
| `loaded` | A program loaded one of its binaries within the last seven days, and none that loaded it was seen listening on the network. Rank unchanged |
| `not_loaded` | The package ships native code, the host's complete reads cover the last seven days with no gap over 36 hours, and none saw it loaded. When every flaw's vector is network or adjacent and nothing says it's exploited (KEV, Microsoft, a public exploit), the score is multiplied by 0.75 |
| `restart` | The fixed version is installed (or the package removed), but the latest read names a program still running the copy it replaced: the finding stays open with a `Still open: …` reason until a read no longer does |
| `null` | Unknown: no read, no native code the agent can see mapped, partial or stale reads, a kernel package, or not a distribution package |

`running` (detail only) is `null` for a host that has never sent a read, or an object with `state` (as above), `binary` (the binary that set the state), `binaries` (the source's installed binaries), `reason` (the words in `reasons`), `programs` (up to 20 programs loading one of them: `name`, `users`, `listen`, `loads`, `replaced`), `read_at`, `read_state` (`ok`, `partial` or `failed`), `read_problem`, `since` (when the current run of complete reads began) and `covered` (seven days of complete reads). Sampling at each report can't see programs that run for a moment, such as cron jobs and commands; the host firewall isn't read. Source: [`runtime.py`](../../api/src/nimstead/runtime.py).

## Group fields

`by=vuln` is the default. `by=package` groups package names separately for each ecosystem. Groups sort by worst priority, descending score, and descending finding count. Remaining ties have no explicit key order.

| Field | Meaning |
| --- | --- |
| `key` | Grouped vulnerability ID or package name |
| `findings`, `hosts` | Finding count and distinct asset count |
| `score` | Highest score |
| `kev` | True if any row has KEV true |
| `priority` | Most urgent recognized priority |
| `fixed_version` | Highest known fix for a single-ecosystem group, otherwise `null` |
| `packages`, `vulns` | Distinct package-name and vulnerability-ID counts |
| `package`, `vuln_id` | Lexicographically smallest values, selected independently |
| `ecosystem` | Sole ecosystem, otherwise `null` |

Version-comparison failures can propagate as server errors in group/detail fix selection. Missing fixes do not prevent a known fix from appearing for the rest of the group.

## CSV contract

Columns appear in this order: `hostname`, `package`, `installed_version`, `fixed_version`, `vuln_id`, `priority`, `score`, `cvss`, `epss`, `kev`, `status`, `first_seen`, `last_seen`, `resolved_at`, `summary`, `owner` (the asset's owner, empty when it has none), `runtime` (empty when unknown). New columns are added at the end, so a script that reads columns by position keeps working.

The attachment filename is `nimstead-findings-STATUS.csv`. Null cells are empty. Boolean cells use Python's `True`/`False` text. Timestamp cells use the datetime string representation, with a space between date and time.

String cells that begin with `=`, `+`, `-`, `@`, tab, or carriage return receive a leading apostrophe. These are the implemented formula-prefix guards, not a guarantee for every spreadsheet interpretation.

CSV applies the filters without list pagination. It reads through a separate database session in batches. The organisation shares a 30-export-per-hour quota with `/api/baselines.csv`. A refused attempt returns `429`. Quota accounting commits a database write even though the export is GET.

## Acceptance operations

All acceptance POST operations require an organisation admin browser session. API tokens are refused.

| Operation | Input and result |
| --- | --- |
| `POST /api/findings/{finding_id}/accept` | Reason of 10–2000 characters. `days` defaults to 90, range 1–365. Accepts an open or already-accepted finding; `409` for a resolved one. Returns a full row |
| `POST /api/findings/accept` | Same reason/days plus `vuln_id` of 1–200 characters. Accepts currently open matches. Returns integer `accepted`, or `404` if none match |
| `POST /api/findings/accept-many` | Same reason/days plus 1–1000 `ids`. Counts duplicate IDs once. Accepts owned open rows and returns integer `accepted`/`skipped` |
| `POST /api/findings/{finding_id}/revoke-acceptance` | Reason of 3–2000 characters. Requires accepted status. Returns a full row, or `409` for another status |

Unavailable individual IDs return `404`. Bulk selection skips unavailable or nonopen IDs, including already accepted rows. Bulk acceptance does not cover future findings or new hosts.

Single acceptance and revocation retain an existing `resolved_at` value. Read `status` as the current state. Acceptance records a reason and duration in the ledger. Revocation records its reason. These operations commit their state and ledger changes.

## Reassessment and resolution

`rescan()` reassesses stored inventory, updates risk signals, and commits finding/ledger changes. The commit includes the caller's pending changes on purpose: the report, context and SBOM endpoints and the hourly feed run stage their own writes and ledger entries and rely on it. Its `open` result counts all seen identities, including accepted findings. `resolved` counts new transitions to resolved.

Since 0.7.6 the detection engine's verdicts decide which identities are seen, inside the engine's slice: the Windows OS, Microsoft products, curated Windows apps, distribution packages, language packages and SBOM components (DECISIONS 123). A `vulnerable` verdict makes an identity seen. Since 0.7.7 an identity in the slice that isn't seen resolves only on evidence (DECISIONS 124). Since 0.8.0 the engine is the only source of these identities: the earlier matching is gone, so no decision means nothing opens (DECISIONS 125). An agent without a collection document (older than 0.5.0) gets no new findings, and its open ones stay open with a `Still open: …` reason until the agent is updated.

| Existing state and observation | Result |
| --- | --- |
| Resolved identity matches again | Open, with `resolved_at` cleared |
| Accepted identity matches after its nonnull expiry timestamp | Open, with acceptance cleared |
| Accepted identity still matches before expiry | Accepted |
| Open/accepted identity in the engine's slice is absent, and the engine proves it absent (`not-vulnerable`, or `not-applicable`: product gone with its list read in full, `removed`; no live advisory carries the identity, `withdrawn`) | Resolved |
| Open/accepted identity in the engine's slice is absent, with no such proof | Unchanged; a `Still open: …` reason says why |
| Open/accepted distribution-package identity is absent, its installed version changed (or the package went), and the latest runtime read names a program running the replaced copy | Unchanged, `runtime` = `restart`, with a `Still open: …` reason naming the programs (DECISIONS 162) |
| Open/accepted identity outside the slice (settings, drivers, Windows and app end of support) is absent and its collection guard does not block | Resolved |

Read APIs do not expire acceptance. Expiry is applied to matching identities during reassessment: a host's or application's rescan, an internet target's scan, and a device's network check (releases up to 0.11.0 expired acceptances on machines and applications only). Each expiry writes an `acceptance_expired` ledger entry. A blocked or otherwise unreassessed identity can retain its previous state.

The expiry rule requires a stored acceptance timestamp. An accepted row without that timestamp is not reopened by this rule.

Outside the slice, explicit failed/partial Windows sources and empty Uninstall counts block resolution for the affected ecosystems. Windows settings also require `facts.config` to be a dictionary. Driver findings require `driver_scan.complete=true` before absent identities resolve. There, a feed change or a missing match can still resolve a finding without proof of a repair.

A version fixed by hand on a distribution release past end of support resolves: end of support stops new advisories, it doesn't undo a fix. If the engine fails on a host, that reassessment opens nothing in the slice and resolves nothing. `inventory_received=false` (the hourly re-match and re-scoring) suppresses receipt logging; it still opens and resolves findings. External assets instead rescore their open findings through the separate external path.

Inventory receipts are logged when the package digest changes, or after one day without a receipt. The digest covers sorted ecosystem/name/version/source tuples, with source version when present. It excludes package origin and host facts. Finding transition events remain separate ledger records.

## Related

- [Detection confidence](../explanation/detection-confidence.md)
- [From inventory to evidence](../explanation/inventory-to-evidence.md)
- [External scan reference](external-scans.md)
- Source: [`scan.py`](../../api/src/nimstead/scan.py) and finding handlers in [`app.py`](../../api/src/nimstead/app.py)
