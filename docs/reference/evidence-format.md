# Evidence responses and pack format

Evidence APIs return either JSON lookup/report data or a signed ZIP. These fields describe the current source contract. They do not certify compliance with a named framework.

## Endpoint responses

| Endpoint | Result |
| --- | --- |
| `GET /api/evidence/public-key` | Public JSON with `pem`, `fingerprint_sha256`, and `verifier_sha256` strings. No session required |
| `GET /api/evidence/verify.py` | Python verifier source, media type `text/x-python` |
| `GET /api/evidence/ledger` | JSON with `problems` (string array), `entries` (ledger-record array), and `total` (matching count before the limit) |
| `GET /api/evidence/report` | Report JSON; `ledger.entries` is an integer count in both summary modes |
| `GET /api/evidence/pack` | `application/zip` attachment. Returns HTTP 409 if integrity checks refuse signing |

The report text describes stored observations and recorded resolutions. Advisory changes can resolve a finding without a package update. The signed basis states this limit.

The report and pack accept `days` from 1 through 730, default 90. The report also accepts `summary`, default false. With `summary=true`, it omits `assets` and `findings`; it retains metrics and controls.

The ledger accepts `limit` from 1 through 1,000, default 100. Its optional `group` is `decisions`, `fixes`, `detections`, or `access`. Entries are newest first. Organisation session/read-token requirements are in [HTTP API reference](http-api.md).

## ZIP members

| File | Contents |
| --- | --- |
| `pack.json` | Exact UTF-8 JSON bytes covered by the signature |
| `pack.sig` | Base64 Ed25519 signature over `pack.json` |
| `public_key.pem` | Signing public key in PEM SubjectPublicKeyInfo form |
| `README.txt` | Verification instructions and the signing-key fingerprint |

The ZIP does not contain a trusted verifier. Obtain the verifier and expected fingerprint through a separate trusted source. A key inside the ZIP is not its own trust anchor.

## Pack and report root fields

| Field | Type and meaning |
| --- | --- |
| `format` | Literal `nimstead-evidence/1` |
| `organisation`, `organisation_id` | Organisation name and stable identifier strings |
| `organisation_created` | UTC timestamp string identifying organisation creation |
| `verified_domains` | Sorted strings from verified SSO domains and verified external-target hostnames |
| `generated_at` | UTC timestamp string for report generation |
| `period` | Object with inclusive `from` and `to` UTC timestamp strings |
| `basis` | Text describing the inventory, matching, timing, and signing basis |
| `sla_days` | Current priority-to-deadline mapping, in days |
| `sla_changes` | Period policy-change records: `ts`, `by`, and `sla_days` |
| `metrics` | Counts and timing values defined below |
| `controls` | Framework/control assessment records defined below |
| `forward_only_changes` | Winget job records updated in the period, excluding planned/cancelled jobs |
| `assets` | Current organisation asset records, not a historical inventory snapshot. Omitted by `summary=true` |
| `findings` | Finding review records defined below. Omitted by `summary=true` |
| `ledger` | Period entries/count and head information, with endpoint-specific differences below |

Asset records contain `hostname`, `os`, and `last_seen` strings. Forward-only job records contain `job`, `host`, `summary`, `approved_by`, `status`, and `updated`. The approver can be absent.

A finding resolved before the review period is excluded. Findings without a lifecycle ledger record are excluded from review rows and counted separately. The report uses recorded lifecycle times; it does not use an invented resolution time.

## Finding review fields

| Field | Type and meaning |
| --- | --- |
| `vuln_id`, `package`, `host`, `priority` | Vulnerability, package, host, and priority strings |
| `cvss` | Numeric score or `null` |
| `kev` | Boolean known-exploitation flag |
| `status` | Current stored finding status. Use `resolved_at` for resolution within the selected period |
| `first_seen` | Naive UTC timestamp string from the lifecycle ledger |
| `resolved_at` | Naive UTC timestamp string, or `null` if not resolved by the period end |
| `days_open` | Number rounded to one decimal; first detection to resolution or period end |
| `sla_days` | Deadline in force at first detection, in days |
| `within_sla` | Boolean comparison of elapsed time with that deadline |

Current deadline keys are `fix-now`, `next`, `planned`, and `low`. Defaults are 14, 30, 90, and 180 days respectively. Organisation policy can override them. The finding row uses the policy recorded at first detection, not the current mapping.

A currently resolved finding can have `resolved_at: null` when its resolution is later than the selected period end. Do not use `status` alone to reconstruct historical state.

## Metrics

All metrics are integer counts except `mttr_days`.

| Field | Meaning |
| --- | --- |
| `resolved` | Included findings resolved by the period end |
| `resolved_within_sla` | Those resolutions within their original policy deadline |
| `overdue_open` | Included open findings beyond their original deadline |
| `ce_in_scope_resolved` | Resolved findings with KEV membership or CVSS at least 7 |
| `ce_in_scope_resolved_in_14d` | Those findings resolved within 14 days |
| `ce_in_scope_overdue` | In-scope open findings older than 14 days |
| `critical_overdue_30d` | Open findings older than 30 days with KEV membership or CVSS at least 9 |
| `findings_without_ledger_record` | Candidate findings with no recorded opening event |
| `assets` | Current organisation asset count |
| `assets_reporting` | Assets whose latest report is within the period or later than its end |
| `assets_silent_now` | Host assets whose latest report precedes the period end by more than 14 hours |
| `mttr_days` | Mean days to resolution, rounded to one decimal; `null` when no included findings were resolved |
| `changes` | Jobs updated within the period whose current status is neither planned nor cancelled |
| `changes_authorised` | Those jobs with an approver recorded |
| `changes_self_approved` | Those jobs whose approver is also their creator |
| `forward_only_changes` | Number of included winget job records |
| `sla_changes` | Number of deadline-policy changes in the period |

Metric names alone do not establish an independent approval or a historical asset snapshot. For example, `assets_silent_now` uses the requested period end as its cutoff.

## Control records

Each record has `framework`, `control`, `requirement`, `status`, and `evidence` strings. Some also have an integer `exceptions` count.

`status` is `met`, `not_met`, or `no_activity`. A passing timeliness check with no qualifying activity is `no_activity`. A failing condition remains `not_met`. Other controls have their own conditions. The accompanying evidence text and exception count remain part of the result.

These are Assure's computed indicators. Read the declared basis and time window before using them in a wider review.

Inventory indicators use current asset report timestamps in or after the selected period. They do not establish complete collection or an actual scan within that period. Change authorization counts jobs with a recorded approver. It does not establish execution, health checks, rollback, or independent approval.

## Ledger variants

Ledger entry records contain `seq` (integer), `ts`, `kind`, `subject`, `prev_hash`, `hash` (strings), and `data` (event-specific JSON). Entries in a pack are oldest first.

| Context | `ledger` fields |
| --- | --- |
| Signed pack | `entries` array, `head_hash`, `chain_head`, `checkpoints` |
| Report, either summary mode | `entries` integer count and `head_hash` only |

`head_hash` identifies the last entry in the selected period, or 64 zeroes for an empty period. `chain_head` identifies the latest whole-chain `seq` and `hash` at generation, which can be outside the period.

Each checkpoint contains `org_id`, `seq`, `hash`, `ts`, and `sig`. Its base64 signature covers canonical JSON of the first four fields. Checkpoints can cover history outside the pack's selected period.

See [verify an evidence pack](../how-to/verify-evidence.md) for the procedure and [evidence trust](../explanation/evidence-trust.md) for the limits.

The public-key endpoint can create a missing local signing key or call the configured key backend. Retrieval can therefore have side effects or fail. The ZIP route can write a checkpoint before a later refusal.
