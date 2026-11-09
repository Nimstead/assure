# Scan report format

`GET /api/assets/{asset_id}/scan-report` returns a grouped report for stored inventory. It does not return every raw verdict. Authentication requires a session or an eligible read-only API token. An unavailable asset returns `404`.

This GET can create a scan record and commit the database session. The server deduplicates records by asset, inventory hash, content version, and verdict hash. It retains five records per asset. Report generation does not change findings.

## Root fields

| Field | Value |
| --- | --- |
| `host` | Reported hostname |
| `kind` | `host` or `application` |
| `os` | Reported operating-system name |
| `agent_version` | Reported agent version |
| `inventory_read_at` | Collection timestamp, or `null` |
| `engine_version` | Evaluator version string, currently `3` |
| `content_version` | Selected advisory-content identifier |
| `inventory_sha256` | SHA-256 hex digest of the stored inventory representation |
| `verdicts_sha256` | SHA-256 hex digest of the ordered verdict representation |
| `headline` | Object with `status` and display `text` |
| `vulnerable` | Vulnerable groups, one per family/product/instance |
| `undetermined` | Groups of `undetermined` and `not-run` checks |
| `not_vulnerable` | Groups with `family`, `product`, `instance`, `grade`, and integer `checks` |
| `not_applicable` | Integer count of not-applicable verdicts |
| `applications` | Per-install outcomes for software outside the package manager |
| `attack_paths` | Correlated Windows paths, as defined below |
| `coverage` | Collection sources, family counts, application counts, and scope statements |

## Headline status

| `status` | Selection rule |
| --- | --- |
| `vulnerable` | At least one vulnerable verdict exists |
| `not-assessed` | No vulnerable verdict exists and patch state lacks a determined verdict |
| `undetermined` | Patch state has a determined verdict, but at least one check is undetermined or not-run |
| `no-known-vulnerabilities` | Patch state has a determined verdict, with no vulnerable, undetermined, or not-run verdicts |

A determined verdict is vulnerable, not-vulnerable, or not-applicable. Patch-state assessment requires an OS or distribution verdict, or an application-component verdict for an application asset. Lifecycle verdicts alone do not establish patch-state assessment.

The headline covers checks this report judges. Read `coverage.statements` for excluded software and disabled collection. It does not certify the whole asset as secure.

## Vulnerable groups

| Field | Value |
| --- | --- |
| `family`, `product`, `instance` | Group identity. `instance` can be `null` |
| `grade`, `version`, `observed`, `source` | Values from the first vulnerability after group sorting. Values can be `null` |
| `expected`, `action` | Display text for the selected fix or support requirement |
| `kernel` | `running`, `not-running`, empty string when unknown, or `null` for other installs |
| `pending_reboot` | True if any grouped verdict marks a pending restart |
| `fixed_after_restart` | Count of grouped verdicts with `pending_reboot=true`. On Windows this flag does not prove the fix is installed |
| `raise_confidence` | First sorted verdict's detail, or `null` |
| `count` | Number of grouped vulnerable verdicts |
| `no_fix` | Count without a fixed version |
| `no_fix_planned` | Count with vendor status `no-fix-planned` |
| `known_exploited` | Count with KEV true |
| `worst_cvss` | Highest nonzero CVSS value, or `null` |
| `vulnerabilities` | Array of vulnerability rows |

Each vulnerability row has `id`, `kev`, `cvss`, `cvss_source`, `fixed`, `kb`, `summary`, and `vendor_status`. Values other than `id` and `kev` can be `null`.

Within a group, KEV comes first, then descending CVSS, then vulnerability ID. Groups sort by descending KEV count, descending worst CVSS, product, and instance.

The proposed action uses the highest available fixed version among grouped verdicts. If comparison raises `ValueError`, selection falls back to lexical order. Some grouped vulnerabilities can still lack a fix. The action is a report summary, not an executed or verified remediation plan.

## Incomplete groups

Each `undetermined` row has these fields:

| Field | Value |
| --- | --- |
| `outcome`, `reason` | Outcome and incomplete-check reason |
| `blocked_by` | Collection source name, or `null` |
| `why`, `what_to_do` | Reason explanation and suggested action |
| `source_said` | Source detail, or `null` |
| `count` | Number of checks with this outcome/reason/blocker/detail combination |
| `examples` | Up to five sorted unique vulnerability IDs, instances, or products |

Rows sort by descending count, then reason. See [scan outcomes](scan-outcomes.md) for reason and grade values.

## Application rows and coverage

Each `applications` row has `ecosystem`, `product`, `instance`, `grade`, and `outcomes`. `outcomes` maps outcome names to integer counts. The grade is the weakest nonempty grade among that install's verdicts, or `null`.

`coverage` has four fields:

| Field | Value |
| --- | --- |
| `sources` | Array with `name`, display `label`, `state`, integer `count`, and nullable `error` |
| `families` | Map keyed by family, with `label`, integer `attempted`, integer `determined`, and an `outcomes` count map |
| `applications` | Counts and exclusions for software outside the package manager |
| `statements` | Array of scope and incomplete-assessment statements |

Families are `os`, `microsoft`, `app`, `distro`, and `application`. Relevant families appear even when they have no checks. Others can be absent.

`coverage.applications` has integer `installs`, `judged`, `vulnerable`, `no_advisory`, `left_to_package_manager`, and `sbom_components_not_assessed`. Its `not_looked_for` field lists disabled or unreported scan labels.

`judged` counts installs with advisory records. It does not count successful conclusions. `no_advisory` requires a loaded ecosystem feed and no record for the install. Neither value proves that an install is safe.

## Host attack paths

Linux and application assets return an empty `attack_paths` array. Windows can return one `network` path, followed by one `foothold` path. These are inferred combinations of reported vulnerabilities and settings. They do not prove an exploit succeeded.

| Path field | Value |
| --- | --- |
| `kind`, `start` | Path type and start description |
| `grade` | Weakest grade among the first displayed way in each required step |
| `steps` | Required stage objects |
| `then` | Optional lateral-movement stage object, or `null` |
| `break_at` | Earliest required step with the fewest ways |

Each required step has `stage`, `label`, `ways`, and integer `count`. `then` has `label`, `ways`, and `count`. Each array shows at most five ways. The count includes ways beyond those shown.

A way has `what`, `ref`, `grade`, and `kev`. Vulnerability-based ways also have integer `flaws`. Setting-based ways omit `flaws`. Stages use `entry`, `escalate`, `credentials`, or `lateral`.

`break_at` has `stage`, `label`, integer `fixes`, and up to five `refs`. Its count identifies the full step, including references omitted from display.

## Hashes and text rendering

The inventory digest hashes `json.dumps(inventory.to_doc(), sort_keys=True, default=str)`. Package-list order affects the hash. The server sorts stored package rows before it creates this representation.

The verdict digest hashes `json.dumps([v.as_dict() for v in verdicts], sort_keys=True)`. Verdict order affects the hash. The evaluator sorts its results before report generation.

The content identifier has a newest `modified` prefix, or `none`, followed by a dot and 12 SHA-256 hex characters. The hash includes the application version, selected records, KEV, CVSS, feed coverage, package universe, and lifecycle data. It identifies inputs without retaining a full advisory archive. Reproduction also requires the same inventory, prior-finding identities, and evaluator implementation.

The CLI text renderer shows at most five vulnerability IDs per group. It replaces C0, DEL, and C1 control characters inside output lines with `?`. JSON retains original field text. The CLI adds a final newline after the rendered string.

## Related

- [Inventory and collection metadata](inventory-format.md)
- [Fleet attack-path format](fleet-paths.md)
- [Detection confidence](../explanation/detection-confidence.md)
- Source: [`report.py`](../../api/src/nimstead/engine/report.py), [`content.py`](../../api/src/nimstead/engine/content.py), and [`paths.py`](../../api/src/nimstead/engine/paths.py)
