# Remediation job reference

Remediation jobs describe approved package or configuration operations. Server planning, host execution, and finding verification are separate stages. A stored job does not establish local consent or successful repair.

## HTTP operations

Read operations accept user sessions or eligible read-only organisation API tokens. Job creation, approval, cancellation, and policy changes require an admin browser session. Agent operations require the asset's bearer key. Ownership, origin, and two-step authentication rules also apply.

| Operation | Result and effects |
| --- | --- |
| `POST /api/remediation/jobs` | HTTP 201 with a planned job. Commit plan and evidence |
| `POST /api/remediation/jobs/batch` | HTTP 201 with `jobs` and `errors`. Commit each successful asset separately |
| `GET /api/remediation/jobs` | Up to 500 jobs, newest `updated` first. Sweep and commit timeouts first |
| `POST /api/remediation/jobs/{job_id}/approve` | Updated job. Commit approval |
| `POST /api/remediation/jobs/{job_id}/cancel` | Updated job. Commit cancellation |
| `GET /api/agent/jobs` | Eligible execution plans. Sweep and commit, then mark dispatched |
| `POST /api/agent/jobs/{job_id}/report` | `status` after the report commits. May schedule background step planning |
| `GET /api/windows-updates` | Compact cumulative-update groups. Sweep and commit timeouts first |
| `GET /api/windows-updates/{kb}?product=…` | One group with host details. Sweep and commit timeouts first |

Unknown/unowned assets and jobs return 404. Planning, approval, cancellation, and report-state refusals return 409. Body validation normally returns 422. Unhandled stored-data, database, key, or evidence errors can propagate.

## Plan and approval inputs

| Field | Constraint |
| --- | --- |
| `asset_id` | Required asset ID for a single plan |
| `ecosystem` | Required text, at most 100 characters |
| `package` | Required text, at most 255 characters |
| `include` | Single-plan dependency names, default empty list, at most 20 entries |
| `asset_ids` | Batch list with 1–5000 entries. Duplicate IDs collapse in request order |
| `forward_only` | Optional approval body boolean, default false |

Plans select open findings. Ordinary packages require a fixed version. Supported Windows configuration checks can lack one. Active jobs with the same asset/action prevent another normal plan. Closed product and setting maps determine supported application paths.

For ordinary package managers, `include` adds installed dependency names and their source-package siblings. Those dependencies' open findings also join verification. WinApp, Microsoft, and WinConfig delegation ignores `include`. Planning does not apply the approval mode, production guard, or local execution consent.

| Top-level ecosystem | Base manager |
| --- | --- |
| `Debian`, `Ubuntu` | `apt` |
| `Alpine` | `apk` |
| `Rocky Linux`, `AlmaLinux` | `dnf` |
| `openSUSE`, `SUSE` | `zypper` |
| `Windows` | `windows` |
| `WinApp`, `Microsoft` | `winget`, with Office/.NET delegation |
| `WinConfig` | `winconfig` |

Other ecosystem roots are unsupported by this planner. Ordinary package validation uses exact source patterns: names start with an alphanumeric character and allow `+._-`. Versions allow alphanumeric text and `.+~:_^-`. Each has at most 201 characters. Windows product and KB selection use separate patterns. These checks do not validate a complete package-manager grammar.

Batch errors contain `asset_id` and `error`. An all-error result still uses HTTP 201. Ownership and planning refusals preserve earlier successes. Other exceptions can stop the request after earlier commits.

Approval requires `planned` state, an enabled mode, and production permission or a sandbox asset. Winget/configuration and servicing-stack policy approvals are refused. Forward-only jobs require `forward_only=true`. Human approval does not require the policy canary gate. Cancellation accepts only `planned` or `approved`.

## Public job fields

| Field | Value |
| --- | --- |
| `id` | Job identifier |
| `asset_id`, `hostname` | Asset identity and current hostname |
| `status` | Stored job state |
| `manager` | `apt`, `apk`, `dnf`, `zypper`, `windows`, `winget`, `office`, or `winconfig` |
| `action_key` | Ecosystem, `|`, and source package/product/check |
| `packages` | Manager-specific package dictionaries |
| `finding_ids` | Findings selected for verification |
| `summary` | Plan description |
| `created_by`, `approved_by` | Creator and nullable approver text. Policy actions use `policy` |
| `created`, `updated` | Stored UTC timestamps |
| `steps` | Reported step dictionaries with `step`, `ok`, and `output` |
| `error` | Error text or null |
| `result_versions` | Reported package-version map or null |
| `forward_only` | Manager/servicing classification, not an independent rollback probe |
| `waits_for_window` | List-only optional field. Approved rows add the next UTC start or null |

Ordinary API job results have 17 fields. The list's `status` query splits on commas without whitespace removal or enum validation. Unknown names can yield an empty result. `waits_for_window=null` also covers an unavailable next start, not only an open window.

### Package and execution dictionaries

Ordinary package plans have `name` and `from`, with optional pinned `to`. Windows KB plans add `kb`, `to`, optional `alt` with its own `kb`/`to`, and optional boolean `servicing`. Application plans have `name`, `from`, and `to`. Configuration plans use `current` and `fixed` marker versions.

Agent execution plans have `id`, `manager`, `packages`, and `health_units`. Windows KB plans also have `reboot_by`, calculated at dispatch from the organisation's current restart deadline. Health units come from the current asset. These dictionaries contain no shell command field.

## States and verification

| State | Meaning |
| --- | --- |
| `planned` | Awaiting approval, or returned to planning after a policy hold |
| `approved` | Eligible for later dispatch, subject to current gates |
| `dispatched` | Handed to an agent. Execution may still continue |
| `verifying` | Agent reported `applied`. Awaiting stored finding evaluation |
| `succeeded` | No selected open/accepted findings remain, or a Windows step qualifies |
| `not_fixed` | Selected open/accepted findings remain without qualifying step evidence |
| `rolled_back`, `rollback_failed`, `aborted` | Agent-reported outcomes |
| `failed` | Server timeout or dispatch refusal |
| `cancelled` | Withdrawn before dispatch, or cancelled by suggest mode at dispatch |

The report endpoint accepts outcome text of at most 30 characters. Allowed outcomes are `applied`, `rolled_back`, `rollback_failed`, and `aborted`. Applied becomes verifying. Timeout-failed jobs accept late reports. Other states refuse another report.

Request limits are 200 step dictionaries, 500 version entries, 5000 error characters, and ten offered-update entries. Storage retains 200 steps. Step and output text truncate to 200 and 2000 characters. Stored error text truncates to 2000. Truthy version values become strings with 200-character keys and values.

Verification normally treats accepted findings as unresolved. Missing finding rows count as no remaining open/accepted findings. The helper does not prove inventory freshness itself. Its caller must establish that prerequisite.

A Windows job can succeed as a step when its alternative build appears in any reported version value. Selected findings can remain open. This is an intermediate success, not proof that the final target was installed or every finding resolved.

### Timeouts and dispatch

Ordinary dispatched jobs time out after two hours since `updated`. Windows waits the current organisation restart deadline plus four hours, with a 24-hour deadline fallback. Timeout handling changes `updated` and commits all pending session changes. It does not stop a host process.

Dispatch first sweeps timeouts. It then checks the effective window, production permission, suggest-mode switch, and broad policy canary state. Outside the window, it returns before those later checks. Approved jobs can therefore remain pending cancellation until an eligible poll.

Windows sequencing blocks another Windows dispatch for the same host while one is dispatched or recently timeout-failed. A verifying job on that same host does not independently hold this check. Peer cluster/DC jobs in dispatched or verifying state can block within the restart-deadline horizon. Other managers are not serialized by this Windows check.

Cluster names take precedence over domain-controller groups. Values compare case-insensitively after lowercase conversion. DC grouping requires integer `domain_role>=4` and a domain. These are reported facts, not independent membership verification.

## Maintenance windows and policy

| Window field | Accepted value |
| --- | --- |
| `days` | Nonempty integer list, Monday 0 through Sunday 6. Booleans refused. Duplicates accepted |
| `start` | `HH:MM` in 24-hour form |
| `hours` | Integer 1–24. The current helper also accepts boolean true as one hour |
| `tz` | Name accepted by the server's `ZoneInfo` database |

No extra keys are accepted. Windows start in local wall time and last elapsed UTC hours, including clock changes. End boundaries are exclusive. The direct `window_state` helper expects a naive UTC datetime and returns naive UTC boundaries. Invalid direct inputs can raise errors.

`PATCH /api/settings` accepts optional policy fields. Omitted/null fields keep their values. An empty organisation window clears the restriction. `PATCH /api/assets/{asset_id}` accepts an empty window to inherit the organisation window. It does not disable that organisation restriction.

| Policy field | Accepted update |
| --- | --- |
| `remediation_mode` | `suggest`, `approve`, or `auto` |
| `canary_soak_hours` | Integer 1–720 |
| `maintenance_window` | Window dictionary, or `{}` to clear |
| `reboot_deadline_hours` | Integer 1–168 |
| `agent_updates_paused` | Boolean |
| `sla_days` | Priority keys to 1–365 days. Supplied keys merge with current values |

Settings GET/PATCH returns these six policy fields plus `signed_agent_release`, `platform`, and `production_remediation_allowed`. The platform object uses the [update status fields](platform-updates.md#settings-status-fields). PATCH commits before that response's cache/key reads, which can still fail.

### Canary limits

Automatic planning skips manual-only base managers. Broad policy approval requires a same-action succeeded canary on a current ring-0 asset, old enough for the soak. Failure states `rolled_back`, `rollback_failed`, `failed`, and `not_fixed` halt rollout. `aborted` and `cancelled` are not halt states.

For KB jobs, a failed earlier target does not necessarily halt a newer release. Canary version reports must show a valid upgrade reaching the requested target. Non-KB packages impose no version test in `proves()`. A succeeded same-action canary can therefore qualify without complete package version evidence.

`pin_to_canary()` selects the newest succeeded same-action canary with nonnull results. It replaces only non-KB targets with readable reported upgrades. Missing or invalid versions leave targets unchanged, potentially unpinned. The helper does not independently repeat soak checks.

## Windows cumulative groups and step planning

`windows_kbs()` selects each CVE's lowest stored fixed build, then the highest of those choices. Every requested CVE needs a valid numeric KB. Alternatives can describe an umbrella KB, explicit earlier step, complete hotpatch coverage, or older cumulative candidate. This is advisory selection, not a probe of Windows Update availability.

The fleet view includes numeric-version Windows host package rows. It shows at most three newest cumulative groups per product. A group counts fixed by a sufficient reported build, or a recognized hotpatch build without overlapping open/accepted CVEs. Repeated stored package rows can contribute repeated host counts.

| Group field | Value |
| --- | --- |
| `kb`, `product`, `title` | Group identity and label |
| `released` | Source date text or null |
| `build` | Highest stored fixed build for that KB/product |
| `hosts`, `fixed` | Counted package-member rows and members treated as fixed |
| `plan_note` | Rollout suggestion or null |
| `missing` | Detail-only host rows |
| `plan_asset_ids` | Detail-only suggested planning targets |

Each missing row has `asset_id`, `hostname`, `build`, `ring`, `why`, `notes`, and nullable `job`. The nested job has `id` and `status`. Notes describe reported conditions, not proven causes. Suggested targets still require normal plan/approval checks.

After an aborted Windows report, background step planning reads at most ten offered KB/title dictionaries and 300 title characters. Numeric KBs and `YYYY-MM` title prefixes select stored builds or MSRC month requests. At most three attempted month fetches per organisation per 24 hours are recorded. Failed requests consume quota, and their records commit before transport.

An earlier cumulative must share the target's build line and fall between current and target builds. A narrowly eligible single offer can instead form a forward-only servicing plan. .NET Framework can use a same-month combined cumulative alternative. Step planning creates plans without approval. Successful plans commit. Fetches and earlier commits can survive a later refusal or failure.

## Python helper ownership

Most planning, approval, cancellation, report, automatic-policy, and verification helpers leave commits to their caller. Queries can autoflush changes. `sweep`, processed `dispatch`, successful step plans, and month-quota records commit all pending session changes. Outside-window dispatch still follows the sweep commit.

`plan_windows_app()` is a lower-level helper. It trusts caller-selected findings and does not enforce active-duplicate checks itself. Pure path/group classifiers also do not establish permissions, consent, or actual rollback capability. Field, comparator, evidence, timezone and database failures can propagate after partial in-session changes.

## Related

- [Enable remediation](../how-to/enable-remediation.md)
- [Remediation modes](remediation-modes.md)
- [Remediation safety](../explanation/remediation-safety.md)
- [Finding state](findings.md)
- Source: [`remediate.py`](../../api/src/nimstead/remediate.py) and [`app.py`](../../api/src/nimstead/app.py)
