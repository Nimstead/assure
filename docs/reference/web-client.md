# Web client reference

The Assure web client uses React, TanStack Router, and TanStack Query. TypeScript interfaces describe selected expected data. They do not validate API responses at runtime or enumerate every server field. This page covers shared helpers, UI components, enrolment, and the reviewed Assets, Fix first, Findings, Evidence, settings, and remediation pages.

## Component context

Query components require a `QueryClientProvider`. Route links, navigation, and route hooks require the app router. Dialogs require a browser DOM. The application entry point supplies these contexts.

Client admin controls do not replace server authorization. `useIsAdmin()` returns true only when cached `/api/me` data says `admin=true`. Missing data produces false. `adminGate(false)` keeps a button focusable, marks it unavailable, and replaces its click handler. It must be spread after the button's own props.

`api<T>()` parses JSON without validating `T`. HTTP, network, and request-preparation failures become `ApiError`. Successful JSON parse failures can propagate separately. Rendering assumes typed shapes. Malformed dates, package fields, or nested values can cause render failures.

## Settings components

| Export | Inputs and behavior |
| --- | --- |
| `SettingsPage()` | No props. Reads policy and user queries, plus admin-only asset counts. Child sections own account/integration requests |
| `PlatformSection({p})` | `p` is `Settings.platform`. Renders cached version/channel/outcome text without requests or mutation |

Settings form values seed once per mount. A save in one section preserves edits elsewhere. Policy saves use `PATCH /api/settings`. Success replaces cached settings, resets only saved form fields, and invalidates the ledger. Errors appear beside the relevant control.

Mode selection alone does not save. Auto requires a separate confirmation. Its machine and canary counts describe the loaded fleet, not the number of fixes eligible for automatic approval. The server determines eligibility. Human-only fixes remain human-only.

The maintenance form uses the stored timezone, otherwise the browser timezone or UTC. It validates selected days, `HH:MM`, whole hours 1–24, and restart deadline 1–168. An empty organisation window clears the restriction. [Server window rules](remediation-jobs.md#maintenance-windows-and-policy) define inheritance and timing boundaries.

Platform display uses cache data without signature or freshness checks. A missing newer version means no newer release in that cached check. Unknown update outcomes display their raw text. Last-update messages are historical text, not live alerts.

## Assets and Fix first components

| Export | Inputs and behavior |
| --- | --- |
| `Home()` | No props. Read summary, coverage and policy. Zero assets lazy-loads onboarding. Only summary errors render retry |
| `ActionCard({a})` | Render a server action and select display targets from asset/policy queries. PlanFixButton owns plan requests |
| `AssetsPage()` | No props. Read assets and independent directory/path/baseline/coverage sections. Own context PATCH and confirmed DELETE |
| `AssetRow({...})` | Render typed asset and admin/read-only controls. Parent callbacks own context edits and deletion |
| `baselineSummary(c)` | Format pass against automated minus not-applicable, with fail/unknown counts. No range validation |
| `Baselines()` | No props. Query stored summaries; host expansion enables detail. Missing/empty host data renders nothing |
| `AttackPaths()` | No props. Query stored path inferences. Missing data or no paths/chains renders nothing |
| `NotAssessed()` | No props. Display nonzero inventory-only mapping counts. Missing/zero data renders nothing |
| `SbomUpload({a})` | Read selected File as text and POST verbatim for asset a. Refresh asset-derived queries after success |

All query components require QueryClient context. Links and route hooks also require the app router. Invalid typed shapes, dates or status keys can throw. The client does not collect host facts or independently evaluate findings.

### Recommendations and optional data

Fix first sums the four recognized priority counts from the summary. It displays at most five supplied attention jobs. Missing coverage defaults to zero inventory-only entries. Missing policy does not block the summary or display a separate error.

ActionCard removes supplied busy IDs from the action's asset IDs. When production permission is known false, it further selects loaded sandbox assets. Unknown policy lets the server decide. Missing asset data can therefore hide controls under a known production restriction.

A selected dependency refusal directs review to its job instead of ordinary retry. An active job can still leave other targets available. Recommendation counts use vulnerability identities and asset IDs. The displayed hostname list can contain fewer entries when names coincide.

Path grades and suggested interruption references come from the server. Cross-host links can carry confirmed grades under the [recorded evidence rules](fleet-paths.md). That grade does not establish current access or a successful attack. Edge truncation and selected routes can omit alternatives.

Coverage counts describe supported identities or matching runtime facts, not completed verdicts or advisory availability. The server supplies at most 200 unmatched name/publisher groups. Baseline manual checks remain unassessed. Baseline hosts group by name/version in the client, not by baseline ID.

Directory, path, baseline, and mapping sections can disappear on an uncached query error. The asset list has a separate retry state. Expanded baseline details show their own errors. A missing optional section does not prove an empty or successful result.

### Asset list URL and selection

| Parameter | State |
| --- | --- |
| `q` | Initial search text |
| `crit` | Initial criticality, otherwise any |
| `sort` | Initial urgent/name/seen order, otherwise urgent |
| `show` | Initial filter tokens. Later nonempty values update selected filters |
| `machine` | Current drawer asset ID |

Local filters replace the URL as they change. Query, criticality, and sort are not fully re-synchronized from later URL changes while mounted. Removing `show` does not independently clear local filter state. Malformed runtime values can fail rendering.

The list starts with forty rows and adds up to two hundred per display action. This is client slicing, not API pagination. Select all includes every matching row, even beyond the displayed slice. Existing selection can retain rows hidden by later filters. A new select-all action replaces selection with the matching set.

### Context requests and recovery

Context edits optimistically update the cached asset row. A failed request restores that row's captured prior object. This protects other rows but can overlap later edits to the same row. Final invalidation refreshes server state.

Bulk edits invoke the parent callback independently per selected asset. Ring changes omit nonhosts. Prepared feedback appears without waiting for every save. There is no atomic transaction or complete per-row aggregate result in this control. Saved/error markers track recent mutation callbacks.

Single-change Undo resubmits prior criticality, exposure, ring, and health units. It omits directory_source. Bulk Undo uses captured values for staged fields, including selections now hidden by filters. Undo creates new requests; it does not reverse a transaction or guarantee success.

Host health text splits commas, trims values and removes empty entries. Duplicates remain. Blur or Enter invokes the callback when normalized text differs. The server validates names/counts. Prop changes re-seed the text, including after rollback.

### AssetRow props

| Prop | Meaning |
| --- | --- |
| `a` | Asset snapshot. Objects are not mutated by the row |
| `onPatch` | Parent callback with context fields |
| `onDelete` | Parent removal action |
| `saved`, `error` | Optional parent feedback |
| `inDrawer` | Hide duplicate heading and show additional context |
| `undo` | Optional parent recovery callback, displayed after saved feedback |

The row renders read-only context for nonadmins. Admin controls submit through callbacks without a local pending lock. A reported pending restart does not establish that the next inventory will resolve findings. A reported OS mapping gap does not prove other collectors succeeded.

### Applications, uploads and directory observations

Application creation trims a nonempty name, requests an asset, and invalidates the asset list on success. The creation response supplies a reusable upload secret. Closing the dialog clears its local displayed result. It does not revoke the secret.

The displayed CI command uses the current browser origin and returned asset ID/token. It sends raw JSON. Supported server formats are CycloneDX and SPDX. The browser uploader does not validate file size or format. File-read and request failures appear locally, and input reset permits the same file to be retried.

The directory-source flag permits that agent's directory uploads when collection is enabled. Multiple flagged sources can upload. Each accepted upload replaces the organisation's entire stored list. Directory display compares reported short names with enrolled hosts, across domains, using a 30-day logon cutoff. It does not query Active Directory live.

The directory section shows at most 200 returned rows and offers CSV for the full response. Its source enabled status and timestamps are reported observations. The UI does not independently verify domain membership, current sign-in, or lifecycle entitlement.

For operational steps, use [Change asset context](../how-to/change-asset-context.md).

## Findings components

| Export | Input and behavior |
| --- | --- |
| `FindingsPage` | `search: RawSearch`. Normalizes URL filters, requests individual rows/counts or groups, and renders selection, saved views and a drawer |
| `AcceptRisk` | `f: Finding`. Uses its ID, vulnerability ID and hostname. The caller controls finding status and component lifetime |

### Queries and navigation

Plain text replaces the URL after 250ms. Trailing spaces remain when the URL returns the same trimmed text. A different URL query replaces the input.

Recognized questions wait for Ask or Enter when AI is enabled. An answer applies only while the pathname remains `/findings`. This guard does not compare later text edits. A late answer can replace newer filters on that page.

Individual rows use offset pages of `FINDINGS_CAP`. A full page permits another request. The independent count query excludes sorting. Missing count data falls back to loaded rows. Count failures have no separate error panel.

Grouped mode requests vulnerability or package aggregates. Exactly 500 groups produces `worst 500`. A group click uses its key as substring search and returns to individual rows. It does not preserve exact group identity.

List/group queries retain previous data during filter changes. Their failures expose retry. Optional assets, AI and settings failures can omit labels or controls. Typed response shapes remain unvalidated.

The virtual table renders loaded rows with 12 extra rows around its window. It requests another page near the last 40 loaded rows. CSV exports individual findings with the current filters, including from grouped mode. Server limits still apply.

### Selection and bulk results

Admins can select open individual rows. Select-all covers loaded rows, including rows outside the virtual window. It excludes unloaded matches. A changed serialized list query clears selection. Escape clears selection when no dialog is present.

Bulk planning uses selected rows with fixed versions. It groups by ecosystem/package and deduplicates asset IDs within each group. Configuration fixes without fixed versions do not enter these groups. Server eligibility remains authoritative.

Groups submit sequentially. Responses accumulate job counts and distinct refusal messages. Any jobs cause success to clear selection. Zero jobs retains selection. A transport failure stops later groups. Earlier groups can already have created jobs. Job queries refresh on settlement, including failure.

Bulk acceptance submits selected IDs once. Success displays the accepted count and clears selection. The UI omits the returned skipped count. The server skips unavailable/nonopen rows. Future findings are outside this scope.

### Drawer and evidence

The URL selects the drawer identity. Previous/next and `j`/`k` use loaded individual IDs only. The `a` key opens acceptance controls. The `p` key focuses the plan button without submission. Inputs, textareas and selects suppress shortcuts.

A detail `404` means that the finding is unavailable to the current organisation. Resolution retains its row. Other failures expose retry. Dates and nested fields are trusted and can cause render errors if malformed.

The active-jobs query matches asset ID and ecosystem/package action key. Its existing-fix label includes planned jobs that have not executed. A failed query can omit this label.

A combined package version covers recorded fixes. It does not prove execution or later resolution. KEV absence means absence from that catalogue. Rule-evidence labels describe historical mapping evidence, not proof from this asset.

Known production execution restrictions hide this drawer's plan control for known production assets. Missing settings default to permission. Unknown asset context leaves eligibility to the server. These controls do not establish API planning or execution eligibility.

### Acceptance and saved views

`AcceptRisk` gates its opening button with cached admin state. It trims the reason and requires ten characters. Duration choices are 30, 90 and 180 days. The default is 90. The API enforces upper limits and authorization.

The default POST accepts the supplied finding ID. Optional vulnerability scope accepts currently open matches across the organisation, including other packages/assets. Success invalidates related queries. The component does not close/reset its form. Parent refresh can remove it after a status change. Errors remain visible.

Acceptance moves findings to Accepted. Expiry alone does not change read responses. Later reassessment can reopen an expired finding if its match remains. Revocation submits a trimmed reason of at least three characters and refreshes related queries.

Saved views omit the drawer ID. A trimmed nonempty name replaces a stored view with that name. The input permits 60 characters. Equality compares sorted serialized search entries. Storage failure can still produce success feedback. Views belong to browser storage, not the organisation's server account.

## Evidence components

`EvidencePage()` has no props. It requires query/router providers and a browser DOM. The component displays server results and performs no independent cryptographic verification.

### URL state and requests

| Input or query | Contract |
| --- | --- |
| `period` | URL text converted to a number. Supported values are 30, 90 and 365. Other values use 90 |
| `show` | Raw URL ledger group. Buttons offer Everything, Decisions, Fixes, Detections and Sign-ins and access. The server rejects invalid groups |
| Report | `/api/evidence/report?days=DAYS&summary=true`, keyed by period |
| Ledger | `/api/evidence/ledger?limit=50` with optional group, keyed by group |
| Current exceptions | Shared summary query, independent of the report period |
| Ledger context | Shared jobs and assets queries supply optional subject labels |
| Signing material | Public-key query supplies fingerprint and verifier hash, with infinite stale time |

Period and category controls replace history, preserve other URL fields, and preserve scroll. The period does not filter the ledger list. The report and ledger can describe different request times. The download creates another snapshot.

Main report and ledger failures expose retry. The ledger keeps previous data during category changes without a dedicated stale-data indicator. Counts and rows can temporarily describe the previous category. Optional summary/job/asset failures omit context without a dedicated error panel.

### Report display

Statuses use `met`, `not_met` and `no_activity`. A met control with a truthy exception count uses warning styling. Unknown statuses use the not-met style. Aggregate counts still use the raw status. These indicators do not independently certify a framework requirement.

Mean resolution time displays `n/a` for null, `under a day` below one, otherwise the supplied day value. It describes included finding resolutions, not necessarily successful remediation jobs.

Fewer than five resolved findings triggers a sample-size note. Current Fix now and silent-host counts come from the summary query. A failed summary query defaults both to zero. The absence of this warning does not prove that the current fleet has no exceptions.

The overdue link selects open, overdue findings and disables Fixable only. Results are current and can differ from the report snapshot.

### Ledger and downloads

The ledger displays at most 50 newest matching events across its whole history. Its total is the matching count before that limit. An empty category does not imply an empty organisation ledger.

An empty server `problems` list produces the integrity-status message. Server checks can reuse a verified prefix for up to one hour. A nonempty list displays only its first five problems. The pack endpoint checks integrity before signing and rehashes its exact period entries.

Subject text uses selected event strings, deduplicates them, and falls back to the first eight subject characters. Optional cached asset/job labels can add a hostname. Remediation events link to their job anchor. Highlighted failure kinds use a regular-expression heuristic. Neither label nor colour independently proves an outcome.

Pack and verifier downloads use native links. HTTP or download errors do not appear in component query errors. The public-key query exposes retry but stays fresh indefinitely after success. Key rotation can require a reload or explicit query invalidation before new signing material appears.

The pack omits its verifier. Fingerprint and verifier-hash text can be copied with the shared copy control. A separate trusted channel remains necessary to establish the key and verifier identity.

## Remediation components

| Export | Inputs and behavior |
| --- | --- |
| `RemediationPage()` | No props. Reads jobs, user, and assets. Groups jobs and controls approval/cancellation dialogs |
| `KbFleet()` | No props. Reads cumulative groups. Opening a row enables its KB/product host query |
| `JobCard({job,onApprove,onCancel})` | Displays typed job data. Optional parent callbacks expose eligible actions through the client admin gate |
| `ApproveDialog({...})` | Controlled view. A null job closes it. Parent callbacks control open state and submit approval |
| `PlanFixButton({...})` | Sends one batch-plan request for the supplied action and asset IDs |

The jobs query polls every three seconds while an approved, dispatched, or verifying row exists. Planned-only data does not trigger polling. Polling is not a push subscription. Job reads can also [commit server timeout changes](remediation-jobs.md#timeouts-and-dispatch).

Approval/cancellation success refreshes `jobs`, `summary`, `ledger`, and `kb-fleet` query groups. Query and mutation errors appear locally. The cumulative summary renders nothing while data is pending or empty. Its errors provide retry. Host detail loads only for an open row.

Job cards display package scope for planned jobs. They offer parent approval/cancellation actions only in permitted display states. An aborted dependency refusal can create a replacement plan directly. Normal retry uses `PlanFixButton`. Neither path approves the new plan.

The `Sent to host` and `Job succeeded` labels describe stored job state. They do not establish current host execution or complete finding resolution. A Windows step can succeed before the final fix. The [job reference](remediation-jobs.md#states-and-verification) defines those states.

### Approval dialog props

| Prop | Meaning |
| --- | --- |
| `job` | Null, or summary/hostname with optional package, manager, and forward-only metadata |
| `onOpenChange` | Parent callback for requested dialog state |
| `onConfirm` | Parent submission callback. The dialog itself makes no request |
| `pending` | Optional flag that disables confirmation |
| `error` | Optional parent error text |
| `ownPlan` | Optional self-approval information |
| `context` | Optional host-context text |

Forward-only wording covers application installers and servicing-stack changes. The confirmation records acceptance through the parent's request. The component does not independently verify rollback capability or policy eligibility.

### Batch planning props and results

`ecosystem` and `pkg` identify the action. `assetIds` is sent unchanged. The server deduplicates and validates it. There is no equivalent client count or empty-list check in this button.

`hosts` defaults to `assetIds.length` and affects accessible text only. `label` defaults to `Plan fix`. `className` customizes the wrapper.

Any per-asset errors produce one message with duplicate error text removed. Jobs created for other assets remain created. Success or failure refreshes job-derived queries. Full success navigates to Remediation, with the first job's anchor when present.

Navigation checks whether the current pathname equals its value at click time. Query/hash changes do not affect that test. A user who leaves and returns to the same pathname can still be navigated. The button creates plans without approval or execution.

## Display helpers

| Helper | Contract |
| --- | --- |
| `jobPackages(j)` | New array of package objects with a string `name`. Non-array input returns empty. Other fields remain unvalidated and objects are shared |
| `stepState(s)` | False `ok` means failed. Otherwise fallback wording means recovered, else passed |
| `machineContext(a)` | Hostname, criticality, ring, sandbox, and health-unit text. Absent asset returns undefined |
| `plainRefusal(error)` | Dependency-refusal explanation for recognized text, otherwise null |
| `filterAssets(assets,text,on,crit,sort)` | New filtered/sorted array with shared asset objects |

Recovered-step wording uses a case-insensitive search for `not available`, `rebuilding`, `rebuilt from`, or `retry` followed by a number. This is a display heuristic. It does not inspect host execution independently.

Dependency parsing uses case-sensitive `would also change:` text. It reads until newline or semicolon, splits commas, trims names, and removes empty entries. It does not deduplicate or validate package names. The raw report remains available.

Asset search is a case-insensitive substring across hostname, OS name, and agent version. Selected filters combine with AND. Criticality is an optional exact match. Name order uses locale comparison. Seen order uses ascending timestamp text. Urgency uses priority counts weighted by one billion, one million, one thousand, and one, with hostname ties.

These helpers perform no requests and preserve input array order. They assume typed nested values. Invalid filters or malformed values can throw. Package objects and asset objects remain shared with callers.

## Request and query helpers

`api<T>(path,init)` uses browser `fetch`. It expects a same-origin path but does not refuse absolute or cross-origin URLs. Browser defaults determine credential handling. The helper supplies no timeout, abort signal, retry, or independent origin check.

Only truthy bodies are sent. Strings pass verbatim; other truthy values use `JSON.stringify`. False, zero, empty text, null, and undefined send no body or JSON header. Serialization failures also become `ApiError` with status zero. That status does not establish a network failure.

Non-success HTTP responses become `ApiError` with the response status. Detail text uses a string `detail` or the first validation message and its last location field. Other shapes use generic status text. HTTP 204 returns undefined. Other successful responses must parse as JSON.

`ApiError(status,message)` preserves both arguments without validation. Its inherited `name` remains `Error`. UI error handling uses `instanceof`, not that name.

| Query | Key and endpoint |
| --- | --- |
| `coverageQ` | `coverage` → `/api/coverage` |
| `jobsQ` | `jobs` → `/api/remediation/jobs` |
| `kbFleetQ` | `kb-fleet` → `/api/windows-updates` |
| `kbHostsQ(r)` | `kb-fleet`, KB, product → KB detail with encoded product query |
| `settingsQ` | `settings` → `/api/settings` |
| `meQ` | `me` → `/api/me`. Five-minute stale time, retry disabled |
| `aiStatusQ` | `ai-status` → `/api/ai/status`. Five-minute stale time, retry disabled |
| `summaryQ` | `summary` → `/api/summary` |
| `assetsQ` | `assets` → `/api/assets` |

These definitions build query options rather than subscribe or fetch by themselves. Caller/provider options govern other cache and retry behavior. `kbHostsQ` encodes product text but interpolates the KB directly. Query response types do not perform validation.

`refresh(qc,what)` invalidates query prefixes and returns a promise for all invalidations:

| Change group | Invalidated prefixes |
| --- | --- |
| `jobs` | jobs, summary, ledger, kb-fleet |
| `findings` | findings, finding, summary, ledger |
| `assets` | assets, findings, finding, summary, ledger, jobs, kb-fleet |
| `people` | users, api-tokens, enroll-tokens, ledger |

This helper does not replace cached data itself. It does not invalidate unrelated prefixes such as coverage or settings. QueryClient behavior determines active refetches and errors.

## Findings URL and AI helpers

`parseFilters(raw)` accepts string-valued search data. It copies query, asset, and drawer ID text unchanged. Priority names are case-sensitive and untrimmed. Repeated recognized priorities remain repeated.

| URL key | Default and interpretation |
| --- | --- |
| `q`, `asset`, `f` | Empty text. `f` becomes the open drawer ID |
| `priority` | Empty list. Comma-separated recognized priority names |
| `fixable` | True unless exact `0` |
| `kev`, `overdue` | True only for exact `1` |
| `status` | `open`. Other accepted values are `resolved` and `accepted` |
| `sort` | `score`. Other values are `package`, `host`, `vuln`, `newest` |
| `group` | Empty. Other values are `vuln` and `package` |

Unknown enum values fall back. Unrecognized keys are ignored. Invalid runtime value types can throw.

`filtersToSearch(f)` returns an object with undefined default fields. It canonicalizes priorities to unique `fix-now,next,planned,low` order. This normalization is not an exact inverse for every raw URL. It does not URL-encode values itself.

`filtersToApi(f,list=true)` returns an encoded query. It always includes status. The default adds `limit=500`, `view=list`, and nondefault sort. `list=false` omits those controls. Asset becomes `asset_id`. False booleans, drawer ID, and grouping state are omitted. Priority order is preserved.

`looksLikeQuestion(t)` tests for a final question mark or at least four whitespace-separated tokens. `aiFilterToPatch(a)` always sets query, priority, KEV, and fixable values. Missing text/list becomes empty, and flags use truthiness. Only a recognized status is included. Missing/invalid status therefore leaves that field out of the patch. Duplicate valid priorities remain.

These helpers neither call an AI provider nor validate a complete AI response. The [AI reference](optional-ai.md) defines server/provider behavior.

## Formatting and recorded evidence

| Helper | Contract |
| --- | --- |
| `priorityOf(score,kev)` | KEV or score ≥75: fix-now. Scores ≥50: next, ≥25: planned, otherwise low. No range validation |
| `parseUtc(s)` | Append `Z` unless a UTC/numeric offset suffix exists. Invalid text produces an invalid Date |
| `relativeTime(s,now)` | English rounded elapsed time. `now` is Unix milliseconds. Invalid dates/nonfinite values can raise RangeError |
| `plural(n,one,many=one+"s")` | English-formatted count. Singular only for exact one |
| `pct(x)` | `<1%` below 0.01, otherwise rounded `x*100`. No range validation |
| `humaniseKind(k)` | Replace underscores, trim, capitalize first character. Preserve repeated internal spaces |
| `sbomSummary(r)` | Mapping/finding summary. Skipped equals components minus mapped, without validating consistency |
| `fixLabel(f)` | Nonnull recorded fixed version, otherwise ecosystem action or no-fix-recorded text |
| `whyMatched(f)` | Format recorded match text, with at most three advisory IDs. Do not re-evaluate evidence or compare versions |

Relative time uses fixed units: 30-day months and 365-day years. Under 45 rounded seconds displays `just now`. These are elapsed approximations, not calendar differences.

`updateSource(f)` describes reported Windows update facts. Explicit `wsus=null` selects Windows Update. Deferral-only facts produce no text. A success date beginning `1601-` means no prior install. Other dates use relative formatting. The function does not probe the host.

Agent labels use the server's classification. `updating` does not prove a newer channel-eligible release. `reinstall` can mean missing local capability or no served signed release. A failed self-test can delay retry for 24 hours. These labels do not predict a successful next run.

`groupJobs(jobs)` returns all configured groups with new arrays and shared job objects. Unknown statuses belong to no group. `isActiveJob(j)` selects approved/dispatched/verifying. `jobAnchor(id)` prefixes text with `job-` without encoding or validation.

`installCommands(origin,token)` returns curl, direct-Python, and PowerShell text without execution. Inputs must be a trusted server origin and generated token. The helper does not escape shell input or normalize URLs. Direct Python assumes the agent file exists. Environment assignments do not independently guarantee caller logging or process privacy.

## Browser hooks, announcements and saved views

| Interface | Behavior |
| --- | --- |
| `useTitle(title)` | React effect sets the product document title. No restoration on cleanup |
| `useHashScroll(ready)` | On mount/ready changes, decode the hash, scroll, and request focus. Missing targets are ignored without retry |
| `announce(text,assertive=false)` | Clear `live` or `live-alert`, then set text after 30 ms. Missing document/region is ignored |
| `themeChoice()` | Read light/dark from the document dataset, otherwise system. Do not read storage or media preferences |
| `setTheme(t)` | Update dataset and storage key `theme`. System removes overrides. Storage errors are suppressed after the DOM change |
| `savedViews()` | Read `nimstead:findings-views`, retaining only entries with string names |
| `saveViews(views)` | JSON-store data, then dispatch `nimstead-views`. Suppress serialization, storage and event errors |

Browser hooks require a DOM. Hash changes alone do not repeat the scroll effect. Invalid percent escapes can raise URIError. The caller must make the target focusable.

Announcement timers are independent and are not cancelled on unmount. An earlier message can appear during a later call's delay. Each page needs unique live-region IDs.

Saved views belong to the browser storage, without account scoping. Only names are validated; search data can be missing or malformed. Read/parse failure returns an empty list. A storage write can succeed even if the subsequent event fails.

## Enrolment components

`InstallCommands({origin,token})` renders the trusted command text through CopyBlock. It makes no network request or installation attempt. The Windows installer supplies its pinned runtime. A separate Python installation is not required for that route.

`Onboarding()` requires router/query context and reads the asset list and current role. A host-type choice enables the admin-gated enrolment-token request. Token text comes from mutation data. The component does not write it to browser storage.

After token creation, the asset query polls every three seconds while the tab is visible. A two-minute timer exposes troubleshooting. Query failures are not displayed by this component. Token request failures are displayed.

The final view uses total asset-count growth from the first observed list. An unrelated asset can trigger it, even before token creation. It does not prove that this token enrolled a host or that inventory arrived. The displayed instruction requires verification on Assets. The troubleshooting timer is cancelled during effect cleanup.

## Shared UI components

These components render trusted typed props. They do not validate API data or establish server permissions.

| Export | Props and behavior |
| --- | --- |
| `chip(on)` | Selected/unselected class string. No event handling or ARIA state |
| `PriorityPill({priority,count})` | Priority text/style and optional raw count, including zero |
| `StatusPill({status})` | Shared job label/style. Unknown runtime status has no label fallback |
| `Tag({children,tone,why,className})` | Tone defaults to muted. Why becomes title and hidden suffix, not visible touch help |
| `KevBadge()` | Static KEV explanation, without a feed check |
| `Loading({className,rows,label})` | Default one skeleton and hidden Loading label. Class applies to skeletons. Empty label suppresses hidden text |
| `Alert({error,prefix,className,id})` | Truthy string or Error message as an alert. Falsey input renders nothing |
| `Done({children,className})` | String text with check icon. Announce on mount/text changes without verifying success |
| `Notice({children,className})` | Bordered string text with the same announcement mechanism |
| `LiveRegions()` | Empty polite/assertive regions with unique IDs expected by announce |
| `Field({label,hint,error,children,className})` | Label, child, hint and error. Clone a valid element with replacement ARIA properties |
| `ErrorState({error,retry})` | Status-based lead, raw message, and a button invoking retry |
| `EmptyState({title,children,action})` | Title, paragraph-compatible child content, and caller-owned action |
| `CopyBlock({label,text})` | Selectable text and clipboard button. Success feedback lasts two seconds |

Loading row counts are not range-validated. Extreme values can fail allocation. Priority/status/style helpers assume supported values. Class constants supply presentation; an ARIA-disabled class does not itself prevent clicks.

Field replaces existing `aria-invalid` and `aria-describedby` values. Arrays/text children remain unchanged. Custom controls must forward the cloned props to their input. The component neither validates nor stores the field value.

`errorLead(error)` gives status-specific text only for ApiError instances: zero, 401/403, or ≥500. Other errors use generic load-failure text. It does not inspect the message to prove a cause.

Clipboard failure is suppressed without an error message. Text remains selectable. Copy timers are independent and not cleared on unmount. Repeated copy success can have overlapping feedback timers.

### Confirmation and focus contracts

`ConfirmDialog` takes controlled `open`/`onOpenChange`, title, description, confirmation label, and `onConfirm`. Optional props add children, pending/cancel labels, destructive styling, pending state, and error feedback.

Confirmation invokes the callback without awaiting it or automatically closing the dialog. Pending disables confirmation only. Cancellation remains available and requests a parent state change. The parent owns requests, result handling, and cancellation consequences.

`useReturnFocus(initial?)` supplies Radix open/close autofocus handlers. It remembers the active opener and requests focus on an optional initial element. Closing requests focus on a still-connected opener. Otherwise Radix handles the fallback. Hidden, disabled, or unfocusable targets can prevent the intended focus result.

## Related

- [Remediation jobs and policy](remediation-jobs.md)
- [Developer commands](tooling.md)
- Source: [`settings.tsx`](../../web/src/settings.tsx), [`remediation.tsx`](../../web/src/remediation.tsx), and [`planfix.tsx`](../../web/src/planfix.tsx)
- Shared transport and queries: [`lib.ts`](../../web/src/lib.ts)
- Asset filtering: [`assets.tsx`](../../web/src/assets.tsx)
- Shared components: [`ui.tsx`](../../web/src/ui.tsx)
- Enrolment view: [`onboarding.tsx`](../../web/src/onboarding.tsx)
