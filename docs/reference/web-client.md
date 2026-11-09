# Web client reference

The Assure web client uses React, TanStack Router, and TanStack Query. TypeScript interfaces describe expected data. They do not validate API responses at runtime. This page defines the reviewed settings and remediation interfaces.

## Component context

Query components require a `QueryClientProvider`. Route links, navigation, and route hooks require the app router. Dialogs require a browser DOM. The application entry point supplies these contexts.

Client admin controls do not replace server authorization. `useIsAdmin()` returns true only when cached `/api/me` data says `admin=true`. Missing data produces false. `adminGate(false)` keeps a button focusable, marks it unavailable, and replaces its click handler. It must be spread after the button's own props.

`api<T>()` parses JSON without validating `T`. HTTP/network failures become `ApiError`; successful JSON parse failures can propagate separately. Rendering assumes typed shapes. Malformed dates, package fields, or nested values can cause render failures.

## Settings components

| Export | Inputs and behavior |
| --- | --- |
| `SettingsPage()` | No props. Reads policy and user queries, plus admin-only asset counts. Child sections own account/integration requests |
| `PlatformSection({p})` | `p` is `Settings.platform`. Renders cached version/channel/outcome text without requests or mutation |

Settings form values seed once per mount. A save in one section preserves edits elsewhere. Policy saves use `PATCH /api/settings`. Success replaces cached settings, resets only saved form fields, and invalidates the ledger. Errors appear beside the relevant control.

Mode selection alone does not save. Auto requires a separate confirmation. Its machine and canary counts describe the loaded fleet, not the number of fixes eligible for automatic approval. The server determines eligibility. Human-only fixes remain human-only.

The maintenance form uses the stored timezone, otherwise the browser timezone or UTC. It validates selected days, `HH:MM`, whole hours 1–24, and restart deadline 1–168. An empty organisation window clears the restriction. [Server window rules](remediation-jobs.md#maintenance-windows-and-policy) define inheritance and timing boundaries.

Platform display uses cache data without signature or freshness checks. A missing newer version means no newer release in that cached check. Unknown update outcomes display their raw text. Last-update messages are historical text, not live alerts.

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

## Related

- [Remediation jobs and policy](remediation-jobs.md)
- [Developer commands](tooling.md)
- Source: [`settings.tsx`](../../web/src/settings.tsx), [`remediation.tsx`](../../web/src/remediation.tsx), and [`planfix.tsx`](../../web/src/planfix.tsx)
- Shared transport and queries: [`lib.ts`](../../web/src/lib.ts)
- Asset filtering: [`assets.tsx`](../../web/src/assets.tsx)
