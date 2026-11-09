# Documentation compliance audit

Status: in progress. Documentation presence and correct folder names do not establish Diataxis or Code Documenter compliance.

## Scope and conventions

The audit covers tracked repository documentation, public Python and web interfaces, and the published wiki. Use existing Markdown, Python docstrings, and JSDoc conventions. The user requested the whole repository without exclusions. Legal and governance text keeps its purpose; historical plans remain historical, with links that distinguish them from current instructions.

## Requirements and evidence

| Requirement | Current evidence | Remaining work |
| --- | --- | --- |
| One primary reader job per maintained page | Reviewed both tutorials and the operational guide corpus; revised backup, Group Policy, upgrade, release and recovery procedures | Review every remaining page and root entry point; finish the remaining reference and root-document reviews |
| Safe tutorial with visible success | Both SBOM Python examples executed and matched the documented output; SBOM doctest passed | Worked example, filter and case record verified in the public product |
| Task prerequisites, ordered actions, warnings, recovery and verification | Revised three operational guides; retained secrets, rollback and rollout boundaries | Check each other guide against source and its operational environment |
| Complete, scannable reference | Existing API reference admits missing response schemas | Review parameters, limits, defaults, errors and completeness against implementation |
| Explanations develop understanding | Moved channel eligibility and recovery implications out of task narratives | Review every explanation, including Pulse |
| Reader-first and STE-style English | Revised procedures have shorter steps and separate conditions | Review remaining prose; preserve technical names and uncertainty |
| All public interfaces documented accurately | Presence checker reports 632/632 declarations. The module ledger records semantic review scope | Inspect remaining parameter descriptions, return contracts and exceptions; presence alone is insufficient |
| Examples tested | SBOM tutorial and doctest passed with standard-library parser | Inventory all code fences and doc examples; execute safe examples and validate environment-dependent procedures appropriately |
| Repo and site agree | Static build passes internal links and anchors | Publish reviewed changes after content verification, then inspect live pages |
| Coverage report | docs/reference/documentation-coverage.md describes measurement limits | Refresh final coverage and record contract/example verification separately |

## Current findings

- `docs/install.md` is now a task directory with its original anchors. Unique runtime, scheduling, diagnostics, proxy, health-check and measurement details moved to focused guides or reference.
- Release publishing and key recovery now have separate task guides. CONTRIBUTING links to the release task; release-key reference contains exact raw public keys and links to recovery procedures.
- `docs/how-to/upgrade-server.md` contained a time-sensitive claim that no stable release exists. Removed that claim; readers check the actual available target.
- The checker now inventories tracked and unignored repository Markdown, including nested documentation, HTML links, reference definitions and same-page anchors. Web export scanning is recursive. Sandbox public-entry contract review still needs completion.
- A failed copy during backup must not leave feeds stopped. The revised procedure includes restart on failure and rejects incomplete backups.

## Verification performed

- `python3 scripts/check_docs.py`:630 declarations, zero undocumented declarations, zero local link problems at this checkpoint.
- `npm --prefix docs-site run build`:53 articles and valid internal links/anchors.
- `PYTHONPATH=api/src python3 -m doctest api/src/nimstead/sbom.py`:passed.
- Both examples in `docs/tutorials/first-sbom.md`:executed parser calls and asserted their complete documented outputs.
- Upgrade flags, checkout restrictions and timer schedule compared with `deploy/update.sh`.

No production upgrade, backup, restore or fleet rollout was executed during this audit. Those procedures affect real systems and need an isolated validation environment.

## Continuation checkpoint

The task-guide and reference migrations were published from commit fc02cd8 and verified on docs.nimstead.systems. Both release-key values match the agent source. XCCDF parser docstrings now describe several previously implicit parameters and refusal results. The broad parameter-name scan found many more contracts that need semantic review; it included nested helpers, so it is a review queue rather than a public-interface failure count.

The isolated Python environment at `/private/tmp/nimstead-doc-validation` has uv, cryptography50.0.2 and cvss3.6 installed. Both risk and SBOM doctests passed. A release manifest signed by an ephemeral in-memory Ed25519 test key passed the agent verifier; a modified manifest was refused. No production key was used.

Remaining work: finish parameter/error contract audit, strengthen whole-repository checker scope, review all reference and root records, finish remaining example and public-contract verification, run final prose/STE-style checks, publish and inspect the resulting site. The goal remains active.

## Contract and example verification checkpoint

- Office feed/public lookup contracts reviewed against implementation. Docstrings now identify inputs, return shapes, transaction ownership and propagated failures.
- DNS TXT lookup documents its failure suppression, resolver transport and timeout. Domain ownership lookup names its organisation and domain inputs.
- Whole-tree link regression tests pass, including duplicate and same-page heading cases.
- Five documentation tests pass, including 43 shell syntax subchecks and both SBOM tutorial executions. Shell syntax checks do not execute deployment, installation or release commands.
- The locked Python 3.14 API environment is `/private/tmp/nimstead-api-doc-venv`; 59 locked packages installed successfully.
- 44 targeted Office, SSO and documentation tests passed before the added shell/tutorial subchecks. All API/agent/tool doctests passed (two executable doctests).
- `create_app('sqlite://').openapi()` produced OpenAPI 3.1.0 with 83 operations and 31 schemas. Endpoint/authentication/response completeness still requires the reference audit.
- Ruff passed with the API project's configuration. An initial invocation from the repository root used different inherited rules; no unrelated style rewrites were applied.

This remains an incomplete compliance assessment. The task and reference improvements were published independently of the remaining contract audit.

## Endpoint reference checkpoint

The endpoint catalog now lists all 83 schema operations with handler links and authentication entry requirements. `scripts/export_api_docs.py` produces the catalog and OpenAPI JSON. CI checks both for freshness. The export supplements FastAPI request/response definitions with relative-server and authentication metadata; it does not change authentication behavior.

Redocly CLI validation with the minimal ruleset passes without warnings. Tests cover cookie-only admin writes, optional read tokens on eligible GETs, agent keys, upload alternatives and enrolment body-token labeling. Six documentation tests and six site tests pass. The build contains 54 articles.

Empty dictionary response schemas remain an explicit reference limitation. This catalog does not claim field-complete response models. Public callable parameter/error review and Pulse workflow verification remain active.

## Pulse verification checkpoint

Reviewed the nine Pulse pages against the public product and temporary source checkout 968e465c2ea55375733beb8ea41118a05677a1bc. The parser source is `src/lib/snapshot.ts`; the file-picker byte limit is in `src/views/Watchlist.svelte`.

Playwright verified the 14-CVE worked example, single-CVE filter, case record, text-file analysis, missing-ID coverage, snapshot download/import, same-day comparison, full-list handover despite filtering, Clear/Undo, reload reset, and rejection of an unsupported snapshot version. Test input contained two public CVEs and one nonexistent test ID. The observed analysis made only the five shared index GET requests; selected IDs were absent from the URL.

The snapshot reference now defines root/source/finding fields, ranges, cross-field constraints, byte and character limits, and import behavior. Its example is a public-only downloaded snapshot. The actual Pulse parser accepts it, discards extra properties, and refuses wrong versions, empty lists, duplicate IDs and out-of-range scores. Self-comparison reports no changes and handover preserves all IDs.

In the disposable Pulse checkout: Node 22.22.2, locked dependency install, 22 tests, Svelte/TypeScript checks, complete public-data generation and production build passed. The build also passed six report/sitemap checks. No Pulse source was changed or deployed. npm reported two low-severity dependency advisories; dependency remediation is outside this documentation change.

The description-download implementation was inspected; the 40 MB live download was not repeated. Privacy evidence combines observed analysis requests with the implementation, not an assertion about every possible browser environment.

The documented Pulse development server also started successfully. Playwright verified its worked example against the locally generated public data. The wiki example download and mobile snapshot reference passed browser checks.

## Evidence contract checkpoint

The semantic review now has a [module ledger](CONTRACT-REVIEW.md). Evidence, offline verification, key storage and MFA were reviewed against source, with Office and SSO review evidence retained from earlier batches.

The evidence-report docstring incorrectly described `summary=true` as omission of ledger entries. The endpoint always returns an entry count; summary removes asset/finding arrays. The docstring, generated OpenAPI and field reference now match the implementation. A regression assertion checks both response modes.

The new evidence reference names ZIP members, root fields, nested finding/asset/control/ledger fields, every metric, and temporal caveats. A test checks that fixed fields emitted by real API responses appear in the reference. This does not claim every remaining response shape is complete.

This batch passed 27 targeted evidence/documentation tests, the evidence/key tests, all three executable docstrings, link checks and the 55-article site build. The full SQLite run passed 1611 tests with 59 skips; skipped cases do not establish fresh platform proofs.

A further temporal check confirms that finding `status` is current while `resolved_at` is limited by the selected period. The reference states this distinction explicitly. All 22 evidence tests passed after that addition. The refreshed OpenAPI export passed Redocly validation without warnings.

## Matching and priority checkpoint

Version, matching, risk and SBOM public contracts were reviewed against source. `clip` can return n+1 characters after its ellipsis. No-fix adjustment can lower a KEV score while retaining its 90-point floor. Those prose overstatements were corrected without changing behavior.

The version reference names every dispatched ecosystem, input/refusal behavior, supported matcher events, and the Alpine/Pub limits. The priority reference defines the generic formula and context adjustments, without treating the score as a probability or claiming every platform check uses it.

The SBOM reference now describes all six root response fields, including that `open` counts matching identities even when risk is accepted. The exported OpenAPI declares the raw JSON body, parser limits and successful counter response; it does not pretend to implement complete upstream SBOM schemas.

321 focused tests and 46 subchecks passed, including the accepted-count assertion. All six executable docstrings passed. Redocly validation passed without warnings. Remaining modules and endpoint responses still require review.

## Outbound request and optional AI checkpoint

Reviewed the public interfaces in `netguard.py` and `ai.py`, plus the AI HTTP handlers. The URL checker skips DNS and address validation for hostname URLs when `resolve=False`. It still checks literal IPs. The docstring now describes this distinction and the resolver timeout boundary.

Either Anthropic credential variable enables AI calls. The configuration reference now includes `ANTHROPIC_AUTH_TOKEN`. The new optional AI reference defines selected provider fields, truncation, cache behavior, filter defaults, quotas and errors. Selected text has no general hostname redaction. The configured model name also does not prove which provider fallback produced the answer.

43 AI and notification tests passed. New assertions cover token-only enablement, explicit disablement, search defaults and truncation, explanation field selection, and URL checks without DNS. Provider calls used a fake client. No credential or customer data was sent to Anthropic.

## Detection-engine checkpoint

Reviewed collection, content, evaluator, verdict model, reports, host/fleet paths, parity, database wrappers and CLI interfaces. The module ledger records the scope. Engine network interfaces remain pending.

Added reference pages for inventory/collection metadata, grouped scan reports, and fleet path fields. Expanded the outcome reference to cover every current reason code. These pages define lookup contracts and link to the existing confidence explanation and troubleshooting procedure.

Corrected several broad claims. The install mapper excludes language/SBOM installs handled separately. Collection source entries are closed, but root extra keys are accepted. Content models share nested data, and their identifiers do not retain a full replay archive. The scan-report GET can persist a record and commit the session.

New assertions compare actual report and fleet field names with their references. They also exercise collection root/source boundaries, the agent-loader round-trip limit, shared content mutation, ordered verdict hashes, and numeric-zero omission.

105 focused tests and 46 subchecks passed. Two Windows PowerShell parsing cases were skipped on this host. The 61-article build and six site tests passed. The pending endpoint response and remaining module audits still prevent a full compliance claim.
