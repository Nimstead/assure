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
| Complete, scannable reference | Source-backed field references and selected exported response schemas. Remaining dictionary responses still lack complete schemas | Review remaining parameters, limits, defaults, errors and completeness against implementation |
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

## External and network checkpoint

Reviewed `external.py`, `engine/network.py`, external-target HTTP handlers and both target UI components. The normal scanner and network evaluator now have separate reference pages. The external-target task guide keeps its ordered UI procedure and links to those lookup details.

Corrected pre-packet proof and strict-deadline claims. DNS and address-proof requests precede service checks. Network budgets can overrun before an endpoint is marked timed out. The network content identifier also omits rule bodies and predicates.

The reference documents the normal scanner's absence-based resolution rule, including filtered ports and unavailable TLS observations. Accepted findings remain accepted when observed but can resolve when omitted. It also describes the network web check's current not-vulnerable result after an absent HTTP response. These are implementation limits, not new guarantees.

The exported OpenAPI now includes the four-field external-scan response. Tests cover accepted counters, omission-based resolution, scope refusal before service-prober creation, incomplete web responses, rule-hash limits and documented response fields.

40 external/network/documentation tests and 46 subchecks passed after generated files were refreshed and loopback tests received socket permission. All six executable docstrings passed. Ruff, Redocly and the web TypeScript check passed. The locked web dependency install reported no vulnerabilities. Node22.22.2 satisfies its dependency engine requirements. No public target was scanned.

## Release and platform checkpoint

Reviewed public update discovery/cache, lifecycle, Microsoft mapping, driver matching and signing-tool contracts. Reviewed the agent's signature/channel/update entry points as a named subset. Other agent interfaces remain pending.

The release-key reference now defines signed fields and separates the server's signature check from the agent's field validation. Added platform-update and lifecycle lookup pages. The platform reference now describes Microsoft track inputs and exact-hash driver matching. Offline configuration now names required runtime archives.

Corrected cache fetch, missing-signature repair, runtime-version, strict key-list and whole-update rollback implications. The manifest relay and four public distribution files now have exported response contracts. Tests distinguish a signed JSON object from a valid agent manifest and check the verifier's text coercion of hash-shaped values.

New cache and lifecycle cases cover unverified cache metadata, stored-before-verification bytes, older cached runtime versions, duplicate cycles and date-shape-only validation. These assertions preserve current behavior while preventing inaccurate documentation claims. The audit does not certify vendor lifecycle dates or perform a production update.

418 focused tests and 46 subchecks passed. One Windows PowerShell parser test was skipped on this host. Seven executable docstrings, Ruff, Redocly, the 65-article build and six site tests passed. Signing tests use generated ephemeral keys. GitHub calls use fake responses, and actual update transport tests use loopback fixtures.

## Finding and database checkpoint

Reviewed all public scan persistence/coverage functions and database declarations/helpers. Reviewed finding list, detail, count, groups, CSV and acceptance handlers. The reference separates persistent finding state from evidence-qualified engine verdicts.

Added complete finding row/group/filter/CSV and acceptance lookup material, plus a database connection/model reference. Corrected misleading tenant-key, plaintext-secret and immutable-model comments. The database reference explains explicit transaction ownership, defaults and JSON replacement behavior.

The export now describes full/compact/detail/group responses, count and acceptance results, and findings CSV. Real API responses match the documented/exported fixed field sets. Tests cover overdue=false, ignored grouped overdue, SQL LIKE wildcards, acceptance after resolution, retained timestamps and CSV formula-prefix guards.

A new regression confirms that feed absence can resolve an identity while its package remains installed. Another confirms that rescan commits other caller-session changes. SQLite checks verify constructor/insert defaults, foreign keys, explicit commit and JSON mutation behavior.

106 focused tests and 46 subchecks passed, with two Windows-only parser skips. Seven executable docstrings, Ruff and Redocly passed. The site builds 67 articles and its six tests pass. PostgreSQL migration behavior is not newly established by the SQLite-specific checks. Remaining modules, response contracts and final editorial review still prevent a full compliance claim.

## Notifications and Windows checks checkpoint

Reviewed notification delivery, consent, retries and silent-host monitoring, plus Windows configuration and bundled-baseline evaluation. Added separate lookup pages and expanded the related API response schemas. The alert task guide now includes the consent button and a procedure for requesting another confirmation.

Corrected claims about durable queueing, retry age, redirect errors, null configuration values and manual baseline results. A test acknowledgement can occur without destinations. Recent delivery state uses only five rows. Windows checks can report default-policy problems from missing values. Baseline manual counts do not represent evaluated rules.

190 focused tests and 46 subchecks passed. Ten Windows-only parser checks were skipped. Executable docstrings, Ruff, Redocly, the 69-article build and six site tests passed. Repository coverage reports 632 declarations, none undocumented, and no local link problems.

Playwright MCP verified readable selected-product navigation in both themes, backup search ranking, query/filter restoration, mobile section anchors and source applicability. SMTP delivery and native Windows collection were not exercised. Other modules, response contracts and the final editorial review remain pending.

## Feed and Windows application checkpoint

Reviewed all public feed helpers and Windows application mapping/conversion interfaces. Added separate lookup pages for source selection, commit boundaries, counts, refusal rules, range conversion, and historical rule evidence. Reviewed the evidence generator without changing its generated data.

Corrected atomic-update and universal-error implications. OSV batches and source stages commit separately. NVD CVEs without scores retain old scores. A rejected NVD record does not remove existing v5 fallback rows. A translated NVD product removes all fallback rows for that CVE. The v5 platform test is a substring search, not a strict platform allowlist.

454 focused tests and 46 subchecks passed. New tests verify partial commits, unrelated session commits, retained scores, fallback precedence, permissive platform text, response fields and historical mapping reproducibility. Ruff, repository link/presence checks, the 71-article build and six site tests passed. No live feed update or Windows installation was performed.

The references received neutral prose and STE-style checks. Remaining remediation, agent, web, tool and endpoint reviews still prevent a full compliance claim.

## Remediation checkpoint

Reviewed every public remediation helper and its planning, canary, scheduling, report, verification, fleet and step-selection implementation. Reviewed related job, agent report, Windows update and policy HTTP handlers. Added the complete job/policy lookup page and exported response schemas. Task and explanation pages retain their separate reader jobs.

Corrected universal rollback, exact canary pinning, host-opt-in dispatch, window-completion and finding-resolution claims. Forward-only changes exist. Non-KB canary proof can lack version evidence. Windows intermediate success can leave findings open, and its direct helper accepts an alternative build from any result-version value. Read operations can commit timeout changes.

153 focused tests and 46 subchecks passed. New assertions compare actual job, plan, policy, fleet and missing-host field sets with the reference/schema. They also verify boolean window hours, naive UTC requirements, closed-window cancellation delay and intermediate-success limits. Ruff, Redocly, repository presence/links, the 72-article build and six site tests passed.

Playwright MCP verified the reference, modes, task guide and explanation at desktop/mobile widths. Section anchors and search work without page overflow. The pending web review must also correct broad canary/automatic-change copy in `settings.tsx` and `assets.tsx` against these documented limits.

No production remediation, host restart or rollback was performed. Agent tests use controlled command runners. Remaining agent, web, tool and unnamed endpoint contracts, plus final editorial/example review, still prevent a full compliance claim.

## Web settings and remediation checkpoint

Reviewed every export in settings, remediation and batch-plan components. Reviewed asset filtering and selected shared request, role, job and invalidation helpers. Expanded JSDoc and added a developer-facing web client reference. The operator guide now uses the actual Remediation navigation label.

Corrected UI copy about automatic eligibility, canary gates, immediate execution, intermediate success, universal rollback, restart windows and cached release freshness. Forward-only wording now covers servicing steps as well as installers. Dependency-refusal text describes the report without independently asserting that no change occurred.

All 70 web tests, TypeScript checks and the production build passed with Node22.22.2. New tests cover partial batch errors/cache refresh and name-only package validation. Existing dialog expectations match the corrected controls. Playwright MCP verified settings and approval dialogs at desktop/mobile widths with local read-only API fixtures. It also verified the new reference, mobile anchors and search.

The 73-article wiki build and six site tests passed. The first build stalled during generated-directory cleanup. A process sample identified directory scanning. The generated output was preserved in `/private/tmp`, then a clean build passed. Source behavior was not changed to bypass the check.

No production Assure application was deployed or mutated. The repository contains the reviewed UI copy. Wiki publication includes its supporting reference and corrected operator guide. Remaining web exports, agent/tool contracts, unnamed API handlers and final editorial/example review remain pending.

## Shared web and enrolment checkpoint

Reviewed every public helper/type/query declaration in `lib.ts`, every shared component/hook in `ui.tsx`, and the enrolment view. Expanded the existing web reference with transport, filter normalization, formatting, storage, DOM, query, clipboard, confirmation and focus contracts. Added accurate JSDoc and corrected selected API-shape comments.

Corrected network-only status-zero claims, exact URL-inverse claims, calendar-unit wording, unconditional focus/clipboard feedback, agent retry/eligibility text and separate Windows Python prerequisites. Enrolment now describes asset-count growth without claiming that the intended machine reported inventory. The underlying count heuristic is explicitly documented.

79 web tests, TypeScript checks and the production build passed. New checks cover request serialization, falsey bodies, invalid JSON, priority normalization, invalid dates, name-only saved views, ARIA replacement, pending cancellation and unrelated asset growth. A 30-test API/documentation run and 46 subchecks passed, including agent-label precedence/eligibility limits. Ruff and whole-repository presence/link checks passed.

Playwright MCP used local fixtures to verify agent-group/retry wording, the Windows runtime instruction, silent clipboard refusal, asset-count completion wording, and desktop/mobile reference layout and anchors. No real enrolment token, clipboard write, host installation or production mutation occurred. The 73-article build and six site tests passed.

The remaining asset, home, findings, evidence, access/integration, auth and shell exports still need their own reviews. Remaining agent/tool/API and final editorial/example reviews also keep full compliance unproven.

## Assets and Fix first checkpoint

Reviewed every public Assets and Fix first export and their private helpers. Expanded the web reference with provider context, query failure limits, asset counts, mapping coverage, baseline groups, URL state, selection, callbacks and upload behavior. Added a how-to guide for changing asset context, with separate verification and recovery steps.

Corrected claims about universal cleanliness, attacker access, evidence-grade ceilings, completed Windows checks, restart resolution and immediate bulk-save success. Bulk feedback now says that requests were prepared and asks the operator to review results. A duplicated-hostname regression verifies that recommendations count asset identities.

Reviewed asset-list, coverage and directory HTTP handlers. Their documentation now describes mapping-only counts, organization-wide directory replacement, committed quota attempts, trusted source status, cross-domain short-name matching and timezone removal without conversion.

80 web tests, TypeScript checks and the production build passed. 331 focused API tests and 46 subchecks passed. Generated API freshness, Ruff and repository presence/link checks passed. The wiki builds 74 articles and its six tests pass. Playwright MCP verified desktop/mobile articles and local fixture UI, including delayed failed bulk requests and their error display.

No production asset, directory collector or Assure application was changed by browser verification. The complete CLI end-to-end suite was not rerun. Remaining findings, evidence, access/integration, auth and shell exports, plus agent/tool/API contracts and final editorial/example review, keep full compliance unproven.

## Findings web checkpoint

Reviewed both Findings exports and their private query, grouping, virtual-table, drawer, planning, acceptance and saved-view helpers. Expanded the developer reference with props, defaults, mutations, failures and partial-result limits. The triage how-to now includes acceptance, verification and recovery without duplicating API field lookup.

Corrected universal-cleanliness, resolution-causes-404, immediate-expiry and guaranteed-package-resolution claims. KEV absence now means that the vulnerability is not listed. A planned job now has an existing-fix label, without implying execution.

80 web tests, type checks and the production build passed. The acceptance test also checks the reassessment qualification. Repository checks report 632 public declarations, none undocumented, and no local link problems. The 74-article build and six site tests passed. Prose received the reference/how-to humanizer and STE-style passes.

Playwright MCP verified the revised drawer, acceptance qualification, KEV text, mobile layout and new task-section anchor. API requests used local fixtures and writes were refused. Production acceptance, remediation and the complete CLI end-to-end suite were not exercised. Evidence, access/integration, auth and shell exports, remaining agent/tool/API contracts, and final editorial/example review remain pending.

## Evidence web checkpoint

Reviewed EvidencePage and every private display/query helper. The developer reference now specifies URL defaults, independent period/category queries, stale data, optional context, native downloads, cached signing material and trusted response shapes. The export how-to includes downloaded-result verification and export/key recovery. The restore guide uses the current integrity-status text.

Corrected claims about every recorded event, fresh full-chain verification, fixed pack counts, empty organisation history and low-sample repair proof. Generated control evidence no longer promises universal dry runs, health checks or rollback. Inventory text states the implemented current report-timestamp condition. Calculations and authorization behavior remain unchanged.

80 web tests, type checks and the production build passed. 28 evidence/documentation tests and 46 subchecks passed. Existing assertions now check the qualified integrity and change-evidence text. Ruff, repository presence/links, the 74-article build and six site tests passed. The reference and how-to prose received humanizer and STE-style review.

Playwright MCP verified report/ledger separation, category URL state, period-specific download links, resolution sample wording and mobile layout with refused-write local fixtures. No production pack, signature, restore or remediation was created. The complete CLI end-to-end suite was not rerun. Remaining access/integration, auth/shell, agent/tool/API and final editorial/example reviews still prevent a full compliance claim.

## Access, integrations and authentication checkpoint

Reviewed all exports and private helpers in people, integrations and authentication modules. Added parameter/context/error contracts for QR, MFA, recovery-code, account, user, token, SSO, notification and authentication components. The developer reference separates lookup contracts from two new how-to guides: API token lifecycle and authenticator setup/replacement. Existing SSO and alert guides now describe saved-state behavior and delivery limits.

Corrected claims that QR secrets never leave the browser, invitations/tests prove delivery, every Fix now finding is KEV, or SSO password access always has confirmed alert delivery. Role promotion now states its session effect and distinguishes password-admin MFA. Auth reset acknowledgement preserves account-existence and delivery uncertainty.

81 web tests, type checks and the production build passed. 103 focused API/SSO/notification/documentation tests and 46 subchecks passed. The 76-article build and six site tests passed. Repository checks report 632 documented public declarations and no local link problems. New reference/how-to prose received humanizer and STE-style review.

Playwright MCP verified saved-domain verification without lost unsaved issuer edits, test acknowledgement without a settings save, mobile settings, both new task guides and their section anchors. All API writes used local fixtures. No identity provider, SMTP delivery, real credential creation, MFA change or production account was changed. The complete CLI end-to-end suite was not rerun. Remaining shell/entry, agent/tool/API contracts and final editorial/example reviews still prevent a full compliance claim.

## Shell, routes and checker checkpoint

Reviewed all shell exports, private hooks, command construction and route-entry configuration. Added reference contracts for identity failures, mobile tab changes, theme state, focus attempts, keyboard scope, query defaults, URL serialization and palette result limits. The triage how-to now includes palette steps. Help opens the public Assure wiki. Member messaging preserves access to personal account controls. Group hints count returned findings rather than hosts.

Reviewed every public documentation-checker function and the release runtime-download helper. Expanded their parameters, return values, write ordering and error contracts. The coverage report now links to recognition limits. The runtime helper checks initial URL prefixes and body hashes, without its own final-origin check or atomic writes. No tool runtime behavior changed.

81 web tests, type checks and the production build passed. Six documentation tests and 46 subchecks passed. Ruff passed under the repository's API configuration. Repository checks report 632 declarations and no recognized link problems. The site builds 76 articles and six site tests pass. Prose received reference/how-to humanizer and STE-style review.

Offline assertions verified retained earlier runtime output after a later mismatch, preserved previous bytes for the refused target, duplicate route counting and approximate fenced headings. No network download occurred. Playwright MCP verified member text, public Help, finding-row counts, application suggestions, failed-logout navigation and both mobile tab arrangements. API requests used local fixtures. The full CLI end-to-end suite and production session revocation were not exercised.

Every exported callable in the current web source now has a recorded semantic review. This does not complete the goal. Remaining work includes the agent's other public interfaces, API handler/schema gaps, API-export/XCCDF tools, remaining sandbox entry contracts, and the final root/reference/explanation/example audit. Browser fixture checks do not replace native-host or deployment evidence.

## API export and baseline authoring checkpoint

Reviewed both API-export functions and every XCCDF conversion function. Expanded inline contracts for parameters, result fields, parser dispatch, copied provenance, traversal, refusals, writes and propagated errors. The tooling reference now describes exact export/check behavior and its manually maintained schema limits.

Added a baseline conversion reference and a separate how-to for producing a candidate for review. Corrected broad whole-text and XML-validation implications. The builder reads only direct XCCDF 1.1 groups and first rule/check text. It can return an empty/partial table successfully. Supplied hash/regex labels are not verified. Runtime parsing and conversion behavior were preserved.

Executed all five new how-to command blocks against a local synthetic benchmark. Assertions verified source hash, automated/manual counts, collection JSON, preserved regex and omission of nested/additional rules. The shell-example gate now recognizes indented Bash/sh fences and removes their presentation indentation. 71 focused baseline/documentation tests and 53 subchecks passed. One PowerShell-only syntax case was skipped. Ruff, generated-file freshness and Redocly passed. Repository checks report 632 declarations and no recognized link problems.

The site builds 78 articles with valid local links/anchors and six passing site tests. Playwright MCP verified both new pages at desktop/mobile widths and their mobile section links without overflow. Prose received humanizer and STE-style review. No Windows assessment, upstream benchmark download or shipped baseline change occurred.

Every counted public callable in scripts/ now has a named semantic review. Remaining agent interfaces, API handler/schema gaps, sandbox/web helper contracts and final root/reference/explanation/example review still keep the goal open.

## Agent core, transport and dispatch checkpoint

Reviewed Linux collection/parsers, config read/write, request/proxy/lock helpers, runners, logging, diagnostics and CLI dispatch. Expanded their parameter, return, mutation and error contracts. Added a separate developer reference while retaining command lookup and operator procedures in their own pages.

Corrected reinstallation/enrolment identity claims. Direct enrolment creates a new server asset before later local validation/saving. Current installers invoke that path. Existing-host directory/remediation guides now preserve configuration and asset identity when changing local flags. Diagnostics no longer claims that no proxy selection means direct traffic. CLI help distinguishes absence of Assure reporting from manager network use. Uninstall output now states that ledger events remain.

Offline assertions verified retained package rows after a failed query, destructive config-save failure, retained process proxy, doctor success without a saved key, enrolment before local refusal, and serialization before a request. CLI help executed. The focused suite passed 138 tests and 53 subchecks, with six Windows-only skips. Its loopback update test initially hit sandbox socket restrictions, then passed with local-network permission. The real file swap and smoke collection used only an owned temporary agent and ephemeral test signing key. Ruff and repository presence/link checks passed.

The site builds 79 articles with six passing site tests. Playwright MCP verified the new reference and mobile diagnostic anchors without page overflow. Reference/how-to prose received humanizer and STE-style review. No production enrolment, host configuration edit, package change or agent release occurred.

The agent review remains partial. Windows/remote collection, optional scan internals, job classes and remaining schedule/security/update helpers still need named completion. API gaps, sandbox/helpers and final editorial/example review also remain open.

## Application scans, scheduling and cleanup checkpoint

Reviewed all optional Java/Python/npm metadata scan helpers and their private traversal/read paths. Added a developer reference with exact default globs, returned fields, ownership heuristics, exclusions and budget limits. Added a separate how-to for changing existing-host collection flags and verifying the report without another enrolment.

Corrected complete-scan, hard-deadline and link/mount exclusion implications. Java can skip bad archives while complete remains true. Application thresholds can apply after an entire folder. Direct install roots can bypass discovery exclusions. The reference distinguishes these limits from a negative assessment.

Reviewed filesystem checks, Windows state cleanup, schedule generation/installation and uninstall. Corrected guaranteed immediate execution and universal schedule/removal claims. Non-systemd Linux receives instructions without cron installation. Linux jitter is 15 minutes, Windows periodic jitter 30 minutes. Returned cleanup paths can remain after ignored errors. Operator guides now require verification and preserve configuration ownership/ACLs.

117 focused tests and 53 subchecks passed, with six native Windows skips. Temporary assertions verified skipped/missing archives with complete=true, direct-root mount-filter bypass, post-folder package truncation, non-systemd no-op, partial unit writes, ignored scheduler stop failures and selected cleanup paths still present. Commands used fake runners and owned directories. Ruff and repository presence/links passed.

The 81-article site build and six site tests passed. Playwright MCP verified desktop/mobile task/reference layouts and mobile anchors without page overflow. New prose received humanizer and STE-style review. No production scanner opt-in, scheduler, ACL, uninstall or agent release changed.

The previous publication returned success while old content remained live. Reapplying its exact saved version was followed by successful source-hash and new-page checks. Publication evidence therefore includes rendered content, not only deployment status. Remaining Windows/remote collection, job classes, other agent/API contracts, sandbox/helpers and final editorial/example review keep the goal active.


## Windows and remote collection checkpoint

Separated Windows helper lookup from the operator remote-scan procedure. The new reference documents parameters, returned rows, temporary files/hives, collection status and failure boundaries. The procedure now identifies prerequisites, ordered actions, report verification, cache preservation and recovery.

Corrected exact client-product, guaranteed hive cleanup, universal partial-failure containment and complete driver-list implications. Remote collection uses multiple calls and skips offline profiles. Report keys are credentials cached locally. Missing or invalid cache JSON can cause another enrolment, while wrong-shaped valid JSON can abort the loop. Existing cache permissions are not repaired.

62 focused tests and 53 subchecks passed, with eight native Windows skips. Eight offline boundary checks passed and executable AST comparison confirms documentation-only agent edits. The site builds 82 articles with valid local links/anchors and six passing tests. Playwright MCP verified desktop/mobile lookup, task steps, local anchors and search. Prose received humanizer and STE-style review. The local preview required loopback permission after sandbox socket binding failed. No real Windows registry mount, remoting session, host enrolment or agent release occurred.

The whole-repository audit remains in progress. Remaining job classes, agent/API contracts, sandbox/helper interfaces and final editorial/example review still require evidence.


## Agent execution and recovery checkpoint

Added a developer reference for Linux package jobs, Windows application/settings jobs, cumulative update phases, report retries and restart requests. Updated the operator recovery procedure and conceptual safety page without mixing their primary reader jobs. Expanded source docstrings and removed unsupported exact-image, exhaustive dry-run and never-raises claims.

The contracts now distinguish preparation effects, command success, observed versions, selected service health, host recovery and server reporting. Aborted application/install paths can follow host changes. Undo closures exist only after successful handler completion. Linux applied results do not independently assert target attainment. Windows state can clear before terminal record creation. Saved outcome writes are non-atomic and sanitized filenames can collide.

181 focused tests and 53 subchecks passed, with two native Windows skips. Eight offline counterexamples passed. An initial API counterexample used a nonexistent job and returned 404. A real dispatched fixture then established HTTP 409 for the servicing state's unsupported failed outcome. The final documentation reflects its rejected-record disposition. No real enrolment, package operation or restart occurred. Executable AST comparison confirms documentation-only agent edits.

Repository checks report 632 public declarations, no undocumented declarations and no recognized link errors. Ruff, API export freshness, the 83-article build and six site tests pass. Playwright MCP verifies local desktop/mobile lookup, recovery steps, search and anchors. New prose received humanizer and STE-style review. Remaining unnamed agent/API interfaces, sandbox/helpers and final editorial/example review still prevent a whole-repository completion claim.


## Asset API response and retention checkpoint

Added a source-backed asset/inventory API reference. It separates common/host/external response fields and defines creation, context updates, deletion, enrolment, inventory retention, SBOM side effects and fleet summary fields. Added ten response schemas and route bindings to the deterministic export. The schema now contains 57 definitions for 83 operations.

Corrected cached agent-version ordering implications and low-level verifier error guarantees. Asset patch responses provide empty finding counts and default pause context. Missing/invalid facts can preserve older facts. Partial or empty declared Linux package coverage can preserve older package rows. SBOM uploads update last_seen but follow a different job-verification path. These limitations now appear next to their API contracts.

153 tests and 53 subchecks passed. The signed-update loopback test required network permission after a sandbox binding refusal. Four new API contract tests verify response fields and replacement/credential/evidence boundaries with temporary databases. Four agent-helper assertions verify message errors, subgroup-policy omission and numeric parsing. Executable AST comparison confirms app/agent behavior is unchanged.

Ruff, generated export freshness and repository presence/links pass. Redocly validates the schema with 27 warnings, principally undeclared 4xx responses and license metadata. The 84-article build and six site tests pass. Playwright MCP verifies the local reference, schema, search and mobile anchors without overflow. New reference prose received humanizer and STE-style review.

Other API handler/response gaps, sandbox/web helper contracts and final repository/site editorial and example checks still keep the objective open. Presence coverage and partial schema expansion do not establish full compliance.


## Authentication and account checkpoint

Added a lookup reference for account/session/token/MFA/SSO contracts. Corrected the confirmation-handler docstring: invitation completion establishes a member session, while signup/reset completion redirects to sign-in. The MFA task guide now treats response loss separately from an explicit validation refusal. It directs readers to inspect state and test the new authenticator before another change.

Reviewed credential precedence, transaction commits during reads/quota checks, pending-link replacement, setup state, role changes and revocation scope. Stored SSO domain verification survives removal of TXT records. SSO configuration PUT defaults can disable the integration when issuer is omitted. The reference makes those limits explicit and keeps operator procedures separate.

Added twelve account response definitions and branch/status bindings, plus shared 401/403 descriptions. The export has 69 definitions for 83 operations. Redocly validates with ten warnings, down from 27. These remaining declarations/metadata warnings are not treated as resolved by the successful validation result.

99 tests and 53 subchecks pass. Three new fixture tests verify published account fields, MFA/session branches, credential revocation, invitation sessions, saved domain verification and omitted-issuer behavior. App executable AST is unchanged. Ruff, export freshness and repository presence/links pass. The 85-article build and six site tests pass. Playwright MCP verifies desktop/mobile reference, downloaded schema branches, MFA recovery text, search and section anchors. Prose received humanizer and STE-style review. All mail/provider traffic used local fakes.

Remaining app helper/handler gaps, sandbox/web helper contracts and final whole-repository editorial/example review keep this objective active.
