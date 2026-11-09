# Public contract review

This record distinguishes semantic review from docstring-presence coverage. A row marked reviewed covers the named module or subset, not unlisted modules. Types in signatures and model fields complement prose; failures and side effects need prose where they affect callers.

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `api/src/nimstead/evidence.py` | Public functions: deadline history, append, row conversion, integrity checks, checkpoints, keys, packs and periods | Compared implementation with docstrings and evidence-format field tables. Corrected transaction ownership, cached/full verification, key creation, and count/list variants. Evidence tests exercise signatures, tampering, policy history, checkpoints, partial periods and report counts | Reviewed |
| `api/src/nimstead/verify_pack.py` | All public verifier/hash/fingerprint functions | Reviewed required fields, canonical bytes, trusted fingerprint requirement, returned issue strings and exceptions from malformed input. Offline signature/tampering tests pass | Reviewed |
| `api/src/nimstead/keys.py` | Vault public methods and S3 entry points | Reviewed constructor/configuration, return encodings, propagated errors, no silent local fallback, COMPLIANCE retention and pagination. Fake-transit tests pass; real-service proofs remain historical STATUS evidence | Reviewed |
| `api/src/nimstead/mfa.py` | All public secret/code/verification/URI/recovery functions | Reviewed counter/time inputs, replay handling, secret decoding, nonpositive recovery counts and caller-owned persistence. Added an executable fixed-test-secret OTP example | Reviewed |
| `api/src/nimstead/office.py` | All public channel/feed/database functions | Inputs, return shapes, validation, transaction ownership and errors documented from source. Office tests passed | Reviewed |
| `api/src/nimstead/sso.py` | Public OIDC, secret and domain-ownership functions | Reviewed cached discovery/key lookup, caller-owned flow state, encryption tags and DNS failure suppression. OIDC/DNS tests passed | Reviewed |
| `api/src/nimstead/versions.py` | All public comparators, dispatch and sorting helper | Compared function bodies and parser helpers with accepted forms, failures and dispatcher table. Exposed Alpine/Pub limits. Dispatch, sorting and limit examples pass doctest; comparator fixtures pass | Reviewed |
| `api/src/nimstead/match.py` | Package/Match containers, clipping, ecosystem/ID normalization and package matcher | Corrected clipping budget and fixed-version candidate scope. Reviewed exact identities, supported event/range handling, deduplication and exception paths | Reviewed |
| `api/src/nimstead/risk.py` | Risk container, CVSS extraction, base score and context modifiers | Corrected no-fix/KEV claim, documented trusted inputs, missing-value defaults, empty role data and object reuse. Numeric examples and risk tests pass | Reviewed |
| `api/src/nimstead/sbom.py` | All public parse/load/package-URL interfaces and SbomError | Reviewed supported format markers, skipped values, version fallbacks, depth/count limits, nonmutation and error mapping. Clarified that full upstream schemas and HTTP size are separate | Reviewed |
| `api/src/nimstead/netguard.py` | All public URL/address checks, guarded transport and client factory | Corrected the resolve=False claim. Documented empty address results, literal-IP checks, development bypass, request mutation, client ownership and unbounded system DNS lookup. Refusal, pinning and resolver-mode tests pass | Reviewed |
| `api/src/nimstead/ai.py` | All public enablement/client, explanation and search interfaces | Reviewed credentials, cache keys, selected provider fields, truncation, local validation defaults and propagated failures. Corrected hostname-redaction implication and documented prompt-only output limits. Mocked tests pass without provider calls | Reviewed |
| `api/src/nimstead/engine/collection.py` | All public containers, inventory constructors, source status and install mappings | Reviewed shallow sharing, source validation and consistency, serialization boundaries, Linux grouping and separate language/SBOM mapping. Corrected claims about closed root fields and every-install coverage | Reviewed |
| `api/src/nimstead/engine/content.py` | Content container, make and load | Reviewed hash inputs, selected advisory scope, mutable nested data, failure and session-autoflush boundaries. Corrected deterministic-replay claim to include prior findings and evaluator code | Reviewed |
| `api/src/nimstead/engine/model.py` | Outcomes, grades, Verdict, serialization and absence predicate | Reviewed every field and defaults. Documented unvalidated construction, numeric-zero omission through equality, and absence predicate without finding mutation | Reviewed |
| `api/src/nimstead/engine/evaluate.py` | Public evaluator, including all branch/helper behavior | Reviewed inventory/content/prior inputs, no-inventory and unsupported-platform exits, sorting, evidence gates, lifecycle and kernel cases. Internal model failures propagate | Reviewed |
| `api/src/nimstead/engine/report.py` | digest, build and render | Documented ordered hashes, grouped fields, scope-limited headlines, nullable/count variants, text control replacement and display limits. Report-reference assertions cover emitted fixed fields | Reviewed |
| `api/src/nimstead/engine/paths.py` | build and render, with correlation helpers | Reviewed Windows-only scope, path/stage/way shapes, grade selection, display limits and caller-owned terminal escaping | Reviewed |
| `api/src/nimstead/engine/fleet.py` | build and reachability helpers | Reviewed stored-report/current-fact inputs, inferred edges, account/routing evidence, 2000-edge and 50-chain caps, shortest-hop selection and truncation semantics. Fleet-reference assertions cover emitted fields | Reviewed |
| `api/src/nimstead/engine/parity.py` | in_slice and compare | Reviewed ecosystem dispatch, deduplicated identities, explained/unexplained differences, count fields and meaning of ok | Reviewed |
| `api/src/nimstead/engine/__init__.py` | All public database/report functions | Corrected read-only implication: report storage can commit the caller session. Documented cache location, prior-finding timestamp selection, SBOM ledger shape and five-record retention | Reviewed |
| `api/src/nimstead/engine/__main__.py` | CLI main and input/output path | Reviewed positional inventory, database selection, JSON/text modes, exit behavior and SQLite setup caveat. Existing CLI tests pass | Reviewed |
| `api/src/nimstead/engine/network.py` | All public rule/budget/endpoint containers, Prober, evaluator, report, parity and run entry points | Corrected strict-deadline and pre-packet scope claims. Documented direct-call ownership boundary, rule-hash limits, observation errors, network report variants and incomplete web-response behavior. Local socket, fake-observation and reference checks pass | Reviewed |
| `api/src/nimstead/external.py` | All public ownership, network, classification, scan and rescore functions | Reviewed proof substring/ports/timeouts, selected address, current-clock TLS rules, commit/refusal paths, accepted counts and absence-based resolution. Added actual accepted/omitted-check regression coverage | Reviewed |
| `web/src/targets.tsx` | Both exported components and their props/callback/error behavior | Compared UI labels with the external-target task guide. Corrected DNS-only proof implication. TypeScript check passes with locked dependencies and Node22.22.2 | Reviewed |
| `api/src/nimstead/updates.py` | All public channel/version, status, discovery/cache, runtime and check functions | Reviewed one-page discovery, signature/field validation split, missing-signature cache behavior, cache-version runtime downloads, file limits and alerts. Mocked release/cache tests pass | Reviewed |
| `api/src/nimstead/lifecycle.py` | Row and all public mapping/parser/verdict/finding functions | Reviewed supplied-date warning rules, ESU fact trust, directory edition inference, cycle parsing limits and no-row semantics. Does not certify curated vendor dates | Reviewed |
| `api/src/nimstead/msproducts.py` | All public normalization and feed/host/Uninstall mapping functions | Reviewed full case-sensitive allowlists, source context, numeric normalization and candidate selection. Fixed module return-type description. Mapper tests and executable normalizer example pass | Reviewed |
| `api/src/nimstead/windrivers.py` | parse and findings | Reviewed verified-entry filtering, hash floor/deduplication, exact reported-hash lookup, row preservation, score constants and non-JSON Risk output. Feed/driver tests pass | Reviewed |
| `api/src/nimstead/scan.py` | All public coverage, identity, host-check and persistence functions | Corrected evidence-of-repair implication. Documented missing-source behavior, cache mutation, accepted counters, absence resolution, commit ownership and receipt digest scope. Actual API/storage tests confirm feed-absence resolution while packages remain | Reviewed |
| `api/src/nimstead/db.py` | All model declarations and connection/session helpers | Reviewed columns, defaults, keys, cascades, JSON storage and helper ownership. Corrected direct-org-id, plaintext-secret, immutable-ledger and exhaustive-state implications. SQLite tests verify foreign keys, explicit commits, defaults and JSON replacement | Reviewed |
| `scripts/sign_release.py` | All public runtime-pin, key, manifest and CLI functions | Reviewed canonical bytes, required metadata, optional runtime trust, key-file refusal/mode, and source-text key guard. Tests use generated ephemeral keys | Reviewed |
| `agent/nimstead_agent.py` | verify_release, release_channel, channel_ok, self_update and runtime_update | Reviewed signature versus schema checks, channel fallback, agent anti-rollback, runtime-before-agent ordering, bundled-only Python downgrade gate, side effects and error boundaries | Partial: other agent interfaces remain |
| `api/src/nimstead/app.py` | Finding read/group/count/CSV and acceptance handlers, plus all earlier named scopes | Reviewed every finding response/filter, historical-policy/current-priority deadline, group/detail fix selection, acceptance variants, quota commits and CSV fields. Exported schemas match actual response field sets | Partial: other handlers remain |
| Other production, agent, web and tool interfaces | Presence coverage exists | Semantic parameter/error review is not yet complete. Existing tests supplement but do not replace that review | Pending |

## Notification and Windows review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `api/src/nimstead/notify.py` | All public delivery, consent/account mail, retry, migration, flush and monitor functions | Reviewed synchronous lookup and Vault I/O, process-local queue, transport versus storage outcomes, redirect handling, per-attempt retry age, consent exclusion and monitor grace. Fake transport and database tests confirm limits | Reviewed |
| `api/src/nimstead/winbaseline.py` | All public bundle loading, host selection, registry identifier, applicability and evaluation functions | Reviewed shared cached data, ordered OS matching, type predicates, applicability overrides, automated/manual counts and result fields. Actual response fields match the reference and schemas | Reviewed |
| `api/src/nimstead/winconfig.py` | evaluate and reachable_listeners, including configuration/certificate helpers | Reviewed missing/default inputs, host context, Risk objects, certificate prerequisites and curated listener heuristics. Added missing-config and certificate gating checks | Reviewed |
| `api/src/nimstead/app.py` | Baseline list/detail/CSV and notification settings/test/consent handlers | Reviewed fixed responses, permissions, quotas, commits, consent proof and the five-row delivery sample. Other unnamed handlers remain pending | Partial |

This batch passed 190 focused tests and 46 subchecks, with ten Windows-only skips. Test transports do not establish production SMTP delivery or native Windows collector behavior.

## Feed and Windows application review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `api/src/nimstead/feeds.py` | All 17 public ingestion, conversion, update and CLI functions, with their helpers | Reviewed feed selection, source shapes, counts, skips, batch/session commits, rollback ownership, retries, buffer limits, optional guards and external/upkeep effects. Corrected atomicity and universal-error claims. Fake-feed tests verify partial commits and retained scores | Reviewed |
| `api/src/nimstead/winapps.py` | Product and all public identity/NVD/v5 functions, with conversion helpers and the full catalogue | Reviewed exact patterns, first identity selection, version mapping/refusal, major-branch bounds, CPE/regex limits and emitted fields. Tests confirm source precedence and permissive platform matching | Reviewed |
| `api/src/nimstead/winapps_evidence.py` | Generated EVIDENCE data shape and finding response use | Labels describe historical observations, not current compatibility or remediation guarantees. Regenerated values in memory match stored data | Reviewed |
| `sandbox/winapps_evidence.py` | identified, derive and command output | Reviewed recursive extraction, proof/version-change rules, file scope, curated filtering, precedence and generated destination. Documented public parameters/errors without rewriting the generated module | Reviewed |

454 focused tests and 46 subchecks passed. Feed requests used fake HTTP clients. No production feed database, historical run files or VM installations were changed.

## Remediation review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `api/src/nimstead/remediate.py` | All public classes/functions, constants and helper paths | Reviewed manager maps, plan/approval scope, KB selection, fleet fields, policy canaries, version pinning, timeout commits, window/DST inputs, host/group sequencing, report limits, finding verification and step fetch quotas. Corrected universal rollback, exact pinning and all-findings-resolved claims | Reviewed |
| `api/src/nimstead/app.py` | Job serialization/create/batch/list/approve/cancel, agent jobs/report, Windows update list/detail, policy GET/PATCH and asset-window update | Reviewed permissions, fixed fields, optional list fields, body/filter limits, per-asset commits, background step work and GET timeout effects. Exported response schemas match actual API fields. Other unnamed handlers remain pending | Partial |
| `agent/nimstead_agent.py` | Health/settle behavior referenced by remediation-mode prose | Compared Linux, Windows cumulative and Windows application/configuration checks. This is a named subset, not a review of remaining agent contracts | Partial |

153 focused tests and 46 subchecks passed. New checks cover the documented intermediate-success and canary-proof limits. Command-runner tests do not establish production rollback or restart safety.

## Web settings and remediation review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `web/src/settings.tsx` | All exports and private form/section helpers | Reviewed provider context, queries, one-time form seeding, policy PATCH/cache effects, local validation, role gates, independent child requests and cached platform display. Corrected Auto/canary/restart/freshness claims | Reviewed |
| `web/src/remediation.tsx` | All exports and private rendering/query helpers | Reviewed job grouping/polling, package field validation, heuristic step/refusal text, callbacks, parent-controlled dialogs, retry mutations, permissions and rendering errors. Corrected immediate execution, all-findings-resolved and installer-only forward-limit copy | Reviewed |
| `web/src/planfix.tsx` | PlanFixButton | Reviewed props, unchanged asset list, display-only host count, per-asset errors, partial success, refresh on settlement and pathname-only navigation guard. New partial-error test passes | Reviewed |
| `web/src/assets.tsx` | filterAssets and remediation help text | Reviewed filter/search/sort and shared-object behavior. Corrected unconditional ring gates and Linux-only service help. Other exports remain pending | Partial |
| `web/src/lib.ts` | api, role gates, job groups/queries/labels, dependency parsing and refresh | Reviewed typed-versus-runtime boundaries, query scope, no-op roles, invalidation groups and parsing limits. Other utilities remain pending | Partial |

70 web tests, type checks and production build passed. Playwright MCP used local fixture responses, rejected writes, and inspected desktop/mobile UI. The complete CLI end-to-end suite was not rerun. This evidence does not establish production application deployment or host execution.

## Shared web and enrolment review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `web/src/lib.ts` | All exported callables/classes, query definitions, display constants and UI-selected type declarations | Reviewed transport/error parsing, falsey bodies, status-zero serialization errors, filters/AI normalization, fixed elapsed-time units, scoring/formatting, DOM hooks, storage, live regions and invalidations. Corrected overstatements and nullable cached error type. Boundary tests pass | Reviewed |
| `web/src/ui.tsx` | All exports and internal helper behavior | Reviewed props/defaults, status styles, ARIA replacement, controlled dialog callbacks, pending cancellation, focus requests, announcements and silent clipboard errors. Types and new component checks pass | Reviewed |
| `web/src/onboarding.tsx` | InstallCommands, Onboarding, constants and effects | Reviewed trusted command interpolation, role/token request, polling, baseline count, timeout cleanup and query-error display limits. Corrected bundled-runtime prerequisites and count-growth proof claims. An unrelated application asset test verifies the limit | Reviewed |
| `web/src/assets.tsx` | AgentUpdateSummary, plus earlier named filter/help scopes | Reviewed reason grouping, combined version counts, link callback and invalid-state behavior. Corrected the assumption that every reinstall state means an old agent. Other exports remain pending | Partial |
| `api/src/nimstead/app.py` | agent_update_status, plus earlier named scopes | Reviewed classification precedence and absence of newer-version/channel proof. A fake served-version test verifies newer reported agents and missing-release states. Other unnamed handlers remain pending | Partial |

79 web tests and 30 API/documentation tests passed, with 46 subchecks. Browser checks used generated fixture text and intercepted all local API requests. Production application deployment, native clipboard behavior, host installation and the full CLI end-to-end suite were not exercised.

The full SQLite suite passed 1611 tests with 59 skips at the start of this batch. The later targeted evidence/key checks passed 23 tests. The new field/summary assertions subsequently passed in a 27-test evidence/documentation run. All three executable docstrings passed. Skipped platform/oracle cases are not newly verified real-host proofs.

The engine batch passed 105 engine/documentation tests and 46 subchecks. Two Windows PowerShell parsing cases were skipped on this host. Reference field assertions supplement the source review and do not prove every possible runtime value.

The subsequent external/network batch passed 40 tests and 46 subchecks, including real loopback proof and concurrency checks. No public target was scanned. Runtime behavior was preserved; the documentation now describes limits that earlier prose obscured.

The release/platform batch uses fake GitHub responses, ephemeral test signing keys and local update fixtures. No production release, key rotation or runtime rollout was performed.

The finding/database batch passed 106 focused tests and 46 subchecks, with two Windows-only parser skips. Actual response/reference checks cover full, compact, detail and group fields. New tests also verify SQL wildcard/overdue behavior, retained resolution timestamps, CSV guards, feed absence and caller-session commits. SQLite-specific model checks do not replace PostgreSQL migration validation.

## Assets and Fix first review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `web/src/assets.tsx` | All exports and private helpers | Reviewed provider/query context, filters, selection across hidden rows, independent optimistic saves, partial errors, Undo fields, mapping-only coverage, baseline groups, evidence grades, application secrets and raw SBOM uploads. Corrected bulk/restart/path/coverage claims | Reviewed |
| `web/src/home.tsx` | Home, ActionCard and private rendering | Reviewed query fallbacks, priority totals, eligibility filtering, asset identity counts, target selection and dependency/refusal limits. Duplicate hostname regression passes | Reviewed |
| `api/src/nimstead/app.py` | list_assets, coverage, agent_directory and unmanaged_computers, plus earlier named scopes | Reviewed permissions, payload fields, mapping counts, rate-attempt commits, whole-organization replacement, timestamp handling, short-hostname comparison and CSV limits. Other unnamed handlers and response schemas remain pending | Partial |

80 web tests and 331 focused API tests passed, with 46 subchecks. Playwright MCP held two fixture PATCH requests, verified prepared feedback before completion, then verified failed-result display. Mobile Assets, Fix first and wiki pages had no page overflow. This does not prove production application deployment, native collection or the complete CLI end-to-end suite.

## Findings web review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `web/src/findings.tsx` | FindingsPage, AcceptRisk and all private helpers | Reviewed URL debounce/AI race limits, independent query errors, virtual loaded rows, group-to-substring navigation, partial sequential plans, skipped acceptance count, drawer identity/shortcuts, active jobs, browser saved views and status effects. Corrected unsupported outcome claims | Reviewed |

80 web tests, type checks, production build, repository presence/links, 74-article build and six site tests passed. Playwright MCP verified local fixture drawer text and mobile task anchors. No production mutation or complete CLI end-to-end run occurred.

## Evidence web review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `web/src/evidence.tsx` | EvidencePage and all private helpers | Reviewed period/category URL state, independent queries, placeholder rows, status counts, low samples, current-summary fallbacks, download failures, infinite key cache, optional subject labels and cached server integrity. Corrected unsupported integrity/completeness claims | Reviewed |
| `api/src/nimstead/evidence.py` | Rechecked generated control evidence against existing metric predicates | Corrected report-timestamp and universal execution/rollback wording. Preserved statuses, metrics and signatures. Existing evidence tests include the revised authorization-evidence qualification | Reviewed |

80 web tests and 28 evidence/documentation tests passed, with 46 subchecks. Playwright MCP verified local fixture period/category requests and mobile layout. Native production downloads and complete CLI end-to-end execution remain unverified.

## Access, integrations and authentication review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `web/src/people.tsx` | All six exports and private helpers | Reviewed local QR encoding, code validation versus verification, callback/state lifetime, cached identity, password/session effects, role confirmations, invitation acknowledgement and displayed token lifetime. Added props, request and error contracts | Reviewed |
| `web/src/integrations.tsx` | SsoSection, NotificationsSection and domain/list helpers | Reviewed uncontrolled form remounts, retained edits, write-only fields, stored-domain verification, saved-state tests, one-shot refresh, errors and delivery uncertainty | Reviewed |
| `web/src/auth.tsx` | SignInPage, SignUpPage and shared state/error helpers | Reviewed server-selected branches, credential/MFA/recovery state, native SSO submission, reset acknowledgement, URL notices and trusted answer shapes | Reviewed |

81 web tests and 103 focused API tests passed, with 46 subchecks. Browser evidence uses intercepted fixtures, not real provider or email operations. Current API implementation supports these web contracts. Full remaining handler/schema review remains a separate requirement.

## Shell, route and checker review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `web/src/shell.tsx` | Logo, Shell, Palette and every private helper | Reviewed identity branches, callbacks, logout settlement, DOM observers, theme state, focus limits, mobile menus, debounce, partial results, row counts, ID selection and saved-view memoization. Corrected member/help/count/key labels | Reviewed |
| `web/src/main.tsx` | Mount, query defaults, all routes and search conversion | Reviewed missing root failure, public versus shell routes, lazy imports, not-found rendering, route search validators, duplicate URL keys and String serialization | Reviewed |
| `scripts/check_docs.py` | All public functions and internal traversal/recognition | Reviewed AST scope, duplicate counts, adjacent web comments, Git inventory, approximate anchors, recognized link forms, error propagation, report generation and write-before-failure order | Reviewed |
| `scripts/fetch_runtimes.py` | main and CLI entry | Reviewed pin lookup, sorted keys, initial URL prefix, redirects, memory reads, pre-write hashing, overwrite/partial-write limits, retained earlier output and propagated errors | Reviewed |

81 web tests, six documentation tests and 46 subchecks passed. Offline assertions establish the named checker/download limits. Playwright MCP verifies controlled local navigation and mobile behavior. All current web exported callables now have named review records. API-export/XCCDF tooling, agent/API and final editorial/example requirements remain open.

## API export and XCCDF review

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `scripts/export_api_docs.py` | render, main and all schema/catalog construction | Reviewed temporary app/client, direct-dependency authentication labels, manually selected schemas, omitted routes, deterministic ordering, source lines, exact freshness checks and non-atomic sequential writes | Reviewed |
| `scripts/xccdf_rules.py` | All 14 public functions, pattern maps and CLI paths | Reviewed numeric forms, regex labels, dispatch precedence, registry/audit/rights records, role reconciliation, byte-size/XML limits, direct-child traversal, provenance labels, collection-list deduplication, output writes and manual-success cases | Reviewed |

71 baseline/documentation tests and 53 subchecks passed, with one native PowerShell syntax skip. Five guide blocks executed against an owned local fixture and verified documented output boundaries. No production files, hosts or benchmark feeds changed. All counted public Python callables under scripts/ now have review records. This does not complete remaining application, agent, sandbox or editorial/example requirements.

## Agent core and CLI review

| Source subset in agent/nimstead_agent.py | Review scope | Status |
| --- | --- | --- |
| config_path, parse_os_release, ecosystem_from_os_release, parse_dpkg, parse_rpm, parse_apk, package_db, reboot_pending, collect_linux, collect | Reviewed exact ID mapping, permissive row shapes, source precedence, retained partial rows, empty-success status, injected callbacks, inventory fields and error boundaries. Windows collector internals remain separate | Named subset reviewed |
| load_config, save_config, winhttp_proxy, use_proxy, post, run_lock | Reviewed trusted config shape, process globals, truncate-before-serialization, retained proxy state, initial/default opener behavior, no redirects, request/response boundaries and advisory lock lifecycle | Named subset reviewed |
| sh, ps, wu, free_bytes, log_event | Reviewed runner effects/statuses, source-fragment replacement, ancestor failures, conditional logs, rotation/redaction limits and propagated exceptions | Named subset reviewed |
| inventory, with_apps, doctor, main, app_flags, app_roots and private dispatch/query helpers | Reviewed local opt-ins, shared-object mutation, all diagnostic predicates/callbacks, CLI argument/status paths, update handoff, enrolment ordering, optional directory reporting and setup side effects | Named subset reviewed |

138 focused tests and 53 subchecks passed. Six native Windows cases were skipped. Offline counterexamples establish the documented partial/failure limits. Loopback update exercised a temporary signed agent and a read-only smoke collection. No production key, enrolment, config file or release was changed. Remaining agent functions/methods retain partial status until their own review.

## Optional scans, scheduling and removal review

| Source subset in agent/nimstead_agent.py | Scope and verified boundaries | Status |
| --- | --- | --- |
| net_mounts, local_roots, scan_jars, package_owned, regular, scan_apps | Reviewed default/excess roots, partial ownership, all metadata readers, traversal/budget checks, output clipping, error suppression, shared source statuses, counters and locations. Counterexamples verify weak complete flags and bypassed discovery guards | Named subset reviewed |
| is_link, remove_link, secure_windows_dir | Reviewed current-entry checks, removal method choice, owner/ACL command ordering, recorded owner use, path checks, partial effects, ignored directory failures and cleanup result limits | Named subset reviewed |
| schedule_units, schedule_windows_script, schedule, uninstall and private command/quote/path helpers | Reviewed exact timers/triggers, trusted config quoting, lexical interpreter check, ignored status paths, sequential writes, config-version ordering, cron omission, pending-state refusal, deferred runtime removal and partial failures | Named subset reviewed |

117 tests and 53 subchecks passed, with six Windows-only skips. Offline filesystem fixtures verify the named failure effects without a real scheduler or ACL command. Native Windows registration, removal and security behavior remain unexercised here. Agent job classes, Windows/remote collectors and other unnamed interfaces remain pending.


## Windows and remote collection review

| Source subset in agent/nimstead_agent.py | Scope and verified boundaries | Status |
| --- | --- | --- |
| msrc_product_name, windows_apps, offline_user_apps, collect_windows and private registry readers | Reviewed server lookup/client inference, value defaults, enumeration errors, clipping/deduplication, source predicates, temporary hive effects and ignored unload status | Named subset reviewed |
| RemoteReg, Key and all adapter methods, collect_remote, scan_remote | Reviewed shared mappings, partial winreg compatibility, script files, architecture fallback, separate snapshots, trusted shapes, exact cache identity, truncate writes, enrolment/upload order and caught/propagated errors | Reviewed |
| windows_microsoft, baseline_id, last_json, windows_baseline_facts, windows_host_facts, windows_drivers, esu_active, ad_computers and associated fixed scripts | Reviewed product selection, observation/inference limits, script caps, policy exports, filtered facts, weak complete flags, directory records and error boundaries | Named subset reviewed |

62 focused tests and 53 subchecks passed. Eight native Windows tests were skipped. Eight offline boundary checks establish inferred client labels, unclassified enumeration endings, discarded driver rows with complete=true, last-JSON failure selection, adapter behavior, X86-to-AMD64 fallback, ignored unload status and invalid cache shapes. Executable AST matches the previous commit. Playwright MCP verified the new reference, operator procedure, mobile anchors and search through an owned local preview. Native registry, WinRM, PowerShell exports and production report keys were not exercised. Job classes, remaining agent/API contracts, sandbox/helpers and final editorial/example review remain open.


## Agent execution and restart review

| Source subset in agent/nimstead_agent.py | Scope and verified boundaries | Status |
| --- | --- | --- |
| repack_deb, apk_owned, dnf_touched, zypper_touched, Job and every method | Reviewed path/identity trust, live file copies, parser omissions, no-op target results, recovery scope, digest metadata exclusions, service samples, aborted preparation effects, cleanup and in-memory-only phase state | Reviewed |
| WinAppJob and every method, fixed application/setting maps and associated scripts | Reviewed source/target evidence, winget output/hash checks, Office repeated requests, registry read defaults, multi-view partial effects, undo-closure timing, no durable state and absent post-undo health verification | Reviewed |
| WinJob and every method, removable, offered_instead, clause_tail, boot_time, windows_build, netfx_build, windows_version_key, restart_for_update and fixed servicing scripts | Reviewed state shape, truncation writes, manifest mounts/exports, install parse timing, boot heuristic, target/hotfix checks, DISM retries, late arrivals, cluster result limits and terminal clear ordering | Reviewed |
| run_jobs and nested retry/record helpers | Reviewed callback forwarding, direct-call consent boundary, report/state ordering, malformed records, ID collisions, error-specific retry disposition, problem counts and cleanup after a failed immediate upload | Reviewed |

181 focused tests and 53 subchecks passed. Two native Windows cases were skipped. Eight temporary offline counterexamples verify partial registry effects, lossy undo after unreadable prior state, applied no-op target versions, colliding outcome filenames/counts, clear-before-build failure, aborted post-install parsing, rejected servicing outcome and dry-run parsing limits. API observations use an owned temporary SQLite database and local request client. Executable AST matches the previous commit. The 83-article build and six site checks pass. Playwright MCP verifies desktop/mobile reference, recovery anchors and search. Real package changes, Windows servicing, cluster transitions and restarts were not performed. Remaining unnamed interfaces/API gaps, sandbox/helpers and final editorial/example review keep the goal open.


## Asset API and final agent helper review

| Source subset | Scope and verified boundaries | Status |
| --- | --- | --- |
| app.py: agent_enroll, room_for_asset, facts_ok, current_agent, agent_inventory, asset_json, owned_asset, delete_asset, update_asset, owned_target, create_target, verify_target, scan_target, create_application, upload_sbom, ingest_sbom, summary | Reviewed credential/ownership checks, all response fields, repeated creation, quota commits, stored-fact/package retention, empty replacement, serializer caller context, rescan/response ordering, target proof, summary ranking/job sampling and deletion evidence | Named subset reviewed |
| agent/nimstead_agent.py: ed25519_verify, version_tuple and Ed25519 private arithmetic/decoder | Reviewed byte/message shape, canonical encoding/scalar checks, omitted subgroup/key-trust policy, unbounded message work, Unicode/leading-zero versions and malformed/extreme-input exceptions | Reviewed |
| scripts/export_api_docs.py: added asset/inventory contracts | Added ten closed response definitions with kind-specific optional fields and route bindings. Schema now has 57 definitions for 83 operations. Existing untyped responses still require their remaining review | Expanded |

153 focused tests and 53 subchecks passed. The existing temporary signed-update test first hit sandbox socket binding, then passed with loopback permission. Four new API tests compare published field sets against all asset kinds, enrolment/inventory, summary actions and attention jobs. They also verify repeated enrolment, patch/list differences, retained data, deletion evidence, SBOM bearer precedence and host last_seen. Four offline agent-helper assertions pass. Agent/app executable AST is unchanged. Redocly validates the export with 27 warnings about license metadata and missing declared 4xx responses. The 84-article build and six site tests pass. Playwright MCP verifies local desktop/mobile lookup, schema download, search and anchors. No real host enrolment, feed/provider request or production key change occurred. Other API handlers/schema gaps, sandbox/web helpers and final editorial/example review remain pending.
