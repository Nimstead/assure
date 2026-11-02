# Detection Engine Specification

**Purpose.** This document specifies what an independent vulnerability detection engine must do. It is organised around the problems such an engine has to solve. It contains no source code, rule text or identifiers from any other product.

**How to read it.** Each section gives the problem, then **Requirements** (R-numbers) and, where useful, **Trade-offs**. Content is general engineering principle or public practice, with an independent source where one exists. Items marked *needs an independent source* state a problem only, with no solution given. Numbers, thresholds and timeouts are left to the implementers to choose and measure. Section 12 is a test list.

---

## 1. The central design decisions

Five decisions shape everything else:

1. **Every check on every host ends in an explicit verdict**, including "could not determine". Silence is never a verdict (section 4).
2. **Detection content is mostly data, not programs.** Most vulnerability knowledge is a comparison of an installed item against a vendor-published fixed version. A small minority truly needs program logic (section 5).
3. **Inventory collection is separate from evaluation.** Collect once per host, evaluate many times. Re-evaluation against new advisories needs no new connection to the host (sections 5 and 14).
4. **Facts have types, provenance and declared dependencies**, checked when the content is built rather than discovered when a scan silently misses something (section 3).
5. **The vendor's statement about its own package outranks upstream version arithmetic** (section 7).

---

## 2. Scan lifecycle and scheduling

**Problem.** Run a large number of checks against many hosts, in the right order, without harming targets or the scanning host, and survive interruption.

Phases in order: target resolution and exclusion → liveness → port and service discovery → identification and inventory (remote and authenticated) → evaluation of data-driven content → active probes → optional disruptive probes (opt-in) → merging of results and reporting.

**Requirements**

- **R2.1** Build an explicit dependency graph per scan before any traffic is sent. Reject cycles at content build time, and treat any cycle or dangling reference at scan time as a content error that is reported, never ignored.
- **R2.2** Group runnable work into layers from the graph (a topological sort), and run within a layer concurrently, subject to the limits below. Prefer a per-host work queue to a fixed global ordering, so one slow host never holds up others.
- **R2.3** Keep independent concurrency limits per scan, per host, per service endpoint and for the scanner host itself. The per-endpoint limit must be declarable, down to one connection at a time.
- **R2.4** Give every unit of work a deadline, enforced by the engine and not by the check. On expiry, stop it, release its resources and record a `timed-out` verdict.
- **R2.5** Detect a host that has become unresponsive mid-scan. Stop sending traffic to it, and mark every remaining check `not-run: host-lost`.
- **R2.6** Declare a safety class on each check (passive, ordinary probe, potentially disruptive). Disruptive checks need an explicit per-scan opt-in, and a global safe mode must be impossible for content to bypass.
- **R2.7** Identify device classes that are easily disrupted before probing them, and let policy reduce or stop probing against them. Scanning has known hazards for such devices; [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) covers planning for this.
- **R2.8** Persist progress per host and per check, so an interrupted scan can resume without losing or duplicating results. Make results idempotent by a stable key: (scan, host, check, location).
- **R2.9** Enforce authorisation scope in the engine: targets outside the allowed list are refused, including names resolved or discovered during a scan.
- **R2.10** Handle virtual hosts deliberately. Web checks may need to run per hostname, but the multiplier must be visible and bounded, and duplicate findings collapsed to one with several locations.

**Trade-offs**

- *Process per check* gives crash and memory isolation and simple timeouts, but costs a lot at high concurrency. *Tasks in one process* are cheap but need a sandboxed rule runtime with hard resource limits. A memory-safe runtime with enforced budgets, and a separate process only for high-risk protocol parsing, is a reasonable middle.
---

## 3. The fact store and detection dependencies

**Problem.** Later checks need what earlier ones learned ("this port speaks TLS", "this host runs product X at version Y, installed at path Z"), and need to know when that knowledge is missing rather than negative.

**Requirements**

- **R3.1** Host-scoped, scan-scoped, append-only facts. Each fact has a type from a versioned schema, a value, the producing check, a timestamp, a location (port, path, or instance), and an evidence grade (section 6).
- **R3.2** Three states for any queried fact: *known with value*, *known absent* (a producer ran successfully and found nothing), and *unknown* (no producer ran, or it failed). Missing data must never read as *absent*.
- **R3.3** Checks declare inputs and outputs in their metadata. At content build time, fail the build when a consumed fact has no producer, when types mismatch, or when a producer is scheduled after its consumer.
- **R3.4** A typed product inventory is the main interface between detection and evaluation. Each entry holds a product identifier ([CPE](https://csrc.nist.gov/pubs/ir/7695/final) where one fits, purl or vendor naming where it doesn't), version, patch or build, install path or port, detection method, and grade.
- **R3.5** Support many instances on one host, as a first-class list. A check iterates explicitly over all instances and produces one verdict for each. Never model multiplicity with implicit branching in a rule's execution, which makes behaviour hard to predict and multiplies work combinatorially.
- **R3.6** Merge multiple sources for one product into a single inventory entry with all sources retained, choosing the value from the highest-grade source and flagging conflicts.
- **R3.7** Precondition outcomes are recorded: when a check doesn't run because a precondition failed, record which one and whether it was *false* (the product isn't there, so not applicable) or *unknown* (no way to tell, so undetermined).
- **R3.8** Dependencies are on *facts*, not on named checks or file names, so producers can be replaced without touching consumers. A dependency on a retired producer is a build error.
- **R3.9** Secrets never enter the fact store. Credentials are held in a separate scoped vault with audit, and handed only to the components that need them. Facts must be safe to log.

---

## 4. Verdicts: the difference between "not vulnerable" and "couldn't tell"

**Problem.** A clean report is a claim. If a scanner can't distinguish "checked and fine" from "never looked", a failed credential looks like a patched estate.

**Requirements**

- **R4.1** Every (check, host, instance) produces exactly one verdict from this closed set, or an equivalent:
  - `vulnerable`: evidence shows the condition is present.
  - `not-vulnerable`: evidence shows it's absent or fixed.
  - `not-applicable`: product or platform affirmatively isn't present.
  - `undetermined`: evaluation ran, but evidence is insufficient or conflicting.
  - `not-run`: with a reason code (no credential, credential failed, access denied, unsupported platform, precondition unknown, policy excluded, host lost, feed missing, out of budget).
  - `error` and `timed-out`.
- **R4.2** Absence of proof isn't a negative: `not-vulnerable` needs positive evidence, such as "package list was retrieved and complete, and the package is at or above the fix". When an expected inventory source failed, every check depending on it becomes `undetermined` or `not-run`, never `not-applicable`.
- **R4.3** Inventory completeness is itself a recorded fact. A partial package list, truncated output, or a query that returned nothing must be distinguished from a real empty result, and an empty list on a system that can't plausibly be empty is treated as a failure.
- **R4.4** Coverage is a product output. Per host, report what was attempted and how much was determined, by source and by check family, and let reports state plainly, "This host's patch state was not assessed." Headline counts must not treat hosts without coverage as clean.
- **R4.5** Each finding records: verdict, grade, the check and content version, the location, the evidence (observed value, expected value, source, and time), the reasoning in structured form, and severity with source and date. Keep it compact and redact secrets and personal data.
- **R4.6** Findings carry stable identities across scans so state can be tracked: new, persisting, fixed, reopened. "Fixed" needs a positive `not-vulnerable` on a later scan. A check that simply wasn't run this time doesn't close a finding.
- **R4.7** Store verdicts compactly enough that negatives can be kept (or kept as per-family summaries); they're what supports the coverage reporting above.

---

## 5. Detection content and its evaluation

**Problem.** Content must scale to a large number of vulnerabilities, be cheap to evaluate, safe to run, and easy to review.

Use these content kinds, in order of preference:

1. **Fixed-version advisories.** Tables keyed by platform, then package, giving the fixed version per advisory. Fed from vendors. One evaluator per version scheme.
2. **Declarative product rules.** Product plus affected version ranges from a vendor advisory, with optional conditions (edition, configuration fact, architecture). Evaluated against the inventory.
3. **Declarative configuration tests.** "Registry value or file content matches a condition", in the spirit of [OVAL](https://oval.mitre.org/) definitions and [SCAP](https://csrc.nist.gov/pubs/sp/800/126/r3/final).
4. **Declarative active probes.** Request, response matcher, and required negative control.
5. **Sandboxed programs.** Reserved for multi-step protocol logic that truly can't be expressed otherwise.

**Requirements**

- **R5.1** A version comparator per scheme, each with a test corpus derived from the specification: [Debian policy](https://www.debian.org/doc/debian-policy/ch-controlfields.html) (epoch, upstream, revision, and the tilde ordering), [RPM](https://rpm-software-management.github.io/rpm/manual/dependencies.html) (epoch, version, release and its segment rules), [SemVer](https://semver.org), Windows four-part versions, and vendor-specific forms (for example network-OS trains, which can't be compared as plain numbers). Further schemes follow from the chosen platform scope.
- **R5.2** Comparators return *less, equal, greater,* or **incomparable**. An incomparable pair (different release lines, unparseable strings) yields `undetermined`. It must not fall through to "not vulnerable" or "vulnerable".
- **R5.3** Version numbers are compared only inside the correct branch. Range rules state branch boundaries explicitly, because a fix in one maintained line doesn't apply numerically to another.
- **R5.4** Rule metadata: stable own identifier, CVE and advisory references, affected and fixed statements, source URL and retrieval date, severity source, content version, safety class, inputs, outputs, and the maximum evidence grade the rule can claim.
- **R5.5** Authoring and supply checks at content build time: schema validity, references resolve, comparator is declared, regression fixtures exist. A rule must ship with at least one positive and one negative test.
- **R5.6** Programs run in a capability sandbox: only declared network targets, no filesystem, CPU and memory budgets. Rule content is treated as code from a supplier.
- **R5.7** Separate content-language versioning from engine versioning, and have the engine refuse content newer than it understands while saying so. Prefer one current content tree that declares a minimum engine version.

**Trade-offs**

- *Script everything:* easy to write, hugely flexible, slow, hard to audit, can't be re-evaluated offline. *Tables only:* fast and auditable, can't handle active checks. The hybrid above costs a bit of design but lets evaluation be offline for most content.
---

## 6. Evidence grades and confidence

**Problem.** A banner match and a confirmed exploit aren't equally trustworthy, and users need to say which they'll accept.

Separate two independent numbers: **severity** (how bad it is if true) and **confidence** (how sure we are it's true). Never mix them.

Define a small ordered scale of evidence grades. It has to express that detection methods differ in how far their results can be trusted. Which grades exist, how many, and in what order: *needs an independent source*.

**Requirements**

- **R6.1** Grade comes from the *method actually used at run time*. A rule declares a ceiling, and the engine lowers it when evidence is weak. How to combine grades when several methods contributed: *needs an independent source*.
- **R6.2** Calibrate by measurement. For each grade, track true- and false-positive rates against labelled test systems (section 12), and revise definitions from data. Don't treat a grade as meaningful just because someone assigned a number.
- **R6.3** Filtering by grade is a visible choice in the UI and in the report, with a count of what was hidden ("37 lower-confidence results not shown"). Hidden isn't deleted.
- **R6.4** Each lower-grade finding says what would raise confidence: "provide credentials to confirm".
- **R6.5** Prioritisation is separate again: combine severity ([CVSS](https://www.first.org/cvss/v3.1/specification-document)) with exploit likelihood ([EPSS](https://www.first.org/epss/)), known exploitation ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)) and asset context. Keep the score's version and source date with each finding.

---

## 7. Linux and Unix missing-patch detection

**Problem.** Distros backport fixes, so the version string stays old while the code is fixed. Red Hat [explains](https://access.redhat.com/security/updates/backporting) why version-only tools give false positives on its products; [Debian's security FAQ](https://www.debian.org/security/faq) describes the same practice.

**Principle.** Compare the installed package to the fix version *the distribution* published, using that distribution's rules. Upstream version ranges aren't applicable to distro-packaged software.

**Requirements**

- **R7.1** Precisely identify the platform: distribution, release, and sub-stream (extended support, modules, livepatch), from authoritative local files. Failure to map to a known platform yields `not-run: unsupported-platform`, reported, never silence.
- **R7.2** Collect name, epoch, version, release, architecture, and source-package name where possible. Query the package database directly and in a stable output format. Record the collection command's status, not just its output (see R4.3).
- **R7.3** Advisory data comes from distro feeds: [Ubuntu OVAL](https://ubuntu.com/security/oval), [Red Hat CSAF/VEX](https://security.access.redhat.com/data/csaf/v2/advisories/), Debian's security tracker, [OSV](https://ossf.github.io/osv-schema/) where it maps. Convert to a single internal model, and retain advisory id, release, package, fixed version and references.
- **R7.4** Evaluation per package: if not installed, `not-applicable`; if at or above the fix, `not-vulnerable`; if below, `vulnerable`; if incomparable, `undetermined`. A package installed for a different stream or architecture must not match.
- **R7.5** Use the vendor's unfixed status too. "Known affected, no fix yet", "no fix planned" and "not affected" are different outcomes ([CSAF](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) and [OpenVEX](https://openvex.dev) model these). A scan that reads only fixed versions misses open vulnerabilities and reports nothing.
- **R7.6** Handle end-of-life platforms explicitly: past end of support, absence of advisories doesn't mean the host is safe. Report end-of-life as its own finding and treat patch state as `undetermined`.
- **R7.7** Kernels: distinguish installed from running. Report a "fix installed, reboot required" state. Treat livepatch as its own evidence source. Any policy that excludes installed-but-not-running kernels from evaluation must be visible in the results.
- **R7.8** Other runtime mismatch: a library updated on disk but still loaded by a running service is a real remaining exposure. Report this where cheaply detectable.
- **R7.9** Software outside the package manager (language packages, vendored binaries, containers, self-installed tools) needs separate inventory. Where package and upstream sources both describe an item, the package manager wins unless the file was changed outside it.
- **R7.10** Keep the host's load low: one brief collection session, read-only commands, bounded file search with exclusions (network mounts, pseudo-filesystems), no required agent. Make privilege escalation optional and audited, and report what degraded when it's absent.
- **R7.11** Network devices without a general-purpose shell must be recognised before collection begins, and receive their own collection path.

---

## 8. Windows missing-patch detection

**Problem.** Windows has several overlapping sources of truth, none complete, and its servicing model has changed over time. Monthly updates are now [cumulative](https://learn.microsoft.com/en-us/windows/deployment/update/release-cycle), so an old patch's identifier may never appear on a fully patched machine.

**Principle: prefer, in order, the evidence that can't lie about what's on disk and what's running.**

| Evidence | Good for | Limits |
|---|---|---|
| OS build and revision (registry) | Fast yes/no for cumulative OS updates | Must be compared per release line. Safe OS and other separately serviced components may differ. Reboot state matters. |
| File version of a representative binary | Direct confirmation; sidesteps supersedence | Needs file access. Must choose the correct binary, architecture and branch. Different servicing branches have different version trains. |
| Component servicing state | Authoritative for installed packages | Needs privileged access. Identifiers change with supersession. |
| [WMI quick-fix listing](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering) | Quick hint | Microsoft says it returns only updates from component servicing, not those from MSI or the update site. Absence proves nothing. |
| [Windows Update Agent](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/windows-update-agent-object-model), [offline with Microsoft's signed catalogue](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline) | Microsoft's own applicability logic, including supersedence | Runs on target, can be heavy on memory by Microsoft's own note. Catalogue needs distribution. Scope limited to what it covers. |
| Installed-programs registry | Non-OS product inventory | Self-reported, incomplete, can be stale. Check both 32- and 64-bit views. |

**Requirements**

- **R8.1** Model *fix conditions* from [MSRC](https://msrc.microsoft.com/update-guide) data: per CVE, per product and release line, the minimum fixed build or the fixing updates. An advisory-to-build table replaces per-patch logic for cumulative OS updates, and turns supersedence into simple version comparison.
- **R8.2** Compute supersedence only where it's still needed (older non-cumulative products, some Office and .NET channels). Use Microsoft's published data, and a supersession graph with transitive closure. "Any later update in this chain is installed" means fixed. [Microsoft's update terminology](https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/standard-terminology-software-updates) covers the categories.
- **R8.3** For high-value checks, confirm with a second source, usually file version. Read version resources by their defined [structure](https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo) from the fixed-file-info block, and not from the display string, which may differ.
- **R8.4** Handle disagreement as data: for instance registry says patched and file says old might mean a pending reboot, and is reported as `undetermined` or "pending reboot", not a guess.
- **R8.5** Detect pending-reboot state and report "installed, not yet effective" as its own state.
- **R8.6** Handle these cases explicitly: [hotpatch](https://learn.microsoft.com/en-us/windows/deployment/update/release-cycle) channels (where the baseline logic differs), extended security update enrolment on out-of-support releases, server core, architecture differences including emulated 32-bit, products with their own servicing (Office click-to-run channels, Edge, .NET, Exchange and SQL cumulative trains, in-box vs. store-delivered apps), and OS version values that [may not reflect the installed OS](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexa). Always key on build number.
- **R8.7** Don't mutate a target as a side effect. If remote command execution by creating a service is ever used as a transport, off by default, with clean-up verified and logged, because endpoint protection often flags it and it changes the host.
- **R8.8** Prefer read-only management interfaces for collection, and support at least two (for instance, SMB with remote registry, and WinRM). Use modern authentication (Kerberos; NTLM where allowed), signing and encryption, and report precisely which were negotiated.
- **R8.9** Respect servicing and concurrency limits: file-share and remote-registry traffic in one per-host session, cached, since many checks need the same few values.

---

## 9. Credentialed access and failure reporting

**Problem.** A wrong password shouldn't look like a healthy host.

**Requirements**

- **R9.1** Run an explicit credential stage per host and protocol, ending in a structured state: `not-supplied`, `succeeded`, `succeeded-limited`, `auth-failed`, `lockout-risk-stop`, `unreachable`, `protocol-mismatch`, `policy-blocked`, `privilege-insufficient`.
- **R9.2** Separate *authentication worked* from *the access needed for collection worked*. After login, run a small self-test of each required capability (read package database, open registry, read a system file, query WMI), and record the result per capability.
- **R9.3** Failure is a high-visibility, first-class status for a host. It isn't an informational log line, and it must survive default filters. It appears in the scan summary, on the host, and in the delta from the last scan ("credentialed last time, not this time").
- **R9.4** Every failure says why and what to do, without leaking secrets: wrong password, account locked, server required algorithm that the client doesn't offer (list both sides), clock skew for Kerberos, service disabled, or specific missing right.
- **R9.5** Protect accounts: try a credential once per host per scan, no retry loops, and detect lockout policy where possible. Stop trying across hosts when failures across many hosts suggest a bad credential, before locking a domain account.
- **R9.6** Connection safety: verify SSH host keys (trust on first use at minimum, with changes flagged). Don't send credentials to an unverified target. A scanner holding domain credentials is a target, so least privilege, short sessions, and vault-backed secrets are design requirements.
- **R9.7** Commands are fixed or strictly parameterised. Never interpolate host-supplied output into later commands. Treat all target output as hostile: a compromised host may try to attack the scanner with long, malformed or misleading output, or lie about patches, which an unauthenticated confirmation can't catch either.
- **R9.8** A clear degradation rule: when authenticated collection fails, remote detection continues, the results are labelled as remote-only, and patch-level checks are `not-run: credential-failed`.
- **R9.9** Credential success must be confirmed against the correct host. Name mismatch or a load-balanced target shouldn't attribute inventory to the wrong asset. Record the identity observed post-login.

---

## 10. Remote detection and active probing

**Requirements**

- **R10.1** Service identification from behaviour, not port number alone. Handle TLS-wrapped services and services on non-standard ports. Identify first, then direct checks to the right port.
- **R10.2** Treat banners as weak. Record where the version came from, and lower the grade when the vendor is known to backport, or when the banner can be configured.
- **R10.3** Every active probe needs a **negative control**. A web check must learn how this site answers a nonexistent resource first, as many sites return a success status with an error page. Compare the suspect response to a control, per host and virtual host, and require a marker that's specific to the flaw.
- **R10.4** Prefer proof that creates no lasting effect: a computed value echoed back (a random arithmetic or token result specific to this request), so reflective pages and honeypots can't satisfy a static pattern. Avoid writes, and clean up where they can't be avoided.
- **R10.5** Detect middleboxes that distort results: a WAF, tarpit or catch-all that answers everything. Where a port "answers everything", suppress product-identification results from it and report that instead.
- **R10.6** Rate limit per host and globally. Cache HTTP fetches per scan, since most web checks ask for the same pages.
- **R10.7** Avoid harmful behaviour to credentials (no default-password testing unless opted in; it can trigger lockouts) and record every probe sent, to make audits possible.
- **R10.8** Offer CPE-to-CVE inference only at a low grade, and clearly label it. CPE data is broad, and [NVD's matching data](https://nvd.nist.gov/vuln/vulnerability-detection-and-remediation) describes the affected configurations but not distro backports.

---

## 11. False-positive handling

Suppression needs to be a controlled workflow:

- **R11.1** Suppressions, downgrades and annotations never alter raw results. They apply as a layer with its own audit trail, so the original can always be shown.
- **R11.2** Scope by check, asset or group, location, and optionally evidence: a suppression tied to a particular evidence value should lapse when evidence changes (a new version appears, for example).
- **R11.3** Every suppression has an author, reason category (false positive, accepted risk, mitigated, not exploitable here), justification and **expiry**. Expired suppressions reopen visibly. Use [VEX](https://openvex.dev)-style justifications, so they can be exchanged.
- **R11.4** Conflict rule: deterministic, and displayed. The order of precedence is documented, and the applied rule is shown on the finding.
- **R11.5** Default behaviour is decided and visible. Apply suppressions by default, with a counter and one-click way to view what's being hidden.
- **R11.6** False-positive reports feed back to content: a report with its evidence can become a regression fixture, and a rule with repeated reports is automatically flagged for review.

---

## 12. What a good engine must get right: testable behaviour

Build a labelled test range with known-patched and known-vulnerable systems; every item below is an automated test. Each should fail the release if it regresses.

**Verdict integrity**
- T1. Wrong SSH password: host shows `auth-failed` in the summary with default filters on; each package check shows `not-run: credential-failed`; host isn't counted as clean.
- T2. Correct login, but package database unreadable: `succeeded-limited`, checks `undetermined`, reason names the capability.
- T3. Truncate the package list mid-collection: engine marks inventory incomplete, doesn't report absent packages as `not-applicable`.
- T4. Unknown distribution: `not-run: unsupported-platform`, reported.
- T5. Stop a producer of a fact: dependent checks say `not-run: precondition unknown`, with the producer named.
- T6. Kill the target mid-scan: remaining checks `not-run: host-lost`; no finding is marked fixed.
- T7. A finding present last scan, no credential this scan: finding stays open, flagged unverified, and isn't closed.
- T8. Rule exceeding its deadline: `timed-out`, resources released, scan continues.

**Version logic**
- T9. Run public test corpora for each comparator, including epochs, tilde ordering, and long numeric segments that overflow a machine integer.
- T10. Incomparable versions yield `undetermined`.
- T11. Backported fix on Debian-family and RPM-family hosts: an old upstream number with a fixed distro revision yields `not-vulnerable`, while the same upstream with an older revision yields `vulnerable`.
- T12. A package for a different architecture or stream doesn't match.
- T13. A vendor-marked "no fix planned" package gets a distinct outcome, and an end-of-life platform is reported as such.

**Windows**
- T14. Fully patched machine that never installed an old update: not reported missing, because of cumulative logic.
- T15. Build one revision below the fix: vulnerable; at the fix: not vulnerable.
- T16. Update installed, reboot pending: reported as pending, not as fixed.
- T17. Quick-fix listing empty while build is current: no false positive.
- T18. Registry read denied: `not-run: access-denied`, naming the permission.
- T19. 32-bit application on 64-bit OS, two versions of a product side by side: both evaluated, one verdict each.
- T20. Out-of-support OS with extended updates, hotpatched host, server core: all produce correct outcomes.
- T21. After a full scan, no service, file, or configuration remains changed on the target (compare before and after state).

**Active checks and quality**
- T22. A site returning success for every URL produces no web-path findings.
- T23. A catch-all port producing any banner suppresses product results, and says why.
- T24. A static page containing a pattern that a probe looks for: a dynamically proven check doesn't fire.
- T25. Safe mode: instrument the target to prove that no disruptive probe arrived, whatever the content says.
- T26. Concurrency: per-endpoint limit of one is never exceeded, verified at the target.
- T27. Report grades, measured over the range: false-positive rate per grade is within a target you set; published with each release.

**Content and supply**
- T28. Tampered rule file, replaced signature, old-version replay, expired metadata, and missing signature: each refused, and scan reports what it did instead.
- T29. A failed update leaves the previous good content running, with a visible staleness warning.
- T30. A rule consuming an undefined fact fails the build. So does a rule with no positive or negative fixture.
- T31. Hostile target: oversized output, terminal escapes, malformed encoding, deceptive injection into report rendering; scanner stays stable and escapes output.
- T32. Secrets: search the logs, fact store, reports and crash dumps for planted test credentials; expect no hits.
- T33. Resume: kill the scanner mid-scan, restart, and compare to an uninterrupted run; results are identical in set, with no duplicates.
- T34. Reproducibility: same inventory plus same content version gives identical verdicts. A scan's record contains both, so results can be explained months later.

**Suppressions**
- T35. Expired suppression reopens the finding. A suppression tied to a version lapses when the version changes. Raw results remain viewable.

**Scale and cost**
- T36. Offline re-evaluation of stored inventories against new content needs no connection to any host, and completes within a time budget you set.
- T37. Measure peak traffic and CPU on easily disrupted targets, and hold a budget per scan profile.

---

## 13. Content distribution and integrity

**Problem.** Content runs in a process trusted with credentials. A feed is a code-execution channel.

**Requirements**

- **R13.1** Signed manifest with hashes of every file, verified **before** parsing any content. Mandatory by default; turning it off needs an explicit flag, is visible on every report, and is never the default. [OpenPGP](https://www.rfc-editor.org/rfc/rfc9580) detached signatures work, as does any comparably strong scheme.
- **R13.2** Defend against more than tampering: rollback, freeze, mix-and-match and key compromise. The threat model of [The Update Framework](https://theupdateframework.io/) is the reference: role separation, thresholds, expiry and monotonically increasing versions. A client refuses older content and warns about stale metadata.
- **R13.3** Authenticated, encrypted transport with proper host verification. Integrity comes from signatures, but transport protects privacy and metadata too. Never disable host-key verification in the default configuration.
- **R13.4** Atomic switch: download to staging, verify, swap by version, and retain the previous version. Never read a half-synced tree. Scans pin one content version from start to finish.
- **R13.5** Incremental updates, plus an offline bundle path for air-gapped sites with identical verification.
- **R13.6** Provenance for content: where each rule's data came from, retrieved when, and from which pipeline version, per [SLSA](https://slsa.dev)-style thinking. Primary-source pipelines must be reproducible.
- **R13.7** The control plane and scan workers agree on a content version, and refuse or warn on mismatch. Report the content version and its age on every scan.
- **R13.8** Key rotation and revocation are designed in from day one, and tested (see T28).

---

## 14. Interfaces at an abstract level

Keep these boundaries so parts can be replaced and tested alone.

- **Collector → Inventory.** Input: host, credentials handle, policy. Output: inventory document (platform, packages, products, patch state, capabilities tested, completeness, collection timing, errors). No judgement made.
- **Evaluator.** Input: inventory, content version. Output: verdict set. Pure and deterministic, no network. This is the heart of testing (T34).
- **Prober.** Input: target, service facts, rule. Output: facts and verdicts with evidence. Budgeted and sandboxed.
- **Scheduler.** Input: targets, selected content, policy. Output: ordered work, progress, resumable state.
- **Content service.** Provides verified, versioned content; states freshness.
- **Result store.** Append-only verdicts and evidence, stable finding identity, deltas.
- **Policy layer.** Grade filters, suppressions, prioritisation. Applied on read, never destructive.
- **Control API.** Authenticated (mutual TLS or equivalent), start, stop, resume, and status with per-host coverage counters, based on checks evaluated rather than checks launched.

---

## 15. Suggested build order

1. Verdict model and result store (section 4), since everything reports through it.
2. Version comparators and test corpora (R5.1, T9–T11).
3. Linux collector, one distro family, offline evaluator, one advisory source. Gives an end-to-end vertical slice with backport correctness.
4. Credential stage and failure reporting (section 9).
5. Windows inventory and build-based evaluation for cumulative updates (R8.1), then file-version confirmation and reboot state.
6. Content signing and update path (section 13), before any external user receives content.
7. Declarative remote rules with negative controls (section 10).
8. Evidence grades calibrated on the test range (section 6).
9. Suppression workflow (section 11).
10. Sandboxed programs, only once a real rule can't be expressed declaratively.

---

## 16. Independent references

- CPE naming: NIST IR 7695, <https://csrc.nist.gov/pubs/ir/7695/final>
- SCAP 1.3: NIST SP 800-126r3, <https://csrc.nist.gov/pubs/sp/800/126/r3/final>
- OVAL: <https://oval.mitre.org/>
- Security testing guide: NIST SP 800-115, <https://csrc.nist.gov/pubs/sp/800/115/final>
- Patch management: NIST SP 800-40r4, <https://csrc.nist.gov/pubs/sp/800/40/r4/final>
- CVSS: <https://www.first.org/cvss/v3.1/specification-document>; EPSS: <https://www.first.org/epss/>; KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CSAF 2.0: <https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html>; OpenVEX: <https://openvex.dev>; OSV: <https://ossf.github.io/osv-schema/>
- Debian version rules: <https://www.debian.org/doc/debian-policy/ch-controlfields.html>; Debian security FAQ: <https://www.debian.org/security/faq>
- RPM: <https://rpm-software-management.github.io/rpm/manual/dependencies.html>; Red Hat on backporting: <https://access.redhat.com/security/updates/backporting>; Red Hat CSAF: <https://security.access.redhat.com/data/csaf/v2/advisories/>
- Ubuntu OVAL: <https://ubuntu.com/security/oval>
- Microsoft: [update release cycle](https://learn.microsoft.com/en-us/windows/deployment/update/release-cycle), [update terminology](https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/standard-terminology-software-updates), [servicing stack updates](https://learn.microsoft.com/en-us/windows/deployment/update/servicing-stack-updates), [quick-fix WMI class](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering), [offline update scan](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline), [Update Agent object model](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/windows-update-agent-object-model), [file version structure](https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo), [MSRC update guide](https://msrc.microsoft.com/update-guide)
- Update security: The Update Framework <https://theupdateframework.io/>; SLSA <https://slsa.dev>; OpenPGP RFC 9580 <https://www.rfc-editor.org/rfc/rfc9580>
