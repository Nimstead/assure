# Implementation Plan (Windows round 1): exact Windows Server and Windows 10/11 detection and remediation

Status: **built on branch `windows-round-1`** (2026-10-29; see STATUS.md for proof and gaps; target: detection parity with commercial scanners on Windows, remediation they don't have). Tasks: `tasks/todo.md`. Previous plans: `plan-0.3-agent.md`, `plan-0.4-security.md`, `plan-0.5-ux.md`, `plan-0.6-ux.md`.

## Overview
Today Windows coverage is: the OS build against MSRC FixedBuild (exact), ~18 third-party apps against a curated NVD CPE
map, and one cumulative update by KB with DISM rollback (proven on Server 2025 and Windows 11 26H2). This plan makes
Windows coverage as good as any product on the market **without giving up what makes it different**: exact, low-noise
matches, refusing to guess, every claim proven on a real VM, and a compromised server that still can't run code
(DECISIONS 7, 27). It closes the gaps in this order: (1) measure accuracy against Microsoft's own oracle, (2) fix the
OS-detection blind spots (hotpatch, end of life, unmapped releases), (3) cover the Microsoft components MSRC already
publishes exact builds for, (4) catch "patched but not protected" and score by what is actually installed,
(5) widen remediation and prove it on every supported Windows version.

It also removes the biggest Windows adoption blocker: today the agent needs an all-users Python on every host (Phase 5).

## Rules for whoever executes this (/goal)
- House rules apply: read STATUS.md first; a test for every change; real-host proof where a change touches a host
  (`sandbox/`, disposable VMs only, never this machine); each new "why" goes in DECISIONS.md (next numbers 51+);
  STATUS, CHANGELOG, README and docs/install.md updated at the end.
- Smallest complete change: reuse what "What exists" lists. No new dependency unless a task says so.
- Do not weaken DECISIONS 7, 27, 31 (the server never hands out code the release key didn't sign; admin is an attacker
  capability across tenants).
- Order: Phase 0 → 1 → 5 → 2 → 6 → 3 → 7 → 8 → 4, then the release gate. Phase 5 comes early because every later VM
  proof should run the agent as customers will install it (no Python on the host); Phase 8 (windows, reboots,
  clusters) comes before Phase 4 so every new fix path is born obeying them.
- One branch `windows-round-1`, a commit per task; do not push, tag or release (owner-only).
- A task blocked on the owner (see "Needs the owner") is skipped and listed as blocked in STATUS, never faked or
  half-done. A task whose T0 data says "not possible" is dropped with the reason in DECISIONS.
- Verify after every task: `cd api && uv run pytest -q && uv run ruff check src tests ../agent ../sandbox ../scripts`;
  when `web/` changes: `cd web && npm test && npm run build && npm run e2e`; when a migration is added:
  `cd api && uv run python ../sandbox/pg.py`.

## Needs the owner (not for /goal)
- An Azure subscription for the hotpatch VM (T15). Without it T15 stays blocked; T2 still ships.
- A Windows 10 image if Windows 10 Enterprise LTSC 2021 is no longer on the Evaluation Center (T18).
- Push the branch, review and merge (including the STATUS "Review notes"), tag v0.6.0, approve the Release workflow,
  promote preview → beta → stable (decision 16).

## What exists (reuse, don't rebuild)
- `feeds.sync_msrc`: MSRC CVRF → OSV-shaped rows (ecosystem `Windows`, package = MSRC product name, `fixed` = lowest
  FixedBuild per product, `database_specific.kb`). Drops every product that isn't `Windows (10|11|Server)`.
- Agent `msrc_product_name` / `collect_windows`: names the OS exactly or raises `AgentError` (so an unmapped OS sends
  **no inventory at all**, apps included). `windows_apps` reads the Uninstall keys (HKLM, WOW6432, loaded user hives).
- `scan.rescan` + `match.match_package` + `versions.windows_cmp`: generic; a new ecosystem needs rows, a comparator and
  a target mapping, nothing else.
- `winapps.py`: curated DisplayName → `vendor:product` map with per-product normalisers (DECISIONS 22/24 pattern).
- `remediate.plan` (Windows branch: KB of the highest fixed build), trust ladder, canary, soak, one Windows job per host.
- Agent `WinJob`: persisted state machine, WUA find/download/install as SYSTEM, permanence check from `update.mum`
  (`PS_PERMANENCE`, `removable`), DISM rollback with transient retries, build verify, service-state health.
- `risk.score` with reasons; findings carry `reasons`, so "why this priority" is already a UI concept.
- VM harnesses: `sandbox/winvm.py` (VirtualBox, cold boot), `wine2e.py`, `winresume.py`, `winlocal.py`, `winattack.py`.
- Real MSRC fixture `api/tests/fixtures/msrc/2026-Oct.json` (trimmed: no Server 2016/2019/2022 entries, no hotpatch).

## Gaps found while reading the code (each one is a task below)
| # | Gap | Effect today |
|---|---|---|
| G1 | `sync_msrc` keeps the **lowest** FixedBuild per product; MSRC lists hotpatch KBs (lower UBR) beside the cumulative update for Server 2025 / Windows 11 Enterprise 24H2+ | A non-hotpatch host can be judged against the hotpatch build, and `plan` can pick the hotpatch KB, which Windows Update won't offer it: the job aborts "No changes made". Needs proof from real CVRF (T0) |
| G2 | No lifecycle data | Windows 10 22H2 without ESU (out of support since 2025-10-14), 11 23H2/24H2 Home/Pro, Server 2012/R2 show only CVEs, never "this OS gets no more fixes" |
| G3 | Unmapped OS = `AgentError` | Server 2012/R2, Server 23H2 (annual channel), Insider builds send nothing, not even third-party apps |
| G4 | Only the OS build | Edge, .NET, SQL Server, Exchange, inbox Store apps (Notepad, Snipping Tool…), Defender, Microsoft 365 Apps: MSRC publishes them, we drop them. Edge goes through NVD Chrome CPEs and misses Microsoft-only CVEs (STATUS) |
| G5 | "Patched" = build only | Fixes that need a second step are reported fixed: Secure Boot 2023 certificates (Windows Production PCA 2011 expired 2026-10-19), BlackLotus revocations (CVE-2023-24932), opt-in mitigations (e.g. CVE-2013-3900 `EnableCertPaddingCheck`) |
| G6 | Every OS CVE scores the same whether or not its role is installed | A DNS Server or MSMQ RCE on a host without that role ranks like one that is exposed |
| G7 | No update-management context | WSUS not approving a KB, WUfB deferrals, missing ESU licence or a pending reboot all surface only as "Windows Update offers exactly KBx: failed" |
| G8 | Windows health = service state once | Linux got "not restarted since the change" (DECISIONS 29); Windows didn't |
| G9 | Remediation is the OS cumulative update only | .NET cumulative, Microsoft 365 Apps and third-party apps have no fix path |
| G10 | Proven on Server 2025 and Windows 11 26H2 only | Windows 10 22H2, Server 2016/2019/2022 detection and remediation unproven on real hosts |

## Coverage against commercial scanners (Windows)
What a buyer comparing us with commercial scanners' agents and their patch management expects on Windows,
and where this plan delivers it. "Out" rows are deliberate and say why.

| Capability buyers expect | Commercial scanners | Today | This plan | Status (2026-10-29) |
|---|---|---|---|---|
| Missing OS security updates, all supported Windows 10/11/Server | both | MSRC build match | T2 hotpatch, T4 unmapped releases, T1 oracle proves it | Built. Windows 11 and Server 2025 oracles agree on the OS KB, every gap explained |
| End-of-life / unsupported OS and software | both (large "unsupported software" family) | none | T3 OS, T28 Microsoft + third-party apps | Built, unit-tested (OS, Microsoft products, endoflife.date) |
| Microsoft products: Edge, .NET, Office/M365, SQL, Exchange, SharePoint, Defender, Store apps, others | both | none | T5–T9, T19, T20, T29 | Proven on Windows 11 for Edge, .NET, .NET Framework, SQL, Defender, Office (`last_run_winproducts.json`, `last_run_winnetfx.json`); Exchange and SharePoint need a domain |
| Third-party apps at breadth (hundreds of products) | both (thousands of plugins / QIDs) | 18 curated | T30 second data source, T31–T33 expand to ~80 curated products, each proven by a real install | Partly: 82 curated products + CVE List v5; 41 proven old to new on a real install |
| Per-user apps of every profile, not just logged-on users | both (credentialed) | logged-on only | T34 | Built, fakes only |
| Vulnerable libraries on disk (log4j-style jar scan) | both | SBOM upload only | T35, reusing the Maven matcher | Built, unit-tested (fat jar) |
| Fix needs a config step (Secure Boot certs, BlackLotus, opt-in mitigations) | both | none | T10 | Built, unit-tested |
| High-signal hardening findings (SMBv1, SMB signing, NTLMv1, LLMNR, WDigest, unquoted service paths, Spooler on DCs…) | both, inside VM (not only the compliance SKU) | none | T36, T37 | Built, unit-tested |
| Exposure-aware priority (role installed?) and threat context (exploit public, ransomware, Microsoft's exploitability index) | VPR / TruRisk | KEV, EPSS, CVSS | T11, T39 | Built, unit-tested |
| Pending reboot, WSUS/WUfB context, ESU | both | none | T12, T14 | Built, shown on Assets (web tests, axe) |
| Find Windows hosts with no agent | both (discovery scans, AD connectors) | none | T43 (from Active Directory) | Built, tests only (no domain in the sandbox) |
| OS patch deployment with rollback | add-on products (rollback limited) | LCU + DISM rollback | T13, T15, T16, T18 | Proven on Windows 11 26H2 (agent 0.4.0) and Server 2025 (agent 0.4.0, 2026-10-29); hotpatch BLOCKED (Azure); .NET DROPPED; Windows 10 / Server 2016–2022 BLOCKED (ISOs) |
| Third-party and Microsoft app patching | add-on | none | T17, T21, T22 | Built, fakes only (no VM run) |
| Reversible configuration fixes | partial | none | T38 | Built, fakes only (no VM run) |
| Maintenance windows, reboot control, user deferral, no install on battery | add-on | immediate, 60 s reboot warning | T40, T41 | Deferral, notice sent, restart after the deadline and job verified on Windows 11 once; an earlier run's restart at 45 min is unexplained; window dispatch fakes only |
| Cluster/DC-safe patching (one node at a time) | partial, ConfigMgr CAU | one job per host only | T42 | Built, fakes only (no cluster or domain) |
| Fleet operation: proxies, jittered schedules, low agent footprint, no runtime to install | both | no proxy, no jitter, Python required | T25–T27, T44 | No-Python install and runtime update proven on Windows 11 and Server 2025 Core; proxy-only enrol, report, self-update and fix proven on Windows 11 |
| Proof of accuracy | vendor claims | Linux: OSV agreement | T1 oracle on every Windows version, Checkpoint C noise review | Windows 11 oracle agrees exactly with Windows Update, OS and .NET Framework (`last_run_winnetfx.json`); Server 2025 before .NET Framework; noise review on one VM, partly |
| Agentless credentialed network scanning (SMB/WinRM) | core | none | `scan-remote` over PowerShell remoting as the admin running it, no stored credential (DECISIONS 65) | Built; on one VM scanning itself, reports exactly what the agent reports (`last_run_winremote.json`); not across two hosts or a domain; no SMB; hosts need remoting on; finds, doesn't fix |
| Full CIS/STIG benchmarks | separate compliance SKUs | none | **Out:** its own plan; T36/T37 and a free hardening audit (DECISIONS 64) cover what's directly exploitable, with no conformance claim | Out |
| Unauthenticated internal network scanning (e.g. MS17-010 from the wire) | yes | external (internet) only | **Out:** the agent sees the build directly; internal scanning is its own plan | Out |

## Architecture decisions (become DECISIONS 51+ as each lands)
1. **Accuracy oracle first.** Windows Update Agent on the host is Microsoft's own answer to "which security updates are
   missing". A harness runs WUA's search (`IsInstalled=0 and Type='Software' and CategoryIDs contains` the Security
   Updates category) in each VM and compares the KBs it reports with the KBs of our open OS findings. Every later task
   reports the agreement table, like the 49-case OSV agreement for Linux. Agreement is measured, not assumed.
2. **MSRC stays the source for everything Microsoft.** Every new Microsoft product comes from CVRF `FixedBuild` (exact
   numeric builds only, as today) through an explicit **product allowlist** in `feeds.py`, never a pattern that admits
   whatever MSRC adds. NVD stays for third-party apps only; Edge moves from the NVD map to MSRC.
3. **Variant products instead of matcher changes.** Where one product has two fix tracks (hotpatch vs cumulative,
   SQL Server GDR vs CU), the feed stores them as separate package names (e.g. `Windows Server 2025 (Hotpatch)`,
   `Microsoft SQL Server 2022 (CU)`) and the agent reports which track the host is on. `match.py` and `scan.py` don't
   change; a host is only ever compared with fixes it can actually install.
4. **Config checks are a closed list in the agent.** The agent reads a fixed set of registry values/events (no
   server-supplied paths: the server must not turn the agent into a remote registry reader). The server evaluates
   curated rules (new ecosystem `WinConfig`, one module like `winapps.py`). Unknown or unreadable = "can't tell",
   never "fixed".
5. **Lifecycle is a curated, dated table** in the API (Microsoft Lifecycle dates per product/edition, with source
   URLs), not a live third-party feed: it changes a few times a year and a wrong date is a wrong security claim. A test
   fails 60 days before any listed date passes so the table is reviewed.
6. **Exposure lowers priority, never closes a finding.** A CVE in a role that isn't installed stays open (the build is
   still vulnerable and adding the role exposes it) with the reason "Windows DNS Server role not installed".
7. **New remediation paths keep the Windows contract:** closed job schema, local opt-in, dry run/permanence check before
   change, verified by fresh inventory, rollback or refuse. A path with no real rollback is offered only as an explicit,
   labelled "forward-only" plan: manual approval, a ConfirmDialog that says it can't be undone, never automated by the
   trust ladder or canary rings.
8. **Third-party fixes through winget, pinned in the agent.** Third-party patching is a paid add-on where commercial scanners offer it at all. The
   agent holds the map curated product key → winget ID (from the `winapps.py` products); the server only names the
   product key and target version. `winget` runs with `--source winget --exact --id`, winget's own installer-hash check,
   and only to a version newer than installed and at least the fixed version. A compromised server can therefore only
   upgrade a curated app to a newer published version, the same residual as DECISIONS 27.
9. **No Python on the host: the agent ships with Python's official embeddable runtime**, not a frozen exe.
   `python-3.x.y-embed-{amd64,arm64,win32}.zip` from python.org is made for embedding, its `python.exe` is
   Authenticode-signed by the Python Software Foundation, and the agent stays one auditable `.py` with self-update
   unchanged. Each runtime's version and SHA-256 are pinned in the repo (`agent/windows-runtime.json`) and carried in
   the **signed** `release.json`, so the server only relays bytes the release key vouched for. The installer also
   checks the PSF signature on `python.exe` before running it, which doesn't depend on the server at all. Runtimes
   live in `Program Files\Nimstead\runtime\<sha12>\` (administrators only, so the existing "SYSTEM runs only an
   interpreter under Program Files" rule still holds), and a new runtime is switched to by re-registering the
   scheduled tasks, which the agent already owns (`schedule`).
   Rejected: PyInstaller/Nuitka exes (the AV false positives that come with frozen Python exes, a code-signing
   certificate needed before anyone trusts them, PyInstaller's one-file mode unpacking into a temp folder as SYSTEM,
   and a self-update path rebuilt from scratch); an MSI (needs that same certificate to be credible; every fleet tool
   (Intune, GPO, ConfigMgr) can run `install.ps1`, so it's a follow-up once a certificate exists).
10. **Third-party breadth comes from curation plus a second source, never fuzzy matching.** NVD's backlog leaves many
    recent CVEs with no CPE configuration, so for curated products the feed also reads the CVE List v5 `affected` data
    (from the CNA itself, e.g. Google or Mozilla) and CISA's Vulnrichment entries, through the same per-product
    normaliser. A product is added to the map only with a real-install test: the harness installs an old and a fixed
    version with winget in a VM and checks inventory → match → finding → closed. That keeps DECISIONS 24's precision
    and makes adding products routine.
11. **Hardening checks are CVE-grade only, each with its reason and evidence.** Only settings that attackers exploit
    directly (relay, credential theft, privilege escalation) and that commercial scanners report inside vulnerability
    management. They reuse T10's closed agent list and `WinConfig` ecosystem. A fix is offered only when it is one
    recorded registry or feature change that can be put back exactly, so rollback restores the value that was there.
12. **Remediation obeys time and topology.** A job dispatches only inside the asset's maintenance window (none set =
    any time, as today); the agent may download early but installs and reboots only in the window. Hosts that share a
    failover cluster, or are domain controllers of one domain, form a serialisation group: one Windows job in flight
    per group, the node drained first. Workstations with a signed-in user get a notice and a deferral up to a deadline.
13. **The agent stays an observer of Active Directory, not a scanner.** Unmanaged-host discovery reads computer
    objects with the machine's own identity on an opted-in host (no stored credentials, no network probing) and
    reports names and OS strings only.

## Dependency graph
```
T0 CVRF data spike ──┬─> T2 hotpatch track ──────────────> T15 hotpatch remediation
                     ├─> T5 MSRC product allowlist (Edge) ─┬─> T6 .NET ──> T16 .NET remediation
                     │                                     ├─> T7 SQL Server ──> T19 Exchange + SharePoint
                     │                                     ├─> T8 Store apps     T20 Defender
                     │                                     │   T21 winget fix (agent) ──> T22 forward-only plans (server + UI)
                     │                                     └─> T9 M365 Apps ──> T17 M365 remediation
                     └─> T11 role-aware scoring
T1 WUA oracle harness ──> (every checkpoint)               T10 config checks (Secure Boot first)
T3 lifecycle/EOL ──> T4 unmapped OS still reports          T12 update-management context ──> T14 "why not offered"
T13 Windows health parity (independent)                    T18 Windows 10 / Server 2016-2022 VM proof (after T2, T12, T27)
T23 pinned runtime in the signed release ──> T24 server relays it ──> T25 install.ps1 without Python
                                                                 └──> T26 agent keeps its runtime current ──> T27 VM proof
T3 ──> T28 lifecycle beyond the OS          T5 ──> T29 more Microsoft products
T30 CVE v5 + Vulnrichment ──> T31 app batch 1 (+ real-install harness) ──> T32 batch 2 ──> T33 batch 3 ──> T21 winget IDs
T34 offline user hives      T35 jar scan     T10 ──> T36, T37 hardening ──> T38 reversible config fixes
T39 threat context (independent)            T40 maintenance windows ──> T41 reboot policy ──> T42 cluster/DC groups
T43 AD discovery (independent)              T44 proxy + fleet scheduling (before T27)
```

## Task list (details and acceptance criteria in `tasks/todo.md`)

### Phase 0: Ground truth (highest risk first)
- [x] T0: CVRF data spike: real fixtures for hotpatch, Edge, .NET, SQL Server, Exchange, Store apps, Defender, Office
- [x] T1: WUA oracle harness: our open OS findings vs Windows Update's missing security KBs, per VM

### Checkpoint A: the numbers we are trying to improve are written down

### Phase 1: OS detection correctness
- [x] T2: Hotpatch and cumulative fixes as separate tracks (detection + KB choice)
- [x] T3: OS lifecycle findings (end of support, ESU, ending within 90 days)
- [x] T4: An unmapped OS still reports apps and says why the OS isn't matched (Server 2012/R2, 23H2 names added)

### Checkpoint B: oracle agreement on Server 2025 + Windows 11; no regressions in the full suite

### Phase 2: Microsoft components from MSRC
- [x] T5: MSRC product allowlist, first slice Microsoft Edge (and Edge out of the NVD map)
- [x] T6: .NET (runtimes and Framework) (runtimes; .NET Framework dropped: compound MSRC builds, DECISIONS 51)
- [x] T7: SQL Server with GDR/CU tracks
- [x] T8: Inbox Store (MSIX) apps
- [x] T9: Microsoft 365 Apps (Click-to-Run) by channel
- [x] T19: Exchange Server and SharePoint Server
- [x] T20: Microsoft Defender engine and platform

### Checkpoint C: each product proven on a real install in a VM; noise review of a real fleet export

### Phase 3: "Patched but not protected" and exposure
- [x] T10: Config checks: Secure Boot 2023 certificates, BlackLotus mitigations, opt-in CVE mitigations
- [x] T11: Role/feature-aware priority (Server roles, client optional features)
- [x] T12: Update-management context on the asset (WSUS/WUfB, ESU, pending reboot, last WU success)

### Checkpoint D: UI shows each new fact; axe clean; self-review notes written (decision 7)

### Phase 4: Remediation
- [x] T13: Windows health parity: crash and restart events since the change
- [x] T14: Say why Windows Update didn't offer the KB (WSUS approval, deferral, ESU), opt-in direct Microsoft Update search
- [ ] T15: Hotpatch remediation (no reboot) on an enrolled VM — BLOCKED on the owner (Azure subscription); the two-KB job ships (T2)
- [ ] T16: .NET cumulative update through `WinJob` with DISM rollback — DROPPED: .NET Framework isn't detected (DECISIONS 51, 57)
- [x] T17: Microsoft 365 Apps update to a pinned build, rollback to the previous build
- [x] T21: winget fix for curated apps and Edge, IDs pinned in the agent
- [x] T22: Forward-only plans: manual approval only, labelled, never automated
- [ ] T18: Real-VM proof on Windows 10 (LTSC 2021 eval), Server 2016, 2019, 2022 (detection + one fix + one rollback each) — partly: Windows 11 re-proven on the new code; Windows 10 / Server 2016–2022 need evaluation ISOs (not on this machine)

### Phase 6: Third-party and on-disk breadth
- [x] T28: End-of-life findings beyond the OS (Microsoft products and curated apps)
- [x] T29: Remaining Microsoft products with numeric MSRC builds
- [x] T30: Second advisory source for curated apps: CVE List v5 (CNA) and CISA Vulnrichment
- [x] T31: App batch 1 (runtimes and browsers) and the real-install harness (code + real-install harness; products proven in a VM listed in STATUS)
- [x] T32: App batch 2 (remote access, VPN and file transfer)
- [x] T33: App batch 3 (virtualisation, backup, vendor tools, drivers, servers)
- [x] T34: Per-user apps of users who aren't signed in (offline hives)
- [x] T35: Opt-in Java library scan feeding the Maven matcher

### Checkpoint G: ~80 curated products, each proven by a real install; noise review repeated

### Phase 7: Hardening and threat context
- [x] T36: Hardening findings: network and authentication
- [x] T37: Hardening findings: privilege escalation and host protection
- [x] T38: Reversible configuration fixes for a closed subset
- [x] T39: Threat context: Microsoft's exploitability index, KEV ransomware use, public exploits

### Phase 8: Fleet-grade remediation operations
- [x] T40: Maintenance windows (dispatch gate, early download)
- [x] T41: Reboot policy (servers in window only; workstations notified and deferred; never on battery)
- [x] T42: Cluster and domain-controller serialisation groups
- [x] T43: Windows hosts with no agent, from Active Directory
- [x] T44: Proxy support and fleet-scale scheduling (jitter, low priority, resource budget)

### Checkpoint H: a 2-node failover cluster and a DC pair patched in a window, one node at a time, in VMs

### Phase 5: Python-free Windows agent (runs after Phase 1, see the rules above)
- [x] T23: Pinned embeddable runtimes, carried in the signed `release.json`
- [x] T24: The server fetches the release's runtimes and serves them to agents
- [x] T25: `install.ps1` installs without Python (runtime checked by hash and PSF signature)
- [x] T26: The agent keeps its runtime current and moves hosts off a system Python
- [x] T27: VM proof: Windows 11 + Server 2025 with no Python, update of agent and runtime by the task alone, clean uninstall (Windows 11 and Server 2025 Core PASS)

### Checkpoint F: Python-free install proven; docs and out-of-band verification steps updated

### Checkpoint E (release gate): full matrix, oracle table, STATUS/DECISIONS/CHANGELOG updated

## Risks and mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| MSRC shapes differ from what this plan assumes (hotpatch, Office "FixedBuild" is a URL, .NET per-OS names) | High | T0 first; every later task names the fixture it depends on and stops if the shape isn't there |
| Hotpatch needs a paid subscription + Azure Arc on-prem | Med | Detection (T2) and the two-KB job (decision 8) ship regardless; T15's real proof waits for an Azure "Datacenter: Azure Edition" VM |
| SQL Server GDR/CU: wrong track = false "fixed" | High | Track from the build band, refuse to match when the band is unknown; table tests from Microsoft's build lists |
| Config checks read as "you're vulnerable" on hardware that can't take the fix (firmware) | Med | Distinct status "needs firmware/vendor action" with the event ID evidence, not fix-now |
| Microsoft 365 Apps data source isn't a documented API | Med | Schema-checked every sync; unusable → T9/T17 dropped and Office covered by lifecycle only (decision 9) |
| VM time: every Windows proof is hours (reboots, NEM hangs) | Med | Reuse `winvm.py` cold boot; one VM per release, snapshot before each fix |
| winget as SYSTEM for third-party apps | High (trust) | IDs pinned in the agent, server names only a product key + version (decision 8); independent security review of T21 before release |
| Current Python doesn't run on Server 2012/R2 (Python stopped supporting Windows 8.1-era systems after 3.11) | Low | Bundled runtime supports Windows 10 / Server 2016 and newer; `install.ps1` refuses older hosts with that reason. Those hosts are past end of support (T3 says so) and stay detectable only with a system Python |
| Hardening fixes break things (SMB signing vs legacy NAS, NTLMv1 vs old apps) | High | Config fixes are canary-gated like packages, health-checked, put back exactly on failure; never automated by default (manual tier until an admin raises it) |
| Loading an offline user hive while that user signs in gives them a temporary profile | Med | Load, read, unload within seconds; skip hives whose profile is in use; VM test signs in during a scan (T34) |
| Jar scan reads every disk | Med | Opt-in, fixed drives only, a time and file-count budget, low I/O priority; reports what it skipped |
| Curated app list goes stale as vendors rename products | Med | Real-install tests run in CI-style batches before each release (the T31 harness); a renamed product shows as "inventory only", never a false match |
| Cluster drain on a cluster the agent misreads | High | Serialise only (one node per group) when drain isn't confirmed by `Get-ClusterNode` state; drain failure aborts with "No changes made" |
| A Python security fix needs a runtime update across the fleet | Med | T26: a new pinned runtime ships in the next signed release and every agent switches to it on its own; the release checklist checks python.org for a newer patch release |
| Embeddable runtime is missing a module the agent uses | Med | T25 runs the agent's full test suite under the embeddable runtime in CI (Windows runner) |
| winget isn't on PATH for SYSTEM / missing on Server | Med | Resolve `winget.exe` from the App Installer package folder under Program Files\WindowsApps (owner must be TrustedInstaller); not found = "winget unavailable" on the asset, plan refused with that reason |

## Not doing in this round (on purpose)
- Agentless credentialed scanning over WinRM/SMB and unauthenticated internal scanning: see the coverage matrix.
- Full CIS/STIG benchmarks: its own plan; T36/T37 cover the settings attackers exploit directly.
- Ticketing/SIEM connectors, trend dashboards: not Windows-specific; on the general roadmap.
- Offline/air-gapped `.msu` installs from the Update Catalog; feature updates (23H2 → 24H2) and enablement packages.
- macOS, Intune/ConfigMgr connectors, decoding `collection.mumx`.
- An MSI installer and Authenticode-signing our own files: after the owner has a code-signing certificate
  (architecture decision 9). `install.ps1` covers Intune, GPO and ConfigMgr until then.

## Decisions on the open questions (2026-10-29, made for parity with commercial scanners; 6 added the same day)
1. **Hotpatch:** detection (T2) ships regardless; it's the correctness bug. Remediation (T15) is proven on an Azure
   "Windows Server 2025 Datacenter: Azure Edition" VM, where hotpatch needs no Arc subscription. Needs an Azure
   subscription from the owner (a few hours of one VM); until then T15 waits and nothing else does.
2. **Forward-only fixes:** allowed, manual-only (architecture decision 7). Edge and curated third-party apps get them
   through winget (decision 8, T21–T22). Competitors patch forward-only too; we label it and never automate it.
3. **Microsoft 365 Apps data:** Microsoft's `OfficeReleases` JSON (what Evergreen and Patch My PC use), schema-checked
   on every sync; a changed schema fails the feed loudly and keeps the last good data, like every other feed.
4. **Windows 10 / older Server proof:** Microsoft Evaluation Center ISOs: Server 2016, 2019, 2022 (180-day eval) and
   Windows 10 Enterprise LTSC 2021 if it's still offered. Without a Windows 10 image, Windows 10 22H2 stays
   unit-tested (incl. ESU) and STATUS says remediation there is unproven.
5. **Detection scope widened** to what both competitors flag on Windows: Exchange and SharePoint (heavy on CISA KEV)
   and Defender engine/platform (T19–T20).
6. **Python-free agent is in this plan** (Phase 5, architecture decision 9), not a later one: neither competitor
   asks for a runtime on the host, and the owner's open question from plan-0.4 is answered here.

## Remaining decisions (2026-10-29, round 2): nothing in this plan waits on a choice
7. **No owner review stops /goal.** Mid-plan "owner review" gates are self-reviews: the executor writes what it
   decided and why into DECISIONS and a "Review notes" section at the end of STATUS, and the owner reviews it all at
   the pull request. The only owner steps are in "Needs the owner".
8. **Hotpatch without knowing enrolment.** A Windows job may carry the cumulative KB *and* the same month's hotpatch
   KB, each with its target build; the agent installs whichever one Windows Update offers (exactly one, as today) and
   verifies against that one's target. Detection: a host whose installed build is a known hotpatch build is on the
   hotpatch track; every other host is compared with cumulative builds (the stricter answer). No enrolment signal
   needed. If T0 finds a documented one, it's reported as context only.
9. **Fallbacks when data isn't usable** (found in T0 or later): Microsoft 365 Apps without a usable `OfficeReleases`
   schema → T9/T17 dropped, recorded in DECISIONS and STATUS, Office covered by lifecycle only (T28). .NET Framework
   without an exact comparable version → .NET Framework dropped, .NET runtimes kept. Any product with no numeric
   build → dropped with the reason. Nothing is approximated to keep a task alive.
10. **SQL Server editions** (Express, Developer, Standard, Enterprise, LocalDB) share engine builds, so all are
    covered by the version's product name; edition is shown, never used for matching.
11. **Config-step CVEs in T10** (the set commercial scanners flag after patching): Secure Boot 2023 certificates;
    CVE-2023-24932 (BlackLotus) boot manager revocations; CVE-2013-3900 (`EnableCertPaddingCheck`, both registry
    views); certificate-based authentication strong mapping on DCs (KB5014754, `StrongCertificateBindingEnforcement`);
    speculative-execution mitigations on Windows Server, which ship disabled (`FeatureSettingsOverride` /
    `FeatureSettingsOverrideMask`). Each encodes the per-build default, because several became enforced by default.
12. **Office apps running during an update (T17):** never force-closed. On a workstation the job waits for the
    notice/deferral flow of T41; on a server or session host it's refused with "Office in use" and retried at the next
    poll inside the window.
13. **Java vendors (T31):** Oracle JDK/JRE (incl. Java 8, normaliser fixed) match `oracle:jdk` / `oracle:jre`;
    Temurin, Corretto and Microsoft Build of OpenJDK match `oracle:openjdk` only, plus T30's CVE v5 data. Java SE
    critical-patch CVEs that list only Oracle's products are not projected onto OpenJDK builds; STATUS names that
    residual.
14. **Bundled Python version (T23):** the newest CPython 3.x minor that has had at least two bugfix releases (3.14.x at
    the time of writing), latest patch release, pinned by hash. Each release checks python.org for a newer patch.
15. **Exploit data (T39):** Metasploit's `db/modules_metadata_base.json` from `rapid7/metasploit-framework`, fetched
    daily, schema-checked, CVE references only. ExploitDB isn't added: proof-of-concept quality varies and EPSS
    already reflects public exploit code.
16. **Release target:** platform 0.6.0, agent 0.4.0 (new managers, runtime, collection). The owner signs it as a
    preview first, then beta after 2 weeks with no agent regressions, then stable; that sequence is the owner's.
