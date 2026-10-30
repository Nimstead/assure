# Windows round 1: task list

Plan, decisions and risks: `tasks/plan.md` (read its "Rules for whoever executes this" and "Needs the owner" first).
**Order: Phase 0 → 1 → 5 → 2 → 6 → 3 → 7 → 8 → 4 → Checkpoint E** (sections below are numbered by phase, not run order). Work on a branch `windows-round-1`; commit per task; don't push, tag or release.
Owner-blocked tasks (T15 without Azure, the Windows 10 part of T18 without an image) are skipped and listed in STATUS, never faked.
Verify every task with: `cd api && uv run pytest -q && uv run ruff check src tests ../agent ../sandbox ../scripts`
(plus `cd web && npm test && npm run build && npm run e2e` when `web/` changes, and `uv run python ../sandbox/pg.py`
when a migration is added). "VM" = a disposable VM from `sandbox/winvm.py`, never this machine.

---

## Phase 0: Ground truth

### T0: CVRF data spike  (S: fixtures + notes, no product code)
**Description:** Download real CVRF months (at least 2025-Sep, which carries the Server 2025 hotpatch KB, and the latest
full month) and record what the plan assumes. Write the findings into DECISIONS as one entry.
**Acceptance criteria:**
- [x] Trimmed real fixtures under `api/tests/fixtures/msrc/` showing: a hotpatch remediation beside the cumulative one
      for one CVE (field that tells them apart), Edge, .NET (runtime and Framework, with product names), SQL Server
      GDR + CU for one CVE, one inbox Store app, Defender, Microsoft 365 Apps (what `FixedBuild` holds)
- [x] For each product: "numeric FixedBuild: yes/no", the inventory value on a host that compares with it, and the
      decision (in / out / needs another source) recorded in DECISIONS
- [x] The CVRF "Tag" note values for the server roles T11 needs (DNS Server, DHCP, RRAS, Hyper-V, IIS/HTTP.sys, AD DS,
      RDS, MSMQ) are listed
**Verification:** fixtures load in a throwaway test; DECISIONS entry written (self-review, plan decision 7).
**Dependencies:** none · **Files:** `api/tests/fixtures/msrc/*.json`, `DECISIONS.md`

### T1: WUA oracle harness  (M)
**Description:** A sandbox harness that, in a VM, runs the real agent, then asks Windows Update for missing security
updates, and compares KBs with the KBs of the host's open OS findings. Writes `sandbox/last_run_win_oracle_<vm>.json`.
**Acceptance criteria:**
- [x] Table per VM: KBs both agree on, KBs only Windows Update reports, KBs only we report, each with the CVEs involved
- [x] Runs unchanged against Server 2025 and Windows 11 26H2 VMs and records today's baseline — **2026-10-29: Windows 11 26H2 and Server 2025 baselines recorded (`last_run_windows11_040.json`, `last_run_windows_server2025.json`, `last_run_windows_nopython_server2025.json`)**
- [x] A mismatch is explained in the run file (e.g. "hotpatch KB", "not offered: superseded"), never silently dropped
- [x] The VM opts in to Microsoft Update (`AddService2` for the Microsoft Update service), so the oracle also covers .NET, SQL Server and Office MSI updates for Phase 2
**Verification:** baseline run files committed; ruff clean.
**Dependencies:** none · **Files:** `sandbox/winoracle.py` (new), `sandbox/winvm.py` (reuse only)

## Checkpoint A
- [x] Baseline oracle tables for Server 2025 and Windows 11 26H2 committed — **2026-10-29: both, in the run files above**
- [x] T0 shapes match the plan; a product whose MSRC data has no numeric build is dropped from T6–T9/T19/T20 and the reason recorded

---

## Phase 1: OS detection correctness

### T2: Hotpatch and cumulative fixes as separate tracks  (M)
**Description:** Plan decision 8. `sync_msrc` stores hotpatch fixes under `<product> (Hotpatch)` and keeps the lowest
**cumulative** build for `<product>`. `scan.rescan` puts a host on the hotpatch track only when its installed build is
a known hotpatch build of that product; every other host is compared with cumulative builds. `remediate.plan` gives a
Windows job the cumulative KB plus, when one exists for the same month, the hotpatch KB (each with its target build);
`WinJob` installs whichever Windows Update offers (exactly one) and verifies against that KB's target.
**Acceptance criteria:**
- [x] A non-hotpatch host is compared only with cumulative-update builds; `test_sync_msrc_keeps_lowest_fixed_build_per_product` updated to say so
- [x] A host on a hotpatch build is compared with hotpatch builds (test from the T0 fixture)
- [x] Job with both KBs: WU offers one → that one installed and verified; offers both or neither → "No changes made" (fakes); state-file validation covers the second KB
**Verification:** API suite; T1 oracle rerun on Server 2025 shows no new disagreement.
**Dependencies:** T0 · **Files:** `api/src/nimstead/feeds.py`, `scan.py`, `remediate.py`, `agent/nimstead_agent.py`, `api/tests/test_windows.py`, `api/tests/test_winjob.py`

### T3: OS lifecycle findings  (M)
**Description:** A curated table (`lifecycle.py`: product, edition family, end date, ESU end, Microsoft source URL).
The agent adds `EditionID` and whether an ESU licence is active. A host past end of support without ESU gets one
finding ("Windows 10 22H2 Pro: no security updates since 2025-10-14") ranked fix-now; within 90 days: a planned-tier
finding. ESU hosts get "supported until <ESU end> by ESU".
**Acceptance criteria:**
- [x] Table covers Windows 10 22H2/LTSC 2019/2021, Windows 11 23H2–26H2 by edition family, Server 2012/R2–2025 and 23H2
- [x] A test fails 60 days before any end date passes (forces review); every row has a source URL
- [x] Findings open, close (after upgrade or ESU) and ledger like any other; evidence pack lists them
**Verification:** API suite; Assets page shows the lifecycle line (web unit test + axe in e2e).
**Dependencies:** none · **Files:** `api/src/nimstead/lifecycle.py` (new), `scan.py`, `agent/nimstead_agent.py`, `api/tests/test_lifecycle.py` (new), `web/src/assets.tsx`

### T4: An unmapped OS still reports  (S)
**Description:** `collect_windows` stops raising for an OS it can't name: it sends apps and lifecycle facts and an OS
package with an empty name and the reason. Add the names T0 confirms (Server 2012/R2 6.x builds, Server 23H2 build 25398).
**Acceptance criteria:**
- [x] Insider/unknown build: inventory arrives, apps are matched, the asset says "OS not matched: <reason>"
- [x] Server 2012 R2 gets its MSRC name and (via T3) its end-of-support finding
- [x] `test_msrc_product_name` table extended from real registry values
**Verification:** API + agent tests.
**Dependencies:** T3 (for the 2012 R2 finding) · **Files:** `agent/nimstead_agent.py`, `api/src/nimstead/app.py`, `api/tests/test_windows.py`, `web/src/assets.tsx`

## Checkpoint B
- [x] Full suite green on SQLite and PostgreSQL
- [x] T1 oracle rerun on Server 2025 and Windows 11: agreement equal or better than baseline, every gap explained — **2026-10-29: both agree on the OS KB (Server 2025: KB5126646). Every gap explained in the run file: .NET Framework KBs not detected (DECISIONS 51); Server 2025 older-month KB5122871 superseded by the agreed cumulative update**
- [x] Self-review notes for Phases 0–1 added to STATUS "Review notes" (plan decision 7)

---

## Phase 2: Microsoft components from MSRC

### T5: MSRC product allowlist, first slice Microsoft Edge  (M)
**Description:** `sync_msrc` keeps an explicit allowlist of non-Windows products (ecosystem `Microsoft`, its own
version comparator if `windows_cmp` doesn't fit). Edge is matched from MSRC by its registry version and removed from
the NVD map in `winapps.py`.
**Acceptance criteria:**
- [x] Only allowlisted product names are stored; a new MSRC product is ignored until added (test)
- [x] Edge on a host is matched against MSRC builds; an Edge CVE that NVD doesn't list for Edge is found (fixture)
- [x] Old `WinApp` Edge findings close and the new ones open in one rescan, both ledgered
**Verification:** API suite; real Edge on a VM: findings agree with Edge's own "About" version vs the MSRC fix.
**Dependencies:** T0 · **Files:** `feeds.py`, `winapps.py`, `scan.py`, `versions.py`, `api/tests/test_msrc_products.py` (new)

### T6: .NET runtimes and .NET Framework  (M)
**Description:** Agent inventories .NET runtimes (registry `dotnet\Setup\InstalledVersions`, every architecture) and
.NET Framework (NDP release + the version MSRC compares with, per T0; if MSRC gives no exact comparable version,
.NET Framework is dropped and only runtimes ship, plan decision 9). Allowlist entries added.
**Acceptance criteria:**
- [x] Side-by-side runtimes each matched against their own major's fix
- [ ] .NET Framework matched only against the MSRC product for this OS version (name built like the OS name) — **DROPPED: .NET Framework not detected (DECISIONS 51)**
- [ ] An unreadable .NET Framework version is inventory only, never "fixed" — **DROPPED with .NET Framework (DECISIONS 51)**
**Dependencies:** T5 · **Files:** `agent/nimstead_agent.py`, `feeds.py`, `api/tests/test_msrc_products.py`, `api/tests/test_agent.py`

### T7: SQL Server with GDR and CU tracks  (M)
**Description:** Agent reads each instance's `PatchLevel`; the feed stores GDR and CU fixes as separate tracks; the
track comes from the build band (Microsoft's published build ranges), unknown band = no match + reason.
**Acceptance criteria:**
- [x] A CU host above the GDR fix but below the CU fix is reported vulnerable (table test)
- [x] Two instances on one host give per-instance findings
- [x] Every edition (Express, Developer, Standard, Enterprise, LocalDB) matched by the version's product name; edition shown, never used to match (plan decision 10)
**Dependencies:** T5 · **Files:** `agent/nimstead_agent.py`, `feeds.py`, `versions.py`, `api/tests/test_msrc_products.py`

### T8: Inbox Store (MSIX) apps  (S)
**Description:** Agent inventories provisioned and installed MSIX packages (`Get-AppxPackage -AllUsers`, name +
version) for the MSRC products T0 found (Notepad, Snipping Tool, Paint…). Allowlist maps MSRC name ↔ package family.
**Acceptance criteria:**
- [x] A user's older copy of an app is reported (oldest wins, as for `WinApp`)
- [x] Packages outside the allowlist are inventory only
**Dependencies:** T5 · **Files:** `agent/nimstead_agent.py`, `feeds.py`, `api/tests/test_msrc_products.py`

### T9: Microsoft 365 Apps by channel  (M)
**Description:** Agent reads `ClickToRun\Configuration` (`VersionToReport`, channel from `CDNBaseUrl`/`UpdateChannel`).
Server maps each month's Office CVEs to the channel's security build from Microsoft's `OfficeReleases` JSON (plan
decision 3).
**Acceptance criteria:**
- [x] Current, Monthly Enterprise and Semi-Annual Enterprise channels each compared with their own build
- [x] Unknown channel or out-of-support build = lifecycle-style finding, not a CVE guess
- [x] A changed `OfficeReleases` schema fails the sync loudly and keeps the last good data (test)
**Dependencies:** T5 · **Files:** `agent/nimstead_agent.py`, `feeds.py`, `api/src/nimstead/office.py` (new), tests

### T19: Exchange Server and SharePoint Server  (M)
**Description:** Same pattern as T7. Exchange: `ExSetup.exe` file version (MSRC names products per CU/SE). SharePoint:
farm build from the registry. Allowlist entries per product name T0 recorded.
**Acceptance criteria:**
- [x] An Exchange host on an older CU is compared only with its CU's fix; an unsupported CU = lifecycle finding
- [x] A SharePoint KEV CVE on a vulnerable build is fix-now (fixture)
**Dependencies:** T7 · **Files:** `agent/nimstead_agent.py`, `feeds.py`, `api/tests/test_msrc_products.py`

### T20: Microsoft Defender engine and platform  (S)
**Description:** Agent reads the engine and platform versions (`Get-MpComputerStatus` or the Defender registry);
allowlist the MSRC Defender products.
**Acceptance criteria:**
- [x] Engine below the MSRC fix = finding; Defender absent or passive = inventory only, with the reason
**Dependencies:** T5 · **Files:** `agent/nimstead_agent.py`, `feeds.py`, `api/tests/test_msrc_products.py`

## Checkpoint C
- [ ] Each product from T5–T9, T19, T20 proven on a real install in a VM (run file committed) — **partly: Office installed in a VM and its fix proven (`last_run_winfixes_client.json`); Edge, .NET, SQL, Exchange, Defender not installed in a VM; the curated-app run covered third-party apps only (see T31)**
- [ ] Noise review: on the demo fleet + one real Windows VM, every new finding opened was checked by hand against Microsoft's KB/release notes; zero unexplained — **NOT done: needs a VM with the products installed**
- [x] Performance: `sandbox/perf.py` re-run, hourly re-match within 10 % of the last numbers — **22.5 s vs 20.8 s (+8 %), `last_run_perf_sqlite.json`**

---

## Phase 3: "Patched but not protected" and exposure

### T10: Config checks, Secure Boot first  (M)
**Description:** The agent reads a closed list: `SecureBoot\Servicing` (`UEFICA2023Status`, `UEFICA2023Error`,
`AvailableUpdates`), Secure Boot state, recent Secure Boot servicing events (1801/1808), and the keys for plan
decision 11: CVE-2023-24932 (BlackLotus) revocations, CVE-2013-3900 `EnableCertPaddingCheck` (64- and 32-bit views),
`StrongCertificateBindingEnforcement` on DCs (KB5014754), and Server speculative-execution mitigations
(`FeatureSettingsOverride`/`Mask`), each with its per-build default. `winconfig.py` turns them into
`WinConfig` findings with the CVE, the evidence and the next step.
**Acceptance criteria:**
- [x] A host whose 2023 certificates aren't applied gets a finding naming the expired 2011 CA and the status value; "Updated" closes it
- [x] Firmware that rejects the update (event evidence) is "needs vendor firmware", not fix-now
- [x] Secure Boot off / unreadable values = "can't tell" with the reason, never closed as fixed
- [x] No server-supplied registry paths reach the agent (schema test)
**Dependencies:** none · **Files:** `agent/nimstead_agent.py`, `api/src/nimstead/winconfig.py` (new), `scan.py`, `api/tests/test_winconfig.py` (new)

### T11: Role/feature-aware priority  (M)
**Description:** Agent reports installed Server roles/features and client optional features (names only). Feed keeps
the CVRF component tag; a curated tag → feature map lowers priority with the reason "<role> not installed".
**Acceptance criteria:**
- [x] MSMQ RCE on a host without MSMQ: open, lower priority, reason shown; installing MSMQ raises it on the next report
- [x] KEV-listed CVEs are never lowered (KEV override wins)
- [x] Unmapped tags change nothing
**Dependencies:** T0 · **Files:** `agent/nimstead_agent.py`, `feeds.py`, `risk.py`, `scan.py`, `api/tests/test_risk.py`

### T12: Update-management context  (S)
**Description:** Agent reports: WSUS server set (`UseWUServer`, server name), WUfB/Intune deferral policies, pending
reboot, ESU, last successful WU install. Asset page shows them; the remediation planner reads them.
**Acceptance criteria:**
- [x] Facts stored on the asset (Alembic migration, linear history) and shown on Assets
- [x] "Fix installed, restart pending" shown on the host instead of a stale "vulnerable" headline
**Dependencies:** none · **Files:** `agent/nimstead_agent.py`, `db.py` + migration, `app.py`, `web/src/assets.tsx`, tests

## Checkpoint D
- [x] Full suite on SQLite + PostgreSQL; web unit + e2e, axe 0 serious/critical at 1440 and 375, light and dark
- [ ] Self-review of how config, lifecycle and exposure findings read in the UI (screenshots at 1440 and 375 in STATUS "Review notes") — **NOT done: no screenshots of config/lifecycle findings taken**

---

## Phase 4: Remediation

### T13: Windows health parity  (S)
**Description:** Like DECISIONS 29 for systemd: a health unit fails if the Service Control Manager logged a crash or
unexpected stop for it (7031/7034/7024) since the change, or the host logged an unexpected shutdown (41) / bugcheck (1001).
**Acceptance criteria:**
- [x] A service that crashes and is restarted by recovery actions fails health even if "Running" when sampled (VM) — proven on Windows 11 (`last_run_winchecks.json`: Spooler killed, seen Running, crash event 7031 caught)
- [x] Failure output names the event and time
**Dependencies:** none · **Files:** `agent/nimstead_agent.py`, `api/tests/test_winjob.py`

### T14: Say why Windows Update didn't offer the KB  (S)
**Description:** When `PS_FIND` returns nothing, the step output uses T12's facts: "WSUS <server> hasn't approved
KBx", "deferred by policy until <date>", "needs an ESU licence". New local-only agent flag
`--windows-update-source microsoft` (never settable by the server) searches Microsoft Update directly.
**Acceptance criteria:**
- [x] Each reason has a test with the WUA result faked
- [x] The server can't change the update source (enrol and job schema tests)
**Dependencies:** T12 · **Files:** `agent/nimstead_agent.py`, `api/tests/test_winjob.py`, `docs/install.md`

### T15: Hotpatch remediation  (M; needs the owner's Azure subscription)
**Description:** T2 already sends both KBs; this task proves the hotpatch branch for real. `WinJob` takes the no-reboot
path it already has; the permanence check must accept the hotpatch package format or refuse it. Proven on an Azure "Windows Server 2025
Datacenter: Azure Edition" VM (plan decision 1).
**Acceptance criteria:**
- [ ] Real enrolled VM: hotpatch installed, no reboot, verified by inventory; forced failure: removed (or refused before install if not removable, with the reason) — **BLOCKED on the owner (Azure subscription)**
**Dependencies:** T2 · **Files:** `agent/nimstead_agent.py`, `remediate.py`, `sandbox/wine2e.py`, tests

### T16: .NET cumulative update through WinJob  (M)
**Description:** Generalise `ROLLUP`/`ROLLUP_NAME` to a closed set of package families (RollupFix, DotNetRollup);
verify by the .NET Framework version from T6 instead of the OS build.
**Acceptance criteria:**
- [ ] Job schema still closed (family is an enum); state-file validation updated — **DROPPED with T16 (DECISIONS 51, 57)**
- [ ] VM: .NET KB installed, verified; forced failure: DISM removed, original version back — **DROPPED with T16**
**Dependencies:** T6, T40, T41 · **Files:** `agent/nimstead_agent.py`, `remediate.py`, `api/tests/test_winjob.py`, `sandbox/wine2e.py`

### T17: Microsoft 365 Apps update with rollback  (M; only with T9)
**Description:** New manager `office`: `OfficeC2RClient.exe /update user updatetoversion=<build>` to the planned build;
rollback = the same to the recorded previous build. Build matched by a strict regex.
**Acceptance criteria:**
- [x] VM: update verified by inventory; forced failure rolls back to the exact previous build — proven on Windows 11 (`last_run_winfixes_client.json`: Microsoft 365 Apps 16.0.20527.20088 → .20112, forced failure back to .20088, then applied)
- [x] Office apps never force-closed: workstation waits through T41's notice/deferral; server or session host refused with "Office in use" and retried next poll in the window (plan decision 12)
**Dependencies:** T9 · **Files:** `agent/nimstead_agent.py`, `remediate.py`, tests, `sandbox/wine2e.py`

### T21: winget fix for curated apps and Edge  (M)
**Description:** New manager `winget`. The agent pins product key → winget ID for the `winapps.py` products and Edge;
the job carries only the product key and target version (strict regexes). The agent resolves `winget.exe` from the
TrustedInstaller-owned App Installer folder, runs `winget upgrade --source winget --exact --id <pinned> --version
<target> --silent --accept-package-agreements --disable-interactivity`, then verifies by fresh inventory.
**Acceptance criteria:**
- [x] A job naming an unknown product key, a winget ID, or a version not newer than installed is refused before anything runs (tests)
- [x] Dry run: `winget show --exact --id --version` must list the version with an installer SHA-256, else refuse
- [ ] VM: Notepad++ and 7-Zip upgraded as SYSTEM, findings closed by inventory; winget missing = refused with "winget unavailable" — **partly: 7-Zip upgraded as SYSTEM and confirmed by inventory on Windows 11 (`last_run_winfixes_client.json`); "winget unavailable" refusal proven on Server 2025 (`last_run_winfixes_server.json`); Notepad++ not upgraded (winget offered no older version to start from)**
**Dependencies:** T40, T41 (windows and reboots); starts with the existing 18 products, T31–T33 add IDs as they add products · **Files:** `agent/nimstead_agent.py`, `api/tests/test_agent_winget.py` (new), `sandbox/wine2e.py`

### T22: Forward-only plans  (M)
**Description:** `remediate.plan` offers `winget` fixes as forward-only: never auto-approved, never in canary/broad
rings, a ConfirmDialog that says "can't be undone", and the evidence ledger records the acknowledgement.
**Acceptance criteria:**
- [x] Trust ladder "Auto" never dispatches a forward-only job (test)
- [x] UI states "can't be undone" before approval; axe clean; e2e approves one
- [x] Evidence pack lists forward-only changes separately
**Dependencies:** T21 · **Files:** `api/src/nimstead/remediate.py`, `evidence.py`, `web/src/remediation.tsx`, `api/tests/test_remediate.py`, `web/e2e/app.spec.ts`

### T18: Real-VM proof on Windows 10, Server 2016, 2019, 2022  (M, long-running)
**Description:** Evaluation Center ISOs (plan decision 4). For each: install.ps1, T1 oracle table, one cumulative fix
through the scheduled task alone, one forced-failure rollback, evidence pack verified.
**Acceptance criteria:**
- [ ] `sandbox/last_run_windows_<version>.json` for each, PASS — **partly: Windows 11 re-proven on agent 0.4.0 (`last_run_windows11_040*.json`); Server 2025 PASS (`last_run_windows_server2025.json`: rollback to the exact build over two restarts, then applied by the agent's own task); Windows 10 / Server 2016–2022 BLOCKED (evaluation ISOs need Microsoft's registration form)**
- [x] Any gap found is fixed with a test, then rerun
- [x] No Windows 10 image available: STATUS says Windows 10 remediation is unproven
**Dependencies:** T2, T12, T13, T27 (VMs are installed without Python), T40, T41 · **Files:** `sandbox/wine2e.py`, `sandbox/winvm.py`, run files

---

## Phase 5: Python-free Windows agent (run after Checkpoint B)

### T23: Pinned embeddable runtimes in the signed release  (M)
**Description:** `agent/windows-runtime.json` pins one CPython release: version and, for `amd64`, `arm64` and `win32`,
the python.org URL of `python-<v>-embed-<arch>.zip` and its SHA-256 (plan decision 14: the newest 3.x minor with at
least two bugfix releases, latest patch). `scripts/sign_release.py` adds `runtimes: {arch: {version, sha256}}` to `release.json`; the agent's
`verify_release` validates that field strictly when present (manifests without it stay valid for older releases).
`release.yml` downloads the three zips, checks each SHA-256 against the pinned file, and uploads them to the release.
**Acceptance criteria:**
- [x] A manifest with a malformed `runtimes` entry (bad arch, version or hash) is refused by the agent (test)
- [x] `sign_release.py` refuses to sign when the pinned file is malformed; the signed bytes include the runtimes (test)
- [x] Workflow test (`tests/test_workflows.py` style): zips are hash-checked before upload, and the signing job still downloads no package tool
**Verification:** API suite incl. `test_agent_ed25519.py`, `test_agent_update.py`; `verify-release` on a locally signed manifest.
**Dependencies:** none · **Files:** `agent/windows-runtime.json` (new), `agent/nimstead_agent.py`, `scripts/sign_release.py`, `.github/workflows/release.yml`, tests

### T24: The server relays the release's runtimes  (S)
**Description:** Where `updates.py` already fetches the signed release files agents need, also fetch the runtime zips
named in the verified manifest, keep only ones whose SHA-256 matches it, and serve them at
`/agent/runtime/<arch>.zip` (404 when missing). No new trust: agents re-check the hash from the signed manifest.
**Acceptance criteria:**
- [x] A zip whose hash doesn't match the signed manifest is never stored or served (test, mocked GitHub)
- [x] Unknown arch → 404; path can't escape the release dir (test)
**Dependencies:** T23 · **Files:** `api/src/nimstead/updates.py`, `api/src/nimstead/app.py`, `api/tests/test_updates.py`

### T25: install.ps1 without Python  (M)
**Description:** `install.ps1` stops looking for Python. It reads the arch (`$env:PROCESSOR_ARCHITECTURE`), refuses
Windows older than 10 / Server 2016 with the reason, downloads `/agent/runtime/<arch>.zip`, extracts it to a fresh
folder under `Program Files\Nimstead\runtime\`, requires `Get-AuthenticodeSignature python.exe` to be `Valid` with
signer "Python Software Foundation", then runs the agent with it (`-I`) as today: enrol, report, schedule. It prints
the zip's SHA-256 next to the agent's for the out-of-band check. A CI job on `windows-latest` runs the agent unit tests
under the pinned embeddable runtime.
**Acceptance criteria:**
- [x] Script tests: no `py`/`python` lookup left; the signature check comes before the first run of `python.exe`; the token still never reaches a command line
- [ ] CI: agent tests pass under the embeddable runtime on Windows (proves no missing module: `ssl`, `ctypes`, `winreg`, `sqlite3` if used) — **CI job written (`ci.yml` windows-runtime); runs on the owner's first push, not run yet**
- [x] docs/install.md: Python requirement removed; the "install without trusting the server" steps cover the runtime zip
**Dependencies:** T24 · **Files:** `api/src/nimstead/static/install.ps1`, `.github/workflows/ci.yml`, `api/tests/test_agent_round4.py`, `api/tests/test_api.py` (existing install.ps1 tests), `docs/install.md`

### T26: The agent keeps its runtime current  (M)
**Description:** In `self_update` on Windows: when the verified manifest names a runtime for this arch whose SHA-256
differs from the one the agent runs on (recorded in the config at install), download it, check the hash, extract to
`runtime\<sha12>\`, check the PSF signature, run the agent's `collect` with it (the existing smoke test), then
re-register the scheduled tasks on it (`schedule`), and record it. The previous runtime folder is removed on the next
run, never the one running. A host on a system Python (installed before T25) moves to the bundled runtime the same
way. Never while a Windows job waits for its reboot (`WIN_STATE`), same as agent updates.
**Acceptance criteria:**
- [x] Wrong hash, bad signature, failed smoke test: the host keeps its runtime and tasks exactly as they were, reason reported (tests)
- [x] A downgrade to an older runtime version is refused, like agents (test)
- [x] `uninstall --yes` removes every runtime folder; `schedule` still refuses an interpreter outside Program Files
**Dependencies:** T23, T24 · **Files:** `agent/nimstead_agent.py`, `api/tests/test_agent_update.py`, `api/tests/test_agent_schedule.py`

### T27: VM proof without Python  (M, long-running)
**Description:** Fresh Windows 11 26H2 and Server 2025 Core VMs with no Python installed. Extend `sandbox/winupdate.py`.
**Acceptance criteria:**
- [x] The documented one-line install enrols, reports and registers SYSTEM tasks; `where python` finds nothing
- [x] The scheduled task alone moves agent X → X+1 and runtime patch A → B from locally signed test releases, then the next run changes nothing
- [x] A host on a system Python moves to the bundled runtime by the task alone
- [ ] `winlocal.py` attack rerun passes against the new layout (a standard user can't write any runtime folder) — **NOT rerun on the new layout (last `winlocal.py` run: 2026-10-28, agent 0.3.0)**
- [x] `uninstall --yes` leaves no Nimstead folder, task or key; `last_run_windows_nopython.json` committed
**Dependencies:** T25, T26, T44 · **Files:** `sandbox/winupdate.py`, `sandbox/winlocal.py`, run files

## Checkpoint F
- [x] T27 PASS on both VMs; full suite; ruff; docs/install.md and the README install line say "no Python needed" — **2026-10-29: Windows 11 and Server 2025 Core PASS (`last_run_windows_nopython*.json`)**
- [x] DECISIONS entry for architecture decision 9, with the rejected options

---

## Phase 6: Third-party and on-disk breadth

### T28: End-of-life findings beyond the OS  (M)
**Description:** Extend T3's `lifecycle.py` to Microsoft products (Office 2016/2019 MSI, SQL Server, Exchange,
SharePoint, .NET major versions, Visual C++ runtimes that Microsoft no longer supports) and, for the curated
third-party products, map each `winapps.py` key to an endoflife.date product (`/api/<product>.json`, schema-checked,
last good data kept on failure).
**Acceptance criteria:**
- [x] SQL Server 2014 and .NET 6 on a host each give one "no security updates since <date>" finding
- [x] A curated app on an end-of-life major (e.g. Node 18) is flagged; apps not in the map never are
**Dependencies:** T3 · **Files:** `api/src/nimstead/lifecycle.py`, `feeds.py`, `winapps.py`, `api/tests/test_lifecycle.py`

### T29: Remaining Microsoft products with numeric MSRC builds  (S)
**Description:** From T0's product list, allowlist every remaining Microsoft product whose `FixedBuild` is numeric and
whose installed version the agent can read exactly (expected: PowerShell 7, Visual Studio, Teams, OneDrive, Windows
Admin Center, Azure Connected Machine agent). Each gets a fixture test; any that fails either condition is listed in
DECISIONS as not covered, with the reason.
**Acceptance criteria:**
- [x] Each product added has a positive and a near-miss test from real MSRC data
**Dependencies:** T5 · **Files:** `feeds.py`, `agent/nimstead_agent.py`, `api/tests/test_msrc_products.py`

### T30: Second advisory source for curated apps  (M)
**Description:** For the CVEs touching curated products, read CVE List v5 records (`cvelistV5` delta feed): the CNA's
`affected` entries and CISA's ADP (Vulnrichment) CPEs and version ranges. Use them when NVD has no configuration for
that CVE yet, through the same product normaliser; NVD wins when both exist.
**Acceptance criteria:**
- [x] A CVE with no NVD configuration but a CNA `affected` range for Chrome produces the same `WinApp` row NVD would (fixture)
- [x] `versionType` other than the product's own scheme, or `status: unknown`, is ignored, never guessed
- [x] Incremental: only the delta since the last sync is fetched (test with recorded delta files)
**Dependencies:** none · **Files:** `feeds.py`, `winapps.py`, `api/tests/test_winapps.py`, `api/tests/fixtures/cvelist/` (new)

### T31: App batch 1 and the real-install harness  (M)
**Description:** `sandbox/winapps_e2e.py`: in a Windows VM, for each product, `winget install --exact --id <id>
--version <old>`, run the agent, check the finding, upgrade to the fixed version, check it closes. Batch 1: Java 8
(fix the dropped `1.8.0 updateN` normaliser; `oracle:jdk`/`oracle:jre`), Eclipse Temurin, Amazon Corretto, Microsoft
Build of OpenJDK (`oracle:openjdk` only, plus T30 data; Oracle-only Java SE CVEs not projected, plan decision 13), Brave, Opera, Vivaldi, Thunderbird, LibreOffice,
Foxit PDF Reader, Adobe Acrobat (full), KeePass, PHP. Each product also records its winget ID for T21.
**Acceptance criteria:**
- [ ] Every product in the batch: open → close proven by the harness (`last_run_winapps_batch1.json`) — **partly (`last_run_winapps_run1-3.json`, Windows 11): 7-Zip, WinSCP, VLC, KeePass proven old → new; Notepad++, OpenVPN, VS Code, Temurin, Microsoft OpenJDK identified at one version; the rest not installable at an older version by winget. Found and fixed: KeePass and Notepad++ (MSI) names**
- [x] A product whose registry name or version can't be matched exactly is left out and named in DECISIONS
- [x] Map positives and near-misses table-tested as today (`test_winapps.py`)
**Dependencies:** T30 (helps; not required) · **Files:** `winapps.py`, `sandbox/winapps_e2e.py` (new), `api/tests/test_winapps.py`

### T32: App batch 2: remote access, VPN, file transfer  (M)
**Description:** Same harness. TeamViewer, AnyDesk, Citrix Workspace, Cisco Secure Client (AnyConnect), FortiClient,
Palo Alto GlobalProtect, Ivanti Secure Access, OpenVPN, WinSCP, FileZilla, mRemoteNG, Slack, Webex. Products winget
can't install at an old version are proven from a recorded real registry export instead, and say so.
**Acceptance criteria:** as T31 (`last_run_winapps_batch2.json`) — **partly: WinSCP proven, OpenVPN identified at one version, FileZilla not installable; the rest not tried**
**Dependencies:** T31 · **Files:** `winapps.py`, `api/tests/test_winapps.py`, run file

### T33: App batch 3: virtualisation, backup, vendor tools, drivers, servers  (M)
**Description:** VMware Tools, VMware Workstation, VirtualBox, Docker Desktop, Veeam Backup & Replication and agent,
Dell Command | Update, HP Support Assistant, Lenovo System Update, NVIDIA display driver, Intel Driver & Support
Assistant, Apache Tomcat, Apache HTTP Server, OpenSSH for Windows (the optional-feature build is the OS; the
standalone MSI is an app), Splunk Universal Forwarder.
**Acceptance criteria:** as T31 (`last_run_winapps_batch3.json`); drivers read from the driver store version, not DisplayName — **NOT proven (VirtualBox 7.0.12 wouldn't install in the VM); drivers dropped (NVIDIA versions don't map, DECISIONS)**
**Dependencies:** T31 · **Files:** `winapps.py`, `agent/nimstead_agent.py` (driver versions), `api/tests/test_winapps.py`, run file

### T34: Per-user apps of users who aren't signed in  (S)
**Description:** As SYSTEM, for each profile in `ProfileList` whose hive isn't loaded: `reg load` it under a unique
temporary key, read its Uninstall key with the existing `windows_apps` code, `reg unload` at once. Removes the
DECISIONS 27 residual.
**Acceptance criteria:**
- [x] A signed-out user's per-user app is inventoried (VM) — proven on Windows 11 (`last_run_winchecks.json`: WinSCP 6.1.2 from a signed-out user)
- [x] The hive is always unloaded, also on error (test with a fake `reg`); a user signing in right after a scan gets their normal profile (VM) — fake `reg` test; on Windows 11 no temporary hive left and the user's own profile after (`last_run_winchecks.json`)
**Dependencies:** none · **Files:** `agent/nimstead_agent.py`, `api/tests/test_winapps.py`, `sandbox/winlocal.py`

### T35: Opt-in Java library scan  (M)
**Description:** Local opt-in `--scan-jars` (never set by the server). The agent walks fixed drives within a time
and file budget at low I/O priority, reads `META-INF/maven/**/pom.properties` (and nested jars one level deep), and
reports `Maven` packages with the jar path as source. The existing OSV Maven matcher does the rest (log4j-core 2.14.1
→ CVE-2021-44228, as SBOM ingest already proves).
**Acceptance criteria:**
- [x] A planted log4j-core 2.14.1 jar inside a fat jar is found; the finding names the path (test + VM) — test, and on Windows 11 with the nested path named (`last_run_winchecks.json`)
- [x] Budget exceeded: partial result reported as partial, with what was skipped
- [x] Works on Linux too (same code, `/` instead of drive letters)
**Dependencies:** none · **Files:** `agent/nimstead_agent.py`, `api/tests/test_agent.py`, `scan.py` (source shown), `docs/install.md`

## Checkpoint G
- [ ] ~80 curated products, each with a run file proving open → close on a real install — **NOT met: 39 curated products; 4 proven open → close on a real install, 5 more identified at one version**
- [ ] Noise review repeated on a VM with every batch installed: zero unexplained findings — **NOT done**

---

## Phase 7: Hardening and threat context

### T36: Hardening findings: network and authentication  (M)
**Description:** Extend T10's closed agent list and `winconfig.py` with: SMBv1 enabled, SMB signing not required
(server; and on DCs), LLMNR and NetBIOS over TCP/IP enabled, NTLMv1 allowed (`LmCompatibilityLevel` < 3), WDigest
`UseLogonCredential` = 1, RDP without NLA, SCHANNEL TLS 1.0/1.1 server enabled, LDAP signing and channel binding not
enforced (DCs). Each finding: reason, evidence (value read), ATT&CK technique, the fix.
**Acceptance criteria:**
- [x] Each check has a table test (secure, insecure, absent = OS default, unreadable = "can't tell")
- [x] Defaults per Windows version are encoded (e.g. SMBv1 absent by default on Windows 11) and tested
**Dependencies:** T10 · **Files:** `agent/nimstead_agent.py`, `api/src/nimstead/winconfig.py`, `api/tests/test_winconfig.py`, `web/src/findings.tsx`

### T37: Hardening findings: privilege escalation and host protection  (M)
**Description:** Unquoted service paths with a space and a user-writable parent, service binaries or folders
writable by non-admins, `AlwaysInstallElevated`, Print Spooler running on a DC, PowerShell 2.0 engine installed, LSA
protection off, Defender real-time protection off or signatures older than 7 days, a firewall profile off, BitLocker
off on the OS drive (workstations).
**Acceptance criteria:**
- [x] ACL checks use the same owner/ACE parsing as `secure_windows_dir`, tested with planted ACLs in a VM — fakes, and planted services on Windows 11: unquoted path and writable binary reported (`last_run_winchecks.json`)
- [x] Each check tested as in T36
**Dependencies:** T10 · **Files:** `agent/nimstead_agent.py`, `winconfig.py`, `api/tests/test_winconfig.py`

### T38: Reversible configuration fixes  (M)
**Description:** New manager `winconfig` for a closed list where the fix is one registry value or one Windows feature
state: SMBv1 off, SMB signing required, LLMNR off, WDigest off, NTLMv1 off, PowerShell 2.0 removed. The job names a
check ID only; the agent holds the change. It records the old value, applies, runs health checks (T13), and puts the
old value back on failure. Canary-gated; manual tier by default.
**Acceptance criteria:**
- [x] A job with an unknown check ID or any path/value is refused (schema test)
- [ ] VM: SMB signing required → health check fails (a legacy test client can't connect) → old value restored, verified by inventory — **partly: on Windows 11 an injected failure restored the old value and a real apply kept LanmanServer running (`last_run_winfixes_client.json`); no legacy client tried, so a health check failing on its own is not proven**
- [x] Changes that need a reboot follow T41's policy
**Dependencies:** T36, T13, T41 · **Files:** `agent/nimstead_agent.py`, `remediate.py`, `api/tests/test_winconfig.py`, `api/tests/test_remediate.py`

### T39: Threat context  (S)
**Description:** Add to risk reasons: MSRC CVRF `Threats` (Exploited, Publicly Disclosed, Exploitability Index:
"Exploitation More Likely/Detected"), the KEV ransomware flag already stored but unused, and a public exploit module
(Metasploit's `db/modules_metadata_base.json` from `rapid7/metasploit-framework`, daily, schema-checked, CVE
references only; no ExploitDB, plan decision 15). Ordering stays: KEV overrides.
**Acceptance criteria:**
- [x] "Exploitation Detected" in MSRC but not yet in KEV ranks fix-now with that reason
- [x] Ransomware use shown as a reason on KEV findings
**Dependencies:** T0 (CVRF threat fields) · **Files:** `feeds.py`, `risk.py`, `scan.py`, `api/tests/test_risk.py`

---

## Phase 8: Fleet-grade remediation operations

### T40: Maintenance windows  (M)
**Description:** Org default plus per-asset weekly windows (day, start, length, time zone). `remediate` dispatches a job
only inside its asset's window (none = any time, as today). The agent may download a Windows update early (new
`downloaded` phase in `WinJob`) and installs only in the window. UI on Assets and Settings.
**Acceptance criteria:**
- [x] A job approved outside the window waits, shows "waits for <next window>", and dispatches at its start (tests with a fixed clock)
- [x] A window ending mid-job never interrupts it; reboot rules are T41's
- [x] Alembic migration, linear history; PostgreSQL suite passes
**Dependencies:** none · **Files:** `db.py` + migration, `remediate.py`, `app.py`, `agent/nimstead_agent.py`, `web/src/settings.tsx`

### T41: Reboot policy  (M)
**Description:** Replaces the fixed `shutdown /r /t 60`. Servers: reboot only inside the window. Workstations with a
signed-in user: a notice (`msg *` / `shutdown /c` text) and deferral up to the org's deadline (default 24 h), then
reboot with a 15-minute warning. Never start an install on battery below 50 % or on a metered connection.
**Acceptance criteria:**
- [ ] Each branch tested with fakes; VM: signed-in user sees the notice, reboot happens at the deadline, job resumes and reports — **partly: every branch tested with fakes. Windows 11 run (`last_run_windows11_signed_in.json`): deferred, notice sent, agent restarted at about 67 min against a 1-hour deadline, job verified. Open: the notice was sent but no screenshot shows it on screen, and an earlier run restarted at 45 min, before the deadline; cause not found (that run didn't log who asked)**
- [x] The pending state survives the deferral (job state validated on every load, as today)
**Dependencies:** T40 · **Files:** `agent/nimstead_agent.py`, `remediate.py`, `api/tests/test_winjob.py`

### T42: Cluster and domain-controller serialisation groups  (M)
**Description:** The agent reports failover-cluster name and node state, and whether it is a DC (and its domain).
`remediate` allows one Windows job in flight per cluster and per domain's DCs. Cluster nodes are drained
(`Suspend-ClusterNode -Drain`) before install and resumed after verify or rollback; a failed drain = "No changes made".
**Acceptance criteria:**
- [x] Two nodes of one cluster approved together: the second waits until the first reports (test)
- [ ] VM (2-node cluster without shared storage, file-share witness): node drained, patched, resumed; roles stayed online — **NOT proven: no cluster in the sandbox**
- [ ] DC pair: one at a time, both healthy after (VM) — **NOT proven: no domain in the sandbox**
**Dependencies:** T40, T41 · **Files:** `agent/nimstead_agent.py`, `remediate.py`, `api/tests/test_remediate.py`, `sandbox/wincluster.py` (new)

### T43: Windows hosts with no agent, from Active Directory  (S)
**Description:** Local opt-in `--ad-discovery` on one domain-joined host: `[adsisearcher]` reads computer objects
(name, `operatingSystem`, `operatingSystemVersion`, `lastLogonTimestamp`) with the machine's own identity. Server
lists enabled computers seen in the last 30 days that have no enrolled agent, with their OS (and T3's lifecycle
verdict from the OS string).
**Acceptance criteria:**
- [x] Assets page: "N Windows computers in <domain> have no agent", exportable (CSV, existing export)
- [ ] No credentials stored or sent; disabled/stale computers excluded (tests); VM with a 2-DC domain — **partly: tests pass; 2-DC domain VM not run**
**Dependencies:** none · **Files:** `agent/nimstead_agent.py`, `app.py`, `db.py` + migration, `web/src/assets.tsx`, tests

### T44: Proxy support and fleet-scale scheduling  (S)
**Description:** `enroll --proxy URL` (local, stored in the config; or the machine's WinHTTP proxy when set), used for
every server call with the server's TLS checks unchanged and the agent key never sent to the proxy in clear.
Scheduled tasks get a random delay (6-hourly: up to 30 min; job poll: up to 2 min), run at below-normal priority, and
`collect` stays under 60 s and 150 MB on the T27 VMs.
**Acceptance criteria:**
- [x] VM behind a squid proxy with direct egress blocked: enrol, report, self-update and a fix all work — proven on Windows 11 with the harness's logging proxy, not squid (`last_run_windows11_proxy.json`)
- [x] Task XML has `RandomDelay` and priority set (test of `schedule_windows_script`)
**Dependencies:** none (run before T27) · **Files:** `agent/nimstead_agent.py`, `api/src/nimstead/static/install.ps1`, `api/tests/test_agent_schedule.py`, `docs/install.md`

## Checkpoint H
- [ ] 2-node failover cluster and a DC pair patched inside a window, one node at a time (VM run files) — **NOT proven: no cluster or domain VMs**
- [ ] A workstation VM with a signed-in user: notice, deferral, reboot at the deadline, job verified — **partly: see T41: passed once on Windows 11, but an earlier run's restart at 45 min is unexplained**

---

## Checkpoint E (release gate)
- [ ] Oracle table for every VM in the matrix, agreement and every disagreement explained — **partly: Windows 11 and Server 2025, every gap explained (see T1); the rest of the matrix is blocked (ISOs, cluster, domain)**
- [x] Every row of the plan's coverage matrix marked done with its evidence, or blocked with the reason — **done: Status column in tasks/plan.md's coverage matrix**
- [x] Full suite SQLite + PostgreSQL, web unit + e2e, perf rerun, pip-audit and npm audit 0 — **978 on SQLite and on PostgreSQL 17, web 46 unit + 10 e2e, perf as above, pip-audit 0, npm audit 0 (2026-10-29)**
- [x] Independent security review of the agent diff (new collection, new managers, closed schemas; T21 winget path and T26 runtime swap first)
- [x] STATUS.md (Done / NOT proven), DECISIONS, CHANGELOG, docs/install.md updated — **2026-10-29: STATUS, CHANGELOG, todo; no new DECISIONS (two name fixes, a cache)**
- [x] Versions bumped: `api/pyproject.toml` 0.6.0, `AGENT_VERSION` 0.4.0, CHANGELOG `[0.6.0]` section (plan decision 16)
- [x] STATUS "Review notes" lists every self-review decision for the owner's PR review; release itself is the owner's
