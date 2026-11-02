# Windows round 2: tasks

Plan and reasons: `tasks/plan-windows-round-2.md`. **Not started: needs review first.**

House rules from round 1 apply: one commit per task; don't push, tag or release; disposable VMs only; every new "why" goes
in DECISIONS.md; blocked means listed in STATUS, never faked.

**Every task's verification also includes:** `cd api && uv run pytest -q && uv run ruff check src tests ../agent ../sandbox ../scripts`.
When `web/` changes: `cd web && npm test && npm run build && npm run e2e`. After a migration: `cd api && uv run python ../sandbox/pg.py`.
Sizes: S = 1–2 files, M = 3–5 files.

## Phase 0: know where we stand

### W1: Coverage: assessed vs inventory-only (M)
Today an app outside the curated map is silently inventory, so "0 findings" can mean "not looked at".
- [ ] `GET` asset and summary responses give assessed and inventory-only app counts, and the names of those not assessed
- [ ] Host page and Home show it in plain words; a host with nothing assessed never reads as clean
- [ ] Fleet list of unassessed apps, most common first, which feeds W12
- Verify: tests with a seeded mixed host; screenshot from the VM with 50 apps. Files: `app.py`, `winapps.py`, `web/src/`. Deps: none.

### W2: Locale bug, proven on a German install (M)
Found while planning: `agent/nimstead_agent.py:551` compares ACL names with English strings (`BUILTIN\Users`, `Everyone`),
so on a localised Windows the service permission check would silently find nothing.
- [x] That check compares SIDs; tested on real ACLs by SID (a German name can't be faked on an English host, so the German install below is the proof)
- [x] Agent's tool output reviewed by reading: the WinHTTP proxy label and winget's hash label were language-dependent too, both fixed (DECISIONS 68). `dism` passes `/english`; `reg` and `secedit` read fixed names. Not confirmed: whether the ESU licence name is translated, and whether the German test strings match real output
- [ ] German evaluation install: enrol, report, settings audit and one update with rollback match the English results
- Verify: `sandbox/last_run_windows_de.json`. Files: agent, `test_agent_*`, `winvm.py` (locale option). Deps: none.

### W3: Side-by-side with Greenbone (M)
- [ ] Short look first: does the free feed's credentialed Windows scan cover patches and apps? If not, stop and report
- [ ] Same VM, old OS and old apps, both scanners; every CVE on only one side classified: ours missed, theirs wrong, or out of scope
- [ ] Each "ours missed" becomes a test or a W-task; the result lives in a private run file, no public claim
- Verify: `sandbox/last_run_compare.json`. Files: `sandbox/wincompare.py` (new), one report. Deps: none. Nessus only if you decide so.

## Phase 1: the OS matrix

### W4: Windows 10 LTSC 2021: real fix and rollback (M) **by mid-December 2026**
- [ ] ISO found (LTSC 2021 evaluation, else IoT LTSC); if neither, blocked and listed
- [ ] `wine2e.py`: finding opens, permanence check passes on a Windows 10 package, install, reboot, injected failure, DISM rollback to the exact build, then applied by the scheduled task
- [ ] Windows Update oracle agrees; .NET Framework proof (`winnetfx.py`) on this line; STATUS says exactly what's still unproven (ESU offer on 22H2)
- Verify: `last_run_windows10_ltsc.json`. Files: `winvm.py`, agent if it finds bugs. Deps: none.

### W5: Server 2022, then Server 2019 (M each)
- [ ] Each: fresh install, fix and rollback through the task, oracle comparison, `winnetfx.py`, hardening audit
- [ ] Differences found (package format, build mapping) fixed with a test
- Verify: `last_run_windows_server2022.json`, `..._server2019.json`. Deps: none.

### W6: Server 2016 and Windows 11 Enterprise (M each)
- [ ] Server 2016 (support ends January 2027, so lowest priority of the servers): same proof, or a clear refusal
- [ ] Windows 11 Enterprise evaluation: the same proof on an edition and release other than 26H2 Pro
- Verify: run files. Deps: W5.

### Checkpoint A
- [ ] Round 1 todo items for the matrix updated; W3's gaps reviewed with you; Phase 3 reordered if needed

## Phase 2: a real domain, in VMs

### W7: `winlab.py`: DC and member (M), the gate
- [ ] Memory per VM and a private network as options; Server Core DC promoted by script, member joined, Kerberos remoting works
- [ ] Peak host memory recorded with two and with three VMs running
- [ ] If it can't hold: stop Phase 2, say so in STATUS. No half-proof
- Verify: `last_run_winlab.json`. Files: `sandbox/winvm.py`, `sandbox/winlab.py` (new). Deps: W5.

### W8: Two DCs: discovery and one-at-a-time patching (M)
- [ ] AD discovery lists the real computers, leaves out disabled and stale ones, stores no credential
- [ ] Both DCs get a job: never at once, both healthy afterwards
- Verify: `last_run_windc.json`. Closes round 1 T42 (DC) and T43 items. Deps: W7.

### W9: Two-node cluster (M)
- [ ] File-share witness cluster; node drained, patched, resumed; the role stays online, checked from outside throughout
- [ ] Maintenance-window dispatch shown on the same run
- Verify: `last_run_wincluster.json`. Closes round 1 cluster items. Deps: W7.

### W10: Agentless and GPO install across real hosts (M)
- [ ] `scan-remote` from one member to another: same packages and settings as that host's agent reports
- [ ] A host with remoting off or no admin right reads as such, not as clean
- [ ] `install.ps1` by GPO startup script enrols a member with no one signed in; documented in `docs/install.md`
- Verify: `last_run_winremote_lab.json`, `last_run_wingpo.json`. Deps: W7.

### W11: SharePoint and Exchange collectors (S, time-box 1 day each)
- [ ] One try each from evaluation media, binaries only if that's enough for the collector
- [ ] Collected version compared with what the host itself reports, or the reason it couldn't run recorded
- Verify: run file or STATUS line. Deps: W7.

### Checkpoint B
- [ ] Every round 1 "NOT proven: no domain" line is closed or restated with the reason

## Phase 3: detection breadth

### W12: Rule proposer and first 25 apps (M)
- [ ] `sandbox/winapps_propose.py` ranks candidates by W1's list, NVD CVE count and winget presence, and prints draft rows; it never edits `winapps.py`
- [ ] 25 accepted rows, each with near-miss tests and `winapps_e2e.py` old-to-new proof where winget allows
- Verify: `last_run_winapps_batch7.json`. Deps: W1.

### W13: Batches to 200 apps (S each, repeated)
- [ ] Each batch ≤ 25, own run file and commit; every app labelled proven, or matched from a real name only, in UI and STATUS
- [ ] Stop early if the next batches have under 20 NVD CVEs each: say so rather than pad the count
- Deps: W12.

### W14: Full noise review (M)
- [ ] `winnoise.py` split across VMs so every curated app is covered (32 weren't; the disk ran out)
- [ ] The 2 `raw_says_applies_no_finding` from the last run explained
- [ ] 50 random findings checked by hand against vendor advisories, on Windows 11, a Server and Windows 10
- [ ] Drop "demo fleet" from the round 1 item: it's Linux, so the reason goes in DECISIONS
- Verify: `last_run_winnoise_full.json`. Deps: W13 (rerun at the end), W4, W5.

### W15: Vulnerable drivers by exact hash (M)
- [ ] LOLDrivers' licence and format checked; a feed syncs its hashes and fails loudly on a changed schema
- [ ] Agent reports the SHA-256 of loaded drivers within a size cap; only exact matches open findings
- [ ] Real VM: a known vulnerable driver file present is flagged, an unrelated driver isn't. File hashed, not loaded
- Verify: `last_run_windrivers.json`. Files: agent, `feeds.py`, `scan.py`. Deps: none.

### W16: Certificates and listening services (M)
- [ ] Machine store: expired, weak key and weak signature findings; roots not in Microsoft's list reported at low priority
- [ ] Listening non-loopback ports, with process and firewall state, raise priority of a matching product through `risk.py`, with the reason shown
- Verify: tests, `last_run_winexposure.json`. Deps: none.

### W17: Second exploit source; every install reported (S each)
- [ ] Public-exploit source beside Metasploit (check Exploit-DB's data and terms first), adds a reason in `risk.py`
- [ ] Two installs of one app both judged; today only the oldest is
- Deps: none.

### Checkpoint C
- [ ] W1's coverage re-measured on the VM with 50 apps; change reported; STATUS's stale apps line rewritten

## Phase 4: benchmarks

### W18: Rule table and terms check (M)
- [ ] DISA and Microsoft terms read and quoted in DECISIONS, amending 64; if they stop redistribution, ship IDs only
- [ ] One baseline (Server 2025 STIG): registry-based automated rules as data, evaluated server-side on agent facts; anything else reads "not assessed"
- [ ] Real VM: results for 20 sampled rules checked by hand against the guest
- Verify: `last_run_winbaseline.json`. Files: `winconfig.py`, new data file, agent's closed list. Deps: none.

### W19: Audit policy and user rights (M)
- [ ] `auditpol` read by subcategory GUID and `secedit` rights by SID, so language doesn't matter
- [ ] Automated rule count rises; German VM agrees (with W2)
- Deps: W18, W2.

### W20: Benchmark view and export (M)
- [ ] Per host and fleet: pass, fail, not assessed, with the baseline's version; wording claims no conformance
- [ ] CSV export; second baseline (Windows 11) added as data only
- Verify: e2e + axe. Deps: W18.

## Phase 5: remediation and fleet view

### W21: Fix first includes all fix paths (S)
- [ ] Settings, Office and winget fixes appear on Home with the same approval rules (STATUS review note)
- Deps: none.

### W22: Per-KB fleet view (M)
- [ ] "October 2026 cumulative: 41 of 50 hosts", drill to the hosts and why each isn't fixed, one action to plan the rest through canary rings
- Verify: tests, e2e, perf at 1,000 hosts with `perf.py`. Deps: none.

### W23: winget on Server (M, spike first)
- [ ] Can Microsoft-signed winget be installed on Server 2022/2025 by a hash-pinned, signature-checked path? If not, stop: DECISIONS entry and STATUS line
- [ ] If so: one app old-to-new as SYSTEM on Server, verified by inventory, person-approved as on clients
- Verify: `last_run_winfixes_server2.json`. Deps: W5.

## Phase 6: agent quality

### W24: `doctor` and a local log (M)
- [ ] `doctor` checks server reach, proxy, clock, tasks, folder ACL, Windows Update service, disk and runtime, and prints a fix for each failure
- [ ] Rotating log under the locked folder with no secrets (test asserts the key never appears); onboarding's troubleshooting points to it
- Verify: unit tests plus one run on a VM with the task removed and the service stopped. Deps: none.

### W25: Footprint (S)
- [ ] One scan on the VM with 50 apps: CPU time, peak memory, disk, duration, bytes sent, recorded per Windows version
- [ ] Limits chosen from that run and checked by the harness; published in `docs/install.md`
- Verify: `last_run_winfootprint.json`. Deps: none.

### W26: Failure runs (M)
- [ ] Hard power-off during install and during rollback: job resumes or reports honestly, and never stays stuck
- [ ] Disk full: refuses before changing anything. Server down for a day: next run catches up. Clock skew: a clear error
- Verify: `last_run_winfailures.json`. Deps: W24 helps. Bugs found get a test.

### Checkpoint D / W27
- [ ] Claude Security scan of the round's diff; findings fixed with a test each
- [ ] API on SQLite and PostgreSQL, web unit and e2e, ruff; STATUS, CHANGELOG, README and `docs/install.md` updated
- [ ] Plan's seven "great" conditions each marked met or not, with the run file

## Needs the owner
- [ ] Review this plan; answer its two open questions
- [ ] Push `windows-round-1`, run CI (the `windows-runtime` job has never run), merge, tag, approve the release
- [ ] Human pentest; code-signing certificate decision; Nessus decision
