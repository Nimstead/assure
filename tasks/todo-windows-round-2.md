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
- [x] `GET /api/assets` gives assessed and inventory-only counts per host; `GET /api/coverage` gives fleet totals and names
- [x] Assets and Home say it in plain words; a host with nothing assessed says so. Home's sentence has no test of its own
- [x] Fleet list of unassessed apps, most common first (top 200), which feeds W12
- [ ] Not done: screenshot from the VM with 50 apps, axe on the new section (the e2e seed has no Windows apps), `perf.py` at 1,000 hosts for the extra query on `/api/assets`. An app assessed through the agent's own Microsoft facts can read as "listed only" if it also has an Uninstall entry: errs towards under-claiming, to be measured on the VM `perf.py` at 1,000 hosts ran on 2026-11-04: `GET /api/assets` 0.43 s; at 200 hosts the coverage query adds 0.02 s (0.066 s to 0.083 s against the 2026-10-29 code on the same machine).
- Verify: tests with a seeded mixed host; screenshot from the VM with 50 apps. Files: `app.py`, `winapps.py`, `web/src/`. Deps: none.

### W2: Locale bug, proven on a German install (M)
Found while planning: `agent/nimstead_agent.py:551` compares ACL names with English strings (`BUILTIN\Users`, `Everyone`),
so on a localised Windows the service permission check would silently find nothing.
- [x] That check compares SIDs; tested on real ACLs by SID (a German name can't be faked on an English host, so the German install below is the proof)
- [x] Agent's tool output reviewed by reading: the WinHTTP proxy label and winget's hash label were language-dependent too, both fixed (DECISIONS 68). `dism` passes `/english`; `reg` and `secedit` read fixed names. Not confirmed: whether the ESU licence name is translated, and whether the German test strings match real output
- [x] German evaluation install (de-DE LTSC 2021, `last_run_windows10_de.json`): enrolled and reported; Windows Update's German titles ("Kumulatives Update") give the same oracle result as the English run (KB5122878 agrees, the same .NET CU unexplained); the settings audit read 29 audit subcategories by GUID, 30 user rights by SID and 101 registry values, 12 settings findings; the collection document is ok for every source
- [ ] German update with rollback: blocked like the English one, the evaluation image's licence service powered the VM off an hour after boot, mid-install (VBox.log, 01:00:30). Needs non-evaluation media (owner)
- Verify: `sandbox/last_run_windows_de.json`. Files: agent, `test_agent_*`, `winvm.py` (locale option). Deps: none.

### W3: Side-by-side with the reference scanner, then commercial scanners (M)
- [ ] Runs as an executable benchmark. Studying its source is the separate research track (E1, DECISIONS 79); whoever runs this comparison and fixes its gaps works from reports and vendor data
- [x] Short look first: does the free feed's credentialed Windows scan cover patches and apps? If not, stop and report. **Not for current Windows patches: stopped and reported** (2026-11-06, DECISIONS 110). From the free feed's own file listing (names only, nothing opened; 95,107 tests): 1,978 Microsoft KB tests, the newest for October 2025 (KB5066xxx), none for any month since; this year's whole addition is about 50 tests, one of them Microsoft's. Windows apps are covered (about 460 Chrome and 460 Firefox tests for Windows, Adobe, 7-Zip, Notepad++), also thin this year. The vendor's own comparison page names enterprise software such as Exchange as paid-feed only. So on a host patched past October 2025, every Windows CVE since would read "theirs missed" and prove nothing about us
- [ ] Waits on the owner (DECISIONS 110): a commercial scanner's trial, or the free feed on a VM held below October 2025. Same VM, old OS and old apps, both scanners; every CVE on only one side classified: ours missed, theirs wrong, or out of scope
- [ ] Each "ours missed" becomes a test or a W-task; the result lives in a private run file, no public claim
- Verify: `sandbox/last_run_compare.json`. Files: `sandbox/wincompare.py` (new), one report. Deps: none. A commercial scanner only if you decide so.

## Engine track: a real scanning engine (owner's priority, 2026-11-02; runs beside the OS matrix)

Boundary in DECISIONS 79: E1 is the research side; E2 onward never opens the reference scanner.

### E1: Research and licences (research side, outside this repo)
- [x] The reference scanner's architecture, knowledge base, dependencies, authenticated checks, patch and version logic, confidence and false positives studied; notes stay outside the repo
- [x] `docs/engine/spec-detection.md`: concepts and requirements in our own words; a licence report, each component's licence quoted, kept on the research side
- [x] Separate reviewer with source access passes the spec: nothing copied or closely paraphrased (ab07eb9; process not legally validated, DECISIONS 79)

### E2: First end-to-end Windows scan (L, split on starting)
- [x] Facts with provenance, detection rules with declared dependencies, a verdict of vulnerable, not vulnerable or can't tell, confidence and an evidence chain for each
- [x] Demonstrable: one command scans a real Windows VM and prints a report saying why each finding exists and what stopped any check from concluding
- [x] Existing OS, Microsoft and curated app detection runs through it with no finding lost or added unexplained, measured against the current pipeline (`last_run_winengine.json`: PASS on Windows 11)

### E3 onward: rule breadth; then Linux, network services, applications and attack-path correlation, in that order, each with a benchmark run
- [x] Linux: Debian 13 and AlmaLinux 9 PASS (`last_run_linengine_*.json`)
- [x] Network services: remote prober with scope proof, negative controls and safety classes, PASS (`last_run_netengine.json`)
- [x] Applications: Python, npm and Java installs and SBOMs, PASS on Debian 13 (`last_run_appengine.json`)
- [x] Attack paths on one host (DECISIONS 97, `docs/engine/design-paths.md`): shown on the real German Windows 10 host's inventory
- [x] Attack paths across hosts (DECISIONS 98): `GET /api/attack-paths` from stored reports and each host's own firewall state
- [ ] Routing between hosts seen by the network slice from inside a segment, and AD group membership, to raise those edges
- [ ] Findings open and close through the engine instead of `scan.rescan` (parity holds on every real run so far)
- [ ] Benchmark runs against the reference scanner, then commercial scanners (W3)

## Phase 1: the OS matrix

### W4: Windows 10 LTSC 2021: real fix and rollback (M) **by mid-December 2026**
- [x] ISO found: LTSC 2021 evaluation, direct from Microsoft (fwlink 2195404), no form
- [x] Finding opens, permanence check passes on a Windows 10 package (found and fixed: Windows 10 names only the servicing stack in its plan), install, reboot, injected failure, DISM rollback to the exact build 19044.1288, three times on final code (`last_run_windows10_ltsc_powercut.json`)
- [ ] NOT done: applied by the scheduled task. This evaluation image is in licence notification mode and `WLMS` shuts it down an hour after each boot; the reinstall after a rollback, and once the task's fix, ran past it (`last_run_windows10_ltsc_task.log`). `slmgr /ato` and `/rearm` didn't help. The shutdown was a real power cut mid-install: the agent reported no changes made within 4 minutes (DECISIONS 78), where before it left the job silent for hours. Found on the way: install.ps1 couldn't be rerun while an agent run held the runtime; winvm power-cycled a healthy Windows 10 VM and couldn't cold-boot a hung one. All fixed. Next try: Windows 10 IoT Enterprise LTSC evaluation, or a licensed image
- [ ] Windows Update oracle agrees; .NET Framework proof (`winnetfx.py`) on this line; STATUS says exactly what's still unproven (ESU offer on 22H2)
- Verify: `last_run_windows10_ltsc.json`. Files: `winvm.py`, agent if it finds bugs. Deps: none.

### W5: Server 2022, then Server 2019 (M each)
- [ ] Each: fresh install, fix and rollback through the task, oracle comparison, `winnetfx.py`, hardening audit
- [ ] Differences found (package format, build mapping) fixed with a test
- Server 2022 so far (`last_run_windows_server2022_not_offered.json`, `last_run_windows_server2022.json`): enrols, reports, oracle run; 2021 media is offered only 2023-11's KB5032198, so the server plans it as a step (DECISIONS 95) and the agent takes it, recording its SSU as permanent. Found and fixed: a second Windows Update search that hung 30 minutes and an ESU reason Server 2022 doesn't need (DECISIONS 96). Not done: the step's install ran past the agent's 2-hour limit on this host's VirtualBox, which runs on Hyper-V's slower engine (NEM), so the agent took its timeout path (roll back, remove what lands late). Needs a host with VT-x/AMD-V free for VirtualBox, or a longer run
- [ ] Server 2019: BLOCKED on this host. Two fresh installs from the evaluation ISO never got past the first boot (Windows' loading spinner, 16 KB written in 30 minutes; the first install's warm-reset loop is fixed, `winvm` now cold-boots). Server 2022 media boots here, so it's this build on VirtualBox's Hyper-V fallback engine (NEM), not the agent. Needs a host where VirtualBox gets AMD-V, or another hypervisor
- Verify: `last_run_windows_server2022.json`, `..._server2019.json`. Deps: none.

### W6: Server 2016 and Windows 11 Enterprise (M each)
- [x] Server 2016 (support ends January 2027, so lowest priority of the servers): same proof, or a clear refusal. **A clear refusal** (`last_run_windows_server2016.json`, 2026-11-04): it installs, enrols and reports here; from 14393.693 Windows Update offers only 2025-07's servicing stack update (KB5062799) and no cumulative, so the job stops with "No changes made" and names the update it offers instead. No step is planned: steps are cumulatives MSRC lists with a build, and servicing stack updates are permanent, which the agent refuses because they can't be rolled back
- [x] Your call: let a servicing stack update through as a forward-only, person-approved step (as winget is), so an old Server 2016 can reach a cumulative. **Allowed** (DECISIONS 105): planned when it's the only update offered, approved only by a person as forward-only, installed only if its own manifest names a servicing stack package; unit-tested
- [x] The same Server 2016 VM, through the servicing step to a cumulative: `last_run_windows_server2016_ssu.json` (2026-11-05). **Proven**: at 14393.693 Windows Update offered only KB5062799; the server planned it as a forward-only servicing step, the harness approved it as forward-only, the agent read the downloaded manifest (`KB5062799|selfUpdate=true|permanent`) and installed it, the KB verified with the build unchanged. Windows Update then offered July 2025's cumulative KB5062560, planned as a step and installed: 14393.693 to 14393.8246. The first run refused with no changes because the check read the package's name, which on Server 2016 is `Package_for_KB5062799`; it reads the attributes now (DECISIONS 105). The run reads FAIL at its last hop only: at 14393.8246 Windows Update offers this evaluation install no newer cumulative (only a 2021 update and a Defender definition), also after a restart and a fresh search, so the newest build (14393.9612) wasn't reached
- [ ] Windows 11 Enterprise evaluation: the same proof on an edition and release other than 26H2 Pro
- Verify: run files. Deps: W5.

### Checkpoint A
- [ ] Round 1 todo items for the matrix updated; W3's gaps reviewed with you; Phase 3 reordered if needed

## Phase 2: a real domain, in VMs

### W7: `winlab.py`: DC and member (M), the gate
- [x] Memory per VM and a private network as options; Server Core DC promoted by script, member joined, Kerberos remoting works. **Proven** (`last_run_winlab.json`, 2026-11-05, Server 2025 Core): NIMDC1 promoted as `nimstead-sbx.test`, NIMM1 and NIMM2 joined with a working secure channel, NIMM1 runs a command on NIMM2 as the domain's Administrator over Kerberos (klist holds the HOST/ ticket WinRM's HTTP name maps to). The real run found three harness bugs, fixed: the join's DNS check gave `Resolve-DnsName` two names, a new DC's slow boot outlasted a 30-minute wait, and the Kerberos check looked only for an HTTP/ ticket
- [x] Peak host memory recorded with two and with three VMs running: 22,513 MB and 22,777 MB used of 31,862 MB at peak, never under 9,085 MB free (2,560 MB per VM)
- [x] If it can't hold: stop Phase 2, say so in STATUS. No half-proof. **It couldn't on 16 GB; it does on 32 GB (above)**. First run (`last_run_winlab.json`, 2026-11-04): three VMs at 2,560 MB plus the host's 2 GB need 9,728 MB free; this host has about 4,300 MB of its 16 GB free with no VM running. Phase 2 (W7-W11) stops here and needs a host with about 12 GB free
- Verify: `last_run_winlab.json`. Files: `sandbox/winvm.py`, `sandbox/winlab.py` (new). Deps: W5.

### W8: Two DCs: discovery and one-at-a-time patching (M)
- [x] AD discovery lists the real computers, leaves out disabled and stale ones, stores no credential. **Proven** (`last_run_windc.json`, 2026-11-05): the DC chosen as directory source read 4 computers (the disabled one left out by its own query); Assets lists only NIMM1, the member with no agent; the never-logged-on one is left out by the 30-day rule; the agent's task runs as SYSTEM with no domain password in its config. (`lastLogonTimestamp` can't be planted: the SAM owns it)
- [x] Both DCs get a job: never at once, both healthy afterwards. **Proven** (same run): NIMDC1 patched and verified first, NIMM2 dispatched only after (313 samples, never both in flight), both builds updated with NTDS, DNS, Netlogon and KDC running, and replication worked after patching. The run reads FAIL on one check only: `repadmin /showrepl` still counted failures from attempts made while the other DC was restarting; the harness now syncs before it reads. NIMM2's guest control hung at its post-update restart for 2 hours (disk idle) and was restarted cleanly by hand; its agent resumed and verified. The first run found a real bug: a DC's job stopped holding the group after 2 hours, so the second DC was handed its update while the first was still installing (fixed, 42334ab)
- Verify: `last_run_windc.json`. Closes round 1 T42 (DC) and T43 items. Deps: W7.

### W9: Two-node cluster (M)
- [x] File-share witness cluster; node drained, patched, resumed; the role stays online, checked from outside throughout. **Proven** (`last_run_wincluster.json`, 2026-11-06, agent 0.6.2): NIMCLUS with a file-share witness on the DC; each node drained, patched to 26100.33438 and resumed, never both at once; 617 probes from the DC, served by both nodes in turn, longest gap 14 s; both nodes up and the role online at the end. The runs found two agent bugs, fixed: ClusSvc read once 15 s before it was up after a restart (0.6.1 waits up to 5 minutes for a service that starts by itself), and the shutdown for the update itself ended ClusSvc with 7031, read as a crash (0.6.2 counts only events after the last boot); each had rolled back a good update. Harness fixes: IIS as an ordinary service with a client access point (as a clustered service it stuck at Start Pending), the NAT step, cluster facts from the database, the witness retried while the DC's server starts. NIMM1's guest control hung at its post-update restart on every run and was restarted cleanly by hand (logged in the run); its agent resumed and verified
- [x] Maintenance-window dispatch shown on the same run: with the window closed both jobs stayed approved and said when they could start (Monday 00:00 UTC); opened, they went out one node at a time
- Verify: `last_run_wincluster.json`. Closes round 1 cluster items. Deps: W7.

### W10: Agentless and GPO install across real hosts (M)
- [x] `scan-remote` from one member to another: same packages and settings as that host's agent reports. **Proven** (`last_run_winremote_lab.json`, 2026-11-05): NIMM1 scanning NIMM2 by Kerberos reads the same 323 packages and 51 settings as NIMM2's own agent. The first run missed .NET Framework and Defender: over remoting on Server Core the fallback `Get-AppxPackage` throws an error `-ErrorAction` can't silence, which lost that whole block; it now costs only the Store list
- [x] A host with remoting off or no admin right reads as such, not as clean: both exit 2 naming the host and why (a WinRM timeout, access denied), and no asset appears
- [x] `install.ps1` by GPO startup script enrols a member with no one signed in; documented in `docs/install.md`. **Proven by a GPO scheduled task instead** (`last_run_wingpo.json`, 2026-11-06): a Group Policy Preferences task (run as SYSTEM, at startup, 2-minute delay, action Update) enrolled NIMM2 3.7 minutes after boot with nobody signed in; the agent's task runs as SYSTEM, the member outside the OU didn't enrol, and a second boot didn't enrol again. A startup script never could on this host: it runs before the member reaches its DC (NETLOGON fails about 20 s in, four runs). Action Replace failed once: it recreates the task at boot, after the trigger. The how-to is in `docs/install.md`, with the note that the token in SYSVOL is readable domain-wide
- Verify: `last_run_winremote_lab.json`, `last_run_wingpo.json`. Deps: W7.

### W11: SharePoint and Exchange collectors (S, time-box 1 day each)
- [x] One try each from evaluation media, binaries only if that's enough for the collector. **Done** (2026-11-06, the owner said download them; `sandbox/winmsservers.py`): SharePoint Server Subscription Edition installed as binaries only (prerequisites, setup with the published trial key, no farm) on NIMM1; Exchange Server Subscription Edition as the management tools role after /PrepareAD on NIMM2, run as the domain's Administrator by a scheduled task (DECISIONS 109). Both from Microsoft's Download Center, setup signed by Microsoft. A mailbox server wasn't tried
- [x] Collected version compared with what the host itself reports. **Proven**: SharePoint 16.0.14326.20450 by the agent and in the host's Uninstall entries (`last_run_winsharepoint.json`); Exchange 15.2.2562.17 by the agent, in its Uninstall entries and in the build its v15 setup key records (`last_run_winexchange.json`). The server keys both for MSRC matching ("SharePoint Server Subscription Edition", "Exchange Server 15.2.2562"); no advisory sync ran, so no findings were checked on them
- Verify: run file or STATUS line. Deps: W7.

### Checkpoint B
- [x] Every round 1 "NOT proven: no domain" line is closed or restated with the reason: AD discovery and DC serialisation (W8), cluster drain and maintenance-window dispatch (W9), Exchange and SharePoint collection (W11) all ran on the domain lab

## Phase 3: detection breadth

### W12: Rule proposer and first 25 apps (M)
- [x] `sandbox/winapps_propose.py` ranks candidates by W1's list, NVD CVE count and winget presence, and prints draft rows; it never edits `winapps.py` (e5448e1, DECISIONS 77)
- [x] 18 accepted rows (batch 7), each with near-miss tests; `winapps_e2e.py --new7` on a real Windows 11 VM (`last_run_winapps_batch7.json`): 10 proven old to new (Acrobat Reader, ClamAV, IntelliJ IDEA, PyCharm, Joplin, Mattermost, OpenSC, Sandboxie-Plus, NetExtender, Splashtop); 5 missed because real installers register other names or publishers (Confluence, OpenSSL Light, Nessus Agent, Plex, Corretto 21), fixed with tests and checked against that VM's own agent output; Ollama and Nessus identified but winget installed one version; TeamCity registers no release, so it stays inventory; Octopus Deploy and PaperCut didn't install (30-minute timeouts). Next batches: server installers in their own run
- Verify: `last_run_winapps_batch7.json`. Deps: W1.

### W13: Batches to 200 apps (S each, repeated)
- [ ] Each batch ≤ 25, own run file and commit; every app labelled proven, or matched from a real name only, in UI and STATUS
- [ ] Stop early if the next batches have under 20 NVD CVEs each: say so rather than pad the count
- Deps: W12.

### W14: Full noise review (M)
- [x] `winnoise.py` split across VMs so every curated app is covered (32 weren't; the disk ran out). **Done** (`--part=k/n`, 2026-11-04): 74 of 78 apps installed across two fresh Windows 11 VMs (FileZilla, MySQL, Vivaldi and TeamCity wouldn't install at an old version). Part 1 (`last_run_winnoise_part1of2.json`): 324 findings at old versions and 32 after updating, none unexplained. Part 2 (`last_run_winnoise_part2of2.json`, rerun 2026-11-05 on a fresh VM after the first stopped answering mid-upgrade): 29 findings at old versions and 23 after updating, none unexplained
- [x] The 2 `raw_says_applies_no_finding` from the last run explained: ImageMagick CVE-2017-5506 and Opera CVE-2010-0653 each list the product at version `*` with no range in NVD, which a raw reading takes as every version. `winapps.py` skips entries with no end bound on purpose. Opera's text says "before 10.10", and ImageMagick's 2017 double free was fixed in the 7.0.4 line, both far older than what was installed, so no finding is right
- [x] 50 random findings checked by hand against vendor advisories, on Windows 11, a Server and Windows 10
  - [x] Windows 11, 25 of the 50 (`last_run_winnoise_handcheck_win11.json`, 2026-11-04): a seeded sample of the 1,164 findings in `last_run_winproducts_findings.json`, stratified by ecosystem (19 Windows, 3 Microsoft, 2 WinConfig, 1 Lifecycle). All 25 confirmed against Microsoft's own sources (MSRC's data, KB pages, Edge release notes, .NET's release index, the setting's documentation). MSRC now says EnableCertPaddingCheck is a DWORD where the agent writes a string; its latest revision says the type doesn't matter, so the fix stands
  - [x] A Server and Windows 10, the other 25 (2026-11-05): `wine2e.py --findings-only` saves a fresh VM's first-report findings. Server 2025 at 26100.1742 (`last_run_windows_server2025_findings.json`, 1,757 findings; `last_run_winnoise_handcheck_server2025.json`, seed 25, 13 rows): 12 confirmed against MSRC's data, 1 unverifiable, the speculative-execution setting (CVE-2017-5715), where Microsoft's guidance says it's off by default on Windows Server but lists versions up to 2022 only. Windows 10 22H2 at 19045.2006 (`last_run_windows10_findings.json`, 2,728 findings, 1,220 of them the Edge 92 shipped on the media; `last_run_winnoise_handcheck_win10.json`, seed 10, 12 rows): all 12 confirmed; the Windows fixes are ESU-only updates, which the machine is still affected by. Across the 50: 49 confirmed, 1 unverifiable, none wrong. Priority isn't judged here: high-CVSS Windows CVEs with low EPSS read "planned" or "low" by design (`risk.py`, hand-tuned weights)
- [x] Drop "demo fleet" from the round 1 item: it's Linux, so the reason goes in DECISIONS (104)
- Verify: `last_run_winnoise_full.json`. Deps: W13 (rerun at the end), W4, W5.

### W15: Vulnerable drivers by exact hash (M)
- [x] LOLDrivers' licence and format checked; a feed syncs its hashes and fails loudly on a changed schema (f25bee4, DECISIONS 71)
- [x] Agent reports the SHA-256 of loaded drivers within a size cap; only exact matches open findings (f25bee4; real VM `last_run_windrivers.json`)
- [x] Real VM: a known vulnerable driver file present is flagged, an unrelated driver isn't. File hashed, not loaded (`last_run_windrivers.json`, Windows 11: 439 drivers hashed, only RTCore64.sys flagged, never loaded)
- Verify: `last_run_windrivers.json`. Files: agent, `feeds.py`, `scan.py`. Deps: none.

### W16: Certificates and listening services (M)
- [x] Machine store: expired, weak key and weak signature findings; roots not in Microsoft's list reported at low priority (real Windows 11: an expired machine certificate opened a finding naming it, none before; weak key and signature unit-tested; roots dropped, DECISIONS 72)
- [x] Listening non-loopback ports, with process and firewall state, raise priority of a matching product through `risk.py`, with the reason shown (`last_run_winexposure.json`, Windows 11: blocked, no reason; allowed, score 17 to 32 with the process and port named; after DECISIONS 100)
- Verify: tests, `last_run_winexposure.json`. Deps: none.

### W17: Second exploit source; every install reported (S each)
- [x] Public-exploit source beside Metasploit (check Exploit-DB's data and terms first), adds a reason in `risk.py` (ded463d, DECISIONS 73: the repository's terms read; the website's terms page refused the download)
- [x] Two installs of one app both judged; today only the oldest is (ded463d)
- Deps: none.

### Checkpoint C
- [ ] W1's coverage re-measured on the VM with 50 apps; change reported; STATUS's stale apps line rewritten

## Phase 4: benchmarks

### W18: Rule table and terms check (M)
- [x] DISA and Microsoft terms read and quoted in DECISIONS, amending 64; if they stop redistribution, ship IDs only (04e5aad, DECISIONS 75: redistribution isn't established, so IDs, severity and setting facts only)
- [x] One baseline (Server 2025 STIG): registry-based automated rules as data, evaluated server-side on agent facts; anything else reads "not assessed" (04e5aad: 85 of 291 rules automated, 156 after W19)
- [x] Real VM: results for 20 sampled rules checked by hand against the guest. **Done** (`last_run_winbaseline.json`, 2026-11-06, fresh Server 2025 Core): 156 automated rules, 51 pass, 79 fail, 26 not applicable, none not assessed. Of 20 sampled (user rights by SID, audit policy by subcategory GUID, registry values), the agent's reading equals the guest's own (secedit, auditpol, Get-ItemProperty) on all 20, and each verdict follows the rule as written. One to read again: WN25-UR-000130 fails on an `S-1-5-99-…` service identity stock Server 2025 grants SeImpersonatePrivilege, which the STIG may already allow for (not checked)
- Verify: `last_run_winbaseline.json`. Files: `winconfig.py`, new data file, agent's closed list. Deps: none.

### W19: Audit policy and user rights (M)
- [x] `auditpol` read by subcategory GUID and `secedit` rights by SID, so language doesn't matter (1df4712, DECISIONS 76)
- [x] Automated rule count rises; German VM agrees (with W2). Count: 85 to 156 of 291 (1df4712). **German install agrees** (`last_run_winbaseline_judged_as.json`, 2026-11-06): on a German Windows 10 LTSC 2021, read against the Windows 11 table with `--judge-as` (no German Server 2025 or Windows 11 image here), all 144 automated rules got a value (none not assessed), and of 20 sampled the agent's reading equals the guest's own on all 20, where auditpol answers "Erfolg", "Erfolg und Fehler" and "Keine Überwachung" and secedit names "Gast": the agent reads audit policy by GUID and rights by SID. Pass/fail there says nothing about Windows 10, which has no table
- Deps: W18, W2.

### W20: Benchmark view and export (M)
- [x] Per host and fleet: pass, fail, not assessed, with the baseline's version; wording claims no conformance (42ea0ab)
- [x] CSV export; second baseline (Windows 11) added as data only (42ea0ab)
- Verify: e2e + axe. Deps: W18.

## Phase 5: remediation and fleet view

### W21: Fix first includes all fix paths (S)
- [x] Settings, Office and winget fixes appear on Home with the same approval rules (STATUS review note) (8d86f23)
- Deps: none.

### W22: Per-KB fleet view (M)
- [x] "October 2026 cumulative: 41 of 50 hosts", drill to the hosts and why each isn't fixed, one action to plan the rest through canary rings (3c0aad8, DECISIONS 70)
- Verify: tests, e2e, perf at 1,000 hosts with `perf.py`. Deps: none.

### W23: winget on Server (M, spike first)
- [x] Can Microsoft-signed winget be installed on Server 2022/2025 by a hash-pinned, signature-checked path? On Server 2025 Core, no: hashes and Microsoft signatures check out but Core can't provision MSIX packages. On Desktop Experience it's already there (DECISIONS 103). Server 2022 not run
- [x] One app old-to-new as SYSTEM on Server, verified by inventory, person-approved as on clients: 7-Zip 26.04 to 26.05 on Server 2025 Desktop Experience (`last_run_winfixes_server2.json`)
- Verify: `last_run_winfixes_server2.json`. Deps: W5.

## Phase 6: agent quality

### W24: `doctor` and a local log (M)
- [x] `doctor` checks server reach, proxy, clock, tasks, folder ACL, Windows Update service, disk and runtime, and prints a fix for each failure (real Windows 11: all ok, then FAIL with a fix for a removed task, disabled wuauserv and a skewed clock)
- [x] Rotating log under the locked folder with no secrets (test asserts the key never appears); onboarding's troubleshooting points to it (b803374, DECISIONS 69; ran on a real VM in 5ef9183)
- Verify: unit tests plus one run on a VM with the task removed and the service stopped. Deps: none.

### W25: Footprint (S)
- [x] One scan: CPU time, peak memory, disk, duration, bytes sent (`last_run_winfootprint.json`, Windows 11: 30 s, 25 s CPU, 280 MB, 76 KB sent). Not on a VM with 50 apps: this one has few
- [x] Limits chosen from that run (about 4x) and checked by the harness; published in `docs/install.md`
- Verify: `last_run_winfootprint.json`. Deps: none.

### W26: Failure runs (M)
- [x] Hard power-off during rollback (`last_run_winfailures.json`, Windows 11: resumed, original build restored, `rolled_back`) and during install (Windows 10 LTSC, a real licence shutdown mid-install: aborted with no changes, DECISIONS 78). The Windows 11 install cut missed its window (the harness waited on IsBusy, which never read true); rerun waiting on the agent's own `installing` flag on a fresh Windows 11 VM: the cut landed mid-install and the job reported no changes made, build unchanged (`last_run_winfailures_install_cut.json`)
- [x] Disk full: refuses before changing anything. Server down: next run catches up. Clock skew: a clear error (`last_run_winfailures.json`, Windows 11)
- Verify: `last_run_winfailures.json`. Deps: W24 helps. Bugs found get a test.

### Checkpoint D / W27
- [x] Security review of the round's routes, engine and agent changes (DECISIONS 101): nothing against 7, 27 or 31; the attack-paths cost fixed with a test; settings exports moved out of ProgramData
- [x] From that review: only an admin-chosen directory source may replace the AD list (DECISIONS 102)
- [x] From that review: `GET /api/assets` sends only the facts the list shows; the per-KB query is chunked; the attack-paths panel says edges rest on each host's own report
- [x] Review not yet covering remediate.py, feeds.py, lifecycle.py, msproducts.py, office.py, winapps.py, external.py, updates.py, and the agent's Linux, jar and app scanners. **Reviewed 2026-11-04**: ten findings, no way around the approval rules. Fixed with tests: held Debian packages (`hi`) left out of the inventory; a FIFO or link named like a jar, METADATA or package.json opened by the root agent (a FIFO blocks it for good); a two-part .NET SDK version failing the host's report; a servicing step planned when MSRC's month wasn't read (refused or failed fetch); `$` in the server's name checks letting a final newline by; one feed's schema change stopping the hourly update for every org; the per-KB view counting a stepped job as reaching the final cumulative. Left, each low: feed size limits checked after download rather than while streaming (TLS-pinned hosts); Thunderbird branch CVEs fixed at a major's first release matching nothing while the branch is current; no start timeout on the agent's systemd unit (the FIFO, the known way to hang it, is fixed)
- [x] Office Click-to-Run on a version line the feed no longer lists, or with no build since a CVE, gets no row for that CVE, so a host years behind on Current reads nearly clean (review 2026-11-04, medium). **Fixed** (DECISIONS 106): a superseded line takes its fix from a newer line of its channel, and a line older than any listed is end of support
- [ ] API on SQLite and PostgreSQL, web unit and e2e, ruff; STATUS, CHANGELOG, README and `docs/install.md` updated. **Partly** (2026-11-06, after W11): API 1,589 passed on SQLite, ruff clean; STATUS, CHANGELOG and docs/install.md carry the round. Not rerun since 0.7.1's CI: PostgreSQL and web (no API or web code changed since); README not reviewed
- [x] Plan's seven "great" conditions each marked met or not, with the run file (2026-11-06):
  1. Every likely Windows version fixed and rolled back on a real install: **not met**. Windows 11 and Server 2025 yes; Server 2016 stepped forward (`last_run_windows_server2016_ssu.json`); Windows 10 LTSC rolled back but not applied by the task (W4, evaluation licence shutdown); Server 2022 overran the install limit and 2019 never boots on this host (W5); Windows 11 Enterprise not tried (W6)
  2. Fleet features on a real domain: **met** (`last_run_windc.json`, `last_run_wincluster.json`, `last_run_winremote_lab.json`, `last_run_wingpo.json`)
  3. A host's page says what share was assessed: **met in code and tests** (W1), not yet shown on a VM with 50 apps
  4. Side-by-side with another scanner, every disagreement explained: **not met**, W3 not started
  5. At least 200 curated apps, noise review over every one: **not met**: 100 curated, noise review over 74 installed (W13, W14)
  6. Benchmark-referenced audit per host: **met** (`last_run_winbaseline.json`, W20's view and export)
  7. Survives power loss, full disk, dead server, explains its failures: **met** (`last_run_winfailures.json`, `last_run_winfailures_install_cut.json`, W24's doctor)

## Open after the sweep (2026-11-06)
Every unchecked item above, by why it's open:
- **Blocked by this host** (VirtualBox on Hyper-V's slower engine): W5 Server 2022 stepping (overran the 2-hour limit) and Server 2019 (never boots). Needs Hyper-V off, which is the owner's call (DECISIONS 107), or another machine
- **Blocked by evaluation media**: W2's German rollback and W4's apply by the task (the licence service powers the VM off an hour after boot); W4's oracle and .NET proofs wait on the same. Needs licensed or IoT LTSC media. W6 Windows 11 Enterprise: its evaluation ISO sits behind Microsoft's registration form, which asks for the owner's details
- **Waiting on the owner**: Checkpoint A (W3's gaps reviewed with you); the items below
- **W3** stopped at its short look (DECISIONS 110): the reference scanner's free feed has no Windows patch tests after October 2025, so which scanner to compare with is the owner's call
- **Not started, real work, unblocked**: W13 app batches to 200 (each batch a VM run of several hours); W1's 50-app VM screenshot and axe check; Checkpoint C (needs W13); the engine track's last three (routing and AD group edges, findings through the engine, its benchmark run, which needs W3)

## Needs the owner
- [ ] Review this plan; answer its two open questions
- [ ] Push `windows-round-1`, run CI (the `windows-runtime` job has never run), merge, tag, approve the release
- [ ] Human pentest; code-signing certificate decision; commercial-scanner decision
