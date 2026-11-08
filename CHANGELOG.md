# Changelog

All notable changes to Nimstead Assure. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.7.4] - 2026-11-08 (preview)

**Agent 0.6.5.** One database migration (two columns on assets), applied on start; run `deploy/update.sh`. Fixes from a full code audit. Every fix has a test that fails without it; API suites pass on SQLite and PostgreSQL, and the platform-update lab passes including its rollback.

### Fixed
- **Two ledger writes at once could fail or fork the chain**: ledger appends now lock the organisation first. One failing host no longer stops the hourly rescan of the rest.
- **Accept risk crashed the findings drawer** (React hook order).
- **A fix was judged "not fixed" from an inventory that kept the old package list**: jobs are verified only on an inventory that replaced it.
- **A host read as clean when a Windows source failed or came back empty**: findings from that source stay open until it reads again.
- **dpkg packages with pending triggers were dropped** (agent 0.6.5): the `iW` and `it` states are reported.
- **One fix record covering several CVEs was ranked by its first CVE only**: KEV, EPSS, CVSS and exploit data now count every CVE, and the summary names the others.
- **Two domain controllers could be planned or dispatched together** under concurrent requests: plan, approve and dispatch lock the organisation.
- **Accepting a finding mid-verification counted the fix as a success**: accepted findings count as not fixed.
- **A failed update's rollback lost job reports written after the backup**: `deploy/update.sh` saves a second dump before restoring.
- **Promotion to beta or stable didn't reach servers that had cached the preview's release files**: they're fetched again while below the server's channel. The release check no longer looks at only the last five tags.
- **One release's failure halted every later Windows release**: a canary failure halts only its own release.
- **A timed-out Windows install could overlap the next**: a timed-out job holds the host for the timeout margin. A held job still answers the kill switch and the canary and suggest-mode gates first.
- **Silent-host alerts fired for hosts that never reported.**
- **Old notification records were kept forever**: they're deleted after 90 days.
- **The agent crashed on a malformed jobs answer** (agent 0.6.5), and a Windows job's target build is checked as a number before anything runs.
- **Settings' server section loaded forever on an error**, the findings search box dropped a trailing space, the finding drawer saw only the newest 500 jobs, and the ledger note counted the wrong set.
- **Versions the matcher couldn't compare were skipped silently**: they're logged.

### Changed
- **"Plan the rest" plans every host in one request** (`POST /api/remediation/jobs/batch`).
- **Faster at 1000 hosts**: ingest 1.43 to 0.86 s, the Assets coverage count 1.7 to 0.3 s, and the next evidence pack at 297k entries 9.7 to 7.8 s. The ledger is checked from its last verified entry, with a full check hourly and on every pack, and an unchanged inventory is recorded once a day per host (DECISIONS 121). The engine evaluates each inventory once and builds and hashes the shared "not installed" verdicts once per process; verdicts and digests are unchanged (DECISIONS 122).

### Removed
- Dead code: the stub `nimstead` console script, an unused match field, a network safety level and option nobody used, a duplicate Windows version comparator, and unused web exports.

## [0.7.3] - 2026-11-08 (preview)

**Agent 0.6.4.** No database migration; run `deploy/update.sh`. Proven on real installs since 0.7.2: Server 2019 and 2022 (fixes, .NET Framework, hardening), Windows 11 Enterprise and Windows 10 22H2 (fixes through the scheduled task), German Windows 11 Pro, and the unverified case of an attack path across hosts. Still not proven: a fix on Windows 10 (it needs an ESU licence).

### Fixed
- **A Windows Server couldn't take a .NET Framework fix** (agent 0.6.4, DECISIONS 118): Windows Update offers servers only .NET's combined cumulative, a KB MSRC never names, so every job stopped with no changes made. The server now plans the same fix with that KB, the agent judges it by the per-version package it downloads as, and it recognises Server's `Package_for_DotNetRollup~` name, without which a failed install couldn't be rolled back. Proven on real Server 2019 and 2022.
- **A .NET update offered alone was planned as a servicing stack step** (DECISIONS 117): only a person could approve it and the agent refused it, so nothing broke, but the host couldn't move on.
- **VirtualBox 7.x was never checked**: its installer registers the publisher as "Oracle and/or its affiliates", which the curated row didn't accept (DECISIONS 113).
- **Microsoft apps more than a year behind missed older CVEs**: the hourly update now also reads the five years of MSRC before the usual 12 months, for Microsoft apps only (VS Code, PowerShell, ...), each month once (DECISIONS 114).

### Proven
- **Server 2019, Server 2022, Windows 11 Enterprise and Windows 10 22H2 on real installs** (2026-11-07/08): fixes through the scheduled task on each, rollback on 2019 and Windows 11 Enterprise, .NET Framework and hardening on both servers. Servers under QEMU with Windows' own hypervisor where VirtualBox couldn't run them here (`sandbox/winqemu.py`, DECISIONS 116).
- **The unverified case of an attack path across hosts, on real hosts** (`last_run_winpaths_lab.json`): with nobody from the target's Administrators group signed in on the source, the sign-in edge reads unverified. 0.7.2 shipped it unit-tested only. No code change.

## [0.7.2] - 2026-11-07 (preview)

**Agent 0.6.3.** No database migration; run `deploy/update.sh`. Proven on real hosts since 0.7.1: the SharePoint and Exchange collectors (`last_run_winsharepoint.json`, `last_run_winexchange.json`), coverage on a Windows 11 VM with 63 apps (`last_run_wincoverage.json`), five more curated apps from real installer names (`last_run_winapps_batch8.json`), and an attack path across hosts read as confirmed (`last_run_winpaths_lab.json`). Not yet proven on real hosts: the unverified case of that edge (unit-tested), and the comparison with a commercial scanner (W3).

### Added
- **Attack paths across hosts tell a real route from a guess** (agent 0.6.3, DECISIONS 112): a sign-in edge inside a domain is confirmed when an account signed in on the first host is an administrator on the second and the first was seen connected to it, and unverified when no signed-in account is. The agent reports its own addresses, its open connections to private addresses, its Administrators group and the signed-in domain accounts' SIDs; nothing is probed.

### Proven
- **SharePoint and Exchange collectors on real installs** (W11): SharePoint Server Subscription Edition and Exchange Server Subscription Edition from Microsoft's trial media, in the domain lab; the agent's version equals the host's own for both (`last_run_winsharepoint.json`, `last_run_winexchange.json`). No code change was needed.

## [0.7.1] - 2026-11-06 (preview)

**Agent 0.6.2.** No database migration; run `deploy/update.sh`. Proven on real hosts since 0.7.0: a two-node failover cluster patched node by node with its role online throughout (`last_run_wincluster.json`), the agent installed at boot by a Group Policy scheduled task (`last_run_wingpo.json`, steps in docs/install.md), and the benchmark settings read in full on Server 2025 and on a German install (`last_run_winbaseline.json`, `last_run_winbaseline_judged_as.json`). Still not proven: SharePoint and Exchange collectors (no install media), Server 2019 and Server 2022 stepping, Windows 10 apply, Windows 11 Enterprise.

### Fixed
- **A Windows update no longer rolls back because a watched service was stopped by the update's own restart** (agent 0.6.2): the crash check counts only events after the last boot. On a slow cluster node, the shutdown ended ClusSvc with event 7031 each time.
- **A Windows fix no longer rolls back because a service was still starting** (agent 0.6.1). The agent's health check gives a service that starts by itself up to 5 minutes to reach Running after a restart; on a real failover cluster node, ClusSvc was 15 seconds from running when it was read, so a good update was rolled back and the rollback then read as failed.

## [0.7.0] - 2026-11-06 (preview)

Windows round 2 (tasks/plan-windows-round-2.md; DECISIONS 102-108): proofs on real Windows servers and a real Active Directory
domain, and the bugs they found. **Agent 0.6.0.** No database migration.

**Upgrade from 0.6.x:** run `deploy/update.sh`. Things to know:
- **AD discovery needs a directory source.** An admin chooses the one host whose directory the server takes (Assets, that host's
  settings); until then its agent's directory upload is refused with a message saying so.
- **Old Windows Server may get a forward-only step.** When Windows Update offers only a servicing stack update, it's planned as a
  forward-only job that only a person can approve (`{"forward_only": true}`).
- **More end-of-support findings for Microsoft 365 Apps** on version lines Microsoft no longer updates.

**Proven on real hosts in this release:** a domain controller and two members built by script, with Kerberos remoting member to
member (`last_run_winlab.json`); AD discovery and two DCs patched one at a time, both healthy after (`last_run_windc.json`);
agentless scanning across hosts matching the host's own agent (`last_run_winremote_lab.json`); a servicing stack update then a
cumulative on Server 2016 (`last_run_windows_server2016_ssu.json`); 50 findings hand-checked against Microsoft's sources on
Windows 11, Server 2025 and Windows 10 (49 confirmed, 1 unverifiable, none wrong).

**Not proven yet** (STATUS lists each): a failover cluster drained and patched (W9: the cluster forms with its witness, the
role didn't stay up on this host), the agent installed by a GPO startup script at boot (W10: the member can't reach its DC that
early here), SharePoint and Exchange collectors (W11), the benchmark rule hand-checks on a VM (W18, W19), Server 2019 and
Server 2022 stepping (W5), Windows 10 apply (needs non-evaluation media), Windows 11 Enterprise (no ISO), commercial-scanner
benchmarks (owner registration).

### Added
- **Servicing stack updates as a forward-only step** (DECISIONS 105): when Windows Update offers an old Windows Server only a servicing stack update, the server plans it as a forward-only job a person approves (`{"forward_only": true}`), and the agent installs it only if the package's own manifest says it's a servicing stack update. The cumulative is planned after it.

### Fixed
- **Two domain controllers (or cluster nodes) could be patched at once** when the first one's Windows update ran past two hours without reporting: the group now holds for as long as the server waits on that install (the restart deadline plus 4 hours). Found on a real two-DC lab.
- Debian and Ubuntu packages held with `apt-mark hold` are reported again (they were left out of the inventory).
- The agent opens only plain files when scanning jars, Python and npm packages: a named pipe a user planted could block it.
- A .NET SDK reported with a two-part version no longer fails that host's report.
- A servicing stack step is planned only when Microsoft's data for that month was read.
- One feed failing or changing format no longer stops the hourly update and re-match for every organisation.
- The per-update fleet view counts a stepped job by the build it installs.
- Microsoft 365 Apps on a version line Microsoft no longer updates is judged: a superseded line's CVEs take their fix from a newer line of the channel, and a line older than any the channel lists opens an end-of-support finding (DECISIONS 106).

## [0.6.0] - 2026-11-04 (preview)

Windows rounds 1 and 2 (tasks/plan.md, tasks/plan-windows-round-2.md; DECISIONS 51–101): Windows detection across the OS, Microsoft's own products and common apps, fixes
with rollback, an agent that needs no Python, and a detection engine that says how sure it is. **Agent 0.5.0.**

**Upgrade from 0.5.x:** run `deploy/update.sh`. Five database migrations (`9a61c0e4d2b7` host facts, `c3e8f1a92d45`
maintenance windows and Active Directory computers, `a7d3e5b1c920` the engine's collection document and scan records, `d4f1b8a3c6e2` a package's source version, `e5c2a9d7f413` the directory source), applied on start. Things to know:
- **Windows installs no longer need Python.** `install.ps1` brings Python's official embeddable runtime (3.15.2,
  pinned by hash in the signed release, every program file signed by the Python Software Foundation). Machines enrolled
  with a system Python move to the bundled runtime on their own at their next agent update. Your server fetches the
  runtime zips with the release files; offline installs copy `python-embed-*.zip` into `NIMSTEAD_RELEASE_DIR` too.
- **More findings on Windows.** Expect new open findings after the first reports: end of support (OS, .NET, SQL
  Server, Exchange, SharePoint, Office, curated apps), Microsoft products (Edge, .NET runtimes, SQL Server, Exchange,
  SharePoint, Defender, Store apps, PowerShell, Visual Studio, Microsoft 365 Apps), 22 more third-party apps, and
  configuration findings (ecosystem `WinConfig`). Edge and VS Code findings move from `WinApp` (NVD) to `Microsoft`
  (MSRC): the old ones close and new ones open once.
- **Approved fixes wait for a maintenance window** once you set one (Settings → Remediation); none set = any time, as
  before. Workstation restarts can now be put off by a signed-in user until a deadline (default 24 hours).
- **API additions:** `facts` on inventories and host assets; `maintenance_window` / `reboot_deadline_hours` on
  `/api/settings` and `maintenance_window` on assets; `waits_for_window` and `forward_only` on jobs; approving a
  forward-only fix needs `{"forward_only": true}`; `POST /api/agent/directory`; `GET /api/directory/unmanaged`
  (`?format=csv`); `forward_only_changes` in evidence packs.

### Added
- **Hotpatch-aware Windows matching:** hotpatch and cumulative fixes are separate tracks; a job carries both KBs and the
  agent installs whichever Windows Update offers (before, a non-hotpatch Server 2025 host could be planned the hotpatch KB).
- **End-of-support findings** from a dated Microsoft Lifecycle table (Windows 10/11 by edition and ESU, Server
  2012–2025 and 23H2, .NET, SQL Server, Exchange, SharePoint, Office) and endoflife.date for curated apps.
- **Microsoft products from MSRC's own fixed builds** by an allowlist, with SQL Server GDR/CU and each Exchange CU as
  separate tracks, and Microsoft 365 Apps / Office LTSC by channel and version line (Microsoft's release feed).
- **CVE List v5 (vendor CNAs + CISA Vulnrichment)** as a second source for curated apps where NVD hasn't configured a
  CVE yet; **22 more curated apps** (OpenJDK builds, browsers, VPN and remote-access clients, file transfer,
  virtualisation, Docker Desktop, Tomcat and more).
- Per-user apps of users who aren't signed in; an opt-in **Java library scan** (`--scan-jars`) whose findings name the jar.
- **Configuration findings:** Secure Boot 2023 certificates (the 2011 CA expired 2026-10-19), BlackLotus revocation,
  CVE-2013-3900, Spectre/Meltdown on Server, SMBv1, SMB signing, LLMNR, NetBIOS, NTLMv1, WDigest, RDP NLA, TLS 1.0/1.1,
  DC LDAP signing and channel binding, AlwaysInstallElevated, Spooler on DCs, unquoted or writable service paths,
  PowerShell 2.0, LSA protection, Defender, firewall, BitLocker.
- **Threat context:** Microsoft "exploited" counts like KEV; Microsoft's exploitability index, public Metasploit modules
  and KEV ransomware use are reasons; CVEs in roles that aren't installed (DNS, DHCP, Hyper-V, MSMQ…) rank lower but stay open.
- **Fix paths:** winget for curated apps (forward-only: a person approves it as such, never the trust ladder), Microsoft
  365 Apps with rollback to the previous build, and six reversible settings.
- **Fleet operations:** maintenance windows, restart deferral with a deadline, no install on battery, one Windows job
  at a time per failover cluster (node drained and resumed) or per domain's controllers, crash events in health checks,
  and why Windows Update didn't offer a KB (WSUS, deferral, ESU). Proxy support (`--proxy` / WinHTTP), jittered
  below-normal scheduled tasks, and a list of Active Directory computers with no agent (opt-in `--ad-discovery` on one machine, which an admin then chooses as the directory source on **Assets**; any other host's list is refused).
- Windows Update accuracy oracle in the VM harnesses (`sandbox/winoracle.py`).

### Fixed
- Findings hid every Windows setting, end-of-support and exposure finding by default, and called them "no fix yet"; they now show, with what to do. Plan fix is offered on settings the agent can change. Links to advisory pages that can't exist are gone, and an unset registry value no longer reads `[None, None]`.
- KeePass and Notepad++ (MSI) are identified by the names their current installers register ("KeePass 2.x",
  "Notepad++ (x64)"); both were inventory only before (found on a real Windows 11 install).
- A Windows job's 15-minute check no longer judges a DISM rollback before the restart it waits for.
- The hourly re-match scores each CVSS vector once per pass.
- `resume-job` takes the run lock, so it can't advance a pending Windows job while the startup run is advancing it.
- A Windows cumulative update gets up to 2 hours to install (a reinstall on Windows 11 with a user signed in ran past 30 minutes), and a rollback also removes an update that finished installing after the agent stopped waiting for it; before, that ended in "ROLLBACK FAILED" (found on a real Windows 11 VM).
- Proven on real Windows 11 VMs: winget, Office and Windows-setting fixes with rollback, proxy-only operation, restart deferral (one early restart in an earlier run remains unexplained), crash events in health checks, offline user hives, the jar scan and service ACL checks.
- A Windows job whose restart a signed-in user put off is no longer marked failed after 2 hours; the server waits until 4 hours after the restart deadline (found on a real Windows 11 VM).
- winget fixes run as SYSTEM on real Windows 11: winget exited with a missing-DLL error because its C++ runtime wasn't on the path. Office updates and rollbacks repeat a request the Click-to-Run client dropped; before, a dropped rollback ended in "ROLLBACK FAILED" (both found on a real Windows 11 VM).
- A Windows update job stops before downloading when the system drive has under 10 GB free, saying how much is free; before, a full disk ended in "downloaded failed: 4" (found on a real Windows 11 VM).
- winget fixes find winget on real Windows 11: the App Installer folder is owned by Administrators there, not TrustedInstaller (only the WindowsApps root is), so every winget job was refused as "winget unavailable". Owners are now compared by SID (found on a real Windows 11 26H2 VM).
- The runtime signature check in `install.ps1` now filters by extension: PowerShell 5.1 ignores `-Include` beside
  `-LiteralPath` (found in the real VM run).

### Since the round 1 notes above

Wider Windows detection and more fixes. **Expect new open findings after the first reports.**
- **Windows hosts far behind can be fixed:** a job installs the earlier cumulative update when that's what Windows Update offers, and the next job finishes the way.
- **Clearer refusal:** a Windows job with two possible updates now says why neither was offered, such as no Extended Security Updates licence.
- **Ended release branches:** Thunderbird, Firefox ESR, PostgreSQL, MySQL, MariaDB, MongoDB, Elasticsearch, Go, Grafana, LibreOffice, Tomcat, Ruby and Perl now report when their branch gets no more fixes.
- **Fixed:** one NVD record with no configuration nodes stopped the app feed sync; a CVE only for Apple silicon was reported on Windows.
- **Agentless scan:** `scan-remote` reads hosts with no agent over PowerShell remoting, as you, with no stored credential. It finds; fixes still need the agent.
- **.NET Framework findings:** read from mscorlib, on the host's own line and OS, with a fix through Windows Update that can be rolled back.
- **.NET SDKs:** the newest of each feature band, against MSRC's SDK fixes.
- **Hardening audit:** 24 more settings (UAC, stored sign-in passwords, password and lockout policy, anonymous access, LM hashes, WinRM, SNMP and more), free; 7 more settings can be fixed by a reversible job. This is not a CIS or STIG conformance check.
- **43 more Windows apps,** including the JetBrains IDEs, Vim, Ruby, Perl, OpenOffice, MySQL, PostgreSQL, MariaDB, MongoDB, Elasticsearch, ImageMagick, Go, Grafana, IntelliJ IDEA, GIMP and calibre; 16 can be updated by a job.
- **Fixed:** the certificate padding fix sets both registry views; it reported applied while its finding stayed open. MSRC sync retries a dropped connection. The restart notice says Windows may restart sooner than the agent would.

Windows round 2 and the detection engine (tasks/plan-windows-round-2.md; DECISIONS 68–101). **Agent 0.5.0.**
- **Scan report per host** (`GET /api/assets/{id}/scan-report`, `python -m nimstead.engine`): every check gets a verdict (vulnerable, not vulnerable, not applicable, couldn't be determined, not run) and how sure it is, and the report says what stopped any check and what to do about it. It covers Windows, Debian and RHEL-family packages, network services, Python, npm and Java installs, and SBOMs. Findings still open and close as before.
- **Attack paths:** each host's report says how its weaknesses chain (getting in, becoming SYSTEM, taking sign-ins, reaching other hosts) and where to break the chain; `GET /api/attack-paths` and the Assets page link one host to the next. No step is better than its evidence: routing between hosts isn't seen, so nothing across hosts reads better than reasonable.
- **Vulnerable drivers** by exact file hash from LOLDrivers, never by name.
- **Machine certificates** (expired, weak key, weak signature), and a listener the firewall lets through raises its product's priority, with the process and port named.
- **Benchmark references:** DISA's Windows Server 2025 and Windows 11 registry rules as a reference per host and fleet, with CSV export. Not a conformance check: manual rules always read "not assessed".
- **Exploit-DB** as a second public-exploit source; a second install of the same app is named on its finding.
- **Windows updates across the fleet:** a count per KB, why each host hasn't got it, and one action to plan the rest. Fix first lists setting fixes beside upgrades.
- **`doctor`** on the agent checks server reach, proxy, clock, tasks, folder permissions, Windows Update, disk and runtime, and says how to fix each failure; the agent keeps a rotating local log with no secrets.
- **Any Windows language:** settings, user rights, audit policy, proxy and winget are read by ID and SID, not English names (checked on a German install).
- **Power cuts:** a job interrupted during install or rollback finishes or says honestly that nothing changed; it never stays pending.
- **Fixed:** Store app firewall rules made every listening port read as allowed. A job on Server 2016–2022 or LTSC no longer blames a missing ESU licence those don't need. One Windows Update search per job instead of one per candidate (the second hung 30 minutes on Server 2022). A host that never installed an update read "last installed 426 years ago".

## [0.5.0] - 2026-10-29

A safer, clearer interface, from two rounds of UI and accessibility review (tasks/plan-0.5-ux.md, tasks/plan-0.6-ux.md; DECISIONS 41–50). Agent unchanged (0.3.0).

**Upgrade from 0.4.x:** run `deploy/update.sh` on the Docker host. No database migration. Things to know:
- **Switching the trust ladder now takes Save**, and switching to Auto asks you to confirm.
- **Evidence packs can report `no_activity`** for timeliness controls with nothing fixed and nothing overdue in the period (Cyber Essentials update management, NIST SI-2, CIS 7.3/7.4, SOC 2 CC8.1), where 0.4.0 said `met`. The pack format and verifier are unchanged; if you parse control statuses, expect a third value. The deadline text in packs now says "routine" for the tier the UI used to call "Planned".
- **API additions:** `POST /api/remediation/jobs/{id}/cancel`; `GET /api/findings?overdue=true` (and on the CSV export) with a `due` date on each finding; `asset_ids`, `job`, `busy_asset_ids` and `last_attempt` on `/api/summary` actions. Cancelled fixes no longer appear in `/api/summary`'s `attention` list.
- Adding a machine now asks whether it's a test or production machine; there's no default.

### Changed
- **The trust ladder no longer switches itself to Auto.** Before, choosing a mode (one click, or one arrow key) saved it at once. Now choosing only selects; Save applies it, and Auto asks first, naming how many machines it covers and the canary-first order.
- **Destructive actions ask first, the same way everywhere:** revoking an API token, removing someone, changing someone's role and signing out everywhere now use the same confirmation as deleting an asset. You can't demote or remove yourself from the People list.
- **Fixes can be cancelled before a machine picks them up** (planned or approved), and cancelling one lets you plan it again. `POST /api/remediation/jobs/{id}/cancel`, admin only, recorded in the ledger.
- **Home links to a fix already in flight** ("View fix") instead of offering "Plan fix" again. The finding drawer shows "Fix in progress" the same way. A job's summary and host link to that machine's findings. `/api/summary` actions carry `asset_ids` and `job`.
- **Evidence says "No activity in period"** for timeliness controls (Cyber Essentials update management, NIST SI-2, CIS 7.3/7.4, SOC 2 CC8.1) when nothing was fixed or changed in the period and nothing is overdue, instead of "Met". Overdue findings still fail. **Signed packs can carry the new status `no_activity`**; the pack format and verifier are unchanged. The period's dates, an "as of" time and each control's counts are shown, and the period is kept in the URL (`?period=30`).
- **Onboarding asks "test or production machines?"** with nothing preselected (it can't be changed after enrolment). It shows troubleshooting after two minutes without a report, and waits for you instead of redirecting on its own.
- **Two-step sign-in shows a QR code** to scan, drawn in the page; the typed key stays as a fallback.
- Settings is grouped into Remediation, Access, Alerts, Your account and This server, with a section bar. Saves say "Saved"; asset changes say the findings were re-ranked.
- Theme follows your system until you pick light or dark, and can go back to following it.
- On phones, Evidence is in the tab bar (Assets moved under More, with Sign out), and buttons, links and form controls are at least 44px tall.
- **Read-only members see an asset's settings as text,** not controls the API would refuse.
- **Every dialog hands focus back to what opened it,** not just the findings drawer. Focus rings are ink in both themes (crimson now only means "fix now", KEV or an error), and headings focused by the app no longer show a ring. After moving to another page, focus goes to its heading and the page title is announced.
- **"Saved" and similar messages are announced** through one live region; form errors sit under, and are tied to, the field they're about. A failed save shows next to the section that failed, not at the top of the page.
- **Overdue is a filter.** `GET /api/findings?overdue=true` (and the CSV export) returns open findings past the deadline in force when they were first detected, the same rule evidence packs use; each finding carries `due`. Findings gets an "Overdue" chip, the drawer says "Due 3 Nov" or "12 days overdue", and Evidence's "Overdue and still open" links to the list.
- **Fixes have an address** (`/remediation#job-<id>`). Home, the finding drawer and Plan fix land on the fix itself. A fix planned and approved by the same person says so.
- **Home doesn't re-plan blind.** `/api/summary` actions carry `busy_asset_ids` and `last_attempt`. When the last attempt failed it links to that job ("Last attempt aborted: review"), and when one host is busy you can still plan the others. Cancelled fixes no longer appear under "needs a look".
- **Production remediation says how to turn it on:** Settings, onboarding and the refusal note name `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1`.
- **The priority tier "Planned" is now labelled "Routine"** in the UI and in the evidence pack's deadline text (the stored value and API stay `planned`), so it can't be mistaken for a planned fix.
- Command palette finds hosts too, keeps the highlighted command while results arrive, and never offers an invalid empty list.
- Assets: the agent-update explanation is said once for the list, grouped by reason; Ring and Health units are explained in place; long host names wrap.
- Findings: package names show the part that differs first (`log4j-core`, then the group, muted), truncated cells carry their full text, rarer filters fold away on phones, the list dims while new filters load, and a capped list (5,000) says so.
- Settings: editing one section no longer loses what you typed in another; the section bar marks where you are and fits phones; trust-ladder options have visible borders and a radio mark. The SSO and alert forms keep your edits when other data refreshes, and "Send test alert" reports success or failure.
- Evidence: the ledger says how many entries it shows of how many and names what each entry is about; mean time to remediate under a day says so.
- Sign-in and onboarding: fields focus where you'd expect, onboarding polls only once there's a command to run.

### Fixed
- "Verified" next to an SSO domain was the same colour as the page in both themes.
- Admin-only buttons could not be focused, so keyboard and touch users never saw why they were off; they now stay focusable and point to a visible "Read-only" note.
- Focus returns to the finding you opened when its drawer closes.
- Keyboard focus on menus, the command palette and filters is visible (not just a faint tint); loading states are announced; the findings table names its columns on phones; reduced motion also stops transitions.
- Plan fix no longer downloads up to 5,000 findings to look up machine ids.
- The web bundle loads Settings, Evidence, sign-in and onboarding on demand (entry chunk 587 kB to 392 kB).
- Settings would crash on an API token without an expiry (none are created that way, but the column allows it).

## [0.4.0] - 2026-10-28

Security round 4 and what a first team needs: people management, two-step sign-in, API tokens and CSV export. Agent 0.3.0.

**Upgrade from 0.3.x:** run `deploy/update.sh` on the Docker host. Things to know:
- **Admins who sign in with a password are signed out by the upgrade and set up two-step sign-in at their next sign-in** (any authenticator app), including break-glass sign-in. Save the recovery codes it shows.
- Swagger UI at `/api/docs` is off unless `NIMSTEAD_API_DOCS=1` (it runs scripts from a CDN); `/api/openapi.json` is still served.
- **The app now listens on `127.0.0.1:8000` only.** Your HTTPS proxy on the same host keeps working. If something on another machine reached port 8000 directly, put it behind the proxy, or set `NIMSTEAD_BIND=0.0.0.0` in `.env`.
- Sign-up links sent before the upgrade stop working; ask for a new one.
- Agents update themselves to 0.3.0. Machines enrolled before 0.3.0 keep taking every channel; rerun the install command to tie one to your server's channel.

### Security
- **Sign-up can no longer be used to pre-set someone else's password.** Emailed sign-ups, invitations and resets let the address owner choose the password on the link's page; the request never carries one.
- **Two-step sign-in (TOTP) is required for admins** who sign in with a password, with one-time recovery codes; anyone else can turn it on in Settings. A new admin's first session comes from signing in (after sign-up you're sent to the sign-in page), wrong codes are limited per account from every address, and promoting someone signs them out so they set it up.
- Request bodies are capped at 10 MB as they arrive, so a chunked upload can't exhaust memory.
- Per-organisation limits: assets (`NIMSTEAD_MAX_ASSETS_PER_ORG`, 5,000), enrolments per token, inventories per hour, and AI calls per user and organisation.
- Security headers on every response: Content-Security-Policy, HSTS (with secure cookies), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`. `/.well-known/security.txt` is served.
- The evidence ledger now records organisation creation, every agent enrolment (with the token used), password sign-ins and every change to people and tokens.
- **Agent 0.3.0:** a fix never installs an older version (pins are compared by the package manager; dry-run downgrades are refused); rollback copies are deleted once the outcome is saved and no change starts below 1 GiB free; signed releases from a less proven channel than the machine's are refused; job fields are validated without trailing newlines; server responses are size-capped.
- **Windows installs without remediation failed at "Scheduling failed"** (since agent 0.2.0): removing the job-poll task that wasn't there left PowerShell exiting 1 with no output. Found on a real Windows 11 VM; the agent now removes it only if it exists, and says the exit code if scheduling ever fails. Rerun the install command on machines that showed the error.
- The Windows installer's trusted-folder check had lost a backslash, so `C:\Program Files Evil\` passed it (the agent's own check still stopped it). Fixed. The Linux installer fetches over HTTPS only and prints the agent's SHA-256.
- `deploy/update.sh` refuses untracked files and Compose override files, checks out the exact verified commit, runs as root only from a checkout only root can change, and checks the backup is readable before dropping the database on rollback.
- CI actions are pinned to commits with a read-only token; a CI job audits Python and npm dependencies; Dependabot covers both; the release signing step installs only hash-pinned packages.

### Added
- **People** in Settings: invite by email, make admin or member, remove (signed out at once). An organisation always keeps one admin. Sessions end after 12 hours idle; **Sign out everywhere**.
- **Change password** and **Forgot password?** (emailed link, 1 hour; you still need your authenticator code).
- **API tokens:** read-only access for scripts to findings, assets, the summary and evidence, as `Authorization: Bearer …`. Creating one needs your authenticator code; each expires within a year, and stops working when its creator is no longer an admin, signs out everywhere, or changes or resets their password.
- **Export CSV** on Findings, with the page's filters (cells a spreadsheet would run as formulas are escaped).
- **Remediation deadlines** per priority in Settings, used and shown in evidence packs. Each finding is held to the deadline in force when it was detected, so relaxing one later can't make an old miss pass.
- Evidence packs map to **SOC 2 CC7.1 and CC8.1** and **NIS2 Art. 21(2)(e)** too.
- Risk acceptance: accept one vulnerability on every host it's open on, and revoke an acceptance (both recorded).
- Each release publishes CycloneDX SBOMs of Assure's own dependencies; upload them to an application to scan Assure with Assure.
- Docs: installing an agent without trusting the server, restoring a backup, release-key rotation and the bad-release runbook (`docs/release-keys.md`).

### Changed
- `SECURITY.md`: response targets per severity, safe harbour, and which releases get fixes.

## [0.3.1] - 2026-10-28 (preview)

**Release channels.** Releases now come in three channels: **preview** (earliest, may break), **beta** (feature-complete, being proven) and **stable** (public). Your server follows one and also takes anything more stable. There's no beta or stable release yet, so **set `NIMSTEAD_UPDATE_CHANNEL=preview` in `.env` to keep getting updates**; the default is `stable`. Agents are unchanged (still 0.2.0), so machines need nothing.

**Upgrade from 0.3.0:** 0.3.0's Settings doesn't show preview releases, so run `deploy/update.sh` on the Docker host (it checks the signature, backs up the database and rolls back if needed). Then add `NIMSTEAD_UPDATE_CHANNEL=preview` to `.env` and restart with `docker compose up -d`. From 0.2.0: `git fetch --tags && git checkout v0.3.1 && docker compose up -d --build`, then rerun the install command on each machine once.

### Added
- **Release channels:** preview, beta and stable. Each release's signed manifest says its channel, and a server follows one (`NIMSTEAD_UPDATE_CHANNEL`, default `stable`), taking its channel and anything more stable. Settings shows the channel, and `deploy/update.sh` installs the newest release the channel allows. A tag is released as preview; promoting it re-signs the same commit for beta or stable with your approval. 0.3.0 is a preview release.
- Docker base images and the PostgreSQL image are pinned by digest, and Dependabot proposes updates to them and to the pinned GitHub Actions.
- `web/scripts/readme-shots.mjs` regenerates the README screenshots from the real-hosts demo.
- Each GitHub release's notes are its CHANGELOG section, not a pointer to the file.

### Changed
- "Not reporting" alerts wait one report cycle after the server itself was down, so an outage doesn't page about every machine.

## [0.3.0] - 2026-10-28 (preview)

Agents and the server now update themselves from signed releases, approved fixes start within minutes, and machines that stop reporting are flagged. **Agents older than 0.2.0 can't update themselves: rerun the install command on each machine once** (the enrolment is kept). After that, updates are automatic.

### Added
- **Agent 0.2.0 updates itself.** At each run it installs a newer release only if it's signed by the Nimstead release key built into the agent. That key is held by the release workflow, never by your server, so a compromised server can't push code to your machines. Older versions are never installed, and the new version must run its inventory on the machine before it replaces the old one. Pause updates for your organisation in **Settings → Agent updates**, or turn them off on one machine with `--no-auto-update`. The Assets page shows each agent's state (updating, failed and why, paused, off, or reinstall needed).
- **Approved fixes start within 15 minutes:** machines that allow remediation check for approved jobs every 15 minutes, and only report inventory when a job ran. The agent now writes its own timers and scheduled tasks (`schedule`), so changes like this reach existing machines without a reinstall.
- **Not reporting:** a machine silent for 14 hours is flagged on Assets and Home, and alert targets hear about it once per outage.
- **`uninstall`** removes the agent, its schedule, key and state from a machine.
- **Server updates:** **Settings → This server** shows the running version and any newer release, and alert targets hear about each new release once. `deploy/update.sh` installs a release only if it's signed and its tag points at the signed commit. It backs up the database, waits for the new version to be healthy and otherwise restores the previous version and the database. `--install-timer` runs it nightly (opt-in).
- **`/api/health`** (database reachable, schema at the release's migration head), used by the Docker healthcheck.
- Releases are signed in a protected GitHub Actions environment and published with a build attestation.

### Changed
- `install.sh` and `install.ps1` let the agent create its schedule (same 6-hour timer or task, plus the 15-minute job check where remediation is allowed).
- The "Agent outdated" badge now says what happens next: most agents update themselves at their next run.

## [0.2.0] - 2026-10-28

A security release: a Claude Security scan of the whole repository found 21 issues (12 medium, 9 low), all fixed here with a test each and, for anything that touches real systems, a run on real services (see [STATUS.md](STATUS.md) and decision 30 in [DECISIONS.md](DECISIONS.md)). **Upgrade, and read "Changed" first: three behaviours change.**

### Security
- **Agent 0.1.3 (Windows):** a standard user who created `C:\ProgramData\Nimstead` before the agent was installed could keep read access to the agent key, and a junction planted there could make the elevated agent delete another user's files. The agent now takes the folder first (Administrators own it, explicit access entries dropped), never follows junctions, and locks the folder before the key is written. Proven in a Windows 11 VM as a standard user.
- Read-only members can no longer upload an SBOM (which resolved findings and wrote evidence).
- SSO sign-in can only be started from the sign-in page (POST), closing a login CSRF and an open redirect; identity provider endpoints must be https.
- One tenant could block another from adding an external target, or learn which hosts other tenants monitor; targets are now per organisation.
- An unknown package ecosystem reported by any agent could stop the hourly feed update for every tenant; each ecosystem now syncs on its own.
- A crafted Composer version string could freeze the API (catastrophic regex backtracking).
- The OIDC client could reuse a TLS connection verified for one hostname for another hostname on the same IP; it no longer keeps connections alive.
- Failed sign-ins spread over many addresses could lock the real user out; the per-email limit now only stops addresses that have failed themselves, and IPv6 is throttled by /64.
- Webhook URLs (Slack-style URLs are secrets) are now encrypted at rest; existing ones are encrypted by the next hourly feed run.
- Host names and job errors can no longer inject links or @channel mentions into Slack alerts.
- The evidence pack no longer ships its own verifier (whoever hands a pack over could swap it): get it from `/api/evidence/verify.py`, checked against the SHA-256 published next to the key fingerprint. Packs now name the tenant's id and DNS-verified domains, since one server key signs every tenant's packs.
- Install commands no longer put the enrolment token on the command line, where other local users and sudo logs could read it (`NIMSTEAD_TOKEN` instead).

### Changed
- **Sign-up no longer says whether an email has an account.** The first account on a server is created straight away; later sign-ups get the same answer either way and finish from an emailed link, so they need SMTP (without it they're closed; colleagues join by SSO). `NIMSTEAD_OPEN_SIGNUP=1` restores instant sign-up for development and demos only.
- **External targets must also serve their verification value** at `/.well-known/nimstead-verify.txt` from the address being scanned (HTTPS or HTTP), checked before every scan. Owning the DNS name alone no longer lets anyone aim the scanner at an IP. Add the file to existing targets, or their hourly scans are refused.
- **Alert email recipients confirm first:** each new address gets a confirmation email and receives alerts only after confirming. Existing recipients must be confirmed again (remove and re-add them in Settings).
- Manual external scans (10 an hour per organisation), test alerts (5 an hour) and sign-ups (10 an hour per address) are rate-limited.
- **Sandbox:** `winvm.py` builds Windows 11 VMs (TPM 2.0, Secure Boot) and cold-boots a VM whose firmware hangs after a restart; Windows 11 runs log to `last_run_windows11*.json`.

### Added
- **Agent 0.1.2:** Windows 10 and 11 fixes. Windows 11 downloads cumulative updates in Windows Update's "express" format, which the permanence check couldn't read, so every Windows 11 fix stopped safely with "No changes made". The agent now reads Windows Update's own install plan (`ActionList.xml`) and checks every package in it before installing: the cumulative update must be removable, and any companion package must be removable too, unless it's the servicing stack or the Safe OS (recovery partition) update, which Microsoft ships as permanent with every cumulative update. The step log names everything that stays after a rollback.

Machines on an older agent show **Agent outdated** after you upgrade the server; rerun the install command on each, especially on Windows (enrolment is kept). This release becomes available under Apache 2.0 on 2028-10-28.

## [0.1.1] - 2026-10-27

### Fixed
- **Agent 0.1.1:** a service crash-looping after a fix could pass the health check if it was sampled in a moment of "active". The check now also counts systemd restarts since the change, so the fix is rolled back. Found on a real Debian 13 host.
- **Agent 0.1.1:** a failed health check now says the service's state (for example "service is inactive") instead of ending in an empty reason.
- **Web:** the home page and the approval dialog no longer repeat the host name after a fix's summary.

### Changed
- README screenshots now come from a real run on five disposable Linux machines (`sandbox/demo.py`).

Machines on agent 0.1.0 show **Agent outdated** after you upgrade the server; rerun the install command on each to update (enrolment is kept). This release becomes available under Apache 2.0 on 2028-10-27.

## [0.1.0] - 2026-10-27

The first early-access release. Everything listed is proven by tests and, for anything that touches real systems, by runs on real machines (see [STATUS.md](STATUS.md)). Expect breaking changes before 1.0.

### Added
- **Detection:** agents for Debian, Ubuntu, RHEL-family, Alpine, SUSE and Windows (the OS and common third-party apps such as Chrome, Firefox, 7-Zip and VS Code); CycloneDX and SPDX SBOM upload; OSV, NVD, CISA KEV, EPSS and MSRC feeds; ecosystem-exact version comparison.
- **Prioritisation:** risk score from KEV, EPSS, CVSS, criticality and exposure, with a reason for every score; "Fix first" upgrades instead of CVE lists.
- **Remediation:** apt, dnf, apk, zypper (snapper) and Windows cumulative updates, with dry run, health checks, automatic rollback, canary and broad rings, kill switch, and success verified by inventory.
- **Evidence:** hash-chained ledger, signed off-database checkpoints, Ed25519 evidence packs mapped to Cyber Essentials, ISO 27001, NIST, PCI DSS and CIS, verifiable offline.
- **External scanning** of internet hosts proven owned by DNS TXT.
- **Platform:** OIDC SSO with verified domains, failure alerts (webhook, email), Vault and S3 object-lock key storage, PostgreSQL, multi-worker safe.
- Agent version reporting, with outdated agents flagged on the Assets page.
- **Install:** Docker Compose (server, PostgreSQL 17 and the hourly feed update), install and configuration guides.

Licensed under FSL-1.1-ALv2: this release becomes available under Apache 2.0 on 2028-10-27.

[Unreleased]: https://github.com/Nimstead/assure/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Nimstead/assure/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Nimstead/assure/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Nimstead/assure/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/Nimstead/assure/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Nimstead/assure/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Nimstead/assure/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Nimstead/assure/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Nimstead/assure/releases/tag/v0.1.0
