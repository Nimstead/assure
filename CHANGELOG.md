# Changelog

All notable changes to Nimstead Assure. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Nimstead/assure/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Nimstead/assure/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Nimstead/assure/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Nimstead/assure/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Nimstead/assure/releases/tag/v0.1.0
