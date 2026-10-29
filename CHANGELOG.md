# Changelog

All notable changes to Nimstead Assure. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Nimstead/assure/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Nimstead/assure/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Nimstead/assure/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/Nimstead/assure/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Nimstead/assure/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Nimstead/assure/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Nimstead/assure/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Nimstead/assure/releases/tag/v0.1.0
