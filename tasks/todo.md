# Todo: a great agent, with automatic updates (see tasks/plan.md)

**Status 2026-10-28: all tasks and checkpoints A–C done** (evidence in STATUS.md). Release keys set up and pinned (primary in the GitHub `release` environment, backup offline). Left for the owner: move the backup key to the password manager and delete both key files, add a `v*` tag ruleset and passkey 2FA, then commit, merge and tag v0.3.0. Not done: Windows VM run of self-update via the scheduled task (proven as a real file swap on Windows and on a real Linux host); base images pinned by digest.

Commands: API tests `cd api && uv run pytest -q` · lint `uv run ruff check src tests ../agent ../sandbox` · web `cd web && npm test && npm run build && npm run e2e`

## Phase 1: Signed agent self-update

### Task 1: Pure-Python Ed25519 verify in the agent
**Description:** Add `ed25519_verify(pub, msg, sig)` to `agent/nimstead_agent.py` (RFC 8032 §5.1.7, verify only, stdlib).
**Acceptance criteria:**
- [x] All RFC 8032 §7.1 test vectors verify
- [x] A flipped bit in sig, message or key fails; S ≥ L and malformed points are rejected, not crashed on
- [x] Agent stays single-file, stdlib-only, Python 3.9+
**Verification:** `uv run pytest -q tests/test_agent_ed25519.py`; ruff clean
**Dependencies:** None
**Files:** `agent/nimstead_agent.py`, `api/tests/test_agent_ed25519.py`
**Scope:** S

### Task 2: CI release signing and signed manifest
**Description:** `.github/workflows/release.yml` runs on a `v*` tag in the protected `release` environment. It calls `scripts/sign_release.py`, which signs `release.json` = `{version, agent_version, agent_sha256, commit}` with the Ed25519 key from the environment secret, then attaches `release.json` + `release.json.sig` to the GitHub release (plus a GitHub artifact attestation for auditors). The image build includes them. The agent pins `RELEASE_KEYS = [primary, backup]`. The API serves `GET /agent/manifest` → manifest + sig + `paused` (the org pause, unsigned by design: it can only withhold).
**Acceptance criteria:**
- [x] Manifest matches the shipped agent; a missing or invalid sig → a manifest with no sig, never a guessed one; dev builds without a release ship none, so agents never update from them
- [x] The private key exists only as an environment secret (and the offline backup); never read by the server, never in the repo or image
- [x] Signature verifies with the agent's own `ed25519_verify` (cross-check against `cryptography`)
**Verification:** `uv run pytest -q tests/test_api.py -k manifest`, `tests/test_sign_release.py`; a dry run of the workflow on a test tag in a fork
**Dependencies:** T1 (test only); owner setup in plan.md
**Files:** `.github/workflows/release.yml`, `scripts/sign_release.py`, `api/src/nimstead/app.py`, `agent/nimstead_agent.py`, `Dockerfile`, tests
**Scope:** M

### Task 3: Agent updates itself
**Description:** At the start of `report` and `remediate` (under `run_lock`; skipped while `WIN_STATE` exists, if `auto_update` is false in config, or if the manifest says `paused`): fetch the manifest, require version > `AGENT_VERSION` and a valid signature from a pinned key, download, check sha256, write the temp file in the agent dir, run `<python> new collect` as the smoke test, keep `.prev`, `os.replace`, re-exec. On any failure keep the old agent and carry on with the run. `enroll --no-auto-update` opts out. Inventory reports `auto_update`.
**Acceptance criteria:**
- [x] Newer + valid → replaced and the run continues on the new version; equal or older → no change; bad sig, bad hash or failed smoke test → old file untouched, reason printed and the run still reports
- [x] Never runs during a pending Windows job; the Windows folder lockdown still runs first
- [x] Download goes through the existing no-redirect `post`/HTTP helpers (https unless `--insecure-http`)
**Verification:** unit tests with a fake server and fake files (`tests/test_agent_update.py`); **Checkpoint A**
**Dependencies:** T1, T2
**Files:** `agent/nimstead_agent.py`, `api/src/nimstead/app.py` (store `auto_update`), `db.py` + Alembic migration, tests
**Scope:** M

### Task 4: Show update state
**Description:** Assets shows "Updates automatically" or "Outdated: reinstall needed" (old agent, or `auto_update` off); Home counts hosts needing a reinstall. Settings gets the admin-only org "Pause agent updates" switch (recorded in the ledger).
**Acceptance criteria:**
- [x] The pause switch is admin-only, and pausing or resuming is ledgered
- [x] 0.1.x agents (no key pinned) → "reinstall needed" with the install command
- [x] Auto-updating hosts one version behind don't show as a problem until 24 h after the server's agent changed
- [x] axe clean
**Verification:** `npm test`, `npm run e2e`, API test for the field
**Dependencies:** T3
**Files:** `api/src/nimstead/app.py`, `web/src/assets.tsx`, `web/src/home.tsx`, tests
**Scope:** S

### Checkpoint A
- [x] API, web and ruff all green
- [x] Real hosts: Debian 13 and Alpine 3.21 (`sandbox/sbx.py --update`) and the Windows 11 VM (`wine2e.py --update`): N → N+1 automatically; tampered sig refused; downgrade refused; broken N+1 reverted, host still reporting
- [x] Review with the owner before Phase 2

## Phase 2: Faster and louder agent

### Task 5: Agent owns its schedule; fast job poll
**Description:** New `schedule` subcommand writes the systemd service and timers (Linux) or the scheduled task (Windows): inventory every 6 h as now, plus for remediation hosts a 15-minute `remediate --if-jobs` that only fetches jobs (and re-reports only if it ran one). The installers call `schedule` instead of writing units themselves. An updated agent re-runs `schedule` once after an update.
**Acceptance criteria:**
- [x] Fresh install and an updated 0.2.x host end with identical units/tasks
- [x] An approved job starts within 15 min; idle polls don't touch the inventory rate limit
- [x] Non-remediation hosts get no poll timer
**Verification:** unit tests for the generated unit text and task args; **Checkpoint B**
**Dependencies:** T3
**Files:** `agent/nimstead_agent.py`, `api/src/nimstead/static/install.sh`, `install.ps1`, tests
**Scope:** M

### Task 6: "Not reporting" hosts
**Description:** A host not seen for 14 h (2× the interval + jitter) shows "Not reporting" on Assets and Home; the hourly feed run sends one failure alert per host per outage (existing `notify.py`).
**Acceptance criteria:**
- [x] One alert per outage, not hourly; cleared when the host reports
- [x] Applications (SBOM assets) are never flagged
**Verification:** `uv run pytest -q -k not_reporting`; web unit test
**Dependencies:** None
**Files:** `api/src/nimstead/feeds.py` or `notify.py`, `app.py`, `db.py` + migration, `web/src/assets.tsx`
**Scope:** M

### Task 7: Uninstall
**Description:** `nimstead_agent.py uninstall` removes the timers or task, config, key and state dir (refuses while a Windows job is pending); docs give the one-line command.
**Acceptance criteria:**
- [x] Nothing of the agent is left except the files the user is told about; refused mid-job
**Verification:** unit test with a temp root; checked on a real host in Checkpoint B
**Dependencies:** T5
**Files:** `agent/nimstead_agent.py`, `docs/install.md`, tests
**Scope:** S

### Checkpoint B
- [x] All suites green; on a real Debian host: job picked up < 15 min, stopped agent → "Not reporting" + one alert, uninstall clean
- [x] Review with the owner

## Phase 3: Assure platform updates

### Task 8: Health endpoint
**Description:** `GET /api/health` → `{version, db: ok, migrations: head}` (no auth, no tenant data); Compose `healthcheck` uses it.
**Acceptance criteria:**
- [x] 503 when the DB is unreachable or migrations aren't at head
**Verification:** API test; `sandbox/compose.py` shows the container `healthy`
**Dependencies:** None
**Files:** `app.py`, `compose.yaml`, `Dockerfile`, tests
**Scope:** S

### Task 9: "Update available"
**Description:** The daily feed run reads the latest release from GitHub (`NIMSTEAD_UPDATE_CHECK=0` turns it off); Settings shows the running version and any newer one with its CHANGELOG link; admins get one alert per new release.
**Acceptance criteria:**
- [x] Offline or failed check → no banner, no error loop; pre-releases ignored
- [x] Outbound call goes through `netguard`
**Verification:** mocked tests; web unit test
**Dependencies:** T8
**Files:** `feeds.py`, `app.py`, `web/src/settings.tsx`, tests
**Scope:** S

### Task 10: `deploy/update.sh` with rollback
**Description:** Opt-in script + systemd timer on the Docker host: `git fetch --tags`; pick the newest release tag above the current one; download its `release.json` + sig, verify against the pinned release keys (same verifier as the agent), and require the tag's commit to equal the manifest's `commit`; `pg_dump` into the data volume; `git checkout`; `docker compose build && up -d`; wait for `/api/health` (5 min). If unhealthy: check out the previous tag, restore the dump, `up -d`, alert. Writes `data/update-status.json`, which Settings shows.
**Acceptance criteria:**
- [x] Unsigned or older tag → refused, nothing changed
- [x] Failed health → previous version running with the pre-update data, reported loudly
- [x] `--dry-run` prints the plan only
**Verification:** **Checkpoint C**
**Dependencies:** T8, T9
**Files:** `deploy/update.sh`, `deploy/nimstead-update.{service,timer}`, `sandbox/compose.py`, `docs/install.md`
**Scope:** M

### Checkpoint C
- [x] `sandbox/compose.py --update` PASS: real update with data intact; forced-unhealthy release rolled back and DB restored; unsigned tag refused
- [x] The new release's agent reaches an enrolled host on its own (T3), closing the loop
- [x] Review with the owner

## Phase 4: Ship

### Task 11: Docs and release
**Description:** DECISIONS 31 (signed agent updates) and 32 (platform updates); STATUS rows with evidence and honest gaps; install docs (reinstall once for 0.1.x, opt-outs, update timer); CHANGELOG; release 0.3.0 with agent 0.2.0 as the first signed agent.
**Acceptance criteria:**
- [x] Every new claim in STATUS points at a test or a `sandbox/last_run_*.json`
**Verification:** CI green on GitHub
**Dependencies:** all
**Scope:** S
