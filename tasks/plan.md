# Implementation Plan (done, shipped in 0.3.0): A great agent, with automatic updates for the agent and the Assure platform

## Overview
Today an agent update means rerunning the install command on every host (the Assets page only flags "Agent outdated"), and updating the Assure server means pulling the repo and rebuilding by hand. The agent also reports and picks up jobs only every 6 hours, and nothing tells an admin when a host goes quiet. This plan makes both update paths automatic **without weakening the threat model** (DECISIONS 7 and 27: a compromised server can only ask opted-in hosts to upgrade real packages, never run code), makes the agent faster to act, and makes silent failures visible.

## What exists (reuse, don't rebuild)
- `AGENT_VERSION` in `agent/nimstead_agent.py`; the server reads it (`latest_agent_version()` in `app.py`) and flags outdated hosts on Assets.
- The server serves the agent at `/agent/nimstead_agent.py`; `install.sh` writes a systemd timer, `install.ps1` a SYSTEM scheduled task (every 6 h + at startup).
- `run_lock`, the persisted Windows job state (`WIN_STATE`), `secure_windows_dir()`: an update must respect all three.
- Ed25519 signing and a pinned fingerprint already exist for evidence packs (`evidence.py`, `verify_pack.py`), but the agent is stdlib-only, so it can't use `cryptography`.
- Failure alerts (`notify.py`), the hourly `feeds update` job, `last_seen` on assets.
- Real-host harnesses: `sandbox/sbx.py` (Linux distros), `sandbox/wine2e.py` + `winvm.py` (Windows), `sandbox/compose.py` (Docker Compose install).

## Architecture decisions (become DECISIONS 31–32)
1. **Agent updates are signed in GitHub Actions, never by the server.** If the server could hand out a new agent, a compromised server would have root/SYSTEM on every host, which is exactly what decision 7 rules out. The Ed25519 release key is a secret in a protected `release` environment (required reviewer: the owner; tag protection; passkey 2FA on the account). A workflow on a release tag signs a release manifest `{version, agent sha256, commit}`. A second, backup key lives offline in the owner's password manager, used only to sign a rotation release. Both public keys are pinned in the agent. Agents keep downloading from their own server (hosts often have no internet access); the server only *relays* `agent + signature`, so a compromised server can withhold updates, never forge one. Rejected: plain HTTPS from GitHub (a GitHub login becomes fleet root, and hosts can't reach it); Sigstore/artifact attestations checked in the agent (X.509 + ECDSA + transparency-log proofs hand-written in a root process). Attestations can be published alongside for auditors at no cost.
2. **Only strictly newer versions are accepted** (anti-rollback): a relayed old-but-validly-signed agent with a known bug can't be pushed back onto the fleet.
3. **Ed25519 verification in pure Python inside the agent** (RFC 8032 reference algorithm, verify only, about 60 lines), tested against the RFC 8032 vectors. That keeps the agent single-file and stdlib-only. It's slow, but one verification per run doesn't matter. Rejected alternative: shelling out to `openssl`, which Windows doesn't have.
4. **Update = replace, smoke-test, keep or revert.** The agent keeps `nimstead_agent.py.prev` and runs the new file's `collect` (no network) before switching. If that fails, it puts the old file back and reports. This is the same "reversible or not at all" rule the agent applies to packages (decision 8).
5. **Never update mid-job.** The update runs under `run_lock` and is skipped while a Windows job waits for its reboot (`WIN_STATE` exists).
6. **The agent owns its own schedule** (`nimstead_agent.py schedule` writes the systemd units or the scheduled task). The installers call it, and an updated agent re-runs it, so hosts pick up schedule changes (such as fast job polling) without a reinstall.
7. **The platform updates from release tags checked against the same CI-signed manifest, built locally, never from a pulled image.** The manifest pins the tag's commit, so one key covers both the agent and the platform. That keeps `pull_policy: build` and the "nobody else's image" guarantee.
8. **Auto-update is on by default, with two off switches:** `enroll --no-auto-update` on the host, and an org-wide pause in Settings, which the server reflects in the manifest it relays. Pausing only withholds updates, which a compromised server could do anyway, so the switch grants nothing new. Rollback = previous tag + restore of a `pg_dump` taken just before migrations, because Alembic downgrades aren't trustworthy on real data. Default is **notify only**; auto-apply is an opt-in timer on the Docker host.

## Dependency graph
```
T1 Ed25519 verify (agent) ──► T3 agent self-update ──► T4 UI shows update state
T2 release signing + manifest ─┘        │
                                        └──► T5 agent-owned schedule + fast job poll
T6 "Not reporting" hosts   (independent)
T7 agent uninstall         (after T5: removes what schedule wrote)
T8 /api/health ──► T9 "update available" in Settings ──► T10 update.sh + rollback
T11 docs / DECISIONS / STATUS / CHANGELOG / release  (last)
```
Parallel-safe: T6 and T8 can run alongside Phase 1. T1 and T2 can run together (T2 needs a verifier only in its test).

## Task list
Done: evidence in STATUS.md. The current plan is `tasks/plan-0.4-security.md`.

### Phase 1: Signed agent self-update (highest risk, so first)
- T1 Pure-Python Ed25519 verify in the agent
- T2 Release signing script, pinned public key, signed manifest served by the API
- T3 Agent updates itself: verify, anti-rollback, smoke test, revert
- T4 Assets/Home show "updates automatically" vs "reinstall needed"

### Checkpoint A (real hosts)
- Debian 13 and Alpine 3.21 (`sbx.py`) and the Windows 11 VM: agent N updates itself to N+1 from the server. A tampered signature, a downgrade and a deliberately broken N+1 are each refused or reverted, with the host still reporting.

### Phase 2: Faster and louder agent
- T5 `schedule` subcommand; 15-minute job poll for remediation hosts (inventory stays every 6 h)
- T6 "Not reporting" hosts on Assets, plus one alert
- T7 `uninstall` subcommand

### Checkpoint B
- Approved job runs within 15 min on a real Debian host; a stopped agent shows "Not reporting" and alerts once; uninstall leaves no timer, task or config.

### Phase 3: Assure platform updates
- T8 `/api/health` + Compose healthcheck
- T9 Server checks for new releases daily; Settings shows the version and "update available"; admins get one alert
- T10 `deploy/update.sh` + opt-in systemd timer: verify tag, back up, build, migrate, health-gate, roll back

### Checkpoint C (real Compose host)
- `sandbox/compose.py --update`: 0.2.0 → new tag succeeds with data intact; a release whose health check fails is rolled back to 0.2.0 and the database restored; an unsigned tag is refused.

### Phase 4: Ship
- T11 DECISIONS 31–32, STATUS, install docs, CHANGELOG, release 0.3.0 (agent 0.2.0), with the first signed agent

## Risks and mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| Hand-rolled Ed25519 verify has a bug that accepts bad signatures | High | RFC 8032 vectors plus negative tests (flipped bit in sig, message and key; non-canonical S ≥ L rejected); verify only, no signing code in the agent |
| Release key leaked or lost | High | Kept offline (hardware key or an air-gapped file), never in the repo or on the server. The agent supports a list of pinned keys so a rotation can ship in an update signed by the old key |
| A bad agent bricks the fleet's reporting | High | Smoke test before switching, `.prev` kept, revert on failure; updates gated per host by version, so a bad release can be followed by N+2 |
| Existing 0.1.x agents have no pinned key | Med | One last manual reinstall (documented, flagged "reinstall needed" by T4). Unavoidable: anything else lets the server push code |
| Platform migration breaks data | High | `pg_dump` before migrate; rollback restores it; health gate checks migrations at head and a real query |
| SQLite installs | Low | update.sh supports Compose + PostgreSQL only (the documented production install); SQLite/dev is "notify only" |
| Windows file lock on replacing a running .py | Med | The scheduled task runs a fresh interpreter each time; replace with `os.replace` from a temp file in the same locked folder; proven in Checkpoint A |

## Decided with the owner (2026-10-28)
1. Agent auto-update: **on by default**, local `--no-auto-update` opt-out, plus an **org-wide pause** in Settings.
2. Release key: **held by GitHub Actions** in a protected environment, plus an offline backup key in a password manager; no hardware key. One key signs the release manifest for both the agent and the platform.
3. Platform: **notify only by default**; the `update.sh` timer is an opt-in.
4. Assure platform = **self-hosted Docker Compose** (no hosted instance).

## Owner setup before Task 2 can ship (one-off, ~10 min)
- [x] Passkey 2FA on the GitHub account(s) with write access to Nimstead/assure (owner confirmed, 2026-10-28)
- [x] Repository → Environments → `release`, required reviewer = owner, deployable from `v*` tags only; primary key stored as `NIMSTEAD_RELEASE_KEY` (2026-10-28)
- [x] Tag protection (ruleset "Release tags", id 26039402) for `v*`: no deletion or moving; repository admins can bypass (2026-10-28)
- [x] v0.3.0 released: Release workflow approved, signed manifest published and verified with the agent's verifier (2026-10-28)
- [x] Backup private key saved in the password manager (owner confirmed); both key files deleted from disk (2026-10-28)

## Skipped on purpose
deb/rpm/MSI packages, a hosted update CDN, staged/percentage agent rollouts (the canary ring already exists for package fixes; add one for agent updates only if a bad release ever escapes the smoke test), Windows 10 remediation proof, agent error telemetry.
