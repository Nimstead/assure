# Todo: paths (spec `tasks/spec-paths.md`, plan `tasks/plan-paths.md`)

## Body contract (drafted in planning, confirmed or corrected by T0)
```json
"access": {"v": 1, "state": "ok", "problem": null,
  "sshd": {"permitrootlogin": "prohibit-password", "pubkeyauthentication": "yes", "passwordauthentication": "no",
           "kbdinteractiveauthentication": "no", "permitemptypasswords": "no", "authorizedkeysfile": [".ssh/authorized_keys"],
           "authorizedkeyscommand": false, "allowusers": [], "denyusers": [], "allowgroups": [], "denygroups": [], "match": false},
  "accounts": [{"name": "www-data", "uid": 33, "groups": ["www-data", "docker"], "login": false, "sudo_all": false, "password": "locked"}],
  "writable": [{"path": "/etc/cron.d/backup", "kind": "cron", "by": "group:deploy"}],
  "shadow_readable_by": [],
  "held": [{"account": "root", "path": "/root/.ssh/id_ed25519", "type": "ssh-ed25519", "fp": "SHA256:…", "passphrase": false}],
  "trusted": [{"account": "root", "fp": "SHA256:…", "type": "ssh-ed25519", "from": ["10.89.0.0/24"], "forced": false, "restrict": false}],
  "credentials": [{"kind": "keytab", "account": "root", "path": "/etc/krb5.keytab"}],
  "agent_sockets": 0, "unidentified_keys": 0}
```
`facts` on Linux gains `addresses` (its own IPv4) and `peers` (`addr:port` of established TCP connections to private
ranges), the same keys and caps Windows sends. A field the pass couldn't read is `null`, never empty.

## T0 Spike: the lab, fixtures, the body
- Acceptance:
  - A fresh disposable WSL Fedora runs Podman with four systemd containers (Debian 13, AlmaLinux 9, Alpine 3.21 with
    OpenRC, a second Debian 13) on one private bridge, each with its own address and sshd.
  - `ssh` with a planted key from one container to another signs in, and the target's `ss` shows the source's address.
  - Saved under `api/tests/fixtures/access/`:
    - `sshd -T` from each distro, default and hardened
    - key files of every type (ed25519, ecdsa, rsa; OpenSSH and PEM; with and without a passphrase) and the matching
      `ssh-keygen -lf` output
    - `authorized_keys` lines with each option, and `/etc/passwd` and `/etc/group`
    - `sudo -n -l -U` output (`NOPASSWD: ALL`, a limited rule, none)
  - The body contract above is confirmed or corrected here.
  - If systemd containers fail, the fallback is decided and written in the run notes.
- Verify: the fixtures exist; the run notes give the lab's addresses and say which distros needed what.
- Files: `api/tests/fixtures/access/*`, `sandbox/paths_lab.py` (lab setup, reused by T9)

## T1 Agent parsers
- Acceptance: each parser agrees with the fixtures' oracle:
  - `parse_sshd_t`: the listed keys, `match` from the config file
  - `parse_private_key`: OpenSSH header to type, public blob, SHA-256 fingerprint equal to `ssh-keygen -lf`, cipher not
    `none` means passphrase; PEM `ENCRYPTED`; truncated or garbage input gives None and never raises
  - `parse_public_key`
  - `parse_authorized_keys`: options before the key type, quoted `from=` with commas, `command=` with escaped quotes,
    `restrict`, `cert-authority` lines skipped; comments dropped
  - `expand_keys_file` (`%h`, `%u`, `%%`, relative to the home)
  - `parse_passwd` and `parse_group`
  - `parse_sudo_l`: `NOPASSWD: ALL` under any runas only
  - `who_can_write(mode, uid, gid)`: owner, group or other; the sticky bit noted
- Verify: `wsl -d Ubuntu -- python3 -m pytest api/tests/test_agent_linux_facts.py -k parse`
- Files: `agent/nimstead_agent.py`, `api/tests/test_agent_linux_facts.py`

## T2 Agent pass
- Acceptance:
  - `access_read()` on a fake root returns the contract: the accounts that matter (login shells plus root, running
    programs' users, `/home` owners), root-equivalent groups, `sudo_all` for at most 32 accounts with `-n` and 3 s each,
    writable root-run files with every parent folder checked, keys held and trusted, credentials by presence.
  - `addresses` and `peers` (private ranges only) go in `facts`.
  - Every budget stops with stable words and `partial`. A non-root pass is partial and says so.
  - Hostile files are named and never read: a link, a FIFO, another user's file, oversize, 10,000 lines, crafted names.
  - Private-key bytes, comments, forced commands and credential contents never appear in the result (an asserting test).
  - `"paths": false` and `enroll --no-paths` leave out `access`, `addresses` and `peers` (line `off`).
  - An unexpected error becomes a failed line, never a lost inventory. AGENT_VERSION is 0.11.0.
- Verify: pytest `test_agent_linux_facts.py` on Linux as root and as non-root; `test_agent*.py` results unchanged.
- Files: `agent/nimstead_agent.py`, `api/tests/test_agent_linux_facts.py`

## Checkpoint A
- [x] Agent suites green (Linux root and non-root, Windows unchanged).
- [x] Fingerprints equal `ssh-keygen -lf` on every fixture.

## T3 Server table and store
- Acceptance:
  - `AssetAccess` (asset_id PK, org_id, read_at, state, problem, data JSON) and an Alembic migration.
  - `access.valid` and `access.store` keep the contract's shape, cap each list (accounts 64, held 256, trusted 5,000,
    writable 50, credentials 100, `from` 16×64), and drop what doesn't fit, never the inventory.
  - The inventory body accepts `access`. Linux `facts` accept `addresses` and `peers`.
  - A 0.10.0 body (no `access`) is judged exactly as before.
- Verify: `uv run pytest -q tests/test_access.py tests/test_migrations.py`
- Files: `api/src/nimstead/access.py`, `db.py`, `migrations/versions/*`, `app.py`, `tests/test_access.py`

## T4 Linux settings findings
- Acceptance:
  - `linconfig.evaluate(access, listening)` gives the six checks with `CFG:` ids, severities, who they help and the fix
    text, and the `LinuxConfig` ecosystem goes through `scan.host_checks`.
  - Findings are unproven (never closed) while `access` is unread or partial for their fields, and close on a complete
    read that no longer shows them.
  - Counted as fixable by changing a setting, like WinConfig, with no automated fix path.
  - Stock-config fixtures open nothing.
- Verify: `uv run pytest -q tests/test_linconfig.py tests/test_scan*.py`
- Files: `api/src/nimstead/linconfig.py`, `scan.py`, `app.py` (fixable lists), `tests/test_linconfig.py`

## Checkpoint B
- [x] API suite green on SQLite (PostgreSQL 17: CI, at ship).
- [x] No finding change on stored Windows and 0.10.0 Linux inventories.

## T5 Engine context and Linux host paths
- Acceptance:
  - `Inventory.context` is filled by `judge` and `asset_report` with `listening` (from `runtime.state` memory) and
    `access`, and carried in `to_doc`.
  - Windows documents are byte-identical.
  - `paths.build` for Linux:
    - Getting in: network-vector verdicts on listening packages, graded no better than *reasonable*, each with its
      program's user; known-exploited flaws without a listener; the ssh settings when sshd listens beyond loopback.
    - Becoming root: local-vector verdicts (the kernel's included); settings only for the user they help; skipped, with
      the reason, for a root listener.
    - Taking credentials: all held keys once root (a passphrase key *unverified*), only the way-in user's own without root;
      the keytab; other credentials "not followed".
  - Each path has `reaches`. The report renders it. Labels read "Becoming root".
- Verify: `uv run pytest -q tests/test_paths_linux.py tests/test_engine*.py`, plus a Windows report identical to before on
  the stored German Windows 10 inventory.
- Files: `engine/collection.py`, `engine/__init__.py`, `engine/paths.py`, `engine/report.py`, `tests/test_paths_linux.py`

## T6 Key edges
- Acceptance:
  - `fleet.build` takes each Linux host's access and links A to B by fingerprint when:
    - A's path reaches root, or the key's owner
    - B's sshd listens beyond loopback with keys on
    - the account may sign in (root login, Allow/Deny users and groups with sshd's wildcard rules)
    - `from=` matches A's addresses (CIDR, wildcards, negation, first match)
  - Grades as the spec's table: passphrase, `command=`/`restrict`, `Match`, `authorizedkeyscommand`, host-name-only
    `from=`, and peers seen.
  - The edge says what B hands over (root, or the account), and chains walk Windows and key edges together.
  - `MAX_EDGES` counts both kinds. The endpoint loads `asset_access` in one query.
- Verify: `uv run pytest -q tests/test_fleet_keys.py tests/test_fleet*.py tests/test_api.py -k attack`
- Files: `engine/fleet.py`, `app.py`, `tests/test_fleet_keys.py`

## T7 Choke points
- Acceptance:
  - `fleet.choke_points(result)` returns up to ten actions, largest cut first. Each gives:
    - the kind (update, retire key, untrust key, setting) and the action in words
    - the machines cut and the edges removed
  - At most 200 candidates. Counts equal a brute-force recount on random small graphs. Ties order stably. When the graph
    was truncated, the counts are said to be a lower bound.
  - `/api/attack-paths` returns `choke_points`. OpenAPI and the API reference are regenerated.
- Verify: `uv run pytest -q tests/test_fleet_keys.py -k choke`; `uv run python ../scripts/export_api_docs.py --check`
- Files: `engine/fleet.py`, `app.py`, `tests/test_fleet_keys.py`, `docs/reference/*`

## Checkpoint C
- [x] API suite green.
- [x] Windows host and fleet paths unchanged (existing Windows path and fleet tests pass unmodified).

## T8 UI
- Acceptance:
  - The machine drawer shows Linux paths with the way-in user, "skips becoming root" and credentials in words.
  - `AttackPaths` shows key edges (key on A, account on B, why the grade) and a Choke points card linking to machines and
    findings.
  - `LinuxConfig` findings show with their fix text and filter like the Windows settings.
  - Unit tests for each wording. e2e with axe at 1440 and 375, in light and dark.
- Verify: `cd web && npm test && npx tsc --noEmit && npm run build && npm run e2e`
- Files: `web/src/assets.tsx`, `findings.tsx`, `lib.ts`, `paths.test.tsx`, `web/e2e/*`

## T9 Real proof
- Acceptance: `sandbox/paths_lab.py` on a fresh lab meets success criteria 1–6:
  1. facts equal the oracles
  2. 14 planted edge cases agree with real `ssh`
  3. privilege-aware paths on three machines
  4. the chain equals an `ssh` walk; the top choke point, applied for real, shrinks reach exactly
  5. the six checks open when planted and close when fixed; stock configs open none
  6. no secret anywhere in stored inventories or the evidence pack; hostile files inert

  Each difference is explained in `sandbox/last_run_paths.json`. The lab is destroyed after.
- Verify: the run record says PASS for each criterion.
- Files: `sandbox/paths_lab.py`, `sandbox/last_run_paths.json`

## T10 Performance
- Acceptance:
  - `perf.py --paths` (3 held and 20 trusted keys per host, a key graph with real fan-out) at 1,000 hosts:
    `/api/attack-paths` with choke points has a median under 2 s.
  - The inventory median stays within 20% of 0.14.1's on this PC.
  - The facts pass takes under 2 s with 50 accounts and 500 trusted keys (measured in WSL).
- Verify: `sandbox/last_run_perf_sqlite_paths.json`
- Files: `sandbox/perf.py`, the run record

## T11 Docs and versions
- Acceptance:
  - `design-paths.md`: Linux stages, key edges, choke points; "Not yet" updated.
  - how-to (read your attack paths; turn the reads off), reference (the `access` body, `LinuxConfig` checks, the endpoint),
    explanation (why exact keys, what isn't followed).
  - README, plus CHANGELOG 0.15.0 with a Highlights summary at the top.
  - DECISIONS 165 onwards, STATUS section, and the versions (`pyproject`, `uv.lock`, `package.json`, lock, `compose.yaml`).
- Verify: `check_docs.py`; `export_api_docs.py --check`
- Files: `docs/**`, `README.md`, `CHANGELOG.md`, `DECISIONS.md`, `STATUS.md`, version files

## Checkpoint D: complete
- [x] Every success criterion met with its run record (last_run_paths.json, last_run_perf_sqlite_paths.json).
- [x] All suites, `tsc`, build and e2e green.
- [x] Docs checks pass.

## T12 Review
- Acceptance:
  - An independent code review and a security audit of the branch.
  - Every finding is fixed with a test that fails first, or answered in DECISIONS with the reason.
  - A mutation check of `linconfig.py`, the key-edge grading and the choke-point count: every mutant caught, and survivors
    become tests.
- Verify: the review notes and the mutation table in DECISIONS.
- Files: wherever the findings lead

## T13 Ship 0.15.0
- Acceptance:
  - The PR passes CI on SQLite, PostgreSQL 17, web, e2e, Docker, audit and the Windows runtime; squash-merged; tagged
    v0.15.0.
  - The release gate is approved by the owner (or on their "you do it" for this run).
  - The manifest is verified with the agent's own verifier, and the published agent matches the tag.
  - The STATUS line is merged.
  - The website PR is opened, and merged only on the owner's word.
  - New docs pages are added to nimstead-docs' `pages.json`, asking first.
- Verify: release run green; `verify_release.py v0.15.0`; the live pages
- Files: release only
