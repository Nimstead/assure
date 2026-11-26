# Todo: runtime (spec `tasks/spec-runtime.md`, plan `tasks/plan-runtime.md`)

## T0 Spike: real /proc text from three distros
- Acceptance: disposable WSL Debian 13 (systemd on), AlmaLinux 9 (systemd on) and Alpine 3.21 each run nginx, sshd and (Debian) PostgreSQL on loopback; `maps`, `cgroup`, `comm`, `status` of each, `/proc/net/{tcp,tcp6,udp,udp6}`, the fd links of the listeners, and the oracle answers (`dpkg -S` / `rpm -qf` / `apk info --who-owns` per mapped file, `ss -H -ltnup`) saved under `api/tests/fixtures/proc/`; after a library upgrade with nginx running, the ` (deleted)` lines and `needrestart -b` / `needs-restarting -s` output saved too.
- Verify: fixtures exist; the run notes say which distro has units in cgroups and what the deleted lines look like.
- Files: `api/tests/fixtures/proc/*`, `sandbox/runtime.py` (distro setup reused by T8)

## T1 Agent parsers
- Acceptance: `parse_maps` (file-backed only, ` (deleted)`, rpm `;hex`, `\012` kept escaped, anon/special skipped), `parse_cgroup_unit` (v2 and v1, system units only), `parse_net` (v4/v6, LISTEN, unconnected UDP, addresses as read), dpkg/apk/rpm list readers matching only wanted paths with merged `/usr` both ways, native detection. Each agrees with the fixtures' oracle.
- Verify: `wsl -d Ubuntu -- python3 -m pytest api/tests/test_agent_runtime_read.py -k parse`
- Files: `agent/nimstead_agent.py`, `api/tests/test_agent_runtime_read.py`

## T2 Agent pass
- Acceptance: `runtime_read()` on a fake `/proc` tree returns programs grouped by unit/comm with user, listen, loads, replaced; other mount namespaces counted not read; budgets stop with stable words and `partial`; non-root says partial; a vanished process is skipped; crafted names sanitised; a secret in cmdline/environ never in the result; `"runtime": false` / `enroll --no-runtime` leave it out (line `off`); inventory body carries `runtime`; AGENT_VERSION 0.10.0.
- Verify: pytest `test_agent_runtime_read.py` on Linux as root and as non-root; `test_agent*.py` unchanged results.
- Files: `agent/nimstead_agent.py`, `api/tests/test_agent_runtime_read.py`

## T3 Server table, store, memory
- Acceptance: `AssetRuntime` (asset_id PK, read_at, since, state, problem, data JSON) + `Finding.runtime` + Alembic migration; `runtime.store()` validates and caps (drops what doesn't fit), merges `seen` (loaded/net dates, programs, addresses), prunes after 7 days and for packages no longer installed, keeps `since` across complete reads with no gap over a day; `runtime.state(pkg)` gives listening/loaded/not_loaded/None per the spec.
- Verify: `uv run pytest -q tests/test_runtime.py tests/test_migrations.py`
- Files: `api/src/nimstead/runtime.py`, `db.py`, `migrations/versions/*`, `tests/test_runtime.py`

## T4 Rank, state, held open
- Acceptance: `risk.context(runtime=...)` +15 listening (network/adjacent/unknown vector, not KEV), reason-only loaded, ×0.75 not loaded (network/adjacent vector, no KEV/exploited/public exploit), kernel packages untouched; `rescan` sets `finding.runtime` for distro packages; a finding no longer matched stays open while the latest read names a program running a replaced copy and the installed version changed, with the reason; closes after.
- Verify: `uv run pytest -q tests/test_runtime.py tests/test_risk.py tests/test_scan*.py`
- Files: `risk.py`, `scan.py`, `runtime.py`, tests

## T5 Verify and API
- Acceptance: `verify` keeps a job verifying while all its open findings are held for a restart (succeeds after); inventory accepts `runtime`; findings items + `?runtime=` filter + CSV `runtime` last; finding detail `runtime` block; `GET /api/assets/{id}/runtime`; summary actions `runtime` and `restarts`; OpenAPI and API docs regenerated; a 0.9.0 body unchanged.
- Verify: `uv run pytest -q`; `export_api_docs.py --check`; `check_docs.py`
- Files: `remediate.py`, `app.py`, `engine/collection.py`, tests, `docs/reference/*`

## T6 Restarts after a fix
- Acceptance: after the package step, the agent reads `/proc` for programs running replaced copies of the job's packages (old and new file lists), restarts system services not on the deny list, records each step, adds them to the health checks; a failed restart rolls back and restarts them again on the restored version; refused or non-systemd programs are named in the steps; the plan JSON carries `restarts` from the latest read and the approval shows them.
- Verify: pytest `-k restart` (agent, fake runner) + API plan tests; the real run (criterion 5).
- Files: `agent/nimstead_agent.py`, `remediate.py`, tests

## T7 UI
- Acceptance: finding drawer "Running" block per state; Findings "Running" filter in the URL and saved views; Fix first per-upgrade runtime counts and a Restart to finish card; machine drawer "Running"; approval names restarts; unit tests; e2e with axe at 1440 and 375, light and dark.
- Verify: `cd web && npm test && npx tsc --noEmit && npm run build && npm run e2e`
- Files: `web/src/findings.tsx`, `home.tsx`, `assets.tsx`, `planfix.tsx`, `lib.ts`, `runtime.test.tsx`, `e2e/*`

## T8 Real-host proof
- Acceptance: `sandbox/runtime.py` passes criteria 1-6 on fresh Debian 13, AlmaLinux 9 and Alpine 3.21 (Alpine: criteria 1, 2, 6 and the no-systemd restart wording); record in `sandbox/last_run_runtime_<distro>.json`; distros destroyed after.
- Verify: the run records say PASS with every difference explained.
- Files: `sandbox/runtime.py`, `sandbox/last_run_runtime_*.json`

## T9 Performance
- Acceptance: the pass under 3 s with 500 processes (proof host); `perf.py --runtime` at 1,000 hosts: report median and hourly re-match within 20% of 0.13.0 on the same machine.
- Verify: `sandbox/last_run_perf_sqlite_runtime.json`
- Files: `sandbox/perf.py`

## T10 Docs and versions
- Acceptance: how-to (what's running and what to restart), reference (agent runtime, findings/assets/summary API), explanation (how runtime ranks and why "not loaded" is said as it is), README bullet, CHANGELOG 0.14.0 with Highlights, STATUS section, DECISIONS 161+, version 0.14.0 / agent 0.10.0.
- Verify: `check_docs.py`, `export_api_docs.py --check`
- Files: `docs/**`, `README.md`, `CHANGELOG.md`, `STATUS.md`, `DECISIONS.md`, version files
