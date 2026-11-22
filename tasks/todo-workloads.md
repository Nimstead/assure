# Todo: workloads (spec `tasks/spec-workloads.md`, plan `tasks/plan-workloads.md`)

## T0 Spike: k3s in a disposable WSL Debian 13
- Acceptance: a k3s node runs pods; `crictl ps -q --state running`, `crictl inspect -o json <ids>` and `crictl version -o json` output saved under `api/tests/fixtures/cri/`; the image id field and cgroup naming confirmed.
- Verify: fixtures exist and parse; notes in the run record.
- Files: `api/tests/fixtures/cri/*`, `sandbox/workloads.py` (distro setup reused later)

## T1 Walker
- Acceptance: `ContainerRoot.walk()` yields entries without following links or entering other mounts; files open only as regular; entry and time budgets stop it with a reason; hostile trees (links out/climbing/loop, FIFO, deep tree) read nothing outside.
- Verify: `wsl -d Ubuntu -- python3 -m pytest api/tests/test_agent_workloads.py -k walk`
- Files: `agent/nimstead_agent.py`, `api/tests/test_agent_workloads.py`

## T2 Python, npm, Java readers + owned exclusion
- Acceptance: rows equal the host scans' for the same layout; dpkg/apk/rpm-owned metadata skipped and counted; FIFOs named METADATA/package.json/evil.jar, a 200 MB sparse jar and a nested zip bomb read nothing and finish.
- Verify: pytest `-k "python or npm or jar or owned"`; host scan tests (`test_agent_jars.py`, app scan tests) still pass.
- Files: `agent/nimstead_agent.py`, `api/tests/test_agent_workloads.py`

## T3 Go build info
- Acceptance: deps (with replacements) and `stdlib` from a Go 1.18+ binary; pre-1.18 or malformed counted unread; capped reads.
- Verify: pytest `-k go` on synthetic ELF fixtures; the real-host run compares with Syft.
- Files: `agent/nimstead_agent.py`, `api/tests/test_agent_workloads.py`

## T4 Wire into containers()
- Acceptance: image entries carry `apps` and four new lines; one walk per image key; budgets partial-not-silent; `container_apps: false` / `enroll --no-container-apps` turns it off locally.
- Verify: pytest `test_agent_containers.py test_agent_workloads.py` on Linux.
- Files: `agent/nimstead_agent.py`, tests

## T5 Server: image apps + engine go_modules
- Acceptance: apps stored with their ecosystems and sources; key includes them; caps; findings open for PyPI/npm/Maven/Go rows on images; a 0.8.1 body judged exactly as before.
- Verify: `uv run pytest -q tests/test_containers.py tests/test_engine_apps.py`
- Files: `api/src/nimstead/containers.py`, `api/src/nimstead/engine/collection.py`, `api/tests/test_containers.py`

## T6 Server: CRI runtimes
- Acceptance: `containerd` and `cri-o` rows stored; a complete listing per runtime removes only its own rows.
- Verify: pytest `tests/test_containers.py -k runtime`
- Files: `api/src/nimstead/containers.py`, tests

## T7 Agent crictl
- Acceptance: listing from recorded fixtures gives ids, PIDs, image ids, `ns/pod/container` names, runtime names; failures are problems, never stopped containers; a removed crictl + runtime lists empty.
- Verify: pytest `-k cri`
- Files: `agent/nimstead_agent.py`, tests

## T8 UI
- Acceptance: image drawer shows per-source read counts and reasons; app findings show location; Fix first's rebuild list names app packages; axe clean.
- Verify: `npm test`, `npm run build`, e2e subset.
- Files: `api/src/nimstead/app.py`, `web/src/assets.tsx`, `web/src/findings.tsx`, `web/src/home.tsx`, `web/src/containers.test.tsx`

## T9 Real-host proof
- Acceptance: criteria 1-5 PASS in `sandbox/last_run_workloads.json`, distro destroyed after.
- Files: `sandbox/workloads.py`

## T10 Performance
- Acceptance: criterion 7 recorded in `sandbox/last_run_perf_sqlite_workloads.json`.
- Files: `sandbox/perf.py`

## T11 Docs and versions
- Acceptance: how-to, README limitations, CHANGELOG with Highlights, DECISIONS 155-159, STATUS section; agent 0.9.0, server 0.13.0; `check_docs.py` and `export_api_docs.py --check` pass.
