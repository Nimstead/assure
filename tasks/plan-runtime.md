# Implementation plan: runtime — what is actually running, and fixes that finish

Source spec: `tasks/spec-runtime.md`. Tasks: `tasks/todo-runtime.md`. DECISIONS from 161. Release 0.14.0, agent 0.10.0.

## Overview
The agent gains one bounded pass over `/proc` at each inventory (`runtime_read`): programs in the host's mount namespace,
the files they map, the files they map that were replaced on disk, and the sockets they listen on, matched to installed
packages through the package manager's own file lists. It rides in the inventory body as a top-level `runtime` object, so
every path that already sends an inventory (the 6-hourly report and the report after a fix) carries it. The server keeps
the latest read plus seven days of "seen loaded" per package in one `asset_runtime` row, derives each finding's
`runtime` state in `rescan`, adjusts rank in `risk.context`, holds a no-longer-matched finding open while a program runs
the replaced copy of its package, and lets `remediate.verify` wait for that restart. Automated Linux fixes restart the
system services that ran the files they replaced, inside the existing health checks and rollback.

## Architecture decisions
- **Parsers split from I/O.** `parse_maps`, `parse_cgroup_unit`, `parse_net` and the file-list readers take text or line
  iterators and are tested on text recorded from real Debian 13, AlmaLinux 9 and Alpine 3.21 hosts (T0). The pass
  (`runtime_read(proc="/proc", ...)`) takes its roots as arguments, so tests run it on a fake `/proc` tree as non-root.
- **Paths of interest first, then the lists.** The pass gathers the (few thousand) paths programs map, then streams each
  file list once, keeping only those paths and noting which packages are native. The full path index (hundreds of
  thousands of paths) is never held in memory.
- **Program = systemd system unit, else comm.** Stable across reports (no PIDs, no command lines), so the server's
  memory keys don't churn; processes of one program merge.
- **Inside the inventory body, not a separate POST.** The fix-verification report already posts `inventory(cfg)`;
  putting runtime there means the held-open rule sees the post-fix read in the same request that verifies the job. Older
  servers ignore the unknown key (pydantic's default).
- **Server memory in its own table.** `asset_runtime` (one row per host: latest read + `seen` map + `since`), loaded only
  by that host's rescan, its drawer and the summary's restart list; the assets list never reads it. `finding.runtime`
  is a plain column so the filter is SQL.
- **The rank rule lives in `risk.context`** beside Windows' listening rule, with the vector from the OSV record or NVD's
  stored vector (`Cvss.vector`), so the same guards (KEV, exploited, public exploit) apply in one place.
- **Held open is positive evidence only**, in the same closing loop as phase 4's `_held_open`, before it: a host with no
  runtime read behaves exactly as 0.13.0.
- **Restarts after a fix come from a second `/proc` read restricted to the job's packages**, not from the server's
  copy, so a stale server view can't name a unit to restart; the server's copy only feeds the approval text.

## Dependency graph
```
T0 spike: record /proc from Debian, Alma, Alpine (WSL, systemd on) ──┐
T1 agent parsers ─→ T2 agent pass + body + opt-out ──────────────────┼─→ T6 agent restarts after a fix ─┐
T3 server table + store + memory ─→ T4 rank + state + held open ─→ T5 verify + API ─┘                   ├─→ T8 proof
                                                                     └─→ T7 UI ─────────────────────────┘
T9 perf (needs T3-T5) ── T10 docs/versions ── review (code + security) ── fixes ── mutation check ── ship
```

## Task list
### Phase 1 — risk first (the agent's read)
- [ ] T0 Spike: real `/proc` text from three distros as fixtures; WSL systemd units visible in cgroups
- [ ] T1 Agent parsers: maps, cgroup unit, net tables, socket inodes, file lists (dpkg/apk/rpm), native
- [ ] T2 Agent pass: budgets, grouping, partial as non-root, secrets never sent, opt-out, collection line, version
### Checkpoint A: agent parsers and pass green on Linux as root and non-root; fixture-based results match the spike's oracle
### Phase 2 — server
- [ ] T3 `AssetRuntime` + `Finding.runtime` + migration; `runtime.py` validate/store/remember/state
- [ ] T4 Rank in `risk.context`; `finding.runtime`; held open for a restart in `rescan`
- [ ] T5 `verify` waits; API: inventory body, findings filter/item/CSV, finding + asset runtime, summary restarts; OpenAPI
### Checkpoint B: API + agent suites green; a 0.9.0 body judged exactly as before
### Phase 3 — fixes that finish
- [ ] T6 Agent restarts services that ran replaced files of the job's packages; health + rollback; plan names restarts
### Phase 4 — UI, proof, scale, docs
- [ ] T7 UI: finding drawer, Running filter, Fix first counts + Restart to finish, machine drawer, approval restarts
- [ ] T8 `sandbox/runtime.py` real-host proof (criteria 1-6) on Debian 13, AlmaLinux 9, Alpine 3.21
- [ ] T9 `perf.py --runtime` (criterion 7)
- [ ] T10 Docs, DECISIONS 161+, CHANGELOG, README, STATUS, versions
### Checkpoint D: every success criterion has evidence; then review (code + security), fixes with failing tests, mutation check, ship

## Risks and mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| WSL distros without systemd give no units, so restarts can't be proven | High | T0 turns on `systemd=true` in `/etc/wsl.conf` (the agent schedule proof ran on real systemd 257 in WSL); Alpine proves the no-systemd path |
| `/proc/<pid>/maps` path forms (usrmerge, rpm `;hex`, `(deleted)`, escaped newlines) mis-attributed | High: wrong "loaded"/"replaced" | Recorded text from three distros; criterion 1 compares every program with `dpkg -S`/`rpm -qf`/`apk info --who-owns` |
| A sample says "not loaded" for code that runs briefly | High: a real risk lowered | Seven days of complete reads, network-vector only, never KEV/exploited/public exploit, never local flaws; said in the reason |
| Priority flapping (fix-now alerts, tickets) as programs come and go | Med | Seven-day memory: promotion at once, demotion only after a week; summary counts read the same memory |
| Restarting a service breaks it | High | Only services that ran replaced files of the job's packages, deny list, health checks on the restarted units, rollback restarts again; proven with a planted broken config (criterion 5) |
| Agent pass cost on busy hosts | Med | Budgets (processes, maps bytes, fds, paths, 20 s), measured on the proof host with 2,000 extra processes |
| Secrets in command lines | High (privacy) | Command lines read only to match a script path on the machine; a test and the real run grep the sent body for a planted secret |
| Old server receives the new body | Low | Unknown top-level key ignored; the new collection line is accepted or the document dropped as today (checked in T5) |

## Parallelisation
T1/T2 (agent) and T3/T4 (server) touch different files and could run in parallel; done here in order because each is
small and they share one test run and the spike's fixtures.
