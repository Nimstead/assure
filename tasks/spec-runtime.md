# Spec: runtime — what is actually running, and fixes that finish (V1)

Status: **written 2026-11-25; the owner set the goal "spec, plan, build, test, review, ship. Next phase. Impress me.
Market leader tool."**, the goal that produced the containers, programme, tickets and workloads phases. Each open
question is answered below with the recommendation and the reason, and the gates between phases are passed on that goal.
Plan: `tasks/plan-runtime.md`. Tasks: `tasks/todo-runtime.md`. DECISIONS from 161. Ships as 0.14.0 with agent 0.10.0.

## Objective

**The gap.** Nimstead says which packages on a Linux machine are vulnerable and which few upgrades clear the most risk.
Two questions every security lead asks next are answered today by guesswork:

1. **Is the vulnerable code actually running, and can the network reach it?** A Debian server carries 600 packages and a
   few hundred findings. Most of that code never runs: man pages, compilers, libraries nothing loads. The handful that
   matter are the libraries a listening service has loaded (the `libssl3` inside nginx on 0.0.0.0:443). Runtime context
   ("in use", "reachable") is how the market leaders cut the list: Wiz, Sysdig, Upwind, Aqua and Prisma Cloud sell it as
   their headline, and each needs a kernel sensor or eBPF DaemonSet to do it. Tenable, Qualys and Rapid7 VM agents don't
   tell you which library a listening process has loaded.
2. **Is a fixed machine actually fixed?** When `apt` replaces `libssl3`, nginx keeps running the old copy until it
   restarts: the vulnerable code is still in memory, serving traffic. Today Nimstead closes the finding as soon as the new
   version is in the inventory, and a fix job on a machine without `needrestart` "succeeds" with the old code still
   running (its health check passes because the service never restarted). Every scanner that judges installed versions
   has this blind spot; it is the difference between "patched" and "fixed".

**Who.** The security lead deciding what to fix this week; the platform engineer who owns the services and needs to know
what to restart; the auditor who asks whether "resolved" means the vulnerable code is gone.

**What sets ours apart** (the promises the rest of Nimstead keeps):
1. **No new sensor.** The agent already on the machine reads `/proc` at each report: which files each running program
   has mapped (its libraries and its executable), which sockets it listens on, and which mapped files have been replaced
   on disk since it started. No kernel module, no eBPF, no extra install, nothing left running between reports.
2. **Said as evidence, never as a verdict.** "Loaded by nginx.service, listening on 0.0.0.0:443" is a fact the agent read
   at a time it states. "Not loaded" is said only after seven days of complete reads, with what a sample can't see
   (programs that run for a moment, like cron jobs and commands) in the same sentence. Runtime changes a finding's rank;
   it never hides one, and known exploitation is never lowered.
3. **A fix counts only when nothing runs the old code.** A finding whose fixed version is installed stays open while a
   program still runs the replaced copy, saying which program to restart; it closes on the report after the restart.
   An automated fix restarts the services that ran the replaced files, then runs its health checks against the new code,
   and rolls back (and restarts them again) if they fail.
4. **Nothing personal leaves the machine.** Command lines and environments can hold secrets; they are used on the
   machine only (to see which script an interpreter runs) and never sent. What is sent: program names (the systemd unit,
   or the process's own short name), the user it runs as, listening addresses, and package names.

### User stories and acceptance
- **S1.** As a security lead, after updating the agent, each finding on a Linux machine says whether its package is
  loaded by a running program, which programs, and whether one of them listens on the network and where. Findings
  filter by **Listening**, **Loaded** and **Not loaded**.
- **S2.** Fix first ranks a network-reachable flaw in a library a listening service has loaded above the same flaw in a
  library nothing loads, says why in words, and each upgrade says "loaded by 4 programs on 3 machines, 2 listening".
- **S3.** As a platform engineer, the machine's drawer lists its listening programs (program, user, addresses) and any
  program still running a replaced copy of a package ("nginx.service runs the copy of libssl3 replaced since it started:
  restart it"). Fix first has a **Restart to finish** list across the fleet.
- **S4.** A finding whose fix is installed but still running in a program stays open with "Still open: the fixed version
  is installed, but nginx.service still runs the copy it replaced: restart it (or the machine)". It closes on the first
  report after the restart, and the evidence pack times it to then.
- **S5.** An automated fix restarts the system services that ran the files it replaced (named in the approval from the
  latest read), checks them with the machine's health units, and rolls back if a restarted service won't come up. A
  program it won't restart (the system manager, D-Bus, the login manager, a user's session) leaves the job waiting for a
  restart, said in words, instead of calling it failed or done.
- **S6.** As a machine's owner, I turn runtime reading off locally (`"runtime": false` in the agent's configuration, or
  `enroll --no-runtime`); the server can't turn it back on. Packages are still read and judged as before.

## Scope

### Module 1 — `runtime-read`: the agent reads what runs (agent 0.10.0, Linux)

At each inventory, as root, one bounded pass over `/proc`:
- **Programs.** Each process in the agent's own mount namespace (container processes are skipped and counted: their
  files belong to their images). Its program is its systemd **system** unit from `/proc/<pid>/cgroup` (cgroup v2 and v1
  `name=systemd`), else its short name from `/proc/<pid>/comm`, sanitised. Processes of one program are one entry (fifty
  php-fpm workers are one `php8.2-fpm.service`). The user is the process's real uid as a name.
- **Loaded files.** `/proc/<pid>/exe` and every file-backed mapping in `/proc/<pid>/maps` (device not `00:`), plus open
  descriptors to Java archives (`.jar`, `.war`), plus the script an interpreter runs (the first absolute path among its
  first three arguments, matched on the machine and never sent).
- **Replaced files.** A mapping or executable whose path ends ` (deleted)` (rpm's `;<hex>` temporary suffix removed) is a
  replaced copy, attributed to the package that owns that path now.
- **Listening.** `/proc/net/tcp`, `tcp6` (state LISTEN) and `udp`, `udp6` (bound, unconnected), each socket's inode
  matched to its process through `/proc/<pid>/fd`. Addresses are kept as read (`0.0.0.0:443/tcp`, `[::1]:5432/tcp`).
- **Packages.** Paths are matched to the installed packages by the package manager's own file lists, streamed, only for
  the paths seen: dpkg's `info/*.list` (architecture suffix dropped), apk's `P:`/`F:`/`R:` lines, rpm's
  `rpm -qa --qf '[%{=NAME}\t%{FILENAMES}\n]'`. Merged `/usr` aliases count both ways. A package is **native** when its
  list has a shared object (`*.so`, `*.so.N`) or an ELF executable in a `bin`, `sbin` or `libexec` folder; only a native
  package can be called "not loaded" (a Python or Perl module is read, not mapped, so the agent can't tell).
- **Budgets** (named constants, the stop said in the same words each time): 4,096 processes, 4 MB of `maps` per
  process, 65,536 descriptors per process, 2,000,000 listed paths, 20 seconds for the pass. A pass that stops at one is
  **partial**: what it saw still counts as seen, and nothing is concluded from what it didn't. A pass not run as root is
  partial ("other users' programs can't be read without root").
- **Report.** A top-level `runtime` object in the inventory: `{"v": 1, "state": "ok"|"partial"|"failed", "problem",
  "programs": [{"name", "unit", "user", "count", "listen": [...], "loads": [package...], "replaced": [package...]}],
  "native": [package...], "other_namespaces": n}`, and a `runtime` line in the collection document. Windows sends none
  (V2). Local opt-out as in S6.

### Module 2 — `runtime-judge`: the server stores, remembers and ranks (API)

- **Storage.** One `asset_runtime` row per host (the latest read, plus what was seen loaded in the last seven days) and a
  `finding.runtime` column (`listening` | `loaded` | `not_loaded` | null) so Findings can filter by it. One migration.
  The body is validated like `neighbours`: what doesn't fit is dropped, never the packages with it.
- **Memory, so a sample doesn't flap.** A package seen loaded stays **loaded** for seven days from the last read that saw
  it, and **listening** for seven days from the last read that saw it loaded by a program listening on a non-loopback
  address. **Not loaded** needs a native package, complete reads covering the last seven days with no gap over 36 hours (a day at first; widened in the build so a missed 6-hourly report or a daily schedule doesn't restart the week, DECISIONS 162),
  and none of them seeing it loaded. Anything else is unknown (null), and so is every package of a host whose latest
  runtime read is over a day old for "not loaded" (loaded and listening keep their seven days).
- **Rank** (`risk.context`, after KEV/EPSS/CVSS as today), for findings on the host's distribution packages:
  - *Listening*, and the flaw's attack vector is network or adjacent or unknown (OSV severity first, then NVD's vector),
    not KEV: **+15**, reason "Loaded by nginx.service, listening on 0.0.0.0:443 (read 25 Nov; the host firewall isn't
    read)". The same +15 Windows listeners get (DECISIONS 72).
  - *Loaded*: reason only ("Loaded by cron.service, which isn't listening on the network").
  - *Not loaded*, the vector is network or adjacent, no KEV, no Microsoft "exploited", no public exploit: **score ×0.75**,
    reason "Not loaded by any long-running program in 7 days of reads (programs that run briefly, like cron jobs, aren't
    seen): lower priority while it stays that way". A local flaw (AV:L, `sudo`, `polkit`) is never lowered: a local user
    runs the program themselves.
  - Kernel packages are left to the engine's running-kernel rule (R7.7) and get no runtime state.
- **Restart to finish.** In the closing pass, a finding no longer matched stays open when the latest read names a
  program running a replaced copy of its package and the installed version is no longer the finding's (upgraded or
  removed): reason "Still open: the fixed version is installed, but nginx.service still runs the copy it replaced:
  restart it (or the machine)". Positive evidence only: a host without a runtime read closes as today.
- **Fix jobs wait for the restart.** `remediate.verify` leaves a job verifying (not `not_fixed`) while every still-open
  finding of it is held only for a restart, and says which programs; it succeeds on the report after the restart.
- **API.** Findings list items carry `runtime`; `?runtime=listening|loaded|not_loaded` filters; the finding detail and
  asset detail carry the programs (names, users, addresses, read time) and replaced copies; `/api/summary` actions carry
  `runtime` (machines loading, machines listening, top programs) and a `restarts` list (program, package, machines);
  the CSV gains `runtime` as its last column. The OpenAPI reference is regenerated.

### Module 3 — `runtime-fix`: automated fixes restart what ran the old code (agent)

- After a Linux fix's package step succeeds and before its health checks, the agent reads `/proc` again for programs
  running replaced copies of **the packages this job changed**, and restarts each that is a systemd system service
  (`systemctl restart`, 120 s), never: `systemd` itself (PID 1), `dbus*`, `systemd-logind`, `systemd-journald`,
  `getty@*`, `user@*`, display managers, `nimstead-*` (the agent's own), and anything not a `.service` in `system.slice`.
  Each restart is a recorded step.
- The restarted services join the job's health units for its checks (active, no restarts since the change). A failure
  rolls back as today and restarts the same services again on the restored version.
- A program left running the old copy (refused above, or no systemd, as on Alpine) is said in the job's steps; the
  server's held-open rule then keeps the job verifying until the machine or program restarts.
- The approval dialog names the services the fix will restart, from the latest read ("Restarts nginx.service and
  php8.2-fpm.service, which ran libssl3 at the last report").

### Module 4 — `runtime-ui` (web)
- **Finding drawer:** a "Running" block in words (listening, loaded, not loaded with its caveat, watching since a date,
  or held for a restart), the programs and addresses, and the read time.
- **Findings:** a Running filter (Listening, Loaded, Not loaded), kept in the URL and saved views like the others.
- **Fix first:** each upgrade says how many machines load it and how many listen; a **Restart to finish** card lists
  programs running replaced copies across the fleet, each linking to its machines.
- **Machine drawer:** "Running" lists listening programs (program, user, addresses) and replaced copies to restart.
- **Approval:** the services a fix will restart.

### Out of scope (deferred, V2 backlog)
- **Containers' runtime** (which image packages a container's processes load): image assets are shared by hosts, so it
  needs a union rule across hosts, and per-package file lists from images (distroless images carry none).
- **Windows loaded modules** (DLLs per process) and Windows "restart to finish": Windows Update's own pending-restart
  state covers most of it today.
- **Linux attack paths** from runtime (a remote flaw in a listening service, then a local escalation): the engine's
  paths builder takes facts, not this read; its own change.
- **Continuous capture** (eBPF or audit) to see programs that run for a moment: a sensor, which promise 1 rules out.
- **The host firewall** (nftables/iptables) as reachability: rules are hard to judge exactly; said in the reason.
- **Interpreted language packages** (which Python or npm modules a process imported): not visible in `/proc`.
- **Restarting programs outside fixes** (a "restart now" button): a new remote action needs its own trust design.

## Tech stack
Unchanged: agent is one Python file (stdlib only, Python 3.9+ on Linux); API Python 3.14, FastAPI, SQLAlchemy, Alembic;
web React 19 + TanStack Router/Query + Tailwind, Vitest, Playwright with axe. No new dependency. Proof tooling (in the
disposable distros only): nginx, PostgreSQL, OpenSSH, `ss`, `lsof`, `needrestart` (Debian), `needs-restarting` (dnf),
each distribution's own `dpkg -S` / `rpm -qf` / `apk info --who-owns` as the oracles.

## Commands
```
API + agent tests:  (cd api && uv run ruff check src tests ../agent ../sandbox ../scripts && PYTHONUTF8=1 uv run pytest -q)
Agent runtime tests on Linux (WSL, root and non-root):  wsl -d Ubuntu -- python3 -m pytest api/tests/test_agent_runtime_read.py
Web:                (cd web && npm test && npx tsc --noEmit && npm run build && npm run e2e)
Docs checks:        (cd api && PYTHONUTF8=1 uv run python ../scripts/check_docs.py && uv run python ../scripts/export_api_docs.py --check)
Real-host proof:    (cd api && uv run python ../sandbox/runtime.py --distro debian|alma|alpine)   # fresh WSL distro each
Performance:        (cd api && uv run python ../sandbox/perf.py --assets 1000 --runtime)
```

## Project structure (what this phase touches)
```
agent/nimstead_agent.py              → runtime read, opt-out, restarts after a fix, AGENT_VERSION 0.10.0
api/src/nimstead/runtime.py          → validate and store a read, the seven-day memory, a package's state (new)
api/src/nimstead/db.py, migrations/  → AssetRuntime, Finding.runtime
api/src/nimstead/risk.py, scan.py    → rank by runtime, hold for a restart
api/src/nimstead/remediate.py        → verify waits for a restart; restarts named in the plan
api/src/nimstead/app.py              → inventory body, findings filter + CSV, finding/asset detail, summary
api/src/nimstead/engine/collection.py → the `runtime` collection line
api/tests/test_agent_runtime_read.py, test_runtime.py (new)
web/src/findings.tsx, home.tsx, assets.tsx, planfix.tsx, remediation.tsx, lib.ts, runtime.test.tsx (new)
sandbox/runtime.py (new), sandbox/perf.py --runtime
docs/how-to, docs/reference, docs/explanation, README.md, CHANGELOG.md, STATUS.md, DECISIONS.md
```

## Code style
Follow the file you are in. The agent's container code is the model for reading `/proc`: a docstring that says what is
refused and why, budgets as named constants with the reason in a trailing comment, parsers with no I/O so they're tested
on recorded text:
```python
RUNTIME_PROCESSES = 4096  # processes read per report; a busy host runs a few hundred

def parse_maps(text):
    """(mapped paths, replaced paths) from /proc/<pid>/maps text: file-backed lines only (device not 00:). No I/O."""
```

## Testing strategy
- **Agent unit tests** (pytest; parsers on recorded `/proc` text from real Debian, Alma and Alpine hosts; the pass on a
  fake `/proc` tree): maps (deleted, rpm suffix, escaped `\012`, anonymous and special lines), cgroup v1/v2 units, net
  tables v4/v6/udp, socket inode matching, file lists for dpkg/apk/rpm with merged `/usr`, native detection, interpreter
  scripts, budgets with stable words, partial as non-root, a process vanishing mid-read, crafted names, and a test that a
  secret in a process's command line and environment never reaches the body. Restart selection: deny list, only the
  job's packages, only system services; rollback restarts again.
- **API tests:** body validation and caps; the seven-day memory (promotion at once, demotion only after seven complete
  days, gaps reset, stale reads); rank changes with each guard (KEV, exploited, public exploit, local vector, kernel);
  held open for a restart and closed after it; a host without runtime unchanged; verify waits and then succeeds;
  findings filter and CSV; summary restarts; a 0.9.0 agent's body judged exactly as before.
- **Web unit tests:** drawer wording per state, filter in the URL, Fix first counts and Restart to finish, machine drawer,
  approval restarts.
- **e2e:** the findings filter and drawer, Fix first's restart card, axe clean at 1440 and 375 in light and dark.
- **Real-host proof** (`sandbox/runtime.py`): see the success criteria.
- **Review:** an independent code review and a security audit; every finding fixed with a test that fails first; a
  mutation check of `runtime.py`, the rank rule and the held-open rule.

## Boundaries
- **Always:** treat everything in `/proc` that a user can choose (process names, file names, cgroup paths) as hostile
  input, bounded and sanitised; send no command line or environment; tests before commits; a test that fails without each
  fix; `check_docs.py` and `export_api_docs.py --check` before pushing; check the branch right before each commit
  (shared checkout).
- **Ask first:** approving the `release` environment gate (the owner's, unless they say "you do it"); anything that costs
  money or touches a machine that isn't disposable.
- **Never:** restart anything outside an approved fix; restart PID 1, D-Bus, the login manager or a user's session; lower
  a known-exploited finding; call a package "not loaded" from a partial read; delete a test that fails.

## Success criteria
1. **Loaded, exactly.** On a fresh disposable Debian 13, AlmaLinux 9 and Alpine 3.21 (WSL) running nginx, PostgreSQL
   (loopback only), OpenSSH and cron, for every program in the host's mount namespace the agent's loaded packages equal
   the oracle's: every file in `/proc/<pid>/maps` and `/proc/<pid>/exe` resolved by the distribution's own `dpkg -S`,
   `rpm -qf` or `apk info --who-owns`. Every difference listed with its reason in the run record; none unexplained.
2. **Listening, exactly.** Each program's listening addresses equal `ss -H -ltnup`'s for the same processes.
3. **Restart to finish, as the distribution's own tool says.** With nginx running, an upgrade of the library it loads
   (`libssl3` from an older to the current version on Debian; `openssl-libs` on Alma) makes the agent name
   `nginx.service` as running a replaced copy, as `needrestart -b` (Debian) and `needs-restarting -s` (Alma) do, and
   lsof's `DEL` lines agree; the upgraded findings stay open with the reason; `systemctl restart nginx` closes them on the
   next report, and the evidence pack verifies.
4. **Rank.** On the same host, a network-vector finding on the library nginx loads (listening on 0.0.0.0) carries the
   listening reason and +15; a network-vector finding on a native package nothing loads, after seven days of complete
   reads (the read history backdated in the harness, said so), is ×0.75 with its reason; a KEV finding is never lowered.
5. **Fixes finish themselves.** An approved fix of that library on a test machine with nginx running restarts
   `nginx.service` after the upgrade, its health check passes on the new code, the job succeeds and its findings close,
   and `needrestart`/`needs-restarting` then report nothing for nginx. A fix whose restarted service fails to start (a
   broken config planted) rolls back and the service runs again on the restored version. A fix whose replaced library is
   also held by a refused program (`dbus`) leaves the job waiting for a restart, and a reboot finishes it.
6. **Hostile input stays inert.** Programs with crafted names (newline, right-to-left override, 15-byte comm, a unit
   path from a user cgroup), a file named with ` (deleted)` and a newline in it, 2,000 extra processes and 60,000 open
   descriptors (budget said in stable words), a process exiting mid-read: none breaks the report, and a secret placed in a
   process's command line and environment is absent from the body sent.
7. **Cost.** The pass takes under 3 s on a host with 500 processes; at 1,000 hosts (`perf.py --runtime`) a report's
   median and the hourly re-match stay within 20% of 0.13.0's on the same machine.
8. **Suites.** API, agent (Linux, root and non-root), web unit, `tsc`, build and e2e green; CI green including PostgreSQL
   17; docs checks pass.

## Open questions (answered on the goal, with the reasons)
1. *Should "not loaded" lower a finding at all?* Yes, modestly (×0.75) and only for network flaws with no sign of
   exploitation: a network flaw needs a running program to reach it, and this is the noise cut the market pays for. Never
   a hide, never for local flaws, never from partial reads.
2. *Hold findings open until a restart, or open a separate "restart" finding?* Hold: a separate finding would let the CVE
   read "resolved" while the vulnerable code runs, which is the untruth this phase removes. The evidence pack and Progress
   then time the fix to when the code stopped running.
3. *Should automated fixes restart services?* Yes, the services that ran the replaced files, inside the job's existing
   health checks and rollback, named in the approval. Without it every library fix on Debian and RHEL would wait on a
   person, and the health check would keep passing against old code.
4. *Seven days?* Hosts report every six hours: 28 reads, enough for weekly batch services that run for hours, and the
   same window the programme view uses for "this week". Short-lived programs are never seen at any window, said in the
   reason.
5. *Migration?* One (table + column): runtime is per host and too big for `facts`' limits, and Findings needs to filter
   on it in SQL.
</content>
</invoke>
