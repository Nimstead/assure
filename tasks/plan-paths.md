# Implementation plan: paths — from the network to root to the next Linux machine

Source spec: `tasks/spec-paths.md` (approved 2026-11-26). Tasks: `tasks/todo-paths.md`. DECISIONS from 165. Release
0.15.0, agent 0.11.0. Written on `/agent-skills:plan`; the owner set the goal "build, test, review" on it (approval). `tasks/plan.md` and `tasks/todo.md` still hold unchecked tasks from
Windows round 1, so this plan follows the project's per-phase files, as every phase since containers has.

## Overview

The agent gains a second bounded pass at each Linux inventory, `access_read`. It reads:
- sshd's effective configuration
- the accounts that matter and their root-equivalent groups and `sudo` rights
- files root runs that someone else can write
- the private keys held and the public keys trusted, as fingerprints
- which credential files exist

It sends all of that as a top-level `access` object. It also sends its own addresses and private-range peers in `facts`,
as Windows does.

The server stores the latest read in an `asset_access` row and turns six settings into `LinuxConfig` findings. The engine
builds Linux attack paths from verdicts, the runtime memory (which program listens, as which user) and the access read.
The fleet view links machines by exact key matches and ranks choke points.

## Architecture decisions

- **`access` is its own object and table, not `facts`.**
  - `facts_ok` caps facts at 64 KB, 500-item lists and depth 4, and the assets list loads `Asset.facts` for every row.
  - Key lists can be tens of KB per host, so they live in `asset_access`, the same choice `asset_runtime` made. It is read
    only by that host's rescan and report, its drawer, and `/api/attack-paths`.
  - Addresses and peers stay in `facts`, so `fleet._routed` works unchanged for both systems.
- **Parsers split from I/O, as in the runtime read.**
  - The parsers take text: `parse_sshd_t`, `parse_private_key` (header to public blob, fingerprint, passphrase or not),
    `parse_authorized_keys`, `parse_sudo_l`, `parse_group`, and the writable-path rule.
  - They are tested on fixtures recorded from Debian 13, AlmaLinux 9 and Alpine 3.21 (T0).
  - `access_read(root="/", run=..., euid=...)` takes its root and command runner as arguments, so tests run it on a fake tree.
- **Fingerprints are computed on the machine.**
  - SHA-256 of the public-key blob, base64 without padding, exactly as `ssh-keygen -lf` prints it, so the oracle compares
    strings.
  - The private part of an OpenSSH key is never decoded: the public blob sits before it in the header.
  - A PEM key is identified only through a `.pub` beside it that parses; otherwise it is counted as "not identified".
- **Hostile homes.**
  - Every file under a home is opened with `O_NOFOLLOW | O_NONBLOCK`, then `fstat`. It must be a regular file, owned by the
    account or root, and only its byte cap is read.
  - Directories are walked one level deep, never recursively.
  - A file that fails a check is named in the problems with stable words, never read.
- **Accounts that matter**, without enumerating a directory server:
  - local `passwd` entries with a login shell, plus root
  - the users of programs running now (uid to name through `getent`)
  - the owners of the folders under `/home`

  That covers directory users who have homes, and avoids `getent passwd` against LDAP.
- **`sudo -n -l -U <account>`**:
  - limited to accounts in a sudo-capable group, accounts running a listening program, and accounts with homes; at most 32,
    with 3 s each inside the 10 s budget
  - `-n` means it never waits for a password
  - only `NOPASSWD: ALL` counts
  - skipped entirely when `sudo` is absent, said in the collection line
- **The engine stays pure.**
  - `Inventory` gains an optional `context` with two parts:
    - `listening`: package to a list of {program, user, address}, from `runtime.state` memory
    - `access`: the latest access read
  - `engine.judge` and `asset_report` fill it from `asset_runtime` and `asset_access`.
  - `to_doc` carries it, so a stored record still explains its report.
  - Windows inventories get an empty context, and their documents and report hashes stay byte-identical.
- **The host report says what a path gives.** Each Linux path gains `reaches`: `"root"`, or the way-in user's name.
  `fleet.build` uses it to decide whether A's held keys are in the attacker's hands: root takes all of them, a user only
  their own.
- **Key edges sit beside Windows edges in `fleet.build`.**
  - The endpoint loads `asset_access` for the organisation's Linux hosts in one query.
  - Trusted keys are indexed by fingerprint, so finding B for each held key is a dictionary lookup, never a scan of every
    pair.
  - Key edges count toward `MAX_EDGES`.
- **Choke points are a pure function of the built graph** (`fleet.choke_points`).
  - Candidates: each start's way in, each key fingerprint (retire it), each key line on one target, each Windows edge's
    setting on its target. Capped at 200, the ones on the most edges first.
  - Each candidate is scored by one breadth-first walk with its edges removed. 200 × 2,000 edges is 400,000 edge visits,
    tens of milliseconds.
  - Tested against a brute-force recount on random small graphs.
- **`from=` matching follows sshd's own rules** (`match_hostname`/`addr_match_list`): CIDR, `*` and `?` wildcards, `!`
  negation, first match wins, against A's own addresses. Host names in `from=` can't be resolved without a probe, so a line
  that only names hosts grades *unverified*, with the reason given.

## Dependency graph
```
T0 spike: the lab runs (systemd containers, bridge, sshd, ssh between them); fixtures from 3 distros
 ├─→ T1 agent parsers ─→ T2 agent pass + body + opt-out ─────────────────────────────┐
 └─→ T3 server table + store ─→ T4 linconfig findings                                  │
                     └─→ T5 engine context + Linux host paths ─→ T6 key edges ─→ T7 choke points ─→ T8 UI
                                                                                        └──────────┴─→ T9 real proof
T10 perf (after T7) ── T11 docs, versions ── T12 review (code + security) + fixes + mutation ── T13 ship
```
T1–T2 (agent) and T3–T4 (server) can be built in parallel once T0 fixes the `access` body's shape, which T0 writes down as
a JSON example in the todo. T8 waits for T5–T7's API shapes.

## Task list

### Phase 1: the riskiest part first (the lab, then the agent's read)
- [ ] T0 Spike: the four-machine lab runs in a disposable WSL distro; real `ssh` between machines; fixtures and the body shape
- [ ] T1 Agent parsers: `sshd -T`, key headers and fingerprints, `authorized_keys` options, groups, `sudo -l`, writable rule
- [ ] T2 Agent pass: accounts, keys, writable files, credentials, peers; budgets; hostile files; secrets never sent; opt-out; 0.11.0

### Checkpoint A
- Agent suites green on Linux as root and non-root.
- Every fixture's fingerprints equal `ssh-keygen -lf`.

### Phase 2: the server
- [ ] T3 `AssetAccess` + migration; `access.py` validate, cap and store; inventory body; a 0.10.0 body judged exactly as before
- [ ] T4 `linconfig.py`: six checks as `LinuxConfig` findings, unproven when unread, closing on a complete read

### Checkpoint B
- API suite green on SQLite and PostgreSQL 17.
- No finding change on stored Windows or 0.10.0 Linux inventories.

### Phase 3: paths
- [ ] T5 Engine context; Linux host paths (way-in user, root listener, settings for the user they help, credentials, `reaches`)
- [ ] T6 Key edges in `fleet.build` (grading, `from=`, Allow/Deny, root login, what B hands over), chains across both systems
- [ ] T7 Choke points in `fleet.choke_points` and `/api/attack-paths`; OpenAPI regenerated

### Checkpoint C
- API suite green.
- Windows host and fleet paths byte-identical on the stored German Windows 10 inventory and the existing tests.

### Phase 4: UI, proof, scale, docs
- [ ] T8 UI: Linux paths in the machine drawer, key edges in words, Choke points card, `LinuxConfig` findings; unit + e2e + axe
- [ ] T9 Real proof `sandbox/paths_lab.py`, success criteria 1–6, record `sandbox/last_run_paths.json`
- [ ] T10 `perf.py --paths`, criterion 7, record `sandbox/last_run_perf_sqlite_paths.json`
- [ ] T11 Docs (design-paths, how-to, reference, explanation), README, CHANGELOG with Highlights, DECISIONS, STATUS, versions

### Checkpoint D: complete
- Every success criterion met, with its run record.
- All suites, `tsc`, build and e2e green.
- Docs checks pass.

### Phase 5: review and ship
- [ ] T12 Independent code review and security audit; each finding fixed with a test that fails first; mutation check
- [ ] T13 Ship 0.15.0:
  - PR, CI green, squash-merge, tag
  - release gate (the owner's), then verify the release
  - STATUS line
  - website PR (merged only on the owner's word)
  - new docs pages added to nimstead-docs' `pages.json` (asking first)

## Risks and mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| systemd containers don't run under Podman in WSL (cgroup v2 delegation) | High: the lab is the proof | T0 first. Fallback: three disposable WSL distros with sshd on distinct ports; "seen connected" then untestable, said in the record (spec open question 5) |
| `sshd -T` fails without host keys, or with a broken config | Medium | Failed read: `sshd` is `null`, so its checks and edges stay unread, never "off". The harness plants a broken config once |
| `sudo -l` hangs on PAM or LDAP | Medium | `-n`, a 3 s timeout each, inside the pass budget; a timeout is named and leaves that account's `sudo` unread |
| A user plants a link or FIFO to make the agent read or claim root's key | High (false edge, or a hang) | `O_NOFOLLOW` and `O_NONBLOCK`, regular files only, owner check; a hostile-file test for each, and in the lab |
| Key lists too big for the body or the fleet read | Medium | Per-host caps (16 files per account, 1,000 trusted per account, 5,000 trusted per host); fingerprints indexed; `perf.py --paths` at 1,000 hosts |
| The engine context changes Linux report hashes | Low | It changes once, on the first report after upgrade, and is said in the CHANGELOG. Windows unchanged, by test |
| Choke points mislead when the graph was cut at `MAX_EDGES` | Medium | When `truncated`, choke points say their counts are a lower bound |
| `from=` with host names can't be judged without DNS | Low | Graded *unverified* with the reason; never resolved (DECISIONS 27) |

## Open questions
None blocking. The spec's five were answered with its recommendations when the owner moved to planning. The design
change found in planning (an `access` object and table instead of `facts`) is recorded in the spec.
