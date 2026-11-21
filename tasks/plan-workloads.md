# Implementation plan: workloads — Kubernetes nodes and the applications inside container images

Source spec: `tasks/spec-workloads.md`. Tasks: `tasks/todo-workloads.md`. DECISIONS from 155. Release 0.13.0, agent 0.9.0.

## Overview
The agent already reads a running container's OS packages through `/proc/<pid>/root` as hostile input
(`ContainerRoot`, DECISIONS 138) and already reads Python, npm and Java metadata on hosts (opt-in, DECISIONS 92, T35).
This phase joins the two: one bounded descriptor walk of each image's root finds Python, npm, Java and (new) Go packages
with the host scans' own parsers, and `crictl` adds Kubernetes nodes as a third listing beside `docker` and `podman`.
The server stores application rows on the image asset with their own ecosystems; the engine already judges agent
application rows (`AGENT_APPS`, `app_installs`), so it gains one source (`go_modules`) and nothing else.

## Architecture decisions
- **The walk lives on `ContainerRoot`.** `walk()` yields (path, name, kind, open-callable) from directory descriptors,
  never following a link, never entering another mount (mount id per directory, as `_resolve` checks), opening a file
  only through its checked `O_PATH` descriptor. Readers never see a path they could re-resolve on the host.
- **Parsers split from I/O.** `_dist_meta`, `_package_json` and `_poms` get byte/zip-level cores that the host scan and
  the container walk both call, so a package reads alike in both places (DECISIONS 92's rules, one copy).
- **Owned files come from the image's own package manager** (dpkg `info/*.list`, apk `F:`/`R:`, rpm trees), read
  through the same root, kept as a set of paths.
- **One walk per image key** (image id + OS read) inside `containers()`; apps join the image entry and its key.
- **Go build info without a Go toolchain:** parse ELF64/ELF32 section headers to find `.go.buildinfo`, read at most
  64 KB from it, accept the Go 1.18+ inline format only.
- **`crictl` is a runtime like the others** with its own listing function (`list_cri`), because its JSON differs; the
  runtime key is `crictl version`'s RuntimeName (`containerd`, `cri-o`).
- **Server:** `containers.image()` validates `apps` (ecosystem in PyPI/npm/Maven/Go, sizes as host rows, 20,000 per
  image); `RUNTIMES` gains `containerd` and `cri-o`. No migration: `installed_package` already carries ecosystem and
  source, `container.runtime` is a 20-char string (checked in T6).

## Dependency graph
```
T0 spike: disposable Debian 13 + Docker + k3s, record crictl output ──┐
T1 walker ─→ T2 py/npm/java readers ─→ T4 wire into containers() ─────┼─→ T9 real-host proof
            T3 Go build info ─────────↗                               │
T5 server apps + engine go_modules ───────────────────────────────────┤
T6 server CRI runtimes ─→ T7 agent crictl (uses T0's recording) ──────┘
T8 UI (needs T5's API fields) ── T10 perf ── T11 docs/versions ── review ── ship
```

## Task list
### Phase 1 — risk first
- [ ] T0 Spike: k3s in a disposable WSL Debian 13; record `crictl ps/inspect/version` JSON as test fixtures
- [ ] T1 `ContainerRoot.walk()` with budgets and every hostile case
### Checkpoint A: walker tests pass on Linux as non-root; k3s works or the plan changes
### Phase 2 — application packages end to end
- [ ] T2 Python, npm, Java readers on the walk + owned exclusion
- [ ] T3 Go build info reader (+ stdlib)
- [ ] T4 Wire into `containers()`: one walk per image, apps, lines, budgets, opt-out
- [ ] T5 Server: image apps stored and judged; engine `go_modules`
### Checkpoint B: API + agent suites green; an image body with apps opens the right findings
### Phase 3 — Kubernetes
- [ ] T6 Server: `containerd`, `cri-o` runtimes and listing proof
- [ ] T7 Agent: `crictl` listing, names, runtime, proof
### Checkpoint C: agent + API suites green
### Phase 4 — UI, proof, scale, docs
- [ ] T8 UI: drawer "What was read", locations in findings and Fix first
- [ ] T9 `sandbox/workloads.py` real-host proof (criteria 1-5)
- [ ] T10 `perf.py --apps` (criterion 7)
- [ ] T11 Docs, DECISIONS 155-159, CHANGELOG, STATUS, versions
### Checkpoint D: every success criterion has evidence; then review (code + security), fixes with failing tests, ship

## Risks and mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| k3s won't run in WSL (no systemd, cgroup v2 quirks) | High: no Kubernetes proof | T0 first; fall back to `k3s server` in the foreground with `--snapshotter native`; last resort a Hyper-V Linux VM via the existing VM tooling |
| `crictl inspect` JSON differs between versions/runtimes | Med | Fixtures recorded from the real node; parse defensively (image id from `status.image.image` or `status.imageId`, else `info.config.image`); unknown shape = a problem line, not a crash |
| Walk cost on big images (node_modules with 100k files) | Med | Entry and time budgets per image, one walk per image, measured on the proof host |
| Base-image packages double-reported | High (noise) | Owned sets from the image's own package manager; criterion 3 tests it on real Debian and Alpine images |
| Zip bombs / huge jars in a root process | High | Declared-size caps (as host scan), zip read through the descriptor, nested ≤ 50 MB, hostile tests incl. lying headers |
| Old server receives new body | Low | Unknown keys ignored by 0.12 (`image()` picks keys); new collection lines only mark app lines partial there |

## Parallelisation
T3 (Go) and T5/T6 (server) are independent of T1/T2 and of each other; done in this session in order, since each is
small and they share the test run.
