# Plan: containers

Spec: `tasks/spec-containers.md` (objective, stories, success criteria, answered questions). Tasks:
`tasks/todo-containers.md`. Follows network services (`plan-network.md`, 0.9.0). DECISIONS 138-142 land with the tasks
that need them. Release as **0.10.0** (agent **0.8.0**, one migration).

## Overview
Two ways in, one judge. (1) The agent on a Linux host lists its running Docker and Podman containers and reads each
one's os-release and package database through the container's own root, never leaving it, never running anything from
it. The server turns each distinct image into an `image` asset and judges it with the engine's existing Linux path, so
a container's findings are exactly as correct (and as honest about coverage) as a host's. (2) An image SBOM's OS
packages map to the distro's ecosystem and are judged the same way, at SBOM grade.

## Architecture decisions
- **Read containers on the host, by default, through the runtimes' own CLIs (DECISIONS 138).** `docker|podman ps -q
  --no-trunc` then `inspect`: id, name, PID, image id, image reference. Read-only commands; the agent never opens a
  socket itself. A host with `crictl` and no other runtime says Kubernetes containers aren't read yet. On by default
  (S7's local opt-out `enroll --no-containers`); the server can't turn it on or name a container.
- **A container's root is read like hostile input (DECISIONS 138).** Paths are resolved component by component from an
  fd for `/proc/<pid>/root` with `O_NOFOLLOW`; a symlink is resolved inside that root (absolute ones from its top, `..`
  stops at its top, 8 hops at most), only regular files are opened (`O_NONBLOCK`, then `fstat`), each read is capped
  (64 MB), the whole pass has a time budget (120 s) and a container cap (128). The PID's mount namespace is read before
  and after: it must differ from the agent's own and must not change, or the read is discarded (PID reuse). No binary
  from the container runs: rpm's SQLite database is read with the standard library's `sqlite3` from a private copy and
  its header blobs parsed in Python; Berkeley DB and ndb are reported as not read.
- **A separate endpoint, after the inventory.** `POST /api/agent/containers` carries the images; a refusal or a 413
  there never costs the host's own inventory, and an older server's 404 is quietly ignored.
- **An image is a content-addressed asset (DECISIONS 139).** Key: SHA-256 of (runtime image id, ecosystem, sorted
  package rows), computed by the server from what arrived. Honest hosts running one image converge on one asset; a
  compromised host can only add an asset, never change or close one another host's report made. The key's hash sits in
  `agent_key_hash` (unique, never handed out: `current_agent` refuses any asset that isn't a host), so no new column.
  `kind="image"`, `hostname` = newest reference, `facts` = {image_id, refs}, `collection` = the image's own document,
  `last_inventory_at` = when its content was first stored (immutable), `last_seen` = last reported running. Outside the
  asset quota, with its own cap (`NIMSTEAD_MAX_IMAGES_PER_ORG`, 2,000). Its criticality and internet exposure are the
  worst of the hosts that run it, refreshed on each report, so a finding ranks by where it runs.
- **Where an image runs is a table.** `container` (host asset id, container id) → image asset id, name, runtime, first
  and last seen; cascades from both. A complete list from a host replaces that host's rows; a partial one only adds and
  refreshes.
- **Close only on evidence (DECISIONS 140).** `rescan` on an image with no container rows resolves its open findings with
  "Not running on any host: every host that ran it has since reported its containers without it". Rows go only when
  their host's complete list leaves them out, so silence never closes anything. Deleting a host deletes the images only
  it ran (as device views go with their host). An image not running for 30 days is deleted in the hourly clean-up; its
  findings were already resolved, and the ledger keeps everything.
- **Images are never remediated (DECISIONS 141).** `remediate.plan` refuses any asset that isn't a host (shared code,
  so the single, batch and auto paths all refuse). Fix first's `top_actions` count hosts only; a new `images_to_rebuild`
  lists images by their worst finding with the fixed versions the rebuild must bring.
- **Image SBOMs (DECISIONS 142).** `pkg:deb`, `pkg:apk` and `pkg:rpm` map to the ecosystem named by the `distro`
  qualifier (only the distros the agent maps); the source package comes from Syft's `upstream` qualifier or Trivy's
  `SrcName`/`SrcVersion` properties, else the binary's own name. One SBOM, one distro: the most common, others counted
  as skipped. Distro rows are accepted only on application assets (a host's agent reads its own). The engine judges an
  application with a distro through its Linux path, with the SBOM as the package list (grade unverified) and the
  base OS's end of support.
- **Reuse, don't add.** The engine, `rescan`, the ledger, `ScanRecord` reports, the devices pattern (per-entity assets
  outside the quota, pruned after 30 days) and the Assets page's view switcher. No new dependency.

## Dependency graph
```
C1 safe root reader + parsers ──► C2 discovery + agent report ─────────────┐
C3 container table ──► C4 store endpoint ──► C5 evidence closing ──► C6 API ├─► C7 Assets UI ──► C8 Findings + Home UI
C9 SBOM OS purls ──► C10 engine: application with a distro                  │
                                                     C11 real-host proof ◄──┘ (needs C2, C5, C10)
                                                     C12 performance (needs C5) · C13 docs and release notes (last)
```
C1-C2 (agent) and C3-C6 (server) are independent until C11; C9-C10 are independent of both.

## Risks and mitigations
| Risk | Impact | Mitigation |
|---|---|---|
| A hostile container steers the root reader (symlink, FIFO, device, huge file, PID reuse) | High | fd-relative resolution with `O_NOFOLLOW`, regular files only, size and time caps, namespace check before and after; a sandbox test for each, plus real hostile containers in C11 |
| Real images' databases differ from fixtures (distroless `status.d`, rpm SQLite blobs) | High | Parsers built against files taken from real images in the disposable distro before C2 is done; C11 compares counts with each container's own package manager |
| Findings flap for short-lived containers (cron jobs) | Medium | Documented limit: a container counts while it runs at report time; a reopen is a regression in the ledger, as on hosts |
| A big fleet's containers cost the hourly re-match | Medium | One asset per image, not per container; C12 measures it at 1,000 hosts |
| Two hosts report one new image at once (PostgreSQL) | Medium | The unique key hash makes the second insert fail; it retries as an update; a Postgres-only test |
| The 10 MB body cap | Low | The agent stops adding images at 8 MB and marks the report partial; a separate endpoint keeps the inventory safe |

## Verification checkpoints
- **After C2:** agent tests green on Windows (POSIX ones skipped) and in WSL; `collect` against real Docker containers
  in the disposable distro lists each image with the right package count.
- **After C6:** full API suite on SQLite and PostgreSQL 17; ruff clean.
- **After C8:** web unit + e2e, axe clean in both themes at 1440 and 375.
- **After C11:** every spec success criterion has a PASS line in `last_run_containers.json`.

## Not doing
As in the spec: Kubernetes/CRI, rootless containers, stopped containers and images at rest, registries, language
packages inside containers, rpm Berkeley DB and ndb, Windows containers.
