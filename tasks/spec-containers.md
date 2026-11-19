# Spec: containers — find what's vulnerable inside them

Status: **written 2026-11-19; the owner set the goal "next phase, market leader tool" and said to be autonomous and make
the best call each time**, so each open question below is answered with the recommendation and the reason. Plan:
`tasks/plan-containers.md`. Tasks: `tasks/todo-containers.md`. DECISIONS from 138.

## Objective

**The gap.** The agent reports a Docker host's own packages and nothing inside its containers. A host running five
containers built on an end-of-life Debian reads as clean, which is the worst answer a scanner can give. In CI, an image
SBOM from Syft or Trivy is mostly OS packages (`pkg:deb`, `pkg:apk`, `pkg:rpm`), and today every one of them is counted
as "a package URL no advisory feed covers" (honest, but blind). Every tool a buyer compares us with (Qualys, Tenable,
Rapid7, Microsoft Defender for Cloud, Wiz, Trivy, Grype) covers running containers and image SBOMs.

**Who.** Ops and security teams with the agent on Linux hosts that run Docker or Podman, and teams that scan images in CI.

**What sets ours apart** (the same promises the rest of Nimstead keeps):
1. **No new moving part.** The agent already on the host reads its containers. No sensor container, no privileged
   DaemonSet, no Docker socket handed to anyone; the server never talks to a container runtime.
2. **Distro-correct matching.** A container's packages are judged by the engine exactly as a host's are: source
   packages, backports, each distro's own fixes, end of support. A distroless image is read too.
3. **Says how sure it is, and never calls an unread container clean.** No package database, an rpm format we don't
   read, a container that exited mid-read: the image is listed as not assessed, with the reason.
4. **One image, one set of findings.** Fifty replicas of one image on twenty hosts are one image with its findings
   once, and the list of where it runs. Fix it once (rebuild), see it closed everywhere it's gone.
5. **Closes only on evidence.** An image's findings close when every host that ran it has since sent a complete
   container list without it. A host that goes silent proves nothing (R4.6).

### User stories and acceptance
- **S1.** With the agent on a Docker or Podman host, I see each image running there (name, base OS, packages) and its
  vulnerabilities, ranked like every other finding, after the next report and with nothing else installed.
- **S2.** I see which hosts and containers run each image. An image's risk takes the most critical and most exposed
  host it runs on.
- **S3.** When I rebuild and redeploy, the old image's findings close at the next report that proves it isn't running,
  and the new image shows what's left.
- **S4.** A container that can't be read says why ("no package database", "rpm Berkeley DB format isn't read yet",
  "exited before it was read") and is never shown as clean.
- **S5.** An image SBOM from Syft or Trivy (CycloneDX or SPDX JSON) has its OS packages matched with the distro's own
  rules, graded as SBOM evidence (unverified), with the base OS's end of support.
- **S6.** Nimstead never plans a fix on an image: it says which packages the rebuild must bring and to rebuild and
  redeploy. Fix first lists images to rebuild apart from fixes it can plan.
- **S7.** I can turn container reading off on a host, locally, and the server can't turn it back on.

### Answered open questions (owner: "be autonomous, best decision each time")
| Question | Answer | Why |
|---|---|---|
| On by default, or opt-in? | **On by default**, local opt-out `enroll --no-containers` | A container's package list is the same class of data as the host's, read from the same fixed files (DECISIONS 7's closed list grows by the container roots, nothing the server names). Opt-in would leave most Docker hosts blind, which is the gap we're closing. |
| Runtimes | **Docker and Podman** (rootful) through their own CLIs (`ps`, `inspect`) | Both read-only commands, both provable here for real. |
| Kubernetes nodes (containerd, CRI-O) | **Not this phase**; a host with `crictl` says so in its container coverage | Can't be proven in this sandbox; an unproven parser is a quiet false negative. |
| Stopped containers, images at rest | **Not this phase** | Their files aren't mounted; reading runtime storage directly is per-driver and fragile. Running containers are what's exposed; CI SBOMs cover images before they run. |
| Language packages inside containers | **Not this phase**; the image's report says they weren't read | The host app scanner follows paths; a container root needs a walker that can't be steered out of it. CI SBOMs cover application dependencies today. |
| rpm databases | **SQLite** (`rpmdb.sqlite`: RHEL/Alma/Rocky 9+, Fedora) read in pure Python; Berkeley DB and ndb reported as not read | Running the host's `rpm` on a container's database would hand a hostile container a memory-corruption bug in a root process. |
| Remediation on images | **Never** | Images are immutable; the fix is a rebuild in the customer's pipeline. |

## Tech stack
Unchanged: Python 3.14 (FastAPI, SQLAlchemy, Alembic) server; the agent stays one standard-library Python file; React +
TanStack web; PostgreSQL 17 / SQLite. **No new dependency** anywhere.

## Commands
```
API tests:      cd api && uv run pytest -q
Lint:           cd api && uv run ruff check src tests ../agent ../sandbox ../scripts
PostgreSQL:     cd api && uv run python ../sandbox/pg.py
Web:            cd web && npm test && npm run build && npm run e2e
Real host:      cd api && uv run python ../sandbox/containers.py        (disposable WSL Debian 13, Docker + Podman)
Performance:    cd api && uv run python ../sandbox/perf.py --assets 1000 --containers 10
```

## Project structure (what's new)
```
agent/nimstead_agent.py           container discovery, safe container-root reader, dpkg-status / rpm-sqlite parsers
api/src/nimstead/containers.py    store a host's container report: image assets, where they run, evidence closing
api/src/nimstead/sbom.py          OS package URLs (deb, apk, rpm) with their distro and source package
api/src/nimstead/engine/*         an SBOM application with a distro is judged as distro packages (sbom grade)
api/migrations/versions/…         one migration: the `container` table
api/tests/test_containers.py      server; test_agent_containers.py agent; test_sbom.py, test_engine_*.py extended
web/src/…                         images on Assets, "runs on", image findings, Fix first's "rebuild" group
sandbox/containers.py             the real-host proof (last_run_containers.json)
docs/…                            how-to, reference, explanation pages; CHANGELOG, STATUS, DECISIONS, README
```

## Code style
The house style: dense, typed, a docstring that says the contract, a one-line comment only for the why, bounds on
everything an agent sends, and "couldn't tell" kept apart from "fine". For example (existing `scan.unread`):
```python
def unread(collection: dict | None) -> set[str]:
    """Finding ecosystems whose sources the agent says it couldn't read in full (failed, partial, or an empty Uninstall list)."""
    sources = (collection or {}).get("sources") or {}
```
Agent code uses only the standard library and keeps every reader injectable for tests (`query=`, `read=`, `which=`).

## Testing strategy
- **Agent (pytest, `api/tests/test_agent_containers.py`):** parsers from real files (dpkg status, distroless
  `status.d`, apk, an `rpmdb.sqlite` from a real AlmaLinux 9 image as a fixture); discovery from captured `docker` /
  `podman inspect` output; the safe reader against hostile trees (absolute and relative symlinks out of the root, `..`,
  a FIFO, a device, an oversized file, a symlink loop, a PID whose namespace changes mid-read). POSIX-only tests skip on
  Windows and run in CI (Ubuntu) and in WSL.
- **Server (pytest):** content-addressed image identity, caps, a hostile report (another host's image key, forged
  digests, oversized fields), evidence closing (complete vs partial lists, silent hosts, deleted hosts), risk taking the
  worst host, remediation refused, hourly re-match, 30-day prune, ledger entries, PostgreSQL concurrency (two hosts
  reporting one new image at once).
- **Engine:** an `image` inventory equals a host inventory's verdicts for the same packages; SBOM distro rows judged at
  `unverified`; end of support from the image's os-release.
- **Web (vitest + Playwright):** images on Assets with where they run, image findings with "rebuild" wording and no
  plan action, Fix first's rebuild group; axe clean at 1440 and 375, light and dark.
- **Real host (`sandbox/containers.py`):** see Success criteria. Agreement is measured against two oracles: the package
  manager inside each container, and the OSV API.

## Boundaries
- **Always:** a test that fails first for each behaviour; bounds on every count, length and depth an agent sends; close
  only on evidence; each new "why" in DECISIONS; STATUS, CHANGELOG, README and docs updated with the release.
- **Ask first:** nothing in this phase (the owner said be autonomous). Outward-facing steps follow the release routine
  in STATUS: push, PR, squash-merge on green, tag, release gate.
- **Never:** run anything inside a container or any binary from a container's files; follow a link out of a container's
  root; open a runtime's socket directly; send a container's file contents beyond package metadata and os-release
  fields; plan or run a fix on an image; let one host's report change or close an image another host's report created.

## Success criteria
1. **Real Docker host** (fresh WSL Debian 13, destroyed after) running `debian:11`, `alpine:3.18`, `almalinux:9`,
   `ubuntu:24.04` and `gcr.io/distroless/base-debian12` (plus `busybox`, which has no package database): each becomes an
   image asset with the right base OS; its package count equals the container's own package manager's (`dpkg-query`,
   `apk info`, `rpm -qa`; for distroless, the `status.d` entries); busybox is "not assessed: no package database".
2. **Findings agree with the OSV API** for every image's packages (querybatch on the same names and versions), with
   every difference explained or none.
3. Debian 11 and Alpine 3.18 open their **end-of-support** findings.
4. Two containers of one image are **one** image asset listing both. A Podman container is read the same way.
5. **Rebuild and redeploy:** stop a vulnerable container and run a newer image; the next report resolves the old image's
   findings ("not running on any host") and the new image's are present. A report whose container list was partial
   closes nothing.
6. **Hostile containers can't steer the reader:** a container whose `/var/lib/dpkg/status` is an absolute symlink to a
   host-only path, one where it is a FIFO, and one with a 200 MB file there: the agent reads nothing outside the
   container, never hangs, stays within its time and memory budget, and reports each as not assessed.
7. **Image SBOMs:** real Syft and Trivy CycloneDX output for `debian:11` and `alpine:3.18` matches the agent's findings
   for the same image (OS packages), graded unverified.
8. Remediation on an image is refused by the API and never offered by the UI.
9. **Performance:** 1,000 hosts with 10 containers each over 50 images: the containers report's median under 1 s, and
   the hourly re-match grows by about what 50 more hosts cost.
10. All suites green: API on SQLite and PostgreSQL 17, web unit and e2e (axe 0 serious/critical), ruff.

## Not doing (this phase)
Kubernetes/CRI runtimes, rootless containers, stopped containers and images at rest, registry scanning, language
packages inside containers, rpm Berkeley DB and ndb, Windows containers, image signing or provenance, admission control.
