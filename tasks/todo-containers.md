# Todo: containers

Spec `tasks/spec-containers.md`, plan and reasons `tasks/plan-containers.md`. House rules: read STATUS.md first; a test
that fails first for every behaviour; real-host proof in `sandbox/` on disposable WSL distros only; each new "why" in
DECISIONS.md (next 138); STATUS, CHANGELOG, README and docs at release.

Standard checks (every task): `(cd api && uv run ruff check src tests ../agent ../sandbox ../scripts && uv run pytest -q)`;
web tasks also `(cd web && npm test && npm run build && npm run e2e)`; the migration task also `sandbox/pg.py`.

---

## Phase 1: the agent reads running containers

### C1: A container root that can't be escaped, and the package databases inside it
**Description:** `ContainerRoot(pid)` opens files under `/proc/<pid>/root` the safe way (plan, "read like hostile
input"); `parse_dpkg_status` reads `/var/lib/dpkg/status` and distroless `status.d/`; `parse_rpm_sqlite` reads
`rpmdb.sqlite` header blobs; `parse_apk` is reused. `read_container(root)` returns the os-release fields, ecosystem,
packages and a collection document like `collect_linux`'s.
**Acceptance criteria:**
- [ ] An absolute symlink, a relative one climbing past the top with `..`, and a symlink loop all resolve inside the root or fail; nothing outside is opened (test builds a fake root and a "host" file next to it)
- [ ] A FIFO, a device and a 200 MB file at the package database's path: refused or capped without blocking; the source says why
- [ ] Rows equal `parse_dpkg`/`parse_rpm`'s for the same packages (source, source_version, epoch kept), from real files
**Verification:** `uv run pytest -q tests/test_agent_containers.py` (POSIX parts in WSL too); standard checks
**Dependencies:** None · **Files:** `agent/nimstead_agent.py`, `api/tests/test_agent_containers.py`, `api/tests/fixtures/containers/*` · **Scope:** M

### C2: Discovery, budgets and the containers report
**Description:** `containers()` lists running containers with `docker`/`podman` (`ps -q --no-trunc`, `inspect`), checks
each PID's mount namespace, reads each root once per (image id, content), and builds the body for `POST
/api/agent/containers`, sent after the inventory by `report`. `enroll --no-containers` turns it off locally; `collect`
prints it; `crictl` alone is reported as not read. Agent 0.8.0.
**Acceptance criteria:**
- [ ] Captured real `inspect` output → the right id, name, PID, image id and reference for both runtimes; a runtime that fails makes the report partial (never complete)
- [ ] Replicas of one image are read once and listed together; budgets (128 containers, 120 s, 8 MB) end the pass as partial
- [ ] Not root, no runtime, opted out: the body says so; a 404 from an older server doesn't fail the run
**Verification:** tests as C1; `collect` in the disposable distro against real Docker containers
**Dependencies:** C1 · **Files:** `agent/nimstead_agent.py`, `api/tests/test_agent_containers.py` · **Scope:** M

### Checkpoint A: agent tests green on Windows and WSL; real containers read with the right counts

## Phase 2: the server

### C3: The `container` table
**Description:** Model + Alembic migration: (asset_id, container_id) primary key, image_asset_id, org_id, name, runtime,
first_seen, last_seen; both foreign keys cascade; index on image_asset_id. `Asset.kind` comment gains `image`.
**Acceptance criteria:**
- [ ] Upgrade and downgrade on SQLite and PostgreSQL; `test_migrations` passes (single head)
- [ ] Deleting a host or an image deletes its rows
**Verification:** `uv run pytest -q tests/test_migrations.py`; `sandbox/pg.py`
**Dependencies:** None · **Files:** `api/src/nimstead/db.py`, `api/migrations/versions/<new>.py`, `api/tests/test_migrations.py` · **Scope:** S

### C4: Store a host's container report
**Description:** `containers.store(s, host, body)` behind `POST /api/agent/containers` (agent key, rate-limited like
inventory). Validates every field, computes each image's key, creates or finds the image asset (caps, outside quota),
stores its packages and document once, replaces or refreshes the host's container rows, sets each image's risk context
from its hosts, rescans new images, writes one `containers_reported` ledger entry. DECISIONS 138, 139.
**Acceptance criteria:**
- [ ] Two hosts with the same image content → one asset listing both; the same image id with different packages → two
- [ ] A forged or oversized report changes nothing another host's report made; caps refuse and count, never crash
- [ ] A new image's findings open through the engine (same verdicts as a host with those packages)
**Verification:** `uv run pytest -q tests/test_containers.py`; standard checks
**Dependencies:** C3 · **Files:** `api/src/nimstead/containers.py`, `api/src/nimstead/app.py`, `api/tests/test_containers.py` · **Scope:** M

### C5: Evidence closing and the image lifecycle
**Description:** `rescan` on an image with no container rows resolves its findings ("Not running on any host"); the
hourly loop re-matches running images; host deletion removes the images only it ran; images not running for 30 days are
deleted in the clean-up. DECISIONS 140.
**Acceptance criteria:**
- [ ] Complete list without the image → resolved with the reason and a ledger entry; partial list or a silent host → open
- [ ] Running again → reopened (a regression in the ledger), on the same asset
- [ ] Host deleted → its only images gone; an image another host still runs stays
**Verification:** `uv run pytest -q tests/test_containers.py tests/test_engine_*.py`; standard checks
**Dependencies:** C4 · **Files:** `api/src/nimstead/scan.py`, `api/src/nimstead/containers.py`, `api/src/nimstead/feeds.py`, `api/src/nimstead/app.py`, tests · **Scope:** M

### C6: The API around images: no remediation, Fix first, assets
**Description:** `remediate.plan` refuses non-host assets; `summary.top_actions` counts hosts only and
`images_to_rebuild` lists images; `GET /api/assets` and `/api/assets/{id}` carry an image's references, base OS and where
it runs, and a host's running containers. DECISIONS 141.
**Acceptance criteria:**
- [ ] Single, batch and auto plan on an image → refused with "rebuild" wording, no job row
- [ ] An image's openssl finding never joins a host's openssl action; it appears in `images_to_rebuild` with its fix
- [ ] Asset JSON: image `running_on` (hosts, containers), host `containers`; another org's image → 404
**Verification:** `uv run pytest -q tests/test_containers.py tests/test_api.py`; standard checks; `sandbox/pg.py`
**Dependencies:** C5 · **Files:** `api/src/nimstead/remediate.py`, `api/src/nimstead/app.py`, tests · **Scope:** M

### Checkpoint B: API suite on SQLite and PostgreSQL 17; ruff clean

## Phase 3: the UI

### C7: Container images on Assets
**Description:** A "Container images" view beside machines, devices and internet (count, worst priority on the tab): each
image's reference, base OS, hosts it runs on, open findings by priority; its drawer lists containers by host, the scan
report, and links to its findings. A machine's drawer lists the containers running on it.
**Acceptance criteria:**
- [ ] Images sorted by most urgent finding; an unread image says "Not assessed" and why
- [ ] Drawer and links keyboard reachable; axe clean at 1440 and 375, light and dark
**Verification:** `npm test`, `npm run e2e`
**Dependencies:** C6 · **Files:** `web/src/assets.tsx`, `web/src/lib.ts`, `web/src/ux.test.tsx`, `web/e2e/*` · **Scope:** M

### C8: Image findings and Fix first's rebuild group
**Description:** Findings name the image and where it runs; the drawer says to rebuild with the fixed packages and
redeploy, and offers no plan; bulk plan skips images; Home shows "Images to rebuild" apart from fixes it can plan.
**Acceptance criteria:**
- [ ] No plan action anywhere for an image finding; the rebuild text names package → fixed version and the base OS
- [ ] Home's rebuild group lists images by urgency and links to each image
**Verification:** `npm test`, `npm run e2e`
**Dependencies:** C6 · **Files:** `web/src/findings.tsx`, `web/src/home.tsx`, `web/src/planfix.tsx`, tests · **Scope:** M

### Checkpoint C: web unit + e2e green, axe clean

## Phase 4: image SBOMs

### C9: OS package URLs in SBOMs
**Description:** `sbom.parse` maps `pkg:deb|apk|rpm` with a `distro` qualifier to the distro ecosystem and source
package (Syft `upstream`, Trivy `SrcName`/`SrcVersion`/`SrcEpoch`), keeps one distro per SBOM, and the upload stores
source rows and the application's ecosystem. DECISIONS 142.
**Acceptance criteria:**
- [ ] Real Syft and Trivy CycloneDX + Syft SPDX for debian:11 and alpine:3.18 → rows with the right ecosystem, source and source version
- [ ] No distro qualifier, an unmapped distro, a second distro: counted as skipped with a reason; on a host asset, OS purls skipped
**Verification:** `uv run pytest -q tests/test_sbom.py`; standard checks
**Dependencies:** None · **Files:** `api/src/nimstead/sbom.py`, `api/src/nimstead/app.py`, `api/tests/test_sbom.py`, fixtures · **Scope:** M

### C10: The engine judges an application with a distro
**Description:** An application inventory whose ecosystem is a distro goes through the Linux path with the SBOM as its
package list (grade unverified), with end of support; its report shows both families.
**Acceptance criteria:**
- [ ] Same packages as an image asset → same vulnerable set, graded unverified, with "An SBOM states what was built" said
- [ ] A later SBOM without a package closes its findings (removed, read in full); language components still judged
**Verification:** `uv run pytest -q tests/test_engine_*.py tests/test_sbom.py`; standard checks
**Dependencies:** C9 · **Files:** `api/src/nimstead/engine/collection.py`, `evaluate.py`, `report.py`, tests · **Scope:** M

## Phase 5: proof and release notes

### C11: Real-host proof
**Description:** `sandbox/containers.py`: fresh WSL Debian 13 with Docker and Podman, the app from this tree, the real
agent; every spec success criterion 1-8 as a step with PASS/FAIL into `last_run_containers.json`; distro destroyed.
**Acceptance criteria:** [ ] Every criterion PASS, or a real bug found, fixed with a test, and rerun
**Dependencies:** C2, C5, C10 · **Files:** `sandbox/containers.py`, `sandbox/last_run_containers.json` · **Scope:** M

### C12: Performance
**Description:** `perf.py --containers N`: 1,000 hosts × 10 containers over 50 images; containers report median and the
hourly re-match before and after. **Acceptance:** [ ] report median < 1 s; re-match growth ≈ 50 hosts' worth
**Dependencies:** C5 · **Files:** `sandbox/perf.py` · **Scope:** S

### C13: Docs and release notes
**Description:** How-to (containers on Docker/Podman hosts, image SBOMs from CI), reference (agent flag, API, asset
kind), explanation (how containers are read safely and closed on evidence); CHANGELOG with Highlights; STATUS; README;
DECISIONS 138-142.
**Acceptance:** [ ] `scripts` docs checks pass; every new flag and endpoint documented
**Dependencies:** all · **Files:** `docs/**`, `CHANGELOG.md`, `STATUS.md`, `README.md`, `DECISIONS.md` · **Scope:** M

### Checkpoint D (release gate): every spec success criterion met; all suites green; review findings fixed
