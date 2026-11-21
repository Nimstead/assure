# Spec: workloads — Kubernetes nodes and the applications inside container images (V1)

Status: **written 2026-11-21; the owner set the goal "spec, plan, build, test, review, ship. Next phase. Impress me.
Market leader tool."**, the goal that produced the containers, programme and tickets phases. The containers spec
(`tasks/spec-containers.md`, DECISIONS 138) listed what it left for later; this phase takes the two items a buyer meets
first. Each open question is answered below with the recommendation and the reason, and the gates between phases are
passed on that goal. Plan: `tasks/plan-workloads.md`. Tasks: `tasks/todo-workloads.md`. DECISIONS from 155. Ships as
0.13.0 with agent 0.9.0.

## Objective

**The gap.** Since 0.10 the agent reads the OS packages inside a Docker or Podman host's running containers. Two things
still leave most real container estates half-seen:

1. **What the application brought.** A container's risk is mostly in what the image's own build added: the jar with
   log4j-core in it, the `node_modules` with an old lodash, the venv with an old urllib3, the Go binary built with a Go
   release that has since had a dozen security fixes. Today an image built `FROM python:3.12-slim` with a vulnerable
   Django reads as its Debian packages only. Every tool a buyer compares us with reads these: Trivy and Grype for free,
   Wiz, Prisma Cloud, Aqua, Sysdig, Qualys Container Security, Tenable Cloud Security and Defender for Containers.
2. **Kubernetes.** Most production containers run under Kubernetes, where the runtime is containerd or CRI-O and there
   is no `docker` CLI. The agent sees `crictl` and says "Kubernetes (CRI) containers aren't read yet". Every tool above
   reads Kubernetes nodes.

**Who.** The platform team that runs the clusters and builds the images; the security lead who needs one list across
VMs, Docker hosts and clusters; the auditor who asks how a finding on a container was established.

**What sets ours apart** (the promises the rest of Nimstead keeps):
1. **Read where it runs, not where it was built.** The agent reads the files of the running container, so the answer
   is what is deployed, with no registry credentials, no image pull, no sensor DaemonSet and no Kubernetes API token.
2. **No noise from the base image.** A Python package that Debian's own `python3-requests` installed is Debian's,
   judged by Debian's advisories with its backports; it is never reported a second time as PyPI `requests`. Only what
   the image's build added outside the package manager is judged as an application package.
3. **Hostile input stays hostile.** An image is someone else's filesystem. The walk follows no link, crosses no mount (so
   a pod's mounted secrets and volumes are never read), opens only regular files, caps every read and runs nothing.
4. **One image, however it runs.** The same image under Docker on one machine and in a pod on another is one image
   asset with one set of findings, fixed by one rebuild, and the fix names the file to change ("log4j-core 2.14.1 in
   /app/app.jar → BOOT-INF/lib/log4j-core-2.14.1.jar").
5. **Honest coverage.** A container whose applications couldn't all be read says which, and why; never clean.

### User stories and acceptance
- **S1.** As a platform engineer with Docker hosts, after updating the agent, my images' findings include the Python,
  npm, Java and Go packages their builds added, each with where it is in the image. Nothing to configure.
- **S2.** As a platform engineer with a Kubernetes cluster, I enrol each node with the usual install command. Its pods'
  containers appear on the node as `namespace/pod/container` running on `containerd` (or `cri-o`), and their images join
  the images list with everything above.
- **S3.** An image's finding on an application package says the package, the version that fixes it, and the file in
  the image that carries it. Fix first's "Container images to rebuild" names those packages too.
- **S4.** The image drawer says what was read in that image: "Debian packages 96 · Python 41 · npm 0 · Java 3 · Go 52",
  and for anything not read in full, why.
- **S5.** As the owner of a host where the walk costs too much, I turn application reading off locally
  (`"container_apps": false` in the agent's configuration, or `enroll --no-container-apps`); the server can't turn it
  back on. OS packages in containers are still read.
- **S6.** A pod I delete stops counting on the node's next report, as a stopped Docker container does today; a node
  whose `crictl` fails closes nothing.

## Scope

### Module 1 — `image-apps`: application packages inside running containers (agent, server, UI)

**What is read** (the same rules as the host scans of DECISIONS 92 and plan T35, so a package reads alike on a host and
in a container):
- **Python:** each `*.dist-info` folder (its `METADATA`) and `*.egg-info` folder or file (`PKG-INFO`) directly inside a
  folder named `site-packages` or `dist-packages`, anywhere in the image (system Python, `/usr/local`, venvs).
- **npm:** each `node_modules/<name>/package.json` and `node_modules/@scope/<name>/package.json`, anywhere, including
  nested `node_modules` (6 levels, as on hosts).
- **Java:** each `.jar`, `.war` and `.ear` anywhere: `META-INF/maven/*/*/pom.properties`, and the same inside one level
  of nested jars (Spring Boot's `BOOT-INF/lib`, a war's `WEB-INF/lib`).
- **Go (new):** each regular file that is an ELF executable with Go's build information (Go 1.18+, inline format): the
  main module's dependencies (`dep` lines, with `=>` replacements applied) and the toolchain as `stdlib` at its Go
  version, as Syft, Trivy and govulncheck name it. Older Go binaries are counted as not read, never silently.

**How it is read.** One bounded walk of the container's root through descriptors, from the root `ContainerRoot`
already holds: each directory is opened relative to its parent's descriptor with `O_PATH | O_NOFOLLOW | O_DIRECTORY`; a
link is never followed (to a folder or a file); a directory on another mount (procfs, a volume, a pod's secrets and
service-account token, FUSE) is never entered; a file is opened only after `fstat` on its `O_PATH` descriptor says
regular, then reopened through `/proc/self/fd`; every read is capped (METADATA 64 KB, package.json 1 MB, pom.properties
64 KB, a nested jar 50 MB, Go build info 64 KB); a jar is read as a zip through its descriptor (central directory and the
named entries only, never the whole file into memory).

**Base-image noise.** Files the image's own package manager installed are left to it: dpkg's `info/*.list` files, apk's
`F:`/`R:` lines; for rpm images (whose file lists live in header blobs) the distribution's own trees, as on hosts, plus
`/usr/bin`, `/usr/sbin` and `/usr/libexec` for Go binaries. Counted as "owned", not reported.

**Budgets.** Per image: 200,000 directory entries, 20,000 application packages, 60 seconds, inside the container pass's
existing 120 seconds and 8 MB. Reaching one marks the affected lines partial with the reason. Containers of one image
whose OS package read is identical share one walk (the first container's).

**Report.** Each image entry gains `apps` (`ecosystem`, `name`, `version`, `source` = the location in the image) and
its collection document gains `python_packages`, `npm_packages`, `java_archives` and `go_modules` lines. The server
stores them as the image's packages with their own ecosystems; the engine judges them as it judges a host's
application packages (graded as a reading of installed files, not an SBOM). The image's identity (its content hash)
includes them.

**UI.** The image drawer's "What was read" line per source; application findings show the location; Fix first's
rebuild list names application packages with their locations.

### Module 2 — `cri-nodes`: Kubernetes nodes through `crictl` (agent, server, UI)

- The agent lists running containers with `crictl ps -q --state running` and describes them with one `crictl inspect -o
  json` (read-only, through the node's own `crictl` and its configured endpoint; no socket of our own, no Kubernetes API).
  Each container's PID, image id (`sha256:` digest of the image config, the same id Docker and Podman report) and
  Kubernetes labels (`io.kubernetes.pod.namespace`, `io.kubernetes.pod.name`, `io.kubernetes.container.name`) are taken;
  the reference shown is the image as the pod asked for it.
- The runtime is named by `crictl version` (`containerd` or `cri-o`); the cgroup check of DECISIONS 138 applies
  unchanged (both runtimes name the container id in its cgroup).
- The container's name is `namespace/pod/container` (255 characters). Its files are read exactly as a Docker
  container's, including Module 1.
- The listing is proof of what stopped, per runtime, as for Docker and Podman (DECISIONS 140): a `crictl` that fails
  closes nothing; a node where `crictl` was removed sends an empty listing for the runtime it last named only if neither
  `crictl` nor that runtime is installed.

### Out of scope (deferred, V2 backlog)
- **Owner from Kubernetes namespace** (a namespace → team mapping for images): needs either the API or a settings
  table; images take an owner by hand today.
- **Rootless containers, stopped containers, images at rest, registry scanning:** each needs a different reader.
- **Ruby, PHP, .NET, Rust packages in images** (`specifications/*.gemspec`, `vendor/composer/installed.json`,
  `*.deps.json`, cargo-auditable): the same walk can carry them later; each is a new collection line.
- **Jars without `pom.properties`** (manifest or file-name guesses): a wrong guess is worse than saying so.
- **Go reachability** (govulncheck's symbol analysis): findings mean the module is in the binary, not that the vulnerable
  function is called, as for SBOMs.
- **Application packages on hosts' own filesystems for Go**, and turning host app scans on by default.
- **Kubernetes workload context** (Deployment, ReplicaSet) and a namespace filter in the UI.

## Tech stack
Unchanged: agent is one Python file (stdlib only, Python 3.9+ on Linux); API Python 3.14, FastAPI, SQLAlchemy, Alembic;
web React 19 + TanStack Router/Query + Tailwind, Vitest, Playwright with axe. No new dependency. Proof tooling (in the
disposable distro only): Docker, k3s (containerd + `crictl`), Syft as the package oracle, the OSV API as the
vulnerability oracle.

## Commands
```
API + agent tests:  (cd api && uv run ruff check src tests ../agent ../sandbox ../scripts && uv run pytest -q)
Agent container tests on Linux (WSL, non-root):  wsl -d Ubuntu -- python3 -m pytest api/tests/test_agent_containers.py api/tests/test_agent_workloads.py
Web:                (cd web && npm test && npm run build && npm run e2e)
Docs checks:        (cd api && PYTHONUTF8=1 uv run python ../scripts/check_docs.py && uv run python ../scripts/export_api_docs.py --check)
Real-host proof:    (cd api && uv run python ../sandbox/workloads.py)            # fresh WSL Debian 13, Docker + k3s
Performance:        (cd api && uv run python ../sandbox/perf.py --assets 1000 --containers 10 --apps 500)
```

## Project structure (what this phase touches)
```
agent/nimstead_agent.py            → walker, app readers on ContainerRoot, Go build info, crictl listing, opt-out
api/src/nimstead/containers.py     → image(): apps rows, runtimes containerd/cri-o, caps, key
api/src/nimstead/engine/collection.py → AGENT_APPS gains go_modules (Go)
api/tests/test_agent_workloads.py  → agent unit tests (new)
api/tests/test_containers.py       → server tests for apps and CRI runtimes
web/src/assets.tsx, findings.tsx, home.tsx → drawer "What was read", locations
sandbox/workloads.py               → real-host proof (new); sandbox/perf.py --apps
docs/how-to/…containers…, README.md, CHANGELOG.md, STATUS.md, DECISIONS.md
```

## Code style
Follow the file you are in. The agent's container code is the model: a docstring that says what is refused and why,
budgets as named constants with the reason in a trailing comment, errors as `ContainerReadError` carrying the
collection document's words, no I/O in parsers:
```python
CONTAINER_LINK_HOPS = 8

def parse_dpkg_status(text, require_status=True):
    """Return package dictionaries from a dpkg status file (or a distroless status.d entry) in parse_dpkg's form. ... No I/O."""
```

## Testing strategy
- **Agent unit tests** (pytest, Linux, non-root, `ContainerRoot.of_dir` on temporary trees): each reader on real layouts;
  owned exclusion for dpkg, apk and rpm; Go build info from real Go binaries' bytes (fixtures built once, small) and
  crafted headers; every hostile case (links out and climbing, a link loop, FIFOs named as metadata or jars, a 200 MB
  sparse jar, a nested zip bomb, a lying zip header, a deep tree, the entry budget); `crictl` parsing from output
  recorded on the real k3s node; runtime naming and listing proof.
- **API tests:** apps stored with their ecosystems and judged; caps; identity includes apps; a 0.8.1 agent's body
  judged exactly as before; `containerd`/`cri-o` rows and their listing proof; Go `stdlib` matched.
- **Web unit tests:** drawer read line, locations in findings and Fix first.
- **Real-host proof** (`sandbox/workloads.py`, disposable WSL Debian 13): see success criteria.
- **Review:** an independent code review and a security audit of the walker; every finding fixed with a test that fails
  first; mutation check of the fixes.

## Boundaries
- **Always:** DECISIONS 138's hostile-input rules for every byte read from a container; tests before commits; a test that
  fails without each fix; check `check_docs.py` and `export_api_docs.py --check` before pushing; the branch checked right
  before each commit (shared checkout).
- **Ask first:** approving the `release` environment gate (the owner's, unless they say "you do it"); anything that costs
  money or touches a real cluster that isn't disposable.
- **Never:** run anything from a container; follow a link or cross a mount inside one; talk to the Kubernetes API or a
  registry; read a pod's secrets; delete a test that fails.

## Success criteria
1. **Packages, exactly.** On a real Docker host, for images built for the proof (a Python app on `python:3.12-slim`, a
   Node app on `node:20-slim`, a Spring Boot fat jar and a plain log4j jar on `eclipse-temurin:17-jre`, and a Go
   service on distroless), the agent's application rows (ecosystem, name, version) equal Syft's for the same image,
   restricted to those ecosystems; every difference is listed with its reason in the run record, none unexplained.
2. **Findings, exactly.** For every application row, the image's findings equal the OSV API's answer for that
   (ecosystem, name, version): each vulnerability OSV lists opens, none extra.
3. **No base-image noise.** On `debian:12` with `python3-requests` from apt and `alpine:3.20` with `py3-requests` from
   apk, no PyPI row appears for what the package manager installed, while a `pip install`ed package next to it does.
4. **Kubernetes.** On real containerd and real CRI-O (Fedora 44's own packages, in a disposable distro), with
   containers created through the CRI as the kubelet creates them (its `io.kubernetes.*` labels, the image by its id),
   every running container is read through `crictl`, named `namespace/pod/container` on runtime `containerd` or
   `cri-o`; an image run under Podman on the same node and in a pod is one image asset; deleting the pod removes its row
   on the next report while Podman's stay; with `crictl` failing, nothing closes. (A k3s download was refused by this
   session's safety policy; the kubelet only calls the same CRI.)
5. **Hostile images.** Links to a host-only marker (absolute, climbing, through `node_modules` and `site-packages`), a
   link loop, FIFOs named `METADATA`, `package.json` and `evil.jar`, a 200 MB sparse jar, a nested zip bomb, a 64-level
   tree and a tree past the entry budget: nothing outside the image is read, nothing hangs, the pass stays within its
   120 seconds, and each limit is said in the image's lines.
6. **Old agents unchanged.** A 0.8.1 agent's container body is stored and judged exactly as on 0.12.0 (API test).
7. **Performance.** On the proof host the container pass with application reading stays inside its budget (time per
   image recorded). Server, `perf.py` at 1,000 hosts × 10 containers over 50 images with 500 application packages each:
   a container report's median and the hourly re-match within 20% of 0.12.0's run, or the difference explained.
8. **UI.** The drawer's read line and the locations render; Playwright e2e with axe clean at 1440 and 375, light and
   dark.
9. **Suites and CI.** API, agent (Linux), web unit and e2e pass; CI green on SQLite and PostgreSQL 17.
10. **Docs.** The containers how-to covers Kubernetes and application packages; README's limitations, CHANGELOG
    (with a Highlights summary), STATUS and DECISIONS updated.

## Open questions (answered on the owner's goal)
1. **On by default?** Yes. Application metadata is the same class of data as a container's package list, read from
   fixed file names the server never chooses (DECISIONS 7), and an opt-in would leave most images half-seen, which is
   the gap. The local opt-out mirrors `--no-containers`.
2. **Walk the whole image or fixed folders?** The whole image, bounded. Applications live anywhere (`/app`,
   `/opt`, `/srv`, `/usr/src/app`, `/home/*`, venvs); fixed folders would miss most of them, which is why every scanner
   above walks.
3. **One walk per image or per container?** Per image (identical OS read), within the pass. A file one replica wrote at
   run time that its siblings didn't is the one thing this can miss; walking 30 replicas of one image 30 times would
   spend the budget that reads the other images.
4. **Go `stdlib`?** Yes: most Go findings in practice are the toolchain's, and Syft, Trivy and govulncheck all report it.
5. **Owner from namespace?** Not this phase (deferred above): it needs a source of truth for namespaces we don't read.
