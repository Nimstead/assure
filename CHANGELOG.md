# Changelog

All notable changes to Nimstead Assure. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Upgrade notes
- **API:** `GET /api/attack-paths` adds `flow`: every machine reached, in full, with its route, the link onto it and which choke points cut it off, and each way in's own reach.

### Highlights
- **Attack paths have a page of their own.** It opens on **Cut these first**, with the top change already chosen. Below it, the fleet's exposure is drawn as one flow: the ways in, the keys and settings machines are reached through, and the machines reached by owner or criticality, with what the chosen change cuts off solid and the rest hatched. A row per machine follows, with its route, how sure, and which changes cut it off. Columns fold past seven rows, so it reads the same at thousands of machines.

### Added
- **The Attack paths page** (DECISIONS 173), in the sidebar after Assets. Assets keeps one line linking to it, and each machine's drawer shows its own paths and how it's reached.

## [0.15.1] - 2026-11-27 (preview)

Agent 0.11.0, unchanged. No database migration.

### Upgrade notes
- **Expect far fewer chain starts and different choke points** on fleets where an unfixed library flaw with no sign of exploitation made most machines a way in. Nothing is hidden: those machines keep their paths and key links.
- **API:** `GET /api/attack-paths` adds `unlikely` (`{"epss": ...}`) to a host whose only way in is a flaw with no sign of exploitation. Such a host's `entry` is now false. Linux ways in in scan reports add `refs`, every flaw id of the way.

### Highlights
- **Cut these first finds the real choke points.** Chains and choke points now start only from a likely way in: a setting, or a flaw that is known to be exploited, has an EPSS of 10% or more, or has no EPSS yet. Before, an unfixed library flaw nobody exploits (one loaded by every sshd, say) made nearly every machine a start, so there was little left to cut. On a 205-machine demo fleet the starts fell from 112 to 2, and retiring the production ansible key now cuts 61 machines instead of 6. Machines left out keep their paths, labelled unlikely, and the view says how many there are.

### Changed
- **Only likely ways in start chains and choke points** (DECISIONS 172).

## [0.15.0] - 2026-11-27 (preview)

Agent 0.11.0. One database migration (`a3c5e7f9b1d2`, a table), applied on start.

### Upgrade notes
- **Linux agents read who can get in once they update to 0.11.0**: sshd's settings, the accounts that matter (groups, whether each password is usable, locked or empty, `sudo -n -l`), files root runs that others can replace, the SSH keys each machine holds and trusts as fingerprints, credential files present, and the machine's own and private-range peer addresses. Private keys, key comments, forced commands, password hashes and what any credential file holds never leave the machine. `sudo -n -l` runs for up to 32 accounts at each report, and sudo logs each call.
- **Expect new findings** in a `LinuxConfig` group (`CFG:ssh-root-password`, `CFG:ssh-empty-passwords`, `CFG:root-equivalent-group`, `CFG:sudo-nopasswd-all`, `CFG:writable-root-run`, `CFG:shadow-readable`), and attack paths on Linux machines where there were none.
- **Linux reports' content version and inventory hash change once**: content now carries NVD's CVSS vectors for Linux, and a Linux inventory carries what runs and the access read for its attack paths. Windows reports don't change.
- **To turn it off on a machine**, enrol with `--no-paths` (the installer takes it too) or set `"paths": false` in `/etc/nimstead/agent.json`. The server can't turn it back on, and it forgets what that machine said before.
- **API:** `GET /api/attack-paths` adds SSH key edges (`kind: "ssh"`, with `key`, `path`, `account`, `needs` and `gives` on each way), `as` on each chain row, `reaches` on Linux paths, `choke_points` (each with a `grade`), and `partial` when chains and choke points may be missing something. Scan reports add `skipped` and `reaches` on Linux paths, and a top-level `ssh`. The inventory body takes `access`.

### Highlights
- **See how an attacker would move between your Linux machines.** Nimstead joins what runs, what's vulnerable and who can get in, so each machine's report says how someone gets from the network to root. For example: in through a flaw in the libssl a web app loaded, as `www-data`; up through `www-data`'s `NOPASSWD` sudo; then root's SSH keys. A way in through a program that runs as root says it's root at once.
- **SSH key links, exact.** A machine links to another only when a key it holds has the same fingerprint as one the other trusts, for an account that machine's sshd lets in. That's judged by sshd's own settings (`PermitRootLogin`, `AllowUsers`, `DenyUsers`, groups, `AuthenticationMethods`, `ForceCommand`) and the key line's `from=` and `expiry-time=`. It's confirmed only when a connection between the two was seen. The lab proof checked 14 cases against real `ssh` sign-ins, and every one agreed.
- **Cut these first.** Choke points rank the single actions that cut the most machines off from every way in: close one machine's way in, retire one key, remove a key from one `authorized_keys`, or change one setting. Each says which machines it cuts off. In the lab, the top one was done for real and cut exactly the machines it said.
- **Chains that know who you are.** A key works only for root or its owner, so reaching a machine as `deploy` opens only what `deploy`'s keys open.
- **Six Linux settings as findings**, with who each one helps and how to fix it.

### Added
- **The access read** (DECISIONS 165), agent 0.11.0.
- **Linux settings findings** (DECISIONS 166).
- **Linux attack paths, aware of privilege** (DECISIONS 167). A flaw the distribution says it won't fix (Debian's "unimportant") is no way in or up.
- **SSH key edges and chains** (DECISIONS 168), and **choke points** (DECISIONS 169) on Assets' attack-path view.
- **Two review rounds before release** (DECISIONS 170, 171): among others, sshd's listening state is read from its own service rather than the first program called `ssh`, every cap on the agent's read makes it partial, and the fleet view takes 0.2 s at 1,000 hosts that are all ways in.

## [0.14.1] - 2026-11-26 (preview)

Agent 0.10.0, unchanged. One database migration (`d4f6a8c0e2b1`, an index), applied on start.

### Upgrade notes
- **The migration adds one index to the findings table** (`org_id, status, priority`). On a large database it takes a moment on start: 0.6 s for 537,000 findings on SQLite.

### Highlights
- **The home page is faster than before runtime, not slower.** At 1,000 hosts with 297,000 open findings, Fix first loads in 0.24 s, down from 0.40 s in 0.14.0 and 0.33 s in 0.13.0; with Windows hosts 0.38 s, down from 0.59 s and 0.55 s.

### Fixed
- **The home page read every open finding to count them by priority** (248 ms of a 0.40 s page at 297,000 open findings). It now counts them from an index alone, in 33 ms. Inventory ingest and the hourly re-match take as long as before.

## [0.14.0] - 2026-11-26 (preview)

Agent 0.10.0. One database migration (`b7d1e3f5a9c2`), applied on start.

### Upgrade notes
- **Linux agents read what runs once they update to 0.10.0**: which installed packages running programs have loaded, which of those programs listen on the network, and which run a copy of a package replaced since they started. Expect rank changes on Linux findings (up for libraries a network listener has loaded; down, a week later, for network flaws in native code nothing loads) and some fixed findings staying open until the program running the old copy restarts.
- **Automated Linux fixes now restart the services that ran the files they replace**, then health-check them, and roll back if one won't come up. The approval names those services. D-Bus, the system manager, login and display managers, networking, container runtimes and the agent are never restarted; a fix they hold waits for a restart, said in words.
- **To turn it off on a machine**, enrol with `--no-runtime` (the installer takes it too) or set `"runtime": false` in `/etc/nimstead/agent.json`. The server can't turn it back on.
- **API:** findings rows add `runtime` and take `?runtime=listening,loaded,not_loaded,restart`; a finding adds `running`; `GET /api/assets/{id}/runtime` is new; `GET /api/summary` adds `restarts` and each fix's `runtime` counts; jobs not yet run add `restarts`; the findings CSV adds `runtime` as its last column.

### Highlights
- **See which vulnerable code is actually running.** Each Linux finding says whether its package is loaded by a running program, which programs, and whether one of them listens on the network and where: "libssl3t64 (from openssl) is loaded by nginx.service, listening on 0.0.0.0:443". Read from `/proc` by the agent already there, with no kernel sensor, no eBPF and nothing left running between reports.
- **Rank by reachability, not just severity.** A network flaw in a library a listening service has loaded ranks higher; one in native code no long-running program has loaded for a week ranks lower, with what a sample can't see said in the same sentence. Known-exploited and local flaws are never lowered, and nothing is hidden.
- **Fixed means fixed, not just installed.** When `apt` replaces a library, the services using it keep the old copy in memory. Nimstead now keeps those findings open ("the fixed version is installed, but nginx.service still runs the copy it replaced: restart it"), lists them under **Restart to finish** on Fix first, and closes them on the report after the restart, so the evidence pack times each fix to when the vulnerable code stopped running.
- **Fixes that finish themselves.** An automated fix restarts the services that ran the replaced files, checks them on the new code and rolls back if one fails, restarting it again on the restored version. Proven on real Debian 13 and AlmaLinux 9 hosts against `needrestart`, `needs-restarting` and `lsof`.
- **Nothing personal leaves the machine.** Command lines and environments are never sent; programs are named by their systemd service or short name.

### Added
- **What runs** (DECISIONS 161): programs (systemd system service, else the process's name), loaded packages (mapped files, executables, jars a JVM holds open, the script an interpreter runs), replaced copies (including libraries an upgrade renamed) and listening sockets, from one bounded pass over `/proc` at each report; services systemd sandboxes are read, containers are left to their images.
- **Seven days of memory, rank by runtime and restart to finish** (DECISIONS 162): Findings' **Running** filter (Listening, Loaded, Not loaded, Restart to finish), **What runs it** in the finding drawer, per-fix machine counts and a **Restart to finish** card on Fix first, **What runs here** in the machine drawer, and fix jobs that wait for a restart instead of failing.
- **Restarts in automated fixes** (DECISIONS 163), named in the approval.
- **`enroll --no-runtime`** and `"runtime": false`, taken by the Linux installer too.

## [0.13.0] - 2026-11-22 (preview)

Agent 0.9.0. No database migration.

### Upgrade notes
- **Agents read more inside containers once they update to 0.9.0**: the Python, npm, Java and Go packages each image's build added, and Kubernetes nodes' containers. Expect new findings on your images (often many, mostly in application packages and Go toolchains); none of your existing image findings closes because of the update.
- **To read only containers' OS packages on a machine**, enrol it with `--no-container-apps` or set `"container_apps": false` in `/etc/nimstead/agent.json`. The server can't turn it back on.
- **`GET /api/findings/{id}` adds `locations`**; each image in `GET /api/summary`'s `images_to_rebuild` names each fix's `ecosystem`; an image in `GET /api/assets` adds `read`. The containers report may add `reread`.

### Highlights
- **See what your images' builds added, not just their base OS.** The old Django in a venv, lodash in `node_modules`, log4j-core inside a Spring Boot jar, a Go service built with an old toolchain: each is found in the running container, with where it sits in the image (`/app/app.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar`), and the rebuild names it.
- **Kubernetes nodes, with nothing to install in the cluster.** Enrol a node like any machine: its containerd or CRI-O containers appear as `namespace/pod/container`, read through the node's own `crictl`, with no API token, no DaemonSet and no registry credentials. One image is one image, in a pod or under Podman.
- **No noise from the base image.** A Python package Debian or Alpine installed is judged once, by its distribution with its backports, never again as a PyPI package. Jars without Maven metadata aren't guessed at.
- **Honest about what it read.** Each image says what was read, source by source ("Debian packages 96 · Python 41 · npm 0 · Java 3 · Go 52"), and why anything wasn't read in full. Updating agents closes nothing: an image read again with its applications keeps its asset and its findings, so Progress counts no fixes nobody made.
- **Hostile images stay harmless.** The walk follows no link, crosses no mount (a pod's mounted tokens and volumes are never read), opens only regular files, caps every read and runs nothing; proven against links out, loops, FIFOs, a 200 MB sparse jar, a nested zip bomb and a 210,000-file image.

### Added
- **Application packages inside containers** (DECISIONS 155-157): Python (`*.dist-info`, `*.egg-info` in any `site-packages` or `dist-packages`), npm (`node_modules`, scoped and nested), Java (`pom.properties` in every jar, war, ear and Jenkins plugin, and in archives nested two levels deep) and Go (each executable's build information, old Go binaries' included, with the toolchain as `stdlib`), read by one bounded walk per image: 200,000 entries, 60 seconds and 20,000 packages an image, 48 folder levels. New collection line `go_modules`.
- **Kubernetes nodes** (DECISIONS 158): containerd and CRI-O containers through `crictl` (`version`, `ps`, `inspect`, `images`, read-only); runtimes `containerd` and `cri-o` in the containers report and its listings.
- **What was read** in each image's drawer; **where it is in the image** on each application finding; each application package's ecosystem beside it in **Container images to rebuild**.
- **`enroll --no-container-apps`** and `"container_apps": false`, taken by the Linux installer too.

### Fixed
- **Container images to rebuild picked each fix's highest version by the image's OS order**; with application packages in images it now uses each package's own ecosystem's order (a npm `1.2.0` is newer than `1.2.0-beta.1`, which Debian's order gets backwards).

## [0.12.0] - 2026-11-21 (preview)

Agent 0.8.1, unchanged. One database migration (`e8b2d4f6a1c3`: ticket settings and tickets): the Docker image applies it on start; without Docker, run `alembic upgrade head`.

### Upgrade notes
- **Nothing is sent until you switch it on.** Ticketing is off until an admin saves a tracker in **Settings → Ticketing** and turns on **Send tickets**.
- **`GET /api/findings/{id}` and `GET /api/summary` carry ticket links** (`ticket` on a finding and on each image to rebuild, `tickets` on each Fix first action): `null` or empty until tickets exist.
- **New server setting `NIMSTEAD_ALLOW_PRIVATE_HOSTS`** for a tracker, identity provider or webhook receiver on a private network. Unset, nothing changes.

### Highlights
- **Fixes reach the team that owns them, in Jira or GitLab.** One ticket per fix per team, in the team's own project: "Upgrade openssl to 3.0.15 on 14 machines (Payments)", with the machines, the vulnerabilities, the priority and the due date. Hundreds of findings become a handful of tickets, not one per CVE per machine.
- **A ticket closes only when the machines prove the fix.** As machines are fixed the ticket says so, with the version now in each machine's inventory; when none is left Nimstead closes it, saying machine by machine why each left. If a fix regresses, or someone closes the ticket while machines are still exposed, it reopens with the evidence.
- **See it before anything is sent.** Preview lists every ticket a sync would open, by project; Test connection says in plain words whether the token and projects work. Every ticket opened, closed and reopened is in the evidence ledger.
- **Proven on a real GitLab** with the real agent: opened, routed, fixed by a real package upgrade, closed, reopened, and a hostile package name rendered harmless. Every Jira call is checked against Atlassian's published API spec.

### Added
- **Settings → Ticketing** (DECISIONS 150-153): Jira Cloud (account email and API token) or Data Center (personal access token), gitlab.com or self-managed GitLab (access token); team routes from owner to project and a default project; which findings become tickets (fix now by default, or next, routine or every priority); Test connection, Preview and Sync now; the last sync (opened, updated, closed, reopened, failed, waiting), open tickets by project and the last errors in the tracker's words. The token is sealed at rest, never shown again, and a new site or tracker needs a new one.
- **The hourly sync**: one ticket per (project, owner, fix), the grouping Fix first uses (a package or setting across the team's machines; a container image as one rebuild). Titles and descriptions kept current, a comment when machines are fixed or join, closed when no finding is open, reopened on a regression or a hand close, opened afresh if deleted. At most 100 ticket changes a sync, most urgent first; at most 5 minutes; a down tracker stops the sync after 5 failures in a row. A crash between the tracker's create and saving it is recovered by the ticket's `nimstead-<id>` label, never duplicated.
- **Ticket links** on each finding's drawer, each fix on Home and each image to rebuild.
- **`GET/PUT /api/settings/tickets`, `POST /api/settings/tickets/test`, `GET /api/settings/tickets/preview`, `POST /api/settings/tickets/sync`** (admin sessions; test and sync six an hour). Ledger entries `tickets_configured`, `ticket_opened`, `ticket_closed`, `ticket_reopened`. See [Send fixes to Jira or GitLab](docs/how-to/send-tickets.md) and the [ticket reference](docs/reference/tickets.md).
- **`NIMSTEAD_ALLOW_PRIVATE_HOSTS`**: hostnames the server operator allows to resolve to private or loopback addresses (never link-local or a cloud's metadata address) for trackers, SSO and webhooks; never for outside-in scans. Every organisation on the server can reach a named host. See [configuration](docs/configuration.md#outbound-requests).

### Security
- Reviewed by an independent code review and a security audit before release (0 critical, 0 high); every finding fixed with a test that failed first (DECISIONS 154): one project's refusals no longer stop an organisation's whole sync; a token is stripped, checked and masked in every error; Test connection gives up after 60 seconds and the hourly run budgets its time across organisations; a named private host can't reach a cloud's metadata address, even inside an IPv6 address; odd tracker replies are errors, not crashes; the tracker can't be changed while a sync runs.

## [0.11.1] - 2026-11-20 (preview)

Agent 0.8.1, unchanged. No database migration. One fix: risk acceptances on internet targets and network devices now end when they say they do.

### Upgrade notes
- **An accepted finding on an internet target or a network device whose acceptance has already ended opens again** at the target's next scan or the device's next network check after you upgrade. Fix first, Progress and the weekly summary count it as open from then on. To keep accepting it, accept it again with a new end date.

### Highlights
- **Accepting a risk on an internet target or a network device now lasts only until the date you set**, as it always has on a machine. Until now it lasted for ever while the finding was still seen, and Progress counted it as accepted risk.

### Fixed
- **An accepted finding on an internet target or a network device never expired.** Only a machine's rescan checked when an acceptance ended, so accepting a risk on a target or a device lasted for ever while it was still seen, and Progress counted it as accepted risk. It now opens again at the target's next scan or the device's next network check after its acceptance ends, recorded in the ledger as `acceptance_expired`, exactly as on a machine (DECISIONS 149).

## [0.11.0] - 2026-11-20 (preview)

Agent 0.8.1, unchanged. One database migration (`d4f6a8c0e2b4`: an owner on assets and enrolment tokens, and the weekly summary switch): the Docker image applies it on start; without Docker, run `alembic upgrade head`.

### Upgrade notes
- **Nothing changes until you use it.** Assets start with no owner and the weekly summary is off.
- **The findings CSV has a new last column, `owner`.** The columns before it are unchanged, so a script that reads them by position keeps working; one that checks the column count needs updating.
- **`GET /api/assets`, a finding's detail and enrolment tokens now carry `owner`** (`null` for none).

### Highlights
- **Progress: is it working, and who is behind?** A new page shows, day by day over 30 days to a year, overdue findings, open findings at each priority and findings accepted as a risk, then what was found and fixed each week. One sentence says whether it's getting better and, for fix-now findings, how long the rest would take at the last four weeks' pace.
- **It agrees with your evidence.** Progress is rebuilt from the signed ledger, so the history is there the day you upgrade, today's numbers are the Findings page's, and a period's on-time share and mean time to resolve equal the evidence pack's.
- **Owners.** Give each machine, application or container image a team: in its drawer, in bulk, or on the install command so new machines arrive owned. Progress lists owners by overdue findings and opens each one's findings; Assets and Findings filter by owner.
- **A weekly summary to Slack or email.** Switch it on in Settings and every Monday morning brings the week's numbers and who is behind, without naming a machine.
- **The Assets page loads faster with containers.**

### Added
- **Progress** (`/progress`, DECISIONS 146): six small charts (overdue, fix now, next, routine, low, accepted risk), each on its own scale from zero and read together by one crosshair, by pointer or arrow keys; findings opened and resolved per week; owners with their overdue, fix-now and open findings, change over the range, findings resolved on time and mean time to resolve; a table view of every chart, CSV downloads, and "How this is judged" naming the ledger entry it was rebuilt up to. A finding with no ledger record, or whose history disagrees with its current state, is counted there and left out of the charts. 0.45-0.55 s for a year on the 206-machine, 44,000-finding demo.
- **`GET /api/progress` and `GET /api/progress.csv`** (`days` 7 to 365; CSV by day or by owner), for sessions and read-only API tokens; at most 120 reads an hour per organisation. Each carries the ledger's integrity check, and Progress says when it fails rather than presenting the numbers as evidence. See the [progress reference](docs/reference/progress.md).
- **Owners** (DECISIONS 145): `owner` on assets and on enrolment tokens (an asset enrolled with a token starts with its owner); names are tidied and take the spelling the organisation already uses, in any case; retyping a team in another case respells it on every asset and token; names can't hide or reverse characters; each change is recorded in the ledger as `asset_context_changed` and changes no priority. An image takes an owner too. The owner filter on Assets and Findings (`owner=`, empty for none), the owner field in the asset and image drawers, the bulk bar and **Add a machine**.
- **Weekly summary** (DECISIONS 147): off by default; the first goes the Monday after it's switched on, then from Monday 08:00 UTC the hourly feed run sends one message a week to the alert destinations with open, fix-now and overdue findings and their change, what was resolved and how much on time, and the owners most overdue. Counts and owner names only. The week is recorded before the message is queued, so it never goes twice, and one organisation's failure costs no other its summary. Reviewed by an independent code review and security audit; every finding fixed (DECISIONS 148).
- `sandbox/progress_demo.py` gives a copy of a demo database simulated history over its real findings, with a valid hash chain, for screenshots and review.

### Changed
- **The Assets page loads faster when machines run containers.** With 1,000 machines running 10 containers each, `GET /api/assets` takes 0.44 s instead of 0.60 s (0.36 s with no containers). Pydantic now writes the response, and the container rows are read as columns rather than objects. The response itself is unchanged.

### Fixed
- **Leaving Assets before its list loaded could bring you straight back.** Clicking another page while the Assets list was still loading sometimes returned you to Assets: when the list arrived, it wrote its filters into the address and so replaced the page you'd chosen. It now leaves the address alone once you've moved on.

## [0.10.1] - 2026-11-19 (preview)

Agent 0.8.1. No database migration. Two container fixes from a review of 0.10.0: update Linux hosts that run containers.

### Highlights
- **A machine that drops Docker for Podman (or the reverse) no longer keeps the old runtime's containers "running" for ever.** Their images stop showing as running there, their findings close if nothing else runs them, and Fix first stops asking to rebuild them.
- **Deleting a machine re-ranks the container images it shared straight away.** An image stops taking its priority from a critical machine that's gone, instead of waiting for the other machines' next report.

### Fixed
- **A runtime removed from a host kept its containers open** (agent 0.8.1, DECISIONS 144). The agent now sends an empty listing for Docker or Podman when it finds the runtime neither on its PATH nor in systemd's default PATH and `/snap/bin`, so the server closes the containers that runtime ran. A runtime found only off the agent's PATH (cron's is shorter) still closes nothing.
- **Deleting a host left the images it shared ranked by it** (DECISIONS 144): their criticality and internet exposure, and so their findings' priority, now follow the hosts left at once, as they do when a host's context changes.

## [0.10.0] - 2026-11-19 (preview)

Agent 0.8.0. One database migration (`c9e1a3f5b7d2`, the `container` table): the Docker image applies it on start; without Docker, run `alembic upgrade head`. Update Linux hosts to read their containers.

### Upgrade notes
- **Agents at 0.8.0 read the packages inside a Linux host's running Docker and Podman containers at each report, by default.** Nothing is installed in a container and nothing in one is run. To turn it off on a host, enrol with `--no-containers`, or set `"containers": false` in `/etc/nimstead/agent.json`; the server can't turn it back on.
- **New limits:** `NIMSTEAD_MAX_IMAGES_PER_ORG` (2,000) caps container images per organisation; they don't count against the asset quota. One machine reports at most 512 containers, 256 images and 48 new images a day, and an image with more than 10,000 packages isn't read.
- **Image SBOMs:** an application's SBOM with `pkg:deb`, `pkg:apk` or `pkg:rpm` components is now judged as that distribution's packages, so an image SBOM uploaded before can open many findings at its next upload.

### Highlights
- **Containers are no longer a blind spot.** The agent already on a Linux host reads its running Docker and Podman containers: no sensor, no Docker socket handed to anyone. Each image is listed once on Assets, however many machines run it, with its base OS, where it runs and what's vulnerable in it, judged with each distribution's own rules exactly as a machine is.
- **Fix it once.** Fix first lists the container images to rebuild and the packages each rebuild must bring. When every machine that ran an image reports without it, its findings close; a machine going quiet closes nothing.
- **Never "clean" by accident.** An image with no package database, or one in a format not read yet, says "Not assessed" and why.
- **Image SBOMs from Syft and Trivy now count.** Their OS packages are matched with the distribution's advisories, end of support included, and their default CycloneDX 1.7 output is accepted (it was refused).

### Added
- **Container images** (agent 0.8.0, DECISIONS 138-141): the agent lists running containers with `docker` and `podman` (`ps`, `inspect`) and reads each one's os-release and package database (dpkg, distroless `status.d`, apk, rpm SQLite) through the container's own root. Each distinct image is one asset of the organisation, shared by every host that runs it, ranked by the most critical and most exposed host that runs it. New **Container images** view on Assets with each image's containers by machine; a machine's details list the containers running on it; the palette finds images. `POST /api/agent/containers`; `GET /api/assets` adds where each image runs; `GET /api/summary` adds `images_to_rebuild`; every finding carries `asset_kind`.
- **Image SBOM OS packages** (DECISIONS 142): `pkg:deb`, `pkg:apk` and `pkg:rpm` with a `distro` qualifier map to Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux, openSUSE Leap or SLES, with the source package from Syft's `upstream` qualifier, Trivy's `Src*` properties or SPDX `sourceInfo`. Real Syft and Trivy output for debian:11, alpine:3.18 and almalinux:9 gives row for row what the agent reads from the same image. The upload response adds `distro` and new skip reasons.
- `enroll --no-containers` and the Linux installer's `--no-containers`.

### Changed
- Remediation is planned only on a machine with an agent: an image or an application asset is refused by every planning path. Fix first's recommended fixes and the Findings bulk bar count machines only.
- The Container images and image findings say how an image is fixed: rebuild with the fixed packages, or a newer base image, and redeploy.
- The e2e accessibility checks now wait for a drawer's fade-in before measuring contrast.

### Fixed
- **CycloneDX 1.7 SBOMs were refused** with HTTP 422. Syft and Trivy write 1.7 by default, so an SBOM straight from either tool couldn't be uploaded.

### Known limits
- Not read yet: Kubernetes (containerd, CRI-O) containers, rootless containers, stopped containers and images at rest, Python, npm and Java packages inside containers, and rpm's Berkeley DB and ndb databases (RHEL 8 family, UBI 8, openSUSE images), which say "Not assessed".
- A container is seen while it runs at report time, so a short-lived job container's findings can open and close between reports.

## [0.9.3] - 2026-11-17 (preview)

Agent 0.7.3. No database migration. Fixes from a whole-repo audit and its review: update Linux and Windows hosts.

### Upgrade notes
- **Set `NIMSTEAD_PUBLIC_URL` if this server sends email.** Sign-up, password-reset, invitation and alert-confirmation emails now need it (Docker installs set it by default). Without it those emails aren't sent; alerts to recipients who already confirmed still are.
- **New limits:** 60 SBOM uploads an hour per asset and 30 ownership checks an hour per organisation (HTTP 429 beyond).
- **Single sign-on:** while an organisation requires SSO, invitations (and invite links sent earlier) are refused, and people join by signing in with SSO. Removing someone in People doesn't stop them signing in with SSO: remove them at your identity provider too.
- **`update.sh`** refuses to run after a rollback that failed until you restore the backup and delete `deploy/last-update.json`, and doesn't retry a release it rolled back unless you pass `--to`.

### Highlights
- **Automatic fixes stop when they fail.** Auto mode no longer repeats a fix that just failed on a machine, and a canary that failed a Windows update now halts that update everywhere.
- **Findings close only on proof.** A failed settings read, an expired certificate or a DNS timeout no longer marks issues fixed or un-verifies an internet target.
- **Linux fixes wait for unattended-upgrades** instead of failing on apt's locks, and a rollback restores through apt (proven on real Debian 13 and Ubuntu 24.04 hosts).
- **One organisation can't stall the server for the others:** every outbound fetch has a total deadline and a size cap, with new rate limits.
- **The offline evidence verifier catches a ledger whose newest entries were deleted.**

### Fixes that matter
- Password-reset links can't be pointed at another site with a forged `Host` header.
- Windows: no reboot loop when DISM is busy after a power cut during an update, and a failed runtime update never deletes the Python the agent's tasks start.
- One driver file in two folders no longer stops a machine's inventory from updating.
- The hourly re-match no longer judges a machine on facts from before it last reported.
- A fumbled authenticator setup no longer locks sign-in or alerts the whole organisation.
- Evidence packs no longer slow down with every hour of history when checkpoints are on S3.

### Security
- **Emailed links are built only from `NIMSTEAD_PUBLIC_URL`.** Without it, a password reset requested with a forged `Host` header mailed the victim a valid link to the requester's site. Sign-up, reset, invitation and alert-confirmation emails now need `NIMSTEAD_PUBLIC_URL` set, as they already needed SMTP.
- **One organisation can't stall or exhaust the server.** The ownership-proof fetch has a total deadline (a server sending one byte at a time held a worker for hours), ownership checks are limited to 30 an hour per org, webhook replies are never read, SSO provider replies stop at 1 MB, and SBOM uploads are limited to 60 an hour per asset, counted before the body is read.
- **The offline verifier catches a ledger cut off after its last checkpoint**: a signed checkpoint past the pack's chain head fails verification.
- Invitations are refused while an organisation requires SSO. The remove dialog says a removed person can sign back in with SSO until they're removed at the identity provider too.

### Fixed
- Automatic remediation no longer repeats a fix that just failed on the same host, and a canary whose stepped Windows update failed now halts that update's rollout.
- A failed settings read no longer closes every Windows setting finding; the hourly re-match reads each host as it is now; one driver file in two folders no longer stops a host's inventory; an expired certificate keeps its untrusted or wrong-name finding open; a DNS timeout no longer un-verifies an internet-facing target.
- A Windows update is handed out after a host's other jobs, and a fix isn't judged on an app list that was read only in part.
- Agent: no reboot loop when DISM is busy after a power cut during an update; apt waits up to 10 minutes for the package lock on upgrade and rollback (the rollback now installs the saved packages through apt), and retries its index refresh while apt's lists lock is held; a failed runtime update never deletes the Python the scheduled tasks start.
- Fumbling an authenticator setup no longer locks sign-in or alerts the organisation; a code in non-ASCII digits is refused instead of failing with an error.
- `update.sh` stops after a rollback that failed until the backup is restored by hand, and doesn't retry a release it rolled back unless asked with `--to`.
- Evidence packs fetch each S3 checkpoint once per process, and the hourly chain check keeps hashes only at checkpoint positions.

## [0.9.2] - 2026-11-16 (preview)

Agent 0.7.2. No database migration. A security release for the Windows agent: update Windows hosts.

### Highlights
- **A standard user on a Windows host can no longer aim the agent's folder lockdown, or its key, at a folder of their choice.**
- **Winget fixes run only on an app installed at the planned version**, so a compromised server can't add an app or move one to an older build.
- Both were proven on real Windows 11 VMs, including a standard user racing to swap the folder during install.

### Security
- **Windows agent: a standard user can no longer redirect the folder lockdown.** A user who created `C:\ProgramData\Nimstead` before install could keep a handle open and swap the folder for a junction while the agent locked it down. SYSTEM would then lock, delete in, and write the agent key into a folder that user chose. The agent now moves such a folder aside and creates a fresh one that only SYSTEM and Administrators can open.
- **Windows agent: winget fixes check what's installed.** The agent ran winget after comparing only the two versions the server sent, so a compromised server could install a curated app that wasn't there (TeamViewer, AnyDesk and VNC servers are in the list) or force an older build. It now runs only when the registry shows that exact product at the planned version, and the fix is newer.

## [0.9.1] - 2026-11-14 (preview)

Agent 0.7.1. No database migration. Released after the design-critique and repo-audit work below; the 2026-11-13 build was never published.

### Upgrade notes
- **Findings opens on every open finding.** "Fixable only" is now an opt-in **Has a fix** filter. Old links and saved views with `fixable` show every finding; add Has a fix to narrow them again.
- **Vault key rotation:** evidence packs now list earlier public keys, and the new `verify.py` accepts checkpoints they signed. Give auditors the new `verify.py` and its SHA-256.

### Highlights
- **Rollouts.** A fix planned on several machines shows as one card on Remediation, with canary and broad tallies and where it stands. You can approve a whole ring in one review. A ring where the fix already failed says so first.
- **Fix first is a queue.** Failed fixes come first, then the fixes you can plan from here, then machines not reporting and devices with issues. Plan fix stays on the page, so you can plan several in a row.
- **Devices with no agent** get their own view on Assets, with search, a drawer per device, and ranking by what an exposure lets an attacker do. Redis with no password on a camera is now Fix now, not Routine.
- **Help in the app** (`?` or Ctrl K): the words used, how priority and rollouts work, and every shortcut. Ctrl K also finds packages, machines and devices.
- **Quieter screens.** Filters sit behind "More filters", long explanations sit behind "How this is judged", and dialogs scroll on phones with their buttons in view.

### Fixes that matter
- Auto-rollout no longer pins broad machines to an old canary's version that doesn't fix this month's issue (it used to abort and re-plan every 15 minutes).
- A reopened finding is timed from when it came back, not from a detection fixed months ago.
- A resolved finding can't be accepted as a risk, and an anonymous SBOM upload is refused before its body is read.
- The agent writes its configuration and job state atomically, so a full disk or power cut can't wipe `agent.json`.
- Fix jobs that changed nothing no longer report "applied": apt, apk, zypper and dnf abort when there's no upgrade, and part-failed Windows fixes roll back.
- A job that applied but is never confirmed fails after 7 days with a reason, instead of staying "verifying" for good.
- One organisation's S3 or Vault outage no longer stops the hourly alerts and release check for all the others.
- No more false regreSSHion (CVE-2024-6387) findings on OpenSSH 9.8 or OpenBSD's sshd.

### Changed
- Confirmation dialogs are wider (36rem), so package lines fit on one line. Evidence's four numbers sit 2x2 on phones. A rolled-back job on a machine production remediation won't change no longer shows retry advice it can't act on.
- An aborted fix's "Plan again including …" on Fix first names its machine, as every plan button does (`last_attempt.asset_id` in `/api/summary`). In a ring review, "on 3 of 4 machines (not …)" sits on its own short line. The Internet targets empty state says how to add one.
- Fix first's plan button for a fix already in flight says how many are planned ("Plan fix on 16 more machines (1 already planned)"), counted from the same machines as "17 of 35 fixable here". On phones the priority counts sit under "Open findings by priority". A machine that isn't reporting says so once in its drawer.
- Wording: "not reporting" everywhere, "All assets" in the Assets filter, "No internet targets yet", "Approve 4 machines and run", and an aborted job names the packages it will add. A rollout lists its canary machines before its broad ones again; the card already names what broke.
- In approve dialogs, cautions (no health checks, self-approval) are amber; crimson is kept for a failure of this fix. Settings' save buttons name their section ("Save trust level", "Save soak time", "Save deadlines", "Save window"). Stepping through findings announces the same position the drawer shows.
- A job card says who planned and who approved it on one line ("planned and approved by …"). Fix first's priority counts say "findings". A rollout's machine list reads "Machines (3, plus 1 cancelled)", matching its title. "Not reporting" is amber, a caution, not crimson. The Devices tab shows how many have findings, not every count at once.
- Both approve dialogs give the no-health-checks warning in the same words and place, after what changes. A rollout's tallies say "approved or running", matching the statuses in its machine list.
- A failed job's status reads "Didn't work", the glossary's word. Remediation sections count fixes (a rollout is one fix). In the approve dialog the ring-failure warning leads, and the no-health-checks note is one line after the packages.
- A rollout card names the machines its fix didn't work on, each a link to its job, before its approve buttons. A ring review names the machines a package isn't on ("on 3 of 4 machines (not cache-dev-32)"). The finding drawer's score disclosure reads "How this is judged".
- The single-machine approve dialog gives the same first warning as ring approval when this fix didn't work on a machine in its ring, and each named machine opens its job. Inside a rollout, the ring with a failure is listed first.
- Approving a ring says first, in crimson, when this fix didn't work on a machine in that ring. Approve dialogs put the operational risk (production off, no health checks, can't be undone) before the machine and package lists, and their buttons stay in view while a long dialog scrolls. A job's time names its event ("failed 4 minutes ago"), so it never reads as the approval time. Inside a rollout, each ring lists what broke first, then what waits, then what's running, then what's done. On Fix first, an aborted fix that needs more packages has "Plan again including musl" as its button.
- Disclosures share one look (the chevron, no underline) and two labels: "How this is judged" where something is judged, "More about this" otherwise. On phones, Fix first's notices sit one per line, the approve dialog lists one machine per line, and Findings' "Download as CSV" is a text link.
- "Plan fix again" names its machine, and where production remediation is off says it can't be planned here instead. On Fix first, an aborted fix that needs more packages links straight to "Plan again including musl". On Assets, Add machine and Add application show only on the machines view. Evidence's Cyber Essentials row says its 14-day count is a different measure from the priority deadlines. The production setting name breaks only at its underscores.
- Every disclosure has the same chevron that turns when open. A rollout card no longer repeats "approve the broad machines" beside its approve button. The filters button reads "More filters" on phones and desktop, with a count only when some are on, and sits after search on Assets as on Findings.
- A rolled-back job says which service didn't start after the upgrade and how often it restarted, with the machine's own text under "What the machine reported". Rollout titles name their target version. Plan fix buttons all read "Plan fix on …". Job statuses say "machine", not "host". The approve dialogs put "How a fix runs" behind a disclosure. Settings disclosures read "More about this" where nothing is judged. Each enrolment token says "Test machines" or "Any machine".
- Fix first names overdue findings first in its line of links ("6 findings overdue"), the same count as Findings' Overdue filter. Devices count findings, not issues; Remediation sections say "7 jobs". Help defines overdue. Clicking a Settings section marks it even when it's too short to scroll to the top.
- On phones, Fix first's priority counts sit in one row so the first recommended fix starts on the first screen, and Findings cards label the score and host. Evidence says Cyber Essentials' 14-day count once, on its card. People, API tokens and single sign-on open with one sentence, the rest behind "How this is judged".
- A rollout's machines are listed under Canary and Broad, and its tallies say "in progress" for approved and running machines alike. Inside a rollout, a machine's card drops what the rollout already says (what it fixes, who planned it). Only versions are set in mono. Devices "with findings", not "with issues"; the first Assets view is "Machines and applications"; Help defines asset and ring. The Assets view tabs fade at the edge on phones to show there are more.
- **A rollout's approve dialog lists every package any chosen machine changes**, with "on 2 of 4 machines" where they differ; before, it showed only the first machine's packages.
- The finding drawer puts "Act on it" straight after the priority and deadline, and dims the last finding while the next loads. A narrowed Findings list says "37 of 43,944 findings". Evidence's SI-2 says "6 open findings past SLA" before "27/27 fixes within SLA". Machines are "machines" on Fix first, in Plan fix and in Windows updates. On a job card, Cancel fix is a trailing link after Review and approve. The Devices tab's "with issues" count is ink, not crimson. Versions and the production setting no longer wrap mid-token. Help puts focus on its title.
- **Help opens in the app** (sidebar Help, `?`, or Ctrl K): the words used here, how priority and rollouts work, and every keyboard shortcut, with the full documentation one link away.
- Findings rows are 36px from tablet width up, with the installed and fixed versions on one line. Stepping through findings keeps the last one on screen until the next loads, and the drawer no longer repeats KEV and CVSS already stated in "Why it's ranked here".
- Assets' agent notices are one line of links, and its view tabs scroll sideways on phones instead of stacking. Evidence names each "late" count by its rule (a priority's deadline, or Cyber Essentials' 14 days).
- **A rollout shows once on Remediation** (DECISIONS 136): one card per package fixed on several machines, with canary and broad tallies, where it stands, ring approval and every machine's job inside. It sits in the section of its most urgent machine, so a failed canary puts it under Needs attention. The separate Rollouts table is gone. A production machine while production remediation is off says "Can't run: production remediation is off" instead of offering approval. Approve buttons on cards are quiet.
- **Toolbars show six controls or fewer before the first row.** On Findings, priority, KEV, Overdue and Has a fix sit behind one "More filters" button that shows how many are on. On Assets, the filter chips are one "Show" menu.
- The finding drawer says where you are in the whole result ("12 of 43,970") and steps past the first 500 by loading more.
- Fix first's machines-and-devices notices are one line of links under the heading, not a second box below the fixes. Ctrl K shows vulnerability IDs in mono. The ledger folds any run of one kind (sign-ins, approvals) into one row; a failure is never folded.
- **DESIGN.md** writes down the design system and the rules it runs on: one word per idea (finding, fix, job, rollout, resolved), a copy budget, one action row, names open and arrows navigate, and how things save.
- A job's title has one format: "Upgrade curl to 8.5.0-2ubuntu10.16 on web-1". How many vulnerabilities it fixes is shown on the job card, not in the title. Jobs planned before keep their wording.
- Long explanations sit behind "How this is judged": one sentence shows, the rest opens (Evidence, Settings, Devices, baselines, attack paths). Every Fix first card has the same two lines: its labels (with "4 of 35 fixable here" when production remediation is off), then what it fixes and where.
- A job card's host opens that machine on Assets. Fix first cards put their action first and their links underneath, in the same order on every card. Each agent notice on Assets has one link. Evidence counts "resolved findings", not "fixes".
- **A device with no agent ranks by what its exposure lets an attacker do** (DECISIONS 133). A service with no password by default (Redis, Elasticsearch, MongoDB, Memcached, the Docker API) is at least Fix now. Telnet, FTP, VNC and an exposed `.git/config` or `.env` file are at least Next. Expired certificates and legacy TLS keep their rank. A device never outranks the same exposure on the internet. Telnet on a camera used to rank Routine, due in 90 days. Existing findings take the new rank at their next network check.
- A network check's remedy reads "Remedy: a configuration change" instead of "Fix available"; banner CVEs, fixed by an upgrade, keep "Fix available".
- **Devices with no agent are a table** below the machines on Assets: those with issues first, with a search across address, maker, MAC and the machines that saw them, a "With issues" filter, and 25 rows at a time. Each device opens a drawer with what its network check found, a link to review those findings, and its maker, MAC, addresses, first and last seen and every machine that saw it. When devices have issues, a line at the top of Assets says so.
- Evidence counts assets as the Assets page does, with devices with no agent counted apart (`network_devices`). A device's findings stay in the report with host `device`, as in the ledger, so its address isn't in the pack.
- Findings can narrow to one distribution or ecosystem (`?eco=Debian:13`, API `ecosystem`), shown as a removable "Distribution" chip. Fix first's "View findings" links and a package picked from Findings' "By package" view use it, so they land on that package's own fix rather than every distribution's.
- **Findings opens on every open finding**, by risk (DECISIONS 135). "Fixable only" is now **Has a fix**, an opt-in filter that says what it means: a fix exists (a fixed version, a setting to change, or a service to close), whether or not Nimstead can apply it. With it on, the count reads "16,872 with a fix, of 43,970 results". An older link or saved view without `fixable` now shows every finding too; add **Has a fix** to narrow it again.
- **Fix first lists only the fixes that can be planned here**. One line under them says these are the top fixes by risk, not every one, names each top fix that can't be planned from here with its priority label and KEV badge, each a link to its findings, and links to every fix by package.
- A rollout's "Where it stands" says what's waiting on you ("Canary fixed: approve the broad machines"), not that the broad machines will follow by themselves.
- Planning a fix on more than two machines lists them all in a short confirmation first ("Planning changes nothing: each machine's fix waits for approval"); one or two machines are named on the button.
- Ctrl K shows one row per package, with how many distributions and hosts it spans ("openssl · 4 distributions · 203 hosts"), opening Findings grouped by package, where each distribution is listed; it no longer leaves stale rows or traps the arrow keys. A search with no match says "No matches." When a search matches host names, a vulnerability's host count says so ("2 hosts matching "db-prod""). The approve dialog says it runs the machine's health checks "if it has any", so it no longer contradicts a missing-checks warning. On phones a fix's version stays on one line, and the plan confirmation says "test machines" when that's all it can plan.
- Ctrl K says "No matches" when only the findings search is left, instead of "1 result", and closing it returns focus to the page heading when nothing was focused before. Low has no mark, so it no longer looks like an empty cell, and a cancelled job's note is plain text, not an error box.
- Ctrl K's commands sit under headings (Go to, Shortcuts, Machines, Devices, Packages, Vulnerabilities, Search, Account and help).
- After stepping through findings with j/k, Esc returns focus to the finding you were on, not the one you opened.
- **Self-approval is said once per Remediation section** ("All 3 self-approved: approved by the person who planned them, with no second approver (SOC 2 CC8.1)") instead of a label on every job; each job still shows who planned and who approved it.
- Fix first opens on the recommended fixes. Failed fixes and machines that need a look are one line under the heading, with the detail after the fixes. A fix's status sits with its priority, so its actions stay on one line.
- In the Findings table, j and k (or the arrow keys) move between rows, as they do in the drawer. On phones, a row's checkbox sits at its edge instead of between the ID and its priority.
- Screen readers hear which finding, package and host each row, "View findings" and device-issue link is for.
- **Plan fix stays where you are** and says what it planned ("Planned on web-prod-02: awaiting approval"), with a link to review and approve it, so several fixes can be planned in a row. On Fix first, a fix for one test machine names it on the button.
- Fix first is a queue: fixes that didn't work come first, each a direct link to its job. Machines not reporting, agents that can't update, and devices with no agent that have issues (new `devices_with_issues` in `/api/summary`) are listed after the fixes, each linking to the machines concerned. A fix's host list expands in place.
- A device's drawer lists each issue with its priority, port and what to do, each opening that finding. Ctrl K finds a checked device by address or maker and opens its drawer (`/assets?device=<mac>`). Ctrl K no longer opens on top of a drawer.
- "Has a fix" says how many findings it hides.
- Approving a fix on a machine with no health checks warns that a service the upgrade breaks isn't noticed or rolled back, with a link to set them.
- Evidence says why a deadline control isn't met when every fix was on time: an open finding past its deadline. The NIS2 and CIS 7.3/7.4 evidence now includes the count of open findings past SLA.
- **Assets has three views**: Machines, Devices with no agent (with a count of those with issues on the tab) and Internet targets (`/assets?view=devices`, `?view=internet`). A device link opens its view.
- Evidence leads with how many controls aren't met and what is overdue. Mean time to remediate and "resolved within SLA" say how many fixes they rest on. When Cyber Essentials' "open past 14 days" differs from "Overdue", one sentence says why.
- A recommended fix says how many of its machines can be fixed from here while production remediation is off ("Only 2 test machines of the 88").
- Each priority has its own mark as well as its shade: filled for Fix now and Next, outlined for Routine, a dash for Low.
- Certificate findings say "1 day" or "49 days", not "day(s)".
- Planning fixes for a selection of findings plans only on machines this server may change: with production remediation off, test machines only, and the bar says so ("Plan 2 fixes on 1 test machine"). It used to offer plans the server then refused.
- **Remediation shows rollouts**: a fix planned on several machines is one row, with how many canary and broad machines are fixed, running, awaiting approval or didn't work, and where it stands ("Waiting on the canary machines", "A canary didn't work: review it before the rest go"). Each machine is still approved on its own card.
- **A rollout ring's waiting machines can be approved in one review** ("Approve canary (2)", "Approve broad (4)" on its Rollouts row). The review has a checkbox per machine, so you can approve the whole ring or just one test device. The broad ring's approval waits until the canary machines are fixed. Approving one broad machine on its own card ahead of the canary still works, and the dialog now says it's ahead of the canary. The dialog lists the machines and the package change, warns about machines with no health checks and about self-approval, and approves each machine separately: one ledger entry and one self-approval check per machine, as when approving them one by one. Production machines while production remediation is off, and fixes that can't be undone, stay on their own cards.
- Approve dialogs put the operational risk first and loudest: no health checks set (red) above the self-approval note (now neutral).
- In the machine drawer, Delete sits apart at the bottom as a danger action, with what it removes; the Ring and Health units notes show for machines only.
- A recommended fix says "1 of 35 can be fixed from here (test machine)"; why is said once, above the list.
- Fix now is a solid red label, the strongest mark on the page; Next, Routine and Low step down from it.
- Remediation lists jobs that need attention first, then those waiting for approval, then those running. Within each, three or more machines for the same package fold into one block ("curl on 4 machines"), which opens to their cards; a link to one of them opens it.
- In Findings, j or k starts at the first finding from anywhere on the page. The drawer's key hint lists only the keys that do something for that finding.
- Plan fix shows which machines it will plan before you click ("On db-staging-12 and auth-prod-30"). An empty Findings list no longer offers "show all".
- Devices with no agent show and sort by their most urgent issue's priority, as machines do (`checked.priority` in `/api/network/unmanaged`).
- Ctrl K finds packages ("Package: curl (Ubuntu:24.04) · 4 vulnerabilities · 88 hosts", opening Findings grouped by package), and `?` opens a list of every keyboard shortcut.
- The evidence ledger folds a run of sign-ins into one row ("17 sign-ins") that opens to every entry, so decisions and fixes aren't pushed off the first screen.
- Ctrl K offers a machine first ("Machine: db-prod-01", its details) and its findings second ("Findings on db-prod-01").
- The machine drawer says that its changes save as you make them and that Undo takes back the last one; Settings' org-wide sections keep a Save each.
- Approving a fix on a production machine while production remediation is off isn't offered: the dialog says the fix can't run yet and links to how to turn it on. It used to record an approval for a job the server then refused.
- Fix first lists the fixes you can plan from here first; those that can't be planned from here (their own updater, or production machines while production remediation is off) follow, still in risk order.
- The finding drawer's title shows the host and where you are in the list ("auth-prod-15 · 2 of 500 loaded"), so stepping with j/k visibly moves.
- Ctrl K's vulnerability results show the real number of hosts each is on, not a count within its first 30 rows.
- A job's status is an outlined label with its own icon (aborted, rolled back, awaiting approval…), so it no longer looks like a priority.
- CSV downloads are labelled "Download as CSV" everywhere. A finding description cut off at 200 characters points to the advisory for the full text.

### Fixed
- **Auto-rollout no longer pins broad machines to an old canary's version** (DECISIONS 137). A canary vouches for, and pins, a Linux fix only if what it installed reaches that fix; before, last month's canary could approve this month's job and pin it to a version that doesn't fix it, which aborted and re-planned every 15 minutes or came back not fixed.
- **A reopened finding is timed from its return** (DECISIONS 137), in the evidence pack and its due date, not from a first detection that was fixed months ago.
- Fix first counts every fix in flight as already planned; it stopped at 50 jobs, so a large fleet was offered plans the server then refused.
- A resolved finding can't be accepted as a risk (409); accepting it dropped a real fix from the evidence counts.
- An SBOM upload is authenticated before its body is read, so an anonymous caller can't make the server buffer 10 MiB.
- The ledger integrity check streams entries instead of loading the whole history at once. A domain controller's job poll no longer loads every asset unless it has a Windows job to hand out, and the summary reads only the host columns it counts. One list defines a failed job, and one rule guards every CSV export against formulas.
- Confirmation dialogs never grow taller than the screen: a long machine list scrolls inside, so Cancel and Approve stay reachable on a phone. The finding drawer's host opens that machine. A rollout's machine list counts cancelled machines in its total ("Machines (4: 1 cancelled)"). Evidence's tile says "Overdue findings". Fix first's and Assets' notice links are 44px touch targets on phones.
- A rollout counts each machine's newest job, so a canary fixed after a failed attempt counts as fixed and the broad ring can be approved. Approving several machines unticks each one as it's approved, so a retry after a partial failure sends only what's left. Stepping past the last loaded finding no longer jumps ahead later when the next page is empty. A break-glass sign-in is never folded with the sign-ins after it. The Ctrl K help command opens Help.
- Agent update notices name an agent that reported no version "unknown" instead of showing an empty label ("(2)"), and count machines per version.
- An end-of-support finding (for example .NET 8) no longer closes, and reopens on the next report, when the agent couldn't read the Microsoft products or Uninstall list it is judged from; those false fixes no longer reach the ledger. A remote scan, which never reads signed-out users' profiles, still closes Microsoft product findings.
- A servicing stack update that installs and then fails its check is reported as needing attention (`rollback_failed`); the server used to refuse the report, so the job only timed out.
- The agent writes its configuration, Windows job state and job outcomes whole (temporary file, then replace), so a full disk or power cut can no longer leave `agent.json` empty and the agent key lost.
- A fix job that applied but is never proven by a full inventory fails after 7 days with a reason, instead of staying "verifying" and blocking that fix on the machine for ever. That timeout doesn't halt automatic rollout: a switched-off machine is no evidence against the fix.
- In the hourly run, a checkpoint that can't be written for one organisation (S3 or Vault down, a damaged checkpoint file) no longer stops alert retries, "not reporting" alerts and the release check for every organisation.
- External and network scans no longer report CVE-2024-6387 (regreSSHion) for OpenSSH 9.8, the fixed release, or for OpenBSD's own sshd.
- The scan report judges an advisory that names several CVEs on the worst of them (known exploited, highest CVSS), as its finding already did, so the two no longer disagree.
- A fix job on Debian for a package installed for two architectures (amd64 and i386) is refused with that reason before anything changes, instead of as "drifted"; multi-arch upgrades are not supported yet. Only installed copies count: leftover configuration of a removed architecture doesn't.
- apt, apk and zypper fix jobs abort with "the package source offers no upgrade" before taking a rollback copy, instead of reporting "applied" with nothing changed. A dnf dry run that prints an empty summary is refused the same way (one with no summary was already refused).
- A Windows app or setting fix that fails part way (Click-to-Run takes an update but doesn't report the new build in time, the second registry view can't be set, a winget installer fails) is rolled back, or reported as needing attention, instead of "No changes made".
- A rolled-back Linux fix no longer halts automatic rollout of that package for good: a later success that installed at least the versions the failed job aimed at lifts the halt (Windows updates were already judged per month).
- A failed advisory query during the hourly re-match no longer hides that package's advisories from every later host in the same run.
- A fix job with more than 200 steps (a rolled-back apt job of about 60 packages) is reported with its first and last 100, instead of being refused by the server and retried for ever.
- The jar scan stops at 20,000 packages and says it is partial, like the app scan, so a large build server's inventory stays under the server's size limit instead of being refused whole.
- Cancelling a job, an agent's report and the 2-hour timeout now take the same lock as approval, so a cancel can't overwrite a job a machine has just picked up and a timed-out job is failed (and alerted) once.
- The hourly checkpoint reads only the newest checkpoint (one S3 object, not every one), chain checks load the signing key once, and the Evidence page no longer loads every checkpoint.
- After a Vault signing-key rotation, checkpoints signed with the old key no longer read as tampering, so evidence packs still build. Each pack lists the earlier public keys under its own signature, and `verify.py` accepts checkpoints signed by them; auditors still pin only the current fingerprint. Fetch the new `verify.py` and its SHA-256. If an old key leaked, raise the transit key's `min_decryption_version` above it: checkpoints it signed then show as bad signatures.
- PowerShell output is read as UTF-8, so names like "Intel®" no longer arrive as "Intel©".
- SBOM uploads are buffered without copying the body on every chunk, and an ecosystem name can no longer add a path segment to the OSV download URL.

## [0.9.0] - 2026-11-12 (preview)

Agent 0.7.0. One database migration (`b7d2e4f6a813`, neighbour rows and device facts): the Docker image applies it on start; without Docker, run `alembic upgrade head`. Network checks are off unless a machine is enrolled with the local `--allow-network-checks` opt-in; an agent older than 0.7.0 keeps working and sends no neighbour table.

### Added
- **Devices with no agent** (agent 0.7.0, DECISIONS 128): each agent reports its machine's own neighbour table (ARP/NDP) and its own addresses, read only. Assets lists the devices on your networks that none of your agents accounts for, with their maker from the IEEE registry, which machines saw them and when, and a CSV download. Nothing is sent to those devices. Rows are deleted 30 days after they were last seen. Turn it off on a host with `"neighbours": false` in the agent's configuration. One migration (b7d2e4f6a813).
- **Network checks for devices with no agent** (agent 0.7.0, DECISIONS 129): a machine enrolled with `--allow-network-checks` (a local opt-in the server can't set) checks up to 32 devices it already talks to on its own private subnet, every report, with the same read-only checks as the external scan. Unauthenticated or cleartext services (Telnet, FTP, VNC, Redis, Elasticsearch, MongoDB, Memcached, the Docker API), expired certificates, legacy TLS, exposed `.git/config` and `.env`, and vulnerable banners become findings on the device, which close only on evidence. The server never chooses what is checked.
- Each external target shows **what its last scan checked**: every port's result, what couldn't be determined and why, and each finding's confidence (`GET /api/assets/{id}/scan-report` now answers for targets).
- External scans open findings for **exposed `/.git/config` and `/.env`** files (read-only requests, each after a negative control, so a site that answers every path with a page opens nothing), and for **vulnerable versions in service banners** (vsftpd 2.3.4, ProFTPD 1.3.5, OpenSSH regreSSHion), graded unverified and ranked below exposures read directly (DECISIONS 127). Every request a scan sends is in its ledger entry.

### Changed
- External targets are scanned by the detection engine's prober, once per scan (DECISIONS 126). **A finding now closes only on evidence**: a refused port, or a TLS handshake that no longer shows the problem. A port that a firewall drops, a timed-out check or a target that stopped answering keeps the finding open with a "Still open" reason, where it used to close. The scan result gains `still_open`.
- External findings are keyed by vulnerability and endpoint, so the same banner CVE on two ports is two findings.
- A greeting or version cut off mid-line, or one that hides its version but still names the product, no longer closes a banner CVE; a MAC seen at several addresses at once, or a web check whose control got no answer, is no longer judged; a hostile banner can no longer make a device report fail on PostgreSQL; one host claiming an address hides at most one device there, and holds at most 256 device views; network checks write one ledger entry per report (DECISIONS 132).
- A TLS 1.0/1.1 try that is reset or times out no longer closes NIM-TLS-LEGACY, on external targets or devices; only a refusal does. A host can no longer hide devices through its `addresses` fact unless it is an agent before 0.7.0, and then for at most 64 addresses. Deleting a host removes the device views it made; device reports say "on your network" throughout; the device list is limited per person or token, and shows when it couldn't be read (DECISIONS 131).
- Network checks keep a separate view of each device per machine that checks it, so one machine's report never closes another's finding. The agent judges web paths itself and sends only facts, never file contents. A banner finding closes only on a positive greeting. Every device is reached over a few runs (random start), no device can stall the agent, network-check reports and the device list are limited per organisation, neighbour rows are capped, and devices' addresses and MACs stay out of the permanent ledger (DECISIONS 130).
- A TLS handshake on 443 that is cut, reset, times out or is refused is now undetermined instead of "not a TLS service", so it no longer closes certificate findings, and a server that speaks only TLS 1.0/1.1 now opens the legacy-TLS finding (it used to open nothing). A web path missing from an agent's network-check report keeps its finding open, and a neighbour that is one of your own machines is never checked as a device.

## [0.8.0] - 2026-11-11 (preview)

### Changed
- The detection engine is now the only thing that decides which findings exist for the Windows OS, Microsoft products, curated Windows apps, distribution packages, language packages and SBOMs (phase 5 of `tasks/plan-engine-findings.md`, DECISIONS 125). The earlier matching that ran beside it as a check is removed, with its `engine_disagrees` ledger entries and the `NIMSTEAD_ENGINE_FINDINGS` setting.
- **Agents older than 0.5.0** (they send no collection document) get no new findings. Their open findings stay open with a "Still open: the agent doesn't say what it managed to read" reason until the agent is updated. Agents from 0.5.0 on are unaffected, unless the server rejects their document as malformed or too long: that host is treated the same way, and the server log gives a warning naming it. Settings, drivers and Windows end-of-support findings are unchanged.
- If the engine fails on a host, that reassessment opens nothing in its slice and closes nothing.

## [0.7.8] - 2026-11-10 (preview)

### Fixed
- A network web check that gets no HTTP response (a timeout or reset) is now undetermined (`host-lost`) instead of not vulnerable, so it can't close a real finding.
- An external target's legacy-TLS finding no longer resolves when a scan couldn't test legacy TLS (the scanner's OpenSSL can't offer TLS 1.0/1.1).
- A webhook that answers with a redirect (3xx) is now a failed delivery, and retried, instead of counting as delivered: redirects aren't followed, so the alert never reached the receiver.
- **Send test alert** with no usable destination is refused (HTTP 409) instead of answering `queued=true` and sending nothing.
- A host whose agent is newer than the one this server serves shows as current, not "updating": agents only move to a newer release.
- The server stores release files only after their signature checks, a cached manifest with a missing or bad signature is fetched again instead of skipping the fetch, and the running channel in Settings comes only from a verified manifest.
- An end-of-life date from endoflife.date that isn't a real date (`2026-99-99`) is refused when fetched, keeping the stored cycles, instead of breaking lifecycle checks later.
- A CVSS score of 0 is kept in a verdict's record, so it no longer hashes the same as no score. The detection engine's version is now 4.
- Agent 0.6.9: a signed release manifest whose `agent_sha256` or `commit` is a JSON number instead of a hex string is refused as malformed.

### Changed
- Evidence packs describe their controls more exactly. The reporting control counts assets with a report in or after the period. CC8.1 counts changes with an approver recorded, which doesn't prove execution, health checks or rollback. The basis notes that a resolution can reflect changed observations or advisory data. Older packs still verify.
- Agent 0.6.9 also carries corrected help text and messages (`--scan-apps`/`--scan-jars` budgets are soft; `doctor`, `run-job` and `resume-job` no longer claim to use no network; uninstall says the ledger is kept), plus interface docstrings. Collection and remediation behaviour is unchanged.

### Added
- About 65 documentation pages (how-to, reference, explanation), also published at <https://docs.nimstead.systems/>. The OpenAPI schema and endpoint catalog are generated by `scripts/export_api_docs.py`.
- Contract tests that check API responses and documented fields against the reference pages.

## [0.7.7] - 2026-11-09 (preview)

### Changed
- A finding now closes only on evidence that it's fixed or no longer installed (phase 4 of `tasks/plan-engine-findings.md`, DECISIONS 124). If the agent couldn't read what a finding is about, for example a package scan cut short, the finding stays open and says why. A product that's uninstalled, dropped from an SBOM, or left behind by a distro or Windows upgrade still closes, once the list that would show it was read in full.
- A finding whose advisory is withdrawn, or filed again under another id (a GitHub advisory that later gains a CVE), now closes instead of staying open beside its new id. A package fixed by hand on a distro release past end of support now closes too.
- The agent is unchanged (0.6.7), so installed agents don't update for this release.

### Added
- A weekly check of the matcher and the detection engine against OSV's live answers (`.github/workflows/oracle.yml`).

## [0.7.6] - 2026-11-09 (preview)

### Changed
- Findings open from the detection engine's verdicts (phase 3 of `tasks/plan-engine-findings.md`, DECISIONS 123). Where the engine judged a vulnerability, its verdict decides; where it couldn't (an old agent, a source that failed), the previous matching stands. A difference between the two goes to the evidence ledger as `engine_disagrees`. `NIMSTEAD_ENGINE_FINDINGS=0` restores the previous matching.
- Linux hosts past their release's end of support now get a fix-now finding, as Windows hosts already do.
- The engine now runs on the hourly re-match as well, sharing that pass's advisories, so findings there follow the same rule.

### Documentation
- Add tutorials, task guides, API/agent/SBOM reference, and an explanation of the inventory-to-evidence flow.
- Document public server, agent, tool, and web interfaces; add a repeatable coverage and local-link check.
- Correct development command working directories and the minimum Node 22 version required by locked test dependencies.
- Agent documentation changes its signed bytes; bump the agent to 0.6.7 so a future signed release can distribute it. Collection and remediation logic are unchanged.

## [0.7.5] - 2026-11-09 (preview)

**Agent 0.6.6.** No database migration. A UI review at fleet scale (a demo of 206 machines and 44k findings), run as rounds of Impeccable critique and audit with fixes between them. axe finds no violations at 1440 and 375 in light and dark.

### Added
- **Bulk actions on Findings**: select findings, then plan one fix per package on every selected machine, or accept the risk with one reason. Each acceptance is its own ledger entry (`POST /api/findings/accept-many`).
- **Saved views** on Findings, also in the Ctrl K palette. They're kept in the browser.
- **Findings**: sortable, sticky headers; grouping by vulnerability or package (split by distro, naming the version that clears the group); the true total; pages of 500 rows loaded as you scroll; j/k, p (then Enter) and a in the finding drawer.
- **Assets**: one line per machine with search, filters and sort kept in the URL, bulk edit with Undo, and each machine's settings in a drawer.
- **Remediation**: Review and approve lists each package and its target version, names the target machine, and warns before you approve your own plan. Steps that fell back show as recovered; a jump link focuses the failed step.
- **Evidence**: a summary-only report (`?summary=true`), ledger filters, a note when a control rests on few fixes, and "Met, with exceptions" for self-approved changes and machines not reporting.
- An in-app page for unknown addresses, and a clear message for links to findings that no longer exist.

### Changed
- **API responses are gzip-compressed**, and content-hashed web assets are cached for a year.
- `GET /api/findings` takes `sort`, `offset` and `view=list` (the table's columns only); new `/api/findings/count` and `/api/findings/groups`.
- Text follows the browser's text size (the root was pinned to 15px); the smallest text is 12px.
- Plan fix offers only machines the server will change while production remediation is off.

### Fixed
- **The agent reported "sha256 mismatch or missing" on a rollback artefact check that passed** (agent 0.6.6).
- Grouped views compared versions as text ("2.9" above "2.18").
- Advisory text was cut mid-word.
- Keyboard focus was lost after the command palette closed, and on the first visit to a page that loads on demand.
- Focused controls could hide under the phone tab bar.

## [0.7.4] - 2026-11-08 (preview)

**Agent 0.6.5.** One database migration (two columns on assets), applied on start; run `deploy/update.sh`. Fixes from a full code audit. Every fix has a test that fails without it; API suites pass on SQLite and PostgreSQL, and the platform-update lab passes including its rollback.

### Fixed
- **Two ledger writes at once could fail or fork the chain**: ledger appends now lock the organisation first. One failing host no longer stops the hourly rescan of the rest.
- **Accept risk crashed the findings drawer** (React hook order).
- **A fix was judged "not fixed" from an inventory that kept the old package list**: jobs are verified only on an inventory that replaced it.
- **A host read as clean when a Windows source failed or came back empty**: findings from that source stay open until it reads again.
- **dpkg packages with pending triggers were dropped** (agent 0.6.5): the `iW` and `it` states are reported.
- **One fix record covering several CVEs was ranked by its first CVE only**: KEV, EPSS, CVSS and exploit data now count every CVE, and the summary names the others.
- **Two domain controllers could be planned or dispatched together** under concurrent requests: plan, approve and dispatch lock the organisation.
- **Accepting a finding mid-verification counted the fix as a success**: accepted findings count as not fixed.
- **A failed update's rollback lost job reports written after the backup**: `deploy/update.sh` saves a second dump before restoring.
- **Promotion to beta or stable didn't reach servers that had cached the preview's release files**: they're fetched again while below the server's channel. The release check no longer looks at only the last five tags.
- **One release's failure halted every later Windows release**: a canary failure halts only its own release.
- **A timed-out Windows install could overlap the next**: a timed-out job holds the host for the timeout margin. A held job still answers the kill switch and the canary and suggest-mode gates first.
- **Silent-host alerts fired for hosts that never reported.**
- **Old notification records were kept forever**: they're deleted after 90 days.
- **The agent crashed on a malformed jobs answer** (agent 0.6.5), and a Windows job's target build is checked as a number before anything runs.
- **Settings' server section loaded forever on an error**, the findings search box dropped a trailing space, the finding drawer saw only the newest 500 jobs, and the ledger note counted the wrong set.
- **Versions the matcher couldn't compare were skipped silently**: they're logged.

### Changed
- **"Plan the rest" plans every host in one request** (`POST /api/remediation/jobs/batch`).
- **Faster at 1000 hosts**: ingest 1.43 to 0.86 s, the Assets coverage count 1.7 to 0.3 s, and the next evidence pack at 297k entries 9.7 to 7.8 s. The ledger is checked from its last verified entry, with a full check hourly and on every pack, and an unchanged inventory is recorded once a day per host (DECISIONS 121). The engine evaluates each inventory once and builds and hashes the shared "not installed" verdicts once per process; verdicts and digests are unchanged (DECISIONS 122).

### Removed
- Dead code: the stub `nimstead` console script, an unused match field, a network safety level and option nobody used, a duplicate Windows version comparator, and unused web exports.

## [0.7.3] - 2026-11-08 (preview)

**Agent 0.6.4.** No database migration; run `deploy/update.sh`. Proven on real installs since 0.7.2: Server 2019 and 2022 (fixes, .NET Framework, hardening), Windows 11 Enterprise and Windows 10 22H2 (fixes through the scheduled task), German Windows 11 Pro, and the unverified case of an attack path across hosts. Still not proven: a fix on Windows 10 (it needs an ESU licence).

### Fixed
- **A Windows Server couldn't take a .NET Framework fix** (agent 0.6.4, DECISIONS 118): Windows Update offers servers only .NET's combined cumulative, a KB MSRC never names, so every job stopped with no changes made. The server now plans the same fix with that KB, the agent judges it by the per-version package it downloads as, and it recognises Server's `Package_for_DotNetRollup~` name, without which a failed install couldn't be rolled back. Proven on real Server 2019 and 2022.
- **A .NET update offered alone was planned as a servicing stack step** (DECISIONS 117): only a person could approve it and the agent refused it, so nothing broke, but the host couldn't move on.
- **VirtualBox 7.x was never checked**: its installer registers the publisher as "Oracle and/or its affiliates", which the curated row didn't accept (DECISIONS 113).
- **Microsoft apps more than a year behind missed older CVEs**: the hourly update now also reads the five years of MSRC before the usual 12 months, for Microsoft apps only (VS Code, PowerShell, ...), each month once (DECISIONS 114).

### Proven
- **Server 2019, Server 2022, Windows 11 Enterprise and Windows 10 22H2 on real installs** (2026-11-07/08): fixes through the scheduled task on each, rollback on 2019 and Windows 11 Enterprise, .NET Framework and hardening on both servers. Servers under QEMU with Windows' own hypervisor where VirtualBox couldn't run them here (`sandbox/winqemu.py`, DECISIONS 116).
- **The unverified case of an attack path across hosts, on real hosts** (`last_run_winpaths_lab.json`): with nobody from the target's Administrators group signed in on the source, the sign-in edge reads unverified. 0.7.2 shipped it unit-tested only. No code change.

## [0.7.2] - 2026-11-07 (preview)

**Agent 0.6.3.** No database migration; run `deploy/update.sh`. Proven on real hosts since 0.7.1: the SharePoint and Exchange collectors (`last_run_winsharepoint.json`, `last_run_winexchange.json`), coverage on a Windows 11 VM with 63 apps (`last_run_wincoverage.json`), five more curated apps from real installer names (`last_run_winapps_batch8.json`), and an attack path across hosts read as confirmed (`last_run_winpaths_lab.json`). Not yet proven on real hosts: the unverified case of that edge (unit-tested), and the comparison with a commercial scanner (W3).

### Added
- **Attack paths across hosts tell a real route from a guess** (agent 0.6.3, DECISIONS 112): a sign-in edge inside a domain is confirmed when an account signed in on the first host is an administrator on the second and the first was seen connected to it, and unverified when no signed-in account is. The agent reports its own addresses, its open connections to private addresses, its Administrators group and the signed-in domain accounts' SIDs; nothing is probed.

### Proven
- **SharePoint and Exchange collectors on real installs** (W11): SharePoint Server Subscription Edition and Exchange Server Subscription Edition from Microsoft's trial media, in the domain lab; the agent's version equals the host's own for both (`last_run_winsharepoint.json`, `last_run_winexchange.json`). No code change was needed.

## [0.7.1] - 2026-11-06 (preview)

**Agent 0.6.2.** No database migration; run `deploy/update.sh`. Proven on real hosts since 0.7.0: a two-node failover cluster patched node by node with its role online throughout (`last_run_wincluster.json`), the agent installed at boot by a Group Policy scheduled task (`last_run_wingpo.json`, steps in docs/install.md), and the benchmark settings read in full on Server 2025 and on a German install (`last_run_winbaseline.json`, `last_run_winbaseline_judged_as.json`). Still not proven: SharePoint and Exchange collectors (no install media), Server 2019 and Server 2022 stepping, Windows 10 apply, Windows 11 Enterprise.

### Fixed
- **A Windows update no longer rolls back because a watched service was stopped by the update's own restart** (agent 0.6.2): the crash check counts only events after the last boot. On a slow cluster node, the shutdown ended ClusSvc with event 7031 each time.
- **A Windows fix no longer rolls back because a service was still starting** (agent 0.6.1). The agent's health check gives a service that starts by itself up to 5 minutes to reach Running after a restart; on a real failover cluster node, ClusSvc was 15 seconds from running when it was read, so a good update was rolled back and the rollback then read as failed.

## [0.7.0] - 2026-11-06 (preview)

Windows round 2 (tasks/plan-windows-round-2.md; DECISIONS 102-108): proofs on real Windows servers and a real Active Directory
domain, and the bugs they found. **Agent 0.6.0.** No database migration.

**Upgrade from 0.6.x:** run `deploy/update.sh`. Things to know:
- **AD discovery needs a directory source.** An admin chooses the one host whose directory the server takes (Assets, that host's
  settings); until then its agent's directory upload is refused with a message saying so.
- **Old Windows Server may get a forward-only step.** When Windows Update offers only a servicing stack update, it's planned as a
  forward-only job that only a person can approve (`{"forward_only": true}`).
- **More end-of-support findings for Microsoft 365 Apps** on version lines Microsoft no longer updates.

**Proven on real hosts in this release:** a domain controller and two members built by script, with Kerberos remoting member to
member (`last_run_winlab.json`); AD discovery and two DCs patched one at a time, both healthy after (`last_run_windc.json`);
agentless scanning across hosts matching the host's own agent (`last_run_winremote_lab.json`); a servicing stack update then a
cumulative on Server 2016 (`last_run_windows_server2016_ssu.json`); 50 findings hand-checked against Microsoft's sources on
Windows 11, Server 2025 and Windows 10 (49 confirmed, 1 unverifiable, none wrong).

**Not proven yet** (STATUS lists each): a failover cluster drained and patched (W9: the cluster forms with its witness, the
role didn't stay up on this host), the agent installed by a GPO startup script at boot (W10: the member can't reach its DC that
early here), SharePoint and Exchange collectors (W11), the benchmark rule hand-checks on a VM (W18, W19), Server 2019 and
Server 2022 stepping (W5), Windows 10 apply (needs non-evaluation media), Windows 11 Enterprise (no ISO), commercial-scanner
benchmarks (owner registration).

### Added
- **Servicing stack updates as a forward-only step** (DECISIONS 105): when Windows Update offers an old Windows Server only a servicing stack update, the server plans it as a forward-only job a person approves (`{"forward_only": true}`), and the agent installs it only if the package's own manifest says it's a servicing stack update. The cumulative is planned after it.

### Fixed
- **Two domain controllers (or cluster nodes) could be patched at once** when the first one's Windows update ran past two hours without reporting: the group now holds for as long as the server waits on that install (the restart deadline plus 4 hours). Found on a real two-DC lab.
- Debian and Ubuntu packages held with `apt-mark hold` are reported again (they were left out of the inventory).
- The agent opens only plain files when scanning jars, Python and npm packages: a named pipe a user planted could block it.
- A .NET SDK reported with a two-part version no longer fails that host's report.
- A servicing stack step is planned only when Microsoft's data for that month was read.
- One feed failing or changing format no longer stops the hourly update and re-match for every organisation.
- The per-update fleet view counts a stepped job by the build it installs.
- Microsoft 365 Apps on a version line Microsoft no longer updates is judged: a superseded line's CVEs take their fix from a newer line of the channel, and a line older than any the channel lists opens an end-of-support finding (DECISIONS 106).

## [0.6.0] - 2026-11-04 (preview)

Windows rounds 1 and 2 (tasks/plan.md, tasks/plan-windows-round-2.md; DECISIONS 51–101): Windows detection across the OS, Microsoft's own products and common apps, fixes
with rollback, an agent that needs no Python, and a detection engine that says how sure it is. **Agent 0.5.0.**

**Upgrade from 0.5.x:** run `deploy/update.sh`. Five database migrations (`9a61c0e4d2b7` host facts, `c3e8f1a92d45`
maintenance windows and Active Directory computers, `a7d3e5b1c920` the engine's collection document and scan records, `d4f1b8a3c6e2` a package's source version, `e5c2a9d7f413` the directory source), applied on start. Things to know:
- **Windows installs no longer need Python.** `install.ps1` brings Python's official embeddable runtime (3.15.2,
  pinned by hash in the signed release, every program file signed by the Python Software Foundation). Machines enrolled
  with a system Python move to the bundled runtime on their own at their next agent update. Your server fetches the
  runtime zips with the release files; offline installs copy `python-embed-*.zip` into `NIMSTEAD_RELEASE_DIR` too.
- **More findings on Windows.** Expect new open findings after the first reports: end of support (OS, .NET, SQL
  Server, Exchange, SharePoint, Office, curated apps), Microsoft products (Edge, .NET runtimes, SQL Server, Exchange,
  SharePoint, Defender, Store apps, PowerShell, Visual Studio, Microsoft 365 Apps), 22 more third-party apps, and
  configuration findings (ecosystem `WinConfig`). Edge and VS Code findings move from `WinApp` (NVD) to `Microsoft`
  (MSRC): the old ones close and new ones open once.
- **Approved fixes wait for a maintenance window** once you set one (Settings → Remediation); none set = any time, as
  before. Workstation restarts can now be put off by a signed-in user until a deadline (default 24 hours).
- **API additions:** `facts` on inventories and host assets; `maintenance_window` / `reboot_deadline_hours` on
  `/api/settings` and `maintenance_window` on assets; `waits_for_window` and `forward_only` on jobs; approving a
  forward-only fix needs `{"forward_only": true}`; `POST /api/agent/directory`; `GET /api/directory/unmanaged`
  (`?format=csv`); `forward_only_changes` in evidence packs.

### Added
- **Hotpatch-aware Windows matching:** hotpatch and cumulative fixes are separate tracks; a job carries both KBs and the
  agent installs whichever Windows Update offers (before, a non-hotpatch Server 2025 host could be planned the hotpatch KB).
- **End-of-support findings** from a dated Microsoft Lifecycle table (Windows 10/11 by edition and ESU, Server
  2012–2025 and 23H2, .NET, SQL Server, Exchange, SharePoint, Office) and endoflife.date for curated apps.
- **Microsoft products from MSRC's own fixed builds** by an allowlist, with SQL Server GDR/CU and each Exchange CU as
  separate tracks, and Microsoft 365 Apps / Office LTSC by channel and version line (Microsoft's release feed).
- **CVE List v5 (vendor CNAs + CISA Vulnrichment)** as a second source for curated apps where NVD hasn't configured a
  CVE yet; **22 more curated apps** (OpenJDK builds, browsers, VPN and remote-access clients, file transfer,
  virtualisation, Docker Desktop, Tomcat and more).
- Per-user apps of users who aren't signed in; an opt-in **Java library scan** (`--scan-jars`) whose findings name the jar.
- **Configuration findings:** Secure Boot 2023 certificates (the 2011 CA expired 2026-10-19), BlackLotus revocation,
  CVE-2013-3900, Spectre/Meltdown on Server, SMBv1, SMB signing, LLMNR, NetBIOS, NTLMv1, WDigest, RDP NLA, TLS 1.0/1.1,
  DC LDAP signing and channel binding, AlwaysInstallElevated, Spooler on DCs, unquoted or writable service paths,
  PowerShell 2.0, LSA protection, Defender, firewall, BitLocker.
- **Threat context:** Microsoft "exploited" counts like KEV; Microsoft's exploitability index, public Metasploit modules
  and KEV ransomware use are reasons; CVEs in roles that aren't installed (DNS, DHCP, Hyper-V, MSMQ…) rank lower but stay open.
- **Fix paths:** winget for curated apps (forward-only: a person approves it as such, never the trust ladder), Microsoft
  365 Apps with rollback to the previous build, and six reversible settings.
- **Fleet operations:** maintenance windows, restart deferral with a deadline, no install on battery, one Windows job
  at a time per failover cluster (node drained and resumed) or per domain's controllers, crash events in health checks,
  and why Windows Update didn't offer a KB (WSUS, deferral, ESU). Proxy support (`--proxy` / WinHTTP), jittered
  below-normal scheduled tasks, and a list of Active Directory computers with no agent (opt-in `--ad-discovery` on one machine, which an admin then chooses as the directory source on **Assets**; any other host's list is refused).
- Windows Update accuracy oracle in the VM harnesses (`sandbox/winoracle.py`).

### Fixed
- Findings hid every Windows setting, end-of-support and exposure finding by default, and called them "no fix yet"; they now show, with what to do. Plan fix is offered on settings the agent can change. Links to advisory pages that can't exist are gone, and an unset registry value no longer reads `[None, None]`.
- KeePass and Notepad++ (MSI) are identified by the names their current installers register ("KeePass 2.x",
  "Notepad++ (x64)"); both were inventory only before (found on a real Windows 11 install).
- A Windows job's 15-minute check no longer judges a DISM rollback before the restart it waits for.
- The hourly re-match scores each CVSS vector once per pass.
- `resume-job` takes the run lock, so it can't advance a pending Windows job while the startup run is advancing it.
- A Windows cumulative update gets up to 2 hours to install (a reinstall on Windows 11 with a user signed in ran past 30 minutes), and a rollback also removes an update that finished installing after the agent stopped waiting for it; before, that ended in "ROLLBACK FAILED" (found on a real Windows 11 VM).
- Proven on real Windows 11 VMs: winget, Office and Windows-setting fixes with rollback, proxy-only operation, restart deferral (one early restart in an earlier run remains unexplained), crash events in health checks, offline user hives, the jar scan and service ACL checks.
- A Windows job whose restart a signed-in user put off is no longer marked failed after 2 hours; the server waits until 4 hours after the restart deadline (found on a real Windows 11 VM).
- winget fixes run as SYSTEM on real Windows 11: winget exited with a missing-DLL error because its C++ runtime wasn't on the path. Office updates and rollbacks repeat a request the Click-to-Run client dropped; before, a dropped rollback ended in "ROLLBACK FAILED" (both found on a real Windows 11 VM).
- A Windows update job stops before downloading when the system drive has under 10 GB free, saying how much is free; before, a full disk ended in "downloaded failed: 4" (found on a real Windows 11 VM).
- winget fixes find winget on real Windows 11: the App Installer folder is owned by Administrators there, not TrustedInstaller (only the WindowsApps root is), so every winget job was refused as "winget unavailable". Owners are now compared by SID (found on a real Windows 11 26H2 VM).
- The runtime signature check in `install.ps1` now filters by extension: PowerShell 5.1 ignores `-Include` beside
  `-LiteralPath` (found in the real VM run).

### Since the round 1 notes above

Wider Windows detection and more fixes. **Expect new open findings after the first reports.**
- **Windows hosts far behind can be fixed:** a job installs the earlier cumulative update when that's what Windows Update offers, and the next job finishes the way.
- **Clearer refusal:** a Windows job with two possible updates now says why neither was offered, such as no Extended Security Updates licence.
- **Ended release branches:** Thunderbird, Firefox ESR, PostgreSQL, MySQL, MariaDB, MongoDB, Elasticsearch, Go, Grafana, LibreOffice, Tomcat, Ruby and Perl now report when their branch gets no more fixes.
- **Fixed:** one NVD record with no configuration nodes stopped the app feed sync; a CVE only for Apple silicon was reported on Windows.
- **Agentless scan:** `scan-remote` reads hosts with no agent over PowerShell remoting, as you, with no stored credential. It finds; fixes still need the agent.
- **.NET Framework findings:** read from mscorlib, on the host's own line and OS, with a fix through Windows Update that can be rolled back.
- **.NET SDKs:** the newest of each feature band, against MSRC's SDK fixes.
- **Hardening audit:** 24 more settings (UAC, stored sign-in passwords, password and lockout policy, anonymous access, LM hashes, WinRM, SNMP and more), free; 7 more settings can be fixed by a reversible job. This is not a CIS or STIG conformance check.
- **43 more Windows apps,** including the JetBrains IDEs, Vim, Ruby, Perl, OpenOffice, MySQL, PostgreSQL, MariaDB, MongoDB, Elasticsearch, ImageMagick, Go, Grafana, IntelliJ IDEA, GIMP and calibre; 16 can be updated by a job.
- **Fixed:** the certificate padding fix sets both registry views; it reported applied while its finding stayed open. MSRC sync retries a dropped connection. The restart notice says Windows may restart sooner than the agent would.

Windows round 2 and the detection engine (tasks/plan-windows-round-2.md; DECISIONS 68–101). **Agent 0.5.0.**
- **Scan report per host** (`GET /api/assets/{id}/scan-report`, `python -m nimstead.engine`): every check gets a verdict (vulnerable, not vulnerable, not applicable, couldn't be determined, not run) and how sure it is, and the report says what stopped any check and what to do about it. It covers Windows, Debian and RHEL-family packages, network services, Python, npm and Java installs, and SBOMs. Findings still open and close as before.
- **Attack paths:** each host's report says how its weaknesses chain (getting in, becoming SYSTEM, taking sign-ins, reaching other hosts) and where to break the chain; `GET /api/attack-paths` and the Assets page link one host to the next. No step is better than its evidence: routing between hosts isn't seen, so nothing across hosts reads better than reasonable.
- **Vulnerable drivers** by exact file hash from LOLDrivers, never by name.
- **Machine certificates** (expired, weak key, weak signature), and a listener the firewall lets through raises its product's priority, with the process and port named.
- **Benchmark references:** DISA's Windows Server 2025 and Windows 11 registry rules as a reference per host and fleet, with CSV export. Not a conformance check: manual rules always read "not assessed".
- **Exploit-DB** as a second public-exploit source; a second install of the same app is named on its finding.
- **Windows updates across the fleet:** a count per KB, why each host hasn't got it, and one action to plan the rest. Fix first lists setting fixes beside upgrades.
- **`doctor`** on the agent checks server reach, proxy, clock, tasks, folder permissions, Windows Update, disk and runtime, and says how to fix each failure; the agent keeps a rotating local log with no secrets.
- **Any Windows language:** settings, user rights, audit policy, proxy and winget are read by ID and SID, not English names (checked on a German install).
- **Power cuts:** a job interrupted during install or rollback finishes or says honestly that nothing changed; it never stays pending.
- **Fixed:** Store app firewall rules made every listening port read as allowed. A job on Server 2016–2022 or LTSC no longer blames a missing ESU licence those don't need. One Windows Update search per job instead of one per candidate (the second hung 30 minutes on Server 2022). A host that never installed an update read "last installed 426 years ago".

## [0.5.0] - 2026-10-29

A safer, clearer interface, from two rounds of UI and accessibility review (tasks/plan-0.5-ux.md, tasks/plan-0.6-ux.md; DECISIONS 41–50). Agent unchanged (0.3.0).

**Upgrade from 0.4.x:** run `deploy/update.sh` on the Docker host. No database migration. Things to know:
- **Switching the trust ladder now takes Save**, and switching to Auto asks you to confirm.
- **Evidence packs can report `no_activity`** for timeliness controls with nothing fixed and nothing overdue in the period (Cyber Essentials update management, NIST SI-2, CIS 7.3/7.4, SOC 2 CC8.1), where 0.4.0 said `met`. The pack format and verifier are unchanged; if you parse control statuses, expect a third value. The deadline text in packs now says "routine" for the tier the UI used to call "Planned".
- **API additions:** `POST /api/remediation/jobs/{id}/cancel`; `GET /api/findings?overdue=true` (and on the CSV export) with a `due` date on each finding; `asset_ids`, `job`, `busy_asset_ids` and `last_attempt` on `/api/summary` actions. Cancelled fixes no longer appear in `/api/summary`'s `attention` list.
- Adding a machine now asks whether it's a test or production machine; there's no default.

### Changed
- **The trust ladder no longer switches itself to Auto.** Before, choosing a mode (one click, or one arrow key) saved it at once. Now choosing only selects; Save applies it, and Auto asks first, naming how many machines it covers and the canary-first order.
- **Destructive actions ask first, the same way everywhere:** revoking an API token, removing someone, changing someone's role and signing out everywhere now use the same confirmation as deleting an asset. You can't demote or remove yourself from the People list.
- **Fixes can be cancelled before a machine picks them up** (planned or approved), and cancelling one lets you plan it again. `POST /api/remediation/jobs/{id}/cancel`, admin only, recorded in the ledger.
- **Home links to a fix already in flight** ("View fix") instead of offering "Plan fix" again. The finding drawer shows "Fix in progress" the same way. A job's summary and host link to that machine's findings. `/api/summary` actions carry `asset_ids` and `job`.
- **Evidence says "No activity in period"** for timeliness controls (Cyber Essentials update management, NIST SI-2, CIS 7.3/7.4, SOC 2 CC8.1) when nothing was fixed or changed in the period and nothing is overdue, instead of "Met". Overdue findings still fail. **Signed packs can carry the new status `no_activity`**; the pack format and verifier are unchanged. The period's dates, an "as of" time and each control's counts are shown, and the period is kept in the URL (`?period=30`).
- **Onboarding asks "test or production machines?"** with nothing preselected (it can't be changed after enrolment). It shows troubleshooting after two minutes without a report, and waits for you instead of redirecting on its own.
- **Two-step sign-in shows a QR code** to scan, drawn in the page; the typed key stays as a fallback.
- Settings is grouped into Remediation, Access, Alerts, Your account and This server, with a section bar. Saves say "Saved"; asset changes say the findings were re-ranked.
- Theme follows your system until you pick light or dark, and can go back to following it.
- On phones, Evidence is in the tab bar (Assets moved under More, with Sign out), and buttons, links and form controls are at least 44px tall.
- **Read-only members see an asset's settings as text,** not controls the API would refuse.
- **Every dialog hands focus back to what opened it,** not just the findings drawer. Focus rings are ink in both themes (crimson now only means "fix now", KEV or an error), and headings focused by the app no longer show a ring. After moving to another page, focus goes to its heading and the page title is announced.
- **"Saved" and similar messages are announced** through one live region; form errors sit under, and are tied to, the field they're about. A failed save shows next to the section that failed, not at the top of the page.
- **Overdue is a filter.** `GET /api/findings?overdue=true` (and the CSV export) returns open findings past the deadline in force when they were first detected, the same rule evidence packs use; each finding carries `due`. Findings gets an "Overdue" chip, the drawer says "Due 3 Nov" or "12 days overdue", and Evidence's "Overdue and still open" links to the list.
- **Fixes have an address** (`/remediation#job-<id>`). Home, the finding drawer and Plan fix land on the fix itself. A fix planned and approved by the same person says so.
- **Home doesn't re-plan blind.** `/api/summary` actions carry `busy_asset_ids` and `last_attempt`. When the last attempt failed it links to that job ("Last attempt aborted: review"), and when one host is busy you can still plan the others. Cancelled fixes no longer appear under "needs a look".
- **Production remediation says how to turn it on:** Settings, onboarding and the refusal note name `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1`.
- **The priority tier "Planned" is now labelled "Routine"** in the UI and in the evidence pack's deadline text (the stored value and API stay `planned`), so it can't be mistaken for a planned fix.
- Command palette finds hosts too, keeps the highlighted command while results arrive, and never offers an invalid empty list.
- Assets: the agent-update explanation is said once for the list, grouped by reason; Ring and Health units are explained in place; long host names wrap.
- Findings: package names show the part that differs first (`log4j-core`, then the group, muted), truncated cells carry their full text, rarer filters fold away on phones, the list dims while new filters load, and a capped list (5,000) says so.
- Settings: editing one section no longer loses what you typed in another; the section bar marks where you are and fits phones; trust-ladder options have visible borders and a radio mark. The SSO and alert forms keep your edits when other data refreshes, and "Send test alert" reports success or failure.
- Evidence: the ledger says how many entries it shows of how many and names what each entry is about; mean time to remediate under a day says so.
- Sign-in and onboarding: fields focus where you'd expect, onboarding polls only once there's a command to run.

### Fixed
- "Verified" next to an SSO domain was the same colour as the page in both themes.
- Admin-only buttons could not be focused, so keyboard and touch users never saw why they were off; they now stay focusable and point to a visible "Read-only" note.
- Focus returns to the finding you opened when its drawer closes.
- Keyboard focus on menus, the command palette and filters is visible (not just a faint tint); loading states are announced; the findings table names its columns on phones; reduced motion also stops transitions.
- Plan fix no longer downloads up to 5,000 findings to look up machine ids.
- The web bundle loads Settings, Evidence, sign-in and onboarding on demand (entry chunk 587 kB to 392 kB).
- Settings would crash on an API token without an expiry (none are created that way, but the column allows it).

## [0.4.0] - 2026-10-28

Security round 4 and what a first team needs: people management, two-step sign-in, API tokens and CSV export. Agent 0.3.0.

**Upgrade from 0.3.x:** run `deploy/update.sh` on the Docker host. Things to know:
- **Admins who sign in with a password are signed out by the upgrade and set up two-step sign-in at their next sign-in** (any authenticator app), including break-glass sign-in. Save the recovery codes it shows.
- Swagger UI at `/api/docs` is off unless `NIMSTEAD_API_DOCS=1` (it runs scripts from a CDN); `/api/openapi.json` is still served.
- **The app now listens on `127.0.0.1:8000` only.** Your HTTPS proxy on the same host keeps working. If something on another machine reached port 8000 directly, put it behind the proxy, or set `NIMSTEAD_BIND=0.0.0.0` in `.env`.
- Sign-up links sent before the upgrade stop working; ask for a new one.
- Agents update themselves to 0.3.0. Machines enrolled before 0.3.0 keep taking every channel; rerun the install command to tie one to your server's channel.

### Security
- **Sign-up can no longer be used to pre-set someone else's password.** Emailed sign-ups, invitations and resets let the address owner choose the password on the link's page; the request never carries one.
- **Two-step sign-in (TOTP) is required for admins** who sign in with a password, with one-time recovery codes; anyone else can turn it on in Settings. A new admin's first session comes from signing in (after sign-up you're sent to the sign-in page), wrong codes are limited per account from every address, and promoting someone signs them out so they set it up.
- Request bodies are capped at 10 MB as they arrive, so a chunked upload can't exhaust memory.
- Per-organisation limits: assets (`NIMSTEAD_MAX_ASSETS_PER_ORG`, 5,000), enrolments per token, inventories per hour, and AI calls per user and organisation.
- Security headers on every response: Content-Security-Policy, HSTS (with secure cookies), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`. `/.well-known/security.txt` is served.
- The evidence ledger now records organisation creation, every agent enrolment (with the token used), password sign-ins and every change to people and tokens.
- **Agent 0.3.0:** a fix never installs an older version (pins are compared by the package manager; dry-run downgrades are refused); rollback copies are deleted once the outcome is saved and no change starts below 1 GiB free; signed releases from a less proven channel than the machine's are refused; job fields are validated without trailing newlines; server responses are size-capped.
- **Windows installs without remediation failed at "Scheduling failed"** (since agent 0.2.0): removing the job-poll task that wasn't there left PowerShell exiting 1 with no output. Found on a real Windows 11 VM; the agent now removes it only if it exists, and says the exit code if scheduling ever fails. Rerun the install command on machines that showed the error.
- The Windows installer's trusted-folder check had lost a backslash, so `C:\Program Files Evil\` passed it (the agent's own check still stopped it). Fixed. The Linux installer fetches over HTTPS only and prints the agent's SHA-256.
- `deploy/update.sh` refuses untracked files and Compose override files, checks out the exact verified commit, runs as root only from a checkout only root can change, and checks the backup is readable before dropping the database on rollback.
- CI actions are pinned to commits with a read-only token; a CI job audits Python and npm dependencies; Dependabot covers both; the release signing step installs only hash-pinned packages.

### Added
- **People** in Settings: invite by email, make admin or member, remove (signed out at once). An organisation always keeps one admin. Sessions end after 12 hours idle; **Sign out everywhere**.
- **Change password** and **Forgot password?** (emailed link, 1 hour; you still need your authenticator code).
- **API tokens:** read-only access for scripts to findings, assets, the summary and evidence, as `Authorization: Bearer …`. Creating one needs your authenticator code; each expires within a year, and stops working when its creator is no longer an admin, signs out everywhere, or changes or resets their password.
- **Export CSV** on Findings, with the page's filters (cells a spreadsheet would run as formulas are escaped).
- **Remediation deadlines** per priority in Settings, used and shown in evidence packs. Each finding is held to the deadline in force when it was detected, so relaxing one later can't make an old miss pass.
- Evidence packs map to **SOC 2 CC7.1 and CC8.1** and **NIS2 Art. 21(2)(e)** too.
- Risk acceptance: accept one vulnerability on every host it's open on, and revoke an acceptance (both recorded).
- Each release publishes CycloneDX SBOMs of Assure's own dependencies; upload them to an application to scan Assure with Assure.
- Docs: installing an agent without trusting the server, restoring a backup, release-key rotation and the bad-release runbook (`docs/release-keys.md`).

### Changed
- `SECURITY.md`: response targets per severity, safe harbour, and which releases get fixes.

## [0.3.1] - 2026-10-28 (preview)

**Release channels.** Releases now come in three channels: **preview** (earliest, may break), **beta** (feature-complete, being proven) and **stable** (public). Your server follows one and also takes anything more stable. There's no beta or stable release yet, so **set `NIMSTEAD_UPDATE_CHANNEL=preview` in `.env` to keep getting updates**; the default is `stable`. Agents are unchanged (still 0.2.0), so machines need nothing.

**Upgrade from 0.3.0:** 0.3.0's Settings doesn't show preview releases, so run `deploy/update.sh` on the Docker host (it checks the signature, backs up the database and rolls back if needed). Then add `NIMSTEAD_UPDATE_CHANNEL=preview` to `.env` and restart with `docker compose up -d`. From 0.2.0: `git fetch --tags && git checkout v0.3.1 && docker compose up -d --build`, then rerun the install command on each machine once.

### Added
- **Release channels:** preview, beta and stable. Each release's signed manifest says its channel, and a server follows one (`NIMSTEAD_UPDATE_CHANNEL`, default `stable`), taking its channel and anything more stable. Settings shows the channel, and `deploy/update.sh` installs the newest release the channel allows. A tag is released as preview; promoting it re-signs the same commit for beta or stable with your approval. 0.3.0 is a preview release.
- Docker base images and the PostgreSQL image are pinned by digest, and Dependabot proposes updates to them and to the pinned GitHub Actions.
- `web/scripts/readme-shots.mjs` regenerates the README screenshots from the real-hosts demo.
- Each GitHub release's notes are its CHANGELOG section, not a pointer to the file.

### Changed
- "Not reporting" alerts wait one report cycle after the server itself was down, so an outage doesn't page about every machine.

## [0.3.0] - 2026-10-28 (preview)

Agents and the server now update themselves from signed releases, approved fixes start within minutes, and machines that stop reporting are flagged. **Agents older than 0.2.0 can't update themselves: rerun the install command on each machine once** (the enrolment is kept). After that, updates are automatic.

### Added
- **Agent 0.2.0 updates itself.** At each run it installs a newer release only if it's signed by the Nimstead release key built into the agent. That key is held by the release workflow, never by your server, so a compromised server can't push code to your machines. Older versions are never installed, and the new version must run its inventory on the machine before it replaces the old one. Pause updates for your organisation in **Settings → Agent updates**, or turn them off on one machine with `--no-auto-update`. The Assets page shows each agent's state (updating, failed and why, paused, off, or reinstall needed).
- **Approved fixes start within 15 minutes:** machines that allow remediation check for approved jobs every 15 minutes, and only report inventory when a job ran. The agent now writes its own timers and scheduled tasks (`schedule`), so changes like this reach existing machines without a reinstall.
- **Not reporting:** a machine silent for 14 hours is flagged on Assets and Home, and alert targets hear about it once per outage.
- **`uninstall`** removes the agent, its schedule, key and state from a machine.
- **Server updates:** **Settings → This server** shows the running version and any newer release, and alert targets hear about each new release once. `deploy/update.sh` installs a release only if it's signed and its tag points at the signed commit. It backs up the database, waits for the new version to be healthy and otherwise restores the previous version and the database. `--install-timer` runs it nightly (opt-in).
- **`/api/health`** (database reachable, schema at the release's migration head), used by the Docker healthcheck.
- Releases are signed in a protected GitHub Actions environment and published with a build attestation.

### Changed
- `install.sh` and `install.ps1` let the agent create its schedule (same 6-hour timer or task, plus the 15-minute job check where remediation is allowed).
- The "Agent outdated" badge now says what happens next: most agents update themselves at their next run.

## [0.2.0] - 2026-10-28

A security release: a Claude Security scan of the whole repository found 21 issues (12 medium, 9 low), all fixed here with a test each and, for anything that touches real systems, a run on real services (see [STATUS.md](STATUS.md) and decision 30 in [DECISIONS.md](DECISIONS.md)). **Upgrade, and read "Changed" first: three behaviours change.**

### Security
- **Agent 0.1.3 (Windows):** a standard user who created `C:\ProgramData\Nimstead` before the agent was installed could keep read access to the agent key, and a junction planted there could make the elevated agent delete another user's files. The agent now takes the folder first (Administrators own it, explicit access entries dropped), never follows junctions, and locks the folder before the key is written. Proven in a Windows 11 VM as a standard user.
- Read-only members can no longer upload an SBOM (which resolved findings and wrote evidence).
- SSO sign-in can only be started from the sign-in page (POST), closing a login CSRF and an open redirect; identity provider endpoints must be https.
- One tenant could block another from adding an external target, or learn which hosts other tenants monitor; targets are now per organisation.
- An unknown package ecosystem reported by any agent could stop the hourly feed update for every tenant; each ecosystem now syncs on its own.
- A crafted Composer version string could freeze the API (catastrophic regex backtracking).
- The OIDC client could reuse a TLS connection verified for one hostname for another hostname on the same IP; it no longer keeps connections alive.
- Failed sign-ins spread over many addresses could lock the real user out; the per-email limit now only stops addresses that have failed themselves, and IPv6 is throttled by /64.
- Webhook URLs (Slack-style URLs are secrets) are now encrypted at rest; existing ones are encrypted by the next hourly feed run.
- Host names and job errors can no longer inject links or @channel mentions into Slack alerts.
- The evidence pack no longer ships its own verifier (whoever hands a pack over could swap it): get it from `/api/evidence/verify.py`, checked against the SHA-256 published next to the key fingerprint. Packs now name the tenant's id and DNS-verified domains, since one server key signs every tenant's packs.
- Install commands no longer put the enrolment token on the command line, where other local users and sudo logs could read it (`NIMSTEAD_TOKEN` instead).

### Changed
- **Sign-up no longer says whether an email has an account.** The first account on a server is created straight away; later sign-ups get the same answer either way and finish from an emailed link, so they need SMTP (without it they're closed; colleagues join by SSO). `NIMSTEAD_OPEN_SIGNUP=1` restores instant sign-up for development and demos only.
- **External targets must also serve their verification value** at `/.well-known/nimstead-verify.txt` from the address being scanned (HTTPS or HTTP), checked before every scan. Owning the DNS name alone no longer lets anyone aim the scanner at an IP. Add the file to existing targets, or their hourly scans are refused.
- **Alert email recipients confirm first:** each new address gets a confirmation email and receives alerts only after confirming. Existing recipients must be confirmed again (remove and re-add them in Settings).
- Manual external scans (10 an hour per organisation), test alerts (5 an hour) and sign-ups (10 an hour per address) are rate-limited.
- **Sandbox:** `winvm.py` builds Windows 11 VMs (TPM 2.0, Secure Boot) and cold-boots a VM whose firmware hangs after a restart; Windows 11 runs log to `last_run_windows11*.json`.

### Added
- **Agent 0.1.2:** Windows 10 and 11 fixes. Windows 11 downloads cumulative updates in Windows Update's "express" format, which the permanence check couldn't read, so every Windows 11 fix stopped safely with "No changes made". The agent now reads Windows Update's own install plan (`ActionList.xml`) and checks every package in it before installing: the cumulative update must be removable, and any companion package must be removable too, unless it's the servicing stack or the Safe OS (recovery partition) update, which Microsoft ships as permanent with every cumulative update. The step log names everything that stays after a rollback.

Machines on an older agent show **Agent outdated** after you upgrade the server; rerun the install command on each, especially on Windows (enrolment is kept). This release becomes available under Apache 2.0 on 2028-10-28.

## [0.1.1] - 2026-10-27

### Fixed
- **Agent 0.1.1:** a service crash-looping after a fix could pass the health check if it was sampled in a moment of "active". The check now also counts systemd restarts since the change, so the fix is rolled back. Found on a real Debian 13 host.
- **Agent 0.1.1:** a failed health check now says the service's state (for example "service is inactive") instead of ending in an empty reason.
- **Web:** the home page and the approval dialog no longer repeat the host name after a fix's summary.

### Changed
- README screenshots now come from a real run on five disposable Linux machines (`sandbox/demo.py`).

Machines on agent 0.1.0 show **Agent outdated** after you upgrade the server; rerun the install command on each to update (enrolment is kept). This release becomes available under Apache 2.0 on 2028-10-27.

## [0.1.0] - 2026-10-27

The first early-access release. Everything listed is proven by tests and, for anything that touches real systems, by runs on real machines (see [STATUS.md](STATUS.md)). Expect breaking changes before 1.0.

### Added
- **Detection:** agents for Debian, Ubuntu, RHEL-family, Alpine, SUSE and Windows (the OS and common third-party apps such as Chrome, Firefox, 7-Zip and VS Code); CycloneDX and SPDX SBOM upload; OSV, NVD, CISA KEV, EPSS and MSRC feeds; ecosystem-exact version comparison.
- **Prioritisation:** risk score from KEV, EPSS, CVSS, criticality and exposure, with a reason for every score; "Fix first" upgrades instead of CVE lists.
- **Remediation:** apt, dnf, apk, zypper (snapper) and Windows cumulative updates, with dry run, health checks, automatic rollback, canary and broad rings, kill switch, and success verified by inventory.
- **Evidence:** hash-chained ledger, signed off-database checkpoints, Ed25519 evidence packs mapped to Cyber Essentials, ISO 27001, NIST, PCI DSS and CIS, verifiable offline.
- **External scanning** of internet hosts proven owned by DNS TXT.
- **Platform:** OIDC SSO with verified domains, failure alerts (webhook, email), Vault and S3 object-lock key storage, PostgreSQL, multi-worker safe.
- Agent version reporting, with outdated agents flagged on the Assets page.
- **Install:** Docker Compose (server, PostgreSQL 17 and the hourly feed update), install and configuration guides.

Licensed under FSL-1.1-ALv2: this release becomes available under Apache 2.0 on 2028-10-27.

[Unreleased]: https://github.com/Nimstead/assure/compare/v0.15.1...HEAD
[0.15.1]: https://github.com/Nimstead/assure/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/Nimstead/assure/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/Nimstead/assure/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/Nimstead/assure/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/Nimstead/assure/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/Nimstead/assure/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/Nimstead/assure/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/Nimstead/assure/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/Nimstead/assure/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/Nimstead/assure/compare/v0.9.3...v0.10.0
[0.9.3]: https://github.com/Nimstead/assure/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/Nimstead/assure/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/Nimstead/assure/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/Nimstead/assure/compare/v0.8.0...v0.9.0
[0.6.0]: https://github.com/Nimstead/assure/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Nimstead/assure/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Nimstead/assure/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/Nimstead/assure/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Nimstead/assure/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Nimstead/assure/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Nimstead/assure/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Nimstead/assure/releases/tag/v0.1.0
