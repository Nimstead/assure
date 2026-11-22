# Find vulnerabilities in running containers

See what is vulnerable inside the containers running on your Linux machines and Kubernetes nodes, which machines run each image, and what each image's rebuild must fix. You need agents running as root (the installer sets this up): 0.8.0 or later reads Docker and Podman containers' OS packages; 0.9.0 or later also reads Kubernetes nodes and the Python, npm, Java and Go packages inside every image.

## See your container images

1. Update your Linux agents. They update themselves from signed releases, so in most cases this needs nothing from you. At each report, the agent lists the running containers and reads each one's operating system, its package list, and what its image's build added.
2. Open **Assets** and select the **Container images** view. Each image appears once, however many machines run it, with its base operating system, the machines it runs on and its open findings, most urgent first.
3. Select an image to see how it's fixed, **what was read** in it (for example "Debian packages 96 · Python 41 · npm 0 · Java 3 · Go 52", with the reason for anything not read in full), and every container that runs it, by machine. A machine's own details list the containers running on it, each linking to its image.

An image's findings appear in **Findings** like any other, named by the image. Each one says which package to bring to which version and where the image runs; for a Python, npm, Java or Go package it also says where the package sits in the image, such as `/app/app.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar`. **Fix first** lists **Container images to rebuild** below the fixes it can plan.

Nothing is installed in a container, and nothing in a container is run. The agent reads the container's files through the container's own root: it never follows a link, never enters another mount (so a pod's secrets and volumes are never read) and opens only regular files.

## Kubernetes nodes

Enrol each node with the usual install command. The agent asks the node's own `crictl` (the CRI tool that ships with containerd and CRI-O installs, using the node's `/etc/crictl.yaml`) which containers are running. Each pod's container is listed on the node as `namespace/pod/container`, on runtime `containerd` or `cri-o`, and its image joins the images list with everything above.

Nimstead needs no Kubernetes API token, no DaemonSet and no registry credentials: it reads what is deployed on each node. The same image running in a pod on one node and under Podman on another is one image. (Docker 29's containerd image store names an image by its registry digest rather than its configuration digest, so the same image under it shows as a separate image with the same findings.)

## What is read in an image

| What | Where | As |
| --- | --- | --- |
| Distribution packages | dpkg (including distroless `status.d`), apk, rpm's SQLite database | Judged by the distribution's own advisories, backports included |
| Python | `*.dist-info` and `*.egg-info` in any `site-packages` or `dist-packages` folder (system Python, `/usr/local`, virtual environments) | PyPI |
| npm | `node_modules/<name>/package.json` and `node_modules/@scope/<name>/package.json`, nested ones included | npm |
| Java | `META-INF/maven/*/*/pom.properties` in every `.jar`, `.war`, `.ear` and Jenkins plugin (`.hpi`, `.jpi`), and in archives nested up to two levels inside them (Spring Boot's `BOOT-INF/lib`, a war's `WEB-INF/lib`, a war's Jenkins plugins and their jars) | Maven |
| Go | The build information in every executable built with Go (Go 1.18's format, and older binaries' through the pointers they store): its modules and its Go version as `stdlib` | Go |

What the image's own package manager installed is left to it: Debian's `python3-requests` is judged as Debian's package with Debian's backports, never a second time as PyPI `requests`. A jar without `pom.properties` isn't guessed from its name. Findings mean a package is present in the image, not that its vulnerable code is called.

## Fix an image

Rebuild the image and redeploy it: from a newer base image or with the fixed distribution packages for those, and in the image's build (its lock file, `pom.xml` or `go.mod`) for application packages. Nimstead never changes a running container and never plans a fix on an image.

When every machine that ran the old image has reported its containers without it, the old image's findings are resolved with the reason "no host runs this image any more". The rebuilt image appears as a new image, with whatever is still open in it. An image no machine has run for 30 days leaves the list.

## When an image says "Not assessed"

An image Nimstead couldn't read is marked **Not assessed**, with the reason. It is never shown as clean. The common reasons:

- **No package database.** Images such as `busybox` and `scratch` builds have none. Distroless images are read from their `status.d` entries. Their application packages are still read.
- **rpm's Berkeley DB or ndb format isn't read yet.** RHEL 8, Rocky 8, AlmaLinux 8, UBI 8 and openSUSE images use these. RHEL 9 family and Fedora images use rpm's SQLite database, which is read. For the others, upload an image SBOM from CI instead.
- **No advisory feed maps this platform.** The image's operating system isn't one Nimstead has advisories for.

"What was read" says the same for application packages: partly read (a walk that reached its budget, a folder too deep, a jar that couldn't be opened), or not looked for (an agent before 0.9.0, or a machine that turned it off).

## What isn't read yet

- Rootless containers (run by a user rather than root), stopped containers and images that aren't running.
- Ruby, PHP, .NET and Rust packages inside images. Upload an SBOM of the image from CI to cover them: see [Upload an SBOM from CI](upload-sbom.md#container-images).
- Which Kubernetes team owns an image: set an image's owner by hand.

A container counts while it runs at report time (every 6 hours), so a short-lived job container may come and go between reports. The agent reads at most 128 containers in 120 seconds a report; each image's walk stops at 200,000 entries, its time budget (60 seconds, less when the pass is nearly out of time) or 20,000 application packages, and says so in the same words each time.

## Turn container reading off on a machine

Enrol the machine with a local opt-out. Only the machine can choose this; the server can't turn reading back on. `--no-containers` stops reading containers at all; `--no-container-apps` reads their OS packages only.

```bash
curl -fsSL --proto '=https' https://assure.example.com/install.sh | sudo --preserve-env=NIMSTEAD_TOKEN sh -s -- --no-container-apps
```

On a machine already enrolled, set `"containers": false` or `"container_apps": false` in `/etc/nimstead/agent.json`. Images it reported earlier keep their findings, and keep showing it as a machine that runs them, until you delete the machine or turn reading back on.

See the [assets API reference](../reference/assets-api.md#container-images) for the data and the [agent reference](../reference/agent-core.md#containers) for exactly what is read and the limits. [How containers are read safely](../explanation/coverage-limits.md#containers) explains what "nothing found" means for an image.
