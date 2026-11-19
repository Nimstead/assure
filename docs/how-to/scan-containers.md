# Find vulnerabilities in running containers

See what is vulnerable inside the Docker and Podman containers running on your Linux machines, which machines run each image, and what each image's rebuild must fix. You need agents at 0.8.0 or later, running as root (the installer sets this up).

## See your container images

1. Update your Linux agents to 0.8.0 or later. They update themselves from signed releases, so in most cases this needs nothing from you. At each report, the agent lists the running containers and reads each one's operating system and package list.
2. Open **Assets** and select the **Container images** view. Each image appears once, however many machines run it, with its base operating system, the machines it runs on and its open findings, most urgent first.
3. Select an image to see how it's fixed and every container that runs it, by machine. A machine's own details list the containers running on it, each linking to its image.

An image's findings appear in **Findings** like any other, named by the image. Each one says which package to bring to which version and where the image runs. **Fix first** lists **Container images to rebuild** below the fixes it can plan.

Nothing is installed in a container, and nothing in a container is run. The agent reads the container's `/etc/os-release` and its package database (dpkg, apk or rpm's SQLite database) through the container's own root, and never follows a link out of it.

## Fix an image

Rebuild the image with the fixed packages, or from a newer base image, and redeploy it. Nimstead never changes a running container and never plans a fix on an image.

When every machine that ran the old image has reported its containers without it, the old image's findings are resolved with the reason "no host runs this image any more". The rebuilt image appears as a new image, with whatever is still open in it. An image no machine has run for 30 days leaves the list.

## When an image says "Not assessed"

An image Nimstead couldn't read is marked **Not assessed**, with the reason. It is never shown as clean. The common reasons:

- **No package database.** Images such as `busybox` and `scratch` builds have none. Distroless images are read from their `status.d` entries.
- **rpm's Berkeley DB or ndb format isn't read yet.** RHEL 8, Rocky 8, AlmaLinux 8, UBI 8 and openSUSE images use these. RHEL 9 family and Fedora images use rpm's SQLite database, which is read. For the others, upload an image SBOM from CI instead.
- **No advisory feed maps this platform.** The image's operating system isn't one Nimstead has advisories for.

## What isn't read yet

- Containers run by Kubernetes through containerd or CRI-O. A machine with `crictl` and no Docker or Podman says so in its scan report.
- Rootless containers (run by a user rather than root), stopped containers and images that aren't running.
- Python, npm and Java packages inside containers. Upload an SBOM of the image from CI to cover them: see [Upload an SBOM from CI](upload-sbom.md#container-images).

A container counts while it runs at report time (every 6 hours), so a short-lived job container may come and go between reports.

## Turn container reading off on a machine

Enrol the machine with the local opt-out. Only the machine can choose this; the server can't turn reading back on.

```bash
curl -fsSL --proto '=https' https://assure.example.com/install.sh | sudo --preserve-env=NIMSTEAD_TOKEN sh -s -- --no-containers
```

On a machine already enrolled, set `"containers": false` in `/etc/nimstead/agent.json`. Images it reported earlier keep their findings, and keep showing it as a machine that runs them, until you delete the machine or turn reading back on.

See the [assets API reference](../reference/assets-api.md#container-images) for the data and the [agent reference](../reference/agent-core.md#containers) for exactly what is read and the limits. [How containers are read safely](../explanation/coverage-limits.md#containers) explains what "nothing found" means for an image.
