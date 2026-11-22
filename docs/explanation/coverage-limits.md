# Coverage and known limits

Assure reports what its collectors and advisory sources can establish. Coverage varies by platform, package ecosystem, permissions, and available content.

## Application inventory

SBOM support covers CycloneDX and SPDX JSON with supported, versioned package URLs. It does not include XML, SPDX tag-value, or VEX. A package being present does not prove that vulnerable code is reachable.

Windows third-party application matching uses a curated catalogue. Other applications remain inventory. Advisory delays and incorrect upstream ranges can affect results.

## Version ordering

The Alpine comparator treats dotted numeric components as integers. It does not implement fractional ordering for leading-zero components.

The Pub comparator uses the shared SemVer function and ignores build metadata. Versions that differ only in that metadata compare as equal. These limits can affect matching even when collection completes.

Use the [version comparison reference](../reference/version-comparison.md) for comparator selection and accepted forms.

## Remote checks

The external scanner performs proof requests, TCP connections, TLS handshakes and a few read-only web-path requests. It does not exploit services or inspect UDP. Address selection and TLS-port limits make this a focused exposure check.

A finding resolves only on evidence: the port refused the connection, or the TLS handshake ran and no longer shows the problem. A filtered port, a timed-out check or a target that stopped answering keeps it open with a "Still open" reason. The [external scan reference](../reference/external-scans.md) defines these limits.

The scan runs the [network engine](../reference/network-engine.md)'s prober. Its banner-to-CVE findings are graded unverified and ranked below exposures read directly: a banner can be spoofed, and distributions backport fixes without changing the version. Its time budgets do not guarantee cancellation at an exact deadline.

## Devices on your networks

The device list comes from your machines' own neighbour tables, so it shows only devices those machines have talked to recently. A device on a network with no agent, or one that never talks to an enrolled machine, isn't listed. Network checks cover only private IPv4 subnets a machine is directly attached to (IPv6 neighbours are listed but not checked), at most 32 devices a run, with the same fixed checks as the external scanner. A network card that answers at several addresses at once isn't checked. "Nothing found" means those checks found nothing, not that the device is secure.

A compromised enrolled machine can report false results about the devices it checks; these change only its own view of each device. It can also take up to 64 devices off the list by claiming their addresses. DECISIONS 130–132 record these limits.

## Containers

The agent reads the distribution packages inside running Docker, Podman and Kubernetes (containerd, CRI-O) containers, and from agent 0.9.0 the Python, npm, Java and Go packages their images added, each with where it sits. "Nothing found" in an image means nothing was found in what was read, not that the image is safe, and an application package's finding means it is present, not that its vulnerable code runs. Not read yet: Ruby, PHP, .NET and Rust packages, jars without `pom.properties`, Java archives nested more than two levels deep, other software copied into an image outside its package manager, rootless containers, stopped containers and images at rest, and rpm's Berkeley DB and ndb databases (RHEL 8 family, UBI 8 and openSUSE images). Each image that couldn't be read says so and why; none is shown as clean.

A container is seen only while it runs at report time, so a short-lived job container's findings can open and close between reports. An image's findings close when every machine that ran it reports its containers without it, or reports that the runtime it ran in (Docker or Podman) is no longer installed; a machine that stops reporting keeps its images open. A package database on a separate mount inside the container (a volume over `/var/lib/dpkg`, say), or one with more than 10,000 packages, isn't read and says so. A compromised enrolled machine can add images of its own invention (at most 48 a day and 256 at once), or stop listing an image only it runs, but it can't change, rename or close an image another machine reported (DECISIONS 139, 140, 143).

## Agentless Windows

Agentless Windows scans depend on PowerShell remoting and the caller's permissions. They provide findings, but fixes need an installed agent.

## Evidence and operation

A signature cannot prove complete collection. A rollback cannot necessarily reverse every installer side effect. Performance measured on a test host is not a capacity guarantee for a production deployment.

The repository's [STATUS](https://github.com/Nimstead/assure/blob/main/STATUS.md) records detailed proofs and remaining gaps. It includes historical entries. Check their date, platform, and code context before applying a result to your environment.

For action, use [scan troubleshooting](../how-to/troubleshoot-scans.md). For interpretation, read [detection confidence](detection-confidence.md).
