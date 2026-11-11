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

Agentless Windows scans depend on PowerShell remoting and the caller's permissions. They provide findings, but fixes need an installed agent.

## Evidence and operation

A signature cannot prove complete collection. A rollback cannot necessarily reverse every installer side effect. Performance measured on a test host is not a capacity guarantee for a production deployment.

The repository's [STATUS](https://github.com/Nimstead/assure/blob/main/STATUS.md) records detailed proofs and remaining gaps. It includes historical entries. Check their date, platform, and code context before applying a result to your environment.

For action, use [scan troubleshooting](../how-to/troubleshoot-scans.md). For interpretation, read [detection confidence](detection-confidence.md).
