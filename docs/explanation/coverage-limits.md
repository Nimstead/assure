# Coverage and known limits

Assure reports what its collectors and advisory sources can establish. Coverage varies by platform, package ecosystem, permissions, and available content.

## Application inventory

SBOM support covers CycloneDX and SPDX JSON with supported, versioned package URLs. It does not include XML, SPDX tag-value, or VEX. A package being present does not prove that vulnerable code is reachable.

Windows third-party application matching uses a curated catalogue. Other applications remain inventory. Advisory delays and incorrect upstream ranges can affect results.

## Remote checks

External scans perform TCP connections and TLS handshakes. They do not exploit services, inspect UDP, or derive remote CVEs from banners. Address selection and TLS-port limits make this a focused exposure check.

Agentless Windows scans depend on PowerShell remoting and the caller's permissions. They provide findings, but fixes need an installed agent.

## Evidence and operation

A signature cannot prove complete collection. A rollback cannot necessarily reverse every installer side effect. Performance measured on a test host is not a capacity guarantee for a production deployment.

The repository's [STATUS](https://github.com/Nimstead/assure/blob/main/STATUS.md) records detailed proofs and remaining gaps. It includes historical entries. Check their date, platform, and code context before applying a result to your environment.

For action, use [scan troubleshooting](../how-to/troubleshoot-scans.md). For interpretation, read [detection confidence](detection-confidence.md).
