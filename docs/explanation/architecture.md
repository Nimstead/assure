# Deployment architecture

Assure runs on infrastructure you operate. The server combines an HTTP API, web interface, and agent distribution. PostgreSQL stores operational records. A separate feed process refreshes advisory data and reassesses inventory.

## Three sources of inventory

An installed agent reports packages and host facts. A build pipeline uploads an SBOM for an application. An external target supplies a narrower view through network and TLS checks after ownership verification.

These sources answer different questions. An external check cannot replace a host inventory. An SBOM identifies dependencies but cannot establish whether an affected code path is reachable.

## From reports to records

The server evaluates inventory against its available content. Findings carry evidence and limits. Approved remediation jobs travel back to opted-in agents. Later inventory establishes whether the affected state changed.

Ledger events preserve the operational history. Signed checkpoints outside the database make changes or truncation detectable. An evidence pack carries material for independent verification.

## Boundaries that matter

The operator controls hosting and evidence keys. Nimstead release signatures control which agent updates are accepted. A server cannot grant itself the host's local remediation permission.

A self-hosted deployment still needs backups, protected keys, current feeds, trusted TLS, and recovery procedures. The [deployment guide](../how-to/deploy-server.md) provides the steps. [Configuration](../configuration.md) lists the operational controls.
