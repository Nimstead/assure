# Assure documentation

Choose a page for your reader task. These pages describe the current checkout. Check [STATUS](../STATUS.md) for recorded platform proofs and limits.

Use the [searchable wiki](https://docs.nimstead.systems/assure/) or browse below. [Pulse documentation](https://docs.nimstead.systems/pulse/) covers the other current Nimstead product.

## Learn

Follow a safe worked example.

- [Read your first SBOM](tutorials/first-sbom.md)

## Complete a task

Choose the procedure for your task.

- [Deploy with Docker Compose](how-to/deploy-server.md)
- [Configure HTTPS](how-to/configure-https.md)
- [Enrol a Linux machine](how-to/enrol-linux.md)
- [Enrol a Windows machine](how-to/enrol-windows.md)
- [Deploy through Group Policy](how-to/deploy-group-policy.md)
- [Review and triage findings](how-to/review-findings.md)
- [Enable remediation safely](how-to/enable-remediation.md)
- [Upload an SBOM from CI](how-to/upload-sbom.md)
- [Scan an external target](how-to/scan-external-target.md)
- [Scan Windows without an agent](how-to/remote-windows.md)
- [Configure single sign-on](how-to/configure-sso.md)
- [Configure alerts](how-to/configure-alerts.md)
- [Export evidence for a reviewer](how-to/export-evidence.md)
- [Verify an evidence pack](how-to/verify-evidence.md)
- [Verify an agent release](how-to/verify-agent-release.md)
- [Upgrade the server](how-to/upgrade-server.md)
- [Back up Assure](how-to/back-up.md)
- [Restore a backup](how-to/restore.md)
- [Troubleshoot a missing or incomplete scan](how-to/troubleshoot-scans.md)
- [Remove an agent](how-to/remove-agent.md)
- [Run without Docker](how-to/run-without-docker.md)
- [Contribute to Assure](../CONTRIBUTING.md)
- [Prepare a production deployment](how-to/prepare-production.md)
- [Release Assure](how-to/release-assure.md)
- [Recover from a bad release or signing-key leak](how-to/recover-release.md)
- [Check Windows Update access through a proxy](how-to/configure-windows-update-proxy.md)

## Look up details

Find commands, settings, formats, and limits.

- [Configuration](configuration.md)
- [Supported platforms](reference/platforms.md)
- [Lifecycle reference](reference/lifecycle.md)
- [Platform update reference](reference/platform-updates.md)
- [Agent command reference](reference/agent-cli.md)
- [Version comparison reference](reference/version-comparison.md)
- [Priority score reference](reference/risk-score.md)
- [Optional AI reference](reference/optional-ai.md)
- [HTTP endpoint catalog](reference/api-endpoints.md)
- [HTTP API reference](reference/http-api.md)
- [Finding API and state reference](reference/findings.md)
- [Database model reference](reference/database.md)
- [Notification reference](reference/notifications.md)
- [Windows settings and baseline reference](reference/windows-checks.md)
- [Windows application mapping reference](reference/windows-apps.md)
- [Feed synchronisation reference](reference/feed-sync.md)
- [SBOM input reference](reference/sbom.md)
- [Scan outcomes](reference/scan-outcomes.md)
- [Scan report format](reference/scan-report.md)
- [Inventory and collection metadata](reference/inventory-format.md)
- [Fleet attack-path format](reference/fleet-paths.md)
- [External scan reference](reference/external-scans.md)
- [Network engine reference](reference/network-engine.md)
- [Evidence responses and pack format](reference/evidence-format.md)
- [Remediation modes](reference/remediation-modes.md)
- [Remediation jobs and policy](reference/remediation-jobs.md)
- [Release keys](release-keys.md)
- [Developer tools and repository map](reference/tooling.md)
- [Web client reference](reference/web-client.md)
- [Glossary](reference/glossary.md)

## Understand the system

Read the reasons, trust boundaries, and tradeoffs.

- [Deployment architecture](explanation/architecture.md)
- [From inventory to evidence](explanation/inventory-to-evidence.md)
- [Detection confidence and incomplete scans](explanation/detection-confidence.md)
- [How remediation limits a change](explanation/remediation-safety.md)
- [Why agent updates are signed](explanation/signed-updates.md)
- [What an evidence signature proves](explanation/evidence-trust.md)
- [Coverage and known limits](explanation/coverage-limits.md)

## Repository records

[Design decisions](../DECISIONS.md), [engine designs](engine/design-e2.md), and [task plans](../tasks/plan.md) retain rationale and planned work. They do not replace current operator instructions.

[Changelog](../CHANGELOG.md) records release changes. [Security](../SECURITY.md) gives the vulnerability-reporting policy.
