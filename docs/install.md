# Install and operate Assure

Choose the task you need. Each linked guide gives its prerequisites, procedure, and verification. For commands and limits, use the [documentation index](README.md).

## With Docker Compose

[Deploy the server](how-to/deploy-server.md) on one host with Docker Compose v2. The guide covers initial configuration, feed history, and health checks.

## Put it behind HTTPS

[Configure HTTPS](how-to/configure-https.md) before remote browser access or agent enrolment. Plain HTTP sign-in works only on localhost.

## Add your first machine

- [Enrol Linux](how-to/enrol-linux.md).
- [Enrol Windows](how-to/enrol-windows.md).
- [Deploy through Group Policy](how-to/deploy-group-policy.md).

Use [supported platforms](reference/platforms.md) for requirements and collection limits. Use [agent commands](reference/agent-cli.md) for flags, state, and scheduling.

### The agent updates itself

Read [signed updates](explanation/signed-updates.md) for the trust model and [agent update controls](reference/agent-cli.md#update-controls) for pause and migration options.

### Install without trusting the server

[Verify an agent release](how-to/verify-agent-release.md) against a trusted verifier before the first installation.

### Troubleshooting

[Diagnose a missing or incomplete scan](how-to/troubleshoot-scans.md). The guide includes Linux and Windows diagnostic commands.

### Remove the agent

[Remove an agent](how-to/remove-agent.md) and verify removal. Export required logs before you delete local state.

### Fixing things automatically

[Enable remediation](how-to/enable-remediation.md) on test machines before production. Check [remediation modes](reference/remediation-modes.md) for scheduling and rollback boundaries.

## Upgrade

[Upgrade the server](how-to/upgrade-server.md) with signed releases, health checks, and automatic rollback.

## Back up

[Back up the database and signing material](how-to/back-up.md) together.

### Restore

[Restore a matching backup](how-to/restore.md) on an isolated or replacement host. Compare its evidence fingerprint with your trusted copy.

## Without Docker

[Run without Docker](how-to/run-without-docker.md) for a local trial or a separately managed deployment.

## Production checklist

[Prepare a production deployment](how-to/prepare-production.md) before you permit production changes.

## Scan Windows hosts with no agent

[Scan remote Windows hosts](how-to/remote-windows.md) through PowerShell remoting. This collects inventory but cannot apply fixes.
