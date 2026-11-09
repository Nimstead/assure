# Enrol a Linux machine

Connect a supported Linux host to an existing HTTPS Assure server. You need root or sudo access, Python 3.9 or later, and curl.

## Install and report

1. Open **Assets** and choose the action to add a machine.
2. Select the host's environment. Use **Test machines** for a disposable or staging host.
3. Copy the enrolment command supplied by your server. Its shape is:

```bash
export NIMSTEAD_TOKEN=nme_…
curl -fsSL --proto '=https' https://assure.example.com/install.sh | sudo --preserve-env=NIMSTEAD_TOKEN sh
unset NIMSTEAD_TOKEN
```

Replace the example server and token with the values from Assure. The installer registers the host and configures a systemd timer.

4. Open the asset record. Confirm the hostname and recent report time.
5. Review the scan outcomes before you act on findings.

The token is an environment variable to keep it out of process arguments. Revoke the enrolment token when your rollout is complete.

## Choose optional access

Remediation is off by default. Follow [enable remediation](enable-remediation.md) when you are ready to permit changes.

For collection options, use the agent's `enroll` flags in the [command reference](../reference/agent-cli.md). Java and application scans require explicit local opt-in.

If the host does not report, run [scan troubleshooting](troubleshoot-scans.md). For a first installation you must trust the server, or follow [verify an agent release](verify-agent-release.md).
