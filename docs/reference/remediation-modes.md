# Remediation modes

The organisation's trust ladder controls how fixes become eligible to run. It does not override local host consent.

| Mode | Behaviour |
| --- | --- |
| Suggest | Assure recommends upgrades. It does not apply changes. |
| Approve | A person must approve each planned fix. The approval is recorded. |
| Auto | Eligible actions can receive policy approval. Broad-ring policy approval requires a qualifying canary and soak period. |

Hosts must opt in locally. Production remediation also requires `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1` on the server.

Planning does not require local opt-in, production permission, or an enabled approval mode. Approval and dispatch apply server gates. The agent enforces local execution consent.

Winget and Windows configuration changes require a person. Automatic planning also skips Microsoft/WinApp base-manager paths, including Office and .NET application fixes. A human can approve without the policy canary gate. Forward-only winget and servicing-stack jobs require explicit acknowledgement.

## Scheduling constraints

Approved fixes are dispatched inside the applicable maintenance window. A host's window overrides the organisation's window. Dispatch eligibility does not guarantee that execution or restart finishes inside it.

An empty host window inherits the organisation window. An empty organisation window permits any time. Canary health and soak requirements can delay broad policy rollout.

Windows restart handling depends on server/workstation state and configured deadlines. Cluster nodes and domain controllers have additional sequencing rules.

## Verification and failure

The job log records reported execution. Stored finding state normally determines success after inventory. A Windows stepping job can succeed while findings remain open for another update. Accepted findings still count as unresolved for ordinary verification.

A failed health check triggers the agent's recovery path where available. Server success does not independently establish host health or repair. See [job states and verification](remediation-jobs.md#states-and-verification).

Not every application update can be undone. A plan without rollback needs explicit acknowledgement and must retain that limitation in review.

## Health checks

Linux package jobs check configured systemd units and restart counters. Their default settling delay is 15 seconds when health units exist. Windows cumulative jobs normally wait 60 seconds before post-change health checks when services exist. They also inspect service crash/stop events since the change.

Windows application/configuration jobs use service-state checks without that cumulative-job settling delay. An empty health-unit list provides no application service check. These checks do not test every application behavior.

Related: [enable remediation](../how-to/enable-remediation.md), [job reference](remediation-jobs.md), [remediation safety](../explanation/remediation-safety.md).
