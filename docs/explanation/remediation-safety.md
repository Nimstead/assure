# How remediation limits a change

Remediation crosses a different trust boundary from collection. A report describes a host. A fix changes it. Assure therefore requires host consent, server permission, and approval through the organisation's selected mode.

## Plans constrain execution

A plan identifies the permitted package changes. Linux execution compares parsed manager dry-run output with that plan. Unfamiliar or incomplete output can weaken that check. If a dependency requires a wider change, the operator must review the expanded plan. A successful package command supplies an execution result. Subsequent inventory normally establishes finding resolution.

Windows can need an earlier update before the final fix becomes available. Assure can record that step as successful while findings remain open. The job and finding therefore answer different questions: whether a permitted step completed, and whether the vulnerability remains recorded.

Canaries reduce the number of machines exposed to a bad change. Health checks and a soak period supply evidence before broad policy rollout. Human approval can proceed without that policy gate.

Version evidence also has limits. KB jobs require reported versions that reach their targets. Other jobs can qualify without complete version reports. Pinning only changes targets when a reported version is a valid upgrade. These controls do not prove that every application behavior remained correct.

## Rollback has a boundary

Package rollback can restore package files and package database state without reversing every effect of an installation script. Snapshot-based recovery also excludes some separate filesystems and subvolumes.

Some Windows updates leave companion components after rollback. Some application upgrades cannot be undone. The plan's stated recovery method matters more than a general promise of rollback.

Application recovery also depends on when a failure occurs. Office and registry handlers return an undo action only after their change succeeds. A handler that partly changes the host and then fails can return aborted without automatic undo. The job status therefore cannot replace inspection of the host.

Local report retries preserve outcomes across ordinary request failures. Disk errors and process failure can still lose a result. Windows state can disappear before the terminal report is written. Host recovery and evidence delivery therefore remain separate concerns.

Start with test hosts, define important services, and retain a host recovery path. The [remediation guide](../how-to/enable-remediation.md) describes the operational sequence.

For implementation boundaries, see the [agent execution reference](../reference/agent-jobs.md).
