# How remediation limits a change

Remediation crosses a different trust boundary from collection. A report describes a host. A fix changes it. Assure therefore requires host consent, server permission, and approval through the organisation's selected mode.

## Plans constrain execution

A plan identifies the permitted package changes. If a dependency requires a wider change, the operator must review the expanded plan. A successful package command is only an execution result; subsequent inventory establishes whether the finding is resolved.

Canaries reduce the number of machines exposed to a bad change. Health checks and a soak period supply evidence before broad rollout. These controls reduce risk but do not prove that every application behaviour remained correct.

## Rollback has a boundary

Package rollback can restore package files and package database state without reversing every effect of an installation script. Snapshot-based recovery also excludes some separate filesystems and subvolumes.

Some Windows updates leave companion components after rollback. Some application upgrades cannot be undone. The plan's stated recovery method matters more than a general promise of rollback.

Start with test hosts, define important services, and retain a host recovery path. The [remediation guide](../how-to/enable-remediation.md) describes the operational sequence.
