# Remediation modes

The organisation's trust ladder controls how fixes become eligible to run. It does not override local host consent.

| Mode | Behaviour |
| --- | --- |
| Suggest | Assure recommends upgrades. It does not apply changes. |
| Approve | A person must approve each planned fix. The approval is recorded. |
| Auto | Eligible fixes run without individual approval, with canary and rollout controls. |

Hosts must opt in locally. Production remediation also requires `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1` on the server.

## Scheduling constraints

Approved fixes start inside the applicable maintenance window. A host's window overrides the organisation's window. Canary health and soak requirements can delay broad rollout.

Windows restart handling depends on server/workstation state and configured deadlines. Cluster nodes and domain controllers have additional sequencing rules.

## Verification and failure

The job log records execution. The next inventory determines whether the finding is resolved. A failed health check triggers the plan's recovery path where available.

Not every application update can be undone. A plan without rollback needs explicit acknowledgement and must retain that limitation in review.

Related: [enable remediation](../how-to/enable-remediation.md), [remediation safety](../explanation/remediation-safety.md).
