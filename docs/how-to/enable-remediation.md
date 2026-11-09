# Enable remediation safely

Permit Assure to apply approved changes to a test host. You need an organisation admin account and local administrator access to that host.

## Enable the three permissions

1. Opt in on the host with `--allow-remediation` at enrolment. On Windows, set `$env:NIMSTEAD_ALLOW_REMEDIATION = "1"` before installation.
2. Enrol disposable hosts with **Test machines** selected. Production changes remain disabled unless `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1` is set on the server.
3. In **Settings → Trust ladder**, select **Approve** and save. This requires a person to approve each planned fix.

## Opt in an existing host

For an already enrolled test host, retain a protected copy of its agent.json file. Find its path in the [configuration reference](../reference/agent-core.md#configuration-and-state). Set allow_remediation to true in that existing JSON file. Preserve the asset ID, key and all other fields.

Run that agent's schedule command with its normal service privileges to add the job timer/task. Confirm the configuration remains readable with doctor, then verify the expected schedule. Do not reenrol solely to change this flag. Enrolment creates another asset.

Restore the protected copy if the configuration edit fails. Setting this flag does not change the server's production-execution restriction or convert a production asset into a test asset.

## Define health checks

On **Assets**, enter the important services under **Health units**, such as `nginx, postgresql`. Use the actual service names on that host.

After a change, the agent checks those services. A failed health check triggers rollback where the plan supports it.

## Review and approve a fix

1. Select a finding and review the proposed package plan.
2. Check the target machine, package changes, maintenance window, restart requirements, and rollback limits.
3. Approve the plan only when those effects are acceptable.
4. Follow the job's steps on **Remediation**.
5. Inspect the next inventory and the finding's current state. A completed command alone does not prove a fix.

If a Windows stepping job succeeds with findings still open, review the next proposed update. Approve each required step separately. Do not treat intermediate job success as complete remediation.

Plans that cannot be undone require explicit acknowledgement. Do not assume every application update has a rollback.

To withdraw a plan before dispatch, cancel it on **Remediation**. Cancellation is available only for planned or approved jobs. A dispatched job can already run on the host. Use the host's recovery procedure if execution fails.

Keep **Auto** disabled until you have observed successful changes and failure recovery on test hosts. For its behaviour, read [remediation modes](../reference/remediation-modes.md) and [remediation safety](../explanation/remediation-safety.md).

On Windows, preserve the configuration file owner and ACLs during edits. See [state-directory cleanup](../reference/agent-core.md#windows-state-directory) before replacing a file.
