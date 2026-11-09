# Review and triage findings

Use this guide after an asset reports successfully. You need access to the organisation's findings and scan records.

1. Open **Findings** and select the relevant asset or fleet filter.
2. Start with the highest priority findings. Read the reasons rather than using the score alone.
3. Check the detected package, installed version, advisory, and evidence.
4. Open the asset's scan report. Identify incomplete or undetermined checks.
5. Review any proposed fix and its platform limits before planning a change.
6. After a change, wait for a new inventory and confirm the finding's state.

A finding that disappears from one filtered view is not necessarily resolved. Keep the same asset and vulnerability identity when comparing results.

For an unexpected finding, compare the reported version and the advisory's affected range. Distribution backports and Windows product branches require their own version rules.

Use [scan troubleshooting](troubleshoot-scans.md) for incomplete data. Read [scan outcomes](../reference/scan-outcomes.md) and [detection confidence](../explanation/detection-confidence.md) to interpret negative results.

## Accept a documented risk

You need an organisation admin browser session. Acceptance changes triage status. It does not repair the asset.

1. Open the finding drawer.
2. Select **Accept risk**.
3. Enter a reason of at least ten characters.
4. Select 30, 90 or 180 days.
5. Leave the scope checkbox clear to accept only this finding.
6. Select **Accept risk** to submit the request.
7. Open the **Accepted** status view.
8. Clear **Fixable only** if the finding has no fixed version.
9. Confirm the same asset and vulnerability identity appear there.

Select the scope checkbox only to accept all currently open matches for that vulnerability across the organisation. This includes other packages and assets.

For a selection, use the row checkboxes and **Accept risk…**. Select-all covers loaded rows only. Review the accepted count. The server can skip rows that changed status or became unavailable.

After expiry, reassessment can reopen a finding if its match remains. A read request alone does not apply expiry.

## Recover or retry

If acceptance fails, read the displayed error. Correct the reason or permissions before another request.

To reverse acceptance, open the finding under **Accepted**. Enter a reason under **Why it needs fixing after all**. Select **Revoke acceptance**, then confirm its status under **Open**.

If bulk planning fails, inspect **Remediation** before another attempt. Earlier package groups can already have created jobs.

See the [finding API reference](../reference/findings.md) for status transitions, accepted/skipped counts and expiry limits.
