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
