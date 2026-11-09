# Analyse your CVE list

Rank a scanner or ticket CVE list using public observations. You need a browser and the CVE IDs you want to review.

1. Open [Your CVEs](https://pulse.nimstead.systems/watchlist/).
2. Paste your CVE IDs, or select **Choose file** to read a local export.
3. Select **Analyse** and wait for the public index to load.
4. Read the matched, not-found, and rejected counts before you use the priority table.
5. Review the source dates, KEV observations, and missing scores.
6. Open relevant case records and verify whether the affected products apply to your environment.

The list is processed in the browser. It is not uploaded or saved automatically. Reloading the page clears the session.

If analysis fails, check the connection and select **Analyse** again. Read the error before using any previous results that remain visible.

Use [snapshots](snapshots.md) to preserve a list for a later comparison. Use [handovers](handover.md) to prepare a text summary. Keep those files private because your choice of CVEs can reveal information about your environment.

Source: [Pulse repository documentation](https://github.com/Nimstead/pulse/blob/main/README.md).
