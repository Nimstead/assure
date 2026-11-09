# Save and compare snapshots

Keep a CVE list and compare public observations on a later visit. You need a completed analysis of your own list.

## Save a baseline

1. Review the analysis coverage and feed dates.
2. Select **Download snapshot**.
3. Save the JSON file in an appropriate private location.

The snapshot includes all submitted CVE IDs, including missing and rejected records. It excludes raw scanner text and downloaded descriptions.

## Compare a saved list

1. Open **Your CVEs** and select **Load snapshot**.
2. Choose the Pulse JSON snapshot.
3. Wait for the refreshed public index and analysis.
4. Read **Changes since your saved snapshot**.
5. Select **Review changes** to inspect the differences.

You can edit the restored list and analyse it again to compare membership changes. Removing a CVE from a list does not mean it was remediated.

Federal due dates are comparable only when both snapshots included them. Model changes and snapshots newer than the current feeds need separate interpretation. A same-day reload can show no change.

An imported snapshot is user-supplied information, not authenticated historical evidence. If it is rejected, read the validation error and use an original Pulse snapshot. See [snapshot fields and limits](../reference/snapshots.md).

Source: [Pulse repository documentation](https://github.com/Nimstead/pulse/blob/main/README.md).
