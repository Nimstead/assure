# Read your first Pulse triage

Open Pulse's worked example and learn how to read a CVE list without using any private data. You need a browser and an internet connection. No account is required.

## Open the worked example

Open [Your CVEs](https://pulse.nimstead.systems/watchlist/). The page starts with a fixed example of 14 well-known CVEs. Confirm that it is labelled as a worked example.

If the example does not load, reload the page. If you previously cleared it, select **Show the example again** when offered. Do not paste a real scanner export for this lesson.

## Read the coverage

Find the analysis coverage summary. It separates matched, missing, and rejected records. Missing records do not count as zero risk.

Read the public feed dates. The page describes a daily snapshot, not a live monitoring feed. The example's exact observations can change with later feed updates.

## Inspect one CVE

Select a CVE in the priority table to open its case record. Compare its severity, KEV status, and EPSS observation.

These values answer different questions. Severity describes impact. KEV records confirmed exploitation in CISA's catalogue. EPSS estimates the probability of exploitation in the next 30 days.

## Try a filter

Enter one visible CVE ID into the table filter. Confirm that the table narrows to matching rows. Clear the filter to restore the list.

You have now checked coverage, inspected a record, and separated three risk signals. To work with your own input, follow [analyse a CVE list](../how-to/analyse-list.md).

Source: [Pulse repository documentation](https://github.com/Nimstead/pulse/blob/main/README.md).
