# Export evidence for a reviewer

Create an evidence pack for independent verification. You need access to your organisation's **Evidence** page and the review period.

1. Open **Evidence** and check the ledger verification result.
2. Select the period required by the reviewer.
3. Review each control's evidence, exceptions, coverage and findings for that period.
4. Download the signed evidence pack.
5. Verify the downloaded pack with the [verification procedure](verify-evidence.md).
6. Give the reviewer the pack and the [verification procedure](verify-evidence.md).
7. Send the evidence key fingerprint through a separate trusted channel.

Do not use a fingerprint carried only inside the pack as the trust reference. Obtain it from the established operator or your operator's established evidence-key endpoint over a trusted connection.

If the ledger reports a shortened or changed history, investigate before sending the pack as a complete record. A restore from an older backup can cause a shortened-history warning.

A valid signature proves the pack's integrity under its key. It does not certify that every control was met. See [evidence trust](../explanation/evidence-trust.md).

## Check the downloaded result

The ledger category filter does not change the pack. Its list shows the latest 50 matching events across the whole history. The period applies to the report and pack.

Check the downloaded pack's organisation and period. The report and download are separate requests, so their counts can differ after new events. The pack includes checkpoints that can cover history outside the period.

## Recover from an export failure

If the download returns an integrity error, stop distribution and investigate the ledger problems. Do not describe a failed download as a signed export.

If the signing key changed, reload the page before obtaining its fingerprint again. The page caches signing material indefinitely within its query client. Establish the new fingerprint through the trusted channel before the reviewer accepts it.
