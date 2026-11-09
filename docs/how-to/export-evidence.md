# Export evidence for a reviewer

Create an evidence pack for independent verification. You need access to your organisation's **Evidence** page and the review period.

1. Open **Evidence** and check the ledger verification result.
2. Select the period required by the reviewer.
3. Review coverage, findings, and any gaps in that period.
4. Download the signed evidence pack.
5. Give the reviewer the pack and the [verification procedure](verify-evidence.md).
6. Send the evidence key fingerprint through a separate trusted channel.

Do not use a fingerprint carried only inside the pack as the trust reference. Obtain it from the established operator or the server's authenticated evidence-key endpoint.

If the ledger reports a shortened or changed history, investigate before sending the pack as a complete record. A restore from an older backup can cause a shortened-history warning.

A valid signature proves the pack's integrity under its key. It does not certify that every control was met. See [evidence trust](../explanation/evidence-trust.md).
