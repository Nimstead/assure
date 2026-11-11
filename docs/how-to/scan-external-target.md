# Scan an external target

Check exposed services and TLS from the Assure server's network vantage point. You need an admin session, DNS control, and control of the target web service.

Keep `NIMSTEAD_ALLOW_PRIVATE_TARGETS` disabled in production. This development switch bypasses the private-address refusal.

1. On **Assets → External targets**, enter the hostname and select **Add target**.
2. Publish the exact TXT record shown by Assure.
3. Serve the same value at the displayed `/.well-known/nimstead-verify.txt` path over HTTP or HTTPS.
4. Select **Verify**. Confirm the target shows **Verified**.
5. Select **Scan now**.
6. Review open findings and any **Not checked** text.

Both proofs are required. DNS ownership alone does not prove control of the scanned server. Keep both proofs available for later scans.

After verification, scheduled feed runs also scan the target. Manual scans are limited to ten per organisation per hour.

If verification fails, check the public DNS answer and the response body at the exact proof path. Return HTTP 200 directly, without a redirect. A target without HTTP on 80 or HTTPS on 443 cannot supply the proof.

If scanning reports lost DNS ownership, restore the TXT record and select **Verify** again. If scanning reports missing address proof, restore the proof response and repeat the scan.

A finding resolves only when the scan sees evidence: the port refused the connection, or the TLS handshake no longer shows the problem. A port that drops connections keeps its finding open with a "Still open" reason. Open **What the last scan checked** under the target to see each port's result.

The scan performs proof requests, TCP connections, TLS handshakes, and read-only `GET` requests for `/.git/config` and `/.env` on port 80. It does not log in or exploit a service.

See [external scan reference](../reference/external-scans.md) for ports, counters, and address selection. Read [coverage limits](../explanation/coverage-limits.md) before interpreting a result with no findings.
