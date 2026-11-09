# Scan an external target

Check exposed services and TLS on a host you control. You need an admin session, DNS control, and access to the web service at the target address.

1. On **Assets → External targets**, enter the hostname and select **Add target**.
2. Publish the exact TXT record shown by Assure.
3. Serve the same value at the displayed `/.well-known/nimstead-verify.txt` path over HTTP or HTTPS.
4. Select **Verify**. Confirm the target shows **Verified**.
5. Select **Scan now**.
6. Review open findings and the **Not checked** list.

Both proofs are required. DNS ownership alone does not prove control of the scanned server. Targets that resolve to a private address are refused.

If verification fails, check the public DNS answer and response body at the exact proof path. A target with no web service on port 80 or 443 cannot supply this proof.

The scan performs TCP connections and TLS handshakes. It does not log in, exploit a service, or infer remote CVEs from banners. Read [coverage limits](../explanation/coverage-limits.md) before interpreting a result with no findings.
