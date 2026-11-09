# Upload an SBOM from CI

Use this guide to replace an application's package inventory after a build. You need an Assure server, an organisation admin account, curl, and a supported JSON SBOM.

1. Sign in as an admin and add an application on **Assets**. Record its asset ID and the upload token shown when it is created. The API equivalent is `POST /api/assets` with an admin session.
2. Store the `nmu_` upload token as a masked CI secret. Set `ASSURE_URL`, `ASSURE_ASSET_ID`, and `ASSURE_UPLOAD_TOKEN` in the job environment.
3. Generate the complete SBOM for the build and save it as `sbom.json`.
4. Send the JSON body:

   ```bash
   curl --fail-with-body --silent --show-error \
     --header "Authorization: Bearer ${ASSURE_UPLOAD_TOKEN}" \
     --header 'Content-Type: application/json' \
     --data-binary @sbom.json \
     "${ASSURE_URL}/api/assets/${ASSURE_ASSET_ID}/sbom"
   ```

5. Check `unique_packages` and both `skipped` counters in the response. Compare them with the build inventory. Open the application in Assure and review its findings and scan coverage.

The token only works for that asset. Organisation API tokens (`nmt_`) are read-only and cannot upload. An asset's agent key can also upload an SBOM for its own asset.

Every successful upload replaces the previous SBOM packages. Keep the previous build's SBOM if you need to restore its inventory. Re-upload that complete document to restore it; doing so records a new scan and ledger event.

## Resolve an upload failure

| Response | Action |
| --- | --- |
| 401 | Check the asset ID and its upload token. Do not substitute an organisation API token. |
| 403 with a browser session | Sign in as an admin and complete two-step sign-in when required. |
| 413 | Reduce the document below 10 MiB. Do not split it into consecutive partial uploads: each replaces the previous inventory. |
| 422 | Read `detail`; check JSON format, supported spec version, nesting, and component count. |
| Success with skipped packages | Generate versioned package URLs for supported ecosystems. Review the skipped counts before treating the scan as complete. |

See [SBOM reference](../reference/sbom.md) for limits and [HTTP API](../reference/http-api.md) for authentication.
