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

The token only works for that asset. Organisation API tokens (`nmt_`) are read-only and cannot upload. An asset's agent key can also upload an SBOM for its own asset. Each asset takes at most 60 uploads an hour; more answer HTTP 429.

Every successful upload replaces the previous SBOM packages. Keep the previous build's SBOM if you need to restore its inventory. Re-upload that complete document to restore it; doing so records a new scan and ledger event.

## Container images

An image's SBOM is mostly operating-system packages. Assure matches them against the distribution's own advisories, using the source package each was built from, as the agent does for a machine. Generate the SBOM with Syft or Trivy (CycloneDX or SPDX JSON, both tools' default format), then upload it as above:

```bash
syft "registry.example.com/billing-api:${GIT_SHA}" -o cyclonedx-json > sbom.json
```

```bash
trivy image --format cyclonedx --output sbom.json "registry.example.com/billing-api:${GIT_SHA}"
```

The response's `distro` names the release the OS packages belong to, such as `Debian:12`. Findings from an SBOM are graded unverified, because an SBOM states what was built, not what is running. If the base image is past its end of support, that is a finding too. Assure never plans a fix on an image: rebuild it and upload the new SBOM, and the findings it no longer has close.

One SBOM is one image. OS packages of a second release are skipped and counted as `other_distro`. To see what actually runs, rather than what was built, let the agents read the running containers: see [Find vulnerabilities in running containers](scan-containers.md).

## Resolve an upload failure

| Response | Action |
| --- | --- |
| 401 | Check the asset ID and its upload token. Do not substitute an organisation API token. |
| 403 with a browser session | Sign in as an admin and complete two-step sign-in when required. |
| 413 | Reduce the document below 10 MiB. Do not split it into consecutive partial uploads: each replaces the previous inventory. |
| 422 | Read `detail`; check JSON format, supported spec version, nesting, and component count. |
| Success with skipped packages | Generate versioned package URLs for supported ecosystems. Review the skipped counts before treating the scan as complete. |

See [SBOM reference](../reference/sbom.md) for limits and [HTTP API](../reference/http-api.md) for authentication.
