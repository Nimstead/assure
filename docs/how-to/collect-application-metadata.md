# Collect application package metadata

Enable optional metadata collection on an enrolled host. You need local administrator access and permission to inspect the asset's scan report. Select local application roots that you intend the agent to read.

Java scans use default local drive roots. Python/npm scans use declared defaults and optional extra roots. Budgets are soft checks between operations. A slow read can exceed the nominal duration.

## Enable collection

1. Locate agent.json in the [configuration reference](../reference/agent-core.md#configuration-and-state).
2. Retain a protected copy of that file.
3. Set scan_apps to true for Python/npm collection.
4. Add app_roots as an array of absolute project/environment paths when needed.
5. Set scan_jars to true if you also need Java archive discovery.
6. Save valid JSON while preserving the asset ID, key and other fields.

Limit extra roots to 20 for consistency with the CLI. Select regular local directories. Avoid links and network shares. Preserve the owner and permissions, including Windows ACLs.

Do not enrol again solely to change these flags. Direct enrolment creates another asset. app_roots does not restrict Java's default drive traversal.

## Verify a report

1. Run the enrolled agent's report command with its service privileges.
2. Confirm that the intended asset's last report time advances.
3. Review scan outcomes and incomplete reasons.

For local detail, run collect with the same --scan-apps, --scan-jars and --app-root choices. Collect does not load saved opt-in flags. Inspect packages, collection.sources and scan facts.

Python/npm records use PyPI/npm ecosystems. Java records use Maven. Inspect source paths and collection errors before treating a missing package as absent. Java complete=true means no budget stop. Unreadable archives can still have been skipped.

A report acknowledgement does not establish advisory coverage or runtime use. See the [scan reference](../reference/agent-app-scans.md) for exclusions, summaries and failure limits.

## Recover or disable collection

If a configuration edit breaks loading, restore the protected copy and report again. Keep the key private.

If collection exceeds your intended load, set the relevant scan flag to false. Save valid JSON and verify the next report. Extra roots add to default Python/npm folders. They do not disable those defaults.

Do not interpret disabled collection or an empty list as a successful negative assessment. Review retained findings and source outcomes separately.
