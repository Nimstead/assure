# Change asset context

Set asset criticality, exposure, rollout ring, or health checks. You need an organisation admin session. Other members can read these values.

These controls change server context and derived findings. They do not configure the host's firewall or install software.

## Change one asset

1. Open **Assets**.
2. Search for the asset by name, OS, or agent version.
3. Select its name to open the details drawer.
4. Select the required **Criticality**.
5. Set **Internet-facing** from the asset's actual exposure.
6. For a host, select **Canary** or **Broad** under **Ring**.
7. Enter the host's actual systemd unit or Windows service names under **Health units**.
8. Leave the health-unit field or press Enter to submit it.
9. Wait for saved feedback or an error beside the asset.
10. Reload Assets and confirm the stored values.

Select and switch changes submit immediately. There is no separate Save button in the drawer. A value can appear before the server confirms it. On failure, inspect the error and reload before another change.

Use comma-separated service names, such as `nginx, postgresql`, only when those services exist on the host. These are service identifiers, not display descriptions. The server validates names and accepts at most twenty health units.

The ring controls policy rollout eligibility. Human approval can proceed separately. See [remediation modes](../reference/remediation-modes.md).

## Change several assets

1. Filter or search the asset list.
2. Select the intended rows, or select **Select all**.
3. Review the selected count.
4. Choose the staged criticality, ring, or exposure value in the selection bar.
5. Select **Apply** for the selected assets.
6. Open each affected asset and inspect its stored values.
7. Reload Assets and confirm the stored values.

Select all includes matching rows beyond those currently displayed. Selection can also retain rows hidden by later filters. Clear the selection before a different batch if those rows must be excluded.

Ring changes apply only to host assets. Application assets can share criticality and exposure edits. The batch submits separate requests. Some can fail while others succeed. **Prepared** feedback describes the staged change. It does not confirm a successful save.

The drawer can show the most recent failed asset's error. That message is not a complete batch report. Verify every intended change after reload.

## Recover from an incorrect edit

1. Select **Undo** when available for the previous change.
2. Reload Assets and confirm the restored values.
3. Correct any remaining values explicitly in the drawer.

Undo submits new requests and can fail. The single-change Undo restores criticality, exposure, ring, and health units. It does not restore the directory-source flag. Bulk Undo uses the captured prior values for staged fields. It can replace later edits to those same fields.

## Permit directory observations

You also need local administrator access to configure the agent's directory option.

1. Open the intended Windows host's details drawer.
2. Enable **Directory source** when the control is available.
3. Configure the agent's `--ad-discovery` option. See the [agent command reference](../reference/agent-cli.md).
4. After a report, inspect the directory-observation section on Assets.

The flag permits directory uploads from that host. More than one host can hold it. Each accepted upload replaces the organisation's entire stored directory list. Select collectors with that replacement behavior in mind.

## Verify finding context

1. Open the asset's findings after a saved edit.
2. Inspect any changed priorities or recommended actions.
3. Check report age and collection coverage before interpreting the result.

A context change rescans stored inventory. It does not establish a fresh host observation. Missing findings and supported product mappings do not independently establish safety.

See the [web client reference](../reference/web-client.md) for filter, selection, and request behavior.
