# Check Windows Update access through a proxy

Verify update downloads before you permit fixes on a Windows host without direct internet access. You need local administrator access and a disposable test host with the same network policy.

The agent's proxy does not necessarily control Windows Update's download path.

1. Set the agent proxy through `NIMSTEAD_PROXY` before installation, or configure the machine-wide WinHTTP proxy.
2. Inspect the WinHTTP configuration with `netsh winhttp show proxy`.
3. Check the download method supported by your Windows version and network policy.
4. Test an approved update on the disposable host.
5. Confirm that the download completes and the next inventory reports the result.

If Delivery Optimization ignores the proxy, the download can stall. The job times out without applying the update. Do not repeat production jobs until the test download works.

A recorded Windows 11 26H2 test used **Download Mode → Bypass** (`DODownloadMode=100`) and a device-wide proxy. Another option was direct HTTP access to `*.delivery.mp.microsoft.com`. This is a historical workaround, not a guarantee for every Windows version. Check current Microsoft guidance for your supported version before changing policy.

The policy path used in that test was **Computer Configuration → Administrative Templates → Windows Components → Delivery Optimization**.

For the recorded environment and limits, see [STATUS](../../STATUS.md). For enrolment proxy controls, see [enrol Windows](enrol-windows.md#configure-a-proxy).
