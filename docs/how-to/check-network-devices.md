# Find and check devices with no agent

See the devices on your networks that have no agent, such as printers, cameras and network storage, and let a machine next to them check them for exposed services. You need agents at 0.7.0 or later.

## See the devices

1. Update your agents to 0.7.0 or later. Each one then reports its own neighbour table: the addresses and network cards (MACs) its machine already talks to.
2. Open **Assets**. The **devices on your networks have no agent** section lists every device none of your machines accounts for, newest first, with its addresses, its network card's maker, which machines saw it and when.
3. Select **Show them** to see the list, or **Download as CSV** to export it.

Nothing is sent to these devices to find them. A device not seen for 30 days drops off the list. A machine whose MAC changes on each network (most phones and laptops) shows as "randomised MAC".

To leave one machine's table out, set `"neighbours": false` in its agent configuration file.

## Turn on network checks for one machine

Choose one machine on each network you want checked, then enrol it with the local opt-in. Only the machine can turn this on. The server can't turn it on or choose what is checked.

On Linux, add the flag to the install command:

```bash
curl -fsSL --proto '=https' https://assure.example.com/install.sh | sudo --preserve-env=NIMSTEAD_TOKEN sh -s -- --allow-network-checks
```

On Windows, set the variable before running the install command:

```powershell
$env:NIMSTEAD_ALLOW_NETWORK_CHECKS = "1"
```

After each report, the machine checks up to 32 devices from its own neighbour table on its own private IPv4 subnets, starting at a random point each run so every device is reached over a few runs.

- **Ports:** it connects to a fixed list of risky ports, such as Telnet, FTP, VNC, Redis and databases.
- **Banners:** it reads the greeting on banner ports.
- **TLS:** it reads the certificate on 443 and tries TLS 1.0/1.1.
- **Web files:** it requests `/.git/config` and `/.env` on port 80.

It never logs in or exploits anything. A web file's contents never leave the network: the machine sends only whether the file matched.

## Read the results

A checked device shows **checked by** the machine that checked it, with a link to its issues, or "nothing found". Its findings appear in **Findings** with the reason "Seen on your network". On a network an open SMB or RDP port is normal, so only services that answer without a password or in cleartext become findings.

A finding closes only on evidence, such as the port refusing the connection. A device that stops answering, or a check that couldn't finish, keeps its findings open. A network card that answers at several addresses at once, such as a Wi-Fi extender's, isn't checked, because one device's result must not close another's finding.

To turn checks off, set `"network_checks": false` in that agent's configuration file. Deleting the machine in **Assets** also removes what it found on the devices it checked.

See [configuration](../configuration.md#devices-on-your-networks) and the [agent reference](../reference/agent-core.md) for the exact checks and limits. Read [coverage limits](../explanation/coverage-limits.md) before reading "nothing found" as clean.
