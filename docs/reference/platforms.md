# Supported platforms

Platform support depends on the collector, advisory data, and remediation method. Detection support does not imply that every fix is supported.

| Platform | Agent requirements | Scheduling |
| --- | --- | --- |
| Debian and Ubuntu | Python 3.9+, curl, root for installation | systemd timer |
| RHEL family, including AlmaLinux and Rocky | Python 3.9+, curl, root for installation | systemd timer |
| Alpine | Python 3.9+, curl; use the installation and scheduling supported by the host | See host setup |
| SUSE | Python 3.9+, curl, root for installation | systemd timer |
| Windows 10 / Server 2016 and newer | Administrator installation; bundled Python runtime | SYSTEM scheduled task |

The normal report interval is six hours. Hosts that permit remediation poll for jobs every 15 minutes. Windows also reports at startup.

## Windows collection

The installer supplies the pinned official embeddable Python runtime. It checks program signatures against the Python Software Foundation and stores the runtime under `Program Files\Nimstead\runtime`. Only administrators can modify that directory. The installer prints the runtime SHA-256. Signed agent releases also update the runtime. The pinned version is in [windows-runtime.json](../../agent/windows-runtime.json).

Windows 8.1 / Server 2012 R2 and older are refused. Third-party application detection uses a curated product catalogue. Unrecognised applications remain inventory and do not gain guessed CVE matches.

## Windows matching inputs

Microsoft matching uses full, case-sensitive allowlists. Product names and publishers must match the configured patterns. Dotted numeric versions are normalized before track selection. An unsupported identity or required context can produce no mapping.

| Product input | Track context |
| --- | --- |
| .NET SDK | Major/minor version and SDK feature band |
| .NET Framework | Registry Release value and Windows product |
| SQL Server | Major version and configured build threshold for GDR/CU |
| Exchange Server | First three version components |
| SharePoint Server | Configured build thresholds |
| Microsoft 365 Apps | Click-to-Run channel and version line |
| Curated Store packages | OS-specific key before generic product key |

The [Microsoft mapper](../../api/src/nimstead/msproducts.py) defines the current allowlists and thresholds. [Lifecycle checks](lifecycle.md) use a separate mapping, so advisory coverage and support-deadline coverage can differ.

Driver detection matches the exact reported file hash against verified LOLDrivers entries. A filename alone does not match. Parsed hashes are lowercase, but the finding helper compares the reported value exactly.

| Driver category/state | Base score | Priority |
| --- | --- | --- |
| Malicious | 95 | `fix-now` |
| Vulnerable and reported loaded | 70 | `next` |
| Vulnerable and other reported state | 45 | `planned` |

Only source text equal to `loaded` selects the loaded state. Other values use the on-disk state. The parser requires at least 1000 unique file hashes. It uses the first entry for duplicate hashes and excludes Authenticode-only samples. See [`windrivers.py`](../../api/src/nimstead/windrivers.py) for parser refusal rules.

## Limits by operation

- Remote Windows scans collect findings but cannot apply fixes.
- Java archive and application scans require local opt-in.
- Some Windows updates cannot be removed. The plan must state its rollback limits.
- Linux package rollback does not necessarily reverse package-script effects outside restored files.

Use the current [repository status](https://github.com/Nimstead/assure/blob/main/STATUS.md) for named platform proofs and gaps. Historical proof on one version does not establish support for every later image or package combination.


## Collection budgets and historical measurements

Java collection scans local `.jar`, `.war`, and `.ear` files, including one nested archive level. It does not follow links or enter network shares. It stops after five minutes or 500,000 files and reports partial coverage.

A recorded Windows 11 26H2 footprint run took 30 seconds and used 25 CPU seconds with 280 MB peak memory. It read 168 MB, stored 25 MB, and sent 76 KB. It covered a fresh installation with few applications. These are historical measurements, not capacity guarantees. More applications and drivers can cost more.

The [footprint harness](../../sandbox/winfootprint.py) enforces budgets of 120 CPU seconds, 512 MB memory, five minutes, 100 MB stored, and 5 MB sent. Read [STATUS](../../STATUS.md) for the recorded environment and proof limits.
