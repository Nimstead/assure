# Nimstead agent installer for Windows. Run in an elevated PowerShell:
#   $env:NIMSTEAD_TOKEN = "<token>"; irm __SERVER__/install.ps1 | iex
# Optional: $env:NIMSTEAD_ALLOW_REMEDIATION = "1" lets this machine install approved updates (local opt-in).
# Installs the agent, enrols this machine, and adds SYSTEM scheduled tasks: every 6 hours and at startup (so an update
# that needed a restart is verified and reported right after it), and with remediation a 15-minute check for approved
# fixes. The agent updates itself from signed releases.
$ErrorActionPreference = "Stop"
$Server = "__SERVER__"
$Channel = "__CHANNEL__"  # this server's release channel: the agent takes no less proven signed releases
$Token = $env:NIMSTEAD_TOKEN
if (-not $Token) { throw "Set `$env:NIMSTEAD_TOKEN to your enrolment token first." }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this in an elevated (Administrator) PowerShell." }

# The SYSTEM task runs this interpreter, so it must be one only administrators can change: an all-users install under
# Program Files. A per-user Python (AppData) would hand SYSTEM to whoever can write there.
$launcher = (Get-Command py -ErrorAction SilentlyContinue).Source
$launcherArgs = @("-3")
if (-not $launcher) { $launcher = (Get-Command python -ErrorAction SilentlyContinue).Source; $launcherArgs = @() }
if (-not $launcher) { throw "Python 3.9+ is required (winget install Python.Python.3.13 --scope machine)." }
$py = (& $launcher @launcherArgs -I -c "import sys; print(sys.executable)").Trim()
$trusted = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' }  # the trailing \ stops "C:\Program Files Evil" matching
if (-not ($trusted | Where-Object { $py.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })) {
  throw "Python at $py is not an all-users install under Program Files; SYSTEM must not run an interpreter other users can modify. Install one with: winget install Python.Python.3.13 --scope machine"
}
$pyArgs = @("-I")  # isolated: no user site-packages, no PYTHON* environment variables

$dir = Join-Path $env:ProgramFiles "Nimstead"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$agent = Join-Path $dir "nimstead_agent.py"
Invoke-WebRequest -UseBasicParsing -Uri "$Server/agent/nimstead_agent.py" -OutFile $agent
Write-Host "agent sha256: $((Get-FileHash -Algorithm SHA256 $agent).Hash.ToLower())"  # compare with the signed release (docs/install.md)
$insecure = @()
if ($Server.StartsWith("http://")) { $insecure = @("--insecure-http"); Write-Warning "Plain HTTP server (dev only)" }

$remediate = @()
if ($env:NIMSTEAD_ALLOW_REMEDIATION -eq "1") { $remediate = @("--allow-remediation") }
& $py @pyArgs $agent @insecure enroll --server $Server --channel $Channel @remediate
if ($LASTEXITCODE -ne 0) { throw "Enrolment failed." }
& $py @pyArgs $agent @insecure report
if ($LASTEXITCODE -ne 0) { throw "First report failed." }

& $py @pyArgs $agent @insecure schedule  # SYSTEM tasks; the agent keeps them current when it updates itself
if ($LASTEXITCODE -ne 0) { throw "Scheduling failed." }
Write-Host "Nimstead agent installed."
