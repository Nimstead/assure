# Nimstead agent installer for Windows. Run in an elevated PowerShell:
#   $env:NIMSTEAD_TOKEN = "<token>"; irm __SERVER__/install.ps1 | iex
# Optional: $env:NIMSTEAD_ALLOW_REMEDIATION = "1" lets this machine install approved updates (local opt-in).
# Installs the agent, enrols this machine, and adds a scheduled task (SYSTEM) that runs every 6 hours and at startup
# (so an update that needed a restart is verified and reported right after it).
$ErrorActionPreference = "Stop"
$Server = "__SERVER__"
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
$trusted = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('') + '' }
if (-not ($trusted | Where-Object { $py.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })) {
  throw "Python at $py is not an all-users install under Program Files; SYSTEM must not run an interpreter other users can modify. Install one with: winget install Python.Python.3.13 --scope machine"
}
$pyArgs = @("-I")  # isolated: no user site-packages, no PYTHON* environment variables

$dir = Join-Path $env:ProgramFiles "Nimstead"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$agent = Join-Path $dir "nimstead_agent.py"
Invoke-WebRequest -UseBasicParsing -Uri "$Server/agent/nimstead_agent.py" -OutFile $agent
$insecure = @()
if ($Server.StartsWith("http://")) { $insecure = @("--insecure-http"); Write-Warning "Plain HTTP server (dev only)" }

$remediate = @()
if ($env:NIMSTEAD_ALLOW_REMEDIATION -eq "1") { $remediate = @("--allow-remediation") }
& $py @pyArgs $agent @insecure enroll --server $Server @remediate
if ($LASTEXITCODE -ne 0) { throw "Enrolment failed." }
& $py @pyArgs $agent @insecure report
if ($LASTEXITCODE -ne 0) { throw "First report failed." }

$verb = if ($remediate) { "remediate" } else { "report" }  # remediate also re-reports inventory
$argList = (@($pyArgs) + @("`"$agent`"") + $insecure + @($verb)) -join " "
$action = New-ScheduledTaskAction -Execute $py -Argument $argList
$triggers = @((New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 6)),
              (New-ScheduledTaskTrigger -AtStartup))
Register-ScheduledTask -TaskName "Nimstead agent" -Action $action -Trigger $triggers -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Write-Host "Nimstead agent installed; reporting every 6 hours."
