# Nimstead agent installer for Windows. Run in an elevated PowerShell:
#   $env:NIMSTEAD_TOKEN = "<token>"; irm __SERVER__/install.ps1 | iex
# Installs the agent, enrols this machine, and adds a scheduled task (SYSTEM) that reports every 6 hours.
$ErrorActionPreference = "Stop"
$Server = "__SERVER__"
$Token = $env:NIMSTEAD_TOKEN
if (-not $Token) { throw "Set `$env:NIMSTEAD_TOKEN to your enrolment token first." }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this in an elevated (Administrator) PowerShell." }

$py = (Get-Command py -ErrorAction SilentlyContinue).Source
$pyArgs = @("-3")
if (-not $py) { $py = (Get-Command python -ErrorAction SilentlyContinue).Source; $pyArgs = @() }
if (-not $py) { throw "Python 3.9+ is required (winget install Python.Python.3.13)." }

$dir = Join-Path $env:ProgramFiles "Nimstead"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$agent = Join-Path $dir "nimstead_agent.py"
Invoke-WebRequest -UseBasicParsing -Uri "$Server/agent/nimstead_agent.py" -OutFile $agent
$insecure = @()
if ($Server.StartsWith("http://")) { $insecure = @("--insecure-http"); Write-Warning "Plain HTTP server (dev only)" }

& $py @pyArgs $agent @insecure enroll --server $Server
if ($LASTEXITCODE -ne 0) { throw "Enrolment failed." }
& $py @pyArgs $agent @insecure report
if ($LASTEXITCODE -ne 0) { throw "First report failed." }

$argList = (@($pyArgs) + @("`"$agent`"") + $insecure + @("report")) -join " "
$action = New-ScheduledTaskAction -Execute $py -Argument $argList
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 6)
Register-ScheduledTask -TaskName "Nimstead agent" -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Write-Host "Nimstead agent installed; reporting every 6 hours."
