# Nimstead agent installer for Windows. Run in an elevated PowerShell:
#   $env:NIMSTEAD_TOKEN = "<token>"; irm __SERVER__/install.ps1 | iex
# Optional: $env:NIMSTEAD_ALLOW_REMEDIATION = "1" lets this machine install approved updates (local opt-in);
# $env:NIMSTEAD_PROXY = "http://proxy:8080" sends the agent's traffic through that proxy (TLS stays end to end;
# without it the machine's WinHTTP proxy is used, if one is set).
# No Python needed: the agent runs on Python's official embeddable runtime, which this script downloads from your
# server, checks against the Python Software Foundation's code signature (program files) and keeps under Program
# Files (plan decision 9). It prints the runtime's SHA-256 for the out-of-band check against the signed release
# (docs/install.md); the agent's first update replaces anything that isn't the signed runtime. Adds SYSTEM scheduled tasks: every 6 hours and at startup, and with remediation a
# 15-minute check for approved fixes. The agent updates itself (and its runtime) from signed releases.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Server = "__SERVER__"
$Channel = "__CHANNEL__"  # this server's release channel: the agent takes no less proven signed releases
$Token = $env:NIMSTEAD_TOKEN
if (-not $Token) { throw "Set `$env:NIMSTEAD_TOKEN to your enrolment token first." }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this in an elevated (Administrator) PowerShell." }
if ([Environment]::OSVersion.Version.Build -lt 10240) {
  throw "Windows 10 / Windows Server 2016 or newer is required: the bundled Python doesn't run on older Windows, which no longer gets security updates."
}
$arch = @{ AMD64 = "amd64"; ARM64 = "arm64"; x86 = "win32" }[$(if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE })]
if (-not $arch) { throw "Unsupported processor architecture: $env:PROCESSOR_ARCHITECTURE" }
$web = @{ UseBasicParsing = $true }
$proxyArgs = @()
if ($env:NIMSTEAD_PROXY) { $web.Proxy = $env:NIMSTEAD_PROXY; $proxyArgs = @("--proxy", $env:NIMSTEAD_PROXY) }

# Everything lives under Program Files, which only administrators can change: SYSTEM must never run code other users
# can modify.
$dir = Join-Path $env:ProgramFiles "Nimstead"
$runtimes = Join-Path $dir "runtime"
New-Item -ItemType Directory -Force -Path $runtimes | Out-Null
$zip = Join-Path $runtimes "download.zip"
Invoke-WebRequest @web -Uri "$Server/agent/runtime/$arch.zip" -OutFile $zip
$sha = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
Write-Host "runtime sha256: $sha"  # compare with the signed release (docs/install.md)
$rt = Join-Path $runtimes $sha.Substring(0, 12)
# Same hash, same runtime: an agent run may have it loaded, so rerunning this script must not try to replace it (real VM).
if (-not (Test-Path -LiteralPath (Join-Path $rt "python.exe"))) {
  if (Test-Path -LiteralPath $rt) { Remove-Item -LiteralPath $rt -Recurse -Force }
  Expand-Archive -LiteralPath $zip -DestinationPath $rt
}
Remove-Item -LiteralPath $zip
# Every executable file in the runtime must carry a valid Python Software Foundation signature, checked before any runs;
# the Visual C++ runtime DLLs Python ships are Microsoft's own, signed by Microsoft (seen in the 3.15.2 zip).
# (filtered by extension: PowerShell 5.1 ignores -Include next to -LiteralPath, seen for real in the VM proof)
$bad = @(Get-ChildItem -LiteralPath $rt -Recurse -File | Where-Object { @('.exe', '.dll', '.pyd') -contains $_.Extension.ToLower() } | Where-Object {
    $s = Get-AuthenticodeSignature -LiteralPath $_.FullName
    $s.Status -ne "Valid" -or -not ($s.SignerCertificate.Subject -match '^CN=Python Software Foundation,' -or
      ($_.Name -match '^vcruntime140(_1)?\.dll$' -and $s.SignerCertificate.Subject -match ', O=Microsoft Corporation,')) })
if ($bad.Count -or -not (Test-Path -LiteralPath (Join-Path $rt "python.exe"))) {
  Remove-Item -LiteralPath $rt -Recurse -Force
  throw "The downloaded runtime isn't signed by the Python Software Foundation ($($bad[0].Name)); nothing was installed."
}
$py = Join-Path $rt "python.exe"
$pyArgs = @("-I")  # isolated: no user site-packages, no PYTHON* environment variables

$agent = Join-Path $dir "nimstead_agent.py"
Invoke-WebRequest @web -Uri "$Server/agent/nimstead_agent.py" -OutFile $agent
Write-Host "agent sha256: $((Get-FileHash -Algorithm SHA256 $agent).Hash.ToLower())"  # compare with the signed release (docs/install.md)
$insecure = @()
if ($Server.StartsWith("http://")) { $insecure = @("--insecure-http"); Write-Warning "Plain HTTP server (dev only)" }

$remediate = @()
if ($env:NIMSTEAD_ALLOW_REMEDIATION -eq "1") { $remediate = @("--allow-remediation") }
if ($env:NIMSTEAD_SCAN_JARS -eq "1") { $remediate += @("--scan-jars") }  # local opt-in: Java libraries on disk
& $py @pyArgs $agent @insecure enroll --server $Server --channel $Channel @remediate @proxyArgs
if ($LASTEXITCODE -ne 0) { throw "Enrolment failed." }
& $py @pyArgs $agent @insecure report
if ($LASTEXITCODE -ne 0) { throw "First report failed." }

& $py @pyArgs $agent @insecure schedule  # SYSTEM tasks; the agent keeps them current when it updates itself
if ($LASTEXITCODE -ne 0) { throw "Scheduling failed." }
Write-Host "Nimstead agent installed."
