# LassiNet with REAL blocks on this PC (Windows Firewall).
#
# Run it from Explorer ("Run with PowerShell") or:
#     powershell -ExecutionPolicy Bypass -File .\scripts\start-live-windows.ps1
#
# It asks for elevation (UAC): a Windows Firewall rule can only be created by
# an Administrator. The server then runs in live mode with LASSI_FW=windows,
# so "Block" really installs an inbound rule `LassiNet-Block-<ip>` on this PC.
# The auto-block stays OFF: only what you click is enforced.
#
# If you use a virtual environment, activate it first (or pass -PythonExe):
# the launcher reuses the interpreter of your current session, so the
# elevated process sees the same dependencies.
#
# Scope reminder: a Windows rule filters INBOUND traffic to THIS PC. It does
# not cut the device off the Internet or from other devices; for the whole LAN
# use the OPNsense provider on the router.

param(
    [int]$Port = 8000,
    [string]$PythonExe = ""
)

# Resolve the interpreter before elevating: an elevated PowerShell starts a
# fresh environment and would otherwise lose an activated virtualenv.
if (-not $PythonExe) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $PythonExe = $cmd.Source }
}

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator rights (UAC)..." -ForegroundColor Yellow
    $arguments = @(
        "-NoExit", "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`"", "-Port", "$Port"
    )
    if ($PythonExe) { $arguments += @("-PythonExe", "`"$PythonExe`"") }
    Start-Process powershell -Verb RunAs -ArgumentList $arguments
    exit
}

Set-Location (Split-Path $PSScriptRoot -Parent)
$env:LASSI_MODE = "live"
$env:LASSI_FW = "windows"
$env:LASSI_AUTO_BLOCK = "0"

# The app refuses live without a declared scope (a school/customer Wi-Fi must
# not be swept by accident). Ask once, in the elevated window, unless the
# caller already provided one.
if (-not $env:LASSI_LIVE_ALLOW -and -not $env:LASSI_LIVE_ALLOW_ANY) {
    $cidr = Read-Host "Authorized LAN CIDR for live capture (e.g. 192.168.0.0/24)"
    if ([string]::IsNullOrWhiteSpace($cidr)) {
        Write-Error "No scope provided. Set LASSI_LIVE_ALLOW or LASSI_LIVE_ALLOW_ANY=1."
        exit 1
    }
    $env:LASSI_LIVE_ALLOW = $cidr.Trim()
}

# Fall back to the project virtualenv, then to PATH.
if (-not $PythonExe -or -not (Test-Path $PythonExe)) {
    $venvPython = Join-Path (Get-Location) ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) { $PythonExe = $venvPython } else { $PythonExe = "python" }
}

Write-Host "LassiNet live + Windows Firewall (Administrator)" -ForegroundColor Green
Write-Host "  dashboard: http://127.0.0.1:$Port   (Ctrl+C stops the server)"
Write-Host "  blocks are real inbound rules on THIS PC; auto-block is off."
Write-Host "  python: $PythonExe"
Write-Host ""

$python = Start-Process -FilePath $PythonExe -ArgumentList @("app.py", "--port", "$Port") -NoNewWindow -PassThru
$python.Id | Out-File -FilePath "$env:TEMP\lassinet-live.pid" -Encoding ascii -NoNewline
$python.WaitForExit()
