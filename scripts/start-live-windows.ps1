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
# Scope reminder: a Windows rule filters INBOUND traffic to THIS PC. It does
# not cut the device off the Internet or from other devices; for the whole LAN
# use the OPNsense provider on the router.

param([int]$Port = 8000)

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator rights (UAC)..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList @(
        "-NoExit", "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`"", "-Port", "$Port"
    )
    exit
}

Set-Location (Split-Path $PSScriptRoot -Parent)
$env:LASSI_MODE = "live"
$env:LASSI_FW = "windows"
$env:LASSI_AUTO_BLOCK = "0"

Write-Host "LassiNet live + Windows Firewall (Administrator)" -ForegroundColor Green
Write-Host "  dashboard: http://127.0.0.1:$Port   (Ctrl+C stops the server)"
Write-Host "  blocks are real inbound rules on THIS PC; auto-block is off."
Write-Host ""

$python = Start-Process -FilePath "python" -ArgumentList @("app.py", "--port", "$Port") -NoNewWindow -PassThru
$python.Id | Out-File -FilePath "$env:TEMP\lassinet-live.pid" -Encoding ascii -NoNewline
$python.WaitForExit()
