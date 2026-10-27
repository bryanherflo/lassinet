# LassiNet one-click installer for Windows.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "  LassiNet installer" -ForegroundColor Cyan
Write-Host "  ------------------" -ForegroundColor Cyan

$python = $null
$pyArgs = @()
$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) {
    & $py.Source -3.12 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"
    if ($LASTEXITCODE -eq 0) {
        $python = $py.Source
        $pyArgs = @("-3.12")
    }
}
if (-not $python) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) {
        & $cmd.Source -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"
        if ($LASTEXITCODE -eq 0) {
            $python = $cmd.Source
        }
    }
}
if (-not $python) {
    Write-Host "Python 3.12+ was not found." -ForegroundColor Red
    Write-Host "Install it from https://www.python.org/downloads/ and run install.bat again."
    exit 1
}

& $python @pyArgs scripts/setup_env.py
if ($LASTEXITCODE -ne 0) { exit 1 }

$desktop = [Environment]::GetFolderPath("Desktop")
$lnk = Join-Path $desktop "LassiNet.lnk"
try {
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($lnk)
    $sc.TargetPath = Join-Path $PSScriptRoot "start.bat"
    $sc.WorkingDirectory = $PSScriptRoot
    $sc.Description = "LassiNet dashboard"
    $sc.Save()
    Write-Host "Desktop shortcut: $lnk" -ForegroundColor Green
} catch {
    Write-Host "Could not create the desktop shortcut: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Starting the dashboard. Keep this window open; Ctrl+C stops it." -ForegroundColor Green
Start-Job -ScriptBlock {
    for ($i = 0; $i -lt 120; $i++) {
        try {
            Invoke-WebRequest "http://127.0.0.1:8000/healthz" -UseBasicParsing -TimeoutSec 2 | Out-Null
            Start-Process "http://127.0.0.1:8000"
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    }
} | Out-Null
& $python @pyArgs run.py
