#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AkesoAV Uninstaller (P10-T5)

.DESCRIPTION
    Completely removes AkesoAV from the system:
      - Stops and deletes Windows services
      - Removes binaries from %ProgramFiles%\AkesoAV
      - Removes data from %ProgramData%\Akeso
      - Removes registry keys from HKLM\SOFTWARE\Akeso\AV
      - Optionally preserves quarantine vault

.PARAMETER KeepQuarantine
    If specified, preserves the quarantine vault directory.

.EXAMPLE
    .\scripts\uninstall.ps1
    .\scripts\uninstall.ps1 -KeepQuarantine
#>

param(
    [switch]$KeepQuarantine
)

$ErrorActionPreference = "Stop"

# ── Paths ──────────────────────────────────────────────────────────
$InstallDir   = "$env:ProgramFiles\AkesoAV"
$DataDir      = "$env:ProgramData\Akeso"
$ServiceName  = "AkesoAV"
$WatchdogName = "AkesoAVWatchdog"
$RegPath      = "HKLM:\SOFTWARE\Akeso"

# ── Functions ──────────────────────────────────────────────────────

function Write-Step($msg) {
    Write-Host "[UNINSTALL] $msg" -ForegroundColor Cyan
}

function Write-OK($msg) {
    Write-Host "[  OK  ] $msg" -ForegroundColor Green
}

function Write-Warn($msg) {
    Write-Host "[ WARN ] $msg" -ForegroundColor Yellow
}

# ── Stop and remove services ───────────────────────────────────────

Write-Step "AkesoAV Uninstaller"
Write-Host ""

Write-Step "Stopping services..."

# Stop watchdog first (depends on service)
$wd = Get-Service -Name $WatchdogName -ErrorAction SilentlyContinue
if ($wd) {
    if ($wd.Status -eq "Running") {
        Stop-Service -Name $WatchdogName -Force -ErrorAction SilentlyContinue
        Write-OK "Stopped $WatchdogName"
    }
    sc.exe delete $WatchdogName | Out-Null
    Write-OK "Deleted service: $WatchdogName"
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Write-OK "Stopped $ServiceName"
    }
    sc.exe delete $ServiceName | Out-Null
    Write-OK "Deleted service: $ServiceName"
}

# Wait for service processes to exit
Start-Sleep -Seconds 2

# Kill any lingering processes
foreach ($proc in @("akesoav-service", "akesoav-watchdog", "akavscan")) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# ── Remove binaries ───────────────────────────────────────────────

Write-Step "Removing binaries..."
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-OK "Removed $InstallDir"
} else {
    Write-Warn "$InstallDir not found (already removed?)"
}

# ── Remove data directory ──────────────────────────────────────────

Write-Step "Removing data..."
if (Test-Path $DataDir) {
    if ($KeepQuarantine) {
        # Remove everything except Quarantine
        Get-ChildItem -Path $DataDir -Exclude "Quarantine" | Remove-Item -Recurse -Force
        Write-OK "Removed data (quarantine preserved)"
    } else {
        Remove-Item -Path $DataDir -Recurse -Force
        Write-OK "Removed $DataDir"
    }
} else {
    Write-Warn "$DataDir not found (already removed?)"
}

# ── Remove registry keys ──────────────────────────────────────────

Write-Step "Removing registry keys..."
if (Test-Path $RegPath) {
    Remove-Item -Path $RegPath -Recurse -Force
    Write-OK "Removed $RegPath"
} else {
    Write-Warn "$RegPath not found (already removed?)"
}

# ── Summary ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  AkesoAV uninstallation complete!" -ForegroundColor Green
Write-Host "════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
if ($KeepQuarantine) {
    Write-Host "  Note: Quarantine vault preserved at $DataDir\Quarantine"
    Write-Host ""
}
