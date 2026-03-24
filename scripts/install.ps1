#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AkesoAV Installer (P10-T5)

.DESCRIPTION
    Installs AkesoAV on Windows 10/11 x64:
      - Copies binaries to %ProgramFiles%\AkesoAV
      - Deploys .akavdb signatures to %ProgramData%\Akeso
      - Creates directory structure with restricted ACLs
      - Registers akesoav-service as a Windows service
      - Sets up watchdog as a secondary service
      - Creates config registry keys under HKLM\SOFTWARE\Akeso\AV
      - Runs EICAR self-test to verify installation

.PARAMETER SourceDir
    Path to the build output directory containing binaries.
    Default: .\build\Release

.PARAMETER SignatureDb
    Path to the .akavdb signature database file.
    If not specified, skips signature deployment.

.EXAMPLE
    .\scripts\install.ps1
    .\scripts\install.ps1 -SourceDir C:\AkesoAV\build\Release -SignatureDb C:\sigs\signatures.akavdb
#>

param(
    [string]$SourceDir = ".\build\Release",
    [string]$SignatureDb = ""
)

$ErrorActionPreference = "Stop"

# ── Paths ──────────────────────────────────────────────────────────
$InstallDir   = "$env:ProgramFiles\AkesoAV"
$DataDir      = "$env:ProgramData\Akeso"
$LogDir       = "$DataDir\Logs"
$QuarantineDir = "$DataDir\Quarantine"
$VaultDir     = "$QuarantineDir\vault"
$ConfigDir    = "$DataDir"
$ServiceName  = "AkesoAV"
$WatchdogName = "AkesoAVWatchdog"
$RegPath      = "HKLM:\SOFTWARE\Akeso\AV"

# ── Binaries to install ───────────────────────────────────────────
$Binaries = @(
    "akesoav.dll",
    "akesoav-service.exe",
    "akesoav-watchdog.exe",
    "akavscan.exe"
)

# ── Functions ──────────────────────────────────────────────────────

function Write-Step($msg) {
    Write-Host "[INSTALL] $msg" -ForegroundColor Cyan
}

function Write-OK($msg) {
    Write-Host "[  OK  ] $msg" -ForegroundColor Green
}

function Write-Warn($msg) {
    Write-Host "[ WARN ] $msg" -ForegroundColor Yellow
}

function Write-Fail($msg) {
    Write-Host "[ FAIL ] $msg" -ForegroundColor Red
}

function Set-RestrictedAcl($path) {
    # SYSTEM + Administrators only (no Users/Everyone)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance

    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($adminRule)
    Set-Acl -Path $path -AclObject $acl
}

# ── Pre-flight checks ─────────────────────────────────────────────

Write-Step "AkesoAV Installer"
Write-Host ""

# Verify source directory
if (-not (Test-Path $SourceDir)) {
    Write-Fail "Source directory not found: $SourceDir"
    exit 1
}

# Verify binaries exist
foreach ($bin in $Binaries) {
    $path = Join-Path $SourceDir $bin
    if (-not (Test-Path $path)) {
        Write-Fail "Binary not found: $path"
        exit 1
    }
}
Write-OK "All binaries found in $SourceDir"

# ── Stop existing services ─────────────────────────────────────────

Write-Step "Stopping existing services..."
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Stop-Service -Name $ServiceName -Force
    Write-OK "Stopped $ServiceName"
}
$wd = Get-Service -Name $WatchdogName -ErrorAction SilentlyContinue
if ($wd -and $wd.Status -eq "Running") {
    Stop-Service -Name $WatchdogName -Force
    Write-OK "Stopped $WatchdogName"
}

# ── Create directory structure ─────────────────────────────────────

Write-Step "Creating directory structure..."

$dirs = @($InstallDir, $DataDir, $LogDir, $QuarantineDir, $VaultDir)
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-OK "Directories created"

# Set restricted ACLs on sensitive directories
Write-Step "Setting restricted ACLs..."
try {
    Set-RestrictedAcl $DataDir
    Set-RestrictedAcl $QuarantineDir
    Set-RestrictedAcl $VaultDir
    Write-OK "ACLs set (SYSTEM + Administrators only)"
} catch {
    Write-Warn "ACL setup failed: $_"
}

# ── Copy binaries ─────────────────────────────────────────────────

Write-Step "Copying binaries to $InstallDir..."
foreach ($bin in $Binaries) {
    $src = Join-Path $SourceDir $bin
    $dst = Join-Path $InstallDir $bin
    Copy-Item -Path $src -Destination $dst -Force
}

# Copy zlib.dll if present (runtime dependency)
$zlibSrc = Join-Path $SourceDir "zlib.dll"
if (Test-Path $zlibSrc) {
    Copy-Item -Path $zlibSrc -Destination (Join-Path $InstallDir "zlib.dll") -Force
}

Write-OK "Binaries installed"

# ── Deploy signature database ──────────────────────────────────────

if ($SignatureDb -and (Test-Path $SignatureDb)) {
    Write-Step "Deploying signature database..."
    $dbDest = Join-Path $DataDir "signatures.akavdb"
    Copy-Item -Path $SignatureDb -Destination $dbDest -Force
    Write-OK "Signatures deployed to $dbDest"
} else {
    Write-Warn "No signature database specified (--SignatureDb), skipping"
}

# ── Registry configuration ─────────────────────────────────────────

Write-Step "Creating registry configuration..."

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set default values
Set-ItemProperty -Path $RegPath -Name "InstallDir" -Value $InstallDir -Type String
Set-ItemProperty -Path $RegPath -Name "DataDir" -Value $DataDir -Type String
Set-ItemProperty -Path $RegPath -Name "SignatureDb" -Value (Join-Path $DataDir "signatures.akavdb") -Type String
Set-ItemProperty -Path $RegPath -Name "LogDir" -Value $LogDir -Type String
Set-ItemProperty -Path $RegPath -Name "QuarantineDir" -Value $QuarantineDir -Type String
Set-ItemProperty -Path $RegPath -Name "Version" -Value "1.0.0" -Type String
Set-ItemProperty -Path $RegPath -Name "HeuristicLevel" -Value 2 -Type DWord
Set-ItemProperty -Path $RegPath -Name "MaxScanDepth" -Value 10 -Type DWord
Set-ItemProperty -Path $RegPath -Name "IntegrityCheckInterval" -Value 60 -Type DWord

# Restrict registry key ACL
try {
    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Akeso\AV", $true)
    if ($regKey) {
        $acl = $regKey.GetAccessControl()
        $acl.SetAccessRuleProtection($true, $false)
        $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($systemRule)
        $acl.AddAccessRule($adminRule)
        $regKey.SetAccessControl($acl)
        $regKey.Close()
    }
    Write-OK "Registry configured with restricted ACL"
} catch {
    Write-Warn "Registry ACL restriction failed: $_"
}

# ── Register Windows service ──────────────────────────────────────

Write-Step "Registering AkesoAV service..."

$serviceBin = Join-Path $InstallDir "akesoav-service.exe"

# Remove existing service if present
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# Create service
sc.exe create $ServiceName `
    binPath= "`"$serviceBin`"" `
    start= auto `
    DisplayName= "AkesoAV Antivirus Service" | Out-Null

sc.exe description $ServiceName "AkesoAV real-time antivirus protection service" | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

Write-OK "Service registered: $ServiceName"

# ── Register watchdog service ──────────────────────────────────────

Write-Step "Registering watchdog service..."

$watchdogBin = Join-Path $InstallDir "akesoav-watchdog.exe"

$existingWd = Get-Service -Name $WatchdogName -ErrorAction SilentlyContinue
if ($existingWd) {
    sc.exe delete $WatchdogName | Out-Null
    Start-Sleep -Seconds 1
}

sc.exe create $WatchdogName `
    binPath= "`"$watchdogBin`" `"$serviceBin`"" `
    start= auto `
    DisplayName= "AkesoAV Watchdog" | Out-Null

sc.exe description $WatchdogName "Monitors AkesoAV service health and auto-restarts on failure" | Out-Null

# Watchdog depends on the main service
sc.exe config $WatchdogName depend= $ServiceName | Out-Null

Write-OK "Watchdog registered: $WatchdogName"

# ── Start services ─────────────────────────────────────────────────

Write-Step "Starting services..."
try {
    Start-Service -Name $ServiceName
    Write-OK "$ServiceName started"
} catch {
    Write-Warn "Could not start $ServiceName : $_"
}

# ── EICAR self-test ────────────────────────────────────────────────

Write-Step "Running EICAR self-test..."

$akavscan = Join-Path $InstallDir "akavscan.exe"
if (Test-Path $akavscan) {
    try {
        $output = & $akavscan --eicar-test 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-OK "EICAR self-test PASSED"
        } else {
            Write-Warn "EICAR self-test returned exit code $LASTEXITCODE"
            Write-Host $output
        }
    } catch {
        Write-Warn "EICAR self-test failed: $_"
    }
} else {
    Write-Warn "akavscan.exe not found, skipping self-test"
}

# ── Summary ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  AkesoAV installation complete!" -ForegroundColor Green
Write-Host "════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  Install dir:    $InstallDir"
Write-Host "  Data dir:       $DataDir"
Write-Host "  Log dir:        $LogDir"
Write-Host "  Registry:       $RegPath"
Write-Host "  Service:        $ServiceName"
Write-Host "  Watchdog:       $WatchdogName"
Write-Host ""
Write-Host "  To scan a file: akavscan.exe <path>"
Write-Host "  To uninstall:   .\scripts\uninstall.ps1"
Write-Host ""
