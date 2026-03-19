# create_testdata.ps1 — Generate test corpus for AkesoAV
# Run from repo root: powershell -ExecutionPolicy Bypass -File scripts/create_testdata.ps1

$testdir = Join-Path $PSScriptRoot "..\testdata"
New-Item -ItemType Directory -Force -Path $testdir | Out-Null

Write-Host "Creating test corpus in $testdir"

# ── EICAR test string ──
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

# eicar.com.txt — plain EICAR
$eicarPath = Join-Path $testdir "eicar.com.txt"
[System.IO.File]::WriteAllText($eicarPath, $eicar, [System.Text.Encoding]::ASCII)
Write-Host "  Created eicar.com.txt"

# eicar.zip — EICAR inside a ZIP
$eicarZip = Join-Path $testdir "eicar.zip"
$tempEicar = Join-Path $env:TEMP "eicar_temp.txt"
[System.IO.File]::WriteAllText($tempEicar, $eicar, [System.Text.Encoding]::ASCII)
if (Test-Path $eicarZip) { Remove-Item $eicarZip }
Compress-Archive -Path $tempEicar -DestinationPath $eicarZip -Force
Write-Host "  Created eicar.zip"

# eicar_nested.zip — ZIP containing eicar.zip
$nestedZip = Join-Path $testdir "eicar_nested.zip"
if (Test-Path $nestedZip) { Remove-Item $nestedZip }
Compress-Archive -Path $eicarZip -DestinationPath $nestedZip -Force
Write-Host "  Created eicar_nested.zip"

# eicar.gz — EICAR in GZIP
$eicarGz = Join-Path $testdir "eicar.gz"
$eicarBytes = [System.Text.Encoding]::ASCII.GetBytes($eicar)
$ms = New-Object System.IO.MemoryStream
$gzStream = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
$gzStream.Write($eicarBytes, 0, $eicarBytes.Length)
$gzStream.Close()
[System.IO.File]::WriteAllBytes($eicarGz, $ms.ToArray())
$ms.Close()
Write-Host "  Created eicar.gz"

# clean.txt — known-clean file
$cleanPath = Join-Path $testdir "clean.txt"
[System.IO.File]::WriteAllText($cleanPath, "This is a clean test file. No malware here.", [System.Text.Encoding]::ASCII)
Write-Host "  Created clean.txt"

# empty.bin — zero-length file
$emptyPath = Join-Path $testdir "empty.bin"
[System.IO.File]::WriteAllBytes($emptyPath, @())
Write-Host "  Created empty.bin"

# truncated.exe — first 100 bytes of a PE header (MZ + partial DOS stub)
$truncPath = Join-Path $testdir "truncated.exe"
$dosHeader = New-Object byte[] 100
$dosHeader[0] = 0x4D  # M
$dosHeader[1] = 0x5A  # Z
$dosHeader[2] = 0x90
$dosHeader[60] = 0x80  # e_lfanew pointing past truncation
[System.IO.File]::WriteAllBytes($truncPath, $dosHeader)
Write-Host "  Created truncated.exe"

# Copy clean system PEs (if available)
$notepad = "C:\Windows\System32\notepad.exe"
if (Test-Path $notepad) {
    Copy-Item $notepad (Join-Path $testdir "clean_pe_64.exe") -Force
    Write-Host "  Copied notepad.exe as clean_pe_64.exe"
}

$notepad32 = "C:\Windows\SysWOW64\notepad.exe"
if (Test-Path $notepad32) {
    Copy-Item $notepad32 (Join-Path $testdir "clean_pe_32.exe") -Force
    Write-Host "  Copied 32-bit notepad.exe as clean_pe_32.exe"
}

# Cleanup temp
Remove-Item $tempEicar -Force -ErrorAction SilentlyContinue

Write-Host "Test corpus created successfully."
Write-Host "Files:"
Get-ChildItem $testdir | ForEach-Object { Write-Host "  $($_.Name) ($($_.Length) bytes)" }
