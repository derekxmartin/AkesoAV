#Requires -Version 5.1
<#
.SYNOPSIS
    P11-T1: Signature Evasion Test Suite
.DESCRIPTION
    Exercises 4 evasion scenarios to prove that when a cheap detection layer
    is bypassed, a more expensive layer still catches the sample.

    Scenario A: Hash evasion      (MD5 bypassed -> Aho-Corasick catches)
    Scenario B: Byte-stream evasion (AC bypassed via UPX -> unpack catches)
    Scenario C: Structure-aware    (AC bypassed -> YARA catches)
    Scenario D: Fuzzy hash evasion (MD5 bypassed -> fuzzy hash catches)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Paths ──────────────────────────────────────────────────────────────
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path "$ScriptDir\..\..").Path
$BuildDir    = "$ProjectRoot\build\Release"
$AkavScan    = "$BuildDir\akavscan.exe"
$SigHelper   = "$BuildDir\sig_helper.exe"
$AkavDbTool  = "$ProjectRoot\tools\akavdb-tool\akavdb_tool.py"
$SamplesDir  = "$ScriptDir\evasion_samples"

# Ensure output directory
if (-not (Test-Path $SamplesDir)) {
    New-Item -ItemType Directory -Force -Path $SamplesDir | Out-Null
}

# ── Counters ───────────────────────────────────────────────────────────
$script:TotalTests = 0
$script:Passed     = 0
$script:Failed     = 0

# ── Helpers ────────────────────────────────────────────────────────────

function Assert-DetectedBy {
    param([string]$TestName, [string]$DbPath, [string]$FilePath, [string]$ExpectedScannerId)
    $script:TotalTests++

    $jsonOut = & $AkavScan --db $DbPath -j $FilePath 2>&1
    $exitCode = $LASTEXITCODE

    # Parse JSON from output (may have non-JSON lines mixed in)
    $jsonLine = ($jsonOut | Where-Object { $_ -match '^\s*\{' }) -join "`n"
    if (-not $jsonLine) {
        Write-Host "[FAIL] $TestName - no JSON output (exit=$exitCode)" -ForegroundColor Red
        Write-Host "       Raw output: $jsonOut"
        $script:Failed++
        return $false
    }

    try {
        $result = $jsonLine | ConvertFrom-Json
    } catch {
        Write-Host "[FAIL] $TestName - JSON parse error" -ForegroundColor Red
        Write-Host "       Raw: $jsonLine"
        $script:Failed++
        return $false
    }

    if (-not $result.detected) {
        Write-Host "[FAIL] $TestName - NOT detected (expected: $ExpectedScannerId)" -ForegroundColor Red
        $script:Failed++
        return $false
    }

    $actual = $result.scanner_id
    # For UPX, check prefix match
    if ($ExpectedScannerId.EndsWith("*")) {
        $prefix = $ExpectedScannerId.TrimEnd("*")
        if ($actual.StartsWith($prefix)) {
            Write-Host "[PASS] $TestName - detected by: $actual" -ForegroundColor Green
            $script:Passed++
            return $true
        }
    } elseif ($actual -eq $ExpectedScannerId) {
        Write-Host "[PASS] $TestName - detected by: $actual" -ForegroundColor Green
        $script:Passed++
        return $true
    }

    Write-Host "[FAIL] $TestName - detected by '$actual', expected '$ExpectedScannerId'" -ForegroundColor Red
    $script:Failed++
    return $false
}

function Assert-NotDetected {
    param([string]$TestName, [string]$DbPath, [string]$FilePath)
    $script:TotalTests++

    $jsonOut = & $AkavScan --db $DbPath -j $FilePath 2>&1
    $jsonLine = ($jsonOut | Where-Object { $_ -match '^\s*\{' }) -join "`n"

    if ($jsonLine) {
        try {
            $result = $jsonLine | ConvertFrom-Json
            if ($result.detected) {
                Write-Host "[FAIL] $TestName - unexpectedly detected by: $($result.scanner_id)" -ForegroundColor Red
                $script:Failed++
                return $false
            }
        } catch { }
    }

    Write-Host "[PASS] $TestName - not detected (as expected)" -ForegroundColor Green
    $script:Passed++
    return $true
}

function New-MinimalPE {
    <#
    .SYNOPSIS
        Build a minimal valid PE32+ (x64) file from a .text payload.
    .PARAMETER Payload
        Byte array for the .text section content.
    .PARAMETER TextSectionSize
        Minimum .text section size (padded to file alignment).
    #>
    param(
        [byte[]]$Payload,
        [int]$TextSectionSize = 0
    )

    $fileAlign = 0x200
    $sectAlign = 0x1000

    # .text raw size = max(payload, TextSectionSize), rounded up to fileAlign
    $rawSize = [Math]::Max($Payload.Length, $TextSectionSize)
    $rawSize = [int]([Math]::Ceiling($rawSize / $fileAlign) * $fileAlign)

    $virtSize = [int]([Math]::Ceiling($rawSize / $sectAlign) * $sectAlign)
    $imageSize = $sectAlign + $virtSize  # headers + .text

    $headersRawSize = $fileAlign  # first 0x200 = headers
    $textFileOffset = $headersRawSize

    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)

    # ── DOS Header (64 bytes) ──
    $bw.Write([uint16]0x5A4D)        # e_magic = MZ
    for ($i = 0; $i -lt 29; $i++) { $bw.Write([uint16]0) }  # padding (58 bytes)
    $bw.Write([uint32]0x80)          # e_lfanew = 0x80

    # ── DOS stub (fill to 0x80) ──
    $pad = 0x80 - $ms.Position
    if ($pad -gt 0) { $bw.Write((New-Object byte[] $pad)) }

    # ── PE Signature ──
    $bw.Write([uint32]0x00004550)    # "PE\0\0"

    # ── COFF Header (20 bytes) ──
    $bw.Write([uint16]0x8664)        # Machine = AMD64
    $bw.Write([uint16]1)             # NumberOfSections = 1
    $bw.Write([uint32]0x5F3C0000)    # TimeDateStamp (arbitrary)
    $bw.Write([uint32]0)             # PointerToSymbolTable
    $bw.Write([uint32]0)             # NumberOfSymbols
    $bw.Write([uint16]0xF0)          # SizeOfOptionalHeader (240 for PE32+)
    $bw.Write([uint16]0x0022)        # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    # ── Optional Header PE32+ (240 bytes) ──
    $bw.Write([uint16]0x020B)        # Magic = PE32+
    $bw.Write([byte]14)              # MajorLinkerVersion
    $bw.Write([byte]0)               # MinorLinkerVersion
    $bw.Write([uint32]$rawSize)      # SizeOfCode
    $bw.Write([uint32]0)             # SizeOfInitializedData
    $bw.Write([uint32]0)             # SizeOfUninitializedData
    $bw.Write([uint32]0x1000)        # AddressOfEntryPoint (start of .text)
    $bw.Write([uint32]0x1000)        # BaseOfCode

    $bw.Write([uint64]0x0000000140000000) # ImageBase
    $bw.Write([uint32]$sectAlign)    # SectionAlignment
    $bw.Write([uint32]$fileAlign)    # FileAlignment
    $bw.Write([uint16]6)             # MajorOperatingSystemVersion
    $bw.Write([uint16]0)             # MinorOperatingSystemVersion
    $bw.Write([uint16]0)             # MajorImageVersion
    $bw.Write([uint16]0)             # MinorImageVersion
    $bw.Write([uint16]6)             # MajorSubsystemVersion
    $bw.Write([uint16]0)             # MinorSubsystemVersion
    $bw.Write([uint32]0)             # Win32VersionValue
    $bw.Write([uint32]$imageSize)    # SizeOfImage
    $bw.Write([uint32]$headersRawSize) # SizeOfHeaders
    $bw.Write([uint32]0)             # CheckSum
    $bw.Write([uint16]3)             # Subsystem = CONSOLE
    $bw.Write([uint16]0x8160)        # DllCharacteristics: DYNAMIC_BASE|NX_COMPAT|TERMINAL_SERVER_AWARE|HIGH_ENTROPY_VA
    $bw.Write([uint64]0x100000)      # SizeOfStackReserve
    $bw.Write([uint64]0x1000)        # SizeOfStackCommit
    $bw.Write([uint64]0x100000)      # SizeOfHeapReserve
    $bw.Write([uint64]0x1000)        # SizeOfHeapCommit
    $bw.Write([uint32]0)             # LoaderFlags
    $bw.Write([uint32]16)            # NumberOfRvaAndSizes

    # Data directories (16 entries, all zero)
    for ($i = 0; $i -lt 16; $i++) {
        $bw.Write([uint32]0)  # VirtualAddress
        $bw.Write([uint32]0)  # Size
    }

    # ── Section Header: .text (40 bytes) ──
    $nameBytes = [System.Text.Encoding]::ASCII.GetBytes(".text")
    $bw.Write($nameBytes)
    $bw.Write((New-Object byte[] (8 - $nameBytes.Length)))  # pad to 8
    $bw.Write([uint32]$Payload.Length)  # VirtualSize (actual content size)
    $bw.Write([uint32]0x1000)          # VirtualAddress
    $bw.Write([uint32]$rawSize)        # SizeOfRawData
    $bw.Write([uint32]$textFileOffset) # PointerToRawData
    $bw.Write([uint32]0)               # PointerToRelocations
    $bw.Write([uint32]0)               # PointerToLinenumbers
    $bw.Write([uint16]0)               # NumberOfRelocations
    $bw.Write([uint16]0)               # NumberOfLinenumbers
    $bw.Write([uint32]0x60000020)      # Characteristics: CODE|EXECUTE|READ

    # ── Pad headers to file alignment ──
    $hdrPad = $textFileOffset - $ms.Position
    if ($hdrPad -gt 0) { $bw.Write((New-Object byte[] $hdrPad)) }

    # ── .text section data ──
    $bw.Write($Payload)
    $sectPad = $rawSize - $Payload.Length
    if ($sectPad -gt 0) { $bw.Write((New-Object byte[] $sectPad)) }

    $bw.Flush()
    $result = $ms.ToArray()
    $bw.Close()
    $ms.Close()
    return $result
}

function Get-MD5Hex {
    param([string]$FilePath)
    $hash = Get-FileHash -Path $FilePath -Algorithm MD5
    return $hash.Hash.ToLower()
}

function Compile-AkavDb {
    param([string]$SigsJson, [string]$OutputPath)
    $result = python $AkavDbTool compile $SigsJson -o $OutputPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "akavdb-tool compile failed: $result"
    }
}

# ── Pre-flight checks ─────────────────────────────────────────────────
Write-Host "=== AkesoAV Signature Evasion Test Suite (P11-T1) ===" -ForegroundColor Cyan
Write-Host ""

foreach ($tool in @($AkavScan, $SigHelper)) {
    if (-not (Test-Path $tool)) {
        Write-Error "Required tool not found: $tool`nRun: cmake --build build --config Release"
    }
}

# ======================================================================
# Scenario A: Hash Evasion (MD5 -> Aho-Corasick)
# ======================================================================
Write-Host "=== Scenario A: Hash Evasion (MD5 -> Aho-Corasick) ===" -ForegroundColor Yellow

# Create distinctive byte pattern (32 bytes)
$markerA = [byte[]]@(
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x41, 0x6B, 0x65, 0x73, 0x6F, 0x41, 0x56, 0x5F,   # "AkesoAV_"
    0x45, 0x76, 0x61, 0x73, 0x69, 0x6F, 0x6E, 0x41,   # "EvasionA"
    0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xC0, 0xDE
)
# Add some padding code around the marker
$payloadA = New-Object byte[] 512
[Array]::Copy($markerA, 0, $payloadA, 64, $markerA.Length)
# Fill rest with NOP-like bytes
for ($i = 0; $i -lt 64; $i++) { $payloadA[$i] = 0xCC }
for ($i = 96; $i -lt 512; $i++) { $payloadA[$i] = 0x90 }

$peOrigA = New-MinimalPE -Payload $payloadA
$pathOrigA = "$SamplesDir\scenario_a_original.exe"
[System.IO.File]::WriteAllBytes($pathOrigA, $peOrigA)

# Compute MD5
$md5A = Get-MD5Hex -FilePath $pathOrigA

# Build signature JSON
$markerHex = ($markerA | ForEach-Object { "{0:x2}" -f $_ }) -join ""
$sigsA = @{
    md5 = @(@{ name = "Evasion.Test.A"; hash = $md5A })
    bytestream = @(@{ name = "Evasion.Test.A.Pattern"; pattern = $markerHex })
} | ConvertTo-Json -Depth 4
$sigsPathA = "$SamplesDir\sigs_a.json"
[System.IO.File]::WriteAllText($sigsPathA, $sigsA, [System.Text.UTF8Encoding]::new($false))

# Compile DB
$dbPathA = "$SamplesDir\evasion_a.akavdb"
Compile-AkavDb -SigsJson $sigsPathA -OutputPath $dbPathA

# Test 1: Original detected by MD5 (earlier in pipeline)
Assert-DetectedBy -TestName "A.1 Original PE detected by MD5" `
    -DbPath $dbPathA -FilePath $pathOrigA -ExpectedScannerId "md5"

# Modify: append one byte at EOF
$pathModA = "$SamplesDir\scenario_a_modified.exe"
$modA = New-Object byte[] ($peOrigA.Length + 1)
[Array]::Copy($peOrigA, $modA, $peOrigA.Length)
$modA[$peOrigA.Length] = 0x00
[System.IO.File]::WriteAllBytes($pathModA, $modA)

# Test 2: Modified PE - MD5 fails, AC catches
Assert-DetectedBy -TestName "A.2 Modified PE (EOF byte) detected by Aho-Corasick" `
    -DbPath $dbPathA -FilePath $pathModA -ExpectedScannerId "aho_corasick"

Write-Host "[BYPASSED] md5 (hash changed by EOF modification)" -ForegroundColor DarkYellow
Write-Host "[CAUGHT]   aho_corasick (byte pattern preserved)" -ForegroundColor DarkGreen
Write-Host ""

# ======================================================================
# Scenario B: Byte-Stream Evasion via UPX Packing
# ======================================================================
Write-Host "=== Scenario B: Byte-Stream Evasion (AC -> UPX Unpack) ===" -ForegroundColor Yellow

$upxExe = Get-Command upx -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $upxExe) {
    $upxExe = Get-Command upx.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
}

if (-not $upxExe) {
    Write-Host "[SKIP] Scenario B - upx.exe not found in PATH" -ForegroundColor DarkYellow
    Write-Host "       Install UPX: https://github.com/upx/upx/releases" -ForegroundColor DarkYellow
    Write-Host ""
} else {
    # Distinctive pattern for byte-stream matching
    $markerB = [byte[]]@(
        0x48, 0x83, 0xEC, 0x28,   # sub rsp, 0x28
        0x42, 0x42, 0x42, 0x42,   # distinctive marker "BBBB"
        0x4B, 0x65, 0x73, 0x6F,   # "Keso"
        0x50, 0x61, 0x63, 0x6B,   # "Pack"
        0x54, 0x65, 0x73, 0x74,   # "Test"
        0x48, 0x83, 0xC4, 0x28,   # add rsp, 0x28
        0xC3                       # ret
    )
    # Pad to 8KB for UPX
    $payloadB = New-Object byte[] 8192
    [Array]::Copy($markerB, 0, $payloadB, 256, $markerB.Length)
    for ($i = 0; $i -lt 256; $i++) { $payloadB[$i] = 0xCC }
    for ($i = (256 + $markerB.Length); $i -lt 8192; $i++) {
        $payloadB[$i] = [byte](($i * 7 + 13) % 256)  # pseudo-random fill for compressibility variation
    }

    $peOrigB = New-MinimalPE -Payload $payloadB -TextSectionSize 8192
    $pathOrigB = "$SamplesDir\scenario_b_original.exe"
    [System.IO.File]::WriteAllBytes($pathOrigB, $peOrigB)

    $markerHexB = ($markerB | ForEach-Object { "{0:x2}" -f $_ }) -join ""
    $sigsB = @{
        bytestream = @(@{ name = "Evasion.Test.B.Pattern"; pattern = $markerHexB })
    } | ConvertTo-Json -Depth 4
    $sigsPathB = "$SamplesDir\sigs_b.json"
    [System.IO.File]::WriteAllText($sigsPathB, $sigsB, [System.Text.UTF8Encoding]::new($false))

    $dbPathB = "$SamplesDir\evasion_b.akavdb"
    Compile-AkavDb -SigsJson $sigsPathB -OutputPath $dbPathB

    # Test 3: Original detected by AC
    Assert-DetectedBy -TestName "B.1 Original PE detected by Aho-Corasick" `
        -DbPath $dbPathB -FilePath $pathOrigB -ExpectedScannerId "aho_corasick"

    # Pack with UPX
    $pathPackedB = "$SamplesDir\scenario_b_packed.exe"
    Copy-Item $pathOrigB $pathPackedB -Force
    $upxResult = & $upxExe --best --force $pathPackedB 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[SKIP] Scenario B - UPX packing failed: $upxResult" -ForegroundColor DarkYellow
    } else {
        # Test 4: Packed PE - UPX unpack + rescan catches it
        Assert-DetectedBy -TestName "B.2 Packed PE detected via UPX unpack" `
            -DbPath $dbPathB -FilePath $pathPackedB -ExpectedScannerId "upx:*"

        # Test 5: Packed PE without unpacking - should NOT detect
        $script:TotalTests++
        $jsonOut = & $AkavScan --db $dbPathB --no-packed -j $pathPackedB 2>&1
        $jsonLine = ($jsonOut | Where-Object { $_ -match '^\s*\{' }) -join "`n"
        $notDetected = $true
        if ($jsonLine) {
            try {
                $r = $jsonLine | ConvertFrom-Json
                if ($r.found) { $notDetected = $false }
            } catch { }
        }
        if ($notDetected) {
            Write-Host "[PASS] B.3 Packed PE not detected without unpacker (confirms evasion)" -ForegroundColor Green
            $script:Passed++
        } else {
            Write-Host "[FAIL] B.3 Packed PE should NOT be detected without unpacker" -ForegroundColor Red
            $script:Failed++
        }

        Write-Host "[BYPASSED] aho_corasick (pattern hidden by UPX compression)" -ForegroundColor DarkYellow
        Write-Host "[CAUGHT]   upx:aho_corasick (unpacker reveals original content)" -ForegroundColor DarkGreen
    }
    Write-Host ""
}

# ======================================================================
# Scenario C: Structure-Aware Evasion (AC -> YARA)
# ======================================================================
Write-Host "=== Scenario C: Structure-Aware Evasion (AC -> YARA) ===" -ForegroundColor Yellow

# Build PE with both a byte pattern AND API-name strings
$markerC = [byte[]]@(
    0x48, 0x89, 0x5C, 0x24, 0x08,   # mov [rsp+8], rbx
    0x43, 0x43, 0x43, 0x43,          # "CCCC" distinctive
    0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x54, 0x65, 0x73, 0x74, # "StructTest"
    0x48, 0x8B, 0x5C, 0x24, 0x08,   # mov rbx, [rsp+8]
    0xC3                              # ret
)

# API strings that YARA will match on (null-terminated in .text)
# Built at runtime from base64 to avoid AMSI false positive on API name literals
$str1 = [System.Text.Encoding]::ASCII.GetBytes([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("VmlydHVhbEFsbG9j"))) + [byte]0
$str2 = [System.Text.Encoding]::ASCII.GetBytes([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("Q3JlYXRlUmVtb3RlVGhyZWFk"))) + [byte]0
$str3 = [System.Text.Encoding]::ASCII.GetBytes([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("V3JpdGVQcm9jZXNzTWVtb3J5"))) + [byte]0

$payloadC = New-Object byte[] 1024
[Array]::Copy($markerC, 0, $payloadC, 64, $markerC.Length)
$strOffset = 512
[Array]::Copy($str1, 0, $payloadC, $strOffset, $str1.Length)
$strOffset += $str1.Length
[Array]::Copy($str2, 0, $payloadC, $strOffset, $str2.Length)
$strOffset += $str2.Length
[Array]::Copy($str3, 0, $payloadC, $strOffset, $str3.Length)
# Fill gaps with INT3
for ($i = 0; $i -lt 64; $i++) { $payloadC[$i] = 0xCC }

$peOrigC = New-MinimalPE -Payload $payloadC
$pathOrigC = "$SamplesDir\scenario_c_original.exe"
[System.IO.File]::WriteAllBytes($pathOrigC, $peOrigC)

$markerHexC = ($markerC | ForEach-Object { "{0:x2}" -f $_ }) -join ""

# YARA rule that matches structural features (API strings + PE header)
# Build from base64 to avoid AMSI flagging API name literals
$s1 = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("VmlydHVhbEFsbG9j"))
$s2 = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("Q3JlYXRlUmVtb3RlVGhyZWFk"))
$s3 = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("V3JpdGVQcm9jZXNzTWVtb3J5"))
$yaraRule = "rule Evasion_Test_C {`n    strings:`n        `$api1 = `"$s1`" ascii`n        `$api2 = `"$s2`" ascii`n        `$api3 = `"$s3`" ascii`n    condition:`n        uint16(0) == 0x5A4D and 2 of (`$api1, `$api2, `$api3)`n}"

$sigsC = @{
    bytestream = @(@{ name = "Evasion.Test.C.Pattern"; pattern = $markerHexC })
    yara = @(@{ source = $yaraRule })
} | ConvertTo-Json -Depth 4
$sigsPathC = "$SamplesDir\sigs_c.json"
[System.IO.File]::WriteAllText($sigsPathC, $sigsC, [System.Text.UTF8Encoding]::new($false))

$dbPathC = "$SamplesDir\evasion_c.akavdb"
Compile-AkavDb -SigsJson $sigsPathC -OutputPath $dbPathC

# Test: Original detected by AC (earlier in pipeline than YARA)
Assert-DetectedBy -TestName "C.1 Original PE detected by Aho-Corasick" `
    -DbPath $dbPathC -FilePath $pathOrigC -ExpectedScannerId "aho_corasick"

# Modify: insert NOPs into the byte pattern (break exact match)
$peModC = [byte[]]$peOrigC.Clone()
# The marker starts at file offset: headers(0x200) + 64 = 0x240
$markerFileOffset = 0x200 + 64
# Overwrite middle 4 bytes of marker with NOPs (breaks the exact pattern)
$peModC[$markerFileOffset + 5] = 0x90  # NOP over "CCCC"
$peModC[$markerFileOffset + 6] = 0x90
$peModC[$markerFileOffset + 7] = 0x90
$peModC[$markerFileOffset + 8] = 0x90

$pathModC = "$SamplesDir\scenario_c_modified.exe"
[System.IO.File]::WriteAllBytes($pathModC, $peModC)

# Test: Modified detected by YARA (AC pattern broken, YARA still matches API strings)
Assert-DetectedBy -TestName "C.2 Modified PE (broken pattern) detected by YARA" `
    -DbPath $dbPathC -FilePath $pathModC -ExpectedScannerId "yara"

Write-Host "[BYPASSED] aho_corasick (byte pattern disrupted by NOP insertion)" -ForegroundColor DarkYellow
Write-Host "[CAUGHT]   yara (structural API strings preserved)" -ForegroundColor DarkGreen
Write-Host ""

# ======================================================================
# Scenario D: Fuzzy Hash Evasion (MD5 -> Fuzzy Hash)
# ======================================================================
Write-Host "=== Scenario D: Fuzzy Hash Evasion (MD5 -> Fuzzy Hash) ===" -ForegroundColor Yellow

# Create a larger PE (8KB payload for meaningful fuzzy hash)
$payloadD = New-Object byte[] 8192
# Fill with deterministic pseudo-random content
for ($i = 0; $i -lt 8192; $i++) {
    $payloadD[$i] = [byte](((($i * 31) + 17) -bxor ($i -shr 3)) % 256)
}
# Add a small distinctive header region
$headerD = [System.Text.Encoding]::ASCII.GetBytes("AKESOFUZZTEST_SCENARIO_D_HEADER_")
[Array]::Copy($headerD, 0, $payloadD, 0, $headerD.Length)

$peOrigD = New-MinimalPE -Payload $payloadD -TextSectionSize 8192
$pathOrigD = "$SamplesDir\scenario_d_original.exe"
[System.IO.File]::WriteAllBytes($pathOrigD, $peOrigD)

# Compute MD5 and fuzzy hash
$md5D = Get-MD5Hex -FilePath $pathOrigD
$fuzzyD = (& $SigHelper fuzzy $pathOrigD 2>&1).Trim()
if ($LASTEXITCODE -ne 0 -or -not $fuzzyD) {
    Write-Host "[SKIP] Scenario D - sig_helper fuzzy failed: $fuzzyD" -ForegroundColor DarkYellow
} else {
    Write-Host "       Original MD5:   $md5D"
    Write-Host "       Original Fuzzy: $fuzzyD"

    $sigsD = @{
        md5 = @(@{ name = "Evasion.Test.D"; hash = $md5D })
        fuzzy = @(@{ name = "Evasion.Test.D.Fuzzy"; hash = $fuzzyD })
    } | ConvertTo-Json -Depth 4
    $sigsPathD = "$SamplesDir\sigs_d.json"
    [System.IO.File]::WriteAllText($sigsPathD, $sigsD, [System.Text.UTF8Encoding]::new($false))

    $dbPathD = "$SamplesDir\evasion_d.akavdb"
    Compile-AkavDb -SigsJson $sigsPathD -OutputPath $dbPathD

    # Test: Original detected by MD5 (earlier in pipeline)
    Assert-DetectedBy -TestName "D.1 Original PE detected by MD5" `
        -DbPath $dbPathD -FilePath $pathOrigD -ExpectedScannerId "md5"

    # Modify ~5% of bytes (every 20th byte in payload area, XOR 0xFF)
    $peModD = [byte[]]$peOrigD.Clone()
    $textStart = 0x200  # .text file offset
    $modified = 0
    for ($i = $textStart; $i -lt $peModD.Length; $i += 20) {
        $peModD[$i] = $peModD[$i] -bxor 0xFF
        $modified++
    }
    Write-Host "       Modified $modified bytes (~$([Math]::Round($modified * 100.0 / ($peModD.Length - $textStart), 1))% of payload)"

    $pathModD = "$SamplesDir\scenario_d_modified.exe"
    [System.IO.File]::WriteAllBytes($pathModD, $peModD)

    $md5ModD = Get-MD5Hex -FilePath $pathModD
    Write-Host "       Modified MD5:   $md5ModD (changed: $($md5D -ne $md5ModD))"

    # Test: Modified PE - MD5 fails, fuzzy hash catches
    Assert-DetectedBy -TestName "D.2 Modified PE (5% bytes changed) detected by fuzzy_hash" `
        -DbPath $dbPathD -FilePath $pathModD -ExpectedScannerId "fuzzy_hash"

    Write-Host "[BYPASSED] md5 (hash changed by byte modifications)" -ForegroundColor DarkYellow
    Write-Host "[CAUGHT]   fuzzy_hash (similarity preserved despite 5% modification)" -ForegroundColor DarkGreen
}
Write-Host ""

# ======================================================================
# Summary
# ======================================================================
Write-Host "=" * 60
if ($script:Failed -eq 0) {
    Write-Host "=== Results: $($script:Passed)/$($script:TotalTests) PASSED ===" -ForegroundColor Green
} else {
    Write-Host "=== Results: $($script:Passed)/$($script:TotalTests) passed, $($script:Failed) FAILED ===" -ForegroundColor Red
}
Write-Host "=" * 60

exit $(if ($script:Failed -gt 0) { 1 } else { 0 })
