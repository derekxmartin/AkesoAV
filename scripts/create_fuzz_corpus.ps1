<#
.SYNOPSIS
    Creates seed corpus files for ELF, PDF, and OLE2 fuzz targets.
.DESCRIPTION
    Generates minimal valid and malformed samples to seed libFuzzer.
    Run from the repository root:
        powershell -ExecutionPolicy Bypass -File scripts\create_fuzz_corpus.ps1
#>

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Write-Bytes {
    param([string]$Path, [byte[]]$Bytes)
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllBytes($Path, $Bytes)
    Write-Host "  Created: $Path ($($Bytes.Length) bytes)"
}

function Put-U16LE([byte[]]$buf, [int]$off, [uint16]$val) {
    $buf[$off]   = [byte]($val -band 0xFF)
    $buf[$off+1] = [byte](($val -shr 8) -band 0xFF)
}

function Put-U32LE([byte[]]$buf, [int]$off, [uint32]$val) {
    $buf[$off]   = [byte]($val -band 0xFF)
    $buf[$off+1] = [byte](($val -shr 8) -band 0xFF)
    $buf[$off+2] = [byte](($val -shr 16) -band 0xFF)
    $buf[$off+3] = [byte](($val -shr 24) -band 0xFF)
}

function Put-U64LE([byte[]]$buf, [int]$off, [uint64]$val) {
    for ($i = 0; $i -lt 8; $i++) {
        $buf[$off + $i] = [byte](($val -shr ($i * 8)) -band 0xFF)
    }
}

# ────────────────────────────────────────────────────────────────
# ELF Corpus
# ────────────────────────────────────────────────────────────────
$elfDir = Join-Path $repoRoot "tests\fuzz\corpus_elf"
Write-Host "`n=== ELF Corpus ==="

# Minimal valid ELF64 (no sections, no segments)
$elf64 = [byte[]]::new(64)
$elf64[0] = 0x7F; $elf64[1] = 0x45; $elf64[2] = 0x4C; $elf64[3] = 0x46  # magic
$elf64[4] = 2   # EI_CLASS = ELFCLASS64
$elf64[5] = 1   # EI_DATA = ELFDATA2LSB
$elf64[6] = 1   # EI_VERSION = EV_CURRENT
$elf64[7] = 0   # EI_OSABI = ELFOSABI_NONE
Put-U16LE $elf64 16 2     # e_type = ET_EXEC
Put-U16LE $elf64 18 0x3E  # e_machine = EM_X86_64
Put-U32LE $elf64 20 1     # e_version = EV_CURRENT
Put-U64LE $elf64 24 0x400000  # e_entry
Put-U64LE $elf64 32 0     # e_phoff (no program headers)
Put-U64LE $elf64 40 0     # e_shoff (no section headers)
Put-U32LE $elf64 48 0     # e_flags
Put-U16LE $elf64 52 64    # e_ehsize
Put-U16LE $elf64 54 56    # e_phentsize
Put-U16LE $elf64 56 0     # e_phnum
Put-U16LE $elf64 58 64    # e_shentsize
Put-U16LE $elf64 60 0     # e_shnum
Put-U16LE $elf64 62 0     # e_shstrndx
Write-Bytes (Join-Path $elfDir "minimal_elf64.bin") $elf64

# Minimal ELF32
$elf32 = [byte[]]::new(52)
$elf32[0] = 0x7F; $elf32[1] = 0x45; $elf32[2] = 0x4C; $elf32[3] = 0x46
$elf32[4] = 1   # ELFCLASS32
$elf32[5] = 1   # ELFDATA2LSB
$elf32[6] = 1   # EV_CURRENT
Put-U16LE $elf32 16 2     # ET_EXEC
Put-U16LE $elf32 18 3     # EM_386
Put-U32LE $elf32 20 1     # e_version
Put-U32LE $elf32 24 0x08048000  # e_entry
Put-U32LE $elf32 28 0     # e_phoff
Put-U32LE $elf32 32 0     # e_shoff
Put-U32LE $elf32 36 0     # e_flags
Put-U16LE $elf32 40 52    # e_ehsize
Put-U16LE $elf32 42 32    # e_phentsize
Put-U16LE $elf32 44 0     # e_phnum
Put-U16LE $elf32 46 40    # e_shentsize
Put-U16LE $elf32 48 0     # e_shnum
Put-U16LE $elf32 50 0     # e_shstrndx
Write-Bytes (Join-Path $elfDir "minimal_elf32.bin") $elf32

# ELF64 with 1 LOAD program header
$elf_ph = [byte[]]::new(120)  # 64 (ehdr) + 56 (phdr)
[Array]::Copy($elf64, $elf_ph, 64)
Put-U64LE $elf_ph 32 64   # e_phoff = 64
Put-U16LE $elf_ph 56 1    # e_phnum = 1
# Program header at offset 64
Put-U32LE $elf_ph 64 1    # p_type = PT_LOAD
Put-U32LE $elf_ph 68 5    # p_flags = PF_R|PF_X
Put-U64LE $elf_ph 72 0    # p_offset
Put-U64LE $elf_ph 80 0x400000  # p_vaddr
Put-U64LE $elf_ph 88 0x400000  # p_paddr
Put-U64LE $elf_ph 96 120  # p_filesz
Put-U64LE $elf_ph 104 120 # p_memsz
Put-U64LE $elf_ph 112 0x1000  # p_align
Write-Bytes (Join-Path $elfDir "elf64_one_load.bin") $elf_ph

# ELF big-endian (EM_SPARC)
$elf_be = [byte[]]::new(52)
$elf_be[0] = 0x7F; $elf_be[1] = 0x45; $elf_be[2] = 0x4C; $elf_be[3] = 0x46
$elf_be[4] = 1   # ELFCLASS32
$elf_be[5] = 2   # ELFDATA2MSB
$elf_be[6] = 1
$elf_be[17] = 3  # ET_DYN (big-endian: offset 16-17)
$elf_be[19] = 2  # EM_SPARC
$elf_be[23] = 1  # e_version
$elf_be[41] = 52 # e_ehsize
$elf_be[43] = 32 # e_phentsize
$elf_be[47] = 40 # e_shentsize
Write-Bytes (Join-Path $elfDir "elf32_bigendian.bin") $elf_be

# Truncated ELF (just magic + class byte)
Write-Bytes (Join-Path $elfDir "truncated_header.bin") @(0x7F, 0x45, 0x4C, 0x46, 2)

# ELF with section headers pointing past EOF
$elf_oob = [byte[]]::new(64)
[Array]::Copy($elf64, $elf_oob, 64)
Put-U64LE $elf_oob 40 ([uint64]4294901760)  # e_shoff = 0xFFFF0000, way past EOF
Put-U16LE $elf_oob 60 100         # e_shnum = 100
Write-Bytes (Join-Path $elfDir "sections_past_eof.bin") $elf_oob

# ELF with phnum = 0xFFFF (PN_XNUM)
$elf_xnum = [byte[]]::new(64)
[Array]::Copy($elf64, $elf_xnum, 64)
Put-U16LE $elf_xnum 56 0xFFFF  # e_phnum = PN_XNUM
Write-Bytes (Join-Path $elfDir "phnum_xnum.bin") $elf_xnum

# Corrupted: valid magic but all zeros after
$elf_zeros = [byte[]]::new(64)
$elf_zeros[0] = 0x7F; $elf_zeros[1] = 0x45; $elf_zeros[2] = 0x4C; $elf_zeros[3] = 0x46
Write-Bytes (Join-Path $elfDir "magic_then_zeros.bin") $elf_zeros

# ELF with overlapping section and program headers
$elf_overlap = [byte[]]::new(64)
[Array]::Copy($elf64, $elf_overlap, 64)
Put-U64LE $elf_overlap 32 48  # e_phoff overlaps ehdr
Put-U16LE $elf_overlap 56 1   # e_phnum
Put-U64LE $elf_overlap 40 48  # e_shoff = same offset
Put-U16LE $elf_overlap 60 1   # e_shnum
Write-Bytes (Join-Path $elfDir "overlapping_headers.bin") $elf_overlap

# ────────────────────────────────────────────────────────────────
# PDF Corpus
# ────────────────────────────────────────────────────────────────
$pdfDir = Join-Path $repoRoot "tests\fuzz\corpus_pdf"
Write-Host "`n=== PDF Corpus ==="

# Minimal valid PDF
$minPdf = [System.Text.Encoding]::ASCII.GetBytes(
    "%PDF-1.4`n" +
    "1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n" +
    "2 0 obj`n<< /Type /Pages /Kids [3 0 R] /Count 1 >>`nendobj`n" +
    "3 0 obj`n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>`nendobj`n" +
    "xref`n0 4`n" +
    "0000000000 65535 f `n" +
    "0000000009 00000 n `n" +
    "0000000058 00000 n `n" +
    "0000000115 00000 n `n" +
    "trailer`n<< /Size 4 /Root 1 0 R >>`n" +
    "startxref`n190`n%%EOF`n"
)
Write-Bytes (Join-Path $pdfDir "minimal.pdf") $minPdf

# PDF with JavaScript
$jsPdf = [System.Text.Encoding]::ASCII.GetBytes(
    "%PDF-1.4`n" +
    "1 0 obj`n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>`nendobj`n" +
    "2 0 obj`n<< /Type /Pages /Kids [] /Count 0 >>`nendobj`n" +
    "4 0 obj`n<< /Type /Action /S /JavaScript /JS (app.alert\('test'\)) >>`nendobj`n" +
    "xref`n0 5`n" +
    "0000000000 65535 f `n" +
    "0000000009 00000 n `n" +
    "0000000074 00000 n `n" +
    "0000000000 65535 f `n" +
    "0000000124 00000 n `n" +
    "trailer`n<< /Size 5 /Root 1 0 R >>`n" +
    "startxref`n220`n%%EOF`n"
)
Write-Bytes (Join-Path $pdfDir "javascript.pdf") $jsPdf

# PDF with FlateDecode stream (empty deflate)
$flatePdf = [System.Text.Encoding]::ASCII.GetBytes(
    "%PDF-1.4`n" +
    "1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n" +
    "2 0 obj`n<< /Type /Pages /Kids [] /Count 0 >>`nendobj`n" +
    "3 0 obj`n<< /Length 8 /Filter /FlateDecode >>`nstream`n"
)
# Minimal valid zlib: 78 01 03 00 00 00 00 01
$zlibData = [byte[]]@(0x78, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01)
$flateTail = [System.Text.Encoding]::ASCII.GetBytes(
    "`nendstream`nendobj`n" +
    "xref`n0 4`n" +
    "0000000000 65535 f `n" +
    "0000000009 00000 n `n" +
    "0000000058 00000 n `n" +
    "0000000108 00000 n `n" +
    "trailer`n<< /Size 4 /Root 1 0 R >>`n" +
    "startxref`n200`n%%EOF`n"
)
$flatePdfBytes = [byte[]]::new($flatePdf.Length + $zlibData.Length + $flateTail.Length)
[Array]::Copy($flatePdf, 0, $flatePdfBytes, 0, $flatePdf.Length)
[Array]::Copy($zlibData, 0, $flatePdfBytes, $flatePdf.Length, $zlibData.Length)
[Array]::Copy($flateTail, 0, $flatePdfBytes, $flatePdf.Length + $zlibData.Length, $flateTail.Length)
Write-Bytes (Join-Path $pdfDir "flatedecode.pdf") $flatePdfBytes

# PDF with embedded file
$embedPdf = [System.Text.Encoding]::ASCII.GetBytes(
    "%PDF-1.4`n" +
    "1 0 obj`n<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(test.txt) 3 0 R] >> >> >>`nendobj`n" +
    "2 0 obj`n<< /Type /Pages /Kids [] /Count 0 >>`nendobj`n" +
    "3 0 obj`n<< /Type /Filespec /F (test.txt) /EF << /F 4 0 R >> >>`nendobj`n" +
    "4 0 obj`n<< /Length 5 >>`nstream`nhello`nendstream`nendobj`n" +
    "xref`n0 5`n" +
    "0000000000 65535 f `n" +
    "0000000009 00000 n `n" +
    "0000000120 00000 n `n" +
    "0000000169 00000 n `n" +
    "0000000240 00000 n `n" +
    "trailer`n<< /Size 5 /Root 1 0 R >>`n" +
    "startxref`n300`n%%EOF`n"
)
Write-Bytes (Join-Path $pdfDir "embedded_file.pdf") $embedPdf

# PDF with ASCII85 stream
$a85Pdf = [System.Text.Encoding]::ASCII.GetBytes(
    "%PDF-1.4`n" +
    "1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n" +
    "2 0 obj`n<< /Type /Pages /Kids [] /Count 0 >>`nendobj`n" +
    "3 0 obj`n<< /Length 12 /Filter /ASCII85Decode >>`nstream`n87cURD]j7BEbo7~>`nendstream`nendobj`n" +
    "xref`n0 4`n" +
    "0000000000 65535 f `n" +
    "0000000009 00000 n `n" +
    "0000000058 00000 n `n" +
    "0000000108 00000 n `n" +
    "trailer`n<< /Size 4 /Root 1 0 R >>`n" +
    "startxref`n250`n%%EOF`n"
)
Write-Bytes (Join-Path $pdfDir "ascii85.pdf") $a85Pdf

# Truncated PDF (header only)
Write-Bytes (Join-Path $pdfDir "truncated.pdf") ([System.Text.Encoding]::ASCII.GetBytes("%PDF-1.4`n"))

# PDF with xref pointing past EOF
$badXref = [System.Text.Encoding]::ASCII.GetBytes(
    "%PDF-1.4`n" +
    "1 0 obj`n<< /Type /Catalog >>`nendobj`n" +
    "xref`n0 2`n" +
    "0000000000 65535 f `n" +
    "9999999999 00000 n `n" +
    "trailer`n<< /Size 2 /Root 1 0 R >>`n" +
    "startxref`n55`n%%EOF`n"
)
Write-Bytes (Join-Path $pdfDir "xref_past_eof.pdf") $badXref

# PDF header then random bytes
$pdfRand = [byte[]]::new(256)
(New-Object System.Random(42)).NextBytes($pdfRand)
$pdfMagic = [System.Text.Encoding]::ASCII.GetBytes("%PDF-1.7`n")
[Array]::Copy($pdfMagic, $pdfRand, $pdfMagic.Length)
Write-Bytes (Join-Path $pdfDir "header_then_garbage.pdf") $pdfRand

# PDF with LZWDecode filter reference
$lzwPdf = [System.Text.Encoding]::ASCII.GetBytes(
    "%PDF-1.2`n" +
    "1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n" +
    "2 0 obj`n<< /Type /Pages /Kids [] /Count 0 >>`nendobj`n" +
    "3 0 obj`n<< /Length 3 /Filter /LZWDecode >>`nstream`n" + [char]0x80 + [char]0x0B + [char]0x60 + "`nendstream`nendobj`n" +
    "xref`n0 4`n" +
    "0000000000 65535 f `n" +
    "0000000009 00000 n `n" +
    "0000000058 00000 n `n" +
    "0000000108 00000 n `n" +
    "trailer`n<< /Size 4 /Root 1 0 R >>`n" +
    "startxref`n200`n%%EOF`n"
)
Write-Bytes (Join-Path $pdfDir "lzwdecode.pdf") $lzwPdf

# ────────────────────────────────────────────────────────────────
# OLE2 Corpus
# ────────────────────────────────────────────────────────────────
$ole2Dir = Join-Path $repoRoot "tests\fuzz\corpus_ole2"
Write-Host "`n=== OLE2 Corpus ==="

$FREESECT  = [uint32]4294967295   # 0xFFFFFFFF
$ENDOFCHAIN = [uint32]4294967294  # 0xFFFFFFFE
$FATSECT   = [uint32]4294967293   # 0xFFFFFFFD

function New-OLE2([int]$numSectors) {
    # Header (512) + N sectors (512 each)
    $size = 512 + ($numSectors * 512)
    $buf = [byte[]]::new($size)
    # Magic
    $buf[0]=0xD0; $buf[1]=0xCF; $buf[2]=0x11; $buf[3]=0xE0
    $buf[4]=0xA1; $buf[5]=0xB1; $buf[6]=0x1A; $buf[7]=0xE1
    # Version
    Put-U16LE $buf 24 0x003E   # minor
    Put-U16LE $buf 26 0x0003   # major v3
    Put-U16LE $buf 28 0xFFFE   # byte order
    Put-U16LE $buf 30 9        # sector size power (512)
    Put-U16LE $buf 32 6        # mini sector size power (64)
    Put-U32LE $buf 56 0x1000   # mini stream cutoff
    Put-U32LE $buf 60 $ENDOFCHAIN  # minifat start
    Put-U32LE $buf 64 0        # num minifat
    Put-U32LE $buf 68 $ENDOFCHAIN  # difat start
    Put-U32LE $buf 72 0        # num difat
    # Initialize DIFAT array to FREESECT
    for ($i = 0; $i -lt 109; $i++) {
        Put-U32LE $buf (76 + $i * 4) $FREESECT
    }
    return $buf
}

function Write-DirEntry([byte[]]$buf, [int]$offset, [string]$name, [byte]$objType, [uint32]$startSect, [uint32]$streamSize) {
    # Name as UTF-16LE
    $nameBytes = [System.Text.Encoding]::Unicode.GetBytes($name)
    $nameLen = [Math]::Min($nameBytes.Length, 62)
    [Array]::Copy($nameBytes, 0, $buf, $offset, $nameLen)
    Put-U16LE $buf ($offset + 64) ([uint16]($nameLen + 2))  # cb (includes null terminator)
    $buf[$offset + 66] = $objType
    # left/right/child = FREESECT
    Put-U32LE $buf ($offset + 68) $FREESECT  # left
    Put-U32LE $buf ($offset + 72) $FREESECT  # right
    Put-U32LE $buf ($offset + 76) $FREESECT  # child
    Put-U32LE $buf ($offset + 116) $startSect
    Put-U32LE $buf ($offset + 120) $streamSize
}

# Minimal valid OLE2: header + 1 FAT sector + 1 directory sector
$ole2_min = New-OLE2 2
Put-U32LE $ole2_min 44 1       # num_fat_sectors = 1
Put-U32LE $ole2_min 48 1       # dir_start = sector 1
Put-U32LE $ole2_min 76 0       # DIFAT[0] = sector 0 (FAT)
# Sector 0 = FAT: sector 0 = FATSECT, sector 1 = ENDOFCHAIN
Put-U32LE $ole2_min 512 $FATSECT
Put-U32LE $ole2_min 516 $ENDOFCHAIN
# Sector 1 = Directory: Root Entry
Write-DirEntry $ole2_min 1024 "Root Entry" 5 $ENDOFCHAIN 0
Write-Bytes (Join-Path $ole2Dir "minimal.bin") $ole2_min

# OLE2 with a stream entry
$ole2_stream = New-OLE2 4
Put-U32LE $ole2_stream 44 1    # num_fat = 1
Put-U32LE $ole2_stream 48 1    # dir_start = 1
Put-U32LE $ole2_stream 76 0    # DIFAT[0] = 0
# FAT: 0=FATSECT, 1=ENDOFCHAIN, 2=ENDOFCHAIN, 3=ENDOFCHAIN
Put-U32LE $ole2_stream 512 $FATSECT
Put-U32LE $ole2_stream 516 $ENDOFCHAIN
Put-U32LE $ole2_stream 520 $ENDOFCHAIN
Put-U32LE $ole2_stream 524 $ENDOFCHAIN
# Directory sector (sector 1)
Write-DirEntry $ole2_stream 1024 "Root Entry" 5 $ENDOFCHAIN 0
Put-U32LE $ole2_stream (1024 + 76) 1  # child_sid = 1 (the stream)
Write-DirEntry $ole2_stream 1152 "TestStream" 2 2 512  # stream in sector 2
# Sector 2-3 = stream data (512 bytes of 0xAA)
for ($i = 0; $i -lt 512; $i++) { $ole2_stream[1536 + $i] = 0xAA }
Write-Bytes (Join-Path $ole2Dir "one_stream.bin") $ole2_stream

# OLE2 with FAT self-loop (sector 0 points to itself)
$ole2_loop = New-OLE2 2
Put-U32LE $ole2_loop 44 1
Put-U32LE $ole2_loop 48 1
Put-U32LE $ole2_loop 76 0
# FAT: sector 0 = 0 (self-loop!), sector 1 = ENDOFCHAIN
Put-U32LE $ole2_loop 512 0
Put-U32LE $ole2_loop 516 $ENDOFCHAIN
Write-DirEntry $ole2_loop 1024 "Root Entry" 5 $ENDOFCHAIN 0
Write-Bytes (Join-Path $ole2Dir "fat_self_loop.bin") $ole2_loop

# OLE2 with directory chain loop
$ole2_dirloop = New-OLE2 2
Put-U32LE $ole2_dirloop 44 1
Put-U32LE $ole2_dirloop 48 0     # dir starts at sector 0
Put-U32LE $ole2_dirloop 76 1     # DIFAT[0] = sector 1 (FAT)
# FAT at sector 1: sector 0 -> 0 (dir chain loops)
Put-U32LE $ole2_dirloop (512+512) 0       # FAT[0] = 0 (loop)
Put-U32LE $ole2_dirloop (512+512+4) $FATSECT  # FAT[1] = FATSECT
Write-DirEntry $ole2_dirloop 512 "Root Entry" 5 $ENDOFCHAIN 0
Write-Bytes (Join-Path $ole2Dir "dir_chain_loop.bin") $ole2_dirloop

# OLE2 with all-zero directory entries (triggers parent_sid BFS edge case)
$ole2_zeroed = New-OLE2 2
Put-U32LE $ole2_zeroed 44 1
Put-U32LE $ole2_zeroed 48 1
Put-U32LE $ole2_zeroed 76 0
Put-U32LE $ole2_zeroed 512 $FATSECT
Put-U32LE $ole2_zeroed 516 $ENDOFCHAIN
# Directory is all zeros (4 entries of 128 bytes each)
Write-Bytes (Join-Path $ole2Dir "zeroed_directory.bin") $ole2_zeroed

# OLE2 truncated to just header
$ole2_hdr = [byte[]]::new(512)
[Array]::Copy((New-OLE2 0), $ole2_hdr, 512)
Write-Bytes (Join-Path $ole2Dir "header_only.bin") $ole2_hdr

# OLE2 magic then random bytes
$ole2_rand = [byte[]]::new(1024)
(New-Object System.Random(99)).NextBytes($ole2_rand)
$ole2_rand[0]=0xD0; $ole2_rand[1]=0xCF; $ole2_rand[2]=0x11; $ole2_rand[3]=0xE0
$ole2_rand[4]=0xA1; $ole2_rand[5]=0xB1; $ole2_rand[6]=0x1A; $ole2_rand[7]=0xE1
Write-Bytes (Join-Path $ole2Dir "magic_then_random.bin") $ole2_rand

# OLE2 with DIFAT chain
$ole2_difat = New-OLE2 3
Put-U32LE $ole2_difat 44 1
Put-U32LE $ole2_difat 48 1
Put-U32LE $ole2_difat 68 2      # difat_start = sector 2
Put-U32LE $ole2_difat 72 1      # num_difat = 1
Put-U32LE $ole2_difat 76 0      # DIFAT[0] = sector 0 (FAT)
# FAT (sector 0)
Put-U32LE $ole2_difat 512 $FATSECT
Put-U32LE $ole2_difat 516 $ENDOFCHAIN
Put-U32LE $ole2_difat 520 $ENDOFCHAIN
# Directory (sector 1)
Write-DirEntry $ole2_difat 1024 "Root Entry" 5 $ENDOFCHAIN 0
# DIFAT sector (sector 2): all FREESECT except last = ENDOFCHAIN
$difatBase = 512 + 2 * 512
for ($i = 0; $i -lt 127; $i++) {
    Put-U32LE $ole2_difat ($difatBase + $i * 4) $FREESECT
}
Put-U32LE $ole2_difat ($difatBase + 127 * 4) $ENDOFCHAIN
Write-Bytes (Join-Path $ole2Dir "with_difat.bin") $ole2_difat

# OVBA compressed data samples
# Valid OVBA: signature + one compressed chunk with literal "Sub Main"
$vbaText = [System.Text.Encoding]::ASCII.GetBytes("Sub Main")
$chunkData = $vbaText  # all literals for simplicity
$chunkSize = $chunkData.Length + 1  # +1 for flag byte
$sizeField = [uint16]($chunkSize - 3)
$chunkHdr = [uint16]($sizeField -bor 0xB000)  # compressed, sig=011
$ovba = [byte[]]::new(3 + $chunkData.Length + 1)
$ovba[0] = 0x01  # signature
$ovba[1] = [byte]($chunkHdr -band 0xFF)
$ovba[2] = [byte](($chunkHdr -shr 8) -band 0xFF)
# Flag byte: all literals (0x00)
$ovba[3] = 0x00
[Array]::Copy($chunkData, 0, $ovba, 4, $chunkData.Length)
Write-Bytes (Join-Path $ole2Dir "ovba_simple.bin") $ovba

# OVBA with bad signature
Write-Bytes (Join-Path $ole2Dir "ovba_bad_sig.bin") @(0x02, 0x00, 0xB0, 0x00)

# OVBA truncated (signature only)
Write-Bytes (Join-Path $ole2Dir "ovba_truncated.bin") @(0x01)

Write-Host "`n=== Done ==="
Write-Host "Seed corpus files created for ELF, PDF, and OLE2 fuzz targets."
