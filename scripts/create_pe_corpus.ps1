# create_pe_corpus.ps1 — Build a seed corpus for fuzz_pe from system PEs.
# Creates testdata/pe_corpus/ with 10 diverse PE files.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts/create_pe_corpus.ps1

$corpusDir = Join-Path $PSScriptRoot "..\testdata\pe_corpus"
if (-not (Test-Path $corpusDir)) { New-Item -ItemType Directory -Path $corpusDir -Force | Out-Null }

$sources = @(
    # 64-bit system DLLs
    @{ src = "$env:SystemRoot\System32\kernel32.dll";    dst = "kernel32_64.dll"     },
    @{ src = "$env:SystemRoot\System32\ntdll.dll";       dst = "ntdll_64.dll"        },
    @{ src = "$env:SystemRoot\System32\user32.dll";      dst = "user32_64.dll"       },
    @{ src = "$env:SystemRoot\System32\advapi32.dll";    dst = "advapi32_64.dll"     },

    # 32-bit system DLLs (SysWOW64)
    @{ src = "$env:SystemRoot\SysWOW64\kernel32.dll";    dst = "kernel32_32.dll"     },
    @{ src = "$env:SystemRoot\SysWOW64\ntdll.dll";       dst = "ntdll_32.dll"        },

    # .NET runtime DLL (has CLR header)
    @{ src = "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll"; dst = "mscorlib_net.dll" },

    # Resource-heavy DLLs
    @{ src = "$env:SystemRoot\System32\shell32.dll";     dst = "shell32_64.dll"      },
    @{ src = "$env:SystemRoot\System32\imageres.dll";    dst = "imageres_64.dll"     },

    # Signed EXE
    @{ src = "$env:SystemRoot\System32\cmd.exe";         dst = "cmd_64.exe"          }
)

$count = 0
foreach ($entry in $sources) {
    $src = $entry.src
    $dst = Join-Path $corpusDir $entry.dst
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Force
        $count++
        Write-Host "[OK] $($entry.dst)"
    } else {
        Write-Host "[SKIP] $src not found"
    }
}

# Also create synthetic minimal PEs from existing testdata
$existing = @("clean_pe_32.exe", "clean_pe_64.exe", "truncated.exe")
foreach ($f in $existing) {
    $src = Join-Path $PSScriptRoot "..\testdata\$f"
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $corpusDir $f) -Force
        $count++
        Write-Host "[OK] $f (from testdata)"
    }
}

Write-Host "`nSeed corpus: $count files in $corpusDir"
