# build_fuzz.ps1 — Configure and build fuzz targets using clang-cl from VS 2026.
# Run from the project root: .\scripts\build_fuzz.ps1

$ErrorActionPreference = "Stop"

# Find vcvarsall.bat
$VcVarsAll = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $VcVarsAll)) {
    Write-Error "vcvarsall.bat not found at $VcVarsAll"
    exit 1
}

# Add the LLVM/clang-cl directory to PATH
$ClangDir = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\x64\bin"
if (-not (Test-Path "$ClangDir\clang-cl.exe")) {
    Write-Error "clang-cl.exe not found in $ClangDir"
    exit 1
}

Write-Host "Setting up MSVC x64 environment and building fuzz targets..." -ForegroundColor Cyan

# Run vcvarsall + cmake configure + cmake build in a single cmd session
# so the environment variables set by vcvarsall persist for the build.
$ProjectRoot = (Get-Item $PSScriptRoot).Parent.FullName

cmd /c "`"$VcVarsAll`" x64 && set PATH=$ClangDir;%PATH% && cd /d `"$ProjectRoot`" && cmake --preset fuzz && cmake --build build-fuzz"

if ($LASTEXITCODE -ne 0) {
    Write-Error "Fuzz build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Fuzz targets built successfully in build-fuzz/" -ForegroundColor Green
Write-Host ""
Write-Host "Run a 10-minute fuzz session:" -ForegroundColor Yellow
Write-Host "  .\build-fuzz\fuzz_zip.exe tests\fuzz\corpus_zip -max_total_time=600"
Write-Host "  .\build-fuzz\fuzz_gzip.exe tests\fuzz\corpus_gzip -max_total_time=600"
