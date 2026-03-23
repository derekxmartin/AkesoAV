# AkesoAV

<p align="center">
  <img src="akeso-av-logo.jpg" alt="AkesoAV Logo" width="300">
</p>

A proof-of-concept antivirus scan engine for Windows x64, built in C/C++ with a multi-layered detection pipeline covering file signatures, heuristic analysis, archive unpacking, x86 emulation, and plugin extensibility.

AkesoAV provides the static and signature-based detection layer that complements [AkesoEDR](https://github.com/derekxmartin/AkesoEDR)'s behavioral detection capabilities. Integration with [AkesoSIEM](https://github.com/derekxmartin/AkesoSIEM) enables cross-product threat correlation, and [AkesoDLP](https://github.com/derekxmartin/AkesoDLP) extends coverage to data exfiltration prevention.

---

## What It Does

AkesoAV scans files through a six-stage signature pipeline, multiple unpacking engines, heuristic analysis, and recursive archive extraction to classify files as clean or malicious. It operates as a shared library (`akesoav.dll`), a CLI scanner (`akavscan.exe`), or a Windows service with named-pipe IPC.

**Highlights:**

- **Six-stage signature pipeline** with Bloom filter pre-screening, MD5/SHA-256/CRC32 hash matching, TLSH-style fuzzy hashing, and Aho-Corasick byte-stream patterns
- **File type detection** via magic bytes for PE, ELF, ZIP, GZIP, TAR, PDF, and OLE2 formats
- **PE parser** with full import/export tables, section entropy, Rich header, Authenticode, overlay detection, and resource enumeration
- **Extended format parsers** for ELF (program/section headers, symbol tables), PDF (stream decompression, JavaScript extraction), and OLE2 (VBA macro detection)
- **Heuristic engine** analyzing PE header anomalies, section entropy, suspicious imports, and string patterns with weighted scoring
- **UPX static unpacker** supporting NRV2B/NRV2D/NRV2E decompression with x86 CALL/JMP filter reversal and PE reconstruction
- **x86 emulator** with 70+ instruction handlers, EFLAGS, prefix support, and 2M instruction limit for behavioral unpacking
- **Generic emulation-based unpacker** detecting write-then-jump patterns (>4KB write + EIP transfer to written region) with PE payload recovery
- **API stub system** logging emulated Windows API calls with parameter capture and plausible return values
- **Archive handling** for ZIP/GZIP/TAR with decompression bomb protection and recursive member scanning
- **Plugin system** with dynamic DLL loading via versioned API (LoadLibrary/GetProcAddress)
- **Quarantine vault** using AES-256-GCM encryption with SQLite metadata index
- **SIEM integration** via JSONL event serialization with HTTP shipping to [AkesoSIEM](https://github.com/derekxmartin/AkesoSIEM)
- **Windows service mode** with named-pipe IPC, cron-based scheduled scanning, and SCM integration
- **CLI scanner** with JSON output, recursive directory scanning, verbose mode, and EICAR self-test

---

## Architecture

```
File In
  -> File Type Detection (magic bytes)
  -> Bloom Filter (quick reject)
  -> MD5 / SHA-256 / CRC32 hash matching
  -> Fuzzy Hash (TLSH-style similarity)
  -> Aho-Corasick byte-stream patterns
  -> Plugin Scanners (dynamic DLL extensions)
  -> UPX Static Unpack (if packed PE detected)
     -> Recursive scan of unpacked content
  -> Generic Emulation Unpack (write-then-jump detection)
     -> PE loader + x86 emulator + API stubs
     -> Recursive scan of recovered payload
  -> Heuristic Analysis
     -> Header anomalies, entropy, imports, strings
  -> Archive Extraction (ZIP / GZIP / TAR)
     -> Recursive scan of archive members
  -> PDF / OLE2 Stream Extraction
     -> Decompressed streams, embedded JS, VBA macros
  -> Verdict (clean / threat name)
```

---

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| **akesoav.dll** | C/C++ | Shared library exposing the C API for scan engine lifecycle, scanning, cache, whitelist, quarantine, and SIEM |
| **akavscan.exe** | C | CLI scanner with JSON output, recursive scanning, verbose mode, and EICAR self-test |
| **akesoav-service.exe** | C++ | Windows service with named-pipe IPC, cron-based scheduling, and SCM integration |
| **create_test_db.exe** | C++ | Utility to generate test signature databases from EICAR and test samples |

---

## x86 Emulator

The emulator provides a complete 32-bit x86 execution environment for analyzing packed and obfuscated PE files that resist static analysis.

**Instruction Decoder:** Handles legacy x86 encoding with prefix bytes (REP, LOCK, segment overrides, operand/address size), ModR/M + SIB addressing, and 0F-prefixed extended opcodes. Supports 70+ instruction mnemonics covering data movement, arithmetic, logic, control flow, string operations, and system instructions.

**Execution Engine:** Register file (EAX-EDI, ESP, EBP, EIP), full EFLAGS computation (ZF/SF/CF/OF/PF/DF), flat memory model with bounds checking, stack sentinel detection for clean halt on RET, and a configurable instruction limit (default 2M) to prevent runaway execution.

**PE Loader:** Maps PE32 sections at ImageBase, resolves imports to stub addresses in the IAT, and sets up minimal TEB/PEB structures at fixed addresses for anti-analysis bypass.

**API Stubs:** Each imported Windows API receives a 3-byte stub (`INT 0x2E; RET`). The INT 0x2E dispatch logs calls with parameters (stdcall convention), sets EAX to plausible return values (e.g., VirtualAlloc returns a heap pointer, GetModuleHandle returns ImageBase), and lets execution continue.

**Write Tracking:** Records memory write regions with merging for efficient tracking. The generic unpacker monitors these regions to detect when EIP transfers into dynamically-written code — the signature of an unpacking stub completing its work.

---

## Building

Requires Visual Studio 2022 with MSVC C/C++ toolset.

```powershell
cmake -G "Visual Studio 17 2022" -A x64 -B build
cmake --build build --config Release
```

### Run Tests

```powershell
cd build
ctest -C Release --output-on-failure
```

### Quick Test

```powershell
# Generate test signature database
.\build\Release\create_test_db.exe testdata\test.akavdb

# EICAR self-test
.\build\Release\akavscan.exe --eicar-test --db testdata\test.akavdb

# Scan a file
.\build\Release\akavscan.exe --db testdata\test.akavdb testdata\eicar.com.txt
```

### Fuzz Testing

Fuzz targets build with clang-cl and libFuzzer:

```powershell
cmake --preset fuzz
cmake --build build-fuzz
.\build-fuzz\fuzz_x86_decode.exe -max_total_time=600
.\build-fuzz\fuzz_x86_emu.exe -max_total_time=600
```

Nine fuzz targets cover the scan buffer, PE parser, x86 decoder, x86 emulator, ZIP/GZIP, ELF, PDF, and OLE2 parsers.

---

## Implementation Phases

| Phase | Description | Status |
|-------|-------------|--------|
| P0 | Project scaffolding, EICAR detection, CLI scanner | Done |
| P1 | Signature engine (Bloom, MD5, SHA-256, CRC32, Aho-Corasick) | Done |
| P2 | PE parser, scan pipeline integration | Done |
| P3 | ZIP / GZIP / TAR archive handling | Done |
| P4 | Heuristic engine (entropy, imports, strings, static analyzer) | Done |
| P5 | Scan cache, whitelist, quarantine, SIEM, service mode | Done |
| P6 | Fuzzy hashing, UPX static unpacker, dynamic plugins | Done |
| P7 | Extended file format parsers (ELF, PDF, OLE2) | Done |
| P8 | x86 emulator + generic unpacking | Done |
| P9 | ML classifier (random forest) | Planned |
| P10 | Update system + delta patches | Planned |
| P11 | Performance tuning + thread pool | Planned |
| P12 | Installer, documentation, final hardening | Planned |

See `REQUIREMENTS.md` for the full implementation roadmap (75 tasks, 13 phases).

---

## Integration with AkesoEDR

In integrated mode, the AkesoEDR agent loads `akesoav.dll` via `LoadLibrary` and calls the C API functions. The engine runs in-process, sharing the EDR's minifilter for real-time on-access scanning. Scan results are forwarded to [AkesoSIEM](https://github.com/derekxmartin/AkesoSIEM) via the SIEM output writer for cross-product correlation with EDR behavioral detections and DLP data exfiltration alerts.

---

## License

MIT License. See [LICENSE](LICENSE).

## Disclaimer

This is an educational proof-of-concept built for learning and research purposes. It is **not** production security software. Deploy only in authorized, isolated test environments.
