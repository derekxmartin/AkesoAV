<p align="center">
  <img src="akeso-av-logo.jpg" alt="AkesoAV Logo" width="300">
</p>

<h1 align="center">AkesoAV</h1>

<p align="center">
  A proof-of-concept antivirus scan engine for Windows x64, built in C/C++.<br>
  AkesoAV provides the static and signature-based detection layer that complements
  <a href="https://github.com/derekxmartin/AkesoEDR">AkesoEDR</a>'s behavioral detection capabilities.
</p>

## Architecture

AkesoAV implements a multi-layered scan pipeline:

- **File Type Detection** — Magic byte identification (PE, ELF, ZIP, GZIP, PDF, OLE2)
- **Signature Engine** — Bloom filter, crypto hash (MD5/SHA-256), CRC32, Aho-Corasick byte-stream, fuzzy hash (TLSH-style)
- **Heuristic Engine** — Static PE analysis (headers, entropy, imports, suspicious strings)
- **Archive Handling** — ZIP/GZIP/TAR with decompression bomb protection
- **Unpacker Engine** — UPX static unpacker (NRV2B/NRV2D/NRV2E + x86 CT filter reversal)
- **Plugin System** — Dynamic DLL plugin loading with versioned API (LoadLibrary/GetProcAddress)
- **Quarantine** — AES-256-GCM encrypted vault with SQLite index
- **SIEM Integration** — JSONL event serialization with HTTP shipping
- **Service Mode** — Windows service with named-pipe IPC and cron-based scheduling

## Scan Pipeline

```
File In
  -> File Type Detection (magic bytes)
  -> Bloom Filter (quick reject)
  -> MD5 / SHA-256 / CRC32 hash matching
  -> Fuzzy Hash (TLSH-style similarity)
  -> Aho-Corasick byte-stream patterns
  -> Plugin Scanners (dynamic DLL extensions)
  -> UPX Unpack (if packed PE detected)
     -> Recursive scan of unpacked content
  -> Heuristic Analysis
     -> Header anomalies, entropy, imports, strings
  -> Archive Extraction (ZIP/GZIP/TAR)
     -> Recursive scan of archive members
  -> Verdict (clean / threat name)
```

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

## Progress

| Phase | Description | Status |
|-------|-------------|--------|
| P0 | Project scaffolding, EICAR detection, CLI scanner | Done |
| P1 | Signature engine (Bloom, MD5, SHA-256, CRC32, Aho-Corasick) | Done |
| P2 | PE parser, scan pipeline integration | Done |
| P3 | ZIP / GZIP / TAR archive handling | Done |
| P4 | Heuristic engine (entropy, imports, strings, static analyzer) | Done |
| P5 | Scan cache, whitelist, quarantine, SIEM, service mode | Done |
| P6 | Fuzzy hashing, UPX static unpacker, dynamic plugins | Done |
| P7 | Extended file format parsers (ELF, PDF, OLE2) | Planned |
| P8 | x86 emulator + generic unpacking | Planned |
| P9 | ML classifier (random forest) | Planned |
| P10 | Update system + delta patches | Planned |
| P11 | Performance tuning + thread pool | Planned |
| P12 | Installer, documentation, final hardening | Planned |

## Integration with AkesoEDR

In integrated mode, the AkesoEDR agent loads `akesoav.dll` via `LoadLibrary` and calls the C API functions. The engine runs in-process, sharing the EDR's minifilter for real-time on-access scanning.

## License

Research and portfolio use only. Not for production deployment.
