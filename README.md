# AkesoAV

A proof-of-concept antivirus scan engine for Windows x64, built in C/C++. AkesoAV provides the static and signature-based detection layer that complements [AkesoEDR](https://github.com/derekxmartin/AkesoEDR)'s behavioral detection capabilities.

## Architecture

AkesoAV implements a multi-layered scan pipeline:

- **File Type Detection** — Magic byte identification (PE, ELF, ZIP, GZIP, PDF, OLE2)
- **Signature Engine** — Bloom filter, crypto hash (MD5/SHA-256), CRC32, Aho-Corasick byte-stream, fuzzy hash, graph-based, YARA
- **Heuristic Engine** — Static PE analysis (headers, entropy, imports, strings, ML classifier) + dynamic scoring from x86 emulator API call logs
- **Archive Handling** — ZIP/GZIP/TAR with decompression bomb protection
- **Unpacker Engine** — UPX static unpacker + x86 emulator-assisted generic unpacking
- **Quarantine** — AES-256-GCM encrypted vault with SQLite index

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
.\build\Release\akavscan.exe --eicar-test
.\build\Release\akavscan.exe testdata\eicar.com.txt
```

## Integration with AkesoEDR

In integrated mode, the AkesoEDR agent loads `akesoav.dll` via `LoadLibrary` and calls the C API functions. The engine runs in-process, sharing the EDR's minifilter for real-time on-access scanning.

## License

Research and portfolio use only. Not for production deployment.
