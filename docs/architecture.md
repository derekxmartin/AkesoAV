# AkesoAV Architecture

## Overview

AkesoAV is a proof-of-concept antivirus scan engine for Windows x64. It provides signature-based detection, heuristic analysis, packed binary unpacking, and integration points for EDR telemetry and SIEM event shipping.

## Component Diagram

```
                    ┌──────────────────────────────────────────┐
                    │              CLI (akavscan.exe)           │
                    │  --db --json --recursive --heur-level    │
                    └───────────────┬──────────────────────────┘
                                    │
                    ┌───────────────▼──────────────────────────┐
                    │         Public C API (akesoav.h)          │
                    │  akav_engine_create / init / scan / destroy│
                    └───────────────┬──────────────────────────┘
                                    │
     ┌──────────────────────────────▼──────────────────────────────┐
     │                        Engine (engine.cpp)                   │
     │  Lifecycle: create → init → load_signatures → scan → destroy │
     │  Thread-safe scanning after init                             │
     └────┬────────┬──────────┬──────────┬──────────┬──────────────┘
          │        │          │          │          │
   ┌──────▼──┐ ┌──▼────┐ ┌──▼────┐ ┌──▼─────┐ ┌──▼──────┐
   │ Scanner │ │Unpack │ │Heuris │ │Plugins │ │  SIEM   │
   │Pipeline │ │UPX/Gen│ │tics   │ │(.dll)  │ │Shipper  │
   └────┬────┘ └───────┘ └───────┘ └────────┘ └─────────┘
        │
   ┌────▼─────────────────────────────────────────┐
   │           Signature Scanner (scanner.cpp)     │
   │  Stage 0: EICAR (builtin)                     │
   │  Stage 1: Bloom filter pre-check              │
   │  Stage 2: MD5 hash match                      │
   │  Stage 3: SHA-256 hash match                  │
   │  Stage 4: CRC32 region match                  │
   │  Stage 5: Fuzzy hash (ssdeep similarity)      │
   │  Stage 6: Aho-Corasick byte-stream            │
   │  Stage 7: YARA rules                          │
   │  Short-circuits on first match                 │
   └──────────────────────────────────────────────┘
```

## Source Directory Layout

| Directory | Purpose |
|-----------|---------|
| `src/cli/` | Command-line scanner (akavscan) |
| `src/database/` | .akavdb binary format I/O, memory mapping |
| `src/emulator/` | x86 emulator, PE loader, API stubs |
| `src/heuristics/` | Static analyzer, entropy, imports, strings, ML classifier, dynamic scorer |
| `src/parsers/` | PE, ELF, PDF, ZIP, GZIP, TAR, OLE2, OOXML, SafeReader |
| `src/plugin/` | Plugin SDK and dynamic loader |
| `src/protection/` | DACL hardening, watchdog, integrity monitor |
| `src/quarantine/` | AES-256-GCM encrypted malware vault |
| `src/service/` | Windows service, named pipe, scheduler |
| `src/siem/` | Event serialization, JSONL writer, HTTP shipper |
| `src/signatures/` | Bloom, MD5/SHA256, CRC32, Aho-Corasick, fuzzy hash, YARA, graph sig |
| `src/unpacker/` | UPX decompressor, generic emulation-based unpacker |
| `src/update/` | HTTPS update client with cert pinning |

## Scan Pipeline Data Flow

```
File Input
    │
    ▼
File Type Detection (magic bytes)
    │
    ▼
Signature Pipeline (scanner.cpp)
    │  EICAR → Bloom → MD5 → SHA256 → CRC32 → Fuzzy → AC → YARA
    │  (short-circuit on first match)
    │
    ├─ No match? → Plugin Scanners
    │
    ├─ No match? → UPX Unpack → Re-scan unpacked content
    │
    ├─ No match? → Generic Unpack (x86 emulator) → Re-scan
    │
    ├─ PE file? → Heuristic Analysis
    │     Static (PE header) + Entropy + Imports + Strings + ML Classifier
    │     Score >= threshold → detection
    │
    ├─ PDF? → Stream decompression → JS extraction → Re-scan
    │
    ├─ OLE2? → Stream extraction → VBA extraction → Re-scan
    │
    ├─ ZIP/GZIP/TAR? → Archive extraction → Re-scan each entry
    │     (bomb detection: skip entry, continue to next)
    │
    └─ Result: found/clean + scanner_id + heuristic_score + warnings
```

## .akavdb Signature Database Format

```
Offset  Size    Field
0x0000  4       Magic: 0x56414B41 ("AKAV")
0x0004  4       Version: 1
0x0008  4       Signature count
0x000C  8       Created timestamp (Unix epoch)
0x0014  4       Section count (N)
0x0018  256     RSA-2048 signature (zeros if unsigned)

0x0118  N*16    Section offset table:
                  Type(4) + Offset(4) + Size(4) + EntryCount(4)

Section types: BLOOM=0, MD5=1, SHA256=2, CRC32=3,
               AHO_CORASICK=4, FUZZY_HASH=5, GRAPH_SIG=6,
               YARA=7, WHITELIST=8, STRING_TABLE=0xFF
```

## Service Architecture

The Windows service (`akesoav-service.exe`) runs the engine in a long-lived process with:

- **Named pipe** (`\\.\pipe\AkesoAVScan`): accepts SCAN, VERSION, RELOAD, STATS, PING commands
- **Watchdog** (`akesoav-watchdog.exe`): monitors heartbeat via `\\.\pipe\AkesoAVWatchdog`, restarts on failure
- **Scheduler**: cron-based scheduled scans from `schedules.json`
- **Integrity monitor**: SHA-256 baseline checks on engine binaries every 60s
- **DACL hardening**: denies PROCESS_TERMINATE/VM_WRITE/VM_OPERATION to non-admin

## SIEM Telemetry Flow

```
Scan Event
    │
    ▼
Event Serialization (event_serialize.cpp)
    │  event_id (UUID), timestamp (ISO 8601), source_type, agent_id
    │
    ├──► JSONL Writer (local file: akesoav.jsonl)
    │      100MB rotation, 5 backups, FILE_SHARE_READ
    │
    └──► HTTP Shipper (remote SIEM endpoint)
           POST with API key, async queue
```

Event types: `av:scan_result`, `av:quarantine`, `av:realtime_block`, `av:signature_update`, `av:scan_error`

## EDR Integration

AkesoAV integrates with AkesoEDR via:
- **Shared engine**: EDR loads `akesoav.dll` in-process for minifilter-triggered scans
- **SIEM co-location**: both `akeso_edr` and `akeso_av` events ship to same SIEM
- **AMSI provider**: EDR's AMSI component delegates content scanning to AV engine

## Design Rationale

- **Layered detection**: Cheap checks first (bloom, hash) → expensive last (YARA, heuristics). Short-circuit minimizes overhead for known-clean files.
- **SafeReader everywhere**: All parsers use bounds-checked I/O to prevent crashes on malformed input.
- **Memory-mapped signatures**: .akavdb is mmap'd read-only for zero-copy access and automatic cleanup.
- **Atomic updates**: Signature DB swapped via `MoveFileEx` with `.prev` backup for rollback.
- **Process isolation**: Service hardened with DACL + watchdog restart. Integrity monitor detects tampering.
