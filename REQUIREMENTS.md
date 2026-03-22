# AkesoAV — Requirements Document v1.2

**A Proof-of-Concept Antivirus Scan Engine for Windows x64**
Version 1.2 — Requirements + Implementation Phases | March 2026
Architecture derived from *The Antivirus Hacker's Handbook* by Joxean Koret & Elias Bachaalany (Wiley, 2015)
Designed for integration with AkesoEDR as the static/signature detection layer within a unified endpoint security platform

> **v1.2 Changelog (from v1.1):** Added AkesoSIEM telemetry integration: §3.7 with full event schema for 7 event types (av:scan_result, av:quarantine, av:realtime_block, av:signature_update, av:scan_error, av:scheduled_scan_start, av:scheduled_scan_complete), common envelope per SIEM v2.4 §2, ECS field mappings per SIEM v2.4 §4.4, NDJSON transport specification, ring buffer batching, standalone HTTP shipper + JSONL local log, integrated-mode callback for EDR agent. C API additions: akav_siem_event_t, akav_siem_callback_t, akav_set_siem_callback(), akav_siem_start/stop_http_shipper(), akav_schedule_load/start/stop/run_now/status(). Added §5.13 Scheduled Scanning: cron-based scheduler, quick/full/custom scan types, I/O throttling, battery-aware pause, progress tracking, CLI exposure. Added Phase 11: Hardening & Evasion Resistance (6 tasks) — signature evasion testing across all layers, parser crash resilience, self-protection attack suite, heuristic boundary testing, emulator anti-analysis testing, update protocol attack suite. Renumbered old Phase 11 → Phase 12. Added P5-T7 (SIEM event shipper, L), P5-T8 (scheduled scanning, L), P12-T8 (SIEM integration test, L). 11 new integration test scenarios (#27–37). Updated repo structure with src/siem/ and tests/hardening/. Total: +9 tasks (67 → 76), +1 phase (12 → 13).

---

# PART I: REQUIREMENTS & ARCHITECTURE

## 1. Executive Summary

AkesoAV is a proof-of-concept antivirus scan engine for 64-bit Windows, built entirely in C/C++. It provides the static and signature-based detection layer that complements AkesoEDR's behavioral detection capabilities. When loaded as a DLL within the AkesoEDR agent, it transforms minifilter file events into malware verdicts — completing the AV+EDR integration pattern used by production platforms like Trellix ENS.

The project's design is directly informed by the AV architecture documented in *The Antivirus Hacker's Handbook*. Each component the book deconstructs — from signature matching algorithms and file format parsers to heuristic engines, CPU emulators, and update protocols — becomes a discrete, testable module within AkesoAV. The book's analysis of real AV vulnerabilities (parser bugs, update protocol weaknesses, self-protection bypasses) informs the security design constraints applied to every component.

AkesoAV operates in two modes: **standalone** (CLI scanner + Windows service for independent operation and development testing) and **integrated** (loaded as a DLL by the AkesoEDR agent, sharing the existing minifilter for real-time on-access scanning). Both modes use the same engine, same C API, same signature database.

This document is organized into two parts. Part I captures the system requirements: what AkesoAV must do, how its components are structured, and the acceptance criteria for each engine subsystem. Part II breaks the implementation into phased tasks sized for iterative development with Claude Code.

## 2. Project Goals & Non-Goals

### 2.1 Goals

- Build a working, modular AV scan engine implementing the kernel/scanner/product architecture described in Ch. 1–5 of the Handbook.
- Target Windows x64 as the primary platform, using MSVC and the same toolchain as AkesoEDR.
- Implement multi-layered signature matching (bloom filter → cryptographic hash → CRC → Aho-Corasick → fuzzy hash → graph-based) as documented in Ch. 4.
- Parse hostile file formats (PE, ELF, ZIP, PDF, OLE2) in C/C++ with defensive coding discipline (SafeReader, MSVC /analyze, continuous fuzzing via clang-cl + libFuzzer).
- Implement static and dynamic heuristic engines (Ch. 3 plug-in architecture, weight-based scoring) for behavioral classification.
- Build an x86 CPU emulator for generic unpacking (Ch. 3) with anti-emulation awareness.
- Implement a secure update protocol that avoids every vulnerability documented in Ch. 5.
- Expose a clean, thread-safe C API (akesoav.dll + akesoav.h) loadable by the AkesoEDR agent, with Python bindings for automation.
- Integrate with AkesoEDR's minifilter for real-time on-access scanning with scan caching to minimize performance impact.
- Enable a single Windows VM deployment with working EDR + AV + DLP POCs producing correlated telemetry.
- Generate structured JSON output compatible with AkesoEDR's telemetry pipeline and rule engine.

### 2.2 Non-Goals (v1)

- Production deployment or commercial use. AkesoAV is a research and portfolio tool.
- Separate filesystem minifilter driver (real-time scanning uses AkesoEDR's existing minifilter).
- Cloud-based reputation scoring, sandboxing-as-a-service, or global telemetry collection.
- Linux/macOS native builds (engine is portable C++, but v1 targets MSVC only; cross-platform is v2).
- Full x86-64 emulation (32-bit x86 subset is sufficient for unpacking).
- ELAM certification or WHQL driver signing (test-signing acceptable for v1).
- Anti-exploiting / ASLR enforcement for third-party applications (deferred to v2+).

## 3. System Architecture

### 3.1 Component Overview

| Component | Mode | Responsibility |
|---|---|---|
| akesoav.dll | Shared library | Core engine: scan pipeline, signature matching, heuristic engines, file parsers, emulator, unpacker, scan cache. C API boundary (akesoav.h). Thread-safe. Loaded by standalone tools and AkesoEDR agent. |
| akavscan.exe | User (CLI) | Standalone scanner. Loads engine DLL, scans files/directories, prints results. JSON output. Recursive and archive-aware. |
| akesoav-service.exe | User (service) | Standalone Windows service. Named pipe IPC. Thread pool. Pre-loads signatures. For independent testing without AkesoEDR. |
| pyakav | Python bindings | ctypes wrapper over C API. Automation, fuzzing harnesses, signature tooling, testing. |
| akavdb-tool | Python CLI | Signature management: create, compile, import (ClamAV/YARA), sign, verify, test. |
| akav-update.exe | User (client) | Secure signature update client. HTTPS + certificate pinning + RSA verification. |

### 3.2 Integration with AkesoEDR

In integrated mode, the AkesoEDR agent loads akesoav.dll via `LoadLibrary` and resolves the C API functions via `GetProcAddress`. No separate service, no separate IPC — the engine runs in-process within akesoedr-agent.exe.

**Cross-project dependency:** AkesoAV Phase 5 (EDR Integration) requires AkesoEDR Phase 5 (Filesystem Minifilter) to be operational. The EDR agent's event processor must have an extensible telemetry schema that accepts additional fields.

```
┌────────────────────────────────────────────────────────────┐
│                   Windows Test VM                           │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              akesoedr-drv.sys (kernel)                │  │
│  │  Process/Thread/Object/Image/Registry Callbacks      │  │
│  │  Filesystem Minifilter (IRP_MJ_CREATE/WRITE)         │  │
│  │  WFP Network Filter                                  │  │
│  └────────────────────┬─────────────────────────────────┘  │
│                       │ filter port + named pipe            │
│  ┌────────────────────▼─────────────────────────────────┐  │
│  │           akesoedr-agent.exe (service)                │  │
│  │                                                      │  │
│  │  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐  │  │
│  │  │ EDR Rule    │ │ AV Engine    │ │ DLP Engine   │  │  │
│  │  │ Engine      │ │ (akesoav     │ │ (akesodlp    │  │  │
│  │  │ (built-in)  │ │  .dll)       │ │  .dll)       │  │  │
│  │  └─────────────┘ └──────────────┘ └──────────────┘  │  │
│  │                                                      │  │
│  │  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐  │  │
│  │  │ ETW         │ │ AMSI Provider│ │ Hook DLL     │  │  │
│  │  │ Consumer    │ │ (akesoedr-   │ │ (akesoedr-   │  │  │
│  │  │             │ │  amsi.dll)   │ │  agent.dll)  │  │  │
│  │  └─────────────┘ └──────────────┘ └──────────────┘  │  │
│  │                                                      │  │
│  │  Telemetry → JSON log / \\.\pipe\AkesoTelemetry      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  akesoedr-cli.exe / akavscan.exe                       │  │
│  │  status | alerts | scan | rules | quarantine         │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

**Integration flow for on-access scanning:**

1. AkesoEDR minifilter intercepts IRP_MJ_CREATE or IRP_MJ_WRITE
2. Minifilter sends file event (path, PID, operation, file size, last-modified timestamp) to agent via filter communication port
3. Agent checks scan cache: if (path + last-modified + size) → cached clean result, skip scan
4. If cache miss or stale: agent calls `akav_scan_file()` on the file path (with 5-second timeout enforced via worker thread + cancellation)
5. Scan result cached. AV fields (av_detected, av_malware_name, av_heuristic_score, av_signature_id, av_scanner_id, av_file_type) merged into telemetry event
6. EDR rule engine evaluates combined behavioral + AV signals
7. If AV detects malware: immediate alert, optional quarantine action
8. Telemetry event written to JSON log and pipe

**Graceful degradation:** If akesoav.dll fails to load at akesoedr-agent.exe startup (missing DLL, version mismatch, signature verification failure), the EDR agent logs a warning and continues operating without AV scanning. All AV telemetry fields are set to their zero/empty defaults. The agent does not crash.

### 3.3 Scan Pipeline

```
File/Buffer Input
       │
       ▼
┌─────────────────┐
│ File Type        │ ── Magic byte detection: MZ (PE), 7F 45 4C 46 (ELF),
│ Detection        │    50 4B (ZIP), 1F 8B (GZIP), 25 50 44 46 (PDF),
│                  │    D0 CF 11 E0 (OLE2). Route to parser. Unknown → sig-only.
└───────┬─────────┘
        │
        ▼
┌─────────────────┐
│ Archive          │ ── If archive: extract entries, recurse each through
│ Extraction       │    pipeline (depth-limited, bomb-protected)
└───────┬─────────┘
        │
        ▼
┌─────────────────┐
│ Unpacking        │ ── If packed executable: UPX static unpack or
│ Engine           │    emulator-assisted generic unpack, re-scan result
└───────┬─────────┘
        │
        ▼
┌─────────────────┐     ┌─ Layer 1: Bloom filter (pre-filter)
│ Signature        │     ├─ Layer 2: MD5/SHA-256 hash match
│ Engine           │ ──  ├─ Layer 3: CRC32 region match
│ (layered)        │     ├─ Layer 4: Aho-Corasick byte-stream
└───────┬─────────┘     ├─ Layer 5: Fuzzy hash (ssdeep)
        │               ├─ Layer 6: Graph-based (CFG hash)
        │               └─ Layer 7: YARA rules
        ▼
┌─────────────────┐     ┌─ PE header analyzer
│ Heuristic        │     ├─ Entropy analyzer
│ Engine           │ ──  ├─ Import analyzer
│ (static)         │     ├─ String analyzer
└───────┬─────────┘     └─ ML classifier
        │
        ▼
┌─────────────────┐
│ Heuristic        │ ── Weight-based behavioral scoring from
│ Engine (dynamic) │    emulator API call log
└───────┬─────────┘
        │
        ▼
   Scan Result
```

**Pipeline error propagation model:** Each pipeline stage returns one of three outcomes: CLEAN (no detection, continue to next stage), DETECTED (malware found, short-circuit, populate result), or ERROR (parser failure). On ERROR: the failing stage is skipped, remaining stages continue on the raw file bytes, and the scan result includes `scan_warnings` indicating which stage failed. Only if ALL stages error does the result become AKAV_SCAN_ERROR. A parser crash (segfault/access violation caught by SEH) is treated as ERROR for that stage plus a heuristic penalty (+10 to score, since files that crash parsers are suspicious by nature).

### 3.4 Signature Database (.akavdb) Binary Format

```
Offset  Size     Field
──────  ───────  ─────────────────────────────────
0x0000  4        Magic: "SAV1" (0x53 0x41 0x56 0x31)
0x0004  4        Version: uint32_t (currently 1)
0x0008  4        SignatureCount: uint32_t (total across all sections)
0x000C  8        CreatedAt: int64_t (Unix epoch seconds)
0x0014  4        SectionCount: uint32_t
0x0018  256      RSA-2048 Signature (covers bytes 0x0000–0x0017 + all section data)

Section Offset Table (starts at 0x0118):
  Per section (SectionCount entries, 16 bytes each):
    0  4  SectionType: uint32_t (enum: 0=Bloom, 1=MD5, 2=SHA256, 3=CRC32,
                                       4=AhoCorasick, 5=FuzzyHash, 6=GraphSig,
                                       7=YARA, 8=Whitelist, 9–255=reserved)
    4  4  Offset: uint32_t (absolute byte offset from file start)
    8  4  Size: uint32_t (section size in bytes)
   12  4  EntryCount: uint32_t (number of signatures in section)

Section Data (follows offset table):
  [0] Bloom Filter: raw bitfield (size = ceil(bits/8))
  [1] MD5 Table: sorted array of {uint8_t md5[16]; uint32_t name_index;}
  [2] SHA256 Table: sorted array of {uint8_t sha256[32]; uint32_t name_index;}
  [3] CRC32 Sigs: array of {uint8_t region_type; uint32_t offset; uint32_t length;
                              uint32_t expected_crc; uint32_t name_index;}
  [4] Aho-Corasick: serialized automaton (implementation-defined binary blob)
  [5] Fuzzy Hash: array of {uint16_t block_size; char hash[128]; uint32_t name_index;}
  [6] Graph Sigs: array of {uint32_t block_hash_count; uint32_t* block_hashes;
                              uint32_t name_index;} (variable length)
  [7] YARA: compiled YARA rules blob (yr_rules_save_stream format)
  [8] Whitelist: sorted array of {uint8_t sha256[32];}

String Table (follows last section):
  Offset: stored as last entry in section offset table (type=0xFF)
  Format: null-terminated UTF-8 strings packed sequentially
  Lookup: name_index = byte offset from string table start
```

### 3.5 Standalone Service Protocol

Named pipe `\\.\pipe\AkesoAVScan`:

```
Client connects       → Server: "220 AKESOAV READY\r\n"
Client: "SCAN <path>" → Server: "210 SCAN DATA\r\n"
                         Server: "<path>\t<malware_name>\t<sig_id>\t<score>\r\n" (per finding)
                         Server: "200 SCAN OK\r\n"
Client: "VERSION"      → Server: "220 AkesoAV <version> DB:<db_version>\r\n"
Client: "RELOAD"       → Server: "220 RELOAD OK\r\n" (remap signature database)
Client: "STATS"        → Server: "220 <files_scanned> <malware_found> <cache_hits> <uptime_s>\r\n"
Client: "PING"         → Server: "220 PONG\r\n"
Client: "QUIT"         → Server closes connection
Error:                   Server: "500 <error_message>\r\n"
```

### 3.6 Telemetry Integration

When integrated with AkesoEDR, scan results add these fields to the existing telemetry event envelope (§3.2 of AkesoEDR spec):

```json
{
  "av_detected": true,
  "av_malware_name": "Win32.Cobalt.Beacon",
  "av_signature_id": "bytestream-4821",
  "av_scanner_id": "aho_corasick",
  "av_heuristic_score": 85.0,
  "av_file_type": "PE32",
  "av_scan_cached": false,
  "av_scan_time_ms": 142,
  "av_scan_warnings": []
}
```

### 3.7 AkesoSIEM Telemetry

AkesoAV ships events to AkesoSIEM for centralized detection, correlation, and investigation. The SIEM owns the ingestion contract (defined in AkesoSIEM Requirements v2.4 §4.4). AkesoAV conforms to that contract.

**Transport:** HTTP POST to `{siem_url}/api/v1/ingest` as NDJSON (newline-delimited JSON, one event per line, UTF-8, no BOM). Authentication via `X-API-Key` header. API key configured in AkesoAV config (`HKLM\SOFTWARE\Akeso\AV\SiemApiKey` or akeso.conf). TLS optional for v1 lab environments.

**Batching:** Events buffered in a ring buffer (capacity 1000). Flushed to SIEM every 5 seconds or when buffer reaches 100 events, whichever comes first. If SIEM is unreachable, events accumulate in ring buffer. Buffer full → oldest events dropped with `av:event_dropped` counter incremented in STATS.

**Standalone vs. Integrated mode:**
- **Standalone** (akesoav-service.exe): The service itself ships events to the SIEM. Configure `siem_url` in config. Events are also written to a local JSONL log file (`%ProgramData%\Akeso\Logs\akesoav.jsonl`, 100MB rotation, 7-day retention).
- **Integrated** (akesoav.dll in EDR agent): AV events are emitted through the EDR agent's existing SIEM shipper. The AV fields are merged into the EDR telemetry event (§3.6) AND the engine emits standalone AV events (§3.7.1–3.7.5) through a callback the EDR agent registers. This ensures the SIEM receives both the enriched EDR+AV event and the dedicated AV event types for Sigma rule compatibility.

**Common envelope** (per AkesoSIEM v2.4 §2):

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-03-14T15:30:00.456Z",
  "source_type": "akeso_av",
  "event_type": "<see below>",
  "agent_id": "WORKSTATION-042",
  "agent_version": "1.0.0",
  "host": {
    "name": "WORKSTATION-042",
    "ip": ["10.0.1.42"],
    "os": { "name": "Windows", "version": "10.0.19045", "platform": "windows" }
  },
  "payload": { }
}
```

#### 3.7.1 `av:scan_result`

Emitted on detection (clean results not forwarded by default; configurable).

```json
{
  "...common envelope...",
  "event_type": "av:scan_result",
  "payload": {
    "scan": {
      "result": "malicious",
      "scanner_id": "akesoav-service",
      "scan_type": "on_access",
      "heuristic_score": 0.92,
      "duration_ms": 145
    },
    "signature": {
      "name": "Win32.Trojan.Mimikatz.A",
      "id": "sig-00482a",
      "engine": "byte_stream",
      "db_version": "2026031401"
    },
    "file": {
      "path": "C:\\Users\\jsmith\\Downloads\\payload.exe",
      "name": "payload.exe",
      "type": "PE32",
      "size": 245760,
      "hash": {
        "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        "md5": "098f6bcd4621d373cade4e832627b4f6"
      },
      "in_whitelist": false
    },
    "process": {
      "pid": 2048,
      "name": "chrome.exe",
      "executable": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
    }
  }
}
```

Field notes: `scan.result` values: malicious, suspicious, clean, error. `scan.scanner_id`: akavscan, akesoav-service, realtime, edr_integrated. `scan.scan_type`: on_demand, on_access, memory. `signature.engine`: hash_md5, hash_sha256, crc32, byte_stream, fuzzy_hash, graph, yara, heuristic. `process` populated only for on_access/memory scans.

**ECS mapping** (applied by SIEM parser): `event.category: malware`, `event.type: info`, `file.*`, `file.hash.*`, `threat.indicator.type: file`, `av.scan.result`, `av.signature.name`

#### 3.7.2 `av:quarantine`

Emitted when a file is quarantined.

```json
{
  "...common envelope...",
  "event_type": "av:quarantine",
  "payload": {
    "quarantine": {
      "action": "quarantined",
      "vault_id": "q-2026031401-0042",
      "original_path": "C:\\Users\\jsmith\\Downloads\\payload.exe",
      "restore_available": true
    },
    "signature": { "name": "Win32.Trojan.Mimikatz.A", "id": "sig-00482a" },
    "file": {
      "path": "C:\\Users\\jsmith\\Downloads\\payload.exe",
      "name": "payload.exe",
      "size": 245760,
      "hash": { "sha256": "b94d27b9..." }
    }
  }
}
```

**ECS mapping:** `event.category: malware`, `event.type: deletion`, `event.action: quarantine`, `file.*`

#### 3.7.3 `av:realtime_block`

Emitted when the minifilter (via EDR) or standalone monitor blocks file access.

```json
{
  "...common envelope...",
  "event_type": "av:realtime_block",
  "payload": {
    "block": { "operation": "file_create", "denied": true },
    "signature": { "name": "Win32.Trojan.Mimikatz.A", "id": "sig-00482a" },
    "file": { "path": "...", "name": "...", "size": 245760, "hash": { "sha256": "..." } },
    "process": { "pid": 2048, "name": "chrome.exe", "executable": "..." }
  }
}
```

**ECS mapping:** `event.category: malware`, `event.type: denied`, `process.*`, `file.*`

#### 3.7.4 `av:signature_update`

Emitted when signature database is updated.

```json
{
  "...common envelope...",
  "event_type": "av:signature_update",
  "payload": {
    "update": {
      "previous_version": "2026031301",
      "new_version": "2026031401",
      "signature_count": 485230,
      "delta_added": 142,
      "delta_removed": 3,
      "update_source": "https://updates.akesoav.local/signatures",
      "verification": "rsa_verified"
    }
  }
}
```

**ECS mapping:** `event.category: configuration`, `event.type: change`, `event.action: signature_update`

#### 3.7.5 `av:scan_error`

Emitted on scan failure (timeout, parser crash, resource limit).

```json
{
  "...common envelope...",
  "event_type": "av:scan_error",
  "payload": {
    "error": {
      "reason": "timeout",
      "detail": "Scan exceeded 30000ms limit",
      "stage": "pe_parser"
    },
    "file": { "path": "...", "name": "...", "size": 524288000 }
  }
}
```

**ECS mapping:** `event.category: malware`, `event.type: error`, `event.outcome: failure`, `error.message`

#### 3.7.7 `av:scheduled_scan_start`

Emitted when a scheduled scan begins.

```json
{
  "...common envelope...",
  "event_type": "av:scheduled_scan_start",
  "payload": {
    "schedule": {
      "name": "Weekly Full Scan",
      "type": "full",
      "paths": ["C:\\"],
      "trigger": "cron"
    }
  }
}
```

**ECS mapping:** `event.category: process`, `event.type: start`, `event.action: scheduled_scan_start`

#### 3.7.8 `av:scheduled_scan_complete`

Emitted when a scheduled scan finishes.

```json
{
  "...common envelope...",
  "event_type": "av:scheduled_scan_complete",
  "payload": {
    "schedule": {
      "name": "Weekly Full Scan",
      "type": "full",
      "paths": ["C:\\"],
      "trigger": "cron"
    },
    "result": {
      "files_scanned": 142385,
      "detections": 2,
      "errors": 1,
      "duration_ms": 3845200,
      "cache_hits": 98412,
      "bytes_scanned": 48291045376
    }
  }
}
```

**ECS mapping:** `event.category: process`, `event.type: end`, `event.action: scheduled_scan_complete`

#### 3.7.6 Local Log Output

In addition to SIEM shipping, all events are written to a local JSONL file for offline analysis and forensics.

| Aspect | Specification |
|---|---|
| Path | `%ProgramData%\Akeso\Logs\akesoav.jsonl` |
| Format | NDJSON (one JSON object per line, UTF-8, no BOM) |
| Rotation | 100MB per file, rotate to `akesoav.1.jsonl` through `akesoav.5.jsonl` |
| Retention | 7 days default (configurable) |
| Content | All 5 event types, same JSON format as SIEM-shipped events |
| Integrated mode | EDR agent's JSON writer handles logging; AV events flow through EDR log pipeline |

## 4. Public C API (akesoav.h)

This is the complete contract. All implementation tasks reference this header.

```c
#ifndef AKESOAV_H
#define AKESOAV_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DLL export/import */
#ifdef AKAV_BUILD_DLL
  #define AKAV_API __declspec(dllexport)
#else
  #define AKAV_API __declspec(dllimport)
#endif

/* ── Opaque handles ── */
typedef struct akav_engine akav_engine_t;

/* ── Error codes ── */
typedef enum {
    AKAV_OK                = 0,
    AKAV_ERROR             = -1,   /* Generic error */
    AKAV_ERROR_INVALID     = -2,   /* Invalid parameter or malformed input */
    AKAV_ERROR_NOMEM       = -3,   /* Allocation failure */
    AKAV_ERROR_IO          = -4,   /* File I/O error */
    AKAV_ERROR_DB          = -5,   /* Signature database error (corrupt, bad sig, version) */
    AKAV_ERROR_TIMEOUT     = -6,   /* Per-file scan timeout exceeded */
    AKAV_ERROR_SIGNATURE   = -7,   /* RSA signature verification failed */
    AKAV_ERROR_NOT_INIT    = -8,   /* Engine not initialized */
    AKAV_ERROR_BOMB        = -9,   /* Decompression bomb detected */
    AKAV_ERROR_SCAN        = -10,  /* Scan-stage error (parser crash, partial failure) */
} akav_error_t;

/* ── Heuristic level ── */
typedef enum {
    AKAV_HEUR_OFF    = 0,
    AKAV_HEUR_LOW    = 1,   /* Score > 100 = suspicious */
    AKAV_HEUR_MEDIUM = 2,   /* Score > 75  = suspicious */
    AKAV_HEUR_HIGH   = 3,   /* Score > 50  = suspicious */
} akav_heur_level_t;

/* ── Scan options ── */
typedef struct {
    int              scan_archives;       /* Recurse into ZIP/GZIP/TAR/OLE2/OOXML     */
    int              scan_packed;         /* Attempt UPX / emulator-assisted unpacking  */
    int              use_heuristics;      /* Enable static + dynamic heuristic engine   */
    akav_heur_level_t heuristic_level;     /* Sensitivity threshold                      */
    int64_t          max_filesize;        /* Skip files larger than this (bytes, 0=no limit) */
    int              max_scan_depth;      /* Archive recursion depth limit (default 10) */
    int              timeout_ms;          /* Per-file scan timeout in ms (default 30000) */
    int              scan_memory;         /* Reserved for v2 memory scanning             */
    int              use_cache;           /* Check/update scan cache (default 1)         */
    int              use_whitelist;       /* Skip whitelisted files (default 1)          */
} akav_scan_options_t;

/* ── Scan result ── */
#define AKAV_MAX_MALWARE_NAME  256
#define AKAV_MAX_SIG_ID         64
#define AKAV_MAX_SCANNER_ID     64
#define AKAV_MAX_FILE_TYPE      32
#define AKAV_MAX_WARNINGS        8
#define AKAV_MAX_WARNING_LEN   128

typedef struct {
    int              found;                                /* 1 = malware detected          */
    char             malware_name[AKAV_MAX_MALWARE_NAME];   /* Detection name                */
    char             signature_id[AKAV_MAX_SIG_ID];         /* Matched signature identifier  */
    char             scanner_id[AKAV_MAX_SCANNER_ID];       /* Engine layer that matched     */
    char             file_type[AKAV_MAX_FILE_TYPE];         /* Detected format (PE32, ELF, etc) */
    double           heuristic_score;                      /* Combined heuristic score      */
    uint32_t         crc1;                                 /* Primary CRC (debug/analysis)  */
    uint32_t         crc2;                                 /* Secondary CRC                 */
    int              in_whitelist;                          /* 1 = file is whitelisted       */
    int64_t          total_size;                            /* File total size               */
    int64_t          scanned_size;                          /* Bytes actually analyzed        */
    int              cached;                                /* 1 = result served from cache  */
    int              scan_time_ms;                          /* Wall-clock scan time           */
    int              warning_count;                         /* Number of pipeline warnings   */
    char             warnings[AKAV_MAX_WARNINGS][AKAV_MAX_WARNING_LEN]; /* Stage error descriptions */
} akav_scan_result_t;

/* ── Engine lifecycle ──
 * Thread safety: akav_engine_create/init/destroy are NOT thread-safe (call from one thread).
 * akav_scan_file, akav_scan_buffer, akav_scan_directory ARE thread-safe after init completes.
 * The signature database is mapped read-only and shared across threads.
 * Each scan call allocates its own Aho-Corasick walk state on the stack (no shared mutable state).
 * akav_engine_load_signatures acquires an internal write lock — concurrent scans will block briefly
 * during reload, then resume with the new database.
 */
AKAV_API akav_error_t akav_engine_create(akav_engine_t **engine);
AKAV_API akav_error_t akav_engine_init(akav_engine_t *engine, const char *config_path);
AKAV_API akav_error_t akav_engine_load_signatures(akav_engine_t *engine, const char *db_path);
AKAV_API akav_error_t akav_engine_destroy(akav_engine_t *engine);

/* ── Scanning (thread-safe after init) ── */
AKAV_API akav_error_t akav_scan_file(akav_engine_t *engine, const char *path,
                                   const akav_scan_options_t *opts, akav_scan_result_t *result);
AKAV_API akav_error_t akav_scan_buffer(akav_engine_t *engine, const uint8_t *buf, size_t len,
                                     const char *name, const akav_scan_options_t *opts,
                                     akav_scan_result_t *result);

/* ── Directory scanning (callback, thread-safe) ── */
typedef void (*akav_scan_callback_t)(const char *path, const akav_scan_result_t *result,
                                     void *user_data);
AKAV_API akav_error_t akav_scan_directory(akav_engine_t *engine, const char *path,
                                        const akav_scan_options_t *opts,
                                        akav_scan_callback_t callback, void *user_data);

/* ── Cache management ── */
AKAV_API akav_error_t akav_cache_clear(akav_engine_t *engine);
AKAV_API akav_error_t akav_cache_stats(akav_engine_t *engine, uint64_t *hits, uint64_t *misses,
                                     uint64_t *entries);

/* ── Whitelist management ── */
AKAV_API akav_error_t akav_whitelist_add_hash(akav_engine_t *engine, const uint8_t sha256[32]);
AKAV_API akav_error_t akav_whitelist_add_path(akav_engine_t *engine, const char *path_prefix);
AKAV_API akav_error_t akav_whitelist_add_signer(akav_engine_t *engine, const char *signer_name);
AKAV_API akav_error_t akav_whitelist_clear(akav_engine_t *engine);

/* ── Info ── */
AKAV_API const char* akav_engine_version(void);
AKAV_API const char* akav_db_version(akav_engine_t *engine);
AKAV_API const char* akav_strerror(akav_error_t err);

/* ── Update ── */
AKAV_API akav_error_t akav_update_signatures(akav_engine_t *engine, const char *update_url);

/* ── SIEM event shipping ── */
typedef struct {
    char event_id[64];             /* UUID v4 string                           */
    char timestamp[32];            /* ISO 8601 with ms: "2026-03-14T15:30:00.456Z" */
    char source_type[32];          /* Always "akeso_av"                     */
    char event_type[32];           /* av:scan_result, av:quarantine, etc.      */
    char agent_id[128];            /* Hostname                                 */
    char payload_json[8192];       /* JSON-serialized payload (§3.7.1–3.7.5)  */
} akav_siem_event_t;

typedef void (*akav_siem_callback_t)(const akav_siem_event_t *event, void *user_data);

/* Register callback invoked on every emittable event. In integrated mode, the
 * EDR agent registers this to route AV events through its own SIEM shipper.
 * In standalone mode, akesoav-service.exe registers its own HTTP+JSONL shipper.
 * Passing NULL disables SIEM output. */
AKAV_API akav_error_t akav_set_siem_callback(akav_engine_t *engine,
                                           akav_siem_callback_t callback,
                                           void *user_data);

/* Built-in HTTP shipper for standalone mode. Ships NDJSON to the configured
 * SIEM endpoint via WinHTTP. Call after init. Starts background flush thread. */
AKAV_API akav_error_t akav_siem_start_http_shipper(akav_engine_t *engine,
                                                  const char *siem_url,
                                                  const char *api_key);
AKAV_API akav_error_t akav_siem_stop_http_shipper(akav_engine_t *engine);

/* ── Scheduled scanning ── */
AKAV_API akav_error_t akav_schedule_load(akav_engine_t *engine, const char *config_path);
AKAV_API akav_error_t akav_schedule_start(akav_engine_t *engine);   /* Start scheduler thread */
AKAV_API akav_error_t akav_schedule_stop(akav_engine_t *engine);    /* Stop scheduler thread */
AKAV_API akav_error_t akav_schedule_run_now(akav_engine_t *engine, const char *schedule_name);
AKAV_API akav_error_t akav_schedule_status(akav_engine_t *engine,
                                         int *active,            /* 1 if scan running */
                                         int *progress_pct,      /* 0-100 estimated */
                                         int64_t *files_scanned,
                                         int *detections);

/* ── Defaults ── */
AKAV_API void akav_scan_options_default(akav_scan_options_t *opts);

#ifdef __cplusplus
}
#endif

#endif /* AKESOAV_H */
```

## 5. Engine Component Requirements

### 5.1 File Type Detection

The first pipeline stage identifies the file format by reading magic bytes at offset 0 via SafeReader. No file extension is trusted — detection is content-based only.

| Magic Bytes | Format | Parser |
|---|---|---|
| `4D 5A` (MZ) | PE (DOS MZ header) | PE parser → validate PE signature at e_lfanew |
| `7F 45 4C 46` (.ELF) | ELF | ELF parser |
| `50 4B 03 04` or `50 4B 05 06` | ZIP (includes OOXML, JAR, DOCX) | ZIP parser → check for OOXML markers |
| `1F 8B` | GZIP | GZIP parser |
| `25 50 44 46` (%PDF) | PDF | PDF parser |
| `D0 CF 11 E0 A1 B4 1A E1` | OLE2 (DOC, XLS, PPT) | OLE2 parser |
| `75 73 74 61 72` at offset 257 | TAR (ustar) | TAR parser |
| No match | Unknown | Signature engine only (byte-stream, hash, YARA). No parser-based analysis. |

### 5.2 Signature Engine (Ch. 4)

| Aspect | Requirement |
|---|---|
| Layer 1: Bloom Filter | Probabilistic pre-filter. Configurable size + hash count (double hashing: murmur3 + fnv1a). FP allowed, FN not. Serializable for .akavdb. |
| Layer 2: Crypto Hash | MD5 + SHA-256 exact match. Sorted arrays, binary search O(log n). Windows CNG BCryptHash. |
| Layer 3: CRC32 | Standard IEEE polynomial + custom variant (modified polynomial table). Region-based: whole file, first/last N bytes, PE section content. |
| Layer 4: Byte-Stream | Aho-Corasick multi-pattern. Handles null bytes. Compiled automaton serialized in .akavdb. Walk state is stack-allocated per scan (thread-safe). |
| Layer 5: Fuzzy Hash | ssdeep-compatible piecewise hashing. Similarity scoring (0–100). Configurable block size. |
| Layer 6: Graph-Based | Basic block hashing from x86 decoder. Opcode-only hash per block (ignore operand values). Sorted block hashes → graph hash. Similarity metric via set intersection. |
| Layer 7: YARA | libyara static integration. Compile + match. Hot-reload via akav_engine_load_signatures. |
| Pipeline | Layered cheapest-to-most-expensive. Bloom short-circuits definite negatives. Database mapped read-only. Zero heap allocation on signature match hot path. |
| Signature Sources | ClamAV import (.hdb/.ndb), community YARA rules (Florian Roth signature-base, Elastic, YARA-Rules repo), hand-crafted test signatures, weekly blog detection content. |
| Test evasions | Single-byte mod (bypasses L2, not L4/L5). Packing (bypasses L2–L4, not unpacker+rescan). Instruction reorder (bypasses L4, not L6). |

### 5.3 Scan Cache

| Aspect | Requirement |
|---|---|
| Key | (file_path, last_modified_timestamp, file_size) → SHA-256 computed lazily. |
| Value | akav_scan_result_t (full cached result). |
| Implementation | Hash map (std::unordered_map) protected by SRWLOCK. Reader-writer pattern: scans acquire shared read; cache updates acquire exclusive write. |
| Invalidation | Entry invalidated when file's last-modified timestamp or size changes. Cache cleared on signature database reload (new signatures may change verdicts). Explicit clear via akav_cache_clear(). |
| Capacity | Configurable max entries (default 50,000). LRU eviction when capacity reached. |
| Scope | Per-engine instance. In integrated mode, shared across all agent threads. |
| Stats | Hit/miss counters exposed via akav_cache_stats() and STATS protocol command. |

### 5.4 Whitelist / Exclusion Mechanism

| Aspect | Requirement |
|---|---|
| Hash Whitelist | SHA-256 hashes of known-clean files. Stored in .akavdb whitelist section + runtime additions via akav_whitelist_add_hash(). Checked after file hash computation (Layer 2). If whitelisted: result.in_whitelist=1, skip all remaining stages. |
| Path Exclusions | Prefix-based path exclusions. Default: skip files under engine's own installation directory. Configurable via config file and akav_whitelist_add_path(). Checked before any file I/O. |
| Signer Trust | Skip files with valid Authenticode signatures from trusted publishers. Configurable trusted signer list. Checked via WinVerifyTrust. Default trusted: "Microsoft Corporation", "Microsoft Windows". |
| Pipeline Position | Path exclusion checked first (before file read). Then hash whitelist (after SHA-256 computation). Then signer trust (if Authenticode present). Any match → short-circuit as clean. |

### 5.5 File Format Parsers (Ch. 1, 3)

| Aspect | Requirement |
|---|---|
| Safety | All reads through SafeReader. No raw pointer arithmetic. Integer overflow checks before all size arithmetic. Per-parser timeout. MSVC /analyze with SAL annotations. Continuous fuzzing via clang-cl + libFuzzer. |
| PE (Phase 2) | DOS→PE sig→COFF→optional header (PE32/PE32+)→sections→imports→exports→resources→overlay→rich header→debug dir→Authenticode certs. Per-section entropy. |
| ELF (Phase 7) | Header (32/64, LE/BE), sections, segments, symbols, dynamic, notes. |
| ZIP/GZIP/TAR (Phase 3) | Recursive extraction. Bomb detection (ratio/size/depth/count limits). zlib for inflate. |
| PDF (Phase 7) | Xref, streams with filter chains (Flate/ASCII85/Hex/LZW), JS extraction (/JS, /JavaScript), embedded files. |
| OLE2 (Phase 7) | FAT/DIFAT chain traversal with loop detection. Streams. VBA decompression (MS-OVBA). |
| OOXML (Phase 10) | ZIP-based. vbaProject.bin → OLE2. Embedded files from media/embeddings. |
| Anti-DoS | Max decompressed 100MB. Max depth 10. Timeout 30s. Ratio 100:1. Max files 10,000. |

### 5.6 Heuristic Engine — Static (Ch. 3)

| Aspect | Requirement |
|---|---|
| PE Header | Entry point outside .text (+15). W+X sections (+20/ea). Packer section names .UPX0/.aspack/.themida (+25). <3 import DLLs (+10). Zero imports (+20). Timestamp >future or <1990 or ==0 (+10). Checksum mismatch (+5). Overlay present with entropy >7.0 (+15). |
| Entropy | Per-section Shannon. .text >7.0 → packed (+20). .text <1.0 → XOR-encoded (+15). Overall >7.5 → suspicious (+10). |
| Imports | VirtualAlloc+WriteProcessMemory+CreateRemoteThread (+35). VirtualAlloc+VirtualProtect(RX)+CreateThread (+25). CreateService+StartService (+20). RegSetValueEx with Run key string (+15). Ordinal-only all imports (+15). Only GetProcAddress+LoadLibrary (+25, API hashing indicator). |
| Strings | cmd.exe (+5), powershell.exe (+10), WScript.Shell (+10), CurrentVersion\Run (+15), http:// or https:// (+5/ea), IP address pattern (+5/ea), base64 blob >100 chars (+10). Configurable JSON weights file. |
| ML Classifier | Random Forest trained on PE feature vectors (Python/scikit-learn). Features: section count, section entropies, import count, suspicious API presence bits, timestamp, overlay size, file size, rich header presence. Exported as JSON decision tree array. C++ inference: walk tree, output probability 0.0–1.0. Score contribution: probability × 50 (so ML alone can push score to +50 at high confidence). |
| Scoring | Weighted sum across all analyzers. Threshold per level: Low (>100), Medium (>75), High (>50). If exceeded and no signature match: result.found=1, malware_name="Heuristic.Suspicious.<top_category>". |

### 5.7 Heuristic Engine — Dynamic (Ch. 3)

Scores API call sequences observed during x86 emulation. Runs only when scan_packed=1 and the emulator was invoked.

**Behavior Scoring Table (default weights, configurable via JSON):**

| Emulated API Call / Pattern | Weight | Category |
|---|---|---|
| GetModuleHandle (self) | -5 | Benign |
| GetSystemInfo | -3 | Benign |
| VirtualAlloc (any) | +5 | Allocation |
| VirtualAlloc (PAGE_EXECUTE_READWRITE) | +15 | Suspicious RWX |
| VirtualProtect (RW → RX transition) | +15 | Shellcode pattern |
| VirtualAlloc + memcpy-like write + VirtualProtect(RX) | +30 | Injection chain |
| VirtualAlloc(RWX) + write + jump-to-allocated | +35 | Classic shellcode |
| LoadLibrary on suspicious DLL name | +10 | Suspicious load |
| GetProcAddress in tight loop (>10 calls) | +20 | API hashing |
| Write to region then EIP transfer to that region | +25 | Unpacking / shellcode |
| INT 3 or invalid opcode exception | +5 | Anti-debug / anti-emu |
| >1M instructions without API call | -10 | Likely legitimate computation |

**Score combination:** Dynamic score is added to static heuristic score. Combined score checked against threshold. If emulation was not performed (scan_packed=0 or file not a PE), dynamic score is 0.

### 5.8 x86 Emulator (Ch. 3)

| Aspect | Requirement |
|---|---|
| Architecture | x86 32-bit. Flat memory model. Instruction decoder + execution engine. |
| Instructions | MOV, PUSH, POP, LEA, XCHG, MOVZX/SX, ADD, SUB, IMUL, MUL, IDIV, DIV, INC, DEC, NEG, CDQ, AND, OR, XOR, NOT, SHL/SHR/SAR, ROL/ROR, TEST, CMP, JMP, Jcc (all conditions), CALL, RET, LOOP/LOOPcc, NOP, MOVS/STOS/LODS/CMPS/SCAS+REP/REPZ/REPNZ, ENTER, LEAVE, INT3, RDTSC, CPUID. |
| Environment | PE sections mapped at ImageBase. Stack (1MB, grows down). TEB/PEB stubs at fs:[0x30] (IsDebuggerPresent=0, NtGlobalFlag=0). 2M instruction limit. |
| API Stubs | LoadLibraryA/W→fake base. GetProcAddress→fake export. VirtualAlloc→allocate from emulator heap, mark RWX. VirtualProtect→update page perms. GetModuleHandleA/W→image base. GetSystemInfo→plausible SYSTEM_INFO. |
| Anti-Emulation | RDTSC: monotonic increments (counter×1000). CPUID: "GenuineIntel", family/model for Pentium. Basic SEH chain (fs:[0] handler dispatch). |

### 5.9 Unpacker Engine (Ch. 3)

| Aspect | Requirement |
|---|---|
| UPX Static | Detect by section names (UPX0/UPX1) or UPX magic in overlay. NRV2B/NRV2D/NRV2E or LZMA decompression. IAT rebuild from packed stub. OEP restore. Output: unpacked PE bytes → re-scan through full pipeline. |
| XOR/ADD Static | Detect loop-XOR at entry point (XOR [mem],reg; INC/ADD ptr; CMP; JNZ pattern). Extract key byte + decode length. Decode in-place copy. Re-scan. |
| Generic (Emulator) | Load packed PE into emulator. Execute. Detect: write of >4KB to contiguous region, followed by EIP transfer (JMP/CALL) to that region. Dump target region. Validate as PE (check MZ+PE sig). Re-scan through full pipeline. If dump is not valid PE, scan as raw buffer. |

### 5.10 Update System (Ch. 5)

| Aspect | Requirement |
|---|---|
| Transport | HTTPS via WinHTTP (or SChannel). TLS 1.2+. Certificate pinning: embedded SHA-256 fingerprint of expected server cert, verified during TLS handshake callback. |
| Manifest | JSON: version (uint32), published_at (ISO 8601), minimum_engine_version, files[] array with name/url/sha256/rsa_signature/size/type(full or delta), manifest_signature (RSA sig covering all fields except itself). |
| Verification | SHA-256 of downloaded files via CNG BCryptHash. RSA-2048 signature via CNG BCryptVerifySignature. Public key embedded in akesoav.dll at compile time (no TOFU). |
| Installation | Write to .akavdb.new. Verify. MoveFileEx(MOVEFILE_REPLACE_EXISTING) for atomic swap. Keep .akavdb.prev for rollback. Send RELOAD to service or call akav_engine_load_signatures() in integrated mode. |
| Distribution | Git-based: akavdb-tool compiles from Git repo. akesoedr-cli rules update pulls, validates, recompiles. Same repo as EDR YAML rules. |

### 5.11 Self-Protection

| Aspect | Requirement |
|---|---|
| Standalone Service | Set service security descriptor to deny PROCESS_TERMINATE from non-admin. Set DACL on service process handle. |
| Integrated | Inherits AkesoEDR ObRegisterCallbacks protection (akesoedr-drv.sys strips PROCESS_TERMINATE/VM_WRITE from non-protected callers targeting akesoedr-agent.exe PID). |
| File Integrity | WinVerifyTrust Authenticode check on akesoav.dll and all plugins at load time. SHA-256 hash of all engine files computed at startup, stored in memory, re-checked on configurable interval (default 60s). |
| Watchdog (standalone) | Separate watchdog.exe process. Named pipe PING/PONG heartbeat (5s interval, 15s timeout). Auto-restart via CreateProcess on crash or hang. |
| Config | HKLM\SOFTWARE\Akeso\AV with restricted ACL (SYSTEM + Administrators). |

### 5.12 Quarantine System

| Aspect | Requirement |
|---|---|
| Vault | %ProgramData%\Akeso\Quarantine\vault\<random_id>.sqz |
| Encryption | AES-256-GCM via CNG BCryptEncrypt. Per-installation key from DPAPI (CryptProtectData with machine scope). |
| Index | SQLite: quarantine.db with columns (id TEXT PK, original_path TEXT, malware_name TEXT, signature_id TEXT, timestamp INTEGER, sha256 TEXT, file_size INTEGER, user_sid TEXT). |
| Operations | Quarantine: encrypt + move + index. Restore: decrypt + write to original or specified path + remove index entry. List: query index. Delete: remove .sqz + index entry. Purge: delete entries older than N days. |
| ACL | Vault directory: SYSTEM + Administrators only. Quarantined files stripped of all execute permissions. |
| CLI | akavscan --quarantine list/restore/delete/purge. akesoedr-cli quarantine list/restore/delete/purge. |

### 5.13 Scheduled Scanning

The standalone service (akesoav-service.exe) includes a built-in scheduler for recurring automated scans. In integrated mode, the EDR agent can invoke scheduled scans via the C API on its own timer.

| Aspect | Requirement |
|---|---|
| Schedule Config | JSON config file (`%ProgramData%\Akeso\schedules.json`) or registry key (`HKLM\SOFTWARE\Akeso\AV\Schedules`). Array of schedule entries. Hot-reloadable via RELOAD command. |
| Schedule Entry | `{ "name": "Weekly Full", "type": "full", "paths": ["C:\\"], "cron": "0 2 * * 0", "enabled": true }` — name, scan type, target paths, cron expression (minute hour day month weekday), enabled flag. |
| Scan Types | **Quick Scan:** Targets high-risk paths only — %TEMP%, %USERPROFILE%\Downloads, %APPDATA%, %PROGRAMDATA%, C:\Windows\Startup, C:\Users\*\AppData\Local\Temp. Completes in minutes. **Full Scan:** All fixed drives (GetLogicalDriveStrings, DRIVE_FIXED). Excludes configured path exclusions (§5.4). May take hours. **Custom Scan:** Arbitrary path list from config. |
| I/O Throttling | Scheduled scans run at below-normal I/O priority via `SetThreadPriority(THREAD_MODE_BACKGROUND_BEGIN)` to avoid impacting the user. CPU affinity limited to 50% of available cores (configurable). Scan pauses if system is on battery power (GetSystemPowerStatus). Resumes on AC power. |
| Concurrency | Only one scheduled scan runs at a time. If a scan is already in progress when the next schedule triggers, the new scan is skipped and logged. On-access scans from the minifilter are not affected — they run concurrently in the normal thread pool. |
| Progress | Scan progress tracked: files scanned, files remaining (estimated from directory enumeration), elapsed time, detections so far. Exposed via STATS command (`scheduled_scan_active`, `scheduled_scan_progress`). |
| Completion | On completion, emit `av:scheduled_scan_complete` event to SIEM (§3.7.7) with summary: scan type, paths, files scanned, detections, duration, errors. If detections found, also emit individual `av:scan_result` events per detection. |
| CLI | `akavscan --schedule list` (show configured schedules), `akavscan --schedule run <name>` (trigger a named schedule immediately), `akavscan --schedule next` (show next scheduled scan time). `akesoedr-cli scan schedule list/run/next`. |
| Default Schedules | Install script (P10-T5) creates two default schedules: Quick Scan daily at 12:00 (noon), Full Scan weekly Sunday at 02:00. Both enabled by default. |

## 6. Integration Test Plan

| # | Scenario | Input | Expected Detection |
|---|---|---|---|
| 1 | EICAR direct | eicar.com.txt | Byte-stream: "EICAR-Test-Signature" |
| 2 | EICAR in ZIP | eicar.zip | Archive extraction → match |
| 3 | EICAR nested ZIP | eicar_nested.zip | Recursive depth 2 → match |
| 4 | EICAR in GZIP | eicar.gz | Decompress → match |
| 5 | MD5-signatured PE | known_malware.exe | Layer 2 hash match |
| 6 | CRC-signatured PE | variant_malware.exe | Layer 3 CRC match |
| 7 | Byte-stream PE | custom_malware.exe | Layer 4 Aho-Corasick |
| 8 | Fuzzy hash variant | modified_malware.exe | Layer 5 similarity >80 |
| 9 | UPX-packed PE | upx_packed.exe | UPX unpack → sig match |
| 10 | XOR-packed PE | xor_packed.exe | Emulator unpack → sig match |
| 11 | PE injection imports | injection_tool.exe | Heuristic import +35 |
| 12 | PE high entropy .text | packed_suspicious.exe | Heuristic entropy +20 |
| 13 | PDF with JS | exploit.pdf | JS extracted → string/YARA |
| 14 | OLE2 with VBA | macro_doc.doc | VBA extracted → string analysis |
| 15 | Clean PE (calc.exe) | calc.exe | No detection. Score 0. |
| 16 | Clean system32 sweep | C:\Windows\System32\*.dll | Zero false positives |
| 17 | Whitelisted PE | MS-signed clean.exe | in_whitelist=1, no scan stages run |
| 18 | Excluded path | File in excluded directory | No scan performed |
| 19 | Zip bomb | 42.zip | AKAV_ERROR_BOMB. No OOM. |
| 20 | Truncated PE | truncated.exe | warnings[] populated. No crash. Remaining stages run. |
| 21 | Standalone service | SCAN via named pipe | Correct result |
| 22 | Scan cache hit | Re-scan unchanged file | cached=1, scan_time_ms ≈ 0 |
| 23 | Cache invalidation | Modify file, re-scan | cached=0, fresh scan |
| 24 | EDR integrated scan | EICAR drop via minifilter | av_detected in EDR telemetry |
| 25 | Signature update | Test HTTPS server | New .akavdb active. Cache cleared. |
| 26 | Ch. 13 XLL | test_xll.xll | Minifilter + AV + EDR sequence |
| 27 | SIEM: scan detection event | EICAR scan with SIEM configured | av:scan_result event received at SIEM endpoint, schema-valid per §3.7.1 |
| 28 | SIEM: quarantine event | Quarantine detected file | av:quarantine event received, vault_id populated |
| 29 | SIEM: realtime block event | Blocked file via minifilter | av:realtime_block event received with process context |
| 30 | SIEM: signature update event | Run akav-update | av:signature_update event received with version delta |
| 31 | SIEM: scan error event | Scan a 500MB timeout-inducing file | av:scan_error event received with reason=timeout |
| 32 | SIEM: JSONL local log | All scan activity | akesoav.jsonl contains all emitted events, matches SIEM-shipped format |
| 33 | SIEM: cross-product correlation | EICAR drop + EDR process event | SIEM receives both akeso_edr and akeso_av events; Sigma cross-source rule fires |
| 34 | Quick scan completes | Trigger quick scan via CLI | High-risk paths scanned. Detections in %TEMP% found. av:scheduled_scan_complete event with correct summary. |
| 35 | Full scan with throttling | Trigger full scan, monitor CPU | CPU usage stays <50%. Scan completes. All fixed drives covered. |
| 36 | Scan pauses on battery | Simulate battery mode during scan | Scan pauses. Resumes on AC. No data loss. |
| 37 | Schedule cron trigger | Configure "every minute" test cron | Scan auto-triggers within 60s. av:scheduled_scan_start event emitted. |
| 38 | AMSI: malicious PowerShell blocked | Paste Invoke-Mimikatz into PS | Execution blocked. av:scan_result with scan_type=amsi emitted. |
| 39 | AMSI: benign PowerShell allowed | Run Get-Process, Get-ChildItem | No block. No detection event. Latency <10ms. |
| 40 | AMSI: .NET reflection blocked | Reflective load of Seatbelt assembly | Blocked. av:scan_result with amsi:dotnet source. |
| 41 | AMSI: bypass attempt detected | Script patches AmsiScanBuffer | Detected by YARA rule. av:scan_result emitted. |

## 7. Feature Priority Matrix

| Feature | Priority | Phase | Book Ch. |
|---|---|---|---|
| SafeReader + file type detection | P0 | P0 | Ch. 1, 3 |
| C API header (akesoav.h) | P0 | P0 | Ch. 2 |
| CLI scanner (akavscan.exe) + EICAR | P0 | P0 | Ch. 1 |
| Bloom/hash/CRC/Aho-Corasick | P0 | P1 | Ch. 4 |
| .akavdb format + compiler | P0 | P1 | Ch. 4 |
| ClamAV signature import | P0 | P1 | Ch. 4 |
| PE parser (PE32/PE32+) | P0 | P2 | Ch. 1, 3 |
| ZIP/GZIP + bomb protection | P0 | P3 | Ch. 1, 3 |
| Python bindings | P0 | P3 | Ch. 2 |
| Test corpus assembly | P0 | P0 | — |
| Static heuristics | P1 | P4 | Ch. 3 |
| Scan cache | P1 | P5 | — |
| Windows service | P1 | P5 | Ch. 1 |
| EDR integration shim | P1 | P5 | — |
| Quarantine | P1 | P5 | Ch. 1 |
| Scheduled scanning (quick/full/custom) | P1 | P5 | Ch. 1 |
| AMSI content scanning (via EDR provider) | P1 | P5 | Ch. 10 |
| Whitelist/exclusions | P1 | P5 | — |
| ELF/PDF/OLE2 parsers | P1 | P7 | Ch. 1, 3 |
| Fuzzy hash | P1 | P6 | Ch. 4 |
| UPX unpacker | P1 | P6 | Ch. 3 |
| x86 emulator + generic unpacker | P2 | P8 | Ch. 3 |
| YARA + graph sigs + ML | P2 | P9 | Ch. 3–4 |
| Dynamic heuristic scoring | P2 | P9 | Ch. 3 |
| Secure update + self-protection | P2 | P10 | Ch. 1, 5 |

## 8. Build & Development Environment

### 8.1 Toolchain

- **Compiler:** MSVC (VS 2022) for all production code (C17 + C++20). clang-cl for fuzzing targets (libFuzzer requires Clang).
- **Build system:** CMake. Two build configurations: MSVC (production + tests) and clang-cl (fuzz targets only).
- **Analysis:** MSVC /analyze with SAL annotations on all public API functions. /W4 /WX. Application Verifier for runtime checks.
- **Debugging:** Visual Studio debugger. WinDbg for EDR integration testing.
- **Fuzzing:** clang-cl + libFuzzer. Separate CMake preset: `cmake --preset fuzz` builds fuzz targets with `-fsanitize=fuzzer,address`. Seed corpus per parser. Fuzz targets are not built by default — only via fuzz preset.
- **Crypto:** Windows CNG (BCrypt*) for all cryptographic operations. No OpenSSL dependency.

### 8.2 Test Environment

- Windows 10 22H2 + Windows 11 23H2 x64 VMs (shared with AkesoEDR, test-signing enabled).
- Test corpus: assembled in P0-T6 (see Part II). EICAR, crafted samples, ClamAV imports, clean system32 binaries, packed PEs, zip bombs, malformed files.
- Attack tooling: shared with AkesoEDR (custom XLL, Cobalt Strike, Mimikatz, Seatbelt).
- Telemetry sink: ELK stack or JSON file sink (shared with EDR).

### 8.3 Repository Structure

```
akesoav/
├── CMakeLists.txt                   # MSVC production build
├── CMakePresets.json                # Includes "fuzz" preset for clang-cl + libFuzzer
├── include/
│   └── akesoav.h                 # Public C API (§4 verbatim)
├── src/
│   ├── api.c                        # C API wrapper
│   ├── engine.cpp                   # Core engine + pipeline orchestration
│   ├── engine_internal.h            # Internal C++ types
│   ├── file_type.cpp                # Magic byte detection + routing
│   ├── scan_cache.cpp/.h            # Hash map scan cache with SRWLOCK
│   ├── whitelist.cpp/.h             # Hash/path/signer exclusions
│   ├── signatures/                  # bloom, hash_matcher, crc_matcher, aho_corasick,
│   │                                # fuzzy_hash, graph_sig, yara_scanner
│   ├── heuristics/                  # static_analyzer, entropy, imports, strings,
│   │                                # ml_classifier, dynamic_scorer
│   ├── parsers/                     # safe_reader, pe, elf, zip, gzip, tar, pdf, ole2, ooxml
│   ├── emulator/                    # x86_decode, x86_emu, memory, winapi_stubs
│   ├── unpacker/                    # upx, generic
│   ├── siem/                        # siem_shipper (WinHTTP), jsonl_writer, event_serialize
│   ├── update/                      # update_client (WinHTTP + CNG)
│   ├── quarantine/                  # quarantine (CNG + DPAPI + SQLite)
│   ├── protection/                  # self_protect, watchdog
│   ├── plugin/                      # plugin_loader (LoadLibrary)
│   ├── database/                    # sigdb (CreateFileMapping reader)
│   ├── cli/akavscan.c               # CLI scanner
│   └── service/akesoav_service.cpp       # Windows service + named pipe
├── integration/
│   └── edr_shim.cpp/.h             # AkesoEDR integration
├── bindings/python/                 # pyakav.py + tests
├── tools/akavdb-tool/                # Python signature toolchain
├── tests/
│   ├── unit/                        # GTest unit tests
│   ├── integration/                 # PowerShell + Python integration tests
│   ├── hardening/                   # Phase 11: evasion, crash resilience, self-protect, update attacks
│   ├── fixtures/                    # siem_schema_validator.py, test SIEM receiver
│   └── fuzz/                        # clang-cl libFuzzer targets (fuzz CMake preset only)
├── testdata/                        # Assembled in P0-T6
├── docs/
├── scripts/
│   ├── install.ps1
│   ├── uninstall.ps1
│   ├── ci.ps1
│   └── benchmark.py
└── README.md
```

## 9. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Parser memory corruption | High | SafeReader, /analyze + SAL, App Verifier, clang-cl libFuzzer, SEH catch in pipeline |
| Aho-Corasick memory blowup | Medium | Automaton size limit (configurable). Benchmark at ClamAV-scale (2M sigs). |
| x86 emulator infinite loops | Medium | 2M instruction limit + per-emulation timeout + fuzz emulator |
| Zip bomb OOM | Medium | Ratio/size/count limits checked during decompression, before allocation |
| Update MITM | Medium | TLS + cert pinning + RSA-signed manifest + embedded public key |
| Integration scan latency | Medium | 5s timeout. Scan cache (50K entries, LRU). Whitelist for MS-signed binaries. Async scan option for low-risk files. |
| System32 false positives | Medium | Clean sweep test (#16). Signer trust whitelist. ML FP rate <5% on clean corpus. |
| Cross-project dependency | Medium | AV Phases 0–4 are self-contained. EDR integration (Phase 5) only after EDR Phase 5 (minifilter) is complete. |
| clang-cl + MSVC coexistence | Low | Fuzz targets are separate CMake preset. Production code is MSVC-only. No code differences between builds. |

## 10. References

- Koret & Bachaalany, *The Antivirus Hacker's Handbook* (Wiley, 2015)
- Hand, *Evading EDR* (No Starch, 2023)
- AkesoEDR Requirements Document v1.0
- ClamAV source (libclamav architecture)
- ssdeep / SpamSum (fuzzy hashing)
- Aho & Corasick, "Efficient String Matching" (1975)
- YARA documentation
- Microsoft PE/COFF specification
- Microsoft CNG BCrypt API reference
- Microsoft WinHTTP API reference
- Microsoft SCM / Service API reference
- Adobe PDF Reference 1.7
- Microsoft MS-CFB (OLE2 compound binary format)
- Microsoft MS-OVBA (VBA binary format)

---

# PART II: IMPLEMENTATION PHASES

## 11. How To Use Part II With Claude Code

77 tasks across 13 phases. Estimated 50–70 Claude Code sessions.

**Complexity:** S (<200 lines, 1 session), M (200–600, 1 session), L (500–1500, 2–3 sessions), XL (cross-component, 2–4 sessions).

**Session tips:**
- Paste the relevant phase table + §4 (C API header) at session start.
- For parser tasks: reference §5.1 (file type detection) and SafeReader requirement.
- For signature tasks: reference §3.4 (.akavdb format).
- For EDR integration: reference AkesoEDR spec §3.2 (telemetry) and §5 (minifilter).
- For heuristics: reference §5.6 (static weights table) and §5.7 (dynamic weights table).
- For SIEM tasks: reference §3.7 (event schema, all 5 types) and AkesoSIEM v2.4 §4.4 (AV ingestion contract).
- For hardening tasks: reference §5.2 "Test evasions" rows, §3.3 (pipeline error model), §5.11 (self-protection), §5.10 (update system). Provide crafted test samples as context.
- Commit prior task output before starting dependent tasks.

---

### Phase 0: Project Scaffolding + EICAR

**Goal:** Repo, build system, C API, SafeReader, file type detection, CLI with working EICAR detection, test corpus. Book: Ch. 1–2.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P0-T1 | Init repo: CMakeLists.txt (MSVC), CMakePresets.json (fuzz preset for clang-cl + libFuzzer), dirs, .gitignore, .clang-format. Find CNG (bcrypt.lib), zlib, GTest. /W4 /WX. | CMakeLists.txt, CMakePresets.json | cmake -G "Visual Studio 17 2022" succeeds. cmake --preset fuzz succeeds with clang-cl. All targets compile. | S |
| P0-T2 | akesoav.h: verbatim from §4. AKAV_API macro, opaque handles, error enum, scan options/result structs (including cache + whitelist + warnings fields), lifecycle, scan functions, cache/whitelist management, version/error strings, defaults. SAL annotations. Thread safety comments. | include/akesoav.h | Compiles under MSVC C17 and C++20. /W4 clean. SAL on all pointer params. | M |
| P0-T3 | api.c + Engine stub. C wrapper delegates to C++ Engine via opaque handle cast. Stub scan returns AKAV_OK found=0. akav_strerror maps all error codes. akav_scan_options_default populates all fields. | src/api.c, engine.cpp, engine_internal.h | akesoav.dll builds. akavscan.exe links. create→init→scan→destroy works. Returns AKAV_OK. | M |
| P0-T4 | SafeReader: bounds-checked reader. read_u8/u16_le/u32_le/u64_le/bytes/skip/seek_to/remaining/position. Returns bool (false=OOB). Integer overflow: `if (count > remaining()) return false`. | src/parsers/safe_reader.h/.cpp | GTest: empty, single byte, boundary, one-past-end, skip-past-end, zero-length read_bytes, SIZE_MAX overflow, seek backward. All pass. /analyze clean. | M |
| P0-T5 | File type detection: magic byte identification per §5.1 table. Returns enum (PE, ELF, ZIP, GZIP, TAR, PDF, OLE2, UNKNOWN). Uses SafeReader for first 8 bytes. | src/file_type.cpp/.h | GTest: MZ→PE. PK→ZIP. %PDF→PDF. Unknown→UNKNOWN. Empty file→UNKNOWN. 1-byte file→UNKNOWN. | S |
| P0-T6 | Test corpus assembly: create testdata/ with eicar.com.txt, eicar.zip (EICAR inside ZIP), eicar_nested.zip (ZIP-in-ZIP), eicar.gz, clean.txt, clean_pe_32.exe (copy of system calc or notepad), clean_pe_64.exe, truncated.exe (first 100 bytes of a PE), empty.bin. PowerShell script to generate. | testdata/*, scripts/create_testdata.ps1 | All test files present. EICAR files contain valid EICAR string. Clean PEs are valid. Truncated PE is genuinely truncated. | S |
| P0-T7 | Hardcoded EICAR detection in Engine::scan_buffer + akavscan.exe with full CLI arg parsing (all flags from §3.5), -j JSON, -v verbose, -r recursive (FindFirstFile/FindNextFile), --eicar-test self-test. | src/engine.cpp, src/cli/akavscan.c | akavscan --eicar-test passes. akavscan testdata/eicar.com.txt→detected (exit 1). akavscan testdata/clean.txt→clean (exit 0). -j valid JSON. -r recursive works. | M |
| P0-T8 | GTest infrastructure: test_safe_reader, test_file_type, test_eicar, test_engine_lifecycle (create/init/destroy, double-destroy safety, scan-after-destroy→error). First fuzz target: fuzz_scan_buffer (clang-cl). | tests/unit/*.cpp, tests/fuzz/fuzz_scan_buffer.cpp | ctest passes. Fuzz target runs 60s clean. | M |

---

### Phase 1: Signature Engine

**Goal:** Full layered signature matching. Replace hardcoded EICAR. Real signature databases. Book: Ch. 4.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P1-T1 | Bloom filter: bit array, double hashing (murmur3+fnv1a), insert/query, serialize/deserialize. | src/signatures/bloom.cpp/.h | 10K→all "maybe". 10K absent→FP<1% at 10 bits/elem. Round-trip. | M |
| P1-T2 | SHA-256/MD5 hash matcher: sorted arrays, binary search, CNG BCryptHash. | src/signatures/hash_matcher.cpp/.h | 1K found. 1K absent→none. 100K lookups <100ms. | M |
| P1-T3 | CRC32 matcher: IEEE + custom polynomial (modified table). Region-based (whole, first/last N, PE section). | src/signatures/crc_matcher.cpp/.h | IEEE reference values match. Custom differs. Region on test PE correct. | M |
| P1-T4 | Aho-Corasick: trie + failure links + search. Byte patterns (handles nulls). Serializable automaton. Stack-allocated walk state (thread-safe). | src/signatures/aho_corasick.cpp/.h | Overlapping patterns. Nulls. Empty input. 1K patterns vs 10MB <500ms. Two threads scanning simultaneously→no data race. | L |
| P1-T5 | .akavdb reader: validate magic/version per §3.4. CreateFileMapping/MapViewOfFile PROT_READ. Section offset table. RSA verify header (CNG BCryptVerifySignature). String table lookup. | src/database/sigdb.cpp/.h | Load crafted .akavdb→all sections accessible. Reject bad magic/version/RSA sig. MapViewOfFile is read-only. | M |
| P1-T6 | akavdb-tool (Python): compile (build all §3.4 sections, write binary format, RSA-sign with cryptography lib), verify, stats, test subcommands. | tools/akavdb-tool/*.py | Compile 5 sigs (1 MD5, 1 SHA256, 1 CRC32, 1 byte-stream, 1 EICAR). Verify. Stats correct. Test→EICAR detected. | L |
| P1-T7 | ClamAV importer: parse .hdb (MD5 hash:file_size:name) and .ndb (name:target:offset:hex_sig). | tools/akavdb-tool/importers/clamav.py | Import 100-sig subset. Compile→count matches. Known sample→detected. | M |
| P1-T8 | Scan pipeline: file type detect→bloom→hash→CRC→Aho-Corasick. Short-circuit. Engine::load_signatures from .akavdb. Replace hardcoded EICAR. Pipeline error model per §3.3. | src/scanner.cpp, engine.cpp | Mixed .akavdb: all sig types detect. Clean files clean. EICAR via byte-stream. --eicar-test still passes. Parser error→warnings populated, remaining stages run. | L |

---

### Phase 2: PE Parser

**Goal:** Full PE32/PE32+ parser. Foundation for heuristics, emulator, graph sigs. Book: Ch. 1, 3.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P2-T1 | PE core: DOS header→PE sig→COFF→optional header (PE32/PE32+)→section table. All SafeReader. File type gate: only runs if file_type==PE. | src/parsers/pe.cpp/.h | Fields match dumpbin/CFF Explorer for 32+64 bit PEs. Truncated→graceful error (warnings[], no crash). Zero-section→error. | L |
| P2-T2 | PE imports/exports: IMAGE_IMPORT_DESCRIPTORs, DLL names, function names/ordinals. Export directory. | src/parsers/pe.cpp | Match dumpbin /imports /exports. Ordinal-only imports parsed. Invalid RVA→skip entry, don't crash. | M |
| P2-T3 | PE metadata: per-section Shannon entropy, overlay detection, rich header hash, resource type enumeration, Authenticode certificate table presence/validity. Output: akav_parsed_pe_t struct. | src/parsers/pe.cpp | Entropy ±0.1 of pefile. Overlay detected. Rich hash correct. Authenticode presence detected. | M |
| P2-T4 | PE fuzz target (clang-cl + libFuzzer). Seed corpus from testdata/ (10 real PEs: 32/64/.NET/UPX/minimal/resource-heavy). | tests/fuzz/fuzz_pe.cpp | 10-min fuzz clean. Crashes filed as bugs with reproducer input. | S |

---

### Phase 3: Archive Handling + Python Bindings

**Goal:** ZIP/GZIP with bomb protection. Python automation layer. End-to-end validation. Book: Ch. 1–2.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P3-T1 | ZIP handler: local file headers, entries, zlib inflate. Anti-DoS per §5.5. Recursive scan of extracted entries through pipeline. File type gated. | src/parsers/zip.cpp/.h | EICAR in ZIP→detected. Nested depth 2→detected. Bomb→AKAV_ERROR_BOMB. Depth limit→stops. No OOM. | L |
| P3-T2 | GZIP + TAR: gzopen/gzread. POSIX ustar header. Recursive scan. | src/parsers/gzip.cpp, tar.cpp | EICAR in .gz→detected. EICAR in .tar.gz→detected. | M |
| P3-T3 | Archive fuzz targets (clang-cl). | tests/fuzz/fuzz_zip.cpp, fuzz_gzip.cpp | 10-min clean. | S |
| P3-T4 | pyakav: ctypes wrapper loading akesoav.dll. AkesoAV class with context manager. ScanOptions/ScanResult structures. Error handling. | bindings/python/pyakav.py, test_pyakav.py | pytest: EICAR detected, clean clean, buffer works, context manager cleans up. | M |
| P3-T5 | Integration tests + CI: akavdb-tool compile→engine load→scan mixed test corpus. PowerShell CI script (build, test, /analyze). | tests/integration/, scripts/ci.ps1 | All expected detections. Zero FP on clean files. CI exits 0. | M |

---

### Phase 4: Static Heuristic Engine

**Goal:** Multi-analyzer PE scoring pipeline per §5.6 weight table. Book: Ch. 3.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P4-T1 | PE header analyzer: all checks from §5.6 PE Header row with specified weights. JSON-configurable weights file. | src/heuristics/static_analyzer.cpp/.h | UPX triggers section name (+25) + entry point (+15). Clean calc.exe→0. Custom weights from JSON override defaults. | L |
| P4-T2 | Entropy analyzer: Shannon per-section + whole-file. Scoring per §5.6 Entropy row. | src/heuristics/entropy.cpp/.h | UPX .text >7.0→+20. Clean 5.5–6.5→0. All-zero→entropy 0. Random→~8. | M |
| P4-T3 | Import analyzer: all combos from §5.6 Imports row. | src/heuristics/imports.cpp/.h | Injection combo→+35. notepad→0. GetProcAddress-only→+25. | M |
| P4-T4 | String analyzer: all patterns from §5.6 Strings row. JSON-configurable pattern list. | src/heuristics/strings.cpp/.h | "powershell.exe -enc"→+10. Base64 blob >100 chars→+10. Clean notepad→0. | M |
| P4-T5 | Heuristic pipeline integration: run analyzers after sigs on PE files. Sum scores. Apply threshold per heuristic_level. Populate result on exceed. | src/scanner.cpp | Injection imports + entropy >7.0→detected at Medium (score ~55 >50 threshold). Same at Low→not detected. Clean PE→score 0 at all levels. | M |

---

### Phase 5: Windows Service + EDR Integration + Scan Cache + Quarantine

**Goal:** Service architecture, EDR integration with scan cache, quarantine. Book: Ch. 1–2.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P5-T1 | Scan cache: hash map (path+timestamp+size→result), SRWLOCK reader-writer, LRU eviction at 50K, invalidation on file change, clear on sig reload. akav_cache_clear/stats API. | src/scan_cache.cpp/.h | Cache hit on unchanged re-scan (cached=1, time≈0). Modified file→miss. Reload→cleared. Stats correct. Two threads→no race. | L |
| P5-T2 | Whitelist/exclusions: hash whitelist (from .akavdb section + runtime), path prefix exclusion, Authenticode signer trust (WinVerifyTrust). Pipeline integration per §5.4. | src/whitelist.cpp/.h | MS-signed calc.exe→in_whitelist=1, skip scan. Path-excluded file→not scanned. SHA-256 whitelisted→skip. | M |
| P5-T3 | akesoav-service.exe: SCM registration, named pipe (\\.\pipe\AkesoAVScan), thread pool (_beginthreadex), full protocol (§3.5 including STATS with cache hits), sig preload, graceful shutdown. | src/service/akesoav_service.cpp | sc start works. SCAN eicar→detected. 4 concurrent clients→all correct. STATS shows cache hits. SIGTERM→clean shutdown. | L |
| P5-T4 | EDR integration shim: LoadLibrary akesoav.dll at akesoedr-agent.exe startup, resolve all C API symbols via GetProcAddress, AVEngine wrapper class (init, scan, reload, shutdown), scan dispatch from minifilter (akesoedr-drv.sys) file events with 5s timeout (worker thread + WaitForSingleObject), scan cache check before scan call, merge AV fields into telemetry struct, graceful degradation on DLL load failure. AV config path read from akesoedr.conf [av] section. | integration/edr_shim.cpp/.h | EICAR drop with EDR→av_detected in telemetry JSON. Alert fires. DLL removed→akesoedr-agent.exe starts without AV, warning logged. Re-scan of unchanged file→cached=1. Scan >5s→timeout, warning. | XL |
| P5-T5 | Quarantine: CNG AES-256-GCM, DPAPI key, SQLite index per §5.12, all operations, ACLs. | src/quarantine/quarantine.cpp/.h | Quarantine→encrypted .sqz + index row. Restore matches original SHA-256. ACL correct (SYSTEM+Admins). Purge works. | M |
| P5-T6 | EDR YAML rules using AV fields: "malware dropped by Office app" (process callback + minifilter + av_detected), "heuristic suspicious from browser" (av_heuristic_score >50 + parent=browser), "AV match + process injection" (av_detected + NtCreateThreadEx remote=true sequence). | rules/av_enhanced_detection.yaml | Rules fire during integrated test scenarios. No FP in 30-min clean baseline. | M |
| P5-T7 | SIEM event shipper: akav_siem_event_t struct, akav_siem_callback_t callback registration, built-in HTTP shipper (WinHTTP, NDJSON batching — 100 events or 5s flush, ring buffer 1000, X-API-Key header), JSONL local log writer (100MB rotation), event serialization for all 5 event types per §3.7. In standalone mode: akesoav-service registers HTTP shipper + JSONL writer. In integrated mode: EDR agent registers callback routing to its own shipper. | src/siem/siem_shipper.cpp/.h, src/siem/jsonl_writer.cpp/.h, src/siem/event_serialize.cpp/.h | EICAR scan→av:scan_result event received at test SIEM endpoint (Python HTTP listener validates JSON schema). Quarantine action→av:quarantine event. SIEM unreachable→events buffered, delivered on reconnect (up to ring buffer capacity). JSONL file written with correct rotation. Integrated mode: callback invoked with correct event. | L |
| P5-T8 | Scheduled scanning: scheduler thread in akesoav-service.exe, cron expression parser (minute/hour/day/month/weekday), schedule config loader (JSON from %ProgramData%\Akeso\schedules.json), quick scan (high-risk paths per §5.13) vs full scan (all fixed drives) vs custom scan, I/O throttling (SetThreadPriority THREAD_MODE_BACKGROUND_BEGIN, CPU affinity cap at 50%), battery-aware pause (GetSystemPowerStatus), progress tracking (files scanned/remaining/elapsed/detections), concurrency guard (one scheduled scan at a time), av:scheduled_scan_start + av:scheduled_scan_complete SIEM events (§3.7.7–3.7.8), CLI exposure (akavscan --schedule list/run/next), STATS integration (scheduled_scan_active, scheduled_scan_progress). Default schedules created by install script. | src/service/scheduler.cpp/.h, src/service/cron_parser.cpp/.h | Quick scan of %TEMP%+Downloads completes in <5 min on test VM. Full scan throttled — CPU usage stays below 50%. Battery mode→scan pauses (simulate with powercfg). Cron "0 2 * * 0"→next trigger is Sunday 02:00. SIEM receives start+complete events with correct summary. Concurrent trigger→second scan skipped and logged. akavscan --schedule list shows configured schedules. | L |
| P5-T9 | AMSI content scanning: In the EDR agent's existing AMSI provider (akesoedr-amsi.dll, AkesoEDR P7-T4), add a call to akav_scan_buffer() on the content buffer received from AmsiScanBuffer. The buffer name is set to "amsi:<source>" where source is powershell, dotnet, vbscript, jscript, or vba (derived from AMSI's appName parameter). If akav_scan_buffer returns found=1, the AMSI provider returns AMSI_RESULT_DETECTED (blocking execution). Results emitted as av:scan_result events with scan_type="amsi" and scanner_id="amsi_provider". Add AMSI-targeted YARA rules: Invoke-Mimikatz, Invoke-Expression+DownloadString chain, [Reflection.Assembly]::Load patterns, AmsiScanBuffer patching attempts (reading amsi.dll base + offset writes), amsiInitFailed variable set. | integration/edr_amsi_av.cpp, yara-rules/amsi_scripts.yar | Paste Invoke-Mimikatz into PowerShell→blocked. av:scan_result event emitted with scan_type=amsi, signature.engine=yara. Paste benign script→allowed, no event. .NET reflection load of Seatbelt→blocked by YARA rule. AMSI bypass attempt (patching AmsiScanBuffer)→detected by YARA + heuristic string match. Clean PowerShell commands (Get-Process, dir)→no detection, no latency >10ms. | L |

---

### Phase 6: Fuzzy Hashing + UPX Unpacker + Dynamic Plugins

**Goal:** Variant detection, common packer support, extensibility. Book: Ch. 3–4.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P6-T1 | Fuzzy hashing (ssdeep-compatible): piecewise hash, rolling hash boundaries, similarity 0–100, sig matching. .akavdb section 5 integration. | src/signatures/fuzzy_hash.cpp/.h | Identical→100. 1-byte→>95. Appended→>80. Different→<10. | L |
| P6-T2 | UPX static unpacker: detect by section names/magic, NRV/LZMA decompress, IAT rebuild, OEP restore. Feed unpacked output through full pipeline. | src/unpacker/upx.cpp/.h | Unpacked matches upx -d output. Packed EICAR-PE→detected after unpack. Non-UPX PE→no unpack attempt. | L |
| P6-T3 | Dynamic plugin loading: LoadLibrary, GetProcAddress("akav_plugin_get_info"), validate API version, register scanner/parser plugins. Clean shutdown (FreeLibrary). | src/plugin/plugin_loader.cpp/.h | Test plugin .dll detects "PLUGINTEST" string. Plugin absent→engine normal. Wrong API version→skip with warning. | M |

---

### Phase 7: Extended File Format Parsers

**Goal:** PDF, OLE2, ELF parsers for document and cross-platform malware analysis. Book: Ch. 1, 3.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P7-T1 | ELF parser: header (32/64, LE/BE), section/program headers, .symtab, .dynsym, .dynamic, .note. All SafeReader. File type gated. | src/parsers/elf.cpp/.h | Fields match readelf for known ELFs. Truncated→error. Fuzz target 10-min clean. | L |
| P7-T2 | PDF parser: xref table (traditional + xref streams), object extraction, stream decompression (Flate/ASCII85/Hex/LZW), multi-filter chains, JS extraction (/JS, /JavaScript actions), embedded file extraction (/EmbeddedFiles). | src/parsers/pdf.cpp/.h | PDF with FlateDecode EICAR→detected. JS extracted. Malformed xref→error (not crash). Fuzz 10-min clean. | L |
| P7-T3 | OLE2 parser: FAT/DIFAT chain traversal with loop detection (visited set), directory entry enumeration, stream extraction, VBA project decompression (MS-OVBA). | src/parsers/ole2.cpp/.h | .doc with VBA macro→source extracted containing expected strings. Circular FAT→error (not infinite loop). Fuzz 10-min clean. | L |
| P7-T4 | Fuzz targets for ELF, PDF, OLE2 (clang-cl). Seed corpus with valid + malformed samples per format. | tests/fuzz/fuzz_elf.cpp, fuzz_pdf.cpp, fuzz_ole2.cpp | All 10-min clean. | S |

---

### Phase 8: x86 Emulator + Generic Unpacker

**Goal:** CPU emulation for unknown packer support. Book: Ch. 3.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P8-T1 | x86 instruction decoder: prefixes, 1-byte opcodes, 2-byte 0F opcodes, ModR/M, SIB, displacement, immediate. Decoded instruction struct. | src/emulator/x86_decode.cpp/.h | Known instruction bytes→correct opcode+operands. 100 instructions from real PE match ndisasm. Invalid opcode→decode error. | L |
| P8-T2 | x86 execution engine: register file (EAX–EDI, ESP, EBP, EIP, EFLAGS), fetch-decode-execute loop. All instructions from §5.8. EFLAGS: ZF/SF/CF/OF correct for arithmetic/logical. 2M instruction limit. | src/emulator/x86_emu.cpp/.h | push 0x41414141; pop eax→EAX=0x41414141. Loop sum(1..10)=55. Jcc branches correct. UPX decompression stub runs to limit without crash. | XL |
| P8-T3 | API stubs + PE loader: map PE sections at ImageBase, resolve imports to stub addresses, TEB/PEB at fs:[0x30], RDTSC/CPUID stubs. API call logging for dynamic heuristics. | src/emulator/winapi_stubs.cpp, memory.cpp | Load UPX PE→execution through decompression stub. API calls logged with params. Memory writes tracked. | L |
| P8-T4 | Generic unpacker: execute packed PE, detect write-then-jump (>4KB write + EIP transfer to written region), dump target region, validate as PE (MZ+PE sig), re-scan through full pipeline. | src/unpacker/generic.cpp/.h | UPX PE→unpacked payload matches static unpacker. Custom XOR PE→recovered. Non-packed→no unpack, no crash. | L |
| P8-T5 | Emulator fuzz targets: fuzz_x86_decode (arbitrary bytes→decoder), fuzz_x86_emu (arbitrary "PE"→load+execute with 10K instruction limit). | tests/fuzz/fuzz_x86_decode.cpp, fuzz_x86_emu.cpp | 10-min clean each. | S |

---

### Phase 9: YARA + Graph Signatures + ML + Dynamic Heuristics

**Goal:** Advanced detection methods. Book: Ch. 3–4.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P9-T1 | YARA integration: libyara static link, scan_file/scan_buffer API, hot-reload on akav_engine_load_signatures. YARA section in .akavdb. akavdb-tool import --format yara. | src/signatures/yara_scanner.cpp/.h | YARA rule matches test pattern. Clean→no match. Hot-reload picks up new rules <1s. | L |
| P9-T2 | Graph-based signatures: build basic block graph from PE .text using x86 decoder. Hash opcodes per block (ignore operands). Sorted block hashes→graph hash. Similarity via set intersection ratio. | src/signatures/graph_sig.cpp/.h | Same C program compiled with MSVC vs Clang→similarity >70%. Same + NOP sleds→>90%. Different program→<20%. | L |
| P9-T3 | ML classifier training: extract PE feature vectors (§5.6 ML row), train Random Forest (scikit-learn), export as JSON decision tree array. Validation on held-out set. | tools/ml/train_classifier.py | 5-fold CV accuracy >85%. Held-out test >80%. JSON exported. FP rate <5% on clean system32 sample. | M |
| P9-T4 | ML classifier inference (C++): load JSON model at engine init, evaluate feature vector→probability 0.0–1.0. Integrate: probability×50 added to heuristic score. | src/heuristics/ml_classifier.cpp/.h | Known-malware features→probability >0.7 (score +35). Clean→<0.3 (score +15, below Medium threshold alone). Integration: ML pushes a borderline PE over Medium threshold when combined with one import anomaly. | M |
| P9-T5 | Dynamic heuristic scorer: weight-based scoring from emulator API call log per §5.7 table. JSON-configurable weights. Score added to static heuristic total. | src/heuristics/dynamic_scorer.cpp/.h | Emulated PE with VirtualAlloc(RWX)+write+jump→+35. Clean PE emulation→score ≈-8 (benign APIs). Combined static+dynamic exceeds threshold for packed suspicious PE. | M |

---

### Phase 10: Update System + Self-Protection + OOXML

**Goal:** Secure signature distribution, tamper resistance, remaining parser. Book: Ch. 1, 5.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P10-T1 | Update client: WinHTTP HTTPS, cert pinning (embedded fingerprint, verified in status callback), fetch manifest JSON, compare version, download, SHA-256 verify (CNG), RSA verify (CNG), MoveFileEx atomic swap, .akavdb.prev rollback, RELOAD. | src/update/update_client.cpp/.h | Local HTTPS test server (Python ssl)→downloads+installs. Tampered manifest→rejected. Tampered file→rejected. Expired cert→rejected. Rollback on bad DB→.prev restored. | L |
| P10-T2 | Self-protection: service DACL hardening (deny PROCESS_TERMINATE from non-admin). WinVerifyTrust on DLL+plugins at load. SHA-256 monitoring (60s interval). | src/protection/self_protect.cpp/.h | TerminateProcess from non-admin→denied. Modified DLL→refuses to load at next check. | M |
| P10-T3 | Watchdog: separate watchdog.exe. Named pipe PING/PONG (5s interval, 15s timeout). CreateProcess auto-restart. Log all events. | src/protection/watchdog.cpp/.h | Kill service→restarted <20s. Hang (simulate SIGSTOP-equivalent)→detected+restarted. Normal operation→no false restarts. | M |
| P10-T4 | OOXML parser: ZIP extraction→[Content_Types].xml→detect vbaProject.bin→feed to OLE2 parser for VBA extraction. Embedded files from media/embeddings. | src/parsers/ooxml.cpp/.h | .docx with macro→VBA extracted. Clean .xlsx→parsed without error. Fuzz target clean. | M |
| P10-T5 | Install/uninstall PowerShell scripts: service registration (sc create), signature deployment (.akavdb to %ProgramData%\Akeso\), config registry keys with restricted ACLs, watchdog setup. | scripts/install.ps1, uninstall.ps1 | Clean install on fresh Win10/11. akavscan --eicar-test passes post-install. Uninstall removes everything. | S |

---

### Phase 11: Hardening & Evasion Resistance

**Goal:** Adversarial validation of every detection and protection layer. Explicit evasion testing matching the "test evasions" rows from Part I requirements tables. Self-protection attack testing. Signature database tamper resistance. Pipeline bypass validation. Mirrors AkesoEDR Phase 11 (Hardening & Self-Protection). Book: Ch. 6–9 (evasion), Ch. 1 (self-protection).

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P11-T1 | Signature evasion test suite: (a) Take a hash-signatured PE (MD5 match), modify one byte at EOF → verify hash match FAILS but byte-stream sig still DETECTS. (b) Take a byte-stream-signatured PE, pack it with UPX → verify byte-stream FAILS on packed file but unpacker + re-scan DETECTS. (c) Take a graph-signatured PE, reorder functions + insert NOP sleds → verify byte-stream FAILS but graph sig still DETECTS (similarity >70%). (d) Take a fuzzy-hash-signatured PE, modify 5% of bytes → verify exact hash FAILS but fuzzy hash DETECTS (similarity >80%). Automated test script exercises all 4 evasion scenarios. | tests/hardening/test_sig_evasion.ps1, tests/hardening/evasion_samples/ (crafted) | All 4 evasion scenarios pass: cheaper layer fails, more expensive layer catches. Each scenario logs which layer detected and which was bypassed. | L |
| P11-T2 | Parser crash resilience: (a) Craft a PE that crashes the PE parser (malformed optional header with integer overflow in SizeOfHeaders) — verify pipeline catches SEH exception, populates warnings[], remaining stages (byte-stream, YARA) still run on raw bytes, and result is not AKAV_OK (either detection from later stage or AKAV_SCAN_ERROR). (b) Craft a ZIP where entry 1 is a zip bomb (triggers AKAV_ERROR_BOMB) and entry 2 contains EICAR — verify entry 2 is still scanned and EICAR detected. (c) Craft a PDF with malformed xref that triggers parser error + valid JavaScript stream — verify JS extraction from fallback still works or raw-byte sig matches. | tests/hardening/test_parser_resilience.cpp (GTest), tests/hardening/crafted_crash_pe.py (generator) | (a) PE parser error in warnings[], byte-stream or YARA catches malware in raw bytes. No process crash. (b) EICAR in entry 2 detected despite bomb in entry 1. (c) PDF pipeline degrades gracefully — either JS extracted or raw-byte sig fires. | L |
| P11-T3 | Self-protection attack suite: (a) From a medium-integrity (non-admin) process, attempt TerminateProcess on akesoav-service.exe PID → verify ACCESS_DENIED. (b) From a medium-integrity process, attempt OpenProcess with PROCESS_VM_WRITE on akesoav-service.exe → verify denied. (c) Replace akesoav.dll on disk with a tampered copy (append 1 byte) while service is running → verify SHA-256 integrity monitor detects within 60s, logs alert, and refuses to use tampered DLL on next RELOAD. (d) Corrupt akeso.akavdb on disk (flip one byte in RSA signature region) → call RELOAD → verify engine rejects corrupted DB and falls back to .akavdb.prev. (e) Kill akesoav-service.exe via taskkill /F /PID → verify watchdog restarts it within 20s. | tests/hardening/test_self_protection.ps1 | (a) TerminateProcess→ACCESS_DENIED. (b) OpenProcess→denied. (c) Tampered DLL→integrity alert within 60s. (d) Corrupt DB→RELOAD fails, prev restored, scanning continues with old sigs. (e) Kill→restarted <20s. | L |
| P11-T4 | Heuristic evasion boundary testing: (a) Craft a PE that triggers exactly the Medium threshold (score=75): 3 suspicious imports (+35) + W+X .text (+20) + high entropy (+20) = 75 → verify DETECTED at Medium, NOT detected at Low. (b) Craft a PE that scores 74 → verify NOT detected at Medium. (c) Craft a clean PE that resembles packed malware (high entropy resources, UPX-like section names, but legitimate signed binary) → verify NOT detected at any level (FP test). (d) Run ML classifier against full clean system32 directory → verify FP rate <5%. | tests/hardening/test_heuristic_evasion.cpp (GTest), tests/hardening/crafted_heuristic_pes.py (generator) | (a) Score=75→detected at Medium. (b) Score=74→not detected at Medium. (c) Clean signed PE with suspicious appearance→not detected. (d) system32 FP rate <5%. | M |
| P11-T5 | Emulator evasion & anti-analysis testing: (a) Craft a PE with RDTSC-based timing check (two RDTSC calls, if delta < threshold → real hardware, else → emulated, branch to different code) → verify emulator's RDTSC returns plausible monotonic values and the packed PE still unpacks correctly. (b) Craft a PE that checks IsDebuggerPresent via PEB.BeingDebugged at fs:[0x30]+0x02 → verify emulator returns 0, execution continues normally. (c) Craft a PE that issues CPUID and validates vendor string → verify emulator returns "GenuineIntel". (d) Craft a PE that uses SEH-based control flow (intentional divide-by-zero, handler transfers to unpack routine) → verify emulator dispatches SEH correctly and unpacking completes. | tests/hardening/test_emu_evasion.cpp (GTest), tests/hardening/emu_evasion_samples/ (NASM-assembled test PEs) | (a) Timing check doesn't prevent unpacking. (b) IsDebuggerPresent returns 0. (c) CPUID vendor = "GenuineIntel". (d) SEH handler runs, unpack completes, re-scan detects payload. | L |
| P11-T6 | Update protocol attack suite: (a) Set up MITM proxy (mitmproxy), intercept update HTTPS connection → verify cert pinning rejects the proxy's certificate. (b) Serve a valid manifest but tampered .akavdb file (correct SHA-256 in manifest but wrong RSA signature on file) → verify engine rejects the file. (c) Serve a valid manifest with correct hashes but replay an old manifest version (version < current) → verify engine ignores the downgrade. (d) Remove the HTTPS test server entirely → verify engine retries, eventually times out, and continues operating with existing signatures (no crash, no data loss). | tests/hardening/test_update_attacks.py (Python + mitmproxy/mock HTTPS server) | (a) Pinning rejects MITM cert. (b) Bad RSA sig→file rejected, existing DB retained. (c) Old version→ignored. (d) Server down→timeout, engine continues, no crash. | L |

---

### Phase 12: Integration Testing + Benchmarks + Documentation

**Goal:** Full validation across standalone + integrated modes. Performance. Docs.

| ID | Task | Files | Acceptance Criteria | Est. |
|---|---|---|---|---|
| P12-T1 | Full integration test: all 41 scenarios from §6. Both standalone and integrated modes. | tests/integration/test_full_system.ps1 | ≥1 detection per scenario. Zero FP in 30-min clean Win11 baseline. Both modes produce identical detection results for same corpus. Scheduled scans and AMSI scans complete in both modes. | L |
| P12-T2 | Ch. 13 cross-validation: run AkesoEDR Ch. 13 attack chain with AV engine loaded. Verify AV fields in telemetry for XLL drop, shellcode runner PE, beacon DLL. | tests/integration/ch13_av_validation.ps1 | AV detections correlate with EDR behavioral alerts for ≥3 of 8 attack phases. Combined AV+EDR YAML rules fire. | L |
| P12-T3 | Performance benchmark: 10K mixed-file corpus. Throughput (files/sec), peak memory (working set), p50/p95/p99 per-file latency. ClamAV (clamscan) comparison on same corpus. Integrated-mode overhead measurement (EDR agent latency with vs without AV). Cache hit rate after second pass. | scripts/benchmark.py, docs/benchmark_report.md | Reproducible numbers. ClamAV comparison table. Integrated latency <2x standalone. Cache hit rate >90% on second pass. Top-5 hotspots identified. | M |
| P12-T4 | Architecture documentation: component diagrams, scan pipeline data flow, .akavdb format, EDR integration, SIEM telemetry flow, design rationale per Handbook chapters. | docs/architecture.md | Another developer understands the full architecture from docs alone. | M |
| P12-T5 | Memory safety documentation: SafeReader patterns, /analyze + SAL methodology, clang-cl fuzzing setup, bugs caught during development with root cause + fix. | docs/memory-safety.md | Includes ≥3 real examples of bugs caught by fuzzing or /analyze. | M |
| P12-T6 | Spec documents: .akavdb binary format (§3.4 verbatim), service protocol (§3.5), update protocol (§5.10), EDR integration API (§3.2 + edr_shim.h), SIEM event schema (§3.7). README with build + install + usage. | docs/*.md, README.md | Build from README alone succeeds. All specs match implementation. | M |
| P12-T7 | Release validation: /analyze zero warnings. Application Verifier clean. All fuzz targets 1-hour each clean. All GTests + integration tests + hardening tests pass. CI script green. Tag v0.1.0. | scripts/ci.ps1 | CI exits 0 with full validation suite including Phase 11 hardening. | M |
| P12-T8 | SIEM integration test: start Python test SIEM receiver (HTTP listener validating NDJSON + JSON schema per §3.7). Configure AkesoAV to ship to test SIEM. Scan EICAR→verify av:scan_result event received with correct fields. Quarantine→verify av:quarantine event. Sig update→verify av:signature_update event. Parser timeout→verify av:scan_error event. Verify JSONL local log contains same events. Verify ECS field mapping matches AkesoSIEM v2.4 §4.4 expectations. In integrated mode: verify EDR+AV events both arrive at SIEM with correct source_type differentiation. | tests/integration/test_siem_integration.py, tests/fixtures/siem_schema_validator.py | All 5 event types received and schema-valid. ECS mappings correct. JSONL log matches. Integrated mode: both akeso_edr and akeso_av events arrive. | L |

---

## Phase Summary & Dependency Map

| Phase | Name | Tasks | Depends On | Book Ch. | Tier |
|---|---|---|---|---|---|
| P0 | Scaffolding + EICAR | 8 | — | Ch. 1–2 | Foundation |
| P1 | Signature Engine | 8 | P0 | Ch. 4 | Core |
| P2 | PE Parser | 4 | P0 (SafeReader) | Ch. 1, 3 | Core |
| P3 | Archives + Python | 5 | P0, P1 | Ch. 1–2 | Core |
| P4 | Static Heuristics | 5 | P2 (PE parser) | Ch. 3 | Intermediate |
| P5 | Service + EDR + Cache + SIEM + Scheduler + AMSI | 9 | P1, P2, P3; **EDR P5, P7** | Ch. 1–2, 10 | Intermediate |
| P6 | Fuzzy Hash + UPX + Plugins | 3 | P1, P2 | Ch. 3–4 | Intermediate |
| P7 | ELF + PDF + OLE2 Parsers | 4 | P0 (SafeReader) | Ch. 1, 3 | Intermediate |
| P8 | x86 Emulator | 5 | P2 (PE parser) | Ch. 3 | Advanced |
| P9 | YARA + Graph + ML + Dynamic | 5 | P1, P2, P8 | Ch. 3–4 | Advanced |
| P10 | Update + Self-Protect + OOXML | 5 | P5 (service) | Ch. 1, 5 | Advanced |
| P11 | Hardening & Evasion Resistance | 6 | P1–P10 (all engines) | Ch. 6–9 | Advanced |
| P12 | Integration + Benchmarks + Docs + SIEM | 8 | All | — | Validation |
| **Total** | | **77 tasks** | | | **~50–70 sessions** |

---

## Code Conventions & Constraints

**Engine (akesoav.dll):** C++20 internal (MSVC), C17 API boundary. RAII (unique_ptr, vector, span). No exceptions across C API. AKAV_API macro (dllexport/dllimport). Fixed-size buffers in public structs. No Boost. No STL across DLL boundary. Thread-safe scanning after init (SRWLOCK for cache + sig reload).

**Parsers:** All reads through SafeReader. No raw pointer arithmetic. Integer overflow checks (`if (a > SIZE_MAX - b) return error`). /analyze + SAL on all functions. clang-cl fuzz targets for every parser.

**CLI + Service:** C17 for akavscan.c. C++20 for akesoav_service.cpp. Win32: CreateNamedPipe, _beginthreadex, overlapped I/O. JSON via snprintf (no external JSON library).

**Python:** ctypes loading akesoav.dll. cryptography for RSA signing in akavdb-tool. pyyaml for sig definitions.

**Crypto:** Windows CNG (BCrypt*) exclusively. BCryptHash for SHA-256/MD5. BCryptVerifySignature for RSA. No OpenSSL.

**Signatures:** CreateFileMapping/MapViewOfFile read-only. Zero heap allocation on scan match hot path. RSA-signed. MoveFileEx atomic swap.

**Fuzzing:** clang-cl + libFuzzer via CMake "fuzz" preset. Separate from production MSVC build. Same source files, different compiler. ASan enabled in fuzz builds.

---

## v2 Roadmap

**v2 Candidates:** Memory scanning (EDR memory scanner → akav_scan_buffer for unbacked RX regions) · Network stream scanning (WFP → AV for HTTP response bodies) · Linux native build · Duktape JS sandbox for PDF analysis · Cloud reputation / prevalence scoring · Full x86-64 emulation · Honeypot files · AkesoDLP content inspection in scan pipeline · Certificate chain analysis (revocation, abused certs) · Sliding-window entropy profiling · API call sequence signatures

**v1 Prep for v2:** akav_scan_buffer() accepts any byte array (AMSI ✓, memory, network). C API stable — new call sites, not new engine code. Plugin architecture extensible. .akavdb format supports reserved section types 9–255. EDR telemetry schema has reserved fields for DLP verdict.
