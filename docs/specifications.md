# AkesoAV Specifications

## 1. .akavdb Binary Format

### Header (280 bytes)

| Offset | Size | Type | Field | Value |
|--------|------|------|-------|-------|
| 0x0000 | 4 | u32 | Magic | `0x56414B41` ("AKAV" LE) |
| 0x0004 | 4 | u32 | Version | `1` |
| 0x0008 | 4 | u32 | Signature count | Total across all sections |
| 0x000C | 8 | i64 | Created timestamp | Unix epoch seconds |
| 0x0014 | 4 | u32 | Section count (N) | Number of sections |
| 0x0018 | 256 | bytes | RSA signature | RSA-2048 PKCS#1 v1.5 over SHA-256 of header+data |

### Section Offset Table (N * 16 bytes, starting at 0x0118)

| Offset | Size | Type | Field |
|--------|------|------|-------|
| +0 | 4 | u32 | Section type |
| +4 | 4 | u32 | Absolute file offset |
| +8 | 4 | u32 | Section size in bytes |
| +12 | 4 | u32 | Entry count |

### Section Types

| Value | Name | Entry Format |
|-------|------|--------------|
| 0 | BLOOM | Serialized bloom filter bitfield |
| 1 | MD5 | 16-byte hash + 4-byte name_index (20 bytes each, sorted) |
| 2 | SHA256 | 32-byte hash + 4-byte name_index (36 bytes each, sorted) |
| 3 | CRC32 | region_type(1) + offset(4) + length(4) + crc(4) + name_index(4) |
| 4 | AHO_CORASICK | Serialized NFA automaton (node array + pattern table) |
| 5 | FUZZY_HASH | 128-byte ssdeep hash (null-padded) + 4-byte name_index |
| 6 | GRAPH_SIG | Sorted block hash arrays for CFG comparison |
| 7 | YARA | Concatenated YARA rule source (UTF-8) |
| 8 | WHITELIST | SHA-256 hashes of known-clean files |
| 0xFF | STRING_TABLE | Null-terminated name strings referenced by name_index |

### RSA Verification

Signed region: bytes 0x0000-0x0017 (header fields before RSA sig) + all section data. Verified with BCRYPT_RSA_ALGORITHM, PKCS#1 v1.5, SHA-256.

---

## 2. Service Protocol

**Pipe name:** `\\.\pipe\AkesoAVScan`
**Format:** Line-based text, `\r\n` terminated
**Buffer:** 8192 bytes max per message

### Commands

| Command | Response | Description |
|---------|----------|-------------|
| `SCAN <path>` | `210 SCAN DATA\r\n` + results + `200 SCAN OK\r\n` | Scan a file |
| `VERSION` | `220 AkesoAV v1.0.0 DB:vN (M sigs)\r\n` | Engine and DB version |
| `RELOAD` | `220 RELOAD OK\r\n` or `500 error\r\n` | Reload signature database |
| `STATS` | `220 <files> <detections> <cache_hits> <uptime>\r\n` | Runtime statistics |
| `PING` | `220 PONG\r\n` | Health check |
| `SCHEDULE LIST` | `220 N schedules\r\n` + entries + `200 OK\r\n` | List scheduled scans |
| `SCHEDULE RUN <name>` | `220 Scheduled run: <name>\r\n` | Trigger a schedule |
| `SCHEDULE STATUS` | `220 ACTIVE\|IDLE\r\n` | Scheduler state |
| `QUIT` | (connection closed) | Disconnect |

### Response Codes

| Code | Meaning |
|------|---------|
| 200 | OK (end of multi-line response) |
| 210 | Data follows |
| 220 | Status / informational |
| 500 | Error |

---

## 3. Update Protocol

### Flow

1. Client fetches `manifest.json` via HTTPS (with optional cert pinning)
2. Verify manifest RSA signature over JSON body (with `manifest_signature` = "")
3. Compare `manifest.version` vs current — skip if `<=`
4. Download each file in `manifest.files[]`
5. Verify SHA-256 hash of downloaded file
6. Verify RSA signature of downloaded file
7. Atomic install: write `.new` → backup current to `.prev` → swap `.new` to live

### Manifest Schema

```json
{
  "version": 42,
  "published_at": "2026-03-24T12:00:00Z",
  "minimum_engine_version": 1,
  "files": [{
    "name": "signatures.akavdb",
    "url": "https://update.example.com/signatures.akavdb",
    "sha256": "hex-encoded-sha256",
    "rsa_signature": "base64-encoded-rsa-2048",
    "size": 123456,
    "type": "full"
  }],
  "manifest_signature": "base64-encoded-rsa-2048"
}
```

### Security

- **Cert pinning**: SHA-256 fingerprint of server certificate checked in WinHTTP callback
- **RSA-2048**: Both manifest and files independently signed
- **SHA-256**: File integrity verified before installation
- **Atomic swap**: `MoveFileEx(MOVEFILE_REPLACE_EXISTING)` with `.prev` rollback

---

## 4. SIEM Event Schema

### Envelope (all events)

```json
{
  "event_id": "uuid-v4-string",
  "timestamp": "2026-03-24T15:30:00.456Z",
  "source_type": "akeso_av",
  "event_type": "av:scan_result",
  "agent_id": "HOSTNAME",
  "payload": { ... }
}
```

### Event Types

**av:scan_result**
```json
{
  "scan": { "result": "malicious", "scanner_id": "md5", "scan_type": "on_demand",
            "heuristic_score": 0.0, "duration_ms": 5 },
  "signature": { "name": "Trojan.Test", "id": "md5-42", "engine": "md5",
                 "db_version": "v42" },
  "file": { "path": "/path/to/file", "name": "test.exe", "type": "PE",
            "size": 4096, "hash": { "sha256": "hex" }, "in_whitelist": false }
}
```

**av:quarantine** — `action` (quarantined/restored/deleted), `vault_id`, `original_path`

**av:realtime_block** — `operation` (file_create/file_write), `denied`, process context

**av:signature_update** — `old_version`, `new_version`, `source`, `rsa_verified`

**av:scan_error** — `reason` (timeout/parser_crash/resource_limit), `stage`, file metadata

### Shipping

- **Local JSONL**: `C:\ProgramData\Akeso\Logs\akesoav.jsonl` (100MB rotation, 5 backups)
- **HTTP POST**: Configurable SIEM endpoint with API key header

---

## 5. EDR Integration API

AkesoAV exposes its engine as a shared library (`akesoav.dll`) for in-process integration:

```c
#include "akesoav.h"

// EDR creates engine once at startup
akav_engine_t* engine;
akav_engine_create(&engine);
akav_engine_init(engine, config_path);
akav_engine_load_signatures(engine, db_path);

// Minifilter callback: scan file buffer
akav_scan_result_t result;
akav_scan_options_t opts;
akav_scan_options_default(&opts);
akav_scan_buffer(engine, data, len, filename, &opts, &result);

if (result.found) {
    // Block file operation, emit telemetry
}

// Shutdown
akav_engine_destroy(engine);
```

The EDR's SIEM events include AV detection fields when `result.found == 1`, enabling cross-product correlation rules.
