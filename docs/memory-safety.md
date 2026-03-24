# Memory Safety in AkesoAV

## Overview

AkesoAV processes untrusted binary input (malware samples, archives, documents) where a single out-of-bounds read can crash the scanner or be exploited. This document describes the memory safety methodology used throughout the project.

## SafeReader Pattern

All file format parsers use `akav_safe_reader_t` (defined in `src/parsers/safe_reader.h`) instead of raw pointer arithmetic. Every read operation checks bounds before accessing memory:

```c
akav_safe_reader_t r;
akav_reader_init(&r, data, data_len);

uint32_t magic;
if (!akav_reader_read_u32_le(&r, &magic))
    return false;  // OOB — not a crash

uint16_t count;
if (!akav_reader_read_u16_le(&r, &count))
    return false;

if (!akav_reader_skip(&r, count * entry_size))
    return false;  // Would overflow — caught
```

**Functions provided:**
- `read_u8`, `read_u16_le/be`, `read_u32_le/be`, `read_u64_le/be` — typed reads
- `read_bytes` — bulk read with length check
- `skip`, `seek_to` — position management with bounds check
- `position`, `remaining` — query without side effects

**Parsers using SafeReader:** PE, ELF, PDF, ZIP, GZIP, TAR, OLE2, OOXML, CRC matcher, sigdb loader.

## MSVC /analyze + SAL Annotations

The build uses `/W4 /WX` (all warnings as errors) and SAL annotations on public API parameters:

```c
AKAV_API akav_error_t akav_scan_file(
    _In_ akav_engine_t* engine,
    _In_z_ const char* file_path,
    _In_ const akav_scan_options_t* options,
    _Out_ akav_scan_result_t* result);
```

`/analyze` (MSVC static analysis) runs as part of CI to catch:
- Null pointer dereferences
- Buffer overruns on annotated parameters
- Uninitialized variable usage
- Resource leaks (handles, memory)

## Clang-cl Fuzzing

Fuzz targets are built with `clang-cl` and AddressSanitizer + libFuzzer:

```powershell
cmake --preset fuzz
cmake --build build-fuzz --config Release
.\build-fuzz\Release\fuzz_pe.exe corpus_pe\ -max_len=65536
```

**Fuzz targets (9 total):**

| Target | Component | Coverage |
|--------|-----------|----------|
| `fuzz_pe` | PE parser | DOS header, COFF, optional header, sections, imports |
| `fuzz_elf` | ELF parser | ELF header, program headers, sections |
| `fuzz_pdf` | PDF parser | xref tables, stream decompression, JS extraction |
| `fuzz_zip` | ZIP parser | Local file headers, deflate, bomb detection |
| `fuzz_gzip` | GZIP parser | Header, inflate, CRC validation |
| `fuzz_ole2` | OLE2 parser | FAT/DIFAT chains, directory entries, VBA streams |
| `fuzz_x86_emu` | x86 emulator | Instruction execution, memory access, faults |
| `fuzz_x86_decode` | x86 decoder | Opcode parsing, ModR/M, SIB, prefixes |
| `fuzz_scan_buffer` | Full pipeline | End-to-end scan with all layers |

## Bugs Found During Development

### Bug 1: PE Section Table OOB Read

**Found by:** `fuzz_pe` (AddressSanitizer)

**Root cause:** When `NumberOfSections` in the COFF header claimed 96 sections but the file was only 512 bytes, the section table parser read past the end of the buffer.

**Fix:** Added bounds check in `parse_section_table()`:
```c
size_t table_size = (size_t)pe->num_sections * 40;
if (akav_reader_remaining(&r) < table_size) {
    pe_warn(pe, "Section table extends beyond file");
    pe->num_sections = (uint16_t)(akav_reader_remaining(&r) / 40);
}
```

### Bug 2: ZIP Decompression Integer Overflow

**Found by:** `fuzz_zip` (libFuzzer + ASan)

**Root cause:** A crafted ZIP entry with `uncompressed_size = 0xFFFFFFFF` and `compressed_size = 10` passed the ratio check (both were uint32, ratio computed as `uncomp / comp` which overflowed). The decompressor allocated 4GB and crashed.

**Fix:** Cast to uint64 before division and added explicit max size check:
```c
if (uncomp_size > AKAV_ZIP_MAX_DECOMPRESSED) {
    ctx->bomb_detected = true;
    continue;  // Skip entry
}
uint64_t ratio = (uint64_t)uncomp_size / (uint64_t)comp_size;
```

### Bug 3: PDF xref Stream Width Overflow

**Found by:** `/analyze` (MSVC static analysis)

**Root cause:** PDF xref stream `/W` array values were read as signed int but used as unsigned size. A negative width value (e.g., `/W [-1 0 0]`) caused a massive allocation.

**Fix:** Validate width values are in range [0, 8]:
```c
for (int i = 0; i < 3; i++) {
    if (widths[i] < 0 || widths[i] > 8) {
        pdf_warn(pdf, "Invalid xref stream width");
        return false;
    }
}
```

### Bug 4: x86 Emulator Stack Underflow

**Found by:** `fuzz_x86_emu`

**Root cause:** A `POP` instruction when ESP was at the top of the emulator's memory region caused an OOB read. The emulator didn't check if ESP + 4 exceeded the memory size.

**Fix:** Bounds check in stack operations:
```c
if (emu->regs.reg[4] + 4 > emu->mem.size)
    return emu_fault(emu, AKAV_EMU_HALT_FAULT, "stack underflow");
```

## Summary

| Technique | Coverage | Catches |
|-----------|----------|---------|
| SafeReader | All parsers | OOB reads, integer overflow on sizes |
| /W4 /WX | All code | Implicit conversions, unused vars, sign mismatches |
| SAL + /analyze | Public API | Null derefs, buffer overruns, resource leaks |
| libFuzzer + ASan | 9 fuzz targets | Heap overflow, use-after-free, stack overflow |
| Hardening tests | P11 suite | Parser crash resilience, emulator evasion |
