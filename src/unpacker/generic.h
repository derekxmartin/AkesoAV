/* generic.h -- Emulation-based generic unpacker (P8-T4).
 *
 * Loads a PE into the x86 emulator, runs it with write tracking,
 * detects "write-then-jump" (>4KB written + EIP transfer to written
 * region), dumps the payload, validates as PE, and returns it for
 * re-scanning through the full pipeline.
 */

#ifndef AKAV_GENERIC_UNPACKER_H
#define AKAV_GENERIC_UNPACKER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────── */

#define AKAV_GUNPACK_WRITE_THRESHOLD   4096   /* min bytes written before jump triggers unpack */
#define AKAV_GUNPACK_MAX_OUTPUT        (64 * 1024 * 1024)  /* 64 MB max unpacked size */
#define AKAV_GUNPACK_EMU_MEM_SIZE      (0x7FFE0000u + 0x20000u)  /* covers stub region + TEB/PEB */

/* ── Result info ──────────────────────────────────────────────── */

typedef struct {
    bool     unpacked;            /* true if payload was recovered */
    uint32_t oep;                 /* original entry point (VA of jump target) */
    uint32_t payload_base;        /* VA where payload starts */
    uint32_t payload_size;        /* size of dumped region */
    uint32_t insn_count;          /* instructions executed before trigger */
    uint32_t api_calls;           /* number of API stubs invoked */
    uint32_t bytes_written;       /* total bytes written during emulation */
    char     error[128];          /* error message on failure */
} akav_gunpack_info_t;

/* ── Public API ───────────────────────────────────────────────── */

/**
 * Attempt to generically unpack a PE via emulation.
 *
 * Loads the PE into an emulator, executes with write tracking, and
 * watches for write-then-jump. If detected, dumps the target region
 * and validates it as a PE (MZ+PE signature).
 *
 * On success, *out_data is heap-allocated (caller must free) and
 * *out_len is set. info is populated with details.
 *
 * Returns true if an unpacked payload was recovered.
 */
bool akav_generic_unpack(const uint8_t* pe_data, size_t pe_len,
                          uint8_t** out_data, size_t* out_len,
                          akav_gunpack_info_t* info);

/**
 * Quick check: is this PE likely packed (has suspicious characteristics)?
 * Used as a pre-filter before expensive emulation.
 * Checks: high entropy in code section, few imports, UPX/ASPack/etc section names.
 */
bool akav_generic_is_likely_packed(const uint8_t* pe_data, size_t pe_len);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_GENERIC_UNPACKER_H */
