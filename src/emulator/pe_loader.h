#ifndef AKAV_PE_LOADER_H
#define AKAV_PE_LOADER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "emulator/x86_emu.h"
#include "emulator/winapi_stubs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────── */

/* TEB/PEB layout addresses */
#define AKAV_TEB_BASE           0x7FFD0000u
#define AKAV_PEB_BASE           0x7FFD1000u
#define AKAV_TEB_PEB_SIZE       0x00002000u  /* 8 KB for both */

/* Write tracking */
#define AKAV_WRITE_TRACK_MAX    256   /* max tracked write regions */

/* ── Write region tracker ─────────────────────────────────────── */

typedef struct {
    uint32_t start;
    uint32_t end;       /* exclusive */
} akav_write_region_t;

typedef struct {
    akav_write_region_t regions[AKAV_WRITE_TRACK_MAX];
    uint32_t            count;
    uint32_t            total_bytes_written;
} akav_write_tracker_t;

/* ── PE loader context ────────────────────────────────────────── */

typedef struct {
    uint32_t image_base;       /* VA where PE is loaded */
    uint32_t entry_point;      /* VA of entry point */
    uint32_t size_of_image;    /* total mapped size */

    /* Write tracking for unpacker detection */
    akav_write_tracker_t write_tracker;

    /* Back-pointers (not owned) */
    akav_x86_emu_t*    emu;
    akav_stub_table_t* stubs;
} akav_pe_loader_t;

/* ── Public API ───────────────────────────────────────────────── */

/**
 * Initialize a PE loader context.
 */
void akav_pe_loader_init(akav_pe_loader_t* loader);

/**
 * Load a PE into the emulator. This:
 *   1. Maps PE headers and sections at ImageBase
 *   2. Parses and resolves imports to stub addresses
 *   3. Sets up TEB/PEB at fixed addresses
 *   4. Sets EIP to the entry point
 *   5. Installs stub code in memory
 *
 * The emulator and stub table must be initialized before calling this.
 * Only supports 32-bit PE (PE32, machine=i386).
 *
 * Returns true on success.
 */
bool akav_pe_loader_load(akav_pe_loader_t* loader,
                          akav_x86_emu_t* emu,
                          akav_stub_table_t* stubs,
                          const uint8_t* pe_data,
                          size_t pe_len);

/**
 * Record a memory write for tracking.
 * Call this from the emulator's write hook.
 */
void akav_pe_loader_track_write(akav_pe_loader_t* loader,
                                 uint32_t addr, uint32_t size);

/**
 * Check if an address falls within a tracked write region.
 * Used to detect execution of dynamically-written code (unpackers).
 */
bool akav_pe_loader_is_written(const akav_pe_loader_t* loader,
                                uint32_t addr);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_PE_LOADER_H */
