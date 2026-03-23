#ifndef AKAV_WINAPI_STUBS_H
#define AKAV_WINAPI_STUBS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "emulator/x86_emu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────── */

#define AKAV_STUB_MAX_FUNCS      512    /* max stub functions */
#define AKAV_STUB_MAX_LOG        4096   /* max API call log entries */
#define AKAV_STUB_MAX_NAME       64     /* max DLL/function name */
#define AKAV_STUB_MAX_PARAMS     6      /* params logged per call */

/* Stub region: each stub is 3 bytes (INT 0x2E; RET) */
#define AKAV_STUB_REGION_BASE    0x7FFE0000u
#define AKAV_STUB_REGION_SIZE    0x00010000u  /* 64 KB */
#define AKAV_STUB_ENTRY_SIZE     3            /* CD 2E C3 */

/* ── API call log entry ───────────────────────────────────────── */

typedef struct {
    char     dll_name[AKAV_STUB_MAX_NAME];
    char     func_name[AKAV_STUB_MAX_NAME];
    uint32_t params[AKAV_STUB_MAX_PARAMS];
    uint32_t return_value;
    uint32_t call_addr;     /* EIP at time of CALL */
} akav_api_call_t;

/* ── Stub table entry ─────────────────────────────────────────── */

typedef struct {
    char     dll_name[AKAV_STUB_MAX_NAME];
    char     func_name[AKAV_STUB_MAX_NAME];
    uint32_t stub_addr;     /* address in emulator memory */
    uint32_t default_ret;   /* value to put in EAX on return */
} akav_stub_entry_t;

/* ── Stub table ───────────────────────────────────────────────── */

typedef struct {
    akav_stub_entry_t entries[AKAV_STUB_MAX_FUNCS];
    uint32_t          count;
    uint32_t          next_addr;  /* next free stub address */

    /* API call log */
    akav_api_call_t   log[AKAV_STUB_MAX_LOG];
    uint32_t          log_count;
} akav_stub_table_t;

/* ── Public API ───────────────────────────────────────────────── */

/**
 * Initialize the stub table. Call before adding stubs.
 */
void akav_stub_table_init(akav_stub_table_t* tbl);

/**
 * Register a stub for a DLL/function pair. Returns the stub address,
 * or 0 on failure (table full).
 */
uint32_t akav_stub_table_add(akav_stub_table_t* tbl,
                              const char* dll_name,
                              const char* func_name,
                              uint32_t default_ret);

/**
 * Write all stub code (INT 0x2E; RET) into emulator memory.
 * Must be called after all stubs are added and before execution.
 */
bool akav_stub_table_install(const akav_stub_table_t* tbl,
                              akav_x86_mem_t* mem);

/**
 * Look up a stub by its address. Returns the entry, or NULL.
 */
const akav_stub_entry_t* akav_stub_table_lookup(const akav_stub_table_t* tbl,
                                                  uint32_t addr);

/**
 * Handle an INT 0x2E from the emulator.
 * Looks up the return address on stack to find which stub was called,
 * logs the call with parameters, sets EAX to default return value,
 * and returns true. Returns false if the call is unknown.
 */
bool akav_stub_dispatch(akav_stub_table_t* tbl, akav_x86_emu_t* emu);

/**
 * Get the API call log.
 */
const akav_api_call_t* akav_stub_get_log(const akav_stub_table_t* tbl,
                                           uint32_t* count);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_WINAPI_STUBS_H */
