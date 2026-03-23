/* winapi_stubs.cpp — API stub table with dispatch and call logging.
 *
 * Each imported API is assigned a stub address in the stub region.
 * The stub is a 3-byte sequence: INT 0x2E; RET (CD 2E C3).
 * When the emulator hits INT 0x2E, the dispatcher:
 *   1. Reads the return address from the stack (which points past the stub)
 *   2. Looks up the stub that was called
 *   3. Logs the call with parameters from the stack
 *   4. Sets EAX to the default return value
 *   5. Lets the RET execute normally
 */

#include "emulator/winapi_stubs.h"
#include "emulator/x86_emu.h"
#include <cstring>
#include <cstdio>

/* ── Init ──────────────────────────────────────────────────────── */

void akav_stub_table_init(akav_stub_table_t* tbl)
{
    if (!tbl) return;
    memset(tbl, 0, sizeof(*tbl));
    tbl->next_addr = AKAV_STUB_REGION_BASE;
}

/* ── Add stub ──────────────────────────────────────────────────── */

uint32_t akav_stub_table_add(akav_stub_table_t* tbl,
                              const char* dll_name,
                              const char* func_name,
                              uint32_t default_ret)
{
    if (!tbl || !dll_name || !func_name) return 0;
    if (tbl->count >= AKAV_STUB_MAX_FUNCS) return 0;
    if (tbl->next_addr + AKAV_STUB_ENTRY_SIZE > AKAV_STUB_REGION_BASE + AKAV_STUB_REGION_SIZE)
        return 0;

    akav_stub_entry_t* e = &tbl->entries[tbl->count];
    snprintf(e->dll_name, sizeof(e->dll_name), "%s", dll_name);
    snprintf(e->func_name, sizeof(e->func_name), "%s", func_name);
    e->stub_addr = tbl->next_addr;
    e->default_ret = default_ret;

    tbl->next_addr += AKAV_STUB_ENTRY_SIZE;
    tbl->count++;

    return e->stub_addr;
}

/* ── Install stubs into emulator memory ───────────────────────── */

bool akav_stub_table_install(const akav_stub_table_t* tbl,
                              akav_x86_mem_t* mem)
{
    if (!tbl || !mem) return false;

    for (uint32_t i = 0; i < tbl->count; i++) {
        uint32_t addr = tbl->entries[i].stub_addr;
        /* INT 0x2E = CD 2E, RET = C3 */
        if (!akav_x86_mem_write8(mem, addr,     0xCD)) return false;
        if (!akav_x86_mem_write8(mem, addr + 1, 0x2E)) return false;
        if (!akav_x86_mem_write8(mem, addr + 2, 0xC3)) return false;
    }
    return true;
}

/* ── Lookup by address ────────────────────────────────────────── */

const akav_stub_entry_t* akav_stub_table_lookup(const akav_stub_table_t* tbl,
                                                  uint32_t addr)
{
    if (!tbl) return nullptr;
    for (uint32_t i = 0; i < tbl->count; i++) {
        if (tbl->entries[i].stub_addr == addr)
            return &tbl->entries[i];
    }
    return nullptr;
}

/* ── Dispatch INT 0x2E ────────────────────────────────────────── */

bool akav_stub_dispatch(akav_stub_table_t* tbl, akav_x86_emu_t* emu)
{
    if (!tbl || !emu) return false;

    /* The INT instruction already advanced EIP past "CD 2E" (2 bytes).
     * EIP now points at the RET (C3) of the stub.
     * The stub address = EIP - 2 (start of the INT 0x2E instruction).
     */
    uint32_t stub_addr = emu->regs.eip - 2;
    const akav_stub_entry_t* entry = akav_stub_table_lookup(tbl, stub_addr);
    if (!entry) return false;

    /* Read call parameters from stack.
     * The CALL instruction pushed the return address onto the stack.
     * Stack layout at this point:
     *   [ESP]   = return address (caller's next instruction)
     *   [ESP+4] = param1 (stdcall convention)
     *   [ESP+8] = param2
     *   etc.
     */
    uint32_t esp = emu->regs.reg[4];
    uint32_t params[AKAV_STUB_MAX_PARAMS] = {};
    for (int i = 0; i < AKAV_STUB_MAX_PARAMS; i++) {
        akav_x86_mem_read32(&emu->mem, esp + 4 + (uint32_t)(i * 4), &params[i]);
    }

    /* Log the call */
    if (tbl->log_count < AKAV_STUB_MAX_LOG) {
        akav_api_call_t* log = &tbl->log[tbl->log_count++];
        snprintf(log->dll_name, sizeof(log->dll_name), "%s", entry->dll_name);
        snprintf(log->func_name, sizeof(log->func_name), "%s", entry->func_name);
        memcpy(log->params, params, sizeof(params));
        log->return_value = entry->default_ret;

        /* Read return address = where the CALL was from */
        uint32_t ret_addr = 0;
        akav_x86_mem_read32(&emu->mem, esp, &ret_addr);
        log->call_addr = ret_addr;
    }

    /* Set return value in EAX */
    emu->regs.reg[0] = entry->default_ret;

    return true;
}

/* ── Get log ──────────────────────────────────────────────────── */

const akav_api_call_t* akav_stub_get_log(const akav_stub_table_t* tbl,
                                           uint32_t* count)
{
    if (!tbl) {
        if (count) *count = 0;
        return nullptr;
    }
    if (count) *count = tbl->log_count;
    return tbl->log;
}
