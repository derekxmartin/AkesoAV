/* fuzz_x86_emu.cpp — libFuzzer target for x86 emulator + PE loader.
 * Build with: cmake --preset fuzz && cmake --build build-fuzz
 *
 * Treats arbitrary input as a "PE file", loads it through the PE loader
 * into the emulator, and executes with a 10K instruction limit.
 * Exercises PE parsing, section mapping, import resolution, stub
 * dispatch, memory access, and all instruction handlers.
 */

#include "emulator/x86_emu.h"
#include "emulator/pe_loader.h"
#include "emulator/winapi_stubs.h"
#include <cstdint>
#include <cstddef>

/* INT callback for API stub dispatch during fuzzing */
static bool fuzz_int_callback(akav_x86_emu_t* emu,
                               uint8_t int_num,
                               void* user_data)
{
    akav_stub_table_t* tbl = (akav_stub_table_t*)user_data;
    if (int_num == 0x2E)
        return akav_stub_dispatch(tbl, emu);
    return false;
}

/* Write callback for tracking (exercises write tracker code paths) */
static void fuzz_write_callback(akav_x86_emu_t* emu,
                                 uint32_t addr,
                                 uint32_t size,
                                 void* user_data)
{
    (void)emu;
    akav_pe_loader_t* loader = (akav_pe_loader_t*)user_data;
    akav_pe_loader_track_write(loader, addr, size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 64) return 0;  /* too small to be a PE */

    /* Initialize emulator with enough memory for PE + stubs + TEB/PEB */
    akav_x86_emu_t emu;
    if (!akav_x86_emu_init(&emu, 0x7FFE0000u + 0x20000u))
        return 0;

    /* Tight instruction limit for fuzzing — 10K steps */
    emu.insn_limit = 10000;

    akav_stub_table_t stubs;
    akav_stub_table_init(&stubs);

    akav_pe_loader_t loader;
    if (!akav_pe_loader_load(&loader, &emu, &stubs, data, size)) {
        akav_x86_emu_free(&emu);
        return 0;
    }

    /* Hook callbacks */
    emu.int_callback = fuzz_int_callback;
    emu.int_callback_data = &stubs;
    emu.write_callback = fuzz_write_callback;
    emu.write_callback_data = &loader;

    /* Run emulation */
    akav_x86_emu_run(&emu);

    /* Exercise post-run queries */
    akav_pe_loader_is_written(&loader, emu.regs.eip);

    uint32_t log_count = 0;
    akav_stub_get_log(&stubs, &log_count);

    akav_x86_emu_free(&emu);
    return 0;
}
