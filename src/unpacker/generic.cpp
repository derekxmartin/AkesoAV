/* generic.cpp -- Emulation-based generic unpacker (P8-T4).
 *
 * Strategy:
 *   1. Load PE into x86 emulator via pe_loader
 *   2. Set up API stubs (INT 0x2E dispatch) and write tracking
 *   3. Run emulation step-by-step
 *   4. After each step, check if EIP landed in a tracked write region
 *      AND total bytes written >= 4KB threshold (write-then-jump)
 *   5. If triggered, scan forward from EIP looking for MZ+PE signature
 *   6. If found, dump the payload and return it
 */

#include "unpacker/generic.h"
#include "emulator/x86_emu.h"
#include "emulator/x86_decode.h"
#include "emulator/pe_loader.h"
#include "emulator/winapi_stubs.h"
#include "parsers/pe.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

/* ── INT callback for stub dispatch ──────────────────────────── */

struct gunpack_ctx_t {
    akav_pe_loader_t*  loader;
    akav_stub_table_t* stubs;
};

static bool gunpack_int_callback(akav_x86_emu_t* emu,
                                  uint8_t int_num,
                                  void* user_data)
{
    gunpack_ctx_t* ctx = (gunpack_ctx_t*)user_data;
    if (int_num == 0x2E)
        return akav_stub_dispatch(ctx->stubs, emu);
    return false;
}

/* ── Write callback for tracking ─────────────────────────────── */

static void gunpack_write_callback(akav_x86_emu_t* emu,
                                    uint32_t addr,
                                    uint32_t size,
                                    void* user_data)
{
    (void)emu;
    gunpack_ctx_t* ctx = (gunpack_ctx_t*)user_data;
    akav_pe_loader_track_write(ctx->loader, addr, size);
}

/* ── Find MZ+PE signature near an address ────────────────────── */

static bool find_pe_at(const akav_x86_mem_t* mem, uint32_t addr,
                        uint32_t* pe_base, uint32_t* pe_size)
{
    /* Search backwards from addr for MZ header (page-aligned) */
    uint32_t search_start = addr & ~0xFFFu;  /* align down to page */

    for (uint32_t base = search_start; base > 0 && base >= search_start - 0x10000;
         base -= 0x1000) {
        if (base + 2 > mem->size) continue;

        uint8_t mz0, mz1;
        if (!akav_x86_mem_read8(mem, base, &mz0)) continue;
        if (!akav_x86_mem_read8(mem, base + 1, &mz1)) continue;
        if (mz0 != 'M' || mz1 != 'Z') continue;

        /* Check e_lfanew and PE signature */
        uint32_t e_lfanew = 0;
        if (!akav_x86_mem_read32(mem, base + 0x3C, &e_lfanew)) continue;
        if (e_lfanew == 0 || e_lfanew > 0x1000) continue;

        uint32_t pe_sig_addr = base + e_lfanew;
        if (pe_sig_addr + 4 > mem->size) continue;

        uint8_t pe0, pe1, pe2, pe3;
        if (!akav_x86_mem_read8(mem, pe_sig_addr, &pe0)) continue;
        if (!akav_x86_mem_read8(mem, pe_sig_addr + 1, &pe1)) continue;
        if (!akav_x86_mem_read8(mem, pe_sig_addr + 2, &pe2)) continue;
        if (!akav_x86_mem_read8(mem, pe_sig_addr + 3, &pe3)) continue;

        if (pe0 == 'P' && pe1 == 'E' && pe2 == 0 && pe3 == 0) {
            *pe_base = base;

            /* Try to read SizeOfImage from optional header */
            /* COFF header is 20 bytes after PE sig, optional header follows */
            uint32_t opt_hdr = pe_sig_addr + 4 + 20;
            uint16_t opt_magic = 0;
            if (opt_hdr + 2 <= mem->size)
                akav_x86_mem_read16(mem, opt_hdr, &opt_magic);

            uint32_t size_of_image = 0;
            if (opt_magic == 0x10B) {
                /* PE32: SizeOfImage at optional header offset 56 */
                akav_x86_mem_read32(mem, opt_hdr + 56, &size_of_image);
            } else if (opt_magic == 0x20B) {
                /* PE32+: SizeOfImage at optional header offset 56 */
                akav_x86_mem_read32(mem, opt_hdr + 56, &size_of_image);
            }

            if (size_of_image > 0 && size_of_image <= AKAV_GUNPACK_MAX_OUTPUT &&
                (size_t)base + size_of_image <= mem->size) {
                *pe_size = size_of_image;
            } else {
                /* Fallback: dump from base to end of last write region */
                *pe_size = 0;
            }
            return true;
        }
    }

    /* Also check if EIP itself points at the start of a region with MZ */
    if (addr + 2 <= mem->size) {
        uint8_t mz0, mz1;
        if (akav_x86_mem_read8(mem, addr, &mz0) &&
            akav_x86_mem_read8(mem, addr + 1, &mz1) &&
            mz0 == 'M' && mz1 == 'Z') {
            *pe_base = addr;
            *pe_size = 0;
            return true;
        }
    }

    return false;
}

/* ── Dump memory region ──────────────────────────────────────── */

static uint8_t* dump_region(const akav_x86_mem_t* mem, uint32_t base,
                              uint32_t size, size_t* out_len)
{
    if (size == 0 || size > AKAV_GUNPACK_MAX_OUTPUT) return nullptr;
    if ((size_t)base + size > mem->size) return nullptr;

    uint8_t* buf = (uint8_t*)malloc(size);
    if (!buf) return nullptr;

    memcpy(buf, mem->data + base, size);
    *out_len = size;
    return buf;
}

/* ── Compute write region extent ─────────────────────────────── */

static uint32_t compute_write_extent(const akav_pe_loader_t* loader,
                                       uint32_t base)
{
    const akav_write_tracker_t* wt = &loader->write_tracker;
    uint32_t max_end = base;

    for (uint32_t i = 0; i < wt->count; i++) {
        if (wt->regions[i].start >= base && wt->regions[i].end > max_end)
            max_end = wt->regions[i].end;
    }

    return max_end - base;
}

/* ── Main unpacker ───────────────────────────────────────────── */

bool akav_generic_unpack(const uint8_t* pe_data, size_t pe_len,
                          uint8_t** out_data, size_t* out_len,
                          akav_gunpack_info_t* info)
{
    if (!pe_data || pe_len < 64 || !out_data || !out_len)
        return false;

    *out_data = nullptr;
    *out_len = 0;

    akav_gunpack_info_t local_info;
    memset(&local_info, 0, sizeof(local_info));

    /* Initialize emulator */
    akav_x86_emu_t emu;
    if (!akav_x86_emu_init(&emu, AKAV_GUNPACK_EMU_MEM_SIZE)) {
        if (info) {
            snprintf(info->error, sizeof(info->error), "emulator init failed");
        }
        return false;
    }

    /* Initialize stub table */
    akav_stub_table_t stubs;
    akav_stub_table_init(&stubs);

    /* Load PE */
    akav_pe_loader_t loader;
    if (!akav_pe_loader_load(&loader, &emu, &stubs, pe_data, pe_len)) {
        if (info) {
            snprintf(info->error, sizeof(info->error), "PE load failed");
        }
        akav_x86_emu_free(&emu);
        return false;
    }

    /* Set up callbacks */
    gunpack_ctx_t ctx;
    ctx.loader = &loader;
    ctx.stubs = &stubs;

    emu.int_callback = gunpack_int_callback;
    emu.int_callback_data = &ctx;
    emu.write_callback = gunpack_write_callback;
    emu.write_callback_data = &ctx;

    /* Step-by-step execution watching for write-then-jump */
    bool found = false;

    while (!emu.halted && emu.insn_count < emu.insn_limit) {
        int rc = akav_x86_emu_step(&emu);

        /* Check for write-then-jump:
         *   - Total bytes written exceeds threshold
         *   - Current EIP is within a tracked write region
         */
        if (loader.write_tracker.total_bytes_written >= AKAV_GUNPACK_WRITE_THRESHOLD &&
            akav_pe_loader_is_written(&loader, emu.regs.eip)) {

            /* Found write-then-jump! Try to find a PE at or near EIP */
            uint32_t pe_base = 0, pe_size = 0;

            if (find_pe_at(&emu.mem, emu.regs.eip, &pe_base, &pe_size)) {
                /* If SizeOfImage wasn't available, use write extent */
                if (pe_size == 0) {
                    pe_size = compute_write_extent(&loader, pe_base);
                    if (pe_size < 512) pe_size = 0x10000;  /* min reasonable PE */
                }

                /* Cap output size */
                if (pe_size > AKAV_GUNPACK_MAX_OUTPUT)
                    pe_size = AKAV_GUNPACK_MAX_OUTPUT;

                uint8_t* payload = dump_region(&emu.mem, pe_base, pe_size, out_len);
                if (payload) {
                    *out_data = payload;
                    local_info.unpacked = true;
                    local_info.oep = emu.regs.eip;
                    local_info.payload_base = pe_base;
                    local_info.payload_size = pe_size;
                    found = true;
                }
            } else {
                /* No PE header found, but still dump the written region
                 * starting from EIP as raw payload */
                uint32_t extent = compute_write_extent(&loader, emu.regs.eip);
                if (extent >= 512) {
                    uint8_t* payload = dump_region(&emu.mem, emu.regs.eip, extent, out_len);
                    if (payload) {
                        *out_data = payload;
                        local_info.unpacked = true;
                        local_info.oep = emu.regs.eip;
                        local_info.payload_base = emu.regs.eip;
                        local_info.payload_size = extent;
                        found = true;
                    }
                }
            }
            break;
        }

        if (rc != AKAV_EMU_OK) break;
    }

    /* Fill info */
    local_info.insn_count = emu.insn_count;
    local_info.bytes_written = loader.write_tracker.total_bytes_written;

    uint32_t log_count = 0;
    akav_stub_get_log(&stubs, &log_count);
    local_info.api_calls = log_count;

    if (!found && !local_info.error[0]) {
        snprintf(local_info.error, sizeof(local_info.error),
                 "no write-then-jump detected (halt=%d, writes=%u)",
                 emu.halt_reason, loader.write_tracker.total_bytes_written);
    }

    if (info) *info = local_info;

    akav_x86_emu_free(&emu);
    return found;
}

/* ── Likely-packed heuristic ─────────────────────────────────── */

bool akav_generic_is_likely_packed(const uint8_t* pe_data, size_t pe_len)
{
    if (!pe_data || pe_len < 64) return false;

    /* Check MZ */
    if (pe_data[0] != 'M' || pe_data[1] != 'Z') return false;

    /* Parse PE to check characteristics */
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    if (!akav_pe_parse(&pe, pe_data, pe_len)) {
        akav_pe_free(&pe);
        return false;
    }

    /* Only support 32-bit */
    if (pe.is_pe32plus || pe.machine != AKAV_PE_MACHINE_I386) {
        akav_pe_free(&pe);
        return false;
    }

    bool likely = false;

    /* Check for known packer section names */
    static const char* packer_sections[] = {
        "UPX0", "UPX1", "UPX2", ".aspack", ".adata",
        ".nsp0", ".nsp1", ".nsp2",              /* NSPack */
        ".MPRESS1", ".MPRESS2",                  /* MPRESS */
        ".petite",                                /* Petite */
        ".yP", ".y0da",                           /* yoda */
        ".themida", ".Themida",                   /* Themida */
        nullptr
    };

    for (uint16_t i = 0; i < pe.num_sections; i++) {
        for (const char** p = packer_sections; *p; p++) {
            if (strncmp(pe.sections[i].name, *p, 8) == 0) {
                likely = true;
                break;
            }
        }
        if (likely) break;
    }

    /* Check for very few imports (packers often have 1-3 imports) */
    if (!likely) {
        akav_pe_parse_imports(&pe, pe_data, pe_len);
        if (pe.num_import_dlls > 0 && pe.num_import_funcs <= 5) {
            likely = true;
        }
    }

    /* Check for high entropy in first code section */
    if (!likely) {
        for (uint16_t i = 0; i < pe.num_sections; i++) {
            if (pe.sections[i].characteristics & 0x20000000u) {  /* IMAGE_SCN_MEM_EXECUTE */
                if (pe.sections[i].entropy >= 7.0) {
                    likely = true;
                    break;
                }
            }
        }
    }

    akav_pe_free(&pe);
    return likely;
}
