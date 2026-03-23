/* pe_loader.cpp — Load a PE into the x86 emulator for analysis.
 *
 * Maps PE sections at ImageBase, resolves imports to API stubs,
 * sets up TEB/PEB, configures write tracking for unpacker detection.
 */

#include "emulator/pe_loader.h"
#include "emulator/x86_emu.h"
#include "emulator/winapi_stubs.h"
#include "parsers/pe.h"
#include <cstring>
#include <cstdio>

/* ── Common default return values for known APIs ──────────────── */

static uint32_t get_default_return(const char* dll, const char* func)
{
    (void)dll;

    /* Memory allocation: return a plausible heap address */
    if (strcmp(func, "VirtualAlloc") == 0 ||
        strcmp(func, "GlobalAlloc") == 0 ||
        strcmp(func, "HeapAlloc") == 0 ||
        strcmp(func, "LocalAlloc") == 0 ||
        strcmp(func, "malloc") == 0)
        return 0x00800000u;  /* plausible heap pointer */

    /* Process/module handles */
    if (strcmp(func, "GetModuleHandleA") == 0 ||
        strcmp(func, "GetModuleHandleW") == 0)
        return 0x00400000u;  /* typical ImageBase */

    if (strcmp(func, "GetCurrentProcess") == 0)
        return 0xFFFFFFFFu;  /* pseudo-handle */

    if (strcmp(func, "GetCurrentProcessId") == 0 ||
        strcmp(func, "GetCurrentThreadId") == 0)
        return 1000;

    if (strcmp(func, "GetProcessHeap") == 0)
        return 0x00700000u;

    /* GetProcAddress: return a non-zero stub address */
    if (strcmp(func, "GetProcAddress") == 0)
        return 0x7FFE8000u;

    /* LoadLibrary: return a non-zero module handle */
    if (strcmp(func, "LoadLibraryA") == 0 ||
        strcmp(func, "LoadLibraryW") == 0 ||
        strcmp(func, "LoadLibraryExA") == 0 ||
        strcmp(func, "LoadLibraryExW") == 0)
        return 0x10000000u;

    /* Success indicators */
    if (strcmp(func, "VirtualProtect") == 0 ||
        strcmp(func, "VirtualFree") == 0 ||
        strcmp(func, "CloseHandle") == 0 ||
        strcmp(func, "FreeLibrary") == 0)
        return 1;  /* TRUE */

    /* Default: return 0 (NULL / FALSE) */
    return 0;
}

/* ── Init ──────────────────────────────────────────────────────── */

void akav_pe_loader_init(akav_pe_loader_t* loader)
{
    if (!loader) return;
    memset(loader, 0, sizeof(*loader));
}

/* ── Set up TEB/PEB ───────────────────────────────────────────── */

static bool setup_teb_peb(akav_x86_emu_t* emu)
{
    /* Minimal TEB at AKAV_TEB_BASE:
     *   +0x00: SEH chain = 0xFFFFFFFF (end of chain)
     *   +0x04: Stack top
     *   +0x08: Stack bottom
     *   +0x18: TEB self-pointer (fs:[0x18])
     *   +0x24: Thread ID
     *   +0x30: PEB pointer (fs:[0x30])
     */
    if (!akav_x86_mem_write32(&emu->mem, AKAV_TEB_BASE + 0x00, 0xFFFFFFFFu))
        return false;
    if (!akav_x86_mem_write32(&emu->mem, AKAV_TEB_BASE + 0x04, emu->regs.reg[4]))
        return false;
    if (!akav_x86_mem_write32(&emu->mem, AKAV_TEB_BASE + 0x08, 0x00010000u))
        return false;
    if (!akav_x86_mem_write32(&emu->mem, AKAV_TEB_BASE + 0x18, AKAV_TEB_BASE))
        return false;
    if (!akav_x86_mem_write32(&emu->mem, AKAV_TEB_BASE + 0x24, 1000))
        return false;
    if (!akav_x86_mem_write32(&emu->mem, AKAV_TEB_BASE + 0x30, AKAV_PEB_BASE))
        return false;

    /* Minimal PEB at AKAV_PEB_BASE:
     *   +0x02: IsDebugged = 0
     *   +0x08: ImageBaseAddress
     *   +0x0C: Ldr = 0 (not populated)
     */
    if (!akav_x86_mem_write8(&emu->mem, AKAV_PEB_BASE + 0x02, 0))
        return false;
    /* ImageBaseAddress set by caller after parsing PE */

    return true;
}

/* ── Map PE sections ──────────────────────────────────────────── */

static bool map_sections(akav_x86_emu_t* emu, const akav_pe_t* pe,
                          const uint8_t* pe_data, size_t pe_len,
                          uint32_t image_base)
{
    /* Map PE headers (first page) */
    uint32_t header_size = pe->size_of_headers;
    if (header_size > pe_len) header_size = (uint32_t)pe_len;
    if (header_size > 0x1000) header_size = 0x1000;
    if (!akav_x86_emu_load(emu, image_base, pe_data, header_size))
        return false;

    /* Map each section */
    for (uint16_t i = 0; i < pe->num_sections; i++) {
        const akav_pe_section_t* sec = &pe->sections[i];
        if (sec->raw_data_size == 0 || sec->raw_data_offset == 0)
            continue;

        uint32_t raw_off = sec->raw_data_offset;
        uint32_t raw_sz = sec->raw_data_size;

        /* Bounds check against PE file */
        if (raw_off >= pe_len) continue;
        if (raw_off + raw_sz > pe_len)
            raw_sz = (uint32_t)(pe_len - raw_off);

        uint32_t va = image_base + sec->virtual_address;

        /* Bounds check against emulator memory */
        if ((size_t)va + raw_sz > emu->mem.size)
            continue;

        if (!akav_x86_emu_load(emu, va, pe_data + raw_off, raw_sz))
            return false;
    }
    return true;
}

/* ── Resolve imports ──────────────────────────────────────────── */

static bool resolve_imports(akav_x86_emu_t* emu, const akav_pe_t* pe,
                             const uint8_t* pe_data, size_t pe_len,
                             akav_stub_table_t* stubs,
                             uint32_t image_base)
{
    if (!pe->import_dlls || pe->num_import_dlls == 0)
        return true;  /* no imports is OK */

    /* Walk each imported DLL */
    for (uint32_t d = 0; d < pe->num_import_dlls; d++) {
        const akav_pe_import_dll_t* dll = &pe->import_dlls[d];

        for (uint32_t f = 0; f < dll->num_functions; f++) {
            uint32_t func_idx = dll->first_func_index + f;
            if (func_idx >= pe->num_import_funcs) break;

            const akav_pe_import_func_t* fn = &pe->import_funcs[func_idx];
            const char* name = fn->is_ordinal ? "ordinal" : fn->name;

            uint32_t default_ret = get_default_return(dll->dll_name, name);
            akav_stub_table_add(stubs, dll->dll_name, name, default_ret);
        }
    }

    /* Now patch the IAT in emulator memory.
     *
     * The IAT is at the Import Directory's FirstThunk RVA. We need to read
     * the original PE to find each descriptor, then overwrite the IAT entries
     * with our stub addresses.
     *
     * We use the Import Directory from data_dirs to locate descriptors.
     */
    uint32_t import_rva = pe->data_dirs[AKAV_PE_DIR_IMPORT].virtual_address;
    uint32_t import_size = pe->data_dirs[AKAV_PE_DIR_IMPORT].size;
    if (import_rva == 0 || import_size == 0) return true;

    uint32_t import_off = akav_pe_rva_to_offset(pe, import_rva);
    if (import_off == 0) return true;

    /* Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each) */
    uint32_t stub_idx = 0;
    uint32_t desc_off = import_off;
    while (desc_off + 20 <= pe_len) {
        /* Read FirstThunk (IAT) RVA at offset +16 in descriptor */
        uint32_t first_thunk_rva = 0;
        if (desc_off + 19 < pe_len) {
            first_thunk_rva = (uint32_t)pe_data[desc_off + 16] |
                              ((uint32_t)pe_data[desc_off + 17] << 8) |
                              ((uint32_t)pe_data[desc_off + 18] << 16) |
                              ((uint32_t)pe_data[desc_off + 19] << 24);
        }

        /* Check for null descriptor (end of import table) */
        uint32_t orig_first_thunk = (uint32_t)pe_data[desc_off] |
                                    ((uint32_t)pe_data[desc_off + 1] << 8) |
                                    ((uint32_t)pe_data[desc_off + 2] << 16) |
                                    ((uint32_t)pe_data[desc_off + 3] << 24);
        if (orig_first_thunk == 0 && first_thunk_rva == 0) break;

        if (first_thunk_rva != 0) {
            /* Walk the IAT entries and patch with stub addresses */
            uint32_t iat_va = image_base + first_thunk_rva;
            uint32_t entry_idx = 0;
            while (true) {
                uint32_t iat_entry = 0;
                if (!akav_x86_mem_read32(&emu->mem, iat_va + entry_idx * 4, &iat_entry))
                    break;
                if (iat_entry == 0) break;

                /* Patch with stub address */
                if (stub_idx < stubs->count) {
                    akav_x86_mem_write32(&emu->mem, iat_va + entry_idx * 4,
                                         stubs->entries[stub_idx].stub_addr);
                    stub_idx++;
                }
                entry_idx++;
            }
        }
        desc_off += 20;
    }

    return true;
}

/* ── Load PE ──────────────────────────────────────────────────── */

bool akav_pe_loader_load(akav_pe_loader_t* loader,
                          akav_x86_emu_t* emu,
                          akav_stub_table_t* stubs,
                          const uint8_t* pe_data,
                          size_t pe_len)
{
    if (!loader || !emu || !stubs || !pe_data || pe_len < 64)
        return false;

    akav_pe_loader_init(loader);
    loader->emu = emu;
    loader->stubs = stubs;

    /* Parse the PE */
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    if (!akav_pe_parse(&pe, pe_data, pe_len)) {
        akav_pe_free(&pe);
        return false;
    }

    /* Only support 32-bit PE */
    if (pe.is_pe32plus || pe.machine != AKAV_PE_MACHINE_I386) {
        akav_pe_free(&pe);
        return false;
    }

    loader->image_base = (uint32_t)pe.image_base;
    loader->entry_point = loader->image_base + pe.entry_point;
    loader->size_of_image = pe.size_of_image;

    /* Map sections into emulator memory */
    if (!map_sections(emu, &pe, pe_data, pe_len, loader->image_base)) {
        akav_pe_free(&pe);
        return false;
    }

    /* Parse and resolve imports */
    akav_pe_parse_imports(&pe, pe_data, pe_len);
    if (!resolve_imports(emu, &pe, pe_data, pe_len, stubs, loader->image_base)) {
        akav_pe_free(&pe);
        return false;
    }

    /* Install stub code in memory */
    if (!akav_stub_table_install(stubs, &emu->mem)) {
        akav_pe_free(&pe);
        return false;
    }

    /* Set up TEB/PEB */
    if (!setup_teb_peb(emu)) {
        akav_pe_free(&pe);
        return false;
    }

    /* Write ImageBase to PEB+0x08 */
    akav_x86_mem_write32(&emu->mem, AKAV_PEB_BASE + 0x08, loader->image_base);

    /* Set EIP to entry point */
    emu->regs.eip = loader->entry_point;

    akav_pe_free(&pe);
    return true;
}

/* ── Write tracking ───────────────────────────────────────────── */

void akav_pe_loader_track_write(akav_pe_loader_t* loader,
                                 uint32_t addr, uint32_t size)
{
    if (!loader || size == 0) return;

    akav_write_tracker_t* wt = &loader->write_tracker;
    uint32_t end = addr + size;
    wt->total_bytes_written += size;

    /* Try to merge with an existing region */
    for (uint32_t i = 0; i < wt->count; i++) {
        if (addr <= wt->regions[i].end && end >= wt->regions[i].start) {
            /* Overlapping or adjacent — extend */
            if (addr < wt->regions[i].start) wt->regions[i].start = addr;
            if (end > wt->regions[i].end)   wt->regions[i].end = end;
            return;
        }
    }

    /* Add new region */
    if (wt->count < AKAV_WRITE_TRACK_MAX) {
        wt->regions[wt->count].start = addr;
        wt->regions[wt->count].end = end;
        wt->count++;
    }
}

bool akav_pe_loader_is_written(const akav_pe_loader_t* loader,
                                uint32_t addr)
{
    if (!loader) return false;
    const akav_write_tracker_t* wt = &loader->write_tracker;
    for (uint32_t i = 0; i < wt->count; i++) {
        if (addr >= wt->regions[i].start && addr < wt->regions[i].end)
            return true;
    }
    return false;
}
