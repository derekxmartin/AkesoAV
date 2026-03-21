#include "pe.h"
#include "safe_reader.h"
#include <string.h>

/* ── Error / warning helpers ─────────────────────────────────────── */

static void pe_error(akav_pe_t* pe, const char* msg)
{
    pe->valid = false;
    strncpy_s(pe->error, sizeof(pe->error), msg, _TRUNCATE);
}

static void pe_warn(akav_pe_t* pe, const char* msg)
{
    if (pe->warning_count < 4) {
        strncpy_s(pe->warnings[pe->warning_count],
                  sizeof(pe->warnings[0]), msg, _TRUNCATE);
        pe->warning_count++;
    }
}

/* ── Parse DOS header ────────────────────────────────────────────── */

static bool parse_dos_header(akav_pe_t* pe, akav_safe_reader_t* r)
{
    if (!akav_reader_read_u16_le(r, &pe->dos_magic)) {
        pe_error(pe, "Truncated DOS header (too small for e_magic)");
        return false;
    }

    if (pe->dos_magic != AKAV_PE_DOS_MAGIC) {
        pe_error(pe, "Invalid DOS magic (expected MZ)");
        return false;
    }

    /* e_lfanew is at offset 0x3C in the DOS header */
    if (!akav_reader_seek_to(r, 0x3C)) {
        pe_error(pe, "Truncated DOS header (too small for e_lfanew)");
        return false;
    }

    if (!akav_reader_read_u32_le(r, &pe->e_lfanew)) {
        pe_error(pe, "Truncated DOS header (cannot read e_lfanew)");
        return false;
    }

    /* Sanity: e_lfanew should be reasonable */
    if (pe->e_lfanew < 0x40) {
        pe_warn(pe, "e_lfanew unusually small (< 0x40)");
    }

    if (pe->e_lfanew > 0x10000) {
        pe_error(pe, "e_lfanew too large (> 64K)");
        return false;
    }

    return true;
}

/* ── Parse PE signature + COFF header ────────────────────────────── */

static bool parse_coff_header(akav_pe_t* pe, akav_safe_reader_t* r)
{
    if (!akav_reader_seek_to(r, pe->e_lfanew)) {
        pe_error(pe, "Cannot seek to PE signature (e_lfanew past EOF)");
        return false;
    }

    /* PE signature: "PE\0\0" = 0x00004550 */
    uint32_t pe_sig;
    if (!akav_reader_read_u32_le(r, &pe_sig)) {
        pe_error(pe, "Truncated PE signature");
        return false;
    }

    if (pe_sig != AKAV_PE_SIGNATURE) {
        pe_error(pe, "Invalid PE signature (expected PE\\0\\0)");
        return false;
    }

    /* COFF header: 20 bytes */
    if (!akav_reader_read_u16_le(r, &pe->machine)) {
        pe_error(pe, "Truncated COFF header (machine)");
        return false;
    }

    if (!akav_reader_read_u16_le(r, &pe->num_sections)) {
        pe_error(pe, "Truncated COFF header (num_sections)");
        return false;
    }

    if (pe->num_sections == 0) {
        pe_error(pe, "Zero sections in COFF header");
        return false;
    }

    if (pe->num_sections > AKAV_PE_MAX_SECTIONS) {
        pe_error(pe, "Section count exceeds maximum (96)");
        return false;
    }

    if (!akav_reader_read_u32_le(r, &pe->timestamp))       { pe_error(pe, "Truncated COFF header (timestamp)"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->symbol_table_offset)) { pe_error(pe, "Truncated COFF header (symbol_table)"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->num_symbols))      { pe_error(pe, "Truncated COFF header (num_symbols)"); return false; }
    if (!akav_reader_read_u16_le(r, &pe->optional_header_size)) { pe_error(pe, "Truncated COFF header (opt_hdr_size)"); return false; }
    if (!akav_reader_read_u16_le(r, &pe->characteristics))  { pe_error(pe, "Truncated COFF header (characteristics)"); return false; }

    return true;
}

/* ── Parse optional header ───────────────────────────────────────── */

static bool parse_optional_header(akav_pe_t* pe, akav_safe_reader_t* r)
{
    if (pe->optional_header_size == 0) {
        pe_warn(pe, "No optional header present");
        return true; /* valid but unusual */
    }

    /* Remember start of optional header for bounds checking */
    size_t opt_start = akav_reader_position(r);

    /* Magic: PE32 (0x10B) or PE32+ (0x20B) */
    if (!akav_reader_read_u16_le(r, &pe->opt_magic)) {
        pe_error(pe, "Truncated optional header (magic)");
        return false;
    }

    if (pe->opt_magic == AKAV_PE_OPT_MAGIC_64) {
        pe->is_pe32plus = true;
    } else if (pe->opt_magic == AKAV_PE_OPT_MAGIC_32) {
        pe->is_pe32plus = false;
    } else {
        pe_error(pe, "Unknown optional header magic");
        return false;
    }

    /* Standard fields */
    if (!akav_reader_read_u8(r, &pe->major_linker))     { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u8(r, &pe->minor_linker))     { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->size_of_code)) { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->size_of_init_data))   { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->size_of_uninit_data)) { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->entry_point))  { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->base_of_code)) { pe_error(pe, "Truncated optional header"); return false; }

    if (!pe->is_pe32plus) {
        /* PE32: BaseOfData (4 bytes) + ImageBase (4 bytes) */
        if (!akav_reader_read_u32_le(r, &pe->base_of_data)) { pe_error(pe, "Truncated optional header"); return false; }
        uint32_t ib32;
        if (!akav_reader_read_u32_le(r, &ib32))             { pe_error(pe, "Truncated optional header"); return false; }
        pe->image_base = ib32;
    } else {
        /* PE32+: no BaseOfData, ImageBase is 8 bytes */
        pe->base_of_data = 0;
        if (!akav_reader_read_u64_le(r, &pe->image_base))   { pe_error(pe, "Truncated optional header"); return false; }
    }

    /* Windows-specific fields */
    if (!akav_reader_read_u32_le(r, &pe->section_alignment)) { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->file_alignment))    { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u16_le(r, &pe->major_os_version))  { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u16_le(r, &pe->minor_os_version))  { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u16_le(r, &pe->major_image_version))     { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u16_le(r, &pe->minor_image_version))     { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u16_le(r, &pe->major_subsystem_version)) { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u16_le(r, &pe->minor_subsystem_version)) { pe_error(pe, "Truncated optional header"); return false; }

    uint32_t win32_version_value;
    if (!akav_reader_read_u32_le(r, &win32_version_value)) { pe_error(pe, "Truncated optional header"); return false; }

    if (!akav_reader_read_u32_le(r, &pe->size_of_image))    { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->size_of_headers))   { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->checksum))          { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u16_le(r, &pe->subsystem))         { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u16_le(r, &pe->dll_characteristics)) { pe_error(pe, "Truncated optional header"); return false; }

    if (!pe->is_pe32plus) {
        /* PE32: 4-byte size fields */
        uint32_t v32;
        if (!akav_reader_read_u32_le(r, &v32)) { pe_error(pe, "Truncated optional header"); return false; }
        pe->stack_reserve = v32;
        if (!akav_reader_read_u32_le(r, &v32)) { pe_error(pe, "Truncated optional header"); return false; }
        pe->stack_commit = v32;
        if (!akav_reader_read_u32_le(r, &v32)) { pe_error(pe, "Truncated optional header"); return false; }
        pe->heap_reserve = v32;
        if (!akav_reader_read_u32_le(r, &v32)) { pe_error(pe, "Truncated optional header"); return false; }
        pe->heap_commit = v32;
    } else {
        /* PE32+: 8-byte size fields */
        if (!akav_reader_read_u64_le(r, &pe->stack_reserve)) { pe_error(pe, "Truncated optional header"); return false; }
        if (!akav_reader_read_u64_le(r, &pe->stack_commit))  { pe_error(pe, "Truncated optional header"); return false; }
        if (!akav_reader_read_u64_le(r, &pe->heap_reserve))  { pe_error(pe, "Truncated optional header"); return false; }
        if (!akav_reader_read_u64_le(r, &pe->heap_commit))   { pe_error(pe, "Truncated optional header"); return false; }
    }

    if (!akav_reader_read_u32_le(r, &pe->loader_flags))     { pe_error(pe, "Truncated optional header"); return false; }
    if (!akav_reader_read_u32_le(r, &pe->num_data_dirs))     { pe_error(pe, "Truncated optional header"); return false; }

    /* Cap data directories to prevent reading garbage */
    if (pe->num_data_dirs > AKAV_PE_MAX_DATA_DIRS) {
        pe_warn(pe, "NumberOfRvaAndSizes capped to 16");
        pe->num_data_dirs = AKAV_PE_MAX_DATA_DIRS;
    }

    /* Read data directories */
    for (uint32_t i = 0; i < pe->num_data_dirs; i++) {
        if (!akav_reader_read_u32_le(r, &pe->data_dirs[i].virtual_address) ||
            !akav_reader_read_u32_le(r, &pe->data_dirs[i].size)) {
            pe_warn(pe, "Data directory table truncated");
            pe->num_data_dirs = i;
            break;
        }
    }

    /* Verify we consumed approximately optional_header_size bytes */
    size_t consumed = akav_reader_position(r) - opt_start;
    if (consumed < pe->optional_header_size) {
        /* Skip remaining optional header bytes we didn't parse */
        size_t skip = pe->optional_header_size - consumed;
        if (!akav_reader_skip(r, skip)) {
            pe_warn(pe, "Could not skip to end of optional header");
        }
    }

    return true;
}

/* ── Parse section table ─────────────────────────────────────────── */

static bool parse_section_table(akav_pe_t* pe, akav_safe_reader_t* r)
{
    for (uint16_t i = 0; i < pe->num_sections; i++) {
        akav_pe_section_t* sec = &pe->sections[i];

        /* Section name: 8 bytes (not necessarily null-terminated) */
        uint8_t name_bytes[AKAV_PE_SECTION_NAME_LEN];
        if (!akav_reader_read_bytes(r, name_bytes, AKAV_PE_SECTION_NAME_LEN)) {
            pe_error(pe, "Truncated section table");
            return false;
        }
        memcpy(sec->name, name_bytes, AKAV_PE_SECTION_NAME_LEN);
        sec->name[AKAV_PE_SECTION_NAME_LEN] = '\0';

        if (!akav_reader_read_u32_le(r, &sec->virtual_size))    { pe_error(pe, "Truncated section table"); return false; }
        if (!akav_reader_read_u32_le(r, &sec->virtual_address))  { pe_error(pe, "Truncated section table"); return false; }
        if (!akav_reader_read_u32_le(r, &sec->raw_data_size))    { pe_error(pe, "Truncated section table"); return false; }
        if (!akav_reader_read_u32_le(r, &sec->raw_data_offset))  { pe_error(pe, "Truncated section table"); return false; }

        /* Skip: relocations_offset(4), linenumbers_offset(4),
                 num_relocations(2), num_linenumbers(2) */
        if (!akav_reader_skip(r, 12)) { pe_error(pe, "Truncated section table"); return false; }

        if (!akav_reader_read_u32_le(r, &sec->characteristics))  { pe_error(pe, "Truncated section table"); return false; }
    }

    return true;
}

/* ── Public API ──────────────────────────────────────────────────── */

bool akav_pe_parse(akav_pe_t* pe, const uint8_t* data, size_t data_len)
{
    if (!pe) return false;
    memset(pe, 0, sizeof(*pe));

    if (!data || data_len == 0) {
        pe_error(pe, "Empty or null buffer");
        return false;
    }

    akav_safe_reader_t r;
    akav_reader_init(&r, data, data_len);

    if (!parse_dos_header(pe, &r))      return false;
    if (!parse_coff_header(pe, &r))     return false;
    if (!parse_optional_header(pe, &r)) return false;
    if (!parse_section_table(pe, &r))   return false;

    pe->valid = true;
    return true;
}

const char* akav_pe_machine_name(uint16_t machine)
{
    switch (machine) {
        case AKAV_PE_MACHINE_I386:  return "i386";
        case AKAV_PE_MACHINE_AMD64: return "AMD64";
        case AKAV_PE_MACHINE_ARM:   return "ARM";
        case AKAV_PE_MACHINE_ARM64: return "ARM64";
        default:                    return "Unknown";
    }
}

const akav_pe_section_t* akav_pe_find_section(const akav_pe_t* pe,
                                                const char* name)
{
    if (!pe || !name || !pe->valid) return NULL;

    for (uint16_t i = 0; i < pe->num_sections; i++) {
        if (strncmp(pe->sections[i].name, name, AKAV_PE_SECTION_NAME_LEN) == 0)
            return &pe->sections[i];
    }
    return NULL;
}

uint32_t akav_pe_rva_to_offset(const akav_pe_t* pe, uint32_t rva)
{
    if (!pe || !pe->valid) return 0;

    for (uint16_t i = 0; i < pe->num_sections; i++) {
        const akav_pe_section_t* sec = &pe->sections[i];
        uint32_t sec_end = sec->virtual_address + sec->virtual_size;
        if (rva >= sec->virtual_address && rva < sec_end) {
            return sec->raw_data_offset + (rva - sec->virtual_address);
        }
    }
    return 0;
}
