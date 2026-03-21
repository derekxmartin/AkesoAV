#include "pe.h"
#include "safe_reader.h"
#include <stdlib.h>
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

void akav_pe_free(akav_pe_t* pe)
{
    if (!pe) return;
    free(pe->import_dlls);
    free(pe->import_funcs);
    free(pe->export_funcs);
    pe->import_dlls = NULL;
    pe->import_funcs = NULL;
    pe->export_funcs = NULL;
    pe->num_import_dlls = 0;
    pe->num_import_funcs = 0;
    pe->num_export_funcs = 0;
}

/* ── Helper: read a null-terminated string at a file offset ──────── */

static bool read_string_at(const uint8_t* data, size_t data_len,
                            uint32_t offset, char* out, size_t out_size)
{
    if (offset >= data_len || out_size == 0) return false;

    size_t max_len = data_len - offset;
    if (max_len > out_size - 1) max_len = out_size - 1;

    size_t i = 0;
    while (i < max_len && data[offset + i] != '\0') {
        out[i] = (char)data[offset + i];
        i++;
    }
    out[i] = '\0';
    return i > 0;
}

/* ── Parse imports ───────────────────────────────────────────────── */

bool akav_pe_parse_imports(akav_pe_t* pe, const uint8_t* data, size_t data_len)
{
    if (!pe || !pe->valid || !data) return false;

    /* Check import directory exists */
    if (pe->num_data_dirs <= AKAV_PE_DIR_IMPORT) return false;
    akav_pe_data_dir_t* imp_dir = &pe->data_dirs[AKAV_PE_DIR_IMPORT];
    if (imp_dir->virtual_address == 0 || imp_dir->size == 0) return false;

    uint32_t imp_offset = akav_pe_rva_to_offset(pe, imp_dir->virtual_address);
    if (imp_offset == 0) {
        pe_warn(pe, "Import directory RVA does not map to file");
        return false;
    }

    /* First pass: count import descriptors (20 bytes each, null-terminated) */
    akav_safe_reader_t r;
    akav_reader_init(&r, data, data_len);

    uint32_t dll_count = 0;
    {
        akav_safe_reader_t cnt = r;
        if (!akav_reader_seek_to(&cnt, imp_offset)) return false;

        while (dll_count < AKAV_PE_MAX_IMPORTS) {
            uint32_t ilt_rva, ts, fchain, name_rva, iat_rva;
            if (!akav_reader_read_u32_le(&cnt, &ilt_rva))   break;
            if (!akav_reader_read_u32_le(&cnt, &ts))        break;
            if (!akav_reader_read_u32_le(&cnt, &fchain))    break;
            if (!akav_reader_read_u32_le(&cnt, &name_rva))  break;
            if (!akav_reader_read_u32_le(&cnt, &iat_rva))   break;

            /* Null descriptor terminates the list */
            if (ilt_rva == 0 && name_rva == 0 && iat_rva == 0) break;
            dll_count++;
        }
    }

    if (dll_count == 0) return false;

    /* Allocate import DLL array */
    pe->import_dlls = (akav_pe_import_dll_t*)calloc(
        dll_count, sizeof(akav_pe_import_dll_t));
    if (!pe->import_dlls) return false;

    /* Temporary: collect all functions, then allocate */
    /* Estimate max functions and allocate upfront */
    akav_pe_import_func_t* funcs = (akav_pe_import_func_t*)calloc(
        AKAV_PE_MAX_FUNCTIONS, sizeof(akav_pe_import_func_t));
    if (!funcs) { free(pe->import_dlls); pe->import_dlls = NULL; return false; }

    uint32_t total_funcs = 0;
    uint32_t ordinal_only = 0;

    if (!akav_reader_seek_to(&r, imp_offset)) {
        free(funcs); free(pe->import_dlls); pe->import_dlls = NULL;
        return false;
    }

    bool is64 = pe->is_pe32plus;
    uint64_t ordinal_flag = is64 ? 0x8000000000000000ULL : 0x80000000ULL;

    for (uint32_t d = 0; d < dll_count; d++) {
        uint32_t ilt_rva, ts, fchain, name_rva, iat_rva;
        if (!akav_reader_read_u32_le(&r, &ilt_rva))   break;
        if (!akav_reader_read_u32_le(&r, &ts))        break;
        if (!akav_reader_read_u32_le(&r, &fchain))    break;
        if (!akav_reader_read_u32_le(&r, &name_rva))  break;
        if (!akav_reader_read_u32_le(&r, &iat_rva))   break;

        akav_pe_import_dll_t* dll = &pe->import_dlls[d];
        dll->first_func_index = total_funcs;
        dll->num_functions = 0;

        /* Read DLL name */
        uint32_t name_off = akav_pe_rva_to_offset(pe, name_rva);
        if (name_off > 0) {
            read_string_at(data, data_len, name_off,
                           dll->dll_name, sizeof(dll->dll_name));
        } else {
            strncpy_s(dll->dll_name, sizeof(dll->dll_name), "<invalid>", _TRUNCATE);
        }

        /* Walk the ILT (or IAT if ILT is zero) */
        uint32_t thunk_rva = (ilt_rva != 0) ? ilt_rva : iat_rva;
        uint32_t thunk_off = akav_pe_rva_to_offset(pe, thunk_rva);
        if (thunk_off == 0) continue;

        akav_safe_reader_t thunk_r;
        akav_reader_init(&thunk_r, data, data_len);
        if (!akav_reader_seek_to(&thunk_r, thunk_off)) continue;

        while (total_funcs < AKAV_PE_MAX_FUNCTIONS) {
            uint64_t thunk_data;
            if (is64) {
                if (!akav_reader_read_u64_le(&thunk_r, &thunk_data)) break;
            } else {
                uint32_t t32;
                if (!akav_reader_read_u32_le(&thunk_r, &t32)) break;
                thunk_data = t32;
            }

            if (thunk_data == 0) break; /* end of thunk list */

            akav_pe_import_func_t* func = &funcs[total_funcs];

            if (thunk_data & ordinal_flag) {
                /* Import by ordinal */
                func->is_ordinal = true;
                func->ordinal = (uint16_t)(thunk_data & 0xFFFF);
                func->name[0] = '\0';
                ordinal_only++;
            } else {
                /* Import by name: thunk_data is RVA to hint/name table entry */
                uint32_t hint_off = akav_pe_rva_to_offset(pe, (uint32_t)thunk_data);
                if (hint_off > 0 && hint_off + 2 < data_len) {
                    /* Hint (2 bytes) + name string */
                    func->ordinal = (uint16_t)(data[hint_off] | (data[hint_off + 1] << 8));
                    func->is_ordinal = false;
                    read_string_at(data, data_len, hint_off + 2,
                                   func->name, sizeof(func->name));
                } else {
                    func->is_ordinal = true;
                    func->ordinal = 0;
                }
            }

            total_funcs++;
            dll->num_functions++;
        }
    }

    pe->num_import_dlls = dll_count;
    pe->ordinal_only_count = ordinal_only;

    /* Shrink function array to actual size */
    if (total_funcs > 0) {
        akav_pe_import_func_t* trimmed = (akav_pe_import_func_t*)realloc(
            funcs, total_funcs * sizeof(akav_pe_import_func_t));
        pe->import_funcs = trimmed ? trimmed : funcs;
    } else {
        free(funcs);
        pe->import_funcs = NULL;
    }
    pe->num_import_funcs = total_funcs;

    return true;
}

/* ── Parse exports ───────────────────────────────────────────────── */

bool akav_pe_parse_exports(akav_pe_t* pe, const uint8_t* data, size_t data_len)
{
    if (!pe || !pe->valid || !data) return false;

    if (pe->num_data_dirs <= AKAV_PE_DIR_EXPORT) return false;
    akav_pe_data_dir_t* exp_dir = &pe->data_dirs[AKAV_PE_DIR_EXPORT];
    if (exp_dir->virtual_address == 0 || exp_dir->size == 0) return false;

    uint32_t dir_offset = akav_pe_rva_to_offset(pe, exp_dir->virtual_address);
    if (dir_offset == 0) {
        pe_warn(pe, "Export directory RVA does not map to file");
        return false;
    }

    akav_safe_reader_t r;
    akav_reader_init(&r, data, data_len);
    if (!akav_reader_seek_to(&r, dir_offset)) return false;

    /* Export directory table (40 bytes) */
    uint32_t export_flags, ts, name_rva;
    uint16_t major_ver, minor_ver;
    uint32_t num_functions, num_names;
    uint32_t addr_table_rva, name_table_rva, ordinal_table_rva;
    uint16_t ordinal_base;

    if (!akav_reader_read_u32_le(&r, &export_flags)) return false;
    if (!akav_reader_read_u32_le(&r, &ts))           return false;
    if (!akav_reader_read_u16_le(&r, &major_ver))    return false;
    if (!akav_reader_read_u16_le(&r, &minor_ver))    return false;
    if (!akav_reader_read_u32_le(&r, &name_rva))     return false;

    uint32_t ordbase32;
    if (!akav_reader_read_u32_le(&r, &ordbase32))    return false;
    ordinal_base = (uint16_t)ordbase32;

    if (!akav_reader_read_u32_le(&r, &num_functions))     return false;
    if (!akav_reader_read_u32_le(&r, &num_names))         return false;
    if (!akav_reader_read_u32_le(&r, &addr_table_rva))    return false;
    if (!akav_reader_read_u32_le(&r, &name_table_rva))    return false;
    if (!akav_reader_read_u32_le(&r, &ordinal_table_rva)) return false;

    /* Populate export dir info */
    pe->export_dir.ordinal_base = ordinal_base;
    pe->export_dir.num_functions = num_functions;
    pe->export_dir.num_names = num_names;

    uint32_t name_off = akav_pe_rva_to_offset(pe, name_rva);
    if (name_off > 0) {
        read_string_at(data, data_len, name_off,
                       pe->export_dir.dll_name, sizeof(pe->export_dir.dll_name));
    }

    /* Cap to prevent excessive allocation */
    if (num_functions > AKAV_PE_MAX_EXPORTS) num_functions = AKAV_PE_MAX_EXPORTS;
    if (num_names > num_functions) num_names = num_functions;

    if (num_functions == 0) return true;

    pe->export_funcs = (akav_pe_export_func_t*)calloc(
        num_functions, sizeof(akav_pe_export_func_t));
    if (!pe->export_funcs) return false;
    pe->num_export_funcs = num_functions;

    /* Read address table (array of RVAs) */
    uint32_t addr_off = akav_pe_rva_to_offset(pe, addr_table_rva);
    if (addr_off > 0) {
        akav_safe_reader_t ar;
        akav_reader_init(&ar, data, data_len);
        if (akav_reader_seek_to(&ar, addr_off)) {
            /* Export directory bounds for forwarder detection */
            uint32_t exp_start = exp_dir->virtual_address;
            uint32_t exp_end = exp_start + exp_dir->size;

            for (uint32_t i = 0; i < num_functions; i++) {
                uint32_t func_rva;
                if (!akav_reader_read_u32_le(&ar, &func_rva)) break;
                pe->export_funcs[i].rva = func_rva;
                pe->export_funcs[i].ordinal = ordinal_base + (uint16_t)i;

                /* Check if this is a forwarder (RVA points inside export dir) */
                if (func_rva >= exp_start && func_rva < exp_end) {
                    pe->export_funcs[i].is_forwarder = true;
                }
            }
        }
    }

    /* Read name pointer table + ordinal table to associate names */
    uint32_t npt_off = akav_pe_rva_to_offset(pe, name_table_rva);
    uint32_t ot_off = akav_pe_rva_to_offset(pe, ordinal_table_rva);

    if (npt_off > 0 && ot_off > 0) {
        akav_safe_reader_t nr, or2;
        akav_reader_init(&nr, data, data_len);
        akav_reader_init(&or2, data, data_len);

        if (akav_reader_seek_to(&nr, npt_off) &&
            akav_reader_seek_to(&or2, ot_off)) {
            for (uint32_t i = 0; i < num_names; i++) {
                uint32_t fname_rva;
                uint16_t ordinal_idx;
                if (!akav_reader_read_u32_le(&nr, &fname_rva))  break;
                if (!akav_reader_read_u16_le(&or2, &ordinal_idx)) break;

                if (ordinal_idx < num_functions) {
                    uint32_t fname_off = akav_pe_rva_to_offset(pe, fname_rva);
                    if (fname_off > 0) {
                        read_string_at(data, data_len, fname_off,
                                       pe->export_funcs[ordinal_idx].name,
                                       sizeof(pe->export_funcs[ordinal_idx].name));
                    }
                }
            }
        }
    }

    return true;
}
