// elf.cpp -- ELF parser for 32/64-bit, LE/BE binaries (P7-T1).
//
// All reads use SafeReader for bounds-checked access. Truncated or
// malformed input produces an error (not a crash).

#include "parsers/elf.h"
#include "parsers/safe_reader.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ── Helpers ────────────────────────────────────────────────────────

static void elf_error(akav_elf_t* elf, const char* msg)
{
    elf->valid = false;
    strncpy_s(elf->error, sizeof(elf->error), msg, _TRUNCATE);
}

static void elf_warn(akav_elf_t* elf, const char* msg)
{
    if (elf->warning_count < 4)
        strncpy_s(elf->warnings[elf->warning_count], 128, msg, _TRUNCATE);
    elf->warning_count++;
}

// Endian-aware read helpers. The reader is selected based on elf->is_big_endian.

static bool read_u16(akav_safe_reader_t* r, bool big_endian, uint16_t* out)
{
    return big_endian ? akav_reader_read_u16_be(r, out)
                      : akav_reader_read_u16_le(r, out);
}

static bool read_u32(akav_safe_reader_t* r, bool big_endian, uint32_t* out)
{
    return big_endian ? akav_reader_read_u32_be(r, out)
                      : akav_reader_read_u32_le(r, out);
}

static bool read_u64(akav_safe_reader_t* r, bool big_endian, uint64_t* out)
{
    return big_endian ? akav_reader_read_u64_be(r, out)
                      : akav_reader_read_u64_le(r, out);
}

// Read a "word" -- 32 bits for ELF32, 64 bits for ELF64.
static bool read_addr(akav_safe_reader_t* r, bool big_endian, bool is_64,
                      uint64_t* out)
{
    if (is_64) {
        return read_u64(r, big_endian, out);
    } else {
        uint32_t v;
        if (!read_u32(r, big_endian, &v)) return false;
        *out = v;
        return true;
    }
}

// Resolve a name from a string table section.
static void resolve_name(const uint8_t* data, size_t data_len,
                          const akav_elf_section_t* strtab,
                          uint32_t name_index,
                          char* out, size_t out_size)
{
    out[0] = '\0';
    if (!strtab || strtab->sh_offset == 0 || strtab->sh_size == 0)
        return;
    uint64_t off = strtab->sh_offset + name_index;
    if (off >= data_len || name_index >= strtab->sh_size)
        return;

    size_t max_len = out_size - 1;
    size_t avail = data_len - (size_t)off;
    if (avail > strtab->sh_size - name_index)
        avail = (size_t)(strtab->sh_size - name_index);
    if (avail > max_len)
        avail = max_len;

    size_t i = 0;
    while (i < avail && data[(size_t)off + i] != '\0') {
        out[i] = (char)data[(size_t)off + i];
        i++;
    }
    out[i] = '\0';
}

// ── ELF header parsing ────────────────────────────────────────────

static bool parse_ident(akav_elf_t* elf, akav_safe_reader_t* r)
{
    uint8_t ident[16];
    if (!akav_reader_read_bytes(r, ident, 16)) {
        elf_error(elf, "Truncated ELF identification");
        return false;
    }

    if (ident[0] != AKAV_ELF_MAGIC0 || ident[1] != AKAV_ELF_MAGIC1 ||
        ident[2] != AKAV_ELF_MAGIC2 || ident[3] != AKAV_ELF_MAGIC3) {
        elf_error(elf, "Invalid ELF magic");
        return false;
    }

    elf->ei_class = ident[4];
    elf->ei_data = ident[5];
    elf->ei_osabi = ident[7];
    elf->ei_abiversion = ident[8];

    if (elf->ei_class != AKAV_ELF_CLASS_32 && elf->ei_class != AKAV_ELF_CLASS_64) {
        elf_error(elf, "Unknown ELF class");
        return false;
    }

    if (elf->ei_data != AKAV_ELF_DATA_LSB && elf->ei_data != AKAV_ELF_DATA_MSB) {
        elf_error(elf, "Unknown ELF data encoding");
        return false;
    }

    elf->is_64 = (elf->ei_class == AKAV_ELF_CLASS_64);
    elf->is_big_endian = (elf->ei_data == AKAV_ELF_DATA_MSB);

    return true;
}

static bool parse_ehdr(akav_elf_t* elf, akav_safe_reader_t* r)
{
    bool be = elf->is_big_endian;

    if (!read_u16(r, be, &elf->e_type))      { elf_error(elf, "Truncated ELF header (e_type)"); return false; }
    if (!read_u16(r, be, &elf->e_machine))    { elf_error(elf, "Truncated ELF header (e_machine)"); return false; }
    if (!read_u32(r, be, &elf->e_version))    { elf_error(elf, "Truncated ELF header (e_version)"); return false; }
    if (!read_addr(r, be, elf->is_64, &elf->e_entry)) { elf_error(elf, "Truncated ELF header (e_entry)"); return false; }
    if (!read_addr(r, be, elf->is_64, &elf->e_phoff)) { elf_error(elf, "Truncated ELF header (e_phoff)"); return false; }
    if (!read_addr(r, be, elf->is_64, &elf->e_shoff)) { elf_error(elf, "Truncated ELF header (e_shoff)"); return false; }
    if (!read_u32(r, be, &elf->e_flags))      { elf_error(elf, "Truncated ELF header (e_flags)"); return false; }
    if (!read_u16(r, be, &elf->e_ehsize))     { elf_error(elf, "Truncated ELF header (e_ehsize)"); return false; }
    if (!read_u16(r, be, &elf->e_phentsize))  { elf_error(elf, "Truncated ELF header (e_phentsize)"); return false; }
    if (!read_u16(r, be, &elf->e_phnum))      { elf_error(elf, "Truncated ELF header (e_phnum)"); return false; }
    if (!read_u16(r, be, &elf->e_shentsize))  { elf_error(elf, "Truncated ELF header (e_shentsize)"); return false; }
    if (!read_u16(r, be, &elf->e_shnum))      { elf_error(elf, "Truncated ELF header (e_shnum)"); return false; }
    if (!read_u16(r, be, &elf->e_shstrndx))   { elf_error(elf, "Truncated ELF header (e_shstrndx)"); return false; }

    if (elf->e_version != 1) {
        elf_warn(elf, "Unexpected e_version (not 1)");
    }

    return true;
}

// ── Section header parsing ────────────────────────────────────────

static bool parse_section_headers(akav_elf_t* elf, akav_safe_reader_t* r,
                                   const uint8_t* data, size_t data_len)
{
    if (elf->e_shoff == 0 || elf->e_shnum == 0) {
        elf->num_sections = 0;
        return true; // No section table is valid (stripped binary)
    }

    uint16_t count = elf->e_shnum;
    if (count > AKAV_ELF_MAX_SECTIONS) {
        elf_warn(elf, "Section count exceeds limit, clamping");
        count = AKAV_ELF_MAX_SECTIONS;
    }

    bool be = elf->is_big_endian;

    for (uint16_t i = 0; i < count; i++) {
        uint64_t offset = elf->e_shoff + (uint64_t)i * elf->e_shentsize;
        if (!akav_reader_seek_to(r, (size_t)offset)) {
            elf_warn(elf, "Section header table truncated");
            elf->num_sections = i;
            return true;
        }

        akav_elf_section_t* sec = &elf->sections[i];

        if (!read_u32(r, be, &sec->sh_name))  goto trunc;

        uint32_t sh_type;
        if (!read_u32(r, be, &sh_type))        goto trunc;
        sec->sh_type = sh_type;

        if (!read_addr(r, be, elf->is_64, &sec->sh_flags))   goto trunc;
        if (!read_addr(r, be, elf->is_64, &sec->sh_addr))    goto trunc;
        if (!read_addr(r, be, elf->is_64, &sec->sh_offset))  goto trunc;
        if (!read_addr(r, be, elf->is_64, &sec->sh_size))    goto trunc;
        if (!read_u32(r, be, &sec->sh_link))   goto trunc;
        if (!read_u32(r, be, &sec->sh_info))   goto trunc;
        if (!read_addr(r, be, elf->is_64, &sec->sh_addralign)) goto trunc;
        if (!read_addr(r, be, elf->is_64, &sec->sh_entsize))   goto trunc;

        sec->name[0] = '\0'; // resolved later
    }

    elf->num_sections = count;

    // Resolve section names from shstrtab
    if (elf->e_shstrndx < count &&
        elf->sections[elf->e_shstrndx].sh_type == AKAV_ELF_SHT_STRTAB) {
        const akav_elf_section_t* shstrtab = &elf->sections[elf->e_shstrndx];
        for (uint16_t i = 0; i < count; i++) {
            resolve_name(data, data_len, shstrtab, elf->sections[i].sh_name,
                         elf->sections[i].name, AKAV_ELF_MAX_NAME_LEN);
        }
    }

    return true;

trunc:
    elf_warn(elf, "Section header table truncated");
    return true;
}

// ── Program header parsing ────────────────────────────────────────

static bool parse_program_headers(akav_elf_t* elf, akav_safe_reader_t* r)
{
    if (elf->e_phoff == 0 || elf->e_phnum == 0) {
        elf->num_phdrs = 0;
        return true;
    }

    uint16_t count = elf->e_phnum;
    if (count > AKAV_ELF_MAX_PHDRS) {
        elf_warn(elf, "Program header count exceeds limit, clamping");
        count = AKAV_ELF_MAX_PHDRS;
    }

    bool be = elf->is_big_endian;

    for (uint16_t i = 0; i < count; i++) {
        uint64_t offset = elf->e_phoff + (uint64_t)i * elf->e_phentsize;
        if (!akav_reader_seek_to(r, (size_t)offset)) {
            elf_warn(elf, "Program header table truncated");
            elf->num_phdrs = i;
            return true;
        }

        akav_elf_phdr_t* ph = &elf->phdrs[i];

        if (!read_u32(r, be, &ph->p_type)) goto trunc;

        if (elf->is_64) {
            // ELF64: p_flags comes after p_type
            if (!read_u32(r, be, &ph->p_flags))    goto trunc;
            if (!read_u64(r, be, &ph->p_offset))   goto trunc;
            if (!read_u64(r, be, &ph->p_vaddr))    goto trunc;
            if (!read_u64(r, be, &ph->p_paddr))    goto trunc;
            if (!read_u64(r, be, &ph->p_filesz))   goto trunc;
            if (!read_u64(r, be, &ph->p_memsz))    goto trunc;
            if (!read_u64(r, be, &ph->p_align))    goto trunc;
        } else {
            // ELF32: p_flags comes after p_memsz
            uint32_t v;
            if (!read_u32(r, be, &v)) goto trunc;  ph->p_offset = v;
            if (!read_u32(r, be, &v)) goto trunc;  ph->p_vaddr  = v;
            if (!read_u32(r, be, &v)) goto trunc;  ph->p_paddr  = v;
            if (!read_u32(r, be, &v)) goto trunc;  ph->p_filesz = v;
            if (!read_u32(r, be, &v)) goto trunc;  ph->p_memsz  = v;
            if (!read_u32(r, be, &ph->p_flags)) goto trunc;
            if (!read_u32(r, be, &v)) goto trunc;  ph->p_align  = v;
        }
    }

    elf->num_phdrs = count;
    return true;

trunc:
    elf_warn(elf, "Program header table truncated");
    return true;
}

// ── Symbol table parsing (shared for .symtab and .dynsym) ─────────

static bool parse_symbols(akav_elf_t* elf, const uint8_t* data, size_t data_len,
                           const akav_elf_section_t* sym_sec,
                           const akav_elf_section_t* str_sec,
                           akav_elf_symbol_t** out_syms, uint32_t* out_count)
{
    *out_syms = nullptr;
    *out_count = 0;

    if (!sym_sec || sym_sec->sh_size == 0 || sym_sec->sh_entsize == 0)
        return false;

    uint64_t entry_size = sym_sec->sh_entsize;
    uint64_t expected = elf->is_64 ? 24u : 16u;
    if (entry_size < expected) {
        elf_warn(elf, "Symbol entry size too small");
        return false;
    }

    uint32_t num = (uint32_t)(sym_sec->sh_size / entry_size);
    if (num > AKAV_ELF_MAX_SYMBOLS) {
        elf_warn(elf, "Symbol count exceeds limit, clamping");
        num = AKAV_ELF_MAX_SYMBOLS;
    }
    if (num == 0)
        return false;

    akav_elf_symbol_t* syms = (akav_elf_symbol_t*)calloc(num, sizeof(akav_elf_symbol_t));
    if (!syms) return false;

    akav_safe_reader_t r;
    akav_reader_init(&r, data, data_len);
    bool be = elf->is_big_endian;

    for (uint32_t i = 0; i < num; i++) {
        uint64_t off = sym_sec->sh_offset + (uint64_t)i * entry_size;
        if (!akav_reader_seek_to(&r, (size_t)off))
            break;

        uint32_t st_name;
        if (!read_u32(&r, be, &st_name)) break;

        if (elf->is_64) {
            // ELF64 Sym: st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
            if (!akav_reader_read_u8(&r, &syms[i].st_info))  break;
            if (!akav_reader_read_u8(&r, &syms[i].st_other)) break;
            if (!read_u16(&r, be, &syms[i].st_shndx))        break;
            if (!read_u64(&r, be, &syms[i].st_value))        break;
            if (!read_u64(&r, be, &syms[i].st_size))         break;
        } else {
            // ELF32 Sym: st_name(4), st_value(4), st_size(4), st_info(1), st_other(1), st_shndx(2)
            uint32_t v;
            if (!read_u32(&r, be, &v)) break;  syms[i].st_value = v;
            if (!read_u32(&r, be, &v)) break;  syms[i].st_size  = v;
            if (!akav_reader_read_u8(&r, &syms[i].st_info))  break;
            if (!akav_reader_read_u8(&r, &syms[i].st_other)) break;
            if (!read_u16(&r, be, &syms[i].st_shndx))        break;
        }

        syms[i].binding = (uint8_t)(syms[i].st_info >> 4);
        syms[i].type    = (uint8_t)(syms[i].st_info & 0x0F);

        // Resolve name
        resolve_name(data, data_len, str_sec, st_name,
                     syms[i].name, AKAV_ELF_MAX_NAME_LEN);

        *out_count = i + 1;
    }

    *out_syms = syms;
    return *out_count > 0;
}

// ── Public API ────────────────────────────────────────────────────

bool akav_elf_parse(akav_elf_t* elf, const uint8_t* data, size_t data_len)
{
    if (!elf) return false;
    memset(elf, 0, sizeof(*elf));

    if (!data || data_len < 16) {
        elf_error(elf, "Buffer too small for ELF");
        return false;
    }

    akav_safe_reader_t r;
    akav_reader_init(&r, data, data_len);

    if (!parse_ident(elf, &r))
        return false;

    if (!parse_ehdr(elf, &r))
        return false;

    if (!parse_section_headers(elf, &r, data, data_len))
        return false;

    if (!parse_program_headers(elf, &r))
        return false;

    elf->valid = true;
    return true;
}

void akav_elf_free(akav_elf_t* elf)
{
    if (!elf) return;
    free(elf->symtab);
    elf->symtab = nullptr;
    elf->num_symtab = 0;
    free(elf->dynsym);
    elf->dynsym = nullptr;
    elf->num_dynsym = 0;
}

bool akav_elf_parse_symtab(akav_elf_t* elf, const uint8_t* data, size_t data_len)
{
    if (!elf || !elf->valid || !data) return false;

    // Find .symtab and its string table
    const akav_elf_section_t* symtab_sec = nullptr;
    const akav_elf_section_t* strtab_sec = nullptr;

    for (uint16_t i = 0; i < elf->num_sections; i++) {
        if (elf->sections[i].sh_type == AKAV_ELF_SHT_SYMTAB) {
            symtab_sec = &elf->sections[i];
            // sh_link points to the associated string table
            if (symtab_sec->sh_link < elf->num_sections)
                strtab_sec = &elf->sections[symtab_sec->sh_link];
            break;
        }
    }

    if (!symtab_sec) return false;

    return parse_symbols(elf, data, data_len, symtab_sec, strtab_sec,
                         &elf->symtab, &elf->num_symtab);
}

bool akav_elf_parse_dynsym(akav_elf_t* elf, const uint8_t* data, size_t data_len)
{
    if (!elf || !elf->valid || !data) return false;

    const akav_elf_section_t* dynsym_sec = nullptr;
    const akav_elf_section_t* dynstr_sec = nullptr;

    for (uint16_t i = 0; i < elf->num_sections; i++) {
        if (elf->sections[i].sh_type == AKAV_ELF_SHT_DYNSYM) {
            dynsym_sec = &elf->sections[i];
            if (dynsym_sec->sh_link < elf->num_sections)
                dynstr_sec = &elf->sections[dynsym_sec->sh_link];
            break;
        }
    }

    if (!dynsym_sec) return false;

    return parse_symbols(elf, data, data_len, dynsym_sec, dynstr_sec,
                         &elf->dynsym, &elf->num_dynsym);
}

bool akav_elf_parse_dynamic(akav_elf_t* elf, const uint8_t* data, size_t data_len)
{
    if (!elf || !elf->valid || !data) return false;

    // Find .dynamic section
    const akav_elf_section_t* dyn_sec = nullptr;
    const akav_elf_section_t* dynstr_sec = nullptr;

    for (uint16_t i = 0; i < elf->num_sections; i++) {
        if (elf->sections[i].sh_type == AKAV_ELF_SHT_DYNAMIC) {
            dyn_sec = &elf->sections[i];
            if (dyn_sec->sh_link < elf->num_sections)
                dynstr_sec = &elf->sections[dyn_sec->sh_link];
            break;
        }
    }

    // Fall back: look for .dynstr by name if sh_link didn't work
    if (!dynstr_sec) {
        for (uint16_t i = 0; i < elf->num_sections; i++) {
            if (strcmp(elf->sections[i].name, ".dynstr") == 0) {
                dynstr_sec = &elf->sections[i];
                break;
            }
        }
    }

    if (!dyn_sec || dyn_sec->sh_size == 0) return false;

    akav_safe_reader_t r;
    akav_reader_init(&r, data, data_len);
    bool be = elf->is_big_endian;

    uint64_t entry_size = dyn_sec->sh_entsize;
    if (entry_size == 0)
        entry_size = elf->is_64 ? 16u : 8u;

    uint32_t num = (uint32_t)(dyn_sec->sh_size / entry_size);
    if (num > AKAV_ELF_MAX_DYNAMIC)
        num = AKAV_ELF_MAX_DYNAMIC;

    elf->num_dynamic = 0;
    elf->num_needed = 0;
    elf->soname[0] = '\0';

    for (uint32_t i = 0; i < num; i++) {
        uint64_t off = dyn_sec->sh_offset + (uint64_t)i * entry_size;
        if (!akav_reader_seek_to(&r, (size_t)off))
            break;

        int64_t  d_tag;
        uint64_t d_val;

        if (elf->is_64) {
            uint64_t tag_u;
            if (!read_u64(&r, be, &tag_u)) break;
            d_tag = (int64_t)tag_u;
            if (!read_u64(&r, be, &d_val)) break;
        } else {
            uint32_t tag_u, val_u;
            if (!read_u32(&r, be, &tag_u)) break;
            if (!read_u32(&r, be, &val_u)) break;
            d_tag = (int64_t)(int32_t)tag_u;
            d_val = val_u;
        }

        if (elf->num_dynamic < AKAV_ELF_MAX_DYNAMIC) {
            elf->dynamic[elf->num_dynamic].d_tag = d_tag;
            elf->dynamic[elf->num_dynamic].d_val = d_val;
            elf->num_dynamic++;
        }

        // Resolve DT_NEEDED and DT_SONAME from dynstr
        if (d_tag == AKAV_ELF_DT_NEEDED && elf->num_needed < AKAV_ELF_MAX_NEEDED) {
            resolve_name(data, data_len, dynstr_sec, (uint32_t)d_val,
                         elf->needed[elf->num_needed], AKAV_ELF_MAX_NAME_LEN);
            if (elf->needed[elf->num_needed][0] != '\0')
                elf->num_needed++;
        } else if (d_tag == AKAV_ELF_DT_SONAME) {
            resolve_name(data, data_len, dynstr_sec, (uint32_t)d_val,
                         elf->soname, AKAV_ELF_MAX_NAME_LEN);
        }

        if (d_tag == AKAV_ELF_DT_NULL)
            break;
    }

    return elf->num_dynamic > 0;
}

bool akav_elf_parse_notes(akav_elf_t* elf, const uint8_t* data, size_t data_len)
{
    if (!elf || !elf->valid || !data) return false;

    elf->num_notes = 0;
    elf->has_build_id = false;
    bool be = elf->is_big_endian;

    // Parse notes from SHT_NOTE sections
    for (uint16_t i = 0; i < elf->num_sections; i++) {
        if (elf->sections[i].sh_type != AKAV_ELF_SHT_NOTE)
            continue;
        if (elf->num_notes >= AKAV_ELF_MAX_NOTES)
            break;

        const akav_elf_section_t* sec = &elf->sections[i];
        if (sec->sh_offset + sec->sh_size > data_len)
            continue;

        akav_safe_reader_t r;
        akav_reader_init(&r, data, data_len);
        if (!akav_reader_seek_to(&r, (size_t)sec->sh_offset))
            continue;

        size_t end = (size_t)(sec->sh_offset + sec->sh_size);

        while (akav_reader_position(&r) + 12 <= end &&
               elf->num_notes < AKAV_ELF_MAX_NOTES) {
            uint32_t namesz, descsz, type;
            if (!read_u32(&r, be, &namesz)) break;
            if (!read_u32(&r, be, &descsz)) break;
            if (!read_u32(&r, be, &type))   break;

            akav_elf_note_t* note = &elf->notes[elf->num_notes];
            note->type = type;
            note->name[0] = '\0';
            note->desc_len = 0;

            // Read name (aligned to 4 bytes)
            uint32_t namesz_aligned = (namesz + 3) & ~3u;
            if (namesz > 0 && namesz <= 31) {
                akav_reader_read_bytes(&r, (uint8_t*)note->name, namesz);
                note->name[namesz] = '\0';
                if (namesz_aligned > namesz)
                    akav_reader_skip(&r, namesz_aligned - namesz);
            } else {
                akav_reader_skip(&r, namesz_aligned);
            }

            // Read descriptor (aligned to 4 bytes)
            uint32_t descsz_aligned = (descsz + 3) & ~3u;
            if (descsz > 0 && descsz <= sizeof(note->desc)) {
                akav_reader_read_bytes(&r, note->desc, descsz);
                note->desc_len = descsz;
                if (descsz_aligned > descsz)
                    akav_reader_skip(&r, descsz_aligned - descsz);
            } else if (descsz > sizeof(note->desc)) {
                // Too large to store, just record type
                akav_reader_skip(&r, descsz_aligned);
                note->desc_len = 0;
            } else {
                akav_reader_skip(&r, descsz_aligned);
            }

            // Extract build-id
            if (type == AKAV_ELF_NT_GNU_BUILD_ID &&
                strcmp(note->name, "GNU") == 0 &&
                note->desc_len > 0 && note->desc_len <= sizeof(elf->build_id)) {
                elf->has_build_id = true;
                memcpy(elf->build_id, note->desc, note->desc_len);
                elf->build_id_len = note->desc_len;
            }

            elf->num_notes++;
        }
    }

    return elf->num_notes > 0;
}

bool akav_elf_parse_interp(akav_elf_t* elf, const uint8_t* data, size_t data_len)
{
    if (!elf || !elf->valid || !data) return false;

    elf->interp[0] = '\0';

    for (uint16_t i = 0; i < elf->num_phdrs; i++) {
        if (elf->phdrs[i].p_type != AKAV_ELF_PT_INTERP)
            continue;

        uint64_t off = elf->phdrs[i].p_offset;
        uint64_t fsz = elf->phdrs[i].p_filesz;

        if (off >= data_len || off + fsz > data_len || fsz == 0)
            return false;

        size_t len = (size_t)fsz;
        if (len >= AKAV_ELF_MAX_NAME_LEN)
            len = AKAV_ELF_MAX_NAME_LEN - 1;

        memcpy(elf->interp, data + (size_t)off, len);
        elf->interp[len] = '\0';

        return true;
    }

    return false;
}

const char* akav_elf_machine_name(uint16_t machine)
{
    switch (machine) {
    case AKAV_ELF_EM_NONE:    return "None";
    case AKAV_ELF_EM_386:     return "Intel 80386";
    case AKAV_ELF_EM_ARM:     return "ARM";
    case AKAV_ELF_EM_X86_64:  return "AMD x86-64";
    case AKAV_ELF_EM_AARCH64: return "AArch64";
    case AKAV_ELF_EM_MIPS:    return "MIPS";
    case AKAV_ELF_EM_PPC:     return "PowerPC";
    case AKAV_ELF_EM_PPC64:   return "PowerPC64";
    case AKAV_ELF_EM_SPARC:   return "SPARC";
    case AKAV_ELF_EM_SPARCV9: return "SPARC V9";
    case AKAV_ELF_EM_S390:    return "IBM S/390";
    case AKAV_ELF_EM_RISCV:   return "RISC-V";
    default:                   return "Unknown";
    }
}

const char* akav_elf_type_name(uint16_t type)
{
    switch (type) {
    case AKAV_ELF_ET_NONE: return "NONE";
    case AKAV_ELF_ET_REL:  return "REL (Relocatable)";
    case AKAV_ELF_ET_EXEC: return "EXEC (Executable)";
    case AKAV_ELF_ET_DYN:  return "DYN (Shared object)";
    case AKAV_ELF_ET_CORE: return "CORE (Core dump)";
    default:                return "Unknown";
    }
}

const akav_elf_section_t* akav_elf_find_section(const akav_elf_t* elf,
                                                  const char* name)
{
    if (!elf || !name) return nullptr;
    for (uint16_t i = 0; i < elf->num_sections; i++) {
        if (strcmp(elf->sections[i].name, name) == 0)
            return &elf->sections[i];
    }
    return nullptr;
}

void akav_elf_analyze(akav_elf_t* elf, const uint8_t* data, size_t data_len)
{
    if (!elf || !elf->valid || !data) return;

    akav_elf_parse_symtab(elf, data, data_len);
    akav_elf_parse_dynsym(elf, data, data_len);
    akav_elf_parse_dynamic(elf, data, data_len);
    akav_elf_parse_notes(elf, data, data_len);
    akav_elf_parse_interp(elf, data, data_len);
}
