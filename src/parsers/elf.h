#ifndef AKAV_ELF_H
#define AKAV_ELF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── ELF format constants ──────────────────────────────────────── */

#define AKAV_ELF_MAGIC0      0x7F
#define AKAV_ELF_MAGIC1      'E'
#define AKAV_ELF_MAGIC2      'L'
#define AKAV_ELF_MAGIC3      'F'

/* e_ident[EI_CLASS] */
#define AKAV_ELF_CLASS_NONE  0
#define AKAV_ELF_CLASS_32    1
#define AKAV_ELF_CLASS_64    2

/* e_ident[EI_DATA] */
#define AKAV_ELF_DATA_NONE   0
#define AKAV_ELF_DATA_LSB    1   /* little-endian */
#define AKAV_ELF_DATA_MSB    2   /* big-endian */

/* e_type */
#define AKAV_ELF_ET_NONE     0
#define AKAV_ELF_ET_REL      1
#define AKAV_ELF_ET_EXEC     2
#define AKAV_ELF_ET_DYN      3
#define AKAV_ELF_ET_CORE     4

/* e_machine (common) */
#define AKAV_ELF_EM_NONE     0
#define AKAV_ELF_EM_386      3
#define AKAV_ELF_EM_ARM      40
#define AKAV_ELF_EM_X86_64   62
#define AKAV_ELF_EM_AARCH64  183
#define AKAV_ELF_EM_MIPS     8
#define AKAV_ELF_EM_PPC      20
#define AKAV_ELF_EM_PPC64    21
#define AKAV_ELF_EM_SPARC    2
#define AKAV_ELF_EM_SPARCV9  43
#define AKAV_ELF_EM_S390     22
#define AKAV_ELF_EM_RISCV    243

/* Section types (sh_type) */
#define AKAV_ELF_SHT_NULL          0
#define AKAV_ELF_SHT_PROGBITS      1
#define AKAV_ELF_SHT_SYMTAB        2
#define AKAV_ELF_SHT_STRTAB        3
#define AKAV_ELF_SHT_RELA          4
#define AKAV_ELF_SHT_HASH          5
#define AKAV_ELF_SHT_DYNAMIC       6
#define AKAV_ELF_SHT_NOTE          7
#define AKAV_ELF_SHT_NOBITS        8
#define AKAV_ELF_SHT_REL           9
#define AKAV_ELF_SHT_DYNSYM        11
#define AKAV_ELF_SHT_INIT_ARRAY    14
#define AKAV_ELF_SHT_FINI_ARRAY    15
#define AKAV_ELF_SHT_GNU_HASH      0x6FFFFFF6
#define AKAV_ELF_SHT_GNU_VERSYM    0x6FFFFFFF
#define AKAV_ELF_SHT_GNU_VERNEED   0x6FFFFFFE
#define AKAV_ELF_SHT_GNU_VERDEF    0x6FFFFFFD

/* Program header types (p_type) */
#define AKAV_ELF_PT_NULL            0
#define AKAV_ELF_PT_LOAD            1
#define AKAV_ELF_PT_DYNAMIC         2
#define AKAV_ELF_PT_INTERP          3
#define AKAV_ELF_PT_NOTE            4
#define AKAV_ELF_PT_PHDR            6
#define AKAV_ELF_PT_TLS             7
#define AKAV_ELF_PT_GNU_EH_FRAME   0x6474E550
#define AKAV_ELF_PT_GNU_STACK       0x6474E551
#define AKAV_ELF_PT_GNU_RELRO       0x6474E552

/* Dynamic tags (d_tag) */
#define AKAV_ELF_DT_NULL       0
#define AKAV_ELF_DT_NEEDED     1
#define AKAV_ELF_DT_PLTRELSZ   2
#define AKAV_ELF_DT_HASH       4
#define AKAV_ELF_DT_STRTAB     5
#define AKAV_ELF_DT_SYMTAB     6
#define AKAV_ELF_DT_RELA       7
#define AKAV_ELF_DT_RELASZ     8
#define AKAV_ELF_DT_STRSZ      10
#define AKAV_ELF_DT_SYMENT     11
#define AKAV_ELF_DT_INIT       12
#define AKAV_ELF_DT_FINI       13
#define AKAV_ELF_DT_SONAME     14
#define AKAV_ELF_DT_RPATH      15
#define AKAV_ELF_DT_REL        17
#define AKAV_ELF_DT_RELSZ      18
#define AKAV_ELF_DT_PLTREL     20
#define AKAV_ELF_DT_JMPREL     23
#define AKAV_ELF_DT_RUNPATH    29

/* Symbol binding (high nibble of st_info) */
#define AKAV_ELF_STB_LOCAL     0
#define AKAV_ELF_STB_GLOBAL    1
#define AKAV_ELF_STB_WEAK      2

/* Symbol type (low nibble of st_info) */
#define AKAV_ELF_STT_NOTYPE    0
#define AKAV_ELF_STT_OBJECT    1
#define AKAV_ELF_STT_FUNC      2
#define AKAV_ELF_STT_SECTION   3
#define AKAV_ELF_STT_FILE      4

/* Note types */
#define AKAV_ELF_NT_GNU_ABI_TAG     1
#define AKAV_ELF_NT_GNU_BUILD_ID    3

/* ── Sanity limits ─────────────────────────────────────────────── */

#define AKAV_ELF_MAX_SECTIONS       256
#define AKAV_ELF_MAX_PHDRS          64
#define AKAV_ELF_MAX_SYMBOLS        16384
#define AKAV_ELF_MAX_DYNAMIC        512
#define AKAV_ELF_MAX_NOTES          64
#define AKAV_ELF_MAX_NEEDED         128
#define AKAV_ELF_MAX_NAME_LEN       256

/* ── Parsed structures ─────────────────────────────────────────── */

typedef struct {
    uint32_t sh_name;         /* index into section name string table */
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
    char     name[AKAV_ELF_MAX_NAME_LEN]; /* resolved name from shstrtab */
} akav_elf_section_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} akav_elf_phdr_t;

typedef struct {
    char     name[AKAV_ELF_MAX_NAME_LEN]; /* resolved from strtab */
    uint64_t st_value;
    uint64_t st_size;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    /* Decoded convenience fields */
    uint8_t  binding;         /* STB_LOCAL/GLOBAL/WEAK */
    uint8_t  type;            /* STT_NOTYPE/OBJECT/FUNC/... */
} akav_elf_symbol_t;

typedef struct {
    int64_t  d_tag;
    uint64_t d_val;           /* or d_ptr */
} akav_elf_dynamic_t;

typedef struct {
    uint32_t type;            /* NT_GNU_ABI_TAG, NT_GNU_BUILD_ID, etc. */
    char     name[32];        /* note name (usually "GNU\0") */
    uint8_t  desc[256];       /* note descriptor (e.g. build-id hash) */
    uint32_t desc_len;
} akav_elf_note_t;

/* ── Parsed ELF ────────────────────────────────────────────────── */

typedef struct {
    /* ELF identification */
    uint8_t  ei_class;        /* ELFCLASS32 or ELFCLASS64 */
    uint8_t  ei_data;         /* ELFDATA2LSB or ELFDATA2MSB */
    uint8_t  ei_osabi;
    uint8_t  ei_abiversion;
    bool     is_64;
    bool     is_big_endian;

    /* ELF header fields */
    uint16_t e_type;          /* ET_EXEC, ET_DYN, etc. */
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;

    /* Section table */
    akav_elf_section_t sections[AKAV_ELF_MAX_SECTIONS];
    uint16_t           num_sections;

    /* Program headers */
    akav_elf_phdr_t    phdrs[AKAV_ELF_MAX_PHDRS];
    uint16_t           num_phdrs;

    /* Symbols (.symtab) */
    akav_elf_symbol_t* symtab;          /* heap-allocated */
    uint32_t           num_symtab;

    /* Dynamic symbols (.dynsym) */
    akav_elf_symbol_t* dynsym;          /* heap-allocated */
    uint32_t           num_dynsym;

    /* Dynamic entries (.dynamic) */
    akav_elf_dynamic_t dynamic[AKAV_ELF_MAX_DYNAMIC];
    uint32_t           num_dynamic;

    /* DT_NEEDED library names (resolved from .dynstr) */
    char               needed[AKAV_ELF_MAX_NEEDED][AKAV_ELF_MAX_NAME_LEN];
    uint32_t           num_needed;

    /* SONAME (from DT_SONAME) */
    char               soname[AKAV_ELF_MAX_NAME_LEN];

    /* Interpreter (from PT_INTERP) */
    char               interp[AKAV_ELF_MAX_NAME_LEN];

    /* Notes (.note sections / PT_NOTE segments) */
    akav_elf_note_t    notes[AKAV_ELF_MAX_NOTES];
    uint32_t           num_notes;

    /* Build-ID (from NT_GNU_BUILD_ID note) */
    bool               has_build_id;
    uint8_t            build_id[64];
    uint32_t           build_id_len;

    /* Parse status */
    bool               valid;
    char               error[128];
    int                warning_count;
    char               warnings[4][128];
} akav_elf_t;

/**
 * Parse an ELF file from a buffer. All reads use SafeReader (bounds-checked).
 * Supports both ELF32 and ELF64, little-endian and big-endian.
 *
 * Returns true if the core structures (ELF header, section table, program
 * headers) were successfully parsed.
 *
 * On failure, elf->valid is false and elf->error describes the issue.
 */
bool akav_elf_parse(akav_elf_t* elf, const uint8_t* data, size_t data_len);

/**
 * Free heap-allocated symbol tables.
 * Safe to call on a zeroed or partially-parsed elf.
 */
void akav_elf_free(akav_elf_t* elf);

/**
 * Parse the symbol table (.symtab section).
 * Requires a valid akav_elf_t from akav_elf_parse.
 * Populates elf->symtab and elf->num_symtab.
 * Returns true if at least some symbols were parsed.
 */
bool akav_elf_parse_symtab(akav_elf_t* elf, const uint8_t* data, size_t data_len);

/**
 * Parse the dynamic symbol table (.dynsym section).
 * Populates elf->dynsym and elf->num_dynsym.
 * Returns true if at least some symbols were parsed.
 */
bool akav_elf_parse_dynsym(akav_elf_t* elf, const uint8_t* data, size_t data_len);

/**
 * Parse the .dynamic section.
 * Populates elf->dynamic[], elf->needed[], and elf->soname.
 * Returns true if the dynamic section was found and parsed.
 */
bool akav_elf_parse_dynamic(akav_elf_t* elf, const uint8_t* data, size_t data_len);

/**
 * Parse note sections (.note.*) and PT_NOTE segments.
 * Populates elf->notes[], elf->build_id, elf->has_build_id.
 * Returns true if any notes were parsed.
 */
bool akav_elf_parse_notes(akav_elf_t* elf, const uint8_t* data, size_t data_len);

/**
 * Parse the interpreter string from PT_INTERP.
 * Populates elf->interp.
 * Returns true if PT_INTERP was found.
 */
bool akav_elf_parse_interp(akav_elf_t* elf, const uint8_t* data, size_t data_len);

/**
 * Return a human-readable string for the machine type.
 */
const char* akav_elf_machine_name(uint16_t machine);

/**
 * Return a human-readable string for the ELF type (ET_EXEC, etc.).
 */
const char* akav_elf_type_name(uint16_t type);

/**
 * Find a section by name. Returns NULL if not found.
 */
const akav_elf_section_t* akav_elf_find_section(const akav_elf_t* elf,
                                                  const char* name);

/**
 * Run all ELF analysis (symtab, dynsym, dynamic, notes, interp).
 * Convenience function that calls all the above.
 */
void akav_elf_analyze(akav_elf_t* elf, const uint8_t* data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_ELF_H */
