#ifndef AKAV_PE_H
#define AKAV_PE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── PE format constants ─────────────────────────────────────────── */

#define AKAV_PE_DOS_MAGIC        0x5A4D   /* "MZ" */
#define AKAV_PE_SIGNATURE        0x00004550 /* "PE\0\0" */
#define AKAV_PE_OPT_MAGIC_32     0x10B    /* PE32 */
#define AKAV_PE_OPT_MAGIC_64     0x20B    /* PE32+ (64-bit) */

#define AKAV_PE_MAX_SECTIONS     96       /* sanity limit */
#define AKAV_PE_MAX_DATA_DIRS    16       /* IMAGE_NUMBEROF_DIRECTORY_ENTRIES */
#define AKAV_PE_SECTION_NAME_LEN 8

/* ── Machine types ───────────────────────────────────────────────── */

#define AKAV_PE_MACHINE_I386     0x014C
#define AKAV_PE_MACHINE_AMD64    0x8664
#define AKAV_PE_MACHINE_ARM      0x01C0
#define AKAV_PE_MACHINE_ARM64    0xAA64

/* ── Characteristics flags ───────────────────────────────────────── */

#define AKAV_PE_CHAR_EXECUTABLE  0x0002
#define AKAV_PE_CHAR_DLL         0x2000

/* ── Section characteristics ─────────────────────────────────────── */

#define AKAV_PE_SCN_CNT_CODE          0x00000020
#define AKAV_PE_SCN_CNT_INIT_DATA     0x00000040
#define AKAV_PE_SCN_CNT_UNINIT_DATA   0x00000080
#define AKAV_PE_SCN_MEM_EXECUTE       0x20000000
#define AKAV_PE_SCN_MEM_READ          0x40000000
#define AKAV_PE_SCN_MEM_WRITE         0x80000000

/* ── Data directory indices ──────────────────────────────────────── */

#define AKAV_PE_DIR_EXPORT        0
#define AKAV_PE_DIR_IMPORT        1
#define AKAV_PE_DIR_RESOURCE      2
#define AKAV_PE_DIR_EXCEPTION     3
#define AKAV_PE_DIR_SECURITY      4   /* Authenticode */
#define AKAV_PE_DIR_BASERELOC     5
#define AKAV_PE_DIR_DEBUG         6
#define AKAV_PE_DIR_TLS           9
#define AKAV_PE_DIR_IAT          12
#define AKAV_PE_DIR_CLR          14

/* ── Parsed structures ───────────────────────────────────────────── */

typedef struct {
    uint32_t virtual_address;
    uint32_t size;
} akav_pe_data_dir_t;

typedef struct {
    char     name[AKAV_PE_SECTION_NAME_LEN + 1]; /* null-terminated */
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_data_size;
    uint32_t raw_data_offset;
    uint32_t characteristics;
} akav_pe_section_t;

typedef struct {
    /* DOS header */
    uint16_t dos_magic;       /* 0x5A4D */
    uint32_t e_lfanew;        /* offset to PE signature */

    /* COFF header */
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t symbol_table_offset;
    uint32_t num_symbols;
    uint16_t optional_header_size;
    uint16_t characteristics;

    /* Optional header */
    uint16_t opt_magic;       /* 0x10B (PE32) or 0x20B (PE32+) */
    bool     is_pe32plus;     /* true if PE32+ */
    uint8_t  major_linker;
    uint8_t  minor_linker;
    uint32_t size_of_code;
    uint32_t size_of_init_data;
    uint32_t size_of_uninit_data;
    uint32_t entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;    /* PE32 only, 0 for PE32+ */
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t stack_reserve;
    uint64_t stack_commit;
    uint64_t heap_reserve;
    uint64_t heap_commit;
    uint32_t loader_flags;
    uint32_t num_data_dirs;

    /* Data directories */
    akav_pe_data_dir_t data_dirs[AKAV_PE_MAX_DATA_DIRS];

    /* Section table */
    akav_pe_section_t  sections[AKAV_PE_MAX_SECTIONS];

    /* Parse status */
    bool     valid;
    char     error[128];
    int      warning_count;
    char     warnings[4][128];
} akav_pe_t;

/**
 * Parse a PE file from a buffer. All reads use SafeReader (bounds-checked).
 *
 * Returns true if the core structures (DOS header, PE signature, COFF header,
 * optional header, section table) were successfully parsed.
 *
 * On failure, pe->valid is false and pe->error describes the issue.
 * On partial success, pe->valid is true but pe->warnings[] may contain
 * notes about non-critical issues.
 */
bool akav_pe_parse(akav_pe_t* pe, const uint8_t* data, size_t data_len);

/**
 * Return a human-readable string for the machine type.
 */
const char* akav_pe_machine_name(uint16_t machine);

/**
 * Find a section by name. Returns NULL if not found.
 */
const akav_pe_section_t* akav_pe_find_section(const akav_pe_t* pe,
                                                const char* name);

/**
 * Convert an RVA (relative virtual address) to a file offset.
 * Returns 0 if the RVA doesn't fall within any section.
 */
uint32_t akav_pe_rva_to_offset(const akav_pe_t* pe, uint32_t rva);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_PE_H */
