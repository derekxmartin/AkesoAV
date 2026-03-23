#ifndef AKAV_OLE2_H
#define AKAV_OLE2_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── OLE2 format constants ─────────────────────────────────────── */

#define AKAV_OLE2_FREESECT     0xFFFFFFFFU
#define AKAV_OLE2_ENDOFCHAIN   0xFFFFFFFEU
#define AKAV_OLE2_FATSECT      0xFFFFFFFDU
#define AKAV_OLE2_DIFSECT      0xFFFFFFFCU

#define AKAV_OLE2_OBJTYPE_EMPTY    0
#define AKAV_OLE2_OBJTYPE_STORAGE  1
#define AKAV_OLE2_OBJTYPE_STREAM   2
#define AKAV_OLE2_OBJTYPE_ROOT     5

#define AKAV_OLE2_HEADER_DIFAT_COUNT  109

/* ── Sanity limits ─────────────────────────────────────────────── */

#define AKAV_OLE2_MAX_FAT_SECTORS    4096
#define AKAV_OLE2_MAX_DIR_ENTRIES    65536
#define AKAV_OLE2_MAX_STREAMS        1024
#define AKAV_OLE2_MAX_VBA_MODULES    64
#define AKAV_OLE2_MAX_NAME_UTF8      128
#define AKAV_OLE2_MAX_CHAIN_LEN      131072
#define AKAV_OLE2_MAX_DECOMP_SIZE    (16 * 1024 * 1024)

/* ── Parsed header ─────────────────────────────────────────────── */

typedef struct {
    uint16_t minor_version;
    uint16_t major_version;
    uint16_t sector_size;
    uint16_t mini_sector_size;
    uint32_t num_fat_sectors;
    uint32_t dir_start_sector;
    uint32_t mini_stream_cutoff;
    uint32_t minifat_start_sector;
    uint32_t num_minifat_sectors;
    uint32_t difat_start_sector;
    uint32_t num_difat_sectors;
    uint32_t difat[AKAV_OLE2_HEADER_DIFAT_COUNT];
} akav_ole2_header_t;

/* ── Directory entry ───────────────────────────────────────────── */

typedef struct {
    char     name[AKAV_OLE2_MAX_NAME_UTF8];
    uint8_t  obj_type;
    uint32_t child_sid;
    uint32_t left_sid;
    uint32_t right_sid;
    uint32_t start_sector;
    uint64_t stream_size;
    uint32_t sid;
    int32_t  parent_sid;
} akav_ole2_dir_entry_t;

/* ── Extracted stream ──────────────────────────────────────────── */

typedef struct {
    char     name[AKAV_OLE2_MAX_NAME_UTF8];
    uint8_t* data;
    size_t   data_len;
    uint32_t dir_sid;
    bool     is_mini;
} akav_ole2_stream_t;

/* ── VBA module ────────────────────────────────────────────────── */

typedef struct {
    char     module_name[AKAV_OLE2_MAX_NAME_UTF8];
    uint8_t* source;
    size_t   source_len;
} akav_ole2_vba_module_t;

/* ── Parsed OLE2 ───────────────────────────────────────────────── */

typedef struct {
    akav_ole2_header_t header;

    uint32_t* fat;
    uint32_t  num_fat_entries;

    uint32_t* minifat;
    uint32_t  num_minifat_entries;

    akav_ole2_dir_entry_t* dir_entries;
    uint32_t               num_dir_entries;

    akav_ole2_stream_t* streams;
    uint32_t            num_streams;

    akav_ole2_vba_module_t* vba_modules;
    uint32_t                num_vba_modules;

    bool has_vba;
    bool has_macros;

    bool valid;
    char error[128];
    int  warning_count;
    char warnings[4][128];
} akav_ole2_t;

/* ── Public API ────────────────────────────────────────────────── */

bool akav_ole2_parse(akav_ole2_t* ole2,
                      const uint8_t* data, size_t data_len);

void akav_ole2_free(akav_ole2_t* ole2);

bool akav_ole2_extract_streams(akav_ole2_t* ole2,
                                const uint8_t* data, size_t data_len);

bool akav_ole2_extract_vba(akav_ole2_t* ole2,
                            const uint8_t* data, size_t data_len);

void akav_ole2_analyze(akav_ole2_t* ole2,
                        const uint8_t* data, size_t data_len);

const akav_ole2_dir_entry_t* akav_ole2_find_entry(
    const akav_ole2_t* ole2, const char* name);

bool akav_ole2_ovba_decompress(const uint8_t* in, size_t in_len,
                                uint8_t** out, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_OLE2_H */
