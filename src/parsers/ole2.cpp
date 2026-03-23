#include "ole2.h"
#include "safe_reader.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cctype>

/* ── Error / warning helpers ─────────────────────────────────────── */

static void ole2_error(akav_ole2_t* ole2, const char* msg)
{
    ole2->valid = false;
    strncpy_s(ole2->error, sizeof(ole2->error), msg, _TRUNCATE);
}

static void ole2_warn(akav_ole2_t* ole2, const char* msg)
{
    if (ole2->warning_count < 4) {
        strncpy_s(ole2->warnings[ole2->warning_count],
                  sizeof(ole2->warnings[0]), msg, _TRUNCATE);
        ole2->warning_count++;
    }
}

/* ── Sector offset helper ────────────────────────────────────────── */

static size_t sector_offset(uint32_t sector, uint32_t sector_size)
{
    return (size_t)(sector + 1) * sector_size;
}

/* ── UTF-16LE to UTF-8 conversion ────────────────────────────────── */

static void utf16le_to_utf8(const uint8_t* src, uint16_t byte_count,
                            char* dst, size_t dst_size)
{
    size_t out = 0;
    uint16_t num_units = byte_count / 2;

    for (uint16_t i = 0; i < num_units; i++) {
        uint16_t code = (uint16_t)(src[i * 2] | (src[i * 2 + 1] << 8));
        if (code == 0) break;

        if (code < 0x80) {
            if (out + 1 >= dst_size) break;
            dst[out++] = (char)code;
        } else if (code < 0x800) {
            if (out + 2 >= dst_size) break;
            dst[out++] = (char)(0xC0 | (code >> 6));
            dst[out++] = (char)(0x80 | (code & 0x3F));
        } else {
            if (out + 3 >= dst_size) break;
            dst[out++] = (char)(0xE0 | (code >> 12));
            dst[out++] = (char)(0x80 | ((code >> 6) & 0x3F));
            dst[out++] = (char)(0x80 | (code & 0x3F));
        }
    }
    dst[out] = '\0';
}

/* ── Follow a FAT chain and collect data ─────────────────────────── */

static uint8_t* follow_fat_chain(const akav_ole2_t* ole2,
                                 const uint8_t* data, size_t data_len,
                                 uint32_t start_sector, uint64_t stream_size,
                                 size_t* out_len)
{
    if (start_sector == AKAV_OLE2_ENDOFCHAIN ||
        start_sector == AKAV_OLE2_FREESECT ||
        stream_size == 0) {
        *out_len = 0;
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc((size_t)stream_size);
    if (!buf) {
        *out_len = 0;
        return NULL;
    }

    uint32_t sec_size = ole2->header.sector_size;
    size_t copied = 0;
    uint32_t sector = start_sector;
    uint32_t chain_len = 0;
    akav_safe_reader_t r;
    akav_reader_init(&r, data, data_len);

    while (sector != AKAV_OLE2_ENDOFCHAIN &&
           sector != AKAV_OLE2_FREESECT &&
           copied < (size_t)stream_size) {

        if (++chain_len > AKAV_OLE2_MAX_CHAIN_LEN) {
            free(buf);
            *out_len = 0;
            return NULL;
        }

        size_t off = sector_offset(sector, sec_size);
        if (!akav_reader_seek_to(&r, off)) {
            free(buf);
            *out_len = 0;
            return NULL;
        }

        size_t to_copy = sec_size;
        if (copied + to_copy > (size_t)stream_size)
            to_copy = (size_t)stream_size - copied;

        if (!akav_reader_read_bytes(&r, buf + copied, to_copy)) {
            free(buf);
            *out_len = 0;
            return NULL;
        }
        copied += to_copy;

        if (sector >= ole2->num_fat_entries) {
            free(buf);
            *out_len = 0;
            return NULL;
        }
        sector = ole2->fat[sector];
    }

    *out_len = copied;
    return buf;
}

/* ── Follow a mini-FAT chain and collect data ────────────────────── */

static uint8_t* follow_minifat_chain(const akav_ole2_t* ole2,
                                     const uint8_t* mini_stream_data,
                                     size_t mini_stream_len,
                                     uint32_t start_sector, uint64_t stream_size,
                                     size_t* out_len)
{
    if (start_sector == AKAV_OLE2_ENDOFCHAIN ||
        start_sector == AKAV_OLE2_FREESECT ||
        stream_size == 0) {
        *out_len = 0;
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc((size_t)stream_size);
    if (!buf) {
        *out_len = 0;
        return NULL;
    }

    uint32_t mini_sec_size = ole2->header.mini_sector_size;
    size_t copied = 0;
    uint32_t sector = start_sector;
    uint32_t chain_len = 0;

    while (sector != AKAV_OLE2_ENDOFCHAIN &&
           sector != AKAV_OLE2_FREESECT &&
           copied < (size_t)stream_size) {

        if (++chain_len > AKAV_OLE2_MAX_CHAIN_LEN) {
            free(buf);
            *out_len = 0;
            return NULL;
        }

        size_t off = (size_t)sector * mini_sec_size;
        if (off >= mini_stream_len) {
            free(buf);
            *out_len = 0;
            return NULL;
        }

        size_t to_copy = mini_sec_size;
        if (copied + to_copy > (size_t)stream_size)
            to_copy = (size_t)stream_size - copied;
        if (off + to_copy > mini_stream_len)
            to_copy = mini_stream_len - off;

        memcpy(buf + copied, mini_stream_data + off, to_copy);
        copied += to_copy;

        if (sector >= ole2->num_minifat_entries) {
            free(buf);
            *out_len = 0;
            return NULL;
        }
        sector = ole2->minifat[sector];
    }

    *out_len = copied;
    return buf;
}

/* ── Parse header ────────────────────────────────────────────────── */

static bool parse_header(akav_ole2_t* ole2, akav_safe_reader_t* r)
{
    /* Validate magic: D0 CF 11 E0 A1 B1 1A E1 */
    static const uint8_t ole2_magic[8] = {
        0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1
    };
    uint8_t magic[8];
    if (!akav_reader_read_bytes(r, magic, 8)) {
        ole2_error(ole2, "File too small for OLE2 magic");
        return false;
    }
    if (memcmp(magic, ole2_magic, 8) != 0) {
        ole2_error(ole2, "Invalid OLE2 magic signature");
        return false;
    }

    /* Skip CLSID (16 bytes) */
    if (!akav_reader_skip(r, 16)) {
        ole2_error(ole2, "Truncated header (CLSID)");
        return false;
    }

    /* Offset 24: minor version */
    if (!akav_reader_read_u16_le(r, &ole2->header.minor_version)) {
        ole2_error(ole2, "Truncated header (minor version)");
        return false;
    }

    /* Offset 26: major version */
    if (!akav_reader_read_u16_le(r, &ole2->header.major_version)) {
        ole2_error(ole2, "Truncated header (major version)");
        return false;
    }

    if (ole2->header.major_version != 3 && ole2->header.major_version != 4) {
        ole2_warn(ole2, "Unexpected major version (not 3 or 4)");
    }

    /* Offset 28: byte order (must be 0xFFFE = little-endian) */
    uint16_t byte_order;
    if (!akav_reader_read_u16_le(r, &byte_order)) {
        ole2_error(ole2, "Truncated header (byte order)");
        return false;
    }
    if (byte_order != 0xFFFE) {
        ole2_error(ole2, "Invalid byte order (expected 0xFFFE)");
        return false;
    }

    /* Offset 30: sector size power */
    uint16_t sector_size_power;
    if (!akav_reader_read_u16_le(r, &sector_size_power)) {
        ole2_error(ole2, "Truncated header (sector size)");
        return false;
    }
    if (sector_size_power < 7 || sector_size_power > 16) {
        ole2_error(ole2, "Invalid sector size power");
        return false;
    }
    ole2->header.sector_size = (uint16_t)(1u << sector_size_power);

    /* Offset 32: mini sector size power */
    uint16_t mini_sector_size_power;
    if (!akav_reader_read_u16_le(r, &mini_sector_size_power)) {
        ole2_error(ole2, "Truncated header (mini sector size)");
        return false;
    }
    if (mini_sector_size_power > 16) {
        ole2_error(ole2, "Invalid mini sector size power");
        return false;
    }
    ole2->header.mini_sector_size = (uint16_t)(1u << mini_sector_size_power);

    /* Skip 6 reserved bytes (offset 34-39) */
    if (!akav_reader_skip(r, 6)) {
        ole2_error(ole2, "Truncated header (reserved)");
        return false;
    }

    /* Offset 40: total sectors (v3 unused, skip) */
    uint32_t total_sectors_v3;
    if (!akav_reader_read_u32_le(r, &total_sectors_v3)) {
        ole2_error(ole2, "Truncated header (total sectors)");
        return false;
    }

    /* Offset 44: num FAT sectors */
    if (!akav_reader_read_u32_le(r, &ole2->header.num_fat_sectors)) {
        ole2_error(ole2, "Truncated header (FAT sector count)");
        return false;
    }

    /* Offset 48: first directory sector */
    if (!akav_reader_read_u32_le(r, &ole2->header.dir_start_sector)) {
        ole2_error(ole2, "Truncated header (dir start sector)");
        return false;
    }

    /* Offset 52: transaction signature (skip) */
    if (!akav_reader_skip(r, 4)) {
        ole2_error(ole2, "Truncated header (transaction sig)");
        return false;
    }

    /* Offset 56: mini stream cutoff */
    if (!akav_reader_read_u32_le(r, &ole2->header.mini_stream_cutoff)) {
        ole2_error(ole2, "Truncated header (mini stream cutoff)");
        return false;
    }

    /* Offset 60: mini FAT start sector */
    if (!akav_reader_read_u32_le(r, &ole2->header.minifat_start_sector)) {
        ole2_error(ole2, "Truncated header (mini FAT start)");
        return false;
    }

    /* Offset 64: num mini FAT sectors */
    if (!akav_reader_read_u32_le(r, &ole2->header.num_minifat_sectors)) {
        ole2_error(ole2, "Truncated header (mini FAT count)");
        return false;
    }

    /* Offset 68: DIFAT start sector */
    if (!akav_reader_read_u32_le(r, &ole2->header.difat_start_sector)) {
        ole2_error(ole2, "Truncated header (DIFAT start)");
        return false;
    }

    /* Offset 72: num DIFAT sectors */
    if (!akav_reader_read_u32_le(r, &ole2->header.num_difat_sectors)) {
        ole2_error(ole2, "Truncated header (DIFAT count)");
        return false;
    }

    /* Offset 76: 109 DIFAT entries */
    for (int i = 0; i < AKAV_OLE2_HEADER_DIFAT_COUNT; i++) {
        if (!akav_reader_read_u32_le(r, &ole2->header.difat[i])) {
            ole2_error(ole2, "Truncated header (DIFAT array)");
            return false;
        }
    }

    return true;
}

/* ── Build FAT from DIFAT ────────────────────────────────────────── */

static bool build_fat(akav_ole2_t* ole2, const uint8_t* data, size_t data_len)
{
    uint32_t sec_size = ole2->header.sector_size;
    uint32_t entries_per_sector = sec_size / 4;

    if (ole2->header.num_fat_sectors > AKAV_OLE2_MAX_FAT_SECTORS) {
        ole2_error(ole2, "Too many FAT sectors");
        return false;
    }

    /* Collect all FAT sector IDs from DIFAT */
    uint32_t fat_sector_ids[AKAV_OLE2_MAX_FAT_SECTORS];
    uint32_t fat_sector_count = 0;

    /* First 109 from header DIFAT */
    for (int i = 0; i < AKAV_OLE2_HEADER_DIFAT_COUNT; i++) {
        if (ole2->header.difat[i] == AKAV_OLE2_FREESECT ||
            ole2->header.difat[i] == AKAV_OLE2_ENDOFCHAIN)
            break;
        if (fat_sector_count >= AKAV_OLE2_MAX_FAT_SECTORS) {
            ole2_error(ole2, "Too many FAT sectors in DIFAT");
            return false;
        }
        fat_sector_ids[fat_sector_count++] = ole2->header.difat[i];
    }

    /* Additional DIFAT sectors */
    uint32_t difat_sector = ole2->header.difat_start_sector;
    uint32_t difat_visited = 0;

    while (difat_sector != AKAV_OLE2_ENDOFCHAIN &&
           difat_sector != AKAV_OLE2_FREESECT) {
        if (++difat_visited > AKAV_OLE2_MAX_CHAIN_LEN) {
            ole2_error(ole2, "DIFAT chain too long (loop?)");
            return false;
        }

        size_t off = sector_offset(difat_sector, sec_size);
        akav_safe_reader_t dr;
        akav_reader_init(&dr, data, data_len);
        if (!akav_reader_seek_to(&dr, off)) {
            ole2_error(ole2, "DIFAT sector out of bounds");
            return false;
        }

        /* Each DIFAT sector: (entries_per_sector - 1) FAT IDs + 1 next DIFAT */
        for (uint32_t i = 0; i < entries_per_sector - 1; i++) {
            uint32_t sid;
            if (!akav_reader_read_u32_le(&dr, &sid)) {
                ole2_error(ole2, "Truncated DIFAT sector");
                return false;
            }
            if (sid == AKAV_OLE2_FREESECT || sid == AKAV_OLE2_ENDOFCHAIN)
                continue;
            if (fat_sector_count >= AKAV_OLE2_MAX_FAT_SECTORS) {
                ole2_error(ole2, "Too many FAT sectors from DIFAT chain");
                return false;
            }
            fat_sector_ids[fat_sector_count++] = sid;
        }

        /* Next DIFAT sector pointer */
        if (!akav_reader_read_u32_le(&dr, &difat_sector)) {
            ole2_error(ole2, "Truncated DIFAT next pointer");
            return false;
        }
    }

    /* Allocate FAT */
    ole2->num_fat_entries = fat_sector_count * entries_per_sector;
    ole2->fat = (uint32_t*)calloc(ole2->num_fat_entries, sizeof(uint32_t));
    if (!ole2->fat) {
        ole2_error(ole2, "FAT allocation failed");
        return false;
    }

    /* Read each FAT sector */
    akav_safe_reader_t fr;
    akav_reader_init(&fr, data, data_len);

    for (uint32_t i = 0; i < fat_sector_count; i++) {
        size_t off = sector_offset(fat_sector_ids[i], sec_size);
        if (!akav_reader_seek_to(&fr, off)) {
            ole2_error(ole2, "FAT sector out of bounds");
            return false;
        }
        for (uint32_t j = 0; j < entries_per_sector; j++) {
            if (!akav_reader_read_u32_le(&fr, &ole2->fat[i * entries_per_sector + j])) {
                ole2_error(ole2, "Truncated FAT sector data");
                return false;
            }
        }
    }

    return true;
}

/* ── Build mini-FAT ──────────────────────────────────────────────── */

static bool build_minifat(akav_ole2_t* ole2, const uint8_t* data, size_t data_len)
{
    if (ole2->header.num_minifat_sectors == 0 ||
        ole2->header.minifat_start_sector == AKAV_OLE2_ENDOFCHAIN ||
        ole2->header.minifat_start_sector == AKAV_OLE2_FREESECT) {
        ole2->minifat = NULL;
        ole2->num_minifat_entries = 0;
        return true;
    }

    uint32_t sec_size = ole2->header.sector_size;
    uint32_t entries_per_sector = sec_size / 4;

    /* Count sectors by following FAT chain */
    uint32_t sector = ole2->header.minifat_start_sector;
    uint32_t sector_count = 0;
    uint32_t chain_len = 0;

    while (sector != AKAV_OLE2_ENDOFCHAIN &&
           sector != AKAV_OLE2_FREESECT) {
        if (++chain_len > AKAV_OLE2_MAX_CHAIN_LEN) {
            ole2_error(ole2, "Mini-FAT chain too long");
            return false;
        }
        sector_count++;
        if (sector >= ole2->num_fat_entries) {
            ole2_error(ole2, "Mini-FAT chain sector out of range");
            return false;
        }
        sector = ole2->fat[sector];
    }

    ole2->num_minifat_entries = sector_count * entries_per_sector;
    ole2->minifat = (uint32_t*)calloc(ole2->num_minifat_entries, sizeof(uint32_t));
    if (!ole2->minifat) {
        ole2_error(ole2, "Mini-FAT allocation failed");
        return false;
    }

    /* Read mini-FAT sectors */
    akav_safe_reader_t mr;
    akav_reader_init(&mr, data, data_len);
    sector = ole2->header.minifat_start_sector;
    uint32_t idx = 0;

    while (sector != AKAV_OLE2_ENDOFCHAIN &&
           sector != AKAV_OLE2_FREESECT) {
        size_t off = sector_offset(sector, sec_size);
        if (!akav_reader_seek_to(&mr, off)) {
            ole2_error(ole2, "Mini-FAT sector out of bounds");
            return false;
        }
        for (uint32_t j = 0; j < entries_per_sector; j++) {
            if (!akav_reader_read_u32_le(&mr, &ole2->minifat[idx++])) {
                ole2_error(ole2, "Truncated mini-FAT data");
                return false;
            }
        }
        if (sector >= ole2->num_fat_entries) break;
        sector = ole2->fat[sector];
    }

    return true;
}

/* ── Parse directory entries ─────────────────────────────────────── */

static bool parse_directory(akav_ole2_t* ole2, const uint8_t* data, size_t data_len)
{
    uint32_t sec_size = ole2->header.sector_size;
    uint32_t entries_per_sector = sec_size / 128;

    /* Count sectors in directory chain */
    uint32_t sector = ole2->header.dir_start_sector;
    uint32_t sector_count = 0;
    uint32_t chain_len = 0;

    while (sector != AKAV_OLE2_ENDOFCHAIN &&
           sector != AKAV_OLE2_FREESECT) {
        if (++chain_len > AKAV_OLE2_MAX_CHAIN_LEN) {
            ole2_error(ole2, "Directory chain too long");
            return false;
        }
        sector_count++;
        if (sector >= ole2->num_fat_entries) {
            ole2_error(ole2, "Directory chain sector out of range");
            return false;
        }
        sector = ole2->fat[sector];
    }

    uint32_t total_entries = sector_count * entries_per_sector;
    if (total_entries > AKAV_OLE2_MAX_DIR_ENTRIES)
        total_entries = AKAV_OLE2_MAX_DIR_ENTRIES;

    ole2->dir_entries = (akav_ole2_dir_entry_t*)calloc(
        total_entries, sizeof(akav_ole2_dir_entry_t));
    if (!ole2->dir_entries) {
        ole2_error(ole2, "Directory allocation failed");
        return false;
    }

    /* Read directory entries */
    akav_safe_reader_t er;
    akav_reader_init(&er, data, data_len);
    sector = ole2->header.dir_start_sector;
    uint32_t dir_idx = 0;

    while (sector != AKAV_OLE2_ENDOFCHAIN &&
           sector != AKAV_OLE2_FREESECT &&
           dir_idx < total_entries) {

        size_t sec_off = sector_offset(sector, sec_size);

        for (uint32_t e = 0; e < entries_per_sector && dir_idx < total_entries; e++) {
            size_t entry_off = sec_off + (size_t)e * 128;
            if (!akav_reader_seek_to(&er, entry_off)) break;

            akav_ole2_dir_entry_t* ent = &ole2->dir_entries[dir_idx];

            /* Bytes 0-63: name (UTF-16LE) */
            uint8_t name_raw[64];
            if (!akav_reader_read_bytes(&er, name_raw, 64)) break;

            /* Byte 64-65: name size in bytes */
            uint16_t name_size;
            if (!akav_reader_read_u16_le(&er, &name_size)) break;

            /* Convert name */
            if (name_size > 64) name_size = 64;
            utf16le_to_utf8(name_raw, name_size, ent->name, sizeof(ent->name));

            /* Byte 66: object type */
            uint8_t obj_type;
            if (!akav_reader_read_u8(&er, &obj_type)) break;
            ent->obj_type = obj_type;

            /* Byte 67: color flag (skip) */
            if (!akav_reader_skip(&er, 1)) break;

            /* Bytes 68-71: left sibling SID */
            if (!akav_reader_read_u32_le(&er, &ent->left_sid)) break;

            /* Bytes 72-75: right sibling SID */
            if (!akav_reader_read_u32_le(&er, &ent->right_sid)) break;

            /* Bytes 76-79: child SID */
            if (!akav_reader_read_u32_le(&er, &ent->child_sid)) break;

            /* Bytes 80-115: CLSID + state bits + timestamps (skip 36 bytes) */
            if (!akav_reader_skip(&er, 36)) break;

            /* Bytes 116-119: start sector */
            if (!akav_reader_read_u32_le(&er, &ent->start_sector)) break;

            /* Bytes 120-127: stream size */
            if (!akav_reader_read_u64_le(&er, &ent->stream_size)) break;

            /* For v3, only lower 32 bits of stream size are valid */
            if (ole2->header.major_version == 3) {
                ent->stream_size = (uint64_t)(uint32_t)ent->stream_size;
            }

            ent->sid = dir_idx;
            ent->parent_sid = -1;

            /* Only count non-empty entries */
            if (ent->obj_type != AKAV_OLE2_OBJTYPE_EMPTY) {
                dir_idx++;
            } else {
                dir_idx++;
            }
        }

        if (sector >= ole2->num_fat_entries) break;
        sector = ole2->fat[sector];
    }

    ole2->num_dir_entries = dir_idx;

    /* Assign parent SIDs by walking the red-black tree under each storage.
     * child_sid points to the root of the RB tree; left_sid/right_sid are
     * siblings that also belong to the same parent storage. */
    for (uint32_t i = 0; i < ole2->num_dir_entries; i++) {
        akav_ole2_dir_entry_t* ent = &ole2->dir_entries[i];
        if (ent->child_sid == AKAV_OLE2_FREESECT ||
            ent->child_sid >= ole2->num_dir_entries)
            continue;

        /* BFS/DFS through the RB tree to assign parent_sid to all siblings */
        uint32_t stack[256];
        uint32_t sp = 0;
        stack[sp++] = ent->child_sid;

        while (sp > 0) {
            uint32_t sid = stack[--sp];
            if (sid >= ole2->num_dir_entries || sid == AKAV_OLE2_FREESECT)
                continue;
            ole2->dir_entries[sid].parent_sid = (int32_t)i;

            uint32_t left = ole2->dir_entries[sid].left_sid;
            uint32_t right = ole2->dir_entries[sid].right_sid;

            if (left != AKAV_OLE2_FREESECT && left < ole2->num_dir_entries &&
                sp < 256)
                stack[sp++] = left;
            if (right != AKAV_OLE2_FREESECT && right < ole2->num_dir_entries &&
                sp < 256)
                stack[sp++] = right;
        }
    }

    return true;
}

/* ── Public: akav_ole2_parse ─────────────────────────────────────── */

extern "C"
bool akav_ole2_parse(akav_ole2_t* ole2, const uint8_t* data, size_t data_len)
{
    memset(ole2, 0, sizeof(*ole2));

    if (!data || data_len < 512) {
        ole2_error(ole2, "Data too small for OLE2 header");
        return false;
    }

    akav_safe_reader_t r;
    akav_reader_init(&r, data, data_len);

    if (!parse_header(ole2, &r)) return false;
    if (!build_fat(ole2, data, data_len)) return false;
    if (!build_minifat(ole2, data, data_len)) return false;
    if (!parse_directory(ole2, data, data_len)) return false;

    ole2->valid = true;
    return true;
}

/* ── Public: akav_ole2_free ──────────────────────────────────────── */

extern "C"
void akav_ole2_free(akav_ole2_t* ole2)
{
    if (!ole2) return;

    if (ole2->fat) {
        free(ole2->fat);
    }

    if (ole2->minifat) {
        free(ole2->minifat);
    }

    if (ole2->dir_entries) {
        free(ole2->dir_entries);
    }

    if (ole2->streams) {
        for (uint32_t i = 0; i < ole2->num_streams; i++) {
            if (ole2->streams[i].data) {
                free(ole2->streams[i].data);
            }
        }
        free(ole2->streams);
    }

    if (ole2->vba_modules) {
        for (uint32_t i = 0; i < ole2->num_vba_modules; i++) {
            if (ole2->vba_modules[i].source) {
                free(ole2->vba_modules[i].source);
            }
        }
        free(ole2->vba_modules);
    }

    memset(ole2, 0, sizeof(*ole2));
}

/* ── Public: akav_ole2_extract_streams ───────────────────────────── */

extern "C"
bool akav_ole2_extract_streams(akav_ole2_t* ole2,
                               const uint8_t* data, size_t data_len)
{
    if (!ole2->valid || !ole2->dir_entries) {
        ole2_error(ole2, "Cannot extract streams: OLE2 not parsed");
        return false;
    }

    /* Get root entry's mini-stream data */
    uint8_t* mini_stream_data = NULL;
    size_t mini_stream_len = 0;

    /* Root entry is always dir_entries[0] (obj_type == ROOT) */
    if (ole2->num_dir_entries > 0 &&
        ole2->dir_entries[0].obj_type == AKAV_OLE2_OBJTYPE_ROOT) {
        const akav_ole2_dir_entry_t* root = &ole2->dir_entries[0];
        if (root->stream_size > 0 &&
            root->start_sector != AKAV_OLE2_ENDOFCHAIN &&
            root->start_sector != AKAV_OLE2_FREESECT) {
            mini_stream_data = follow_fat_chain(
                ole2, data, data_len,
                root->start_sector, root->stream_size,
                &mini_stream_len);
        }
    }

    /* Count stream entries */
    uint32_t stream_count = 0;
    for (uint32_t i = 0; i < ole2->num_dir_entries; i++) {
        if (ole2->dir_entries[i].obj_type == AKAV_OLE2_OBJTYPE_STREAM)
            stream_count++;
    }

    if (stream_count > AKAV_OLE2_MAX_STREAMS)
        stream_count = AKAV_OLE2_MAX_STREAMS;

    if (stream_count == 0) {
        free(mini_stream_data);
        ole2->streams = NULL;
        ole2->num_streams = 0;
        return true;
    }

    ole2->streams = (akav_ole2_stream_t*)calloc(
        stream_count, sizeof(akav_ole2_stream_t));
    if (!ole2->streams) {
        free(mini_stream_data);
        ole2_error(ole2, "Stream array allocation failed");
        return false;
    }

    uint32_t si = 0;
    for (uint32_t i = 0; i < ole2->num_dir_entries && si < stream_count; i++) {
        const akav_ole2_dir_entry_t* ent = &ole2->dir_entries[i];
        if (ent->obj_type != AKAV_OLE2_OBJTYPE_STREAM) continue;
        if (ent->stream_size == 0) {
            /* Empty stream */
            strncpy_s(ole2->streams[si].name,
                      sizeof(ole2->streams[si].name),
                      ent->name, _TRUNCATE);
            ole2->streams[si].data = NULL;
            ole2->streams[si].data_len = 0;
            ole2->streams[si].dir_sid = ent->sid;
            ole2->streams[si].is_mini = false;
            si++;
            continue;
        }

        bool is_mini = (ent->stream_size < ole2->header.mini_stream_cutoff);
        uint8_t* sdata = NULL;
        size_t slen = 0;

        if (is_mini && mini_stream_data) {
            sdata = follow_minifat_chain(
                ole2, mini_stream_data, mini_stream_len,
                ent->start_sector, ent->stream_size, &slen);
        } else {
            sdata = follow_fat_chain(
                ole2, data, data_len,
                ent->start_sector, ent->stream_size, &slen);
        }

        strncpy_s(ole2->streams[si].name,
                  sizeof(ole2->streams[si].name),
                  ent->name, _TRUNCATE);
        ole2->streams[si].data = sdata;
        ole2->streams[si].data_len = slen;
        ole2->streams[si].dir_sid = ent->sid;
        ole2->streams[si].is_mini = is_mini;
        si++;
    }

    ole2->num_streams = si;
    free(mini_stream_data);
    return true;
}

/* ── Public: akav_ole2_ovba_decompress ───────────────────────────── */

extern "C"
bool akav_ole2_ovba_decompress(const uint8_t* in, size_t in_len,
                               uint8_t** out, size_t* out_len)
{
    *out = NULL;
    *out_len = 0;

    if (!in || in_len < 3) return false;  /* need signature + at least 1 chunk header */

    /* Signature byte must be 0x01 */
    if (in[0] != 0x01) return false;

    /* Allocate output buffer */
    size_t out_cap = 4096;
    uint8_t* buf = (uint8_t*)malloc(out_cap);
    if (!buf) return false;

    size_t out_pos = 0;
    size_t in_pos = 1;

    while (in_pos < in_len) {
        /* Read chunk header (2 bytes LE) */
        if (in_pos + 2 > in_len) break;
        uint16_t chunk_header = (uint16_t)(in[in_pos] | (in[in_pos + 1] << 8));
        in_pos += 2;

        uint16_t chunk_data_size = (uint16_t)((chunk_header & 0x0FFF) + 3);
        bool compressed = (chunk_header & 0x8000) != 0;

        size_t chunk_end = in_pos + chunk_data_size;
        if (chunk_end > in_len) {
            chunk_end = in_len;
        }

        size_t chunk_start_out = out_pos;

        if (!compressed) {
            /* Raw chunk: copy 4096 bytes */
            size_t raw_size = chunk_end - in_pos;
            if (raw_size > 4096) raw_size = 4096;

            if (out_pos + raw_size > AKAV_OLE2_MAX_DECOMP_SIZE) {
                free(buf);
                return false;
            }
            while (out_pos + raw_size > out_cap) {
                out_cap *= 2;
                uint8_t* tmp = (uint8_t*)realloc(buf, out_cap);
                if (!tmp) { free(buf); return false; }
                buf = tmp;
            }
            memcpy(buf + out_pos, in + in_pos, raw_size);
            out_pos += raw_size;
            in_pos = chunk_end;
        } else {
            /* Compressed chunk: token stream */
            while (in_pos < chunk_end) {
                if (in_pos >= in_len) break;
                uint8_t flag_byte = in[in_pos++];

                for (int bit = 0; bit < 8 && in_pos < chunk_end; bit++) {
                    if ((flag_byte & (1 << bit)) == 0) {
                        /* Literal byte */
                        if (out_pos + 1 > AKAV_OLE2_MAX_DECOMP_SIZE) {
                            free(buf);
                            return false;
                        }
                        if (out_pos + 1 > out_cap) {
                            out_cap *= 2;
                            uint8_t* tmp = (uint8_t*)realloc(buf, out_cap);
                            if (!tmp) { free(buf); return false; }
                            buf = tmp;
                        }
                        buf[out_pos++] = in[in_pos++];
                    } else {
                        /* CopyToken (2 bytes LE) */
                        if (in_pos + 2 > chunk_end || in_pos + 2 > in_len) {
                            free(buf);
                            return false;
                        }
                        uint16_t token = (uint16_t)(in[in_pos] | (in[in_pos + 1] << 8));
                        in_pos += 2;

                        /* Dynamic bit count based on decompressed chunk length */
                        size_t decompressed_chunk_len = out_pos - chunk_start_out;
                        uint32_t bit_count = 4;
                        while (((size_t)1 << bit_count) < decompressed_chunk_len) {
                            bit_count++;
                        }

                        uint16_t length_mask = (uint16_t)(0xFFFFu >> bit_count);
                        uint32_t copy_len = (uint32_t)(token & length_mask) + 3;
                        uint32_t copy_offset = (uint32_t)(token >> (16 - bit_count)) + 1;

                        if (copy_offset > out_pos - chunk_start_out) {
                            free(buf);
                            return false;
                        }

                        if (out_pos + copy_len > AKAV_OLE2_MAX_DECOMP_SIZE) {
                            free(buf);
                            return false;
                        }
                        while (out_pos + copy_len > out_cap) {
                            out_cap *= 2;
                            uint8_t* tmp = (uint8_t*)realloc(buf, out_cap);
                            if (!tmp) { free(buf); return false; }
                            buf = tmp;
                        }

                        /* Copy byte by byte (source may overlap destination) */
                        size_t src_pos = out_pos - copy_offset;
                        for (uint32_t c = 0; c < copy_len; c++) {
                            buf[out_pos++] = buf[src_pos + c];
                        }
                    }
                }
            }
        }
    }

    *out = buf;
    *out_len = out_pos;
    return true;
}

/* ── Check if a dir entry is a child of a VBA storage ────────────── */

static bool is_child_of_vba(const akav_ole2_t* ole2, uint32_t sid)
{
    /* Walk up parent chain to find a storage named "VBA" */
    int32_t current = (int32_t)sid;
    uint32_t depth = 0;

    while (current >= 0 && (uint32_t)current < ole2->num_dir_entries) {
        if (++depth > ole2->num_dir_entries) break; /* loop guard */
        const akav_ole2_dir_entry_t* ent = &ole2->dir_entries[current];
        if (_stricmp(ent->name, "VBA") == 0 &&
            ent->obj_type == AKAV_OLE2_OBJTYPE_STORAGE) {
            return true;
        }
        current = ent->parent_sid;
    }
    return false;
}

/* ── Public: akav_ole2_extract_vba ───────────────────────────────── */

extern "C"
bool akav_ole2_extract_vba(akav_ole2_t* ole2,
                           const uint8_t* data, size_t data_len)
{
    (void)data;
    (void)data_len;

    if (!ole2->valid || !ole2->streams) {
        return false;
    }

    /* Find the "dir" stream inside VBA storage */
    const akav_ole2_stream_t* dir_stream = NULL;
    for (uint32_t i = 0; i < ole2->num_streams; i++) {
        if (_stricmp(ole2->streams[i].name, "dir") == 0) {
            /* Check it's inside a VBA storage */
            if (is_child_of_vba(ole2, ole2->streams[i].dir_sid)) {
                dir_stream = &ole2->streams[i];
                break;
            }
        }
    }

    if (!dir_stream || !dir_stream->data || dir_stream->data_len == 0) {
        return false; /* No VBA */
    }

    /* Decompress the dir stream */
    uint8_t* dir_data = NULL;
    size_t dir_data_len = 0;
    if (!akav_ole2_ovba_decompress(dir_stream->data, dir_stream->data_len,
                                   &dir_data, &dir_data_len)) {
        return false;
    }

    /* Parse the decompressed dir stream for module info */
    /* We look for MODULE_NAME (0x0019) and MODULE_OFFSET (0x0031) records */
    char module_names[AKAV_OLE2_MAX_VBA_MODULES][AKAV_OLE2_MAX_NAME_UTF8];
    uint32_t module_offsets[AKAV_OLE2_MAX_VBA_MODULES];
    uint32_t module_count = 0;

    memset(module_names, 0, sizeof(module_names));
    memset(module_offsets, 0, sizeof(module_offsets));

    /* Current module state while parsing */
    char current_name[AKAV_OLE2_MAX_NAME_UTF8];
    uint32_t current_offset = 0;
    bool have_name = false;

    memset(current_name, 0, sizeof(current_name));

    akav_safe_reader_t dr;
    akav_reader_init(&dr, dir_data, dir_data_len);

    while (akav_reader_remaining(&dr) >= 2) {
        uint16_t rec_type;
        if (!akav_reader_read_u16_le(&dr, &rec_type)) break;

        if (rec_type == 0x0019) {
            /* MODULE_NAME: uint32_t size, then name bytes */
            uint32_t name_len;
            if (!akav_reader_read_u32_le(&dr, &name_len)) break;
            if (name_len > AKAV_OLE2_MAX_NAME_UTF8 - 1)
                name_len = AKAV_OLE2_MAX_NAME_UTF8 - 1;

            memset(current_name, 0, sizeof(current_name));
            if (name_len > 0) {
                if (!akav_reader_read_bytes(&dr, (uint8_t*)current_name, name_len))
                    break;
            }
            current_name[name_len] = '\0';
            have_name = true;
        } else if (rec_type == 0x0047) {
            /* MODULE_NAMEUNICODE: uint32_t size, then skip unicode name */
            uint32_t size;
            if (!akav_reader_read_u32_le(&dr, &size)) break;
            if (!akav_reader_skip(&dr, size)) break;
        } else if (rec_type == 0x0031) {
            /* MODULE_OFFSET: uint32_t size (always 4), uint32_t TextOffset */
            uint32_t size;
            if (!akav_reader_read_u32_le(&dr, &size)) break;
            if (size != 4) {
                if (!akav_reader_skip(&dr, size)) break;
                continue;
            }
            if (!akav_reader_read_u32_le(&dr, &current_offset)) break;
        } else if (rec_type == 0x002B) {
            /* MODULE_TERMINATOR: uint32_t reserved (skip 4 bytes) */
            if (!akav_reader_skip(&dr, 4)) break;

            /* Save current module */
            if (have_name && module_count < AKAV_OLE2_MAX_VBA_MODULES) {
                strncpy_s(module_names[module_count],
                          sizeof(module_names[0]),
                          current_name, _TRUNCATE);
                module_offsets[module_count] = current_offset;
                module_count++;
            }
            have_name = false;
            current_offset = 0;
            memset(current_name, 0, sizeof(current_name));
        } else {
            /* Generic record: try reading a uint32_t size and skip */
            uint32_t size;
            if (!akav_reader_read_u32_le(&dr, &size)) break;
            if (size > akav_reader_remaining(&dr)) break;
            if (!akav_reader_skip(&dr, size)) break;
        }
    }

    free(dir_data);

    if (module_count == 0) {
        return false;
    }

    /* Allocate vba_modules */
    ole2->vba_modules = (akav_ole2_vba_module_t*)calloc(
        module_count, sizeof(akav_ole2_vba_module_t));
    if (!ole2->vba_modules) {
        ole2_error(ole2, "VBA module allocation failed");
        return false;
    }

    uint32_t found_count = 0;
    for (uint32_t i = 0; i < module_count; i++) {
        /* Find the corresponding stream */
        const akav_ole2_stream_t* mod_stream = NULL;
        for (uint32_t s = 0; s < ole2->num_streams; s++) {
            if (_stricmp(ole2->streams[s].name, module_names[i]) == 0) {
                mod_stream = &ole2->streams[s];
                break;
            }
        }

        if (!mod_stream || !mod_stream->data || mod_stream->data_len == 0)
            continue;

        /* Decompress starting at TextOffset */
        if (module_offsets[i] >= mod_stream->data_len)
            continue;

        const uint8_t* comp_data = mod_stream->data + module_offsets[i];
        size_t comp_len = mod_stream->data_len - module_offsets[i];

        uint8_t* source = NULL;
        size_t source_len = 0;
        if (!akav_ole2_ovba_decompress(comp_data, comp_len, &source, &source_len))
            continue;

        akav_ole2_vba_module_t* mod = &ole2->vba_modules[found_count];
        strncpy_s(mod->module_name, sizeof(mod->module_name),
                  module_names[i], _TRUNCATE);
        mod->source = source;
        mod->source_len = source_len;
        found_count++;
    }

    ole2->num_vba_modules = found_count;
    ole2->has_vba = (found_count > 0);
    ole2->has_macros = ole2->has_vba;

    return ole2->has_vba;
}

/* ── Public: akav_ole2_analyze ───────────────────────────────────── */

extern "C"
void akav_ole2_analyze(akav_ole2_t* ole2,
                       const uint8_t* data, size_t data_len)
{
    if (!akav_ole2_parse(ole2, data, data_len))
        return;

    /* Check for VBA storage presence in directory entries */
    for (uint32_t i = 0; i < ole2->num_dir_entries; i++) {
        if (ole2->dir_entries[i].obj_type == AKAV_OLE2_OBJTYPE_STORAGE &&
            _stricmp(ole2->dir_entries[i].name, "VBA") == 0) {
            ole2->has_vba = true;
            ole2->has_macros = true;
            break;
        }
    }

    if (!akav_ole2_extract_streams(ole2, data, data_len))
        return;

    akav_ole2_extract_vba(ole2, data, data_len);
}

/* ── Public: akav_ole2_find_entry ────────────────────────────────── */

extern "C"
const akav_ole2_dir_entry_t* akav_ole2_find_entry(
    const akav_ole2_t* ole2, const char* name)
{
    if (!ole2 || !ole2->dir_entries || !name) return NULL;

    for (uint32_t i = 0; i < ole2->num_dir_entries; i++) {
        if (_stricmp(ole2->dir_entries[i].name, name) == 0)
            return &ole2->dir_entries[i];
    }
    return NULL;
}
