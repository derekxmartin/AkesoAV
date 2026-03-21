#include "crc_matcher.h"
#include <stdlib.h>
#include <string.h>

/* ── IEEE CRC32 table (polynomial 0xEDB88320, reflected) ──────────── */

static uint32_t s_ieee_table[256];
static bool     s_ieee_init = false;

static void ieee_table_init(void)
{
    if (s_ieee_init) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320u;
            else
                crc >>= 1;
        }
        s_ieee_table[i] = crc;
    }
    s_ieee_init = true;
}

uint32_t akav_crc32_ieee(const uint8_t* data, size_t len)
{
    ieee_table_init();

    uint32_t crc = 0xFFFFFFFFu;
    if (data) {
        for (size_t i = 0; i < len; i++) {
            crc = (crc >> 8) ^ s_ieee_table[(crc ^ data[i]) & 0xFF];
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ── Custom CRC32 table (Castagnoli polynomial 0x82F63B78) ────────── */

static uint32_t s_custom_table[256];
static bool     s_custom_init = false;

static void custom_table_init(void)
{
    if (s_custom_init) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0x82F63B78u;
            else
                crc >>= 1;
        }
        s_custom_table[i] = crc;
    }
    s_custom_init = true;
}

uint32_t akav_crc32_custom(const uint8_t* data, size_t len)
{
    custom_table_init();

    uint32_t crc = 0xFFFFFFFFu;
    if (data) {
        for (size_t i = 0; i < len; i++) {
            crc = (crc >> 8) ^ s_custom_table[(crc ^ data[i]) & 0xFF];
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ── CRC matcher lifecycle ────────────────────────────────────────── */

void akav_crc_matcher_init(akav_crc_matcher_t* matcher)
{
    if (matcher) {
        memset(matcher, 0, sizeof(*matcher));
    }
}

void akav_crc_matcher_destroy(akav_crc_matcher_t* matcher)
{
    if (matcher) {
        free(matcher->entries);
        memset(matcher, 0, sizeof(*matcher));
    }
}

bool akav_crc_matcher_build(akav_crc_matcher_t* matcher,
                             const akav_crc_entry_t* entries,
                             uint32_t count,
                             bool use_custom_poly)
{
    if (!matcher) return false;

    free(matcher->entries);
    matcher->entries = NULL;
    matcher->count = 0;
    matcher->use_custom_poly = use_custom_poly;

    if (count == 0 || !entries) return true;

    akav_crc_entry_t* copy = (akav_crc_entry_t*)malloc(
        (size_t)count * sizeof(akav_crc_entry_t));
    if (!copy) return false;

    memcpy(copy, entries, (size_t)count * sizeof(akav_crc_entry_t));

    matcher->entries = copy;
    matcher->count = count;
    return true;
}

/* ── Region extraction + CRC computation ──────────────────────────── */

typedef uint32_t (*crc_fn_t)(const uint8_t*, size_t);

static bool compute_region_crc(const akav_crc_entry_t* entry,
                                const uint8_t* data, size_t data_len,
                                const akav_pe_section_info_t* pe_sections,
                                uint32_t pe_section_count,
                                crc_fn_t crc_func,
                                uint32_t* out_crc)
{
    const uint8_t* region = NULL;
    size_t region_len = 0;

    switch ((akav_crc_region_type_t)entry->region_type) {
    case AKAV_CRC_REGION_WHOLE:
        region = data;
        region_len = data_len;
        break;

    case AKAV_CRC_REGION_FIRST_N:
        if (entry->offset > data_len) return false;
        region = data;
        region_len = entry->offset;
        break;

    case AKAV_CRC_REGION_LAST_N:
        if (entry->offset > data_len) return false;
        region = data + (data_len - entry->offset);
        region_len = entry->offset;
        break;

    case AKAV_CRC_REGION_PE_SECTION:
        if (!pe_sections || entry->offset >= pe_section_count)
            return false;
        {
            const akav_pe_section_info_t* sec = &pe_sections[entry->offset];
            if (sec->raw_offset >= data_len) return false;
            size_t avail = data_len - sec->raw_offset;
            region_len = sec->raw_size;
            if (region_len > avail) region_len = avail;
            region = data + sec->raw_offset;
        }
        break;

    default:
        return false;
    }

    /* Optional length check */
    if (entry->length != 0 && region_len != entry->length)
        return false;

    *out_crc = crc_func(region, region_len);
    return true;
}

/* ── Scan ─────────────────────────────────────────────────────────── */

uint32_t akav_crc_matcher_scan(const akav_crc_matcher_t* matcher,
                                const uint8_t* data, size_t data_len,
                                const akav_pe_section_info_t* pe_sections,
                                uint32_t pe_section_count,
                                akav_crc_match_t* out, uint32_t out_max)
{
    if (!matcher || !matcher->entries || matcher->count == 0 || !data)
        return 0;

    crc_fn_t crc_func = matcher->use_custom_poly
                             ? akav_crc32_custom
                             : akav_crc32_ieee;

    uint32_t match_count = 0;

    for (uint32_t i = 0; i < matcher->count; i++) {
        uint32_t computed;
        if (!compute_region_crc(&matcher->entries[i], data, data_len,
                                pe_sections, pe_section_count,
                                crc_func, &computed)) {
            continue;
        }

        if (computed == matcher->entries[i].expected_crc) {
            if (out && match_count < out_max) {
                out[match_count].entry_index = i;
                out[match_count].name_index = matcher->entries[i].name_index;
            }
            match_count++;
        }
    }

    return match_count;
}
