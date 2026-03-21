#ifndef AKAV_CRC_MATCHER_H
#define AKAV_CRC_MATCHER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── CRC32 computation ────────────────────────────────────────────── */

/**
 * Compute CRC32 using the standard IEEE 802.3 polynomial (0xEDB88320).
 */
uint32_t akav_crc32_ieee(const uint8_t* data, size_t len);

/**
 * Compute CRC32 using a custom polynomial (0x82F63B78 — Castagnoli).
 * Produces different results from IEEE for the same input.
 */
uint32_t akav_crc32_custom(const uint8_t* data, size_t len);

/* ── Region types for signature matching ──────────────────────────── */

typedef enum {
    AKAV_CRC_REGION_WHOLE     = 0,  /* entire file/buffer */
    AKAV_CRC_REGION_FIRST_N   = 1,  /* first N bytes */
    AKAV_CRC_REGION_LAST_N    = 2,  /* last N bytes */
    AKAV_CRC_REGION_PE_SECTION = 3  /* PE section by index */
} akav_crc_region_type_t;

/* ── CRC32 signature entry (matches .akavdb §3.4 layout) ─────────── */

typedef struct {
    uint8_t  region_type;   /* akav_crc_region_type_t */
    uint32_t offset;        /* region parameter: N for FIRST/LAST, section index for PE */
    uint32_t length;        /* expected region length (0 = don't check) */
    uint32_t expected_crc;  /* CRC32 value to match */
    uint32_t name_index;    /* offset into string table */
} akav_crc_entry_t;

/* ── CRC matcher ──────────────────────────────────────────────────── */

typedef struct {
    akav_crc_entry_t* entries;
    uint32_t          count;
    bool              use_custom_poly;  /* false=IEEE, true=custom */
} akav_crc_matcher_t;

/**
 * Initialize an empty CRC matcher.
 */
void akav_crc_matcher_init(akav_crc_matcher_t* matcher);

/**
 * Free all memory owned by the matcher.
 */
void akav_crc_matcher_destroy(akav_crc_matcher_t* matcher);

/**
 * Build the matcher from an array of entries. Copies the entries.
 * Returns true on success.
 */
bool akav_crc_matcher_build(akav_crc_matcher_t* matcher,
                             const akav_crc_entry_t* entries,
                             uint32_t count,
                             bool use_custom_poly);

/**
 * Match result — returned per-match from akav_crc_matcher_scan.
 */
typedef struct {
    uint32_t entry_index;   /* index into the entry array */
    uint32_t name_index;    /* string table offset of malware name */
} akav_crc_match_t;

/**
 * Scan a buffer against all CRC entries.
 *
 * For AKAV_CRC_REGION_PE_SECTION entries, pe_sections/pe_section_count
 * must describe the PE section layout (NULL if not a PE file — those
 * entries are skipped).
 *
 * Returns the number of matches written to `out`. If out is NULL or
 * out_max is 0, returns the total match count without writing.
 */
typedef struct {
    uint32_t virtual_address;
    uint32_t raw_offset;
    uint32_t raw_size;
} akav_pe_section_info_t;

uint32_t akav_crc_matcher_scan(const akav_crc_matcher_t* matcher,
                                const uint8_t* data, size_t data_len,
                                const akav_pe_section_info_t* pe_sections,
                                uint32_t pe_section_count,
                                akav_crc_match_t* out, uint32_t out_max);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_CRC_MATCHER_H */
