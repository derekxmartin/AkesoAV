#ifndef AKAV_SCANNER_H
#define AKAV_SCANNER_H

#include "akesoav.h"
#include "database/sigdb.h"
#include "signatures/bloom.h"
#include "signatures/hash_matcher.h"
#include "signatures/crc_matcher.h"
#include "signatures/aho_corasick.h"

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Pipeline stage identifiers ──────────────────────────────────── */

typedef enum {
    AKAV_STAGE_BLOOM        = 0,
    AKAV_STAGE_MD5          = 1,
    AKAV_STAGE_SHA256       = 2,
    AKAV_STAGE_CRC32        = 3,
    AKAV_STAGE_AHO_CORASICK = 4,
    AKAV_STAGE_COUNT        = 5
} akav_scan_stage_t;

/* ── Scan pipeline ───────────────────────────────────────────────── */

typedef struct {
    /* Signature database (memory-mapped, read-only) */
    akav_sigdb_t sigdb;
    bool         sigdb_loaded;

    /* Matchers populated from sigdb sections */
    akav_bloom_t         bloom;
    bool                 bloom_loaded;

    akav_hash_matcher_t  hash_matcher;
    bool                 md5_loaded;
    bool                 sha256_loaded;

    akav_crc_matcher_t   crc_matcher;
    bool                 crc_loaded;

    akav_ac_t*           ac;
    bool                 ac_loaded;

    /* String table pointer (from sigdb, not owned) */
    const char*          string_table;
    uint32_t             string_table_size;

    /* Stats */
    uint32_t total_signatures;
} akav_scanner_t;

/**
 * Initialize the scanner to a clean state.
 */
void akav_scanner_init(akav_scanner_t* scanner);

/**
 * Destroy the scanner and release all resources.
 */
void akav_scanner_destroy(akav_scanner_t* scanner);

/**
 * Load signatures from a .akavdb file.
 * Opens the sigdb and populates all matchers from the available sections.
 * Returns AKAV_OK on success, AKAV_ERROR_DB on failure.
 */
akav_error_t akav_scanner_load(akav_scanner_t* scanner, const char* db_path);

/**
 * Load signatures from an in-memory .akavdb buffer (for testing).
 */
akav_error_t akav_scanner_load_memory(akav_scanner_t* scanner,
                                       const uint8_t* data, size_t size);

/**
 * Run the full scan pipeline on a buffer.
 *
 * Pipeline order: Bloom → MD5 → SHA256 → CRC32 → Aho-Corasick
 * Short-circuits on first detection.
 * On stage error: records warning, skips stage, continues.
 *
 * Populates result->found, malware_name, signature_id, scanner_id,
 * warning_count, and warnings[].
 */
void akav_scanner_scan_buffer(const akav_scanner_t* scanner,
                               const uint8_t* data, size_t data_len,
                               akav_scan_result_t* result);

/**
 * Look up a name from the string table by index.
 * Returns the string, or "unknown" if not available.
 */
const char* akav_scanner_lookup_name(const akav_scanner_t* scanner,
                                      uint32_t name_index);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_SCANNER_H */
