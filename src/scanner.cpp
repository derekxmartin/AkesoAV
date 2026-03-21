#include "scanner.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Init / Destroy ──────────────────────────────────────────────── */

void akav_scanner_init(akav_scanner_t* scanner)
{
    if (!scanner) return;
    memset(scanner, 0, sizeof(*scanner));
    akav_hash_matcher_init(&scanner->hash_matcher);
    akav_crc_matcher_init(&scanner->crc_matcher);
}

void akav_scanner_destroy(akav_scanner_t* scanner)
{
    if (!scanner) return;

    if (scanner->ac) {
        akav_ac_destroy(scanner->ac);
        scanner->ac = NULL;
    }

    akav_crc_matcher_destroy(&scanner->crc_matcher);
    akav_hash_matcher_destroy(&scanner->hash_matcher);

    if (scanner->bloom_loaded) {
        akav_bloom_destroy(&scanner->bloom);
    }

    if (scanner->sigdb_loaded) {
        akav_sigdb_close(&scanner->sigdb);
    }

    memset(scanner, 0, sizeof(*scanner));
}

/* ── Helpers ─────────────────────────────────────────────────────── */

static void add_warning(akav_scan_result_t* result, const char* msg)
{
    if (result->warning_count < AKAV_MAX_WARNINGS) {
        strncpy_s(result->warnings[result->warning_count],
                  AKAV_MAX_WARNING_LEN, msg, _TRUNCATE);
        result->warning_count++;
    }
}

const char* akav_scanner_lookup_name(const akav_scanner_t* scanner,
                                      uint32_t name_index)
{
    if (!scanner || !scanner->string_table)
        return "unknown";

    const char* s = akav_sigdb_lookup_string(&scanner->sigdb, name_index);
    return s ? s : "unknown";
}

/* ── Load from sigdb sections ────────────────────────────────────── */

static akav_error_t load_sections(akav_scanner_t* scanner)
{
    const akav_sigdb_t* db = &scanner->sigdb;
    scanner->total_signatures = db->total_signatures;

    /* String table */
    scanner->string_table = db->string_table;
    scanner->string_table_size = db->string_table_size;

    /* Bloom filter */
    const akav_db_section_entry_t* bloom_sec =
        akav_sigdb_find_section(db, AKAV_SECTION_BLOOM);
    if (bloom_sec && bloom_sec->size > 0) {
        const uint8_t* data = akav_sigdb_section_data(db, bloom_sec);
        if (data) {
            memset(&scanner->bloom, 0, sizeof(scanner->bloom));
            scanner->bloom_loaded =
                akav_bloom_deserialize(&scanner->bloom, data, bloom_sec->size);
        }
    }

    /* MD5 — use build (copy+sort) so hash_matcher owns the memory */
    const akav_db_section_entry_t* md5_sec =
        akav_sigdb_find_section(db, AKAV_SECTION_MD5);
    if (md5_sec && md5_sec->entry_count > 0) {
        const uint8_t* data = akav_sigdb_section_data(db, md5_sec);
        if (data) {
            scanner->md5_loaded = akav_hash_matcher_build_md5(
                &scanner->hash_matcher,
                (const akav_md5_entry_t*)data,
                md5_sec->entry_count);
        }
    }

    /* SHA256 */
    const akav_db_section_entry_t* sha_sec =
        akav_sigdb_find_section(db, AKAV_SECTION_SHA256);
    if (sha_sec && sha_sec->entry_count > 0) {
        const uint8_t* data = akav_sigdb_section_data(db, sha_sec);
        if (data) {
            scanner->sha256_loaded = akav_hash_matcher_build_sha256(
                &scanner->hash_matcher,
                (const akav_sha256_entry_t*)data,
                sha_sec->entry_count);
        }
    }

    /* CRC32 — manually parse packed entries (17 bytes each on disk) */
    const akav_db_section_entry_t* crc_sec =
        akav_sigdb_find_section(db, AKAV_SECTION_CRC32);
    if (crc_sec && crc_sec->entry_count > 0) {
        const uint8_t* crc_data = akav_sigdb_section_data(db, crc_sec);
        if (crc_data) {
            uint32_t crc_count = crc_sec->entry_count;
            const size_t PACKED_CRC_SIZE = 17; /* 1 + 4 + 4 + 4 + 4 */

            if ((size_t)crc_count * PACKED_CRC_SIZE <= crc_sec->size) {
                akav_crc_entry_t* entries = (akav_crc_entry_t*)malloc(
                    crc_count * sizeof(akav_crc_entry_t));
                if (entries) {
                    for (uint32_t i = 0; i < crc_count; i++) {
                        const uint8_t* p = crc_data + i * PACKED_CRC_SIZE;
                        entries[i].region_type = p[0];
                        memcpy(&entries[i].offset,       p + 1,  4);
                        memcpy(&entries[i].length,       p + 5,  4);
                        memcpy(&entries[i].expected_crc, p + 9,  4);
                        memcpy(&entries[i].name_index,   p + 13, 4);
                    }
                    scanner->crc_loaded = akav_crc_matcher_build(
                        &scanner->crc_matcher, entries, crc_count, false);
                    free(entries);
                }
            }
        }
    }

    /* Aho-Corasick */
    const akav_db_section_entry_t* ac_sec =
        akav_sigdb_find_section(db, AKAV_SECTION_AHO_CORASICK);
    if (ac_sec && ac_sec->size > 0) {
        const uint8_t* data = akav_sigdb_section_data(db, ac_sec);
        if (data) {
            scanner->ac = akav_ac_deserialize(data, ac_sec->size);
            scanner->ac_loaded = (scanner->ac != NULL);
        }
    }

    return AKAV_OK;
}

akav_error_t akav_scanner_load(akav_scanner_t* scanner, const char* db_path)
{
    if (!scanner || !db_path)
        return AKAV_ERROR_INVALID;

    char error_buf[256] = {0};
    if (!akav_sigdb_open(&scanner->sigdb, db_path,
                          NULL, 0, error_buf, sizeof(error_buf))) {
        return AKAV_ERROR_DB;
    }
    scanner->sigdb_loaded = true;

    return load_sections(scanner);
}

akav_error_t akav_scanner_load_memory(akav_scanner_t* scanner,
                                       const uint8_t* data, size_t size)
{
    if (!scanner || !data || size == 0)
        return AKAV_ERROR_INVALID;

    char error_buf[256] = {0};
    if (!akav_sigdb_open_memory(&scanner->sigdb, data, size,
                                 NULL, 0, error_buf, sizeof(error_buf))) {
        return AKAV_ERROR_DB;
    }
    scanner->sigdb_loaded = true;

    return load_sections(scanner);
}

/* ── Scan pipeline ───────────────────────────────────────────────── */

/* Aho-Corasick callback: captures first match and stops */
typedef struct {
    const akav_scanner_t* scanner;
    akav_scan_result_t*   result;
    bool                  found;
} ac_scan_ctx_t;

static bool ac_match_callback(const akav_ac_match_t* match, void* user_data)
{
    ac_scan_ctx_t* ctx = (ac_scan_ctx_t*)user_data;
    if (!ctx || !match) return false;

    const char* name = akav_scanner_lookup_name(ctx->scanner, match->pattern_id);

    ctx->result->found = 1;
    strncpy_s(ctx->result->malware_name, sizeof(ctx->result->malware_name),
              name, _TRUNCATE);

    /* Build sig ID from pattern_id */
    char sig_id[AKAV_MAX_SIG_ID];
    snprintf(sig_id, sizeof(sig_id), "ac-%u", match->pattern_id);
    strncpy_s(ctx->result->signature_id, sizeof(ctx->result->signature_id),
              sig_id, _TRUNCATE);

    strncpy_s(ctx->result->scanner_id, sizeof(ctx->result->scanner_id),
              "aho_corasick", _TRUNCATE);

    ctx->found = true;
    return false; /* stop searching — short circuit */
}

void akav_scanner_scan_buffer(const akav_scanner_t* scanner,
                               const uint8_t* data, size_t data_len,
                               akav_scan_result_t* result)
{
    if (!scanner || !result) return;

    /* ── Stage 1: Bloom filter pre-check ─────────────────────────── */
    /* The bloom filter is a pre-filter for hash lookups. If the file's
       hash is NOT in the bloom filter, we can skip hash matching entirely.
       If it IS in the bloom filter, we proceed (may be false positive). */
    bool bloom_pass = true; /* default: proceed if no bloom loaded */
    if (scanner->bloom_loaded && data && data_len > 0) {
        /* Compute MD5 for bloom check (bloom is keyed on MD5) */
        uint8_t md5[AKAV_MD5_LEN];
        if (akav_hash_md5(data, data_len, md5)) {
            bloom_pass = akav_bloom_query(&scanner->bloom, md5, AKAV_MD5_LEN);
        }
    }

    /* ── Stage 2: MD5 hash match ─────────────────────────────────── */
    if (bloom_pass && scanner->md5_loaded && data && data_len > 0) {
        uint8_t md5[AKAV_MD5_LEN];
        if (akav_hash_md5(data, data_len, md5)) {
            const akav_md5_entry_t* hit =
                akav_hash_matcher_find_md5(&scanner->hash_matcher, md5);
            if (hit) {
                const char* name = akav_scanner_lookup_name(scanner, hit->name_index);
                result->found = 1;
                strncpy_s(result->malware_name, sizeof(result->malware_name),
                          name, _TRUNCATE);

                char sig_id[AKAV_MAX_SIG_ID];
                snprintf(sig_id, sizeof(sig_id), "md5-%u", hit->name_index);
                strncpy_s(result->signature_id, sizeof(result->signature_id),
                          sig_id, _TRUNCATE);
                strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                          "md5", _TRUNCATE);
                return; /* short-circuit */
            }
        } else {
            add_warning(result, "MD5 hash computation failed");
        }
    }

    /* ── Stage 3: SHA256 hash match ──────────────────────────────── */
    if (scanner->sha256_loaded && data && data_len > 0) {
        uint8_t sha[AKAV_SHA256_LEN];
        if (akav_hash_sha256(data, data_len, sha)) {
            const akav_sha256_entry_t* hit =
                akav_hash_matcher_find_sha256(&scanner->hash_matcher, sha);
            if (hit) {
                const char* name = akav_scanner_lookup_name(scanner, hit->name_index);
                result->found = 1;
                strncpy_s(result->malware_name, sizeof(result->malware_name),
                          name, _TRUNCATE);

                char sig_id[AKAV_MAX_SIG_ID];
                snprintf(sig_id, sizeof(sig_id), "sha256-%u", hit->name_index);
                strncpy_s(result->signature_id, sizeof(result->signature_id),
                          sig_id, _TRUNCATE);
                strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                          "sha256", _TRUNCATE);
                return; /* short-circuit */
            }
        } else {
            add_warning(result, "SHA256 hash computation failed");
        }
    }

    /* ── Stage 4: CRC32 region match ─────────────────────────────── */
    if (scanner->crc_loaded && data && data_len > 0) {
        akav_crc_match_t crc_match;
        uint32_t count = akav_crc_matcher_scan(&scanner->crc_matcher,
            data, data_len, NULL, 0, &crc_match, 1);
        if (count > 0) {
            const char* name = akav_scanner_lookup_name(scanner, crc_match.name_index);
            result->found = 1;
            strncpy_s(result->malware_name, sizeof(result->malware_name),
                      name, _TRUNCATE);

            char sig_id[AKAV_MAX_SIG_ID];
            snprintf(sig_id, sizeof(sig_id), "crc32-%u", crc_match.name_index);
            strncpy_s(result->signature_id, sizeof(result->signature_id),
                      sig_id, _TRUNCATE);
            strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                      "crc32", _TRUNCATE);
            return; /* short-circuit */
        }
    }

    /* ── Stage 5: Aho-Corasick byte-stream ───────────────────────── */
    if (scanner->ac_loaded && data && data_len > 0) {
        ac_scan_ctx_t ctx;
        ctx.scanner = scanner;
        ctx.result = result;
        ctx.found = false;

        akav_ac_search(scanner->ac, data, data_len, ac_match_callback, &ctx);
        if (ctx.found) {
            return; /* short-circuit (result already populated) */
        }
    }

    /* No detection — result->found remains 0 */
}
