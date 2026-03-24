#include "scanner.h"
#include "parsers/pe.h"
#include "file_type.h"
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
    akav_fuzzy_matcher_init(&scanner->fuzzy_matcher);
    akav_yara_scanner_init(&scanner->yara);
    akav_ml_model_init(&scanner->ml_model);
}

void akav_scanner_destroy(akav_scanner_t* scanner)
{
    if (!scanner) return;

    if (scanner->ac) {
        akav_ac_destroy(scanner->ac);
        scanner->ac = NULL;
    }

    akav_yara_scanner_destroy(&scanner->yara);
    scanner->yara_loaded = false;

    akav_ml_model_free(&scanner->ml_model);

    akav_fuzzy_matcher_destroy(&scanner->fuzzy_matcher);
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

    /* Fuzzy hash -- manually parse packed entries (132 bytes each on disk) */
    const akav_db_section_entry_t* fuzzy_sec =
        akav_sigdb_find_section(db, AKAV_SECTION_FUZZY_HASH);
    if (fuzzy_sec && fuzzy_sec->entry_count > 0) {
        const uint8_t* fuzzy_data = akav_sigdb_section_data(db, fuzzy_sec);
        if (fuzzy_data) {
            uint32_t fuzzy_count = fuzzy_sec->entry_count;
            const size_t PACKED_FUZZY_SIZE = AKAV_FUZZY_HASH_MAX + 4; /* 128 + 4 */

            if ((size_t)fuzzy_count * PACKED_FUZZY_SIZE <= fuzzy_sec->size) {
                akav_fuzzy_entry_t* entries = (akav_fuzzy_entry_t*)malloc(
                    fuzzy_count * sizeof(akav_fuzzy_entry_t));
                if (entries) {
                    for (uint32_t i = 0; i < fuzzy_count; i++) {
                        const uint8_t* p = fuzzy_data + i * PACKED_FUZZY_SIZE;
                        memcpy(entries[i].hash, p, AKAV_FUZZY_HASH_MAX);
                        entries[i].hash[AKAV_FUZZY_HASH_MAX - 1] = '\0';
                        memcpy(&entries[i].name_index, p + AKAV_FUZZY_HASH_MAX, 4);
                    }
                    scanner->fuzzy_loaded = akav_fuzzy_matcher_build(
                        &scanner->fuzzy_matcher, entries, fuzzy_count, 80);
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

    /* YARA rules (source text compiled at load time) */
    const akav_db_section_entry_t* yara_sec =
        akav_sigdb_find_section(db, AKAV_SECTION_YARA);
    if (yara_sec && yara_sec->size > 0) {
        const uint8_t* data = akav_sigdb_section_data(db, yara_sec);
        if (data) {
            scanner->yara_loaded =
                akav_yara_load_section(&scanner->yara, data, yara_sec->size);
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

/* EICAR test string — must be detected without signatures per spec */
static const char EICAR_PREFIX[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";
static const size_t EICAR_LEN = 68;

void akav_scanner_scan_buffer(const akav_scanner_t* scanner,
                               const uint8_t* data, size_t data_len,
                               akav_scan_result_t* result)
{
    if (!scanner || !result) return;

    /* ── Stage 0: Built-in EICAR detection ───────────────────────── */
    if (data && data_len >= EICAR_LEN && data_len <= 128) {
        if (memcmp(data, EICAR_PREFIX, sizeof(EICAR_PREFIX) - 1) == 0) {
            result->found = 1;
            strncpy_s(result->malware_name, sizeof(result->malware_name),
                      "EICAR-Test-File", _TRUNCATE);
            strncpy_s(result->signature_id, sizeof(result->signature_id),
                      "eicar-builtin", _TRUNCATE);
            strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                      "builtin", _TRUNCATE);
            return;
        }
    }

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

    /* ── Stage 5: Fuzzy hash match ──────────────────────────────── */
    if (scanner->fuzzy_loaded && data && data_len > 0) {
        akav_fuzzy_match_t fmatch;
        uint32_t fcount = akav_fuzzy_matcher_scan(&scanner->fuzzy_matcher,
            data, data_len, &fmatch, 1);
        if (fcount > 0) {
            const char* name = akav_scanner_lookup_name(scanner, fmatch.name_index);
            result->found = 1;
            strncpy_s(result->malware_name, sizeof(result->malware_name),
                      name, _TRUNCATE);

            char sig_id[AKAV_MAX_SIG_ID];
            snprintf(sig_id, sizeof(sig_id), "fuzzy-%d-%u",
                     fmatch.similarity, fmatch.entry_index);
            strncpy_s(result->signature_id, sizeof(result->signature_id),
                      sig_id, _TRUNCATE);
            strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                      "fuzzy_hash", _TRUNCATE);
            result->heuristic_score = (double)fmatch.similarity;
            return; /* short-circuit */
        }
    }

    /* ── Stage 6: Aho-Corasick byte-stream ───────────────────────── */
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

    /* ── Stage 7: YARA rules ─────────────────────────────────────── */
    if (scanner->yara_loaded && data && data_len > 0) {
        akav_yara_match_t ym;
        if (akav_yara_scan_buffer(&scanner->yara, data, data_len, &ym)) {
            result->found = 1;
            strncpy_s(result->malware_name, sizeof(result->malware_name),
                      ym.rule_name, _TRUNCATE);

            char sig_id[AKAV_MAX_SIG_ID];
            snprintf(sig_id, sizeof(sig_id), "yara-%s", ym.rule_name);
            strncpy_s(result->signature_id, sizeof(result->signature_id),
                      sig_id, _TRUNCATE);
            strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                      "yara", _TRUNCATE);
            return; /* short-circuit */
        }
    }

    /* No detection — result->found remains 0 */
}

/* ── Heuristic weights loading ──────────────────────────────────── */

void akav_scanner_load_heuristic_weights(akav_scanner_t* scanner,
                                          const char* config_dir)
{
    if (!scanner) return;

    /* Always start with defaults */
    akav_pe_header_weights_default(&scanner->pe_header_weights);
    akav_entropy_weights_default(&scanner->entropy_weights);
    akav_import_weights_default(&scanner->import_weights);
    akav_string_weights_default(&scanner->string_weights);

    /* Try loading from JSON if config_dir provided */
    if (config_dir) {
        char path[512];

        snprintf(path, sizeof(path), "%s/pe_header_weights.json", config_dir);
        akav_pe_header_weights_load_json(&scanner->pe_header_weights, path);

        snprintf(path, sizeof(path), "%s/entropy_weights.json", config_dir);
        akav_entropy_weights_load_json(&scanner->entropy_weights, path);

        snprintf(path, sizeof(path), "%s/import_weights.json", config_dir);
        akav_import_weights_load_json(&scanner->import_weights, path);

        snprintf(path, sizeof(path), "%s/string_weights.json", config_dir);
        akav_string_weights_load_json(&scanner->string_weights, path);

        /* Load ML classifier model if available */
        snprintf(path, sizeof(path), "%s/ml_model.json", config_dir);
        akav_ml_model_load(&scanner->ml_model, path);

        /* Load dynamic scorer weights */
        snprintf(path, sizeof(path), "%s/dynamic_weights.json", config_dir);
        if (akav_dynamic_weights_load_json(&scanner->dynamic_weights, path))
            scanner->dynamic_weights_loaded = true;
    }

    if (!scanner->dynamic_weights_loaded)
        akav_dynamic_weights_default(&scanner->dynamic_weights);

    scanner->heuristic_weights_loaded = true;
}

/* ── Heuristic pipeline ─────────────────────────────────────────── */

/* Map heuristic level to score threshold */
static int heuristic_threshold(akav_heur_level_t level)
{
    switch (level) {
        case AKAV_HEUR_HIGH:   return 50;
        case AKAV_HEUR_MEDIUM: return 75;
        case AKAV_HEUR_LOW:    return 100;
        default:               return 0; /* OFF — unreachable if caller checks */
    }
}

/* Find the highest-scoring check name across all results for the
 * malware_name category (e.g., "Heuristic.Suspicious.Injection") */
static const char* top_category(const akav_pe_header_result_t* pe_r,
                                  const akav_entropy_result_t* ent_r,
                                  const akav_import_result_t* imp_r,
                                  const akav_string_result_t* str_r)
{
    const char* best_name = "Generic";
    int best_weight = 0;

    /* Check PE header hits */
    for (int i = 0; i < pe_r->num_hits; i++) {
        if (pe_r->hits[i].weight > best_weight) {
            best_weight = pe_r->hits[i].weight;
            best_name = pe_r->hits[i].check_name;
        }
    }
    /* Check entropy hits */
    for (int i = 0; i < ent_r->num_hits; i++) {
        if (ent_r->hits[i].weight > best_weight) {
            best_weight = ent_r->hits[i].weight;
            best_name = ent_r->hits[i].check_name;
        }
    }
    /* Check import hits */
    for (int i = 0; i < imp_r->num_hits; i++) {
        if (imp_r->hits[i].weight > best_weight) {
            best_weight = imp_r->hits[i].weight;
            best_name = imp_r->hits[i].check_name;
        }
    }
    /* Check string hits */
    for (int i = 0; i < str_r->num_hits; i++) {
        if (str_r->hits[i].weight > best_weight) {
            best_weight = str_r->hits[i].weight;
            best_name = str_r->hits[i].check_name;
        }
    }

    return best_name;
}

int akav_scanner_run_heuristics(const akav_scanner_t* scanner,
                                 const uint8_t* data, size_t data_len,
                                 akav_heur_level_t level,
                                 akav_scan_result_t* result)
{
    if (!scanner || !data || data_len == 0 || !result)
        return 0;

    /* Only run on PE files */
    akav_file_type_t ftype = akav_detect_file_type(data, data_len);
    if (ftype != AKAV_FILETYPE_PE)
        return 0;

    /* Parse PE */
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    if (!akav_pe_parse(&pe, data, data_len)) {
        add_warning(result, "Heuristic: PE parse failed");
        return 0;
    }

    /* Parse imports (needed for import analyzer + PE header import count) */
    akav_pe_parse_imports(&pe, data, data_len);

    /* Compute per-section entropy (needed for entropy analyzer) */
    akav_pe_compute_entropy(&pe, data, data_len);

    /* Analyze metadata (overlay, rich header, authenticode) */
    akav_pe_analyze_metadata(&pe, data, data_len);

    /* Use loaded weights or defaults */
    const akav_pe_header_weights_t* pe_w = scanner->heuristic_weights_loaded
        ? &scanner->pe_header_weights : NULL;
    const akav_entropy_weights_t* ent_w = scanner->heuristic_weights_loaded
        ? &scanner->entropy_weights : NULL;
    const akav_import_weights_t* imp_w = scanner->heuristic_weights_loaded
        ? &scanner->import_weights : NULL;
    const akav_string_weights_t* str_w = scanner->heuristic_weights_loaded
        ? &scanner->string_weights : NULL;

    /* ── Run all 4 analyzers ────────────────────────────────────── */

    akav_pe_header_result_t pe_result;
    akav_pe_header_analyze(&pe, data, data_len, pe_w, &pe_result);

    akav_entropy_result_t entropy_result;
    akav_entropy_analyze(&pe, data, data_len, ent_w, &entropy_result);

    akav_import_result_t import_result;
    akav_import_analyze(&pe, imp_w, &import_result);

    akav_string_result_t string_result;
    akav_string_analyze(data, data_len, str_w, &string_result);

    /* ── ML classifier ──────────────────────────────────────────── */

    int ml_score = 0;
    if (scanner->ml_model.loaded) {
        akav_ml_features_t ml_features;
        akav_ml_extract_features(&pe, data_len, &ml_features);

        akav_ml_result_t ml_result;
        if (akav_ml_classify(&scanner->ml_model, &ml_features, &ml_result)) {
            ml_score = ml_result.score;  /* probability * 50 */
        }
    }

    /* ── Sum scores ─────────────────────────────────────────────── */

    int total_score = pe_result.total_score
                    + entropy_result.total_score
                    + import_result.total_score
                    + string_result.total_score
                    + ml_score;

    result->heuristic_score = (double)total_score;

    /* ── Apply threshold ────────────────────────────────────────── */

    int threshold = heuristic_threshold(level);
    if (threshold > 0 && total_score >= threshold) {
        const char* category = top_category(&pe_result, &entropy_result,
                                              &import_result, &string_result);

        result->found = 1;
        snprintf(result->malware_name, sizeof(result->malware_name),
                 "Heuristic.Suspicious.%s", category);
        strncpy_s(result->scanner_id, sizeof(result->scanner_id),
                  "heuristic", _TRUNCATE);
        snprintf(result->signature_id, sizeof(result->signature_id),
                 "heur-%d", total_score);
    }

    akav_pe_free(&pe);
    return total_score;
}
