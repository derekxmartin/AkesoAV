#ifndef AKAV_HEURISTIC_ENTROPY_H
#define AKAV_HEURISTIC_ENTROPY_H

#include "akesoav.h"
#include "parsers/pe.h"
#include "heuristics/static_analyzer.h"  /* akav_heur_hit_t */

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Entropy Analyzer Weights ────────────────────────────────────── */

typedef struct {
    int text_high_entropy;         /* .text > 7.0  (packed)          (+20) */
    int text_low_entropy;          /* .text < 1.0  (XOR-encoded)     (+15) */
    int overall_high_entropy;      /* whole-file > 7.5 (suspicious)  (+10) */
} akav_entropy_weights_t;

/* ── Analysis result ─────────────────────────────────────────────── */

typedef struct {
    int               total_score;
    int               num_hits;
    akav_heur_hit_t   hits[AKAV_HEUR_MAX_HITS];
    double            whole_file_entropy;      /* 0.0 - 8.0 */
} akav_entropy_result_t;

/* ── API ─────────────────────────────────────────────────────────── */

/**
 * Return the built-in default weights matching section 5.6 Entropy row.
 */
void akav_entropy_weights_default(akav_entropy_weights_t* w);

/**
 * Load weights from a JSON file. Falls back to defaults on any error.
 */
bool akav_entropy_weights_load_json(akav_entropy_weights_t* w,
                                     const char* json_path);

/**
 * Compute Shannon entropy over an arbitrary buffer.
 * Returns 0.0 for empty/null input, up to 8.0 for uniform random.
 */
double akav_shannon_entropy(const uint8_t* data, size_t len);

/**
 * Run entropy heuristic checks on a parsed PE.
 *
 * Requires pe->sections[].entropy to be computed (akav_pe_compute_entropy).
 * Also computes whole-file entropy from the raw buffer.
 */
void akav_entropy_analyze(const akav_pe_t* pe,
                           const uint8_t* data, size_t data_len,
                           const akav_entropy_weights_t* weights,
                           akav_entropy_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_HEURISTIC_ENTROPY_H */
