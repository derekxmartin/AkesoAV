#ifndef AKAV_STATIC_ANALYZER_H
#define AKAV_STATIC_ANALYZER_H

#include "akesoav.h"
#include "parsers/pe.h"

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── PE Header Analyzer Weights ──────────────────────────────────── */

typedef struct {
    int entry_outside_text;        /* Entry point outside .text          (+15) */
    int wx_section;                /* W+X section per occurrence         (+20) */
    int packer_section_name;       /* .UPX0/.aspack/.themida etc.        (+25) */
    int few_import_dlls;           /* <3 import DLLs                     (+10) */
    int zero_imports;              /* No imports at all                  (+20) */
    int suspicious_timestamp;      /* >future, <1990, or ==0             (+10) */
    int checksum_mismatch;         /* PE checksum != computed checksum   (+5)  */
    int overlay_high_entropy;      /* Overlay present with entropy >7.0  (+15) */
} akav_pe_header_weights_t;

/* ── Analysis result detail ──────────────────────────────────────── */

#define AKAV_HEUR_MAX_HITS 16

typedef struct {
    const char* check_name;        /* e.g. "entry_outside_text" */
    int         weight;            /* score contributed */
    char        detail[128];       /* human-readable detail */
} akav_heur_hit_t;

typedef struct {
    int               total_score;
    int               num_hits;
    akav_heur_hit_t   hits[AKAV_HEUR_MAX_HITS];
} akav_pe_header_result_t;

/* ── API ─────────────────────────────────────────────────────────── */

/**
 * Return the built-in default weights matching section 5.6 of REQUIREMENTS.md.
 */
void akav_pe_header_weights_default(akav_pe_header_weights_t* w);

/**
 * Load weights from a JSON file. Falls back to defaults on any error.
 * Returns true if the file was parsed successfully.
 */
bool akav_pe_header_weights_load_json(akav_pe_header_weights_t* w,
                                       const char* json_path);

/**
 * Run all PE header heuristic checks on a parsed PE.
 *
 * Requires:
 *   - pe was successfully parsed (pe->valid == true)
 *   - pe has had imports parsed (akav_pe_parse_imports)
 *   - pe has had metadata analyzed (akav_pe_analyze_metadata)
 *
 * The buffer + length are needed for overlay entropy computation.
 */
void akav_pe_header_analyze(const akav_pe_t* pe,
                             const uint8_t* data, size_t data_len,
                             const akav_pe_header_weights_t* weights,
                             akav_pe_header_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_STATIC_ANALYZER_H */
