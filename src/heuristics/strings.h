#ifndef AKAV_HEURISTIC_STRINGS_H
#define AKAV_HEURISTIC_STRINGS_H

#include "akesoav.h"
#include "heuristics/static_analyzer.h"  /* akav_heur_hit_t */

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── String Analyzer Weights ────────────────────────────────────── */

typedef struct {
    int cmd_exe;               /* "cmd.exe"                          (+5)  */
    int powershell_exe;        /* "powershell.exe"                   (+10) */
    int wscript_shell;         /* "WScript.Shell"                    (+10) */
    int currentversion_run;    /* "CurrentVersion\\Run"              (+15) */
    int url_http;              /* "http://" or "https://" per match  (+5)  */
    int ip_address;            /* IP address pattern per match       (+5)  */
    int base64_blob;           /* base64 blob >100 chars             (+10) */
} akav_string_weights_t;

/* ── Analysis result ─────────────────────────────────────────────── */

typedef struct {
    int               total_score;
    int               num_hits;
    akav_heur_hit_t   hits[AKAV_HEUR_MAX_HITS];
} akav_string_result_t;

/* ── API ─────────────────────────────────────────────────────────── */

/**
 * Return the built-in default weights matching section 5.6 Strings row.
 */
void akav_string_weights_default(akav_string_weights_t* w);

/**
 * Load weights from a JSON file. Falls back to defaults on any error.
 */
bool akav_string_weights_load_json(akav_string_weights_t* w,
                                    const char* json_path);

/**
 * Run string heuristic checks on raw file data.
 *
 * Scans the raw file buffer for suspicious string patterns.
 * Does not require a parsed PE (operates on raw bytes), but
 * typically called after PE parsing to analyze the file content.
 */
void akav_string_analyze(const uint8_t* data, size_t data_len,
                          const akav_string_weights_t* weights,
                          akav_string_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_HEURISTIC_STRINGS_H */
