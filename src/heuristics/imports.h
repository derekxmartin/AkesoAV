#ifndef AKAV_HEURISTIC_IMPORTS_H
#define AKAV_HEURISTIC_IMPORTS_H

#include "akesoav.h"
#include "parsers/pe.h"
#include "heuristics/static_analyzer.h"  /* akav_heur_hit_t */

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Import Analyzer Weights ────────────────────────────────────── */

typedef struct {
    int injection_combo;       /* VirtualAlloc+WriteProcessMemory+CreateRemoteThread (+35) */
    int shellcode_loader;      /* VirtualAlloc+VirtualProtect(RX)+CreateThread       (+25) */
    int service_installer;     /* CreateService+StartService                          (+20) */
    int persistence_registry;  /* RegSetValueEx (Run key indicator)                   (+15) */
    int ordinal_only;          /* All imports by ordinal                              (+15) */
    int api_hashing;           /* Only GetProcAddress+LoadLibrary                     (+25) */
} akav_import_weights_t;

/* ── Analysis result ─────────────────────────────────────────────── */

typedef struct {
    int               total_score;
    int               num_hits;
    akav_heur_hit_t   hits[AKAV_HEUR_MAX_HITS];
} akav_import_result_t;

/* ── API ─────────────────────────────────────────────────────────── */

/**
 * Return the built-in default weights matching section 5.6 Imports row.
 */
void akav_import_weights_default(akav_import_weights_t* w);

/**
 * Load weights from a JSON file. Falls back to defaults on any error.
 */
bool akav_import_weights_load_json(akav_import_weights_t* w,
                                    const char* json_path);

/**
 * Run import heuristic checks on a parsed PE.
 *
 * Requires:
 *   - pe was successfully parsed (pe->valid == true)
 *   - pe has had imports parsed (akav_pe_parse_imports)
 */
void akav_import_analyze(const akav_pe_t* pe,
                          const akav_import_weights_t* weights,
                          akav_import_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_HEURISTIC_IMPORTS_H */
