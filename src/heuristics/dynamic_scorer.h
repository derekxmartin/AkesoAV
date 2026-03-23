/* dynamic_scorer.h -- Dynamic heuristic scorer from emulator API call log (P9-T5).
 *
 * Scores API call sequences observed during x86 emulation per §5.7 table.
 * Runs only when the emulator was invoked (scan_packed=1).
 * Score is added to the static heuristic total.
 *
 * Weights are JSON-configurable (config/dynamic_weights.json).
 */

#ifndef AKAV_HEURISTIC_DYNAMIC_SCORER_H
#define AKAV_HEURISTIC_DYNAMIC_SCORER_H

#include "emulator/winapi_stubs.h"
#include "heuristics/static_analyzer.h"  /* akav_heur_hit_t */

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Dynamic scoring weights (per §5.7) ──────────────────────────── */

typedef struct {
    int get_module_handle_self;      /* -5   Benign */
    int get_system_info;             /* -3   Benign */
    int virtual_alloc_any;           /* +5   Allocation */
    int virtual_alloc_rwx;           /* +15  Suspicious RWX */
    int virtual_protect_rw_rx;       /* +15  Shellcode pattern */
    int alloc_write_protect_chain;   /* +30  Injection chain */
    int alloc_rwx_write_jump;        /* +35  Classic shellcode */
    int load_library_suspicious;     /* +10  Suspicious load */
    int get_proc_address_loop;       /* +20  API hashing */
    int write_then_execute;          /* +25  Unpacking / shellcode */
    int int3_or_invalid;             /* +5   Anti-debug / anti-emu */
    int long_computation;            /* -10  Likely legitimate */
} akav_dynamic_weights_t;

/* ── Dynamic scoring result ──────────────────────────────────────── */

typedef struct {
    int               total_score;
    int               num_hits;
    akav_heur_hit_t   hits[AKAV_HEUR_MAX_HITS];
    uint32_t          api_calls_analyzed;
} akav_dynamic_result_t;

/* ── Emulation context for scoring ───────────────────────────────── */

typedef struct {
    const akav_api_call_t* log;          /* API call log from emulator */
    uint32_t               log_count;    /* Number of log entries */
    uint32_t               insn_count;   /* Total instructions executed */
    uint32_t               eip_final;    /* Final EIP after emulation */
} akav_dynamic_context_t;

/* ── API ──────────────────────────────────────────────────────────── */

/**
 * Return the built-in default weights matching §5.7 table.
 */
void akav_dynamic_weights_default(akav_dynamic_weights_t* w);

/**
 * Load weights from a JSON file. Falls back to defaults on error.
 */
bool akav_dynamic_weights_load_json(akav_dynamic_weights_t* w,
                                      const char* json_path);

/**
 * Score an API call log from emulation.
 *
 * Analyzes individual calls and multi-call patterns (chains).
 * Populates result with total score and individual hit details.
 */
void akav_dynamic_score(const akav_dynamic_context_t* ctx,
                          const akav_dynamic_weights_t* weights,
                          akav_dynamic_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_HEURISTIC_DYNAMIC_SCORER_H */
