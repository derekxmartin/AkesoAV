/* graph_sig.h -- Graph-based (CFG hash) signatures (P9-T2).
 *
 * Builds a control flow graph from PE .text section using the x86
 * decoder, hashes opcodes per basic block (ignoring operands), and
 * produces a sorted set of block hashes. Similarity between two
 * signatures is computed via Jaccard set intersection ratio.
 *
 * This approach is resilient to:
 *   - Different compilers (MSVC vs Clang) — same logic, different registers
 *   - Register reallocation — operands ignored, only opcodes matter
 *   - NOP insertion — NOPs are filtered out before hashing
 */

#ifndef AKAV_GRAPH_SIG_H
#define AKAV_GRAPH_SIG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────── */

#define AKAV_GRAPH_MAX_BLOCKS      8192  /* max basic blocks per function */
#define AKAV_GRAPH_MAX_INSNS      65536  /* max instructions to decode */
#define AKAV_GRAPH_MIN_BLOCK_INSNS    2  /* ignore trivial 1-instruction blocks */

/* ── Graph signature ─────────────────────────────────────────────── */

typedef struct {
    uint32_t* block_hashes;     /* sorted, deduplicated array of block hashes */
    uint32_t  num_blocks;       /* number of unique block hashes */
    uint32_t  total_blocks;     /* total blocks before dedup */
    uint32_t  total_insns;      /* total instructions decoded */
} akav_graph_sig_t;

/* ── Public API ───────────────────────────────────────────────── */

/**
 * Build a graph signature from a PE file's .text section.
 *
 * Parses the PE to find .text (or first executable section),
 * decodes instructions, builds basic blocks, and hashes opcodes.
 *
 * Returns true if a valid signature was produced.
 * Caller must call akav_graph_sig_free() when done.
 */
bool akav_graph_sig_build(const uint8_t* pe_data, size_t pe_len,
                           akav_graph_sig_t* sig);

/**
 * Build a graph signature directly from raw x86 code bytes.
 *
 * base_va is the assumed virtual address of the first byte
 * (used for resolving relative branch targets).
 *
 * Returns true if a valid signature was produced.
 */
bool akav_graph_sig_build_from_code(const uint8_t* code, size_t code_len,
                                     uint32_t base_va,
                                     akav_graph_sig_t* sig);

/**
 * Compare two graph signatures using Jaccard similarity.
 *
 * Returns a value in [0.0, 1.0]:
 *   1.0 = identical block hash sets
 *   0.0 = completely different
 *
 * Formula: |A ∩ B| / |A ∪ B|
 */
double akav_graph_sig_compare(const akav_graph_sig_t* a,
                               const akav_graph_sig_t* b);

/**
 * Free a graph signature's allocated memory.
 */
void akav_graph_sig_free(akav_graph_sig_t* sig);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_GRAPH_SIG_H */
