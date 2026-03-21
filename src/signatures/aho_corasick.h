#ifndef AKAV_AHO_CORASICK_H
#define AKAV_AHO_CORASICK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Aho-Corasick multi-pattern byte matcher.
 *
 * Thread safety:
 *   - After finalize, concurrent search is safe (read-only automaton).
 *   - Walk state is stack-allocated per call, no shared mutable state.
 *   - Adding patterns and finalize are NOT thread-safe.
 */

/* ── Opaque automaton handle ──────────────────────────────────────── */

typedef struct akav_ac akav_ac_t;

/**
 * Create an empty Aho-Corasick automaton.
 * Returns NULL on allocation failure.
 */
akav_ac_t* akav_ac_create(void);

/**
 * Destroy the automaton and free all memory.
 */
void akav_ac_destroy(akav_ac_t* ac);

/**
 * Add a byte pattern to the automaton. Handles null bytes.
 * pattern_id is a caller-chosen identifier returned on match.
 * Must be called before akav_ac_finalize.
 * Returns true on success.
 */
bool akav_ac_add_pattern(akav_ac_t* ac,
                          const uint8_t* pattern, uint32_t pattern_len,
                          uint32_t pattern_id);

/**
 * Build failure links and finalize the automaton for searching.
 * Must be called exactly once after all patterns are added.
 * Returns true on success.
 */
bool akav_ac_finalize(akav_ac_t* ac);

/* ── Search ───────────────────────────────────────────────────────── */

/**
 * Match result from a search.
 */
typedef struct {
    uint32_t pattern_id;     /* caller-assigned pattern ID */
    size_t   offset;         /* byte offset in input where match ends */
    uint32_t pattern_len;    /* length of the matched pattern */
} akav_ac_match_t;

/**
 * Callback invoked for each match during search.
 * Return true to continue searching, false to stop early.
 */
typedef bool (*akav_ac_match_cb)(const akav_ac_match_t* match, void* user_data);

/**
 * Search the input buffer for all pattern matches.
 * Walk state is stack-allocated — safe for concurrent calls on the
 * same finalized automaton from multiple threads.
 *
 * Returns the total number of matches found (even if callback stops early).
 */
uint32_t akav_ac_search(const akav_ac_t* ac,
                         const uint8_t* data, size_t data_len,
                         akav_ac_match_cb callback, void* user_data);

/* ── Serialization ────────────────────────────────────────────────── */

/**
 * Serialize a finalized automaton to a contiguous buffer.
 * Returns required size. If buf is NULL or too small, writes nothing.
 */
size_t akav_ac_serialize(const akav_ac_t* ac, uint8_t* buf, size_t buf_size);

/**
 * Deserialize an automaton from a buffer.
 * Returns a new automaton ready for searching, or NULL on error.
 * The caller must akav_ac_destroy the returned automaton.
 */
akav_ac_t* akav_ac_deserialize(const uint8_t* buf, size_t buf_size);

/**
 * Return the number of patterns in the automaton.
 */
uint32_t akav_ac_pattern_count(const akav_ac_t* ac);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_AHO_CORASICK_H */
