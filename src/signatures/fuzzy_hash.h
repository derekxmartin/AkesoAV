/* fuzzy_hash.h -- ssdeep-compatible fuzzy hashing for variant detection.
 *
 * Implements P6-T1:
 *   - Piecewise hashing with rolling hash boundaries
 *   - ssdeep-compatible output format: "block_size:hash1:hash2"
 *   - Similarity scoring 0-100 via weighted edit distance
 *   - Signature matching with configurable threshold
 *   - .akavdb section 5 integration
 *
 * Fuzzy hash format (ssdeep-compatible):
 *   block_size:base64_block_hash:base64_double_hash
 *
 * Rolling hash: Adler32-variant with ROLLING_WINDOW=7
 * Block hash: FNV-1a accumulated per rolling-boundary block
 * Similarity: longest common subsequence on base64 digests
 */

#ifndef AKAV_FUZZY_HASH_H
#define AKAV_FUZZY_HASH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────── */

#define AKAV_FUZZY_HASH_MAX       128  /* Max hash string length */
#define AKAV_FUZZY_DIGEST_LEN      64  /* Max base64 digest per block hash */
#define AKAV_FUZZY_MIN_BLOCK_SIZE   3  /* Minimum block size exponent (2^3=8) */

/* ── Fuzzy hash computation ─────────────────────────────────────── */

/**
 * Compute an ssdeep-compatible fuzzy hash of a buffer.
 *
 * Output format: "block_size:hash1:hash2"
 *   block_size: rolling hash trigger period
 *   hash1: base64 encoded FNV-1a piecewise hash at block_size
 *   hash2: base64 encoded FNV-1a piecewise hash at block_size*2
 *
 * Returns true on success. out_hash must be at least AKAV_FUZZY_HASH_MAX bytes.
 */
bool akav_fuzzy_hash_compute(const uint8_t* data, size_t len,
                              char out_hash[AKAV_FUZZY_HASH_MAX]);

/**
 * Compare two fuzzy hash strings and return a similarity score 0-100.
 *   100 = identical
 *   0   = completely different
 *
 * Compares block hashes at compatible block sizes (same or 2x).
 * Uses longest common subsequence (LCS) scoring.
 */
int akav_fuzzy_compare(const char* hash1, const char* hash2);

/* ── Fuzzy signature entry (matches .akavdb section 5) ──────────── */

typedef struct {
    char     hash[AKAV_FUZZY_HASH_MAX]; /* ssdeep-compatible hash string */
    uint32_t name_index;                 /* offset into string table */
} akav_fuzzy_entry_t;

/* ── Fuzzy matcher ──────────────────────────────────────────────── */

typedef struct {
    akav_fuzzy_entry_t* entries;
    uint32_t            count;
    int                 threshold;  /* Minimum similarity for match (default 80) */
} akav_fuzzy_matcher_t;

/**
 * Initialize an empty fuzzy matcher.
 */
void akav_fuzzy_matcher_init(akav_fuzzy_matcher_t* matcher);

/**
 * Free all memory owned by the matcher.
 */
void akav_fuzzy_matcher_destroy(akav_fuzzy_matcher_t* matcher);

/**
 * Build the matcher from an array of entries. Copies the entries.
 * threshold: minimum similarity score for a positive match (1-100, default 80).
 */
bool akav_fuzzy_matcher_build(akav_fuzzy_matcher_t* matcher,
                               const akav_fuzzy_entry_t* entries,
                               uint32_t count,
                               int threshold);

/* ── Match result ───────────────────────────────────────────────── */

typedef struct {
    uint32_t entry_index;   /* index into the entry array */
    uint32_t name_index;    /* string table offset of malware name */
    int      similarity;    /* 0-100 similarity score */
} akav_fuzzy_match_t;

/**
 * Scan a buffer against all fuzzy entries.
 * Computes the buffer's fuzzy hash, then compares against each entry.
 *
 * Returns the number of matches written to `out`. If out is NULL or
 * out_max is 0, returns the total match count without writing.
 * Matches are sorted by similarity (highest first).
 */
uint32_t akav_fuzzy_matcher_scan(const akav_fuzzy_matcher_t* matcher,
                                  const uint8_t* data, size_t data_len,
                                  akav_fuzzy_match_t* out, uint32_t out_max);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_FUZZY_HASH_H */
