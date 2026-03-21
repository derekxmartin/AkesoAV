#ifndef AKAV_HASH_MATCHER_H
#define AKAV_HASH_MATCHER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Hash types ───────────────────────────────────────────────────── */

#define AKAV_MD5_LEN    16
#define AKAV_SHA256_LEN 32

typedef enum {
    AKAV_HASH_MD5    = 0,
    AKAV_HASH_SHA256 = 1
} akav_hash_type_t;

/* ── Hash entry (stored in sorted arrays) ─────────────────────────── */

typedef struct {
    uint8_t  hash[AKAV_MD5_LEN];
    uint32_t name_index;       /* offset into string table */
} akav_md5_entry_t;

typedef struct {
    uint8_t  hash[AKAV_SHA256_LEN];
    uint32_t name_index;
} akav_sha256_entry_t;

/* ── Hash matcher ─────────────────────────────────────────────────── */

typedef struct {
    akav_md5_entry_t*    md5_entries;
    uint32_t             md5_count;
    akav_sha256_entry_t* sha256_entries;
    uint32_t             sha256_count;
} akav_hash_matcher_t;

/**
 * Initialize an empty hash matcher. Must call destroy when done.
 */
void akav_hash_matcher_init(akav_hash_matcher_t* matcher);

/**
 * Free all memory owned by the matcher.
 */
void akav_hash_matcher_destroy(akav_hash_matcher_t* matcher);

/**
 * Build the MD5 table from an unsorted array of entries.
 * The matcher takes ownership — entries are copied and sorted internally.
 * Returns true on success, false on allocation failure.
 */
bool akav_hash_matcher_build_md5(akav_hash_matcher_t* matcher,
                                  const akav_md5_entry_t* entries,
                                  uint32_t count);

/**
 * Build the SHA-256 table from an unsorted array of entries.
 */
bool akav_hash_matcher_build_sha256(akav_hash_matcher_t* matcher,
                                     const akav_sha256_entry_t* entries,
                                     uint32_t count);

/**
 * Load a pre-sorted MD5 table (e.g. memory-mapped from .akavdb).
 * The matcher does NOT take ownership — caller must keep data alive.
 */
void akav_hash_matcher_load_md5(akav_hash_matcher_t* matcher,
                                 akav_md5_entry_t* entries,
                                 uint32_t count);

/**
 * Load a pre-sorted SHA-256 table.
 */
void akav_hash_matcher_load_sha256(akav_hash_matcher_t* matcher,
                                    akav_sha256_entry_t* entries,
                                    uint32_t count);

/**
 * Look up an MD5 hash. Returns pointer to matching entry or NULL.
 * O(log n) binary search.
 */
const akav_md5_entry_t* akav_hash_matcher_find_md5(
    const akav_hash_matcher_t* matcher,
    const uint8_t hash[AKAV_MD5_LEN]);

/**
 * Look up a SHA-256 hash. Returns pointer to matching entry or NULL.
 */
const akav_sha256_entry_t* akav_hash_matcher_find_sha256(
    const akav_hash_matcher_t* matcher,
    const uint8_t hash[AKAV_SHA256_LEN]);

/* ── CNG hash computation ─────────────────────────────────────────── */

/**
 * Compute MD5 hash of a buffer using Windows CNG (BCryptHash).
 * out must point to at least AKAV_MD5_LEN bytes.
 * Returns true on success.
 */
bool akav_hash_md5(const uint8_t* data, size_t len,
                   uint8_t out[AKAV_MD5_LEN]);

/**
 * Compute SHA-256 hash of a buffer using Windows CNG.
 * out must point to at least AKAV_SHA256_LEN bytes.
 */
bool akav_hash_sha256(const uint8_t* data, size_t len,
                      uint8_t out[AKAV_SHA256_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_HASH_MATCHER_H */
