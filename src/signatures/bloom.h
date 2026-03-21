#ifndef AKAV_BLOOM_H
#define AKAV_BLOOM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bloom filter using double hashing (MurmurHash3 + FNV-1a).
 *
 * Thread safety: concurrent query is safe after construction.
 * Insert is NOT thread-safe — callers must serialize inserts.
 */
typedef struct akav_bloom {
    uint8_t* bits;          /* bit array */
    uint32_t num_bits;      /* total bits in the array */
    uint32_t num_hashes;    /* number of hash functions (via double hashing) */
    uint32_t num_items;     /* items inserted so far */
} akav_bloom_t;

/**
 * Create a bloom filter sized to hold `expected_items` with
 * `bits_per_item` bits per element.
 *
 * Recommended: bits_per_item=10 yields ~1% FP rate with optimal k.
 * The number of hash functions k is computed as: k = (m/n) * ln(2).
 *
 * Returns true on success, false on allocation failure.
 */
bool akav_bloom_create(akav_bloom_t* bloom, uint32_t expected_items,
                       uint32_t bits_per_item);

/**
 * Free bloom filter memory. Safe to call on a zeroed struct.
 */
void akav_bloom_destroy(akav_bloom_t* bloom);

/**
 * Insert a key into the bloom filter.
 */
void akav_bloom_insert(akav_bloom_t* bloom, const uint8_t* key, size_t key_len);

/**
 * Query the bloom filter. Returns true if the key *may* be present
 * (possible false positive), false if the key is *definitely* absent
 * (no false negatives).
 */
bool akav_bloom_query(const akav_bloom_t* bloom, const uint8_t* key, size_t key_len);

/**
 * Serialize the bloom filter to a contiguous buffer.
 *
 * Format:
 *   [4] num_bits (uint32_t LE)
 *   [4] num_hashes (uint32_t LE)
 *   [4] num_items (uint32_t LE)
 *   [N] bit array (ceil(num_bits / 8) bytes)
 *
 * Returns required buffer size. If buf is NULL or buf_size is too small,
 * writes nothing but still returns the required size.
 */
size_t akav_bloom_serialize(const akav_bloom_t* bloom, uint8_t* buf, size_t buf_size);

/**
 * Deserialize a bloom filter from a buffer produced by akav_bloom_serialize.
 * The bloom struct should be zeroed before calling.
 *
 * Returns true on success, false on invalid data or allocation failure.
 */
bool akav_bloom_deserialize(akav_bloom_t* bloom, const uint8_t* buf, size_t buf_size);

/* --- Hash primitives (exposed for testing) --- */

uint32_t akav_murmur3_32(const uint8_t* key, size_t len, uint32_t seed);
uint32_t akav_fnv1a_32(const uint8_t* key, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_BLOOM_H */
