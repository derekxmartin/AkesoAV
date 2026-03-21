#include "bloom.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ── MurmurHash3 (32-bit, x86) ────────────────────────────────────── */

static inline uint32_t rotl32(uint32_t x, int8_t r)
{
    return (x << r) | (x >> (32 - r));
}

uint32_t akav_murmur3_32(const uint8_t* key, size_t len, uint32_t seed)
{
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    uint32_t h1 = seed;
    const size_t nblocks = len / 4;

    /* body — process 4-byte blocks */
    for (size_t i = 0; i < nblocks; i++) {
        uint32_t k1;
        memcpy(&k1, key + i * 4, 4);

        k1 *= c1;
        k1 = rotl32(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    /* tail */
    const uint8_t* tail = key + nblocks * 4;
    uint32_t k1 = 0;

    switch (len & 3) {
    case 3: k1 ^= (uint32_t)tail[2] << 16; /* fallthrough */
    case 2: k1 ^= (uint32_t)tail[1] << 8;  /* fallthrough */
    case 1: k1 ^= (uint32_t)tail[0];
            k1 *= c1;
            k1 = rotl32(k1, 15);
            k1 *= c2;
            h1 ^= k1;
    }

    /* finalization mix */
    h1 ^= (uint32_t)len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

/* ── FNV-1a (32-bit) ──────────────────────────────────────────────── */

uint32_t akav_fnv1a_32(const uint8_t* key, size_t len)
{
    uint32_t hash = 0x811c9dc5; /* FNV offset basis */
    for (size_t i = 0; i < len; i++) {
        hash ^= key[i];
        hash *= 0x01000193; /* FNV prime */
    }
    return hash;
}

/* ── Double hashing scheme ────────────────────────────────────────── */

static inline uint32_t bloom_hash_i(uint32_t h1, uint32_t h2,
                                     uint32_t i, uint32_t m)
{
    /* g_i(x) = (h1(x) + i * h2(x)) mod m */
    return (h1 + i * h2) % m;
}

/* ── Bloom filter API ─────────────────────────────────────────────── */

bool akav_bloom_create(akav_bloom_t* bloom, uint32_t expected_items,
                       uint32_t bits_per_item)
{
    if (!bloom || expected_items == 0 || bits_per_item == 0) {
        return false;
    }

    uint64_t total_bits = (uint64_t)expected_items * bits_per_item;
    if (total_bits > UINT32_MAX) {
        return false;
    }

    uint32_t m = (uint32_t)total_bits;
    /* optimal k = (m/n) * ln(2) ≈ bits_per_item * 0.6931 */
    uint32_t k = (uint32_t)(bits_per_item * 0.6931471805599453 + 0.5);
    if (k < 1) k = 1;

    size_t byte_count = (m + 7) / 8;
    uint8_t* bits = (uint8_t*)calloc(byte_count, 1);
    if (!bits) {
        return false;
    }

    bloom->bits = bits;
    bloom->num_bits = m;
    bloom->num_hashes = k;
    bloom->num_items = 0;

    return true;
}

void akav_bloom_destroy(akav_bloom_t* bloom)
{
    if (bloom) {
        free(bloom->bits);
        memset(bloom, 0, sizeof(*bloom));
    }
}

void akav_bloom_insert(akav_bloom_t* bloom, const uint8_t* key, size_t key_len)
{
    if (!bloom || !bloom->bits || !key) return;

    uint32_t h1 = akav_murmur3_32(key, key_len, 0);
    uint32_t h2 = akav_fnv1a_32(key, key_len);

    for (uint32_t i = 0; i < bloom->num_hashes; i++) {
        uint32_t idx = bloom_hash_i(h1, h2, i, bloom->num_bits);
        bloom->bits[idx / 8] |= (1u << (idx % 8));
    }

    bloom->num_items++;
}

bool akav_bloom_query(const akav_bloom_t* bloom, const uint8_t* key, size_t key_len)
{
    if (!bloom || !bloom->bits || !key) return false;

    uint32_t h1 = akav_murmur3_32(key, key_len, 0);
    uint32_t h2 = akav_fnv1a_32(key, key_len);

    for (uint32_t i = 0; i < bloom->num_hashes; i++) {
        uint32_t idx = bloom_hash_i(h1, h2, i, bloom->num_bits);
        if (!(bloom->bits[idx / 8] & (1u << (idx % 8)))) {
            return false;
        }
    }

    return true;
}

/* ── Serialization ────────────────────────────────────────────────── */

size_t akav_bloom_serialize(const akav_bloom_t* bloom, uint8_t* buf, size_t buf_size)
{
    if (!bloom || !bloom->bits) return 0;

    size_t byte_count = ((size_t)bloom->num_bits + 7) / 8;
    size_t required = 12 + byte_count; /* 3 × uint32_t + bit array */

    if (!buf || buf_size < required) {
        return required;
    }

    uint32_t vals[3] = { bloom->num_bits, bloom->num_hashes, bloom->num_items };
    memcpy(buf, vals, 12);
    memcpy(buf + 12, bloom->bits, byte_count);

    return required;
}

bool akav_bloom_deserialize(akav_bloom_t* bloom, const uint8_t* buf, size_t buf_size)
{
    if (!bloom || !buf || buf_size < 12) {
        return false;
    }

    uint32_t num_bits, num_hashes, num_items;
    memcpy(&num_bits, buf, 4);
    memcpy(&num_hashes, buf + 4, 4);
    memcpy(&num_items, buf + 8, 4);

    if (num_bits == 0 || num_hashes == 0) {
        return false;
    }

    /* Reject absurd num_hashes — theoretical max is num_bits * ln(2),
       but we cap at 256 which far exceeds any practical configuration.
       This prevents a crafted blob from causing billions of hash iterations. */
    if (num_hashes > 256) {
        return false;
    }

    size_t byte_count = ((size_t)num_bits + 7) / 8;
    if (buf_size < 12 + byte_count) {
        return false;
    }

    uint8_t* bits = (uint8_t*)malloc(byte_count);
    if (!bits) {
        return false;
    }

    memcpy(bits, buf + 12, byte_count);

    bloom->bits = bits;
    bloom->num_bits = num_bits;
    bloom->num_hashes = num_hashes;
    bloom->num_items = num_items;

    return true;
}
