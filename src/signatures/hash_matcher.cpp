#include "hash_matcher.h"
#include <stdlib.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

/* ── Comparators for qsort / bsearch ─────────────────────────────── */

static int cmp_md5(const void* a, const void* b)
{
    return memcmp(((const akav_md5_entry_t*)a)->hash,
                  ((const akav_md5_entry_t*)b)->hash,
                  AKAV_MD5_LEN);
}

static int cmp_sha256(const void* a, const void* b)
{
    return memcmp(((const akav_sha256_entry_t*)a)->hash,
                  ((const akav_sha256_entry_t*)b)->hash,
                  AKAV_SHA256_LEN);
}

/* ── Matcher lifecycle ────────────────────────────────────────────── */

void akav_hash_matcher_init(akav_hash_matcher_t* matcher)
{
    if (matcher) {
        memset(matcher, 0, sizeof(*matcher));
    }
}

void akav_hash_matcher_destroy(akav_hash_matcher_t* matcher)
{
    if (matcher) {
        free(matcher->md5_entries);
        free(matcher->sha256_entries);
        memset(matcher, 0, sizeof(*matcher));
    }
}

/* ── Build (copy + sort) ──────────────────────────────────────────── */

bool akav_hash_matcher_build_md5(akav_hash_matcher_t* matcher,
                                  const akav_md5_entry_t* entries,
                                  uint32_t count)
{
    if (!matcher) return false;

    free(matcher->md5_entries);
    matcher->md5_entries = NULL;
    matcher->md5_count = 0;

    if (count == 0 || !entries) return true;

    akav_md5_entry_t* copy = (akav_md5_entry_t*)malloc(
        (size_t)count * sizeof(akav_md5_entry_t));
    if (!copy) return false;

    memcpy(copy, entries, (size_t)count * sizeof(akav_md5_entry_t));
    qsort(copy, count, sizeof(akav_md5_entry_t), cmp_md5);

    matcher->md5_entries = copy;
    matcher->md5_count = count;
    return true;
}

bool akav_hash_matcher_build_sha256(akav_hash_matcher_t* matcher,
                                     const akav_sha256_entry_t* entries,
                                     uint32_t count)
{
    if (!matcher) return false;

    free(matcher->sha256_entries);
    matcher->sha256_entries = NULL;
    matcher->sha256_count = 0;

    if (count == 0 || !entries) return true;

    akav_sha256_entry_t* copy = (akav_sha256_entry_t*)malloc(
        (size_t)count * sizeof(akav_sha256_entry_t));
    if (!copy) return false;

    memcpy(copy, entries, (size_t)count * sizeof(akav_sha256_entry_t));
    qsort(copy, count, sizeof(akav_sha256_entry_t), cmp_sha256);

    matcher->sha256_entries = copy;
    matcher->sha256_count = count;
    return true;
}

/* ── Load (pre-sorted, no ownership) ──────────────────────────────── */

void akav_hash_matcher_load_md5(akav_hash_matcher_t* matcher,
                                 akav_md5_entry_t* entries,
                                 uint32_t count)
{
    if (!matcher) return;
    /* Free any previously built (owned) data */
    free(matcher->md5_entries);
    matcher->md5_entries = entries;
    matcher->md5_count = count;
}

void akav_hash_matcher_load_sha256(akav_hash_matcher_t* matcher,
                                    akav_sha256_entry_t* entries,
                                    uint32_t count)
{
    if (!matcher) return;
    free(matcher->sha256_entries);
    matcher->sha256_entries = entries;
    matcher->sha256_count = count;
}

/* ── Lookup (binary search) ───────────────────────────────────────── */

const akav_md5_entry_t* akav_hash_matcher_find_md5(
    const akav_hash_matcher_t* matcher,
    const uint8_t hash[AKAV_MD5_LEN])
{
    if (!matcher || !matcher->md5_entries || matcher->md5_count == 0 || !hash)
        return NULL;

    akav_md5_entry_t key;
    memcpy(key.hash, hash, AKAV_MD5_LEN);
    key.name_index = 0;

    return (const akav_md5_entry_t*)bsearch(
        &key, matcher->md5_entries, matcher->md5_count,
        sizeof(akav_md5_entry_t), cmp_md5);
}

const akav_sha256_entry_t* akav_hash_matcher_find_sha256(
    const akav_hash_matcher_t* matcher,
    const uint8_t hash[AKAV_SHA256_LEN])
{
    if (!matcher || !matcher->sha256_entries || matcher->sha256_count == 0 || !hash)
        return NULL;

    akav_sha256_entry_t key;
    memcpy(key.hash, hash, AKAV_SHA256_LEN);
    key.name_index = 0;

    return (const akav_sha256_entry_t*)bsearch(
        &key, matcher->sha256_entries, matcher->sha256_count,
        sizeof(akav_sha256_entry_t), cmp_sha256);
}

/* ── CNG hash computation ─────────────────────────────────────────── */

static bool cng_hash(const wchar_t* algorithm,
                     const uint8_t* data, size_t len,
                     uint8_t* out, ULONG out_len)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&alg, algorithm, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    /* BCryptHash is the one-shot helper (Win10+). */
    status = BCryptHash(alg, NULL, 0,
                        (PUCHAR)data, (ULONG)len,
                        out, out_len);

    BCryptCloseAlgorithmProvider(alg, 0);
    return BCRYPT_SUCCESS(status);
}

bool akav_hash_md5(const uint8_t* data, size_t len,
                   uint8_t out[AKAV_MD5_LEN])
{
    if (!out) return false;
    if (!data && len > 0) return false;

    return cng_hash(BCRYPT_MD5_ALGORITHM,
                    data ? data : (const uint8_t*)"", len,
                    out, AKAV_MD5_LEN);
}

bool akav_hash_sha256(const uint8_t* data, size_t len,
                      uint8_t out[AKAV_SHA256_LEN])
{
    if (!out) return false;
    if (!data && len > 0) return false;

    return cng_hash(BCRYPT_SHA256_ALGORITHM,
                    data ? data : (const uint8_t*)"", len,
                    out, AKAV_SHA256_LEN);
}
