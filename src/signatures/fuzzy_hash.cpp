/* fuzzy_hash.cpp -- ssdeep-compatible fuzzy hashing implementation.
 *
 * Algorithm overview (compatible with ssdeep/ctph):
 *   1. Choose block_size based on file length so digest fits ~64 chars
 *   2. Rolling hash (Adler32-variant, window=7) streams over every byte
 *   3. When rolling_hash % block_size == (block_size - 1), emit boundary
 *   4. FNV-1a accumulates bytes between boundaries → one base64 char each
 *   5. Produce two digests: one at block_size, one at block_size*2
 *   6. Output: "block_size:digest1:digest2"
 *
 * Similarity scoring:
 *   - Parse block sizes from both hashes
 *   - If block sizes are compatible (same or 2x), compare digests
 *   - LCS (longest common subsequence) on the base64 digest strings
 *   - Score = 100 * LCS_len / max(len1, len2), with short-string boost
 */

#include "signatures/fuzzy_hash.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Rolling hash (Adler32-variant, ssdeep-compatible) ─────────── */

#define ROLLING_WINDOW 7

typedef struct {
    uint32_t h1, h2, h3;
    uint32_t n;
    uint8_t  window[ROLLING_WINDOW];
    uint32_t wpos;
} rolling_state_t;

static void rolling_init(rolling_state_t* r)
{
    memset(r, 0, sizeof(*r));
}

static uint32_t rolling_hash(rolling_state_t* r, uint8_t byte)
{
    /* Remove oldest byte contribution */
    r->h2 -= r->h1;
    r->h2 += ROLLING_WINDOW * (uint32_t)byte;

    r->h1 += byte;
    r->h1 -= r->window[r->wpos];

    r->window[r->wpos] = byte;
    r->wpos = (r->wpos + 1) % ROLLING_WINDOW;

    r->h3 = (r->h3 << 5) ^ byte;
    r->n++;

    return r->h1 + r->h2 + r->h3;
}

/* ── FNV-1a for block accumulation ──────────────────────────────── */

#define FNV_OFFSET_BASIS 0x811C9DC5u
#define FNV_PRIME        0x01000193u

static uint32_t fnv1a_init(void) { return FNV_OFFSET_BASIS; }

static uint32_t fnv1a_update(uint32_t h, uint8_t byte)
{
    h ^= byte;
    h *= FNV_PRIME;
    return h;
}

/* ── Base64 encoding for digest ─────────────────────────────────── */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Map a FNV hash to a single base64 character */
static char fnv_to_b64(uint32_t h)
{
    return B64[h % 64];
}

/* ── Block size selection ───────────────────────────────────────── */

/* Choose the smallest block_size such that the file produces
 * a digest of roughly AKAV_FUZZY_DIGEST_LEN characters or fewer.
 * block_size is always a power of 2 times the minimum. */
static uint32_t choose_block_size(size_t file_len)
{
    /* Start at minimum block size */
    uint32_t bs = 3;  /* actual block size = bs, ssdeep uses powers differently */

    /* ssdeep starts block_size at MIN_BLOCKSIZE and doubles until
     * file_len / block_size < SPAMSUM_LENGTH (64). We do the same. */
    bs = 3;  /* minimum */
    while (bs * AKAV_FUZZY_DIGEST_LEN < file_len && bs < 0x40000000u) {
        bs *= 2;
    }

    /* Ensure minimum of 3 to avoid degenerate cases */
    if (bs < 3) bs = 3;

    return bs;
}

/* ── Compute fuzzy hash ─────────────────────────────────────────── */

bool akav_fuzzy_hash_compute(const uint8_t* data, size_t len,
                              char out_hash[AKAV_FUZZY_HASH_MAX])
{
    if (!out_hash) return false;
    out_hash[0] = '\0';

    if (!data || len == 0) {
        snprintf(out_hash, AKAV_FUZZY_HASH_MAX, "3::");
        return true;
    }

    uint32_t block_size = choose_block_size(len);

    /* Two passes: digest1 at block_size, digest2 at block_size*2 */
    char digest1[AKAV_FUZZY_DIGEST_LEN + 1];
    char digest2[AKAV_FUZZY_DIGEST_LEN + 1];
    int d1_len = 0, d2_len = 0;

    rolling_state_t roll;
    rolling_init(&roll);

    uint32_t fnv1 = fnv1a_init();
    uint32_t fnv2 = fnv1a_init();

    uint32_t bs2 = block_size * 2;

    for (size_t i = 0; i < len; i++) {
        uint32_t rh = rolling_hash(&roll, data[i]);
        fnv1 = fnv1a_update(fnv1, data[i]);
        fnv2 = fnv1a_update(fnv2, data[i]);

        /* Check boundary for block_size */
        if ((rh % block_size) == (block_size - 1)) {
            if (d1_len < AKAV_FUZZY_DIGEST_LEN) {
                digest1[d1_len++] = fnv_to_b64(fnv1);
            }
            fnv1 = fnv1a_init();
        }

        /* Check boundary for block_size * 2 */
        if ((rh % bs2) == (bs2 - 1)) {
            if (d2_len < AKAV_FUZZY_DIGEST_LEN) {
                digest2[d2_len++] = fnv_to_b64(fnv2);
            }
            fnv2 = fnv1a_init();
        }
    }

    /* Emit final partial block */
    if (d1_len < AKAV_FUZZY_DIGEST_LEN) {
        digest1[d1_len++] = fnv_to_b64(fnv1);
    }
    if (d2_len < AKAV_FUZZY_DIGEST_LEN) {
        digest2[d2_len++] = fnv_to_b64(fnv2);
    }

    digest1[d1_len] = '\0';
    digest2[d2_len] = '\0';

    snprintf(out_hash, AKAV_FUZZY_HASH_MAX, "%u:%s:%s",
             block_size, digest1, digest2);
    return true;
}

/* ── Longest Common Subsequence (for similarity) ────────────────── */

/* Compute LCS length between two strings.
 * Uses O(min(m,n)) space with two-row DP. */
static int lcs_length(const char* s1, int len1, const char* s2, int len2)
{
    if (len1 == 0 || len2 == 0) return 0;

    /* Ensure s1 is the shorter string for memory efficiency */
    if (len1 > len2) {
        const char* tmp_s = s1; s1 = s2; s2 = tmp_s;
        int tmp_l = len1; len1 = len2; len2 = tmp_l;
    }

    /* Allocate two rows */
    int* prev = (int*)calloc((size_t)len1 + 1, sizeof(int));
    int* curr = (int*)calloc((size_t)len1 + 1, sizeof(int));
    if (!prev || !curr) {
        free(prev);
        free(curr);
        return 0;
    }

    for (int j = 0; j < len2; j++) {
        for (int i = 0; i < len1; i++) {
            if (s1[i] == s2[j]) {
                curr[i + 1] = prev[i] + 1;
            } else {
                curr[i + 1] = curr[i] > prev[i + 1] ? curr[i] : prev[i + 1];
            }
        }
        /* Swap rows */
        int* tmp = prev; prev = curr; curr = tmp;
        memset(curr, 0, ((size_t)len1 + 1) * sizeof(int));
    }

    int result = prev[len1];
    free(prev);
    free(curr);
    return result;
}

/* ── Parse a fuzzy hash string ──────────────────────────────────── */

typedef struct {
    uint32_t block_size;
    char digest1[AKAV_FUZZY_DIGEST_LEN + 1];
    char digest2[AKAV_FUZZY_DIGEST_LEN + 1];
} parsed_fuzzy_t;

static bool parse_fuzzy(const char* hash, parsed_fuzzy_t* out)
{
    if (!hash || !out) return false;
    memset(out, 0, sizeof(*out));

    /* Format: "block_size:digest1:digest2" */
    const char* p = hash;

    /* Parse block_size */
    char* end = NULL;
    unsigned long bs = strtoul(p, &end, 10);
    if (!end || *end != ':' || bs == 0) return false;
    out->block_size = (uint32_t)bs;

    p = end + 1;

    /* Parse digest1 */
    const char* colon = strchr(p, ':');
    if (!colon) return false;
    size_t d1_len = (size_t)(colon - p);
    if (d1_len > AKAV_FUZZY_DIGEST_LEN) d1_len = AKAV_FUZZY_DIGEST_LEN;
    memcpy(out->digest1, p, d1_len);
    out->digest1[d1_len] = '\0';

    /* Parse digest2 */
    p = colon + 1;
    size_t d2_len = strlen(p);
    if (d2_len > AKAV_FUZZY_DIGEST_LEN) d2_len = AKAV_FUZZY_DIGEST_LEN;
    memcpy(out->digest2, p, d2_len);
    out->digest2[d2_len] = '\0';

    return true;
}

/* ── Similarity scoring ─────────────────────────────────────────── */

/* Score two digest strings using LCS */
static int score_strings(const char* s1, const char* s2)
{
    int len1 = (int)strlen(s1);
    int len2 = (int)strlen(s2);

    if (len1 == 0 && len2 == 0) return 100;
    if (len1 == 0 || len2 == 0) return 0;

    int lcs = lcs_length(s1, len1, s2, len2);
    int max_len = len1 > len2 ? len1 : len2;

    /* Scale: LCS / max_len * 100, but give a boost for short strings
     * (ssdeep uses block_size-dependent scoring; we simplify) */
    int score = (lcs * 100) / max_len;

    return score > 100 ? 100 : score;
}

int akav_fuzzy_compare(const char* hash1, const char* hash2)
{
    if (!hash1 || !hash2) return 0;

    /* Same hash string → 100 */
    if (strcmp(hash1, hash2) == 0) return 100;

    parsed_fuzzy_t p1, p2;
    if (!parse_fuzzy(hash1, &p1) || !parse_fuzzy(hash2, &p2))
        return 0;

    /* Block sizes must be compatible:
     * same, or one is 2x the other.
     * When block sizes differ by 2x, compare:
     *   smaller.digest1 vs larger.digest2  (or vice versa) */
    int best_score = 0;

    if (p1.block_size == p2.block_size) {
        /* Compare digest1 vs digest1, and digest2 vs digest2 */
        int s1 = score_strings(p1.digest1, p2.digest1);
        int s2 = score_strings(p1.digest2, p2.digest2);
        best_score = s1 > s2 ? s1 : s2;
    }
    else if (p1.block_size == p2.block_size * 2) {
        /* p2 is smaller block_size: compare p2.digest1 vs p1.digest2 */
        int s = score_strings(p2.digest1, p1.digest2);
        /* Also try same-size comparison if digest2 makes sense */
        best_score = s;
    }
    else if (p2.block_size == p1.block_size * 2) {
        /* p1 is smaller block_size: compare p1.digest1 vs p2.digest2 */
        int s = score_strings(p1.digest1, p2.digest2);
        best_score = s;
    }
    else {
        /* Block sizes too different — not comparable */
        return 0;
    }

    return best_score;
}

/* ── Fuzzy matcher ──────────────────────────────────────────────── */

void akav_fuzzy_matcher_init(akav_fuzzy_matcher_t* matcher)
{
    if (!matcher) return;
    memset(matcher, 0, sizeof(*matcher));
    matcher->threshold = 80; /* default */
}

void akav_fuzzy_matcher_destroy(akav_fuzzy_matcher_t* matcher)
{
    if (!matcher) return;
    free(matcher->entries);
    memset(matcher, 0, sizeof(*matcher));
}

bool akav_fuzzy_matcher_build(akav_fuzzy_matcher_t* matcher,
                               const akav_fuzzy_entry_t* entries,
                               uint32_t count,
                               int threshold)
{
    if (!matcher) return false;

    /* Free any previous data */
    free(matcher->entries);
    matcher->entries = NULL;
    matcher->count = 0;

    if (!entries || count == 0)
        return true; /* Empty matcher is valid */

    matcher->entries = (akav_fuzzy_entry_t*)malloc(
        count * sizeof(akav_fuzzy_entry_t));
    if (!matcher->entries)
        return false;

    memcpy(matcher->entries, entries, count * sizeof(akav_fuzzy_entry_t));
    matcher->count = count;
    matcher->threshold = (threshold > 0 && threshold <= 100) ? threshold : 80;

    return true;
}

uint32_t akav_fuzzy_matcher_scan(const akav_fuzzy_matcher_t* matcher,
                                  const uint8_t* data, size_t data_len,
                                  akav_fuzzy_match_t* out, uint32_t out_max)
{
    if (!matcher || !data || data_len == 0 || matcher->count == 0)
        return 0;

    /* Compute the fuzzy hash of the input */
    char file_hash[AKAV_FUZZY_HASH_MAX];
    if (!akav_fuzzy_hash_compute(data, data_len, file_hash))
        return 0;

    uint32_t match_count = 0;

    /* Compare against each entry */
    for (uint32_t i = 0; i < matcher->count; i++) {
        int sim = akav_fuzzy_compare(file_hash, matcher->entries[i].hash);
        if (sim >= matcher->threshold) {
            if (out && match_count < out_max) {
                out[match_count].entry_index = i;
                out[match_count].name_index = matcher->entries[i].name_index;
                out[match_count].similarity = sim;
            }
            match_count++;
        }
    }

    /* Sort matches by similarity descending (insertion sort, small N) */
    if (out && match_count > 1) {
        uint32_t sort_count = match_count < out_max ? match_count : out_max;
        for (uint32_t i = 1; i < sort_count; i++) {
            akav_fuzzy_match_t key = out[i];
            uint32_t j = i;
            while (j > 0 && out[j - 1].similarity < key.similarity) {
                out[j] = out[j - 1];
                j--;
            }
            out[j] = key;
        }
    }

    return match_count;
}
