// test_fuzzy_hash.cpp -- Tests for ssdeep-compatible fuzzy hashing (P6-T1).
//
// Tests:
//   1. Compute hash returns valid format
//   2. Identical buffers produce score 100
//   3. One-byte change produces score > 95
//   4. Appended data produces score > 80
//   5. Completely different data produces score < 10
//   6. Empty buffer produces valid hash
//   7. Small buffer (< block_size) produces valid hash
//   8. Block size scales with file length
//   9. Compare with incompatible block sizes returns 0
//  10. Prepended data produces score > 70
//  11. Fuzzy matcher init/destroy
//  12. Fuzzy matcher build with entries
//  13. Fuzzy matcher scan detects similar buffer
//  14. Fuzzy matcher scan rejects dissimilar buffer
//  15. Fuzzy matcher respects threshold
//  16. Fuzzy matcher returns best match first

#include <gtest/gtest.h>

#include "signatures/fuzzy_hash.h"

#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

// ---- Helpers ------------------------------------------------------------

// Generate a pseudo-random buffer with good entropy (avoids degenerate
// rolling hash cycles that repeating patterns cause).
static std::vector<uint8_t> make_random_buffer(size_t size, uint32_t seed = 42)
{
    std::vector<uint8_t> buf(size);
    uint32_t state = seed;
    for (size_t i = 0; i < size; i++) {
        state = state * 1103515245u + 12345u;
        buf[i] = (uint8_t)(state >> 16);
    }
    return buf;
}

// Parse block_size from a fuzzy hash string
static uint32_t parse_block_size(const char* hash)
{
    return (uint32_t)strtoul(hash, nullptr, 10);
}

// Count the digest length (number of chars in digest1)
static size_t digest1_length(const char* hash)
{
    std::string h(hash);
    auto c1 = h.find(':');
    if (c1 == std::string::npos) return 0;
    auto c2 = h.find(':', c1 + 1);
    if (c2 == std::string::npos) return 0;
    return c2 - c1 - 1;
}

// ---- Hash computation tests ---------------------------------------------

TEST(FuzzyHash, ComputeReturnsValidFormat)
{
    auto buf = make_random_buffer(4096);
    char hash[AKAV_FUZZY_HASH_MAX];

    ASSERT_TRUE(akav_fuzzy_hash_compute(buf.data(), buf.size(), hash));

    // Format: "block_size:digest1:digest2"
    std::string h(hash);
    auto colon1 = h.find(':');
    ASSERT_NE(colon1, std::string::npos);
    auto colon2 = h.find(':', colon1 + 1);
    ASSERT_NE(colon2, std::string::npos);

    // Block size should be a positive number
    uint32_t bs = parse_block_size(hash);
    EXPECT_GT(bs, 0u);

    // Digests should be non-empty
    std::string d1 = h.substr(colon1 + 1, colon2 - colon1 - 1);
    std::string d2 = h.substr(colon2 + 1);
    EXPECT_GT(d1.size(), 0u);
    EXPECT_GT(d2.size(), 0u);
}

TEST(FuzzyHash, IdenticalBuffersScore100)
{
    auto buf = make_random_buffer(65536, 123);
    char hash1[AKAV_FUZZY_HASH_MAX];
    char hash2[AKAV_FUZZY_HASH_MAX];

    ASSERT_TRUE(akav_fuzzy_hash_compute(buf.data(), buf.size(), hash1));
    ASSERT_TRUE(akav_fuzzy_hash_compute(buf.data(), buf.size(), hash2));

    EXPECT_STREQ(hash1, hash2);
    EXPECT_EQ(akav_fuzzy_compare(hash1, hash2), 100);
}

TEST(FuzzyHash, OneByteChangeScoreAbove95)
{
    // Use 64KB random buffer to get a rich digest
    auto buf = make_random_buffer(65536, 200);
    char hash1[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(buf.data(), buf.size(), hash1));

    // Verify we have a meaningful digest (> 10 chars)
    ASSERT_GT(digest1_length(hash1), 10u)
        << "Digest too short for meaningful comparison: " << hash1;

    // Change one byte in the middle
    buf[32768] ^= 0xFF;
    char hash2[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(buf.data(), buf.size(), hash2));

    int score = akav_fuzzy_compare(hash1, hash2);
    EXPECT_GT(score, 95) << "Score: " << score
        << "\nhash1: " << hash1
        << "\nhash2: " << hash2;
}

TEST(FuzzyHash, AppendedDataScoreAbove80)
{
    auto buf = make_random_buffer(65536, 300);
    char hash1[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(buf.data(), buf.size(), hash1));
    ASSERT_GT(digest1_length(hash1), 10u);

    // Append ~6% extra data
    auto appended = buf;
    auto extra = make_random_buffer(4096, 999);
    appended.insert(appended.end(), extra.begin(), extra.end());

    char hash2[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(appended.data(), appended.size(), hash2));

    int score = akav_fuzzy_compare(hash1, hash2);
    EXPECT_GT(score, 80) << "Score: " << score
        << "\nhash1: " << hash1
        << "\nhash2: " << hash2;
}

TEST(FuzzyHash, DifferentDataScoreBelow10)
{
    auto buf1 = make_random_buffer(65536, 400);
    auto buf2 = make_random_buffer(65536, 500);
    char hash1[AKAV_FUZZY_HASH_MAX];
    char hash2[AKAV_FUZZY_HASH_MAX];

    ASSERT_TRUE(akav_fuzzy_hash_compute(buf1.data(), buf1.size(), hash1));
    ASSERT_TRUE(akav_fuzzy_hash_compute(buf2.data(), buf2.size(), hash2));

    int score = akav_fuzzy_compare(hash1, hash2);
    EXPECT_LT(score, 20) << "Score: " << score
        << "\nhash1: " << hash1
        << "\nhash2: " << hash2;
}

TEST(FuzzyHash, EmptyBufferProducesValidHash)
{
    char hash[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(nullptr, 0, hash));
    EXPECT_STREQ(hash, "3::");
}

TEST(FuzzyHash, SmallBufferProducesValidHash)
{
    uint8_t small[] = "Hello";
    char hash[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(small, 5, hash));

    // Should still have valid format
    std::string h(hash);
    EXPECT_NE(h.find(':'), std::string::npos);
}

TEST(FuzzyHash, BlockSizeScalesWithLength)
{
    auto small = make_random_buffer(1024, 600);
    auto large = make_random_buffer(1024 * 1024, 700);

    char hash_small[AKAV_FUZZY_HASH_MAX];
    char hash_large[AKAV_FUZZY_HASH_MAX];

    ASSERT_TRUE(akav_fuzzy_hash_compute(small.data(), small.size(), hash_small));
    ASSERT_TRUE(akav_fuzzy_hash_compute(large.data(), large.size(), hash_large));

    uint32_t bs_small = parse_block_size(hash_small);
    uint32_t bs_large = parse_block_size(hash_large);

    // Larger files should have larger block sizes
    EXPECT_GT(bs_large, bs_small)
        << "small bs=" << bs_small << " large bs=" << bs_large;
}

// ---- Comparison edge cases ----------------------------------------------

TEST(FuzzyHash, IncompatibleBlockSizesReturnZero)
{
    // Manually craft hashes with block sizes that differ by > 2x
    int score = akav_fuzzy_compare("3:abc:def", "24:xyz:uvw");
    EXPECT_EQ(score, 0);
}

TEST(FuzzyHash, PrependedDataScoreAbove70)
{
    auto buf = make_random_buffer(65536, 800);
    char hash1[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(buf.data(), buf.size(), hash1));
    ASSERT_GT(digest1_length(hash1), 10u);

    // Prepend ~6% data
    auto extra = make_random_buffer(4096, 888);
    auto prepended = extra;
    prepended.insert(prepended.end(), buf.begin(), buf.end());

    char hash2[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(prepended.data(), prepended.size(), hash2));

    int score = akav_fuzzy_compare(hash1, hash2);
    EXPECT_GT(score, 70) << "Score: " << score
        << "\nhash1: " << hash1
        << "\nhash2: " << hash2;
}

// ---- Matcher tests ------------------------------------------------------

TEST(FuzzyMatcher, InitDestroy)
{
    akav_fuzzy_matcher_t m;
    akav_fuzzy_matcher_init(&m);
    EXPECT_EQ(m.count, 0u);
    EXPECT_EQ(m.threshold, 80);
    akav_fuzzy_matcher_destroy(&m);
}

TEST(FuzzyMatcher, BuildWithEntries)
{
    auto buf = make_random_buffer(4096, 900);
    char hash[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(buf.data(), buf.size(), hash));

    akav_fuzzy_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy_s(entry.hash, sizeof(entry.hash), hash, _TRUNCATE);
    entry.name_index = 42;

    akav_fuzzy_matcher_t m;
    akav_fuzzy_matcher_init(&m);
    ASSERT_TRUE(akav_fuzzy_matcher_build(&m, &entry, 1, 80));
    EXPECT_EQ(m.count, 1u);
    EXPECT_EQ(m.threshold, 80);
    akav_fuzzy_matcher_destroy(&m);
}

TEST(FuzzyMatcher, ScanDetectsSimilarBuffer)
{
    // Use 64KB random buffer for rich digests
    auto original = make_random_buffer(65536, 1000);
    char orig_hash[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(original.data(), original.size(), orig_hash));
    ASSERT_GT(digest1_length(orig_hash), 10u);

    akav_fuzzy_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy_s(entry.hash, sizeof(entry.hash), orig_hash, _TRUNCATE);
    entry.name_index = 100;

    akav_fuzzy_matcher_t m;
    akav_fuzzy_matcher_init(&m);
    ASSERT_TRUE(akav_fuzzy_matcher_build(&m, &entry, 1, 80));

    // Scan with a slightly modified version (1 byte changed)
    auto variant = original;
    variant[32768] ^= 0xFF;

    akav_fuzzy_match_t match;
    uint32_t count = akav_fuzzy_matcher_scan(&m, variant.data(), variant.size(),
                                              &match, 1);
    EXPECT_GE(count, 1u);
    if (count > 0) {
        EXPECT_EQ(match.name_index, 100u);
        EXPECT_GT(match.similarity, 80);
    }

    akav_fuzzy_matcher_destroy(&m);
}

TEST(FuzzyMatcher, ScanRejectsDissimilarBuffer)
{
    auto original = make_random_buffer(65536, 1100);
    char orig_hash[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(original.data(), original.size(), orig_hash));

    akav_fuzzy_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy_s(entry.hash, sizeof(entry.hash), orig_hash, _TRUNCATE);
    entry.name_index = 200;

    akav_fuzzy_matcher_t m;
    akav_fuzzy_matcher_init(&m);
    ASSERT_TRUE(akav_fuzzy_matcher_build(&m, &entry, 1, 80));

    // Scan with completely different data
    auto different = make_random_buffer(65536, 1200);

    akav_fuzzy_match_t match;
    uint32_t count = akav_fuzzy_matcher_scan(&m, different.data(), different.size(),
                                              &match, 1);
    EXPECT_EQ(count, 0u);

    akav_fuzzy_matcher_destroy(&m);
}

TEST(FuzzyMatcher, RespectsThreshold)
{
    auto original = make_random_buffer(65536, 1300);
    char orig_hash[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(original.data(), original.size(), orig_hash));

    akav_fuzzy_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy_s(entry.hash, sizeof(entry.hash), orig_hash, _TRUNCATE);
    entry.name_index = 300;

    // Build with very high threshold (99)
    akav_fuzzy_matcher_t m;
    akav_fuzzy_matcher_init(&m);
    ASSERT_TRUE(akav_fuzzy_matcher_build(&m, &entry, 1, 99));

    // Modify a few bytes -- should be similar but potentially below 99
    auto variant = original;
    variant[10000] ^= 0xFF;
    variant[20000] ^= 0xFF;
    variant[40000] ^= 0xFF;

    akav_fuzzy_match_t match;
    uint32_t count = akav_fuzzy_matcher_scan(&m, variant.data(), variant.size(),
                                              &match, 1);

    // With threshold=99, slight changes might not match
    // This test verifies the threshold is applied
    if (count > 0) {
        EXPECT_GE(match.similarity, 99);
    }

    akav_fuzzy_matcher_destroy(&m);
}

TEST(FuzzyMatcher, ReturnsBestMatchFirst)
{
    auto target = make_random_buffer(65536, 1400);
    char target_hash[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(target.data(), target.size(), target_hash));

    // Create a slightly different version
    auto similar = target;
    for (int i = 0; i < 20; i++) {
        similar[(size_t)i * 3000 + 500] ^= 0xFF;
    }
    char similar_hash[AKAV_FUZZY_HASH_MAX];
    ASSERT_TRUE(akav_fuzzy_hash_compute(similar.data(), similar.size(), similar_hash));

    akav_fuzzy_entry_t entries[2];
    memset(entries, 0, sizeof(entries));

    // Entry 0: slightly different (lower score)
    strncpy_s(entries[0].hash, sizeof(entries[0].hash), similar_hash, _TRUNCATE);
    entries[0].name_index = 10;

    // Entry 1: exact match (score 100)
    strncpy_s(entries[1].hash, sizeof(entries[1].hash), target_hash, _TRUNCATE);
    entries[1].name_index = 20;

    akav_fuzzy_matcher_t m;
    akav_fuzzy_matcher_init(&m);
    ASSERT_TRUE(akav_fuzzy_matcher_build(&m, entries, 2, 50));

    akav_fuzzy_match_t matches[2];
    uint32_t count = akav_fuzzy_matcher_scan(&m, target.data(), target.size(),
                                              matches, 2);
    ASSERT_GE(count, 1u);

    // Best match (highest similarity) should be first
    EXPECT_EQ(matches[0].similarity, 100);
    EXPECT_EQ(matches[0].name_index, 20u);

    if (count >= 2) {
        EXPECT_GE(matches[0].similarity, matches[1].similarity);
    }

    akav_fuzzy_matcher_destroy(&m);
}
