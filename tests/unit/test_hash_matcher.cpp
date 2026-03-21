#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <array>

extern "C" {
#include "signatures/hash_matcher.h"
}

/* ── Helpers ──────────────────────────────────────────────────────── */

static void make_md5_entry(akav_md5_entry_t& e, uint8_t seed, uint32_t name_idx)
{
    for (int i = 0; i < AKAV_MD5_LEN; i++)
        e.hash[i] = static_cast<uint8_t>((seed + i * 37) & 0xFF);
    e.name_index = name_idx;
}

static void make_sha256_entry(akav_sha256_entry_t& e, uint8_t seed, uint32_t name_idx)
{
    for (int i = 0; i < AKAV_SHA256_LEN; i++)
        e.hash[i] = static_cast<uint8_t>((seed + i * 41) & 0xFF);
    e.name_index = name_idx;
}

/* ── Fixture ──────────────────────────────────────────────────────── */

class HashMatcherTest : public ::testing::Test {
protected:
    akav_hash_matcher_t matcher{};

    void SetUp() override
    {
        akav_hash_matcher_init(&matcher);
    }

    void TearDown() override
    {
        akav_hash_matcher_destroy(&matcher);
    }
};

/* ── Lifecycle tests ──────────────────────────────────────────────── */

TEST_F(HashMatcherTest, InitDestroy)
{
    EXPECT_EQ(matcher.md5_count, 0u);
    EXPECT_EQ(matcher.sha256_count, 0u);
    EXPECT_EQ(matcher.md5_entries, nullptr);
    EXPECT_EQ(matcher.sha256_entries, nullptr);
}

TEST_F(HashMatcherTest, DestroyNull)
{
    akav_hash_matcher_destroy(nullptr); /* must not crash */
}

/* ── MD5 tests ────────────────────────────────────────────────────── */

TEST_F(HashMatcherTest, BuildAndFindMD5)
{
    const uint32_t N = 100;
    std::vector<akav_md5_entry_t> entries(N);
    for (uint32_t i = 0; i < N; i++) {
        make_md5_entry(entries[i], static_cast<uint8_t>(i), i);
    }

    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, entries.data(), N));
    EXPECT_EQ(matcher.md5_count, N);

    /* All inserted hashes must be found */
    for (uint32_t i = 0; i < N; i++) {
        akav_md5_entry_t e;
        make_md5_entry(e, static_cast<uint8_t>(i), i);
        const akav_md5_entry_t* found = akav_hash_matcher_find_md5(&matcher, e.hash);
        ASSERT_NE(found, nullptr) << "MD5 not found at i=" << i;
        EXPECT_EQ(found->name_index, i);
    }
}

TEST_F(HashMatcherTest, MD5AbsentReturnsNull)
{
    const uint32_t N = 100;
    std::vector<akav_md5_entry_t> entries(N);
    for (uint32_t i = 0; i < N; i++) {
        make_md5_entry(entries[i], static_cast<uint8_t>(i), i);
    }

    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, entries.data(), N));

    /* Query a hash that was never inserted */
    uint8_t absent[AKAV_MD5_LEN];
    memset(absent, 0xFF, AKAV_MD5_LEN);
    EXPECT_EQ(akav_hash_matcher_find_md5(&matcher, absent), nullptr);
}

/* ── SHA-256 tests ────────────────────────────────────────────────── */

TEST_F(HashMatcherTest, BuildAndFindSHA256)
{
    const uint32_t N = 100;
    std::vector<akav_sha256_entry_t> entries(N);
    for (uint32_t i = 0; i < N; i++) {
        make_sha256_entry(entries[i], static_cast<uint8_t>(i), i);
    }

    ASSERT_TRUE(akav_hash_matcher_build_sha256(&matcher, entries.data(), N));
    EXPECT_EQ(matcher.sha256_count, N);

    for (uint32_t i = 0; i < N; i++) {
        akav_sha256_entry_t e;
        make_sha256_entry(e, static_cast<uint8_t>(i), i);
        const akav_sha256_entry_t* found = akav_hash_matcher_find_sha256(&matcher, e.hash);
        ASSERT_NE(found, nullptr) << "SHA256 not found at i=" << i;
        EXPECT_EQ(found->name_index, i);
    }
}

TEST_F(HashMatcherTest, SHA256AbsentReturnsNull)
{
    const uint32_t N = 100;
    std::vector<akav_sha256_entry_t> entries(N);
    for (uint32_t i = 0; i < N; i++) {
        make_sha256_entry(entries[i], static_cast<uint8_t>(i), i);
    }

    ASSERT_TRUE(akav_hash_matcher_build_sha256(&matcher, entries.data(), N));

    uint8_t absent[AKAV_SHA256_LEN];
    memset(absent, 0xFF, AKAV_SHA256_LEN);
    EXPECT_EQ(akav_hash_matcher_find_sha256(&matcher, absent), nullptr);
}

/* ── Scale: 1K found, 1K absent ───────────────────────────────────── */

TEST_F(HashMatcherTest, OneThousandMD5FoundAndAbsent)
{
    const uint32_t N = 1000;
    std::vector<akav_md5_entry_t> entries(N);

    /* Use CNG to generate real MD5 hashes for diversity */
    for (uint32_t i = 0; i < N; i++) {
        std::string data = "md5_present_" + std::to_string(i);
        ASSERT_TRUE(akav_hash_md5(reinterpret_cast<const uint8_t*>(data.data()),
                                  data.size(), entries[i].hash));
        entries[i].name_index = i;
    }

    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, entries.data(), N));

    /* All 1K present must be found */
    for (uint32_t i = 0; i < N; i++) {
        const akav_md5_entry_t* found = akav_hash_matcher_find_md5(
            &matcher, entries[i].hash);
        ASSERT_NE(found, nullptr) << "MD5 miss at i=" << i;
    }

    /* 1K absent must all return NULL */
    uint32_t false_matches = 0;
    for (uint32_t i = 0; i < N; i++) {
        uint8_t h[AKAV_MD5_LEN];
        std::string data = "md5_absent_" + std::to_string(i);
        ASSERT_TRUE(akav_hash_md5(reinterpret_cast<const uint8_t*>(data.data()),
                                  data.size(), h));
        if (akav_hash_matcher_find_md5(&matcher, h) != nullptr) {
            false_matches++;
        }
    }
    EXPECT_EQ(false_matches, 0u);
}

TEST_F(HashMatcherTest, OneThousandSHA256FoundAndAbsent)
{
    const uint32_t N = 1000;
    std::vector<akav_sha256_entry_t> entries(N);

    for (uint32_t i = 0; i < N; i++) {
        std::string data = "sha256_present_" + std::to_string(i);
        ASSERT_TRUE(akav_hash_sha256(reinterpret_cast<const uint8_t*>(data.data()),
                                     data.size(), entries[i].hash));
        entries[i].name_index = i;
    }

    ASSERT_TRUE(akav_hash_matcher_build_sha256(&matcher, entries.data(), N));

    for (uint32_t i = 0; i < N; i++) {
        const akav_sha256_entry_t* found = akav_hash_matcher_find_sha256(
            &matcher, entries[i].hash);
        ASSERT_NE(found, nullptr) << "SHA256 miss at i=" << i;
    }

    uint32_t false_matches = 0;
    for (uint32_t i = 0; i < N; i++) {
        uint8_t h[AKAV_SHA256_LEN];
        std::string data = "sha256_absent_" + std::to_string(i);
        ASSERT_TRUE(akav_hash_sha256(reinterpret_cast<const uint8_t*>(data.data()),
                                     data.size(), h));
        if (akav_hash_matcher_find_sha256(&matcher, h) != nullptr) {
            false_matches++;
        }
    }
    EXPECT_EQ(false_matches, 0u);
}

/* ── Performance: 100K lookups < 100ms ────────────────────────────── */

TEST_F(HashMatcherTest, HundredKLookupsMD5Under100ms)
{
    /* Build a table of 1K entries, then do 100K lookups */
    const uint32_t TABLE_SIZE = 1000;
    const uint32_t LOOKUPS = 100000;

    std::vector<akav_md5_entry_t> entries(TABLE_SIZE);
    for (uint32_t i = 0; i < TABLE_SIZE; i++) {
        std::string data = "perf_md5_" + std::to_string(i);
        ASSERT_TRUE(akav_hash_md5(reinterpret_cast<const uint8_t*>(data.data()),
                                  data.size(), entries[i].hash));
        entries[i].name_index = i;
    }
    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, entries.data(), TABLE_SIZE));

    /* Pre-compute lookup hashes (mix of present + absent) */
    std::vector<std::array<uint8_t, AKAV_MD5_LEN>> lookup_hashes(LOOKUPS);
    for (uint32_t i = 0; i < LOOKUPS; i++) {
        if (i < TABLE_SIZE) {
            memcpy(lookup_hashes[i].data(), entries[i].hash, AKAV_MD5_LEN);
        } else {
            std::string data = "perf_absent_" + std::to_string(i);
            akav_hash_md5(reinterpret_cast<const uint8_t*>(data.data()),
                          data.size(), lookup_hashes[i].data());
        }
    }

    auto start = std::chrono::high_resolution_clock::now();
    volatile uint32_t found_count = 0;
    for (uint32_t i = 0; i < LOOKUPS; i++) {
        if (akav_hash_matcher_find_md5(&matcher, lookup_hashes[i].data())) {
            found_count++;
        }
    }
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    EXPECT_LT(ms, 100) << "100K MD5 lookups took " << ms << "ms (limit: 100ms)";
    EXPECT_EQ(found_count, TABLE_SIZE);
}

TEST_F(HashMatcherTest, HundredKLookupsSHA256Under100ms)
{
    const uint32_t TABLE_SIZE = 1000;
    const uint32_t LOOKUPS = 100000;

    std::vector<akav_sha256_entry_t> entries(TABLE_SIZE);
    for (uint32_t i = 0; i < TABLE_SIZE; i++) {
        std::string data = "perf_sha_" + std::to_string(i);
        ASSERT_TRUE(akav_hash_sha256(reinterpret_cast<const uint8_t*>(data.data()),
                                     data.size(), entries[i].hash));
        entries[i].name_index = i;
    }
    ASSERT_TRUE(akav_hash_matcher_build_sha256(&matcher, entries.data(), TABLE_SIZE));

    std::vector<std::array<uint8_t, AKAV_SHA256_LEN>> lookup_hashes(LOOKUPS);
    for (uint32_t i = 0; i < LOOKUPS; i++) {
        if (i < TABLE_SIZE) {
            memcpy(lookup_hashes[i].data(), entries[i].hash, AKAV_SHA256_LEN);
        } else {
            std::string data = "perf_sha_absent_" + std::to_string(i);
            akav_hash_sha256(reinterpret_cast<const uint8_t*>(data.data()),
                             data.size(), lookup_hashes[i].data());
        }
    }

    auto start = std::chrono::high_resolution_clock::now();
    volatile uint32_t found_count = 0;
    for (uint32_t i = 0; i < LOOKUPS; i++) {
        if (akav_hash_matcher_find_sha256(&matcher, lookup_hashes[i].data())) {
            found_count++;
        }
    }
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    EXPECT_LT(ms, 100) << "100K SHA256 lookups took " << ms << "ms (limit: 100ms)";
    EXPECT_EQ(found_count, TABLE_SIZE);
}

/* ── CNG hash correctness ────────────────────────────────────────── */

TEST_F(HashMatcherTest, CNG_MD5_KnownVector)
{
    /* MD5("") = d41d8cd98f00b204e9800998ecf8427e */
    uint8_t out[AKAV_MD5_LEN];
    ASSERT_TRUE(akav_hash_md5(nullptr, 0, out));

    const uint8_t expected[] = {
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
    };
    EXPECT_EQ(memcmp(out, expected, AKAV_MD5_LEN), 0);
}

TEST_F(HashMatcherTest, CNG_SHA256_KnownVector)
{
    /* SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    uint8_t out[AKAV_SHA256_LEN];
    ASSERT_TRUE(akav_hash_sha256(nullptr, 0, out));

    const uint8_t expected[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    EXPECT_EQ(memcmp(out, expected, AKAV_SHA256_LEN), 0);
}

TEST_F(HashMatcherTest, CNG_MD5_HelloWorld)
{
    /* MD5("Hello, World!") = 65a8e27d8879283831b664bd8b7f0ad4 */
    const uint8_t data[] = "Hello, World!";
    uint8_t out[AKAV_MD5_LEN];
    ASSERT_TRUE(akav_hash_md5(data, 13, out));

    const uint8_t expected[] = {
        0x65, 0xa8, 0xe2, 0x7d, 0x88, 0x79, 0x28, 0x38,
        0x31, 0xb6, 0x64, 0xbd, 0x8b, 0x7f, 0x0a, 0xd4
    };
    EXPECT_EQ(memcmp(out, expected, AKAV_MD5_LEN), 0);
}

/* ── Edge cases ───────────────────────────────────────────────────── */

TEST_F(HashMatcherTest, EmptyTable)
{
    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, nullptr, 0));
    EXPECT_EQ(matcher.md5_count, 0u);

    uint8_t h[AKAV_MD5_LEN] = {};
    EXPECT_EQ(akav_hash_matcher_find_md5(&matcher, h), nullptr);
}

TEST_F(HashMatcherTest, SingleEntryTable)
{
    akav_md5_entry_t e;
    memset(e.hash, 0xAA, AKAV_MD5_LEN);
    e.name_index = 42;

    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, &e, 1));

    EXPECT_NE(akav_hash_matcher_find_md5(&matcher, e.hash), nullptr);

    uint8_t absent[AKAV_MD5_LEN];
    memset(absent, 0xBB, AKAV_MD5_LEN);
    EXPECT_EQ(akav_hash_matcher_find_md5(&matcher, absent), nullptr);
}

TEST_F(HashMatcherTest, FindNullHash)
{
    akav_md5_entry_t e;
    memset(e.hash, 0xAA, AKAV_MD5_LEN);
    e.name_index = 0;
    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, &e, 1));

    EXPECT_EQ(akav_hash_matcher_find_md5(&matcher, nullptr), nullptr);
    EXPECT_EQ(akav_hash_matcher_find_sha256(&matcher, nullptr), nullptr);
}

TEST_F(HashMatcherTest, DuplicateHashes)
{
    /* Two entries with the same hash but different name_index.
       Build must not crash; find returns one of them. */
    akav_md5_entry_t entries[2];
    memset(entries[0].hash, 0xCC, AKAV_MD5_LEN);
    entries[0].name_index = 10;
    memset(entries[1].hash, 0xCC, AKAV_MD5_LEN);
    entries[1].name_index = 20;

    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, entries, 2));

    const akav_md5_entry_t* found = akav_hash_matcher_find_md5(
        &matcher, entries[0].hash);
    ASSERT_NE(found, nullptr);
    /* bsearch may return either duplicate — just verify it's one of them */
    EXPECT_TRUE(found->name_index == 10 || found->name_index == 20);
}

TEST_F(HashMatcherTest, HashOutputNull)
{
    EXPECT_FALSE(akav_hash_md5((const uint8_t*)"x", 1, nullptr));
    EXPECT_FALSE(akav_hash_sha256((const uint8_t*)"x", 1, nullptr));
}

/* ── Adversarial ──────────────────────────────────────────────────── */

TEST_F(HashMatcherTest, AllZeroHashes)
{
    /* A table full of all-zero hashes — tests comparator stability */
    const uint32_t N = 50;
    std::vector<akav_md5_entry_t> entries(N);
    for (uint32_t i = 0; i < N; i++) {
        memset(entries[i].hash, 0x00, AKAV_MD5_LEN);
        entries[i].name_index = i;
    }

    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, entries.data(), N));

    uint8_t zero[AKAV_MD5_LEN] = {};
    const akav_md5_entry_t* found = akav_hash_matcher_find_md5(&matcher, zero);
    ASSERT_NE(found, nullptr);

    uint8_t nonzero[AKAV_MD5_LEN];
    memset(nonzero, 0x01, AKAV_MD5_LEN);
    EXPECT_EQ(akav_hash_matcher_find_md5(&matcher, nonzero), nullptr);
}

TEST_F(HashMatcherTest, AllFFHashes)
{
    const uint32_t N = 50;
    std::vector<akav_sha256_entry_t> entries(N);
    for (uint32_t i = 0; i < N; i++) {
        memset(entries[i].hash, 0xFF, AKAV_SHA256_LEN);
        entries[i].name_index = i;
    }

    ASSERT_TRUE(akav_hash_matcher_build_sha256(&matcher, entries.data(), N));

    uint8_t ff[AKAV_SHA256_LEN];
    memset(ff, 0xFF, AKAV_SHA256_LEN);
    EXPECT_NE(akav_hash_matcher_find_sha256(&matcher, ff), nullptr);

    uint8_t fe[AKAV_SHA256_LEN];
    memset(fe, 0xFE, AKAV_SHA256_LEN);
    EXPECT_EQ(akav_hash_matcher_find_sha256(&matcher, fe), nullptr);
}

TEST_F(HashMatcherTest, RebuildReplacesOldTable)
{
    /* Build once, then build again with different data.
       Old data must be freed, new data must be correct. */
    akav_md5_entry_t e1;
    memset(e1.hash, 0xAA, AKAV_MD5_LEN);
    e1.name_index = 1;
    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, &e1, 1));

    akav_md5_entry_t e2;
    memset(e2.hash, 0xBB, AKAV_MD5_LEN);
    e2.name_index = 2;
    ASSERT_TRUE(akav_hash_matcher_build_md5(&matcher, &e2, 1));

    EXPECT_EQ(matcher.md5_count, 1u);
    EXPECT_EQ(akav_hash_matcher_find_md5(&matcher, e1.hash), nullptr);
    EXPECT_NE(akav_hash_matcher_find_md5(&matcher, e2.hash), nullptr);
}
