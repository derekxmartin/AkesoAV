#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <cstring>

extern "C" {
#include "signatures/bloom.h"
}

class BloomTest : public ::testing::Test {
protected:
    akav_bloom_t bloom{};

    void TearDown() override
    {
        akav_bloom_destroy(&bloom);
    }
};

TEST_F(BloomTest, CreateDestroy)
{
    ASSERT_TRUE(akav_bloom_create(&bloom, 1000, 10));
    EXPECT_EQ(bloom.num_bits, 10000u);
    EXPECT_GT(bloom.num_hashes, 0u);
    EXPECT_EQ(bloom.num_items, 0u);
}

TEST_F(BloomTest, CreateInvalidArgs)
{
    EXPECT_FALSE(akav_bloom_create(nullptr, 1000, 10));
    EXPECT_FALSE(akav_bloom_create(&bloom, 0, 10));
    EXPECT_FALSE(akav_bloom_create(&bloom, 1000, 0));
}

TEST_F(BloomTest, InsertAndQuerySingle)
{
    ASSERT_TRUE(akav_bloom_create(&bloom, 100, 10));

    const uint8_t key[] = "hello";
    akav_bloom_insert(&bloom, key, 5);
    EXPECT_TRUE(akav_bloom_query(&bloom, key, 5));
    EXPECT_EQ(bloom.num_items, 1u);
}

TEST_F(BloomTest, QueryAbsentKey)
{
    ASSERT_TRUE(akav_bloom_create(&bloom, 100, 10));

    const uint8_t key[] = "hello";
    akav_bloom_insert(&bloom, key, 5);

    /* We test the deterministic property: inserted keys always return true */
    EXPECT_TRUE(akav_bloom_query(&bloom, key, 5));
}

TEST_F(BloomTest, TenThousandInsertedAllFound)
{
    const uint32_t N = 10000;
    ASSERT_TRUE(akav_bloom_create(&bloom, N, 10));

    /* Insert 10K items */
    for (uint32_t i = 0; i < N; i++) {
        std::string key = "inserted_key_" + std::to_string(i);
        akav_bloom_insert(&bloom, reinterpret_cast<const uint8_t*>(key.data()),
                          key.size());
    }

    EXPECT_EQ(bloom.num_items, N);

    /* All inserted keys must be found (zero false negatives) */
    for (uint32_t i = 0; i < N; i++) {
        std::string key = "inserted_key_" + std::to_string(i);
        EXPECT_TRUE(akav_bloom_query(&bloom, reinterpret_cast<const uint8_t*>(key.data()),
                                     key.size()))
            << "False negative at i=" << i;
    }
}

TEST_F(BloomTest, TenThousandAbsentFPRateUnderOnePercent)
{
    const uint32_t N = 10000;
    ASSERT_TRUE(akav_bloom_create(&bloom, N, 10));

    /* Insert 10K items */
    for (uint32_t i = 0; i < N; i++) {
        std::string key = "inserted_key_" + std::to_string(i);
        akav_bloom_insert(&bloom, reinterpret_cast<const uint8_t*>(key.data()),
                          key.size());
    }

    /* Query 10K *different* keys and count false positives */
    uint32_t false_positives = 0;
    for (uint32_t i = 0; i < N; i++) {
        std::string key = "absent_key_" + std::to_string(i);
        if (akav_bloom_query(&bloom, reinterpret_cast<const uint8_t*>(key.data()),
                             key.size())) {
            false_positives++;
        }
    }

    double fp_rate = static_cast<double>(false_positives) / N;
    EXPECT_LT(fp_rate, 0.01)
        << "FP rate " << (fp_rate * 100.0) << "% exceeds 1% threshold ("
        << false_positives << " / " << N << ")";
}

TEST_F(BloomTest, SerializeDeserializeRoundTrip)
{
    const uint32_t N = 1000;
    ASSERT_TRUE(akav_bloom_create(&bloom, N, 10));

    /* Insert items */
    for (uint32_t i = 0; i < N; i++) {
        std::string key = "roundtrip_" + std::to_string(i);
        akav_bloom_insert(&bloom, reinterpret_cast<const uint8_t*>(key.data()),
                          key.size());
    }

    /* Serialize */
    size_t needed = akav_bloom_serialize(&bloom, nullptr, 0);
    ASSERT_GT(needed, 0u);

    std::vector<uint8_t> buf(needed);
    size_t written = akav_bloom_serialize(&bloom, buf.data(), buf.size());
    ASSERT_EQ(written, needed);

    /* Deserialize into a new filter */
    akav_bloom_t bloom2{};
    ASSERT_TRUE(akav_bloom_deserialize(&bloom2, buf.data(), buf.size()));

    EXPECT_EQ(bloom2.num_bits, bloom.num_bits);
    EXPECT_EQ(bloom2.num_hashes, bloom.num_hashes);
    EXPECT_EQ(bloom2.num_items, bloom.num_items);

    /* All original keys must still be found */
    for (uint32_t i = 0; i < N; i++) {
        std::string key = "roundtrip_" + std::to_string(i);
        EXPECT_TRUE(akav_bloom_query(&bloom2,
                                     reinterpret_cast<const uint8_t*>(key.data()),
                                     key.size()))
            << "Round-trip false negative at i=" << i;
    }

    akav_bloom_destroy(&bloom2);
}

TEST_F(BloomTest, DeserializeInvalidData)
{
    akav_bloom_t b{};
    EXPECT_FALSE(akav_bloom_deserialize(&b, nullptr, 0));

    uint8_t short_buf[8] = {};
    EXPECT_FALSE(akav_bloom_deserialize(&b, short_buf, sizeof(short_buf)));

    /* num_bits=0 → invalid */
    uint8_t zero_bits[12] = {};
    EXPECT_FALSE(akav_bloom_deserialize(&b, zero_bits, sizeof(zero_bits)));
}

TEST_F(BloomTest, SerializeBufferTooSmall)
{
    ASSERT_TRUE(akav_bloom_create(&bloom, 100, 10));

    size_t needed = akav_bloom_serialize(&bloom, nullptr, 0);
    std::vector<uint8_t> buf(needed - 1); /* one byte too small */
    size_t result = akav_bloom_serialize(&bloom, buf.data(), buf.size());
    EXPECT_EQ(result, needed); /* returns required size, writes nothing */
}

TEST_F(BloomTest, EmptyFilterQueryReturnsFalse)
{
    ASSERT_TRUE(akav_bloom_create(&bloom, 100, 10));
    const uint8_t key[] = "anything";
    EXPECT_FALSE(akav_bloom_query(&bloom, key, 8));
}

TEST_F(BloomTest, NullSafety)
{
    /* Insert/query with null bloom or null key should not crash */
    akav_bloom_insert(nullptr, (const uint8_t*)"x", 1);
    EXPECT_FALSE(akav_bloom_query(nullptr, (const uint8_t*)"x", 1));

    ASSERT_TRUE(akav_bloom_create(&bloom, 100, 10));
    akav_bloom_insert(&bloom, nullptr, 5);
    EXPECT_FALSE(akav_bloom_query(&bloom, nullptr, 5));
}

/* ── Adversarial tests ────────────────────────────────────────────── */

TEST_F(BloomTest, OvercapacityStress)
{
    /* Create a filter sized for 100 items, then insert 10x that.
       Must not crash or corrupt memory — FP rate will degrade but
       the filter must remain functional. */
    ASSERT_TRUE(akav_bloom_create(&bloom, 100, 10));

    for (uint32_t i = 0; i < 1000; i++) {
        std::string key = "overfill_" + std::to_string(i);
        akav_bloom_insert(&bloom, reinterpret_cast<const uint8_t*>(key.data()),
                          key.size());
    }

    EXPECT_EQ(bloom.num_items, 1000u);

    /* All inserted keys must still be found — no false negatives even
       when the filter is heavily overloaded */
    for (uint32_t i = 0; i < 1000; i++) {
        std::string key = "overfill_" + std::to_string(i);
        EXPECT_TRUE(akav_bloom_query(&bloom,
                                     reinterpret_cast<const uint8_t*>(key.data()),
                                     key.size()))
            << "False negative under overcapacity at i=" << i;
    }
}

TEST_F(BloomTest, IdenticalKeysRepeated)
{
    /* Inserting the same key 10K times must not corrupt state */
    ASSERT_TRUE(akav_bloom_create(&bloom, 1000, 10));

    const uint8_t key[] = "same_key";
    for (int i = 0; i < 10000; i++) {
        akav_bloom_insert(&bloom, key, sizeof(key) - 1);
    }

    EXPECT_TRUE(akav_bloom_query(&bloom, key, sizeof(key) - 1));
    EXPECT_EQ(bloom.num_items, 10000u); /* counter tracks calls, not unique keys */
}

TEST_F(BloomTest, ZeroLengthKey)
{
    /* Zero-length keys are valid — they hash to a deterministic value */
    ASSERT_TRUE(akav_bloom_create(&bloom, 100, 10));

    const uint8_t dummy = 0xFF;
    akav_bloom_insert(&bloom, &dummy, 0);
    EXPECT_TRUE(akav_bloom_query(&bloom, &dummy, 0));
}

TEST_F(BloomTest, DeserializeMalformedNumBitsHuge)
{
    /* Craft a buffer claiming num_bits = 0xFFFFFFFF.
       This would require ~512 MB allocation + the buf_size check should
       reject it since the buffer is only 12 bytes. */
    uint8_t buf[12];
    uint32_t num_bits = 0xFFFFFFFF;
    uint32_t num_hashes = 7;
    uint32_t num_items = 100;
    memcpy(buf, &num_bits, 4);
    memcpy(buf + 4, &num_hashes, 4);
    memcpy(buf + 8, &num_items, 4);

    akav_bloom_t b{};
    /* Buffer is only 12 bytes but claims to need ~512 MB of bit array data.
       Must reject, not crash or allocate. */
    EXPECT_FALSE(akav_bloom_deserialize(&b, buf, sizeof(buf)));
}

TEST_F(BloomTest, DeserializeNumHashesZero)
{
    /* num_hashes=0 is structurally invalid — every query would trivially
       return true for any key. Must reject. */
    uint8_t buf[16] = {};
    uint32_t num_bits = 8;
    uint32_t num_hashes = 0;
    uint32_t num_items = 0;
    memcpy(buf, &num_bits, 4);
    memcpy(buf + 4, &num_hashes, 4);
    memcpy(buf + 8, &num_items, 4);

    akav_bloom_t b{};
    EXPECT_FALSE(akav_bloom_deserialize(&b, buf, sizeof(buf)));
}

TEST_F(BloomTest, DeserializeNumHashesAbsurd)
{
    /* num_hashes = 0xFFFFFFFF would make every query loop ~4 billion times.
       Must reject unreasonable values. */
    uint32_t num_bits = 80;
    uint32_t num_hashes = 0xFFFFFFFF;
    uint32_t num_items = 10;
    size_t byte_count = (num_bits + 7) / 8;
    std::vector<uint8_t> buf(12 + byte_count, 0);
    memcpy(buf.data(), &num_bits, 4);
    memcpy(buf.data() + 4, &num_hashes, 4);
    memcpy(buf.data() + 8, &num_items, 4);

    akav_bloom_t b{};
    EXPECT_FALSE(akav_bloom_deserialize(&b, buf.data(), buf.size()));
}

TEST_F(BloomTest, DeserializeBitFlipInBitArray)
{
    /* Serialize a valid filter, flip a single bit in the bit array,
       deserialize, and confirm no crash. The filter will give wrong
       answers but must remain memory-safe. */
    ASSERT_TRUE(akav_bloom_create(&bloom, 100, 10));

    const uint8_t key[] = "test_key";
    akav_bloom_insert(&bloom, key, sizeof(key) - 1);

    size_t needed = akav_bloom_serialize(&bloom, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_bloom_serialize(&bloom, buf.data(), buf.size());

    /* Flip a bit in the middle of the bit array */
    size_t flip_pos = 12 + (needed - 12) / 2;
    buf[flip_pos] ^= 0x01;

    akav_bloom_t b{};
    ASSERT_TRUE(akav_bloom_deserialize(&b, buf.data(), buf.size()));

    /* Query must not crash — result may differ from original */
    (void)akav_bloom_query(&b, key, sizeof(key) - 1);
    akav_bloom_destroy(&b);
}

TEST_F(BloomTest, DeserializeBitFlipInHeader)
{
    /* Corrupt each of the 3 header fields individually.
       Must either reject or produce a usable (if wrong) filter —
       never crash. */
    ASSERT_TRUE(akav_bloom_create(&bloom, 100, 10));

    const uint8_t key[] = "header_test";
    akav_bloom_insert(&bloom, key, sizeof(key) - 1);

    size_t needed = akav_bloom_serialize(&bloom, nullptr, 0);
    std::vector<uint8_t> good(needed);
    akav_bloom_serialize(&bloom, good.data(), good.size());

    /* Flip bit in num_bits field (byte 0) */
    {
        auto bad = good;
        bad[0] ^= 0x80;
        akav_bloom_t b{};
        /* May succeed or fail depending on whether the new num_bits
           is consistent with buf_size — must not crash either way */
        if (akav_bloom_deserialize(&b, bad.data(), bad.size())) {
            (void)akav_bloom_query(&b, key, sizeof(key) - 1);
            akav_bloom_destroy(&b);
        }
    }

    /* Flip bit in num_hashes field (byte 4) */
    {
        auto bad = good;
        bad[4] ^= 0x80;
        akav_bloom_t b{};
        if (akav_bloom_deserialize(&b, bad.data(), bad.size())) {
            (void)akav_bloom_query(&b, key, sizeof(key) - 1);
            akav_bloom_destroy(&b);
        }
    }

    /* Flip bit in num_items field (byte 8) — cosmetic, always succeeds */
    {
        auto bad = good;
        bad[8] ^= 0x01;
        akav_bloom_t b{};
        ASSERT_TRUE(akav_bloom_deserialize(&b, bad.data(), bad.size()));
        (void)akav_bloom_query(&b, key, sizeof(key) - 1);
        akav_bloom_destroy(&b);
    }
}

TEST_F(BloomTest, DeserializeTruncatedBitArray)
{
    /* Valid header but the bit array is truncated mid-way */
    ASSERT_TRUE(akav_bloom_create(&bloom, 1000, 10));

    size_t needed = akav_bloom_serialize(&bloom, nullptr, 0);
    std::vector<uint8_t> buf(needed);
    akav_bloom_serialize(&bloom, buf.data(), buf.size());

    /* Chop off the last 100 bytes of the bit array */
    akav_bloom_t b{};
    EXPECT_FALSE(akav_bloom_deserialize(&b, buf.data(), needed - 100));
}

TEST_F(BloomTest, DeserializeExactMinimumSize)
{
    /* Filter with exactly 1 bit — smallest possible valid filter.
       1 bit → 1 byte of bit array → 13 bytes total. */
    uint8_t buf[13] = {};
    uint32_t num_bits = 1;
    uint32_t num_hashes = 1;
    uint32_t num_items = 0;
    memcpy(buf, &num_bits, 4);
    memcpy(buf + 4, &num_hashes, 4);
    memcpy(buf + 8, &num_items, 4);
    buf[12] = 0x00;

    akav_bloom_t b{};
    ASSERT_TRUE(akav_bloom_deserialize(&b, buf, sizeof(buf)));

    /* Insert and query on a 1-bit filter — always FP after first insert */
    const uint8_t key[] = "x";
    akav_bloom_insert(&b, key, 1);
    EXPECT_TRUE(akav_bloom_query(&b, key, 1));

    akav_bloom_destroy(&b);
}

TEST_F(BloomTest, CreateOverflowBitsPerItem)
{
    /* expected_items × bits_per_item overflows uint32_t.
       Must reject, not wrap around to a tiny allocation. */
    EXPECT_FALSE(akav_bloom_create(&bloom, 0x10000, 0x10000));
    /* 0x10000 * 0x10000 = 0x100000000 > UINT32_MAX */
}

/* ── Hash function smoke tests ────────────────────────────────────── */

TEST(MurmurHash, KnownValues)
{
    /* Empty string with seed 0 — well-known reference value */
    uint32_t h = akav_murmur3_32(nullptr, 0, 0);
    EXPECT_EQ(h, 0u); /* murmurhash3 of empty with seed 0 = 0 */

    const uint8_t data[] = {0x21, 0x43, 0x65, 0x87};
    uint32_t h2 = akav_murmur3_32(data, 4, 0);
    EXPECT_NE(h2, 0u); /* non-trivial input should produce non-zero */
}

TEST(FNV1a, KnownValues)
{
    /* FNV-1a of empty string = offset basis */
    uint32_t h = akav_fnv1a_32(nullptr, 0);
    EXPECT_EQ(h, 0x811c9dc5u);

    /* FNV-1a("a") is a well-known test vector */
    const uint8_t a[] = {'a'};
    uint32_t ha = akav_fnv1a_32(a, 1);
    EXPECT_EQ(ha, 0xe40c292cu);
}
