#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <cstring>

extern "C" {
#include "signatures/crc_matcher.h"
}

/* ── CRC32 computation tests ─────────────────────────────────────── */

TEST(CRC32, IEEEEmptyString)
{
    /* CRC32 of empty input = 0x00000000 */
    uint32_t crc = akav_crc32_ieee(nullptr, 0);
    EXPECT_EQ(crc, 0x00000000u);
}

TEST(CRC32, IEEEKnownVector)
{
    /* CRC32("123456789") = 0xCBF43926 — the canonical check value */
    const uint8_t data[] = "123456789";
    uint32_t crc = akav_crc32_ieee(data, 9);
    EXPECT_EQ(crc, 0xCBF43926u);
}

TEST(CRC32, IEEEHelloWorld)
{
    const uint8_t data[] = "Hello, World!";
    uint32_t crc = akav_crc32_ieee(data, 13);
    /* Known value for "Hello, World!" */
    EXPECT_EQ(crc, 0xEC4AC3D0u);
}

TEST(CRC32, CustomDiffersFromIEEE)
{
    const uint8_t data[] = "123456789";
    uint32_t ieee_crc = akav_crc32_ieee(data, 9);
    uint32_t custom_crc = akav_crc32_custom(data, 9);
    EXPECT_NE(ieee_crc, custom_crc);
}

TEST(CRC32, CustomKnownVector)
{
    /* CRC32-C("123456789") = 0xE3069283 — Castagnoli check value */
    const uint8_t data[] = "123456789";
    uint32_t crc = akav_crc32_custom(data, 9);
    EXPECT_EQ(crc, 0xE3069283u);
}

TEST(CRC32, SingleByte)
{
    uint8_t byte = 0x00;
    uint32_t crc = akav_crc32_ieee(&byte, 1);
    EXPECT_NE(crc, 0u); /* non-trivial for any input */
}

TEST(CRC32, NullDataZeroLen)
{
    /* null pointer with zero length should not crash */
    uint32_t crc = akav_crc32_ieee(nullptr, 0);
    EXPECT_EQ(crc, 0x00000000u);

    crc = akav_crc32_custom(nullptr, 0);
    EXPECT_EQ(crc, 0x00000000u);
}

/* ── Matcher fixture ──────────────────────────────────────────────── */

class CRCMatcherTest : public ::testing::Test {
protected:
    akav_crc_matcher_t matcher{};

    void SetUp() override
    {
        akav_crc_matcher_init(&matcher);
    }

    void TearDown() override
    {
        akav_crc_matcher_destroy(&matcher);
    }
};

TEST_F(CRCMatcherTest, InitDestroy)
{
    EXPECT_EQ(matcher.entries, nullptr);
    EXPECT_EQ(matcher.count, 0u);
}

TEST_F(CRCMatcherTest, DestroyNull)
{
    akav_crc_matcher_destroy(nullptr);
}

/* ── Whole-file region ────────────────────────────────────────────── */

TEST_F(CRCMatcherTest, WholeFileMatch)
{
    const uint8_t data[] = "123456789";
    uint32_t expected = akav_crc32_ieee(data, 9);

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_WHOLE;
    entry.expected_crc = expected;
    entry.name_index = 42;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 9,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(match.name_index, 42u);
}

TEST_F(CRCMatcherTest, WholeFileMismatch)
{
    const uint8_t data[] = "123456789";

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_WHOLE;
    entry.expected_crc = 0xDEADBEEF; /* wrong CRC */
    entry.name_index = 1;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 9,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 0u);
}

/* ── First-N / Last-N regions ─────────────────────────────────────── */

TEST_F(CRCMatcherTest, FirstNRegion)
{
    const uint8_t data[] = "ABCDEFGHIJ"; /* 10 bytes */
    uint32_t first4_crc = akav_crc32_ieee(data, 4); /* CRC of "ABCD" */

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_FIRST_N;
    entry.offset = 4;
    entry.expected_crc = first4_crc;
    entry.name_index = 10;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 10,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(match.name_index, 10u);
}

TEST_F(CRCMatcherTest, LastNRegion)
{
    const uint8_t data[] = "ABCDEFGHIJ"; /* 10 bytes */
    uint32_t last3_crc = akav_crc32_ieee(data + 7, 3); /* CRC of "HIJ" */

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_LAST_N;
    entry.offset = 3;
    entry.expected_crc = last3_crc;
    entry.name_index = 20;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 10,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(match.name_index, 20u);
}

TEST_F(CRCMatcherTest, FirstNExceedsBuffer)
{
    const uint8_t data[] = "AB";

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_FIRST_N;
    entry.offset = 100; /* way past buffer */
    entry.expected_crc = 0;
    entry.name_index = 0;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 2,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 0u); /* skipped, not crashed */
}

TEST_F(CRCMatcherTest, LastNExceedsBuffer)
{
    const uint8_t data[] = "AB";

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_LAST_N;
    entry.offset = 100;
    entry.expected_crc = 0;
    entry.name_index = 0;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 2,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 0u);
}

/* ── PE section region ────────────────────────────────────────────── */

TEST_F(CRCMatcherTest, PESectionRegion)
{
    /* Simulate a buffer with a PE section at offset 0x200, size 0x100 */
    std::vector<uint8_t> data(0x400, 0);
    /* Fill the "section" with recognizable data */
    for (size_t i = 0x200; i < 0x300; i++) {
        data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    uint32_t section_crc = akav_crc32_ieee(data.data() + 0x200, 0x100);

    akav_pe_section_info_t sections[2] = {};
    sections[0].raw_offset = 0x100;
    sections[0].raw_size = 0x100;
    sections[1].raw_offset = 0x200;
    sections[1].raw_size = 0x100;

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_PE_SECTION;
    entry.offset = 1; /* section index 1 */
    entry.expected_crc = section_crc;
    entry.name_index = 55;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data.data(), data.size(),
                                            sections, 2, &match, 1);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(match.name_index, 55u);
}

TEST_F(CRCMatcherTest, PESectionOutOfRange)
{
    std::vector<uint8_t> data(256, 0xAA);

    akav_pe_section_info_t sections[1] = {};
    sections[0].raw_offset = 0;
    sections[0].raw_size = 256;

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_PE_SECTION;
    entry.offset = 5; /* section index 5 but only 1 section exists */
    entry.expected_crc = 0;
    entry.name_index = 0;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data.data(), data.size(),
                                            sections, 1, &match, 1);
    EXPECT_EQ(count, 0u);
}

TEST_F(CRCMatcherTest, PESectionNullSections)
{
    std::vector<uint8_t> data(256, 0xAA);

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_PE_SECTION;
    entry.offset = 0;
    entry.expected_crc = 0;
    entry.name_index = 0;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data.data(), data.size(),
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 0u); /* skipped because no PE sections provided */
}

/* ── Custom polynomial matcher ────────────────────────────────────── */

TEST_F(CRCMatcherTest, CustomPolyMatch)
{
    const uint8_t data[] = "123456789";
    uint32_t custom_crc = akav_crc32_custom(data, 9);

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_WHOLE;
    entry.expected_crc = custom_crc;
    entry.name_index = 77;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, true));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 9,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(match.name_index, 77u);
}

TEST_F(CRCMatcherTest, IEEECrcDoesNotMatchCustomEntry)
{
    /* An entry built with custom poly should NOT match when scanned
       with IEEE (and vice versa) */
    const uint8_t data[] = "123456789";
    uint32_t ieee_crc = akav_crc32_ieee(data, 9);

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_WHOLE;
    entry.expected_crc = ieee_crc; /* IEEE CRC stored */
    entry.name_index = 0;

    /* But matcher uses custom poly */
    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, true));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 9,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 0u); /* should not match */
}

/* ── Multiple entries / multiple matches ──────────────────────────── */

TEST_F(CRCMatcherTest, MultipleEntriesMultipleMatches)
{
    const uint8_t data[] = "ABCDEFGHIJ"; /* 10 bytes */
    uint32_t whole_crc = akav_crc32_ieee(data, 10);
    uint32_t first5_crc = akav_crc32_ieee(data, 5);
    uint32_t last5_crc = akav_crc32_ieee(data + 5, 5);

    akav_crc_entry_t entries[4] = {};
    /* Entry 0: whole file — matches */
    entries[0].region_type = AKAV_CRC_REGION_WHOLE;
    entries[0].expected_crc = whole_crc;
    entries[0].name_index = 1;

    /* Entry 1: first 5 — matches */
    entries[1].region_type = AKAV_CRC_REGION_FIRST_N;
    entries[1].offset = 5;
    entries[1].expected_crc = first5_crc;
    entries[1].name_index = 2;

    /* Entry 2: last 5 — matches */
    entries[2].region_type = AKAV_CRC_REGION_LAST_N;
    entries[2].offset = 5;
    entries[2].expected_crc = last5_crc;
    entries[2].name_index = 3;

    /* Entry 3: whole file — wrong CRC, no match */
    entries[3].region_type = AKAV_CRC_REGION_WHOLE;
    entries[3].expected_crc = 0xDEADBEEF;
    entries[3].name_index = 4;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, entries, 4, false));

    akav_crc_match_t matches[4] = {};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 10,
                                            nullptr, 0, matches, 4);
    EXPECT_EQ(count, 3u);
    EXPECT_EQ(matches[0].name_index, 1u);
    EXPECT_EQ(matches[1].name_index, 2u);
    EXPECT_EQ(matches[2].name_index, 3u);
}

TEST_F(CRCMatcherTest, OutputBufferTooSmall)
{
    const uint8_t data[] = "ABCDEFGHIJ";
    uint32_t whole_crc = akav_crc32_ieee(data, 10);
    uint32_t first5_crc = akav_crc32_ieee(data, 5);

    akav_crc_entry_t entries[2] = {};
    entries[0].region_type = AKAV_CRC_REGION_WHOLE;
    entries[0].expected_crc = whole_crc;
    entries[0].name_index = 1;
    entries[1].region_type = AKAV_CRC_REGION_FIRST_N;
    entries[1].offset = 5;
    entries[1].expected_crc = first5_crc;
    entries[1].name_index = 2;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, entries, 2, false));

    /* Output buffer holds only 1 match but 2 match */
    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 10,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 2u); /* total matches returned */
    EXPECT_EQ(match.name_index, 1u); /* only first written */
}

TEST_F(CRCMatcherTest, CountOnlyNullOutput)
{
    const uint8_t data[] = "123456789";
    uint32_t crc = akav_crc32_ieee(data, 9);

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_WHOLE;
    entry.expected_crc = crc;
    entry.name_index = 0;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    uint32_t count = akav_crc_matcher_scan(&matcher, data, 9,
                                            nullptr, 0, nullptr, 0);
    EXPECT_EQ(count, 1u);
}

/* ── Length check ─────────────────────────────────────────────────── */

TEST_F(CRCMatcherTest, LengthCheckEnforced)
{
    const uint8_t data[] = "ABCDEFGHIJ"; /* 10 bytes */
    uint32_t crc = akav_crc32_ieee(data, 10);

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_WHOLE;
    entry.expected_crc = crc;
    entry.length = 20; /* expect 20 bytes, but buffer is 10 */
    entry.name_index = 0;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 10,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 0u); /* length mismatch → skip */
}

TEST_F(CRCMatcherTest, LengthCheckZeroIgnored)
{
    const uint8_t data[] = "123456789";
    uint32_t crc = akav_crc32_ieee(data, 9);

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_WHOLE;
    entry.expected_crc = crc;
    entry.length = 0; /* 0 means don't check length */
    entry.name_index = 99;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 9,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 1u);
}

/* ── Edge / adversarial ───────────────────────────────────────────── */

TEST_F(CRCMatcherTest, EmptyMatcher)
{
    const uint8_t data[] = "test";
    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 4,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 0u);
}

TEST_F(CRCMatcherTest, NullData)
{
    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_WHOLE;
    entry.expected_crc = 0;
    entry.name_index = 0;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    uint32_t count = akav_crc_matcher_scan(&matcher, nullptr, 0,
                                            nullptr, 0, nullptr, 0);
    EXPECT_EQ(count, 0u);
}

TEST_F(CRCMatcherTest, InvalidRegionType)
{
    const uint8_t data[] = "test";

    akav_crc_entry_t entry{};
    entry.region_type = 0xFF; /* invalid */
    entry.expected_crc = 0;
    entry.name_index = 0;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 4,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 0u); /* invalid region skipped */
}

TEST_F(CRCMatcherTest, PESectionTruncatedRawData)
{
    /* Section claims raw_size=0x200 but buffer only has 0x50 past offset */
    std::vector<uint8_t> data(0x100, 0xCC);

    akav_pe_section_info_t sec{};
    sec.raw_offset = 0xB0;
    sec.raw_size = 0x200; /* extends past buffer */

    /* CRC of the truncated region (0xB0 to end = 0x50 bytes) */
    uint32_t crc = akav_crc32_ieee(data.data() + 0xB0, 0x50);

    akav_crc_entry_t entry{};
    entry.region_type = AKAV_CRC_REGION_PE_SECTION;
    entry.offset = 0;
    entry.length = 0; /* don't enforce length */
    entry.expected_crc = crc;
    entry.name_index = 33;

    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &entry, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data.data(), data.size(),
                                            &sec, 1, &match, 1);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(match.name_index, 33u);
}

TEST_F(CRCMatcherTest, RebuildReplacesOldEntries)
{
    const uint8_t data[] = "test";
    uint32_t crc = akav_crc32_ieee(data, 4);

    akav_crc_entry_t e1{};
    e1.region_type = AKAV_CRC_REGION_WHOLE;
    e1.expected_crc = 0xDEADBEEF;
    e1.name_index = 1;
    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &e1, 1, false));

    /* Rebuild with correct CRC */
    akav_crc_entry_t e2{};
    e2.region_type = AKAV_CRC_REGION_WHOLE;
    e2.expected_crc = crc;
    e2.name_index = 2;
    ASSERT_TRUE(akav_crc_matcher_build(&matcher, &e2, 1, false));

    akav_crc_match_t match{};
    uint32_t count = akav_crc_matcher_scan(&matcher, data, 4,
                                            nullptr, 0, &match, 1);
    EXPECT_EQ(count, 1u);
    EXPECT_EQ(match.name_index, 2u);
}
