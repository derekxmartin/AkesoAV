/* test_yara_scanner.cpp -- Unit tests for YARA rule scanner (P9-T1). */

#include <gtest/gtest.h>
#include "signatures/yara_scanner.h"
#include "scanner.h"
#include "database/sigdb.h"
#include <cstring>
#include <cstdlib>
#include <vector>

/* ── YARA global init/cleanup fixture ───────────────────────────── */

class YaraScannerTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        ASSERT_TRUE(akav_yara_global_init());
    }
    static void TearDownTestSuite() {
        akav_yara_global_cleanup();
    }

    void SetUp() override {
        akav_yara_scanner_init(&scanner_);
    }
    void TearDown() override {
        akav_yara_scanner_destroy(&scanner_);
    }

    akav_yara_scanner_t scanner_{};
};

/* ── Basic lifecycle ─────────────────────────────────────────────── */

TEST_F(YaraScannerTest, InitState) {
    EXPECT_FALSE(scanner_.loaded);
    EXPECT_EQ(scanner_.rule_count, 0u);
    EXPECT_EQ(scanner_.rules, nullptr);
}

TEST_F(YaraScannerTest, DestroyEmptyIsNoOp) {
    akav_yara_scanner_destroy(&scanner_);
    EXPECT_FALSE(scanner_.loaded);
}

/* ── Rule compilation ────────────────────────────────────────────── */

TEST_F(YaraScannerTest, CompileSimpleRule) {
    const char* rule_src =
        "rule test_pattern {\n"
        "  strings:\n"
        "    $s1 = \"EVIL_PAYLOAD\"\n"
        "  condition:\n"
        "    $s1\n"
        "}\n";

    ASSERT_TRUE(akav_yara_load_source(&scanner_, rule_src, strlen(rule_src)));
    EXPECT_TRUE(scanner_.loaded);
    EXPECT_EQ(scanner_.rule_count, 1u);
}

TEST_F(YaraScannerTest, CompileMultipleRules) {
    const char* rule_src =
        "rule rule_a {\n"
        "  strings:\n"
        "    $a = \"AAA\"\n"
        "  condition:\n"
        "    $a\n"
        "}\n"
        "rule rule_b {\n"
        "  strings:\n"
        "    $b = \"BBB\"\n"
        "  condition:\n"
        "    $b\n"
        "}\n";

    ASSERT_TRUE(akav_yara_load_source(&scanner_, rule_src, strlen(rule_src)));
    EXPECT_TRUE(scanner_.loaded);
    EXPECT_EQ(scanner_.rule_count, 2u);
}

TEST_F(YaraScannerTest, CompileInvalidRuleFails) {
    const char* bad_src = "this is not valid yara syntax";
    EXPECT_FALSE(akav_yara_load_source(&scanner_, bad_src, strlen(bad_src)));
    EXPECT_FALSE(scanner_.loaded);
    EXPECT_NE(scanner_.compile_error[0], '\0');
}

TEST_F(YaraScannerTest, CompileEmptySourceFails) {
    EXPECT_FALSE(akav_yara_load_source(&scanner_, "", 0));
    EXPECT_FALSE(scanner_.loaded);
}

TEST_F(YaraScannerTest, NullScannerReturnsFailure) {
    EXPECT_FALSE(akav_yara_load_source(nullptr, "rule x { condition: true }", 26));
}

/* ── Scanning ────────────────────────────────────────────────────── */

TEST_F(YaraScannerTest, ScanMatchesPattern) {
    const char* rule_src =
        "rule detect_evil {\n"
        "  strings:\n"
        "    $payload = \"EVIL_MARKER_STRING\"\n"
        "  condition:\n"
        "    $payload\n"
        "}\n";
    ASSERT_TRUE(akav_yara_load_source(&scanner_, rule_src, strlen(rule_src)));

    const char* test_data = "some prefix EVIL_MARKER_STRING some suffix";
    akav_yara_match_t match;
    bool found = akav_yara_scan_buffer(&scanner_,
        (const uint8_t*)test_data, strlen(test_data), &match);

    EXPECT_TRUE(found);
    EXPECT_TRUE(match.matched);
    EXPECT_STREQ(match.rule_name, "detect_evil");
    EXPECT_EQ(match.match_count, 1u);
}

TEST_F(YaraScannerTest, ScanNoMatch) {
    const char* rule_src =
        "rule detect_evil {\n"
        "  strings:\n"
        "    $payload = \"EVIL_MARKER_STRING\"\n"
        "  condition:\n"
        "    $payload\n"
        "}\n";
    ASSERT_TRUE(akav_yara_load_source(&scanner_, rule_src, strlen(rule_src)));

    const char* clean_data = "this is a perfectly clean file with no markers";
    akav_yara_match_t match;
    bool found = akav_yara_scan_buffer(&scanner_,
        (const uint8_t*)clean_data, strlen(clean_data), &match);

    EXPECT_FALSE(found);
    EXPECT_FALSE(match.matched);
    EXPECT_EQ(match.match_count, 0u);
}

TEST_F(YaraScannerTest, ScanHexPattern) {
    const char* rule_src =
        "rule hex_detect {\n"
        "  strings:\n"
        "    $h = { 4D 5A 90 00 }\n"
        "  condition:\n"
        "    $h\n"
        "}\n";
    ASSERT_TRUE(akav_yara_load_source(&scanner_, rule_src, strlen(rule_src)));

    uint8_t pe_stub[] = { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00 };
    akav_yara_match_t match;
    EXPECT_TRUE(akav_yara_scan_buffer(&scanner_, pe_stub, sizeof(pe_stub), &match));
    EXPECT_STREQ(match.rule_name, "hex_detect");
}

TEST_F(YaraScannerTest, ScanMultipleRulesOneMatch) {
    const char* rule_src =
        "rule rule_a {\n"
        "  strings: $a = \"PATTERN_A\"\n"
        "  condition: $a\n"
        "}\n"
        "rule rule_b {\n"
        "  strings: $b = \"PATTERN_B\"\n"
        "  condition: $b\n"
        "}\n";
    ASSERT_TRUE(akav_yara_load_source(&scanner_, rule_src, strlen(rule_src)));

    const char* data = "contains only PATTERN_B here";
    akav_yara_match_t match;
    EXPECT_TRUE(akav_yara_scan_buffer(&scanner_,
        (const uint8_t*)data, strlen(data), &match));
    EXPECT_STREQ(match.rule_name, "rule_b");
    EXPECT_EQ(match.match_count, 1u);
}

TEST_F(YaraScannerTest, ScanMultipleRulesBothMatch) {
    const char* rule_src =
        "rule rule_a {\n"
        "  strings: $a = \"COMMON\"\n"
        "  condition: $a\n"
        "}\n"
        "rule rule_b {\n"
        "  strings: $b = \"COMMON\"\n"
        "  condition: $b\n"
        "}\n";
    ASSERT_TRUE(akav_yara_load_source(&scanner_, rule_src, strlen(rule_src)));

    const char* data = "COMMON data here";
    akav_yara_match_t match;
    EXPECT_TRUE(akav_yara_scan_buffer(&scanner_,
        (const uint8_t*)data, strlen(data), &match));
    EXPECT_TRUE(match.matched);
    EXPECT_EQ(match.match_count, 2u);
}

TEST_F(YaraScannerTest, ScanWithoutLoadedRulesFails) {
    const uint8_t data[] = { 0x00 };
    akav_yara_match_t match;
    EXPECT_FALSE(akav_yara_scan_buffer(&scanner_, data, sizeof(data), &match));
}

/* ── Hot reload ──────────────────────────────────────────────────── */

TEST_F(YaraScannerTest, HotReloadReplacesRules) {
    /* Load first rule set */
    const char* rules_v1 =
        "rule v1_rule {\n"
        "  strings: $s = \"V1_MARKER\"\n"
        "  condition: $s\n"
        "}\n";
    ASSERT_TRUE(akav_yara_load_source(&scanner_, rules_v1, strlen(rules_v1)));
    EXPECT_EQ(scanner_.rule_count, 1u);

    /* Reload with different rules */
    const char* rules_v2 =
        "rule v2_rule_a {\n"
        "  strings: $s = \"V2_MARKER\"\n"
        "  condition: $s\n"
        "}\n"
        "rule v2_rule_b {\n"
        "  strings: $s = \"ANOTHER_V2\"\n"
        "  condition: $s\n"
        "}\n";
    ASSERT_TRUE(akav_yara_load_source(&scanner_, rules_v2, strlen(rules_v2)));
    EXPECT_EQ(scanner_.rule_count, 2u);

    /* Old rule should no longer match */
    const char* v1_data = "V1_MARKER here";
    akav_yara_match_t match;
    EXPECT_FALSE(akav_yara_scan_buffer(&scanner_,
        (const uint8_t*)v1_data, strlen(v1_data), &match));

    /* New rule should match */
    const char* v2_data = "V2_MARKER here";
    EXPECT_TRUE(akav_yara_scan_buffer(&scanner_,
        (const uint8_t*)v2_data, strlen(v2_data), &match));
    EXPECT_STREQ(match.rule_name, "v2_rule_a");
}

/* ── Section loading ─────────────────────────────────────────────── */

TEST_F(YaraScannerTest, LoadFromSectionBlob) {
    const char* rule_src =
        "rule section_test {\n"
        "  strings: $s = \"SECTION_MARKER\"\n"
        "  condition: $s\n"
        "}\n";

    /* Simulate .akavdb section: raw UTF-8 rule text */
    ASSERT_TRUE(akav_yara_load_section(&scanner_,
        (const uint8_t*)rule_src, strlen(rule_src)));
    EXPECT_TRUE(scanner_.loaded);
    EXPECT_EQ(scanner_.rule_count, 1u);

    const char* data = "prefix SECTION_MARKER suffix";
    akav_yara_match_t match;
    EXPECT_TRUE(akav_yara_scan_buffer(&scanner_,
        (const uint8_t*)data, strlen(data), &match));
    EXPECT_STREQ(match.rule_name, "section_test");
}

/* ── Condition-only rules ────────────────────────────────────────── */

TEST_F(YaraScannerTest, ConditionOnlyRule) {
    /* Rule that matches based on file size */
    const char* rule_src =
        "rule small_file {\n"
        "  condition:\n"
        "    filesize < 100\n"
        "}\n";
    ASSERT_TRUE(akav_yara_load_source(&scanner_, rule_src, strlen(rule_src)));

    uint8_t small_data[10] = {0};
    akav_yara_match_t match;
    EXPECT_TRUE(akav_yara_scan_buffer(&scanner_, small_data, sizeof(small_data), &match));
    EXPECT_STREQ(match.rule_name, "small_file");
}

/* ── Integration with scanner pipeline (akavdb format) ───────────── */

/* Helper: build a minimal .akavdb with only a YARA section + string table */
static std::vector<uint8_t> build_yara_akavdb(const char* yara_source) {
    std::vector<uint8_t> db;
    uint32_t yara_data_len = (uint32_t)strlen(yara_source);

    /* Header: 280 bytes */
    db.resize(0x0118, 0);
    uint32_t magic = 0x56414B41;
    uint32_t version = 1;
    uint32_t sig_count = 1;
    int64_t created = 0;
    uint32_t section_count = 1;  /* just YARA section */

    memcpy(&db[0], &magic, 4);
    memcpy(&db[4], &version, 4);
    memcpy(&db[8], &sig_count, 4);
    memcpy(&db[12], &created, 8);
    memcpy(&db[20], &section_count, 4);

    /* Section offset table: 1 entry × 16 bytes, starts right after header */
    uint32_t sec_type = 7;  /* AKAV_SECTION_YARA */
    uint32_t data_offset = 0x0118 + 16;  /* after header + 1 section entry */
    uint32_t data_size = yara_data_len;
    uint32_t entry_count = 1;

    std::vector<uint8_t> sec_entry(16);
    memcpy(&sec_entry[0], &sec_type, 4);
    memcpy(&sec_entry[4], &data_offset, 4);
    memcpy(&sec_entry[8], &data_size, 4);
    memcpy(&sec_entry[12], &entry_count, 4);
    db.insert(db.end(), sec_entry.begin(), sec_entry.end());

    /* Section data: YARA source */
    db.insert(db.end(), (const uint8_t*)yara_source,
              (const uint8_t*)yara_source + yara_data_len);

    return db;
}

TEST_F(YaraScannerTest, PipelineIntegrationFromAkavdb) {
    const char* rule_src =
        "rule pipeline_test {\n"
        "  strings: $s = \"PIPELINE_MARKER\"\n"
        "  condition: $s\n"
        "}\n";

    auto db_data = build_yara_akavdb(rule_src);

    akav_scanner_t scanner;
    akav_scanner_init(&scanner);

    akav_error_t err = akav_scanner_load_memory(&scanner,
        db_data.data(), db_data.size());
    ASSERT_EQ(err, AKAV_OK);
    EXPECT_TRUE(scanner.yara_loaded);

    /* Scan a buffer containing the marker */
    akav_scan_result_t result;
    memset(&result, 0, sizeof(result));
    const char* data = "some data PIPELINE_MARKER more data";
    akav_scanner_scan_buffer(&scanner, (const uint8_t*)data, strlen(data), &result);

    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.scanner_id, "yara");
    EXPECT_STREQ(result.malware_name, "pipeline_test");

    /* Clean buffer should not match */
    akav_scan_result_t clean_result;
    memset(&clean_result, 0, sizeof(clean_result));
    const char* clean = "totally clean data here";
    akav_scanner_scan_buffer(&scanner, (const uint8_t*)clean, strlen(clean), &clean_result);
    EXPECT_EQ(clean_result.found, 0);

    akav_scanner_destroy(&scanner);
}
