#include <gtest/gtest.h>
#include "scanner.h"
#include "signatures/hash_matcher.h"
#include "signatures/aho_corasick.h"
#include "database/sigdb.h"
#include "engine_internal.h"

#include <cstring>
#include <vector>
#include <string>

/* ── EICAR test string ───────────────────────────────────────────── */

static const uint8_t EICAR[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
    "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
static const size_t EICAR_LEN = 68;

/* ── Helper: Build a minimal .akavdb in memory ───────────────────── */

class AkavDbBuilder {
public:
    struct SectionBlob {
        uint32_t type;
        std::vector<uint8_t> data;
        uint32_t entry_count;
    };

    void add_string(const std::string& s) {
        string_offsets_[s] = (uint32_t)string_table_.size();
        string_table_.insert(string_table_.end(), s.begin(), s.end());
        string_table_.push_back(0);
    }

    uint32_t string_offset(const std::string& s) const {
        auto it = string_offsets_.find(s);
        return it != string_offsets_.end() ? it->second : 0;
    }

    void add_section(uint32_t type, const std::vector<uint8_t>& data, uint32_t entries) {
        sections_.push_back({type, data, entries});
    }

    /* Build the final .akavdb binary */
    std::vector<uint8_t> build() {
        /* Add string table as last section */
        if (!string_table_.empty()) {
            sections_.push_back({0xFF, string_table_, 0});
        }

        uint32_t section_count = (uint32_t)sections_.size();
        uint32_t offset_table_size = section_count * 16;
        uint32_t data_start = 0x0118 + offset_table_size;

        /* Calculate total signature count */
        uint32_t total_sigs = 0;
        for (auto& s : sections_) {
            if (s.type != 0xFF) total_sigs += s.entry_count;
        }

        /* Build header (280 bytes) */
        std::vector<uint8_t> db(0x0118, 0);
        /* magic */
        uint32_t magic = 0x56414B41;
        memcpy(db.data() + 0, &magic, 4);
        /* version */
        uint32_t version = 1;
        memcpy(db.data() + 4, &version, 4);
        /* signature_count */
        memcpy(db.data() + 8, &total_sigs, 4);
        /* created_at */
        int64_t created = 1700000000;
        memcpy(db.data() + 12, &created, 8);
        /* section_count */
        memcpy(db.data() + 20, &section_count, 4);

        /* Build offset table and section data */
        std::vector<uint8_t> offset_table;
        std::vector<uint8_t> section_data;
        uint32_t current_offset = data_start;

        for (auto& sec : sections_) {
            auto push_u32 = [&](uint32_t v) {
                uint8_t buf[4];
                memcpy(buf, &v, 4);
                offset_table.insert(offset_table.end(), buf, buf + 4);
            };
            push_u32(sec.type);
            push_u32(current_offset);
            push_u32((uint32_t)sec.data.size());
            push_u32(sec.entry_count);
            section_data.insert(section_data.end(), sec.data.begin(), sec.data.end());
            current_offset += (uint32_t)sec.data.size();
        }

        db.insert(db.end(), offset_table.begin(), offset_table.end());
        db.insert(db.end(), section_data.begin(), section_data.end());
        return db;
    }

private:
    std::vector<SectionBlob> sections_;
    std::vector<uint8_t> string_table_;
    std::map<std::string, uint32_t> string_offsets_;
};

/* ── Helper: Build MD5 section data ──────────────────────────────── */

static std::vector<uint8_t> build_md5_entry(const uint8_t* data, size_t len,
                                              uint32_t name_index)
{
    uint8_t md5[16];
    akav_hash_md5(data, len, md5);

    std::vector<uint8_t> entry(20);
    memcpy(entry.data(), md5, 16);
    memcpy(entry.data() + 16, &name_index, 4);
    return entry;
}

/* ── Helper: Build SHA256 section data ───────────────────────────── */

static std::vector<uint8_t> build_sha256_entry(const uint8_t* data, size_t len,
                                                 uint32_t name_index)
{
    uint8_t sha[32];
    akav_hash_sha256(data, len, sha);

    std::vector<uint8_t> entry(36);
    memcpy(entry.data(), sha, 32);
    memcpy(entry.data() + 32, &name_index, 4);
    return entry;
}

/* ── Helper: Build Aho-Corasick section from patterns ────────────── */

static std::vector<uint8_t> build_ac_section(
    const std::vector<std::pair<std::vector<uint8_t>, uint32_t>>& patterns)
{
    akav_ac_t* ac = akav_ac_create();
    for (auto& [pat, id] : patterns) {
        akav_ac_add_pattern(ac, pat.data(), (uint32_t)pat.size(), id);
    }
    akav_ac_finalize(ac);

    size_t sz = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> blob(sz);
    akav_ac_serialize(ac, blob.data(), blob.size());
    akav_ac_destroy(ac);
    return blob;
}

/* ══════════════════════════════════════════════════════════════════ */
/* Tests                                                             */
/* ══════════════════════════════════════════════════════════════════ */

#include <map>

class ScanPipelineTest : public ::testing::Test {
protected:
    akav_scanner_t scanner_{};

    void SetUp() override {
        akav_scanner_init(&scanner_);
    }

    void TearDown() override {
        akav_scanner_destroy(&scanner_);
    }
};

/* ── Basic: empty scanner scans clean ────────────────────────────── */

TEST_F(ScanPipelineTest, EmptyScannerReturnsClean) {
    akav_scan_result_t result{};
    uint8_t data[] = "hello world";
    akav_scanner_scan_buffer(&scanner_, data, sizeof(data) - 1, &result);
    EXPECT_EQ(result.found, 0);
}

/* ── MD5 detection ───────────────────────────────────────────────── */

TEST_F(ScanPipelineTest, MD5Detection) {
    AkavDbBuilder builder;
    builder.add_string("Malware.MD5Test");

    auto md5_entry = build_md5_entry(EICAR, EICAR_LEN,
                                      builder.string_offset("Malware.MD5Test"));
    builder.add_section(1 /* MD5 */, md5_entry, 1);

    auto db = builder.build();
    ASSERT_EQ(akav_scanner_load_memory(&scanner_, db.data(), db.size()), AKAV_OK);

    akav_scan_result_t result{};
    akav_scanner_scan_buffer(&scanner_, EICAR, EICAR_LEN, &result);
    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.malware_name, "Malware.MD5Test");
    EXPECT_STREQ(result.scanner_id, "md5");
}

/* ── SHA256 detection ────────────────────────────────────────────── */

TEST_F(ScanPipelineTest, SHA256Detection) {
    AkavDbBuilder builder;
    builder.add_string("Malware.SHA256Test");

    auto sha_entry = build_sha256_entry(EICAR, EICAR_LEN,
                                          builder.string_offset("Malware.SHA256Test"));
    builder.add_section(2 /* SHA256 */, sha_entry, 1);

    auto db = builder.build();
    ASSERT_EQ(akav_scanner_load_memory(&scanner_, db.data(), db.size()), AKAV_OK);

    akav_scan_result_t result{};
    akav_scanner_scan_buffer(&scanner_, EICAR, EICAR_LEN, &result);
    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.malware_name, "Malware.SHA256Test");
    EXPECT_STREQ(result.scanner_id, "sha256");
}

/* ── CRC32 detection ─────────────────────────────────────────────── */

TEST_F(ScanPipelineTest, CRC32Detection) {
    AkavDbBuilder builder;
    builder.add_string("Malware.CRC32Test");

    /* Compute CRC32 of EICAR for the signature */
    uint32_t crc = akav_crc32_ieee(EICAR, EICAR_LEN);
    uint32_t name_idx = builder.string_offset("Malware.CRC32Test");

    /* Packed CRC entry: region_type(1) + offset(4) + length(4) + crc(4) + name_index(4) = 17 bytes */
    std::vector<uint8_t> crc_entry(17, 0);
    crc_entry[0] = 0; /* WHOLE */
    uint32_t zero = 0;
    memcpy(crc_entry.data() + 1, &zero, 4);     /* offset */
    memcpy(crc_entry.data() + 5, &zero, 4);     /* length (0 = don't check) */
    memcpy(crc_entry.data() + 9, &crc, 4);      /* expected_crc */
    memcpy(crc_entry.data() + 13, &name_idx, 4); /* name_index */

    builder.add_section(3 /* CRC32 */, crc_entry, 1);

    auto db = builder.build();
    ASSERT_EQ(akav_scanner_load_memory(&scanner_, db.data(), db.size()), AKAV_OK);

    akav_scan_result_t result{};
    akav_scanner_scan_buffer(&scanner_, EICAR, EICAR_LEN, &result);
    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.malware_name, "Malware.CRC32Test");
    EXPECT_STREQ(result.scanner_id, "crc32");
}

/* ── Aho-Corasick byte-stream detection ──────────────────────────── */

TEST_F(ScanPipelineTest, AhoCorasickDetection) {
    AkavDbBuilder builder;
    builder.add_string("EICAR.ByteStream");

    /* Use first 16 bytes of EICAR as pattern */
    std::vector<uint8_t> pattern(EICAR, EICAR + 16);
    uint32_t name_idx = builder.string_offset("EICAR.ByteStream");

    auto ac_blob = build_ac_section({{pattern, name_idx}});
    builder.add_section(4 /* AHO_CORASICK */, ac_blob, 1);

    auto db = builder.build();
    ASSERT_EQ(akav_scanner_load_memory(&scanner_, db.data(), db.size()), AKAV_OK);

    akav_scan_result_t result{};
    akav_scanner_scan_buffer(&scanner_, EICAR, EICAR_LEN, &result);
    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.malware_name, "EICAR.ByteStream");
    EXPECT_STREQ(result.scanner_id, "aho_corasick");
}

/* ── Clean file returns clean ────────────────────────────────────── */

TEST_F(ScanPipelineTest, CleanFileReturnsClean) {
    AkavDbBuilder builder;
    builder.add_string("Malware.MD5Test");

    auto md5_entry = build_md5_entry(EICAR, EICAR_LEN,
                                      builder.string_offset("Malware.MD5Test"));
    builder.add_section(1, md5_entry, 1);

    auto db = builder.build();
    ASSERT_EQ(akav_scanner_load_memory(&scanner_, db.data(), db.size()), AKAV_OK);

    uint8_t clean[] = "This is a perfectly clean file with no malware.";
    akav_scan_result_t result{};
    akav_scanner_scan_buffer(&scanner_, clean, sizeof(clean) - 1, &result);
    EXPECT_EQ(result.found, 0);
}

/* ── Short-circuit: MD5 fires before Aho-Corasick ────────────────── */

TEST_F(ScanPipelineTest, ShortCircuitMD5BeforeAC) {
    AkavDbBuilder builder;
    builder.add_string("Malware.ViaMD5");
    builder.add_string("Malware.ViaAC");

    /* Add both MD5 and AC detection for EICAR */
    auto md5_entry = build_md5_entry(EICAR, EICAR_LEN,
                                      builder.string_offset("Malware.ViaMD5"));
    builder.add_section(1, md5_entry, 1);

    std::vector<uint8_t> pattern(EICAR, EICAR + 16);
    auto ac_blob = build_ac_section({{pattern, builder.string_offset("Malware.ViaAC")}});
    builder.add_section(4, ac_blob, 1);

    auto db = builder.build();
    ASSERT_EQ(akav_scanner_load_memory(&scanner_, db.data(), db.size()), AKAV_OK);

    akav_scan_result_t result{};
    akav_scanner_scan_buffer(&scanner_, EICAR, EICAR_LEN, &result);
    EXPECT_EQ(result.found, 1);
    /* MD5 should fire first (earlier in pipeline), not AC */
    EXPECT_STREQ(result.scanner_id, "md5");
    EXPECT_STREQ(result.malware_name, "Malware.ViaMD5");
}

/* ── Mixed database: all section types present ───────────────────── */

TEST_F(ScanPipelineTest, MixedDatabaseAllTypes) {
    AkavDbBuilder builder;
    builder.add_string("Malware.AllTypes");

    /* Add MD5 for a different file (not EICAR) */
    uint8_t other[] = "not-eicar-data-blah";
    auto md5_entry = build_md5_entry(other, sizeof(other) - 1,
                                      builder.string_offset("Malware.AllTypes"));
    builder.add_section(1, md5_entry, 1);

    /* Add SHA256 for another different file */
    uint8_t other2[] = "also-not-eicar-different";
    auto sha_entry = build_sha256_entry(other2, sizeof(other2) - 1,
                                          builder.string_offset("Malware.AllTypes"));
    builder.add_section(2, sha_entry, 1);

    /* Add AC pattern that DOES match EICAR */
    builder.add_string("EICAR.ViaAC");
    std::vector<uint8_t> pattern(EICAR, EICAR + 16);
    auto ac_blob = build_ac_section({{pattern, builder.string_offset("EICAR.ViaAC")}});
    builder.add_section(4, ac_blob, 1);

    auto db = builder.build();
    ASSERT_EQ(akav_scanner_load_memory(&scanner_, db.data(), db.size()), AKAV_OK);

    /* EICAR should be detected via AC (MD5/SHA256 don't match EICAR) */
    akav_scan_result_t result{};
    akav_scanner_scan_buffer(&scanner_, EICAR, EICAR_LEN, &result);
    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.scanner_id, "aho_corasick");
    EXPECT_STREQ(result.malware_name, "EICAR.ViaAC");

    /* The other files should match via MD5/SHA256 */
    akav_scan_result_t result2{};
    akav_scanner_scan_buffer(&scanner_, other, sizeof(other) - 1, &result2);
    EXPECT_EQ(result2.found, 1);
    EXPECT_STREQ(result2.scanner_id, "md5");

    akav_scan_result_t result3{};
    akav_scanner_scan_buffer(&scanner_, other2, sizeof(other2) - 1, &result3);
    EXPECT_EQ(result3.found, 1);
    EXPECT_STREQ(result3.scanner_id, "sha256");
}

/* ── Null/empty buffer doesn't crash ─────────────────────────────── */

TEST_F(ScanPipelineTest, NullBufferSafe) {
    akav_scan_result_t result{};
    akav_scanner_scan_buffer(&scanner_, nullptr, 0, &result);
    EXPECT_EQ(result.found, 0);
}

TEST_F(ScanPipelineTest, EmptyBufferSafe) {
    AkavDbBuilder builder;
    builder.add_string("Test");
    auto md5_entry = build_md5_entry(EICAR, EICAR_LEN, builder.string_offset("Test"));
    builder.add_section(1, md5_entry, 1);
    auto db = builder.build();
    ASSERT_EQ(akav_scanner_load_memory(&scanner_, db.data(), db.size()), AKAV_OK);

    akav_scan_result_t result{};
    akav_scanner_scan_buffer(&scanner_, (const uint8_t*)"", 0, &result);
    EXPECT_EQ(result.found, 0);
}

/* ── Scanner init/destroy idempotent ─────────────────────────────── */

TEST_F(ScanPipelineTest, DoubleDestroyIsSafe) {
    akav_scanner_destroy(&scanner_);
    /* SetUp already inited, TearDown will destroy again — no crash */
}

/* ── Load from invalid data fails gracefully ─────────────────────── */

TEST_F(ScanPipelineTest, LoadInvalidDataFails) {
    uint8_t garbage[] = "this is not a valid akavdb file";
    akav_error_t err = akav_scanner_load_memory(&scanner_, garbage, sizeof(garbage));
    EXPECT_EQ(err, AKAV_ERROR_DB);
}

/* ── Engine integration: load_signatures + scan_buffer ───────────── */

TEST(EngineIntegration, ScanWithoutLoadReturnsClean) {
    akav_engine_t* engine = nullptr;
    ASSERT_EQ(akav_engine_create(&engine), AKAV_OK);
    ASSERT_EQ(akav_engine_init(engine, nullptr), AKAV_OK);

    /* Scan without loading signatures — should return clean */
    akav_scan_result_t result{};
    EXPECT_EQ(akav_scan_buffer(engine, EICAR, EICAR_LEN, "eicar.com", nullptr, &result), AKAV_OK);
    EXPECT_EQ(result.found, 0); /* no signatures loaded */

    akav_engine_destroy(engine);
}

/* ── Multiple patterns in AC section ─────────────────────────────── */

TEST_F(ScanPipelineTest, MultipleACPatterns) {
    AkavDbBuilder builder;
    builder.add_string("Pattern.A");
    builder.add_string("Pattern.B");
    builder.add_string("Pattern.C");

    std::vector<uint8_t> patA = {'H', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> patB = {'W', 'o', 'r', 'l', 'd'};
    std::vector<uint8_t> patC = {'X', '5', 'O', '!'};

    auto ac_blob = build_ac_section({
        {patA, builder.string_offset("Pattern.A")},
        {patB, builder.string_offset("Pattern.B")},
        {patC, builder.string_offset("Pattern.C")},
    });
    builder.add_section(4, ac_blob, 3);

    auto db = builder.build();
    ASSERT_EQ(akav_scanner_load_memory(&scanner_, db.data(), db.size()), AKAV_OK);

    /* "Hello" matches Pattern.A */
    uint8_t hello[] = "Hello World";
    akav_scan_result_t r1{};
    akav_scanner_scan_buffer(&scanner_, hello, sizeof(hello) - 1, &r1);
    EXPECT_EQ(r1.found, 1);
    EXPECT_STREQ(r1.malware_name, "Pattern.A");

    /* EICAR matches Pattern.C (starts with X5O!) */
    akav_scan_result_t r2{};
    akav_scanner_scan_buffer(&scanner_, EICAR, EICAR_LEN, &r2);
    EXPECT_EQ(r2.found, 1);
    EXPECT_STREQ(r2.malware_name, "Pattern.C");

    /* Clean data: no patterns */
    uint8_t clean[] = "abcdefghijklmnop";
    akav_scan_result_t r3{};
    akav_scanner_scan_buffer(&scanner_, clean, sizeof(clean) - 1, &r3);
    EXPECT_EQ(r3.found, 0);
}

/* ── Scanner reports total signature count ───────────────────────── */

TEST_F(ScanPipelineTest, TotalSignatureCount) {
    AkavDbBuilder builder;
    builder.add_string("Sig1");
    builder.add_string("Sig2");

    auto md5_entry = build_md5_entry(EICAR, EICAR_LEN, builder.string_offset("Sig1"));
    builder.add_section(1, md5_entry, 1);

    std::vector<uint8_t> pat = {'t', 'e', 's', 't'};
    auto ac_blob = build_ac_section({{pat, builder.string_offset("Sig2")}});
    builder.add_section(4, ac_blob, 1);

    auto db = builder.build();
    ASSERT_EQ(akav_scanner_load_memory(&scanner_, db.data(), db.size()), AKAV_OK);

    EXPECT_EQ(scanner_.total_signatures, 2u);
}

/* ── Lookup name returns "unknown" for bad index ─────────────────── */

TEST_F(ScanPipelineTest, LookupNameOutOfBounds) {
    EXPECT_STREQ(akav_scanner_lookup_name(&scanner_, 99999), "unknown");
}
