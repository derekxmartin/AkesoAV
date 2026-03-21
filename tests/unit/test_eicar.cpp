#include <gtest/gtest.h>
#include "akesoav.h"
#include "engine_internal.h"
#include "scanner.h"
#include "signatures/aho_corasick.h"
#include "signatures/hash_matcher.h"
#include "database/sigdb.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstring>
#include <cstdio>
#include <vector>
#include <map>
#include <string>

/* ── EICAR test string ───────────────────────────────────────────── */

static const char EICAR[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
static const size_t EICAR_LEN = 68;

/* ── Minimal .akavdb builder (shared with test_scan_pipeline) ────── */

static std::vector<uint8_t> build_eicar_db() {
    /* String table */
    const std::string name = "EICAR-Test-File";
    std::vector<uint8_t> strtab(name.begin(), name.end());
    strtab.push_back(0);

    /* Build Aho-Corasick section with EICAR pattern (first 16 bytes) */
    akav_ac_t* ac = akav_ac_create();
    akav_ac_add_pattern(ac, (const uint8_t*)EICAR, 16, 0 /* name_index=0 */);
    akav_ac_finalize(ac);
    size_t ac_sz = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> ac_blob(ac_sz);
    akav_ac_serialize(ac, ac_blob.data(), ac_blob.size());
    akav_ac_destroy(ac);

    /* Also add MD5 for exact EICAR match */
    uint8_t md5[16];
    akav_hash_md5((const uint8_t*)EICAR, EICAR_LEN, md5);
    std::vector<uint8_t> md5_data(20);
    memcpy(md5_data.data(), md5, 16);
    uint32_t zero_idx = 0;
    memcpy(md5_data.data() + 16, &zero_idx, 4);

    /* Assemble .akavdb */
    /* Sections: MD5(1), AhoCorasick(4), StringTable(0xFF) */
    struct { uint32_t type; std::vector<uint8_t>* data; uint32_t count; } secs[] = {
        {1,    &md5_data, 1},
        {4,    &ac_blob,  1},
        {0xFF, &strtab,   0},
    };
    uint32_t section_count = 3;
    uint32_t total_sigs = 2;
    uint32_t offset_table_size = section_count * 16;
    uint32_t data_start = 0x0118 + offset_table_size;

    std::vector<uint8_t> db(0x0118, 0);
    uint32_t magic = 0x56414B41;
    uint32_t version = 1;
    int64_t created = 1700000000;
    memcpy(db.data() + 0, &magic, 4);
    memcpy(db.data() + 4, &version, 4);
    memcpy(db.data() + 8, &total_sigs, 4);
    memcpy(db.data() + 12, &created, 8);
    memcpy(db.data() + 20, &section_count, 4);

    uint32_t off = data_start;
    for (auto& s : secs) {
        uint32_t sz32 = (uint32_t)s.data->size();
        uint8_t entry[16];
        memcpy(entry + 0, &s.type, 4);
        memcpy(entry + 4, &off, 4);
        memcpy(entry + 8, &sz32, 4);
        memcpy(entry + 12, &s.count, 4);
        db.insert(db.end(), entry, entry + 16);
        off += sz32;
    }
    for (auto& s : secs) {
        db.insert(db.end(), s.data->begin(), s.data->end());
    }
    return db;
}

/* ── Test fixture: scanner with EICAR database ───────────────────── */

class EicarTest : public ::testing::Test
{
protected:
    akav_engine_t* engine = nullptr;
    std::vector<uint8_t> db_data_;

    void SetUp() override
    {
        ASSERT_EQ(akav_engine_create(&engine), AKAV_OK);
        ASSERT_EQ(akav_engine_init(engine, nullptr), AKAV_OK);

        /* Build in-memory .akavdb and write to temp file */
        db_data_ = build_eicar_db();
        db_path_ = temp_db_path();
        FILE* f = nullptr;
        ASSERT_EQ(fopen_s(&f, db_path_.c_str(), "wb"), 0);
        ASSERT_NE(f, nullptr);
        fwrite(db_data_.data(), 1, db_data_.size(), f);
        fclose(f);

        ASSERT_EQ(akav_engine_load_signatures(engine, db_path_.c_str()), AKAV_OK);
    }

    void TearDown() override
    {
        if (engine)
            akav_engine_destroy(engine);
        if (!db_path_.empty())
            remove(db_path_.c_str());
    }

private:
    std::string db_path_;

    static std::string temp_db_path() {
        char tmp[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp);
        std::string p = std::string(tmp) + "eicar_test.akavdb";
        return p;
    }
};

TEST_F(EicarTest, DetectsEicarString)
{
    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, (const uint8_t*)EICAR,
                                       strlen(EICAR), "eicar.com",
                                       &opts, &result);
    ASSERT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.malware_name, "EICAR-Test-File");
    EXPECT_STREQ(result.scanner_id, "md5");
}

TEST_F(EicarTest, CleanBufferNotDetected)
{
    const char* clean = "This is a completely clean file with no malware.";
    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, (const uint8_t*)clean,
                                       strlen(clean), "clean.txt",
                                       &opts, &result);
    ASSERT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 0);
    EXPECT_STREQ(result.malware_name, "");
}

TEST_F(EicarTest, EmptyBufferClean)
{
    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, (const uint8_t*)"", 0,
                                       "empty.bin", &opts, &result);
    ASSERT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 0);
}

TEST_F(EicarTest, EicarWithPrefix)
{
    /* EICAR preceded by garbage — detected via AC byte-stream (not MD5, since hash differs) */
    char buf[256];
    memset(buf, 'A', sizeof(buf));
    memcpy(buf + 50, EICAR, strlen(EICAR));

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, (const uint8_t*)buf,
                                       sizeof(buf), "embedded_eicar",
                                       &opts, &result);
    ASSERT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.scanner_id, "aho_corasick");
}

TEST_F(EicarTest, ScanTimePopulated)
{
    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_scan_buffer(engine, (const uint8_t*)EICAR, strlen(EICAR),
                    "eicar.com", &opts, &result);
    EXPECT_GE(result.scan_time_ms, 0);
}
