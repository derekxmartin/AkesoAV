#include <gtest/gtest.h>
#include "parsers/zip.h"
#include "file_type.h"
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
#include <string>
#include <zlib.h>

/* ── EICAR test string ───────────────────────────────────────────── */

static const char EICAR[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
static const size_t EICAR_LEN = 68;

/* ── Helper: build a minimal ZIP archive in memory ───────────────── */

static void write_u16(std::vector<uint8_t>& v, uint16_t val) {
    v.push_back((uint8_t)(val & 0xFF));
    v.push_back((uint8_t)((val >> 8) & 0xFF));
}

static void write_u32(std::vector<uint8_t>& v, uint32_t val) {
    v.push_back((uint8_t)(val & 0xFF));
    v.push_back((uint8_t)((val >> 8) & 0xFF));
    v.push_back((uint8_t)((val >> 16) & 0xFF));
    v.push_back((uint8_t)((val >> 24) & 0xFF));
}

struct ZipEntry {
    std::string filename;
    std::vector<uint8_t> data;
    bool compress;  /* true=deflate, false=stored */
};

static std::vector<uint8_t> build_zip(const std::vector<ZipEntry>& entries) {
    std::vector<uint8_t> zip;
    struct CentralDirEntry {
        uint32_t local_header_offset;
        std::string filename;
        uint32_t crc32_val;
        uint32_t comp_size;
        uint32_t uncomp_size;
        uint16_t method;
    };
    std::vector<CentralDirEntry> central_entries;

    for (const auto& entry : entries) {
        CentralDirEntry cde;
        cde.local_header_offset = (uint32_t)zip.size();
        cde.filename = entry.filename;
        cde.uncomp_size = (uint32_t)entry.data.size();

        /* Compute CRC32 */
        cde.crc32_val = (uint32_t)crc32(0L, entry.data.data(), (uInt)entry.data.size());

        std::vector<uint8_t> comp_data;
        if (entry.compress && !entry.data.empty()) {
            cde.method = 8; /* DEFLATE */
            /* Compress with deflate (raw, no header) */
            z_stream strm = {};
            deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
            comp_data.resize(deflateBound(&strm, (uLong)entry.data.size()));
            strm.next_in = (Bytef*)entry.data.data();
            strm.avail_in = (uInt)entry.data.size();
            strm.next_out = (Bytef*)comp_data.data();
            strm.avail_out = (uInt)comp_data.size();
            deflate(&strm, Z_FINISH);
            comp_data.resize(strm.total_out);
            deflateEnd(&strm);
        } else {
            cde.method = 0; /* STORED */
            comp_data = entry.data;
        }
        cde.comp_size = (uint32_t)comp_data.size();

        /* Local file header */
        write_u32(zip, 0x04034B50);                          /* signature */
        write_u16(zip, 20);                                   /* version needed */
        write_u16(zip, 0);                                    /* flags */
        write_u16(zip, cde.method);                           /* compression method */
        write_u16(zip, 0);                                    /* mod time */
        write_u16(zip, 0);                                    /* mod date */
        write_u32(zip, cde.crc32_val);                        /* crc32 */
        write_u32(zip, cde.comp_size);                        /* compressed size */
        write_u32(zip, cde.uncomp_size);                      /* uncompressed size */
        write_u16(zip, (uint16_t)entry.filename.size());      /* filename length */
        write_u16(zip, 0);                                    /* extra field length */
        zip.insert(zip.end(), entry.filename.begin(), entry.filename.end());
        zip.insert(zip.end(), comp_data.begin(), comp_data.end());

        central_entries.push_back(cde);
    }

    /* Central directory */
    uint32_t cd_offset = (uint32_t)zip.size();
    for (const auto& cde : central_entries) {
        write_u32(zip, 0x02014B50);                          /* signature */
        write_u16(zip, 20);                                   /* version made by */
        write_u16(zip, 20);                                   /* version needed */
        write_u16(zip, 0);                                    /* flags */
        write_u16(zip, cde.method);                           /* compression method */
        write_u16(zip, 0);                                    /* mod time */
        write_u16(zip, 0);                                    /* mod date */
        write_u32(zip, cde.crc32_val);
        write_u32(zip, cde.comp_size);
        write_u32(zip, cde.uncomp_size);
        write_u16(zip, (uint16_t)cde.filename.size());
        write_u16(zip, 0);                                    /* extra */
        write_u16(zip, 0);                                    /* comment */
        write_u16(zip, 0);                                    /* disk start */
        write_u16(zip, 0);                                    /* internal attrs */
        write_u32(zip, 0);                                    /* external attrs */
        write_u32(zip, cde.local_header_offset);
        zip.insert(zip.end(), cde.filename.begin(), cde.filename.end());
    }
    uint32_t cd_size = (uint32_t)zip.size() - cd_offset;

    /* End of central directory */
    write_u32(zip, 0x06054B50);
    write_u16(zip, 0);                                        /* disk number */
    write_u16(zip, 0);                                        /* disk with CD */
    write_u16(zip, (uint16_t)central_entries.size());
    write_u16(zip, (uint16_t)central_entries.size());
    write_u32(zip, cd_size);
    write_u32(zip, cd_offset);
    write_u16(zip, 0);                                        /* comment length */

    return zip;
}

/* ── Helper: build a minimal .akavdb with EICAR sigs ─────────────── */

static std::vector<uint8_t> build_eicar_db() {
    /* String table */
    const std::string name = "EICAR-Test-File";
    std::vector<uint8_t> strtab(name.begin(), name.end());
    strtab.push_back(0);

    /* Build Aho-Corasick section with EICAR pattern (first 16 bytes) */
    akav_ac_t* ac = akav_ac_create();
    akav_ac_add_pattern(ac, (const uint8_t*)EICAR, 16, 0);
    akav_ac_finalize(ac);
    size_t ac_sz = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> ac_blob(ac_sz);
    akav_ac_serialize(ac, ac_blob.data(), ac_blob.size());
    akav_ac_destroy(ac);

    /* MD5 for exact EICAR match */
    uint8_t md5[16];
    akav_hash_md5((const uint8_t*)EICAR, EICAR_LEN, md5);
    std::vector<uint8_t> md5_data(20);
    memcpy(md5_data.data(), md5, 16);
    uint32_t zero_idx = 0;
    memcpy(md5_data.data() + 16, &zero_idx, 4);

    /* Assemble .akavdb (same format as test_eicar.cpp) */
    struct { uint32_t type; std::vector<uint8_t>* data; uint32_t count; } secs[] = {
        {1,    &md5_data, 1},    /* MD5 */
        {4,    &ac_blob,  1},    /* AhoCorasick */
        {0xFF, &strtab,   0},   /* StringTable */
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

/* ── Helper: write temp file, returns path ───────────────────────── */

static std::string write_temp_file(const std::vector<uint8_t>& data, const char* suffix) {
    char tmp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_dir);
    char tmp_path[MAX_PATH];
    snprintf(tmp_path, MAX_PATH, "%sakav_test_%s", tmp_dir, suffix);

    FILE* f = nullptr;
    fopen_s(&f, tmp_path, "wb");
    if (f) {
        fwrite(data.data(), 1, data.size(), f);
        fclose(f);
    }
    return tmp_path;
}

/* ── Helper: build .akavdb with ONLY MD5 (no AC pattern) ─────────── */

static std::vector<uint8_t> build_md5_only_db() {
    const std::string name = "EICAR-Test-File";
    std::vector<uint8_t> strtab(name.begin(), name.end());
    strtab.push_back(0);

    uint8_t md5[16];
    akav_hash_md5((const uint8_t*)EICAR, EICAR_LEN, md5);
    std::vector<uint8_t> md5_data(20);
    memcpy(md5_data.data(), md5, 16);
    uint32_t zero_idx = 0;
    memcpy(md5_data.data() + 16, &zero_idx, 4);

    struct { uint32_t type; std::vector<uint8_t>* data; uint32_t count; } secs[] = {
        {1,    &md5_data, 1},    /* MD5 only */
        {0xFF, &strtab,   0},   /* StringTable */
    };
    uint32_t section_count = 2;
    uint32_t total_sigs = 1;
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

/* ── Test fixture: engine with EICAR database ────────────────────── */

class ZipScanTest : public ::testing::Test {
protected:
    akav_engine_t* engine = nullptr;
    std::string db_path;

    void SetUp() override {
        auto db = build_eicar_db();
        db_path = write_temp_file(db, "zip_test.akavdb");
        ASSERT_EQ(akav_engine_create(&engine), AKAV_OK);
        ASSERT_EQ(akav_engine_init(engine, nullptr), AKAV_OK);
        ASSERT_EQ(akav_engine_load_signatures(engine, db_path.c_str()), AKAV_OK);
    }

    void TearDown() override {
        if (engine) akav_engine_destroy(engine);
        DeleteFileA(db_path.c_str());
    }
};

/* Fixture with MD5-only DB (no AC pattern matching on raw bytes) */
class ZipScanMd5OnlyTest : public ::testing::Test {
protected:
    akav_engine_t* engine = nullptr;
    std::string db_path;

    void SetUp() override {
        auto db = build_md5_only_db();
        db_path = write_temp_file(db, "zip_md5_test.akavdb");
        ASSERT_EQ(akav_engine_create(&engine), AKAV_OK);
        ASSERT_EQ(akav_engine_init(engine, nullptr), AKAV_OK);
        ASSERT_EQ(akav_engine_load_signatures(engine, db_path.c_str()), AKAV_OK);
    }

    void TearDown() override {
        if (engine) akav_engine_destroy(engine);
        DeleteFileA(db_path.c_str());
    }
};

/* ══════════════════════════════════════════════════════════════════ */
/* ZIP parser unit tests                                              */
/* ══════════════════════════════════════════════════════════════════ */

/* ── Basic: extract stored entry ─────────────────────────────────── */

TEST(ZipParser, ExtractStoredEntry) {
    std::vector<uint8_t> content = {'H', 'e', 'l', 'l', 'o'};
    auto zip = build_zip({{"test.txt", content, false}});

    akav_zip_context_t ctx;
    akav_zip_init(&ctx, 0);

    bool called = false;
    akav_zip_extract(&ctx, zip.data(), zip.size(),
        [](const char* fn, const uint8_t* data, size_t len, int depth, void* ud) -> bool {
            auto* called_ptr = (bool*)ud;
            *called_ptr = true;
            EXPECT_STREQ(fn, "test.txt");
            EXPECT_EQ(len, 5u);
            EXPECT_EQ(memcmp(data, "Hello", 5), 0);
            EXPECT_EQ(depth, 1);
            return true;
        }, &called);

    EXPECT_TRUE(called);
    EXPECT_EQ(ctx.num_entries, 1u);
}

/* ── Basic: extract deflated entry ───────────────────────────────── */

TEST(ZipParser, ExtractDeflatedEntry) {
    std::vector<uint8_t> content(1000, 'A'); /* compressible */
    auto zip = build_zip({{"big.txt", content, true}});

    akav_zip_context_t ctx;
    akav_zip_init(&ctx, 0);

    bool ok_data = false;
    akav_zip_extract(&ctx, zip.data(), zip.size(),
        [](const char* fn, const uint8_t* data, size_t len, int /*depth*/, void* ud) -> bool {
            (void)fn;
            auto* ok = (bool*)ud;
            if (len == 1000) {
                bool all_a = true;
                for (size_t i = 0; i < len; i++) {
                    if (data[i] != 'A') { all_a = false; break; }
                }
                *ok = all_a;
            }
            return true;
        }, &ok_data);

    EXPECT_TRUE(ok_data);
}

/* ── Multiple entries ────────────────────────────────────────────── */

TEST(ZipParser, MultipleEntries) {
    auto zip = build_zip({
        {"a.txt", {'A'}, false},
        {"b.txt", {'B'}, false},
        {"c.txt", {'C'}, false},
    });

    akav_zip_context_t ctx;
    akav_zip_init(&ctx, 0);

    int count = 0;
    akav_zip_extract(&ctx, zip.data(), zip.size(),
        [](const char*, const uint8_t*, size_t, int, void* ud) -> bool {
            (*(int*)ud)++;
            return true;
        }, &count);

    EXPECT_EQ(count, 3);
    EXPECT_EQ(ctx.num_entries, 3u);
}

/* ── Empty ZIP ───────────────────────────────────────────────────── */

TEST(ZipParser, EmptyZip) {
    auto zip = build_zip({});

    akav_zip_context_t ctx;
    akav_zip_init(&ctx, 0);

    int count = 0;
    bool ok = akav_zip_extract(&ctx, zip.data(), zip.size(),
        [](const char*, const uint8_t*, size_t, int, void* ud) -> bool {
            (*(int*)ud)++;
            return true;
        }, &count);

    EXPECT_TRUE(ok);
    EXPECT_EQ(count, 0);
}

/* ── Zip bomb: high compression ratio ────────────────────────────── */

TEST(ZipParser, ZipBombRatioDetected) {
    /* Create a highly compressible entry: 10MB of zeros compressed to tiny */
    std::vector<uint8_t> zeros(10 * 1024 * 1024, 0);
    auto zip = build_zip({{"bomb.bin", zeros, true}});

    akav_zip_context_t ctx;
    akav_zip_init(&ctx, 0);

    bool ok = akav_zip_extract(&ctx, zip.data(), zip.size(),
        [](const char*, const uint8_t*, size_t, int, void*) -> bool {
            return true;
        }, nullptr);

    EXPECT_FALSE(ok);
    EXPECT_TRUE(ctx.bomb_detected);
}

/* ── Depth limit ─────────────────────────────────────────────────── */

TEST(ZipParser, DepthLimitEnforced) {
    auto zip = build_zip({{"inner.txt", {'X'}, false}});

    akav_zip_context_t ctx;
    akav_zip_init(&ctx, AKAV_ZIP_MAX_DEPTH); /* already at max */

    bool ok = akav_zip_extract(&ctx, zip.data(), zip.size(),
        [](const char*, const uint8_t*, size_t, int, void*) -> bool {
            return true;
        }, nullptr);

    EXPECT_FALSE(ok); /* should refuse due to depth */
}

/* ── Null/invalid inputs ─────────────────────────────────────────── */

TEST(ZipParser, NullSafety) {
    akav_zip_context_t ctx;
    akav_zip_init(&ctx, 0);

    EXPECT_FALSE(akav_zip_extract(&ctx, nullptr, 0, nullptr, nullptr));
    EXPECT_FALSE(akav_zip_extract(nullptr, (const uint8_t*)"PK", 2, nullptr, nullptr));
}

/* ── Callback stop ───────────────────────────────────────────────── */

TEST(ZipParser, CallbackStopsExtraction) {
    auto zip = build_zip({
        {"a.txt", {'A'}, false},
        {"b.txt", {'B'}, false},
    });

    akav_zip_context_t ctx;
    akav_zip_init(&ctx, 0);

    int count = 0;
    akav_zip_extract(&ctx, zip.data(), zip.size(),
        [](const char*, const uint8_t*, size_t, int, void* ud) -> bool {
            (*(int*)ud)++;
            return false; /* stop after first */
        }, &count);

    EXPECT_EQ(count, 1);
}

/* ── Truncated ZIP ───────────────────────────────────────────────── */

TEST(ZipParser, TruncatedZip) {
    auto zip = build_zip({{"test.txt", {'X'}, false}});

    /* Truncate mid-header */
    akav_zip_context_t ctx;
    akav_zip_init(&ctx, 0);

    bool ok = akav_zip_extract(&ctx, zip.data(), 10,
        [](const char*, const uint8_t*, size_t, int, void*) -> bool {
            return true;
        }, nullptr);

    EXPECT_FALSE(ok);
}

/* ══════════════════════════════════════════════════════════════════ */
/* Engine integration tests (EICAR in ZIP)                            */
/* ══════════════════════════════════════════════════════════════════ */

/* ── EICAR inside a ZIP → detected ───────────────────────────────── */

TEST_F(ZipScanTest, EicarInZipDetected) {
    std::vector<uint8_t> eicar_data(EICAR, EICAR + EICAR_LEN);
    auto zip = build_zip({{"eicar.com", eicar_data, false}});

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, zip.data(), zip.size(),
                                         "eicar.zip", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
    EXPECT_NE(strstr(result.malware_name, "EICAR"), nullptr);
}

/* ── EICAR in deflated ZIP → detected ────────────────────────────── */

TEST_F(ZipScanTest, EicarInDeflatedZipDetected) {
    std::vector<uint8_t> eicar_data(EICAR, EICAR + EICAR_LEN);
    auto zip = build_zip({{"eicar.com", eicar_data, true}});

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, zip.data(), zip.size(),
                                         "eicar.zip", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
}

/* ── Nested ZIP: EICAR in ZIP inside ZIP → detected ──────────────── */

TEST_F(ZipScanTest, NestedZipEicarDetected) {
    /* Inner ZIP contains EICAR */
    std::vector<uint8_t> eicar_data(EICAR, EICAR + EICAR_LEN);
    auto inner_zip = build_zip({{"eicar.com", eicar_data, false}});

    /* Outer ZIP contains inner ZIP */
    auto outer_zip = build_zip({{"inner.zip", inner_zip, false}});

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, outer_zip.data(), outer_zip.size(),
                                         "nested.zip", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
}

/* ── Clean ZIP → no detection ────────────────────────────────────── */

TEST_F(ZipScanTest, CleanZipNotDetected) {
    auto zip = build_zip({
        {"readme.txt", {'H', 'e', 'l', 'l', 'o'}, false},
        {"data.bin", {0x00, 0x01, 0x02, 0x03}, true},
    });

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, zip.data(), zip.size(),
                                         "clean.zip", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 0);
}

/* ── Archive scanning disabled → EICAR in ZIP not detected ───────── */
/* Uses MD5-only DB so pattern matching on raw ZIP bytes doesn't trigger */

TEST_F(ZipScanMd5OnlyTest, ArchiveScanDisabledSkipsZip) {
    std::vector<uint8_t> eicar_data(EICAR, EICAR + EICAR_LEN);
    auto zip = build_zip({{"eicar.com", eicar_data, false}});

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.scan_archives = 0;

    akav_error_t err = akav_scan_buffer(engine, zip.data(), zip.size(),
                                         "eicar.zip", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 0); /* MD5 of ZIP blob ≠ MD5 of EICAR */
}

/* ── Zip bomb → AKAV_ERROR_BOMB ──────────────────────────────────── */

TEST_F(ZipScanTest, ZipBombReturnsBombError) {
    std::vector<uint8_t> zeros(10 * 1024 * 1024, 0);
    auto zip = build_zip({{"bomb.bin", zeros, true}});

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, zip.data(), zip.size(),
                                         "bomb.zip", &opts, &result);
    EXPECT_EQ(err, AKAV_ERROR_BOMB);
}

/* ── Depth limit via options → nested beyond limit not scanned ───── */
/* Uses MD5-only DB so pattern matching on raw ZIP bytes doesn't trigger */

TEST_F(ZipScanMd5OnlyTest, DepthLimitStopsRecursion) {
    std::vector<uint8_t> eicar_data(EICAR, EICAR + EICAR_LEN);
    auto inner = build_zip({{"eicar.com", eicar_data, false}});
    auto outer = build_zip({{"inner.zip", inner, false}});

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.max_scan_depth = 1; /* only scan 1 level deep */

    akav_error_t err = akav_scan_buffer(engine, outer.data(), outer.size(),
                                         "nested.zip", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    /* MD5-only: EICAR is only detected by exact hash match.
     * With depth=1: outer ZIP extracts inner.zip, but inner.zip won't be
     * recursed into. EICAR MD5 only matches the 68-byte file. */
    EXPECT_EQ(result.found, 0);
}
