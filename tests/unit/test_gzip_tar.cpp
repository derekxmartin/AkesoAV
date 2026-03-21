#include <gtest/gtest.h>
#include "parsers/gzip.h"
#include "parsers/tar.h"
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

/* ── Helper: gzip-compress a buffer ──────────────────────────────── */

static std::vector<uint8_t> gzip_compress(const uint8_t* data, size_t len) {
    z_stream strm = {};
    /* 16 + MAX_WBITS for gzip format */
    deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY);

    std::vector<uint8_t> out(deflateBound(&strm, (uLong)len));
    strm.next_in = (Bytef*)data;
    strm.avail_in = (uInt)len;
    strm.next_out = (Bytef*)out.data();
    strm.avail_out = (uInt)out.size();

    deflate(&strm, Z_FINISH);
    out.resize(strm.total_out);
    deflateEnd(&strm);
    return out;
}

/* ── Helper: build a TAR archive in memory ───────────────────────── */

struct TarEntry {
    std::string filename;
    std::vector<uint8_t> data;
};

static void tar_write_octal(uint8_t* dest, size_t field_len, uint64_t val) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%0*llo", (int)(field_len - 1), (unsigned long long)val);
    memcpy(dest, buf, field_len - 1);
    dest[field_len - 1] = '\0';
}

static std::vector<uint8_t> build_tar(const std::vector<TarEntry>& entries) {
    std::vector<uint8_t> tar;

    for (const auto& entry : entries) {
        /* 512-byte header */
        uint8_t header[512] = {0};

        /* filename (0, 100) */
        size_t name_len = entry.filename.size();
        if (name_len > 99) name_len = 99;
        memcpy(header + 0, entry.filename.c_str(), name_len);

        /* mode (100, 8) */
        tar_write_octal(header + 100, 8, 0644);

        /* uid (108, 8), gid (116, 8) */
        tar_write_octal(header + 108, 8, 0);
        tar_write_octal(header + 116, 8, 0);

        /* size (124, 12) */
        tar_write_octal(header + 124, 12, entry.data.size());

        /* mtime (136, 12) */
        tar_write_octal(header + 136, 12, 1700000000);

        /* typeflag (156) - '0' for regular file */
        header[156] = '0';

        /* magic (257, 6) */
        memcpy(header + 257, "ustar", 6);

        /* version (263, 2) */
        header[263] = '0';
        header[264] = '0';

        /* Compute checksum (148, 8): sum of all bytes with checksum field as spaces */
        memset(header + 148, ' ', 8);
        uint32_t cksum = 0;
        for (int i = 0; i < 512; i++)
            cksum += header[i];
        tar_write_octal(header + 148, 7, cksum);
        header[155] = ' ';

        tar.insert(tar.end(), header, header + 512);

        /* Data blocks (512-byte aligned) */
        tar.insert(tar.end(), entry.data.begin(), entry.data.end());

        /* Pad to 512-byte boundary */
        size_t remainder = entry.data.size() % 512;
        if (remainder > 0) {
            size_t pad = 512 - remainder;
            tar.insert(tar.end(), pad, 0);
        }
    }

    /* End-of-archive: two 512-byte zero blocks */
    tar.insert(tar.end(), 1024, 0);

    return tar;
}

/* ── Helper: build .akavdb with EICAR MD5 + AC ──────────────────── */

static std::vector<uint8_t> build_eicar_db() {
    const std::string name = "EICAR-Test-File";
    std::vector<uint8_t> strtab(name.begin(), name.end());
    strtab.push_back(0);

    akav_ac_t* ac = akav_ac_create();
    akav_ac_add_pattern(ac, (const uint8_t*)EICAR, 16, 0);
    akav_ac_finalize(ac);
    size_t ac_sz = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> ac_blob(ac_sz);
    akav_ac_serialize(ac, ac_blob.data(), ac_blob.size());
    akav_ac_destroy(ac);

    uint8_t md5[16];
    akav_hash_md5((const uint8_t*)EICAR, EICAR_LEN, md5);
    std::vector<uint8_t> md5_data(20);
    memcpy(md5_data.data(), md5, 16);
    uint32_t zero_idx = 0;
    memcpy(md5_data.data() + 16, &zero_idx, 4);

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

/* ── Helper: write temp file ─────────────────────────────────────── */

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

/* ── Test fixture: engine with EICAR database ────────────────────── */

class GzipTarScanTest : public ::testing::Test {
protected:
    akav_engine_t* engine = nullptr;
    std::string db_path;

    void SetUp() override {
        auto db = build_eicar_db();
        db_path = write_temp_file(db, "gztar_test.akavdb");
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
/* GZIP parser unit tests                                             */
/* ══════════════════════════════════════════════════════════════════ */

/* ── Basic: decompress gzipped data ──────────────────────────────── */

TEST(GzipParser, DecompressBasic) {
    std::vector<uint8_t> content = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    auto gz = gzip_compress(content.data(), content.size());

    akav_gzip_context_t ctx;
    akav_gzip_init(&ctx);

    uint8_t* out = nullptr;
    size_t out_len = 0;
    bool ok = akav_gzip_decompress(&ctx, gz.data(), gz.size(), &out, &out_len);

    EXPECT_TRUE(ok);
    ASSERT_EQ(out_len, content.size());
    EXPECT_EQ(memcmp(out, content.data(), content.size()), 0);
    free(out);
}

/* ── Decompress EICAR ────────────────────────────────────────────── */

TEST(GzipParser, DecompressEicar) {
    auto gz = gzip_compress((const uint8_t*)EICAR, EICAR_LEN);

    akav_gzip_context_t ctx;
    akav_gzip_init(&ctx);

    uint8_t* out = nullptr;
    size_t out_len = 0;
    bool ok = akav_gzip_decompress(&ctx, gz.data(), gz.size(), &out, &out_len);

    EXPECT_TRUE(ok);
    ASSERT_EQ(out_len, EICAR_LEN);
    EXPECT_EQ(memcmp(out, EICAR, EICAR_LEN), 0);
    free(out);
}

/* ── File type detection for gzip ────────────────────────────────── */

TEST(GzipParser, FileTypeDetected) {
    auto gz = gzip_compress((const uint8_t*)"test", 4);
    EXPECT_EQ(akav_detect_file_type(gz.data(), gz.size()), AKAV_FILETYPE_GZIP);
}

/* ── Invalid gzip: bad magic ─────────────────────────────────────── */

TEST(GzipParser, BadMagicRejected) {
    uint8_t bad[] = {0x00, 0x00, 0x08, 0x00};

    akav_gzip_context_t ctx;
    akav_gzip_init(&ctx);

    uint8_t* out = nullptr;
    size_t out_len = 0;
    EXPECT_FALSE(akav_gzip_decompress(&ctx, bad, sizeof(bad), &out, &out_len));
    EXPECT_EQ(out, nullptr);
}

/* ── Corrupt gzip data: no crash ─────────────────────────────────── */

TEST(GzipParser, CorruptDataNoCrash) {
    uint8_t corrupt[] = {0x1F, 0x8B, 0x08, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                         0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};

    akav_gzip_context_t ctx;
    akav_gzip_init(&ctx);

    uint8_t* out = nullptr;
    size_t out_len = 0;
    EXPECT_FALSE(akav_gzip_decompress(&ctx, corrupt, sizeof(corrupt), &out, &out_len));
    /* Should not crash, out should be NULL */
    EXPECT_EQ(out, nullptr);
}

/* ── Null safety ─────────────────────────────────────────────────── */

TEST(GzipParser, NullSafety) {
    akav_gzip_context_t ctx;
    akav_gzip_init(&ctx);
    EXPECT_FALSE(akav_gzip_decompress(&ctx, nullptr, 0, nullptr, nullptr));
    EXPECT_FALSE(akav_gzip_decompress(nullptr, (const uint8_t*)"x", 1, nullptr, nullptr));
}

/* ── Gzip bomb: highly compressible data ─────────────────────────── */

TEST(GzipParser, BombDetected) {
    /* 10MB of zeros — very high compression ratio */
    std::vector<uint8_t> zeros(10 * 1024 * 1024, 0);
    auto gz = gzip_compress(zeros.data(), zeros.size());

    akav_gzip_context_t ctx;
    akav_gzip_init(&ctx);

    uint8_t* out = nullptr;
    size_t out_len = 0;
    bool ok = akav_gzip_decompress(&ctx, gz.data(), gz.size(), &out, &out_len);

    EXPECT_FALSE(ok);
    EXPECT_TRUE(ctx.bomb_detected);
    if (out) free(out);
}

/* ══════════════════════════════════════════════════════════════════ */
/* TAR parser unit tests                                              */
/* ══════════════════════════════════════════════════════════════════ */

/* ── Basic: extract single entry ─────────────────────────────────── */

TEST(TarParser, ExtractSingleEntry) {
    std::vector<uint8_t> content = {'H', 'e', 'l', 'l', 'o'};
    auto tar = build_tar({{"test.txt", content}});

    akav_tar_context_t ctx;
    akav_tar_init(&ctx);

    struct Result { std::string name; std::vector<uint8_t> data; } result;
    bool ok = akav_tar_extract(&ctx, tar.data(), tar.size(),
        [](const char* fn, const uint8_t* data, size_t len, void* ud) -> bool {
            auto* r = (Result*)ud;
            r->name = fn;
            r->data.assign(data, data + len);
            return true;
        }, &result);

    EXPECT_TRUE(ok);
    EXPECT_STREQ(result.name.c_str(), "test.txt");
    ASSERT_EQ(result.data.size(), 5u);
    EXPECT_EQ(memcmp(result.data.data(), "Hello", 5), 0);
    EXPECT_EQ(ctx.num_entries, 1u);
}

/* ── Multiple entries ────────────────────────────────────────────── */

TEST(TarParser, MultipleEntries) {
    auto tar = build_tar({
        {"a.txt", {'A'}},
        {"b.txt", {'B'}},
        {"c.txt", {'C'}},
    });

    akav_tar_context_t ctx;
    akav_tar_init(&ctx);

    int count = 0;
    bool ok = akav_tar_extract(&ctx, tar.data(), tar.size(),
        [](const char*, const uint8_t*, size_t, void* ud) -> bool {
            (*(int*)ud)++;
            return true;
        }, &count);

    EXPECT_TRUE(ok);
    EXPECT_EQ(count, 3);
    EXPECT_EQ(ctx.num_entries, 3u);
}

/* ── File type detection for TAR ─────────────────────────────────── */

TEST(TarParser, FileTypeDetected) {
    auto tar = build_tar({{"test.txt", {'X'}}});
    EXPECT_EQ(akav_detect_file_type(tar.data(), tar.size()), AKAV_FILETYPE_TAR);
}

/* ── Empty TAR (just end blocks) ─────────────────────────────────── */

TEST(TarParser, EmptyTar) {
    auto tar = build_tar({});

    akav_tar_context_t ctx;
    akav_tar_init(&ctx);

    int count = 0;
    bool ok = akav_tar_extract(&ctx, tar.data(), tar.size(),
        [](const char*, const uint8_t*, size_t, void* ud) -> bool {
            (*(int*)ud)++;
            return true;
        }, &count);

    EXPECT_TRUE(ok);
    EXPECT_EQ(count, 0);
}

/* ── Callback stops extraction ───────────────────────────────────── */

TEST(TarParser, CallbackStopsExtraction) {
    auto tar = build_tar({
        {"a.txt", {'A'}},
        {"b.txt", {'B'}},
    });

    akav_tar_context_t ctx;
    akav_tar_init(&ctx);

    int count = 0;
    akav_tar_extract(&ctx, tar.data(), tar.size(),
        [](const char*, const uint8_t*, size_t, void* ud) -> bool {
            (*(int*)ud)++;
            return false; /* stop after first */
        }, &count);

    EXPECT_EQ(count, 1);
}

/* ── Null safety ─────────────────────────────────────────────────── */

TEST(TarParser, NullSafety) {
    akav_tar_context_t ctx;
    akav_tar_init(&ctx);
    EXPECT_FALSE(akav_tar_extract(&ctx, nullptr, 0, nullptr, nullptr));
    EXPECT_FALSE(akav_tar_extract(nullptr, (const uint8_t*)"x", 1, nullptr, nullptr));
}

/* ── Truncated TAR ───────────────────────────────────────────────── */

TEST(TarParser, TruncatedTar) {
    auto tar = build_tar({{"test.txt", std::vector<uint8_t>(1000, 'X')}});

    /* Truncate: keep header but chop data */
    akav_tar_context_t ctx;
    akav_tar_init(&ctx);

    bool ok = akav_tar_extract(&ctx, tar.data(), 600, /* header + partial data */
        [](const char*, const uint8_t*, size_t, void*) -> bool {
            return true;
        }, nullptr);

    EXPECT_FALSE(ok);
}

/* ══════════════════════════════════════════════════════════════════ */
/* Engine integration tests                                           */
/* ══════════════════════════════════════════════════════════════════ */

/* ── EICAR in .gz → detected ─────────────────────────────────────── */

TEST_F(GzipTarScanTest, EicarInGzipDetected) {
    auto gz = gzip_compress((const uint8_t*)EICAR, EICAR_LEN);

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, gz.data(), gz.size(),
                                         "eicar.gz", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
    EXPECT_NE(strstr(result.malware_name, "EICAR"), nullptr);
}

/* ── EICAR in .tar → detected ────────────────────────────────────── */

TEST_F(GzipTarScanTest, EicarInTarDetected) {
    std::vector<uint8_t> eicar_data(EICAR, EICAR + EICAR_LEN);
    auto tar = build_tar({{"eicar.com", eicar_data}});

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, tar.data(), tar.size(),
                                         "eicar.tar", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
}

/* ── EICAR in .tar.gz → detected ─────────────────────────────────── */

TEST_F(GzipTarScanTest, EicarInTarGzDetected) {
    std::vector<uint8_t> eicar_data(EICAR, EICAR + EICAR_LEN);
    auto tar = build_tar({{"eicar.com", eicar_data}});
    auto gz = gzip_compress(tar.data(), tar.size());

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, gz.data(), gz.size(),
                                         "eicar.tar.gz", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
}

/* ── Clean .tar.gz → no detection ────────────────────────────────── */

TEST_F(GzipTarScanTest, CleanTarGzNotDetected) {
    auto tar = build_tar({
        {"readme.txt", {'H', 'e', 'l', 'l', 'o'}},
        {"data.bin", {0x00, 0x01, 0x02, 0x03}},
    });
    auto gz = gzip_compress(tar.data(), tar.size());

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, gz.data(), gz.size(),
                                         "clean.tar.gz", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 0);
}

/* ── Gzip bomb via engine → AKAV_ERROR_BOMB ──────────────────────── */

TEST_F(GzipTarScanTest, GzipBombReturnsBombError) {
    std::vector<uint8_t> zeros(10 * 1024 * 1024, 0);
    auto gz = gzip_compress(zeros.data(), zeros.size());

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, gz.data(), gz.size(),
                                         "bomb.gz", &opts, &result);
    EXPECT_EQ(err, AKAV_ERROR_BOMB);
}

/* ── EICAR in .gz with clean files in same tar → detected ────────── */

TEST_F(GzipTarScanTest, EicarAmongCleanInTarGz) {
    std::vector<uint8_t> eicar_data(EICAR, EICAR + EICAR_LEN);
    auto tar = build_tar({
        {"clean1.txt", {'A', 'B', 'C'}},
        {"eicar.com", eicar_data},
        {"clean2.txt", {'D', 'E', 'F'}},
    });
    auto gz = gzip_compress(tar.data(), tar.size());

    akav_scan_result_t result;
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);

    akav_error_t err = akav_scan_buffer(engine, gz.data(), gz.size(),
                                         "mixed.tar.gz", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
}
