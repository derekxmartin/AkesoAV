#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <cstring>

extern "C" {
#include "database/sigdb.h"
}

/* ── Helper: build a minimal valid .akavdb in memory ──────────────── */

class SigDbBuilder {
public:
    void set_magic(uint32_t m) { magic_ = m; }
    void set_version(uint32_t v) { version_ = v; }
    void set_signature_count(uint32_t c) { sig_count_ = c; }
    void set_created_at(int64_t t) { created_at_ = t; }

    /* Add a section. Data will be placed after the offset table. */
    void add_section(uint32_t type, const uint8_t* data, uint32_t size,
                     uint32_t entry_count)
    {
        Section s;
        s.type = type;
        s.data.assign(data, data + size);
        s.entry_count = entry_count;
        sections_.push_back(std::move(s));
    }

    /* Add a string table section from a vector of strings */
    void add_string_table(const std::vector<std::string>& strings)
    {
        std::vector<uint8_t> table;
        for (auto& s : strings) {
            table.insert(table.end(), s.begin(), s.end());
            table.push_back('\0');
        }
        add_section(AKAV_SECTION_STRING_TABLE, table.data(),
                    static_cast<uint32_t>(table.size()), 0);
    }

    std::vector<uint8_t> build() const
    {
        uint32_t section_count = static_cast<uint32_t>(sections_.size());
        size_t offset_table_size = section_count * 16; /* 16 bytes per entry */
        size_t data_start = AKAV_DB_HEADER_SIZE + offset_table_size;

        /* Calculate total size */
        size_t total = data_start;
        for (auto& s : sections_) total += s.data.size();

        std::vector<uint8_t> buf(total, 0);

        /* Write header */
        memcpy(buf.data() + 0, &magic_, 4);
        memcpy(buf.data() + 4, &version_, 4);
        memcpy(buf.data() + 8, &sig_count_, 4);
        memcpy(buf.data() + 12, &created_at_, 8);
        memcpy(buf.data() + 20, &section_count, 4);
        /* RSA signature at offset 0x18 is left as zeros (no verification) */

        /* Write section offset table + data */
        size_t current_offset = data_start;
        for (uint32_t i = 0; i < section_count; i++) {
            uint8_t* entry = buf.data() + AKAV_DB_HEADER_SIZE + i * 16;
            uint32_t off = static_cast<uint32_t>(current_offset);
            uint32_t sz = static_cast<uint32_t>(sections_[i].data.size());
            uint32_t ec = sections_[i].entry_count;

            memcpy(entry + 0, &sections_[i].type, 4);
            memcpy(entry + 4, &off, 4);
            memcpy(entry + 8, &sz, 4);
            memcpy(entry + 12, &ec, 4);

            if (sz > 0) {
                memcpy(buf.data() + current_offset,
                       sections_[i].data.data(), sz);
            }
            current_offset += sz;
        }

        return buf;
    }

private:
    uint32_t magic_ = AKAV_DB_MAGIC;
    uint32_t version_ = AKAV_DB_VERSION;
    uint32_t sig_count_ = 0;
    int64_t  created_at_ = 1700000000;

    struct Section {
        uint32_t type;
        std::vector<uint8_t> data;
        uint32_t entry_count;
    };
    std::vector<Section> sections_;
};

/* ── Fixture ──────────────────────────────────────────────────────── */

class SigDbTest : public ::testing::Test {
protected:
    akav_sigdb_t db{};
    char error[256] = {};

    void TearDown() override
    {
        akav_sigdb_close(&db);
    }
};

/* ── Basic open/close ─────────────────────────────────────────────── */

TEST_F(SigDbTest, OpenMinimalValid)
{
    SigDbBuilder b;
    auto buf = b.build();

    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)))
        << error;

    EXPECT_EQ(db.section_count, 0u);
    EXPECT_EQ(db.total_signatures, 0u);
    EXPECT_NE(db.created_at, 0);
}

TEST_F(SigDbTest, OpenWithSections)
{
    SigDbBuilder b;
    b.set_signature_count(5);

    /* Add a dummy bloom section */
    uint8_t bloom_data[64] = {};
    b.add_section(AKAV_SECTION_BLOOM, bloom_data, sizeof(bloom_data), 0);

    /* Add string table */
    b.add_string_table({"EICAR.Test", "Win32.Trojan.Generic"});

    auto buf = b.build();

    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)))
        << error;

    EXPECT_EQ(db.section_count, 2u);
    EXPECT_EQ(db.total_signatures, 5u);
}

TEST_F(SigDbTest, CloseNull)
{
    akav_sigdb_close(nullptr); /* must not crash */
}

TEST_F(SigDbTest, CloseZeroed)
{
    akav_sigdb_t empty{};
    akav_sigdb_close(&empty); /* zeroed struct, must not crash */
}

/* ── Section lookup ───────────────────────────────────────────────── */

TEST_F(SigDbTest, FindSectionByType)
{
    SigDbBuilder b;
    uint8_t data1[32] = {1};
    uint8_t data2[64] = {2};
    b.add_section(AKAV_SECTION_MD5, data1, sizeof(data1), 10);
    b.add_section(AKAV_SECTION_SHA256, data2, sizeof(data2), 20);
    auto buf = b.build();

    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)));

    const akav_db_section_entry_t* md5 =
        akav_sigdb_find_section(&db, AKAV_SECTION_MD5);
    ASSERT_NE(md5, nullptr);
    EXPECT_EQ(md5->entry_count, 10u);
    EXPECT_EQ(md5->size, 32u);

    const akav_db_section_entry_t* sha =
        akav_sigdb_find_section(&db, AKAV_SECTION_SHA256);
    ASSERT_NE(sha, nullptr);
    EXPECT_EQ(sha->entry_count, 20u);

    /* Non-existent section */
    EXPECT_EQ(akav_sigdb_find_section(&db, AKAV_SECTION_YARA), nullptr);
}

TEST_F(SigDbTest, SectionData)
{
    SigDbBuilder b;
    uint8_t marker[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    b.add_section(AKAV_SECTION_BLOOM, marker, sizeof(marker), 0);
    auto buf = b.build();

    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)));

    const akav_db_section_entry_t* sec =
        akav_sigdb_find_section(&db, AKAV_SECTION_BLOOM);
    ASSERT_NE(sec, nullptr);

    const uint8_t* data = akav_sigdb_section_data(&db, sec);
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(memcmp(data, marker, sizeof(marker)), 0);
}

/* ── String table ─────────────────────────────────────────────────── */

TEST_F(SigDbTest, StringTableLookup)
{
    SigDbBuilder b;
    b.add_string_table({"EICAR.Test", "Win32.Trojan.Generic", "Clean"});
    auto buf = b.build();

    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)));

    /* Index 0 = "EICAR.Test" */
    const char* s0 = akav_sigdb_lookup_string(&db, 0);
    ASSERT_NE(s0, nullptr);
    EXPECT_STREQ(s0, "EICAR.Test");

    /* Index 11 = "Win32.Trojan.Generic" (after "EICAR.Test\0") */
    const char* s1 = akav_sigdb_lookup_string(&db, 11);
    ASSERT_NE(s1, nullptr);
    EXPECT_STREQ(s1, "Win32.Trojan.Generic");

    /* Index 32 = "Clean" */
    const char* s2 = akav_sigdb_lookup_string(&db, 32);
    ASSERT_NE(s2, nullptr);
    EXPECT_STREQ(s2, "Clean");
}

TEST_F(SigDbTest, StringTableOutOfBounds)
{
    SigDbBuilder b;
    b.add_string_table({"test"});
    auto buf = b.build();

    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)));

    /* Way past end */
    EXPECT_EQ(akav_sigdb_lookup_string(&db, 9999), nullptr);
}

TEST_F(SigDbTest, StringTableNoTable)
{
    SigDbBuilder b;
    auto buf = b.build();

    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)));

    EXPECT_EQ(akav_sigdb_lookup_string(&db, 0), nullptr);
}

/* ── Validation: bad magic ────────────────────────────────────────── */

TEST_F(SigDbTest, RejectBadMagic)
{
    SigDbBuilder b;
    b.set_magic(0xDEADBEEF);
    auto buf = b.build();

    EXPECT_FALSE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                         nullptr, 0, error, sizeof(error)));
    EXPECT_NE(strstr(error, "magic"), nullptr);
}

/* ── Validation: bad version ──────────────────────────────────────── */

TEST_F(SigDbTest, RejectBadVersion)
{
    SigDbBuilder b;
    b.set_version(99);
    auto buf = b.build();

    EXPECT_FALSE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                         nullptr, 0, error, sizeof(error)));
    EXPECT_NE(strstr(error, "version"), nullptr);
}

/* ── Validation: truncated file ───────────────────────────────────── */

TEST_F(SigDbTest, RejectTruncatedHeader)
{
    uint8_t tiny[16] = {};
    EXPECT_FALSE(akav_sigdb_open_memory(&db, tiny, sizeof(tiny),
                                         nullptr, 0, error, sizeof(error)));
}

TEST_F(SigDbTest, RejectTruncatedSectionTable)
{
    SigDbBuilder b;
    uint8_t data[32] = {};
    b.add_section(AKAV_SECTION_MD5, data, sizeof(data), 1);
    auto buf = b.build();

    /* Truncate to just the header — section table won't fit */
    EXPECT_FALSE(akav_sigdb_open_memory(&db, buf.data(), AKAV_DB_HEADER_SIZE,
                                         nullptr, 0, error, sizeof(error)));
}

TEST_F(SigDbTest, RejectSectionPastFile)
{
    SigDbBuilder b;
    uint8_t data[32] = {};
    b.add_section(AKAV_SECTION_MD5, data, sizeof(data), 1);
    auto buf = b.build();

    /* Truncate so section data doesn't fit */
    size_t trunc_size = AKAV_DB_HEADER_SIZE + 16; /* header + 1 table entry, no data */
    EXPECT_FALSE(akav_sigdb_open_memory(&db, buf.data(), trunc_size,
                                         nullptr, 0, error, sizeof(error)));
}

/* ── Validation: null / empty ─────────────────────────────────────── */

TEST_F(SigDbTest, OpenMemoryNullArgs)
{
    EXPECT_FALSE(akav_sigdb_open_memory(nullptr, (const uint8_t*)"x", 1,
                                         nullptr, 0, error, sizeof(error)));

    EXPECT_FALSE(akav_sigdb_open_memory(&db, nullptr, 100,
                                         nullptr, 0, error, sizeof(error)));

    EXPECT_FALSE(akav_sigdb_open_memory(&db, (const uint8_t*)"x", 0,
                                         nullptr, 0, error, sizeof(error)));
}

/* ── Validation: excessive section count ──────────────────────────── */

TEST_F(SigDbTest, RejectExcessiveSectionCount)
{
    SigDbBuilder b;
    auto buf = b.build();

    /* Patch section_count to 300 (> 256 limit) */
    uint32_t bad_count = 300;
    memcpy(buf.data() + 20, &bad_count, 4);

    EXPECT_FALSE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                         nullptr, 0, error, sizeof(error)));
}

/* ── Multiple section types ───────────────────────────────────────── */

TEST_F(SigDbTest, AllSectionTypes)
{
    SigDbBuilder b;
    b.set_signature_count(100);

    uint8_t dummy[16] = {};
    b.add_section(AKAV_SECTION_BLOOM, dummy, sizeof(dummy), 0);
    b.add_section(AKAV_SECTION_MD5, dummy, sizeof(dummy), 10);
    b.add_section(AKAV_SECTION_SHA256, dummy, sizeof(dummy), 20);
    b.add_section(AKAV_SECTION_CRC32, dummy, sizeof(dummy), 5);
    b.add_section(AKAV_SECTION_AHO_CORASICK, dummy, sizeof(dummy), 30);
    b.add_section(AKAV_SECTION_WHITELIST, dummy, sizeof(dummy), 35);
    b.add_string_table({"test"});

    auto buf = b.build();

    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)))
        << error;

    EXPECT_EQ(db.section_count, 7u);
    EXPECT_NE(akav_sigdb_find_section(&db, AKAV_SECTION_BLOOM), nullptr);
    EXPECT_NE(akav_sigdb_find_section(&db, AKAV_SECTION_MD5), nullptr);
    EXPECT_NE(akav_sigdb_find_section(&db, AKAV_SECTION_SHA256), nullptr);
    EXPECT_NE(akav_sigdb_find_section(&db, AKAV_SECTION_CRC32), nullptr);
    EXPECT_NE(akav_sigdb_find_section(&db, AKAV_SECTION_AHO_CORASICK), nullptr);
    EXPECT_NE(akav_sigdb_find_section(&db, AKAV_SECTION_WHITELIST), nullptr);

    /* String table accessible */
    EXPECT_NE(akav_sigdb_lookup_string(&db, 0), nullptr);
}

/* ── Adversarial ──────────────────────────────────────────────────── */

TEST_F(SigDbTest, SectionDataNull)
{
    EXPECT_EQ(akav_sigdb_section_data(nullptr, nullptr), nullptr);
    EXPECT_EQ(akav_sigdb_section_data(&db, nullptr), nullptr);
}

TEST_F(SigDbTest, FindSectionNull)
{
    EXPECT_EQ(akav_sigdb_find_section(nullptr, AKAV_SECTION_MD5), nullptr);
}

TEST_F(SigDbTest, StringTableMissingNullTerminator)
{
    SigDbBuilder b;
    /* Manually craft a string table without null terminators */
    uint8_t bad_table[] = {'A', 'B', 'C', 'D', 'E'};
    b.add_section(AKAV_SECTION_STRING_TABLE, bad_table, sizeof(bad_table), 0);
    auto buf = b.build();

    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)));

    /* Should return NULL because no null terminator within bounds */
    EXPECT_EQ(akav_sigdb_lookup_string(&db, 0), nullptr);
}

TEST_F(SigDbTest, OverlappingSections)
{
    /* Craft sections where offsets overlap. The builder doesn't do this
       naturally, so we patch the buffer manually. */
    SigDbBuilder b;
    uint8_t data1[64] = {};
    uint8_t data2[64] = {};
    b.add_section(AKAV_SECTION_MD5, data1, sizeof(data1), 1);
    b.add_section(AKAV_SECTION_SHA256, data2, sizeof(data2), 1);
    auto buf = b.build();

    /* Make section 2's offset point into section 1's data */
    uint32_t section1_offset;
    memcpy(&section1_offset, buf.data() + AKAV_DB_HEADER_SIZE + 4, 4);
    /* Point section 2 to section 1's offset + 8 (overlap) */
    uint32_t overlapping = section1_offset + 8;
    memcpy(buf.data() + AKAV_DB_HEADER_SIZE + 16 + 4, &overlapping, 4);

    /* Should still open (overlapping is technically valid in mmap) */
    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)));
}

TEST_F(SigDbTest, ZeroSizeSection)
{
    SigDbBuilder b;
    b.add_section(AKAV_SECTION_BLOOM, nullptr, 0, 0);
    auto buf = b.build();

    /* Patch the offset to point to header area but size is 0 — should be OK */
    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)));

    const akav_db_section_entry_t* sec =
        akav_sigdb_find_section(&db, AKAV_SECTION_BLOOM);
    ASSERT_NE(sec, nullptr);
    EXPECT_EQ(sec->size, 0u);
}

TEST_F(SigDbTest, FileOpenNonexistent)
{
    EXPECT_FALSE(akav_sigdb_open(&db,
        "C:\\nonexistent\\path\\to\\fake.akavdb",
        nullptr, 0, error, sizeof(error)));
    EXPECT_NE(strstr(error, "open"), nullptr);
}

TEST_F(SigDbTest, CreatedAtPreserved)
{
    SigDbBuilder b;
    b.set_created_at(1234567890);
    auto buf = b.build();

    ASSERT_TRUE(akav_sigdb_open_memory(&db, buf.data(), buf.size(),
                                        nullptr, 0, error, sizeof(error)));
    EXPECT_EQ(db.created_at, 1234567890);
}