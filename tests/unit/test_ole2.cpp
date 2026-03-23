// test_ole2.cpp -- Tests for OLE2 parser.
//
// Tests cover:
//   - Null/truncated/bad-magic input rejection
//   - Minimal valid OLE2 parsing (header fields, directory entries)
//   - Stream extraction (regular and mini-stream)
//   - Multiple streams
//   - Entry lookup (including case-insensitive and null safety)
//   - Circular FAT chain detection
//   - OVBA decompression (literal, compressed, copy-token, bad input)
//   - VBA extraction from OLE2 container
//   - Analyze convenience function
//   - Free safety (zeroed, partial parse, double free)
//   - Edge cases (large stream size, empty stream, storage entries)
//   - Header version variants (v3 and v4)

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <cstdint>

extern "C" {
#include "parsers/ole2.h"
}

// ── OLE2 Builder ──────────────────────────────────────────────────

class Ole2Builder {
    std::vector<uint8_t> data_;
    uint32_t sector_size_ = 512;

public:
    void put_u16(size_t off, uint16_t v) {
        if (off + 2 > data_.size()) data_.resize(off + 2, 0);
        data_[off + 0] = static_cast<uint8_t>(v & 0xFF);
        data_[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    }

    void put_u32(size_t off, uint32_t v) {
        if (off + 4 > data_.size()) data_.resize(off + 4, 0);
        data_[off + 0] = static_cast<uint8_t>(v & 0xFF);
        data_[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        data_[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        data_[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    }

    void put_u64(size_t off, uint64_t v) {
        put_u32(off, static_cast<uint32_t>(v & 0xFFFFFFFFU));
        put_u32(off + 4, static_cast<uint32_t>((v >> 32) & 0xFFFFFFFFU));
    }

    // Write a UTF-16LE name into a 64-byte buffer and return name size in bytes
    // (including null terminator).
    static void write_name_utf16le(uint8_t* dest, const char* name,
                                   uint16_t* out_name_size) {
        std::memset(dest, 0, 64);
        size_t len = std::strlen(name);
        if (len > 31) len = 31; // max 31 chars + null
        for (size_t i = 0; i < len; i++) {
            dest[i * 2]     = static_cast<uint8_t>(name[i]);
            dest[i * 2 + 1] = 0;
        }
        // null terminator already there from memset
        *out_name_size = static_cast<uint16_t>((len + 1) * 2);
    }

    // Write a 128-byte directory entry at the given offset in data_.
    void write_dir_entry(size_t offset, const char* name, uint8_t obj_type,
                         uint32_t start_sector, uint64_t stream_size,
                         uint32_t child_sid  = 0xFFFFFFFFU,
                         uint32_t left_sid   = 0xFFFFFFFFU,
                         uint32_t right_sid  = 0xFFFFFFFFU) {
        if (offset + 128 > data_.size()) data_.resize(offset + 128, 0);
        std::memset(&data_[offset], 0, 128);

        uint16_t name_size = 0;
        write_name_utf16le(&data_[offset], name, &name_size);
        put_u16(offset + 64, name_size);

        data_[offset + 66] = obj_type;
        data_[offset + 67] = 1; // color = black

        put_u32(offset + 68, left_sid);
        put_u32(offset + 72, right_sid);
        put_u32(offset + 76, child_sid);

        // CLSID, state bits, timestamps: leave zero
        put_u32(offset + 116, start_sector);
        put_u32(offset + 120, static_cast<uint32_t>(stream_size & 0xFFFFFFFFU));
        put_u32(offset + 124, static_cast<uint32_t>((stream_size >> 32) & 0xFFFFFFFFU));
    }

    // Write the standard OLE2 header at offset 0.
    // sector_size_power: 9 for 512, 12 for 4096.
    void write_header(uint16_t major_version, uint16_t sector_size_power,
                      uint32_t num_fat_sectors, uint32_t dir_start_sector,
                      uint32_t minifat_start = 0xFFFFFFFEU,
                      uint32_t num_minifat   = 0,
                      uint32_t difat_start   = 0xFFFFFFFEU,
                      uint32_t num_difat     = 0) {
        uint32_t actual_sector_size = 1U << sector_size_power;
        sector_size_ = actual_sector_size;

        if (data_.size() < actual_sector_size)
            data_.resize(actual_sector_size, 0);

        // Magic: D0 CF 11 E0 A1 B1 1A E1
        static const uint8_t magic[] = {
            0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1
        };
        std::memcpy(&data_[0], magic, 8);
        // Bytes 8-23: CLSID (16 bytes, all zeros — already zeroed)

        put_u16(24, 0x003E);               // minor version
        put_u16(26, major_version);         // major version
        put_u16(28, 0xFFFE);               // byte order (little-endian)
        put_u16(30, sector_size_power);     // sector size power
        put_u16(32, 0x0006);               // mini sector size power (64)
        // 34-39: reserved (zero)
        // 40-43: total sectors (zero for v3)
        put_u32(44, num_fat_sectors);
        put_u32(48, dir_start_sector);
        // 52-55: transaction signature (zero)
        put_u32(56, 0x00001000);           // mini stream cutoff = 4096
        put_u32(60, minifat_start);
        put_u32(64, num_minifat);
        put_u32(68, difat_start);
        put_u32(72, num_difat);

        // DIFAT array: 109 entries at offset 76, all FREESECT by default
        for (uint32_t i = 0; i < 109; i++) {
            put_u32(76 + i * 4, AKAV_OLE2_FREESECT);
        }
    }

    // Set a DIFAT entry in the header (index 0..108).
    void set_difat(uint32_t index, uint32_t sector_id) {
        put_u32(76 + index * 4, sector_id);
    }

    // Get offset of a sector by its SID.
    size_t sector_offset(uint32_t sid) const {
        return static_cast<size_t>(sector_size_) * (sid + 1);
    }

    // Ensure the data vector covers through the end of sector sid.
    void ensure_sector(uint32_t sid) {
        size_t needed = sector_offset(sid) + sector_size_;
        if (data_.size() < needed)
            data_.resize(needed, 0);
    }

    // Write a FAT entry: fat_sector is the sector containing the FAT,
    // entry_index is the index within that sector.
    void write_fat_entry(uint32_t fat_sector, uint32_t entry_index,
                         uint32_t value) {
        size_t off = sector_offset(fat_sector) + entry_index * 4;
        put_u32(off, value);
    }

    // Fill a FAT sector with FREESECT.
    void fill_fat_sector(uint32_t fat_sector) {
        ensure_sector(fat_sector);
        uint32_t entries_per_sector = sector_size_ / 4;
        for (uint32_t i = 0; i < entries_per_sector; i++) {
            write_fat_entry(fat_sector, i, AKAV_OLE2_FREESECT);
        }
    }

    // Write stream data into a sector.
    void write_sector_data(uint32_t sid, const uint8_t* src, size_t len) {
        ensure_sector(sid);
        size_t off = sector_offset(sid);
        size_t copy_len = len < sector_size_ ? len : sector_size_;
        std::memcpy(&data_[off], src, copy_len);
    }

    // Write mini-FAT entries into a sector.
    void write_minifat_entry(uint32_t minifat_sector, uint32_t entry_index,
                             uint32_t value) {
        size_t off = sector_offset(minifat_sector) + entry_index * 4;
        put_u32(off, value);
    }

    // Access the raw data.
    std::vector<uint8_t>& raw() { return data_; }
    const std::vector<uint8_t>& raw() const { return data_; }
    const uint8_t* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }

    // ── Build helpers ─────────────────────────────────────────────

    // Build a minimal valid OLE2: header + 1 FAT sector + 1 directory sector
    // with just a Root Entry.
    // Layout:
    //   Sector -1 (offset 0):    Header
    //   Sector 0  (offset 512):  FAT
    //   Sector 1  (offset 1024): Directory (Root Entry + 3 empty)
    std::vector<uint8_t> build_minimal() {
        data_.clear();

        write_header(0x0003, 9, 1, 1);
        set_difat(0, 0); // FAT is in sector 0

        // FAT sector
        fill_fat_sector(0);
        write_fat_entry(0, 0, AKAV_OLE2_FATSECT);     // sector 0 = FAT
        write_fat_entry(0, 1, AKAV_OLE2_ENDOFCHAIN);  // sector 1 = dir (end)

        // Directory sector
        ensure_sector(1);
        // Root Entry at SID 0
        write_dir_entry(sector_offset(1), "Root Entry",
                        AKAV_OLE2_OBJTYPE_ROOT,
                        AKAV_OLE2_ENDOFCHAIN, 0);

        return data_;
    }

    // Build an OLE2 with one data stream.
    // Layout:
    //   Sector -1 (offset 0):    Header
    //   Sector 0  (offset 512):  FAT
    //   Sector 1  (offset 1024): Directory
    //   Sector 2  (offset 1536): Stream data
    std::vector<uint8_t> build_with_stream(const char* stream_name,
                                            const uint8_t* stream_data,
                                            size_t stream_len) {
        data_.clear();

        write_header(0x0003, 9, 1, 1);
        set_difat(0, 0);

        // FAT
        fill_fat_sector(0);
        write_fat_entry(0, 0, AKAV_OLE2_FATSECT);
        write_fat_entry(0, 1, AKAV_OLE2_ENDOFCHAIN);  // dir
        write_fat_entry(0, 2, AKAV_OLE2_ENDOFCHAIN);  // stream data

        // Directory
        ensure_sector(1);
        // Root Entry points to first child (SID 1)
        write_dir_entry(sector_offset(1), "Root Entry",
                        AKAV_OLE2_OBJTYPE_ROOT,
                        AKAV_OLE2_ENDOFCHAIN, 0,
                        1);  // child_sid = 1
        // Stream entry at dir SID 1
        write_dir_entry(sector_offset(1) + 128, stream_name,
                        AKAV_OLE2_OBJTYPE_STREAM,
                        2, stream_len);

        // Stream data
        ensure_sector(2);
        if (stream_data && stream_len > 0) {
            write_sector_data(2, stream_data, stream_len);
        }

        return data_;
    }

    // Build an OLE2 with a mini-stream.
    // Mini-stream data lives inside the root entry's stream (the mini-stream
    // container). The root entry's start_sector points to the container sector.
    // Mini-FAT maps mini-sector IDs within the container.
    // Layout:
    //   Sector 0: FAT
    //   Sector 1: Directory
    //   Sector 2: Mini-FAT
    //   Sector 3: Mini-stream container (root entry's data)
    std::vector<uint8_t> build_with_mini_stream(const char* stream_name,
                                                 const uint8_t* stream_data,
                                                 size_t stream_len) {
        data_.clear();

        write_header(0x0003, 9, 1, 1,
                     2,  // minifat_start = sector 2
                     1); // num_minifat = 1
        set_difat(0, 0);

        // FAT
        fill_fat_sector(0);
        write_fat_entry(0, 0, AKAV_OLE2_FATSECT);
        write_fat_entry(0, 1, AKAV_OLE2_ENDOFCHAIN);  // dir
        write_fat_entry(0, 2, AKAV_OLE2_ENDOFCHAIN);  // mini-FAT
        write_fat_entry(0, 3, AKAV_OLE2_ENDOFCHAIN);  // mini-stream container

        // Directory
        ensure_sector(1);
        // Root Entry: start_sector=3 (container), stream_size = container size
        // Container must be large enough to hold the mini-stream data.
        // Mini-sectors are 64 bytes each.
        uint32_t mini_sectors_needed = static_cast<uint32_t>(
            (stream_len + 63) / 64);
        uint64_t container_size = static_cast<uint64_t>(mini_sectors_needed) * 64;

        write_dir_entry(sector_offset(1), "Root Entry",
                        AKAV_OLE2_OBJTYPE_ROOT,
                        3, container_size,
                        1); // child_sid = 1
        // Stream entry: start_sector=0 (mini-sector 0), size < 4096
        write_dir_entry(sector_offset(1) + 128, stream_name,
                        AKAV_OLE2_OBJTYPE_STREAM,
                        0, stream_len);

        // Mini-FAT sector: chain the mini-sectors
        ensure_sector(2);
        // Fill with FREESECT
        for (uint32_t i = 0; i < sector_size_ / 4; i++) {
            write_minifat_entry(2, i, AKAV_OLE2_FREESECT);
        }
        // Chain mini-sectors: 0->1->...->ENDOFCHAIN
        for (uint32_t i = 0; i < mini_sectors_needed; i++) {
            uint32_t next = (i + 1 < mini_sectors_needed)
                            ? (i + 1) : AKAV_OLE2_ENDOFCHAIN;
            write_minifat_entry(2, i, next);
        }

        // Mini-stream container (sector 3): write stream data
        ensure_sector(3);
        if (stream_data && stream_len > 0) {
            write_sector_data(3, stream_data, stream_len);
        }

        return data_;
    }

    // Build an OLE2 with multiple streams.
    struct StreamDef {
        const char* name;
        std::vector<uint8_t> data;
    };

    std::vector<uint8_t> build_with_streams(const std::vector<StreamDef>& streams) {
        data_.clear();

        // Layout:
        //   Sector 0: FAT
        //   Sector 1: Directory
        //   Sector 2..N: stream data (one sector per stream for simplicity)
        uint32_t num_data_sectors = static_cast<uint32_t>(streams.size());

        write_header(0x0003, 9, 1, 1);
        set_difat(0, 0);

        // FAT
        fill_fat_sector(0);
        write_fat_entry(0, 0, AKAV_OLE2_FATSECT);
        write_fat_entry(0, 1, AKAV_OLE2_ENDOFCHAIN); // dir

        for (uint32_t i = 0; i < num_data_sectors; i++) {
            write_fat_entry(0, 2 + i, AKAV_OLE2_ENDOFCHAIN);
        }

        // Directory
        ensure_sector(1);
        // Root Entry: child_sid = 1 (first stream)
        write_dir_entry(sector_offset(1), "Root Entry",
                        AKAV_OLE2_OBJTYPE_ROOT,
                        AKAV_OLE2_ENDOFCHAIN, 0,
                        1); // child_sid

        // Build a simple BST: first stream is root of tree, others linked
        // via right sibling.
        for (uint32_t i = 0; i < num_data_sectors; i++) {
            uint32_t right = (i + 1 < num_data_sectors)
                             ? (i + 2) : 0xFFFFFFFFU;
            write_dir_entry(
                sector_offset(1) + static_cast<size_t>((i + 1)) * 128,
                streams[i].name,
                AKAV_OLE2_OBJTYPE_STREAM,
                2 + i,
                streams[i].data.size(),
                0xFFFFFFFFU,  // child
                0xFFFFFFFFU,  // left
                right);       // right sibling
        }

        // Stream data sectors
        for (uint32_t i = 0; i < num_data_sectors; i++) {
            ensure_sector(2 + i);
            if (!streams[i].data.empty()) {
                write_sector_data(2 + i, streams[i].data.data(),
                                  streams[i].data.size());
            }
        }

        return data_;
    }
};

// ── Null / invalid input tests ────────────────────────────────────

TEST(OLE2Parse, NullInput) {
    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    EXPECT_FALSE(akav_ole2_parse(&ole2, nullptr, 0));
    EXPECT_FALSE(ole2.valid);
}

TEST(OLE2Parse, TooSmall) {
    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    uint8_t small[256] = {};
    EXPECT_FALSE(akav_ole2_parse(&ole2, small, sizeof(small)));
    EXPECT_FALSE(ole2.valid);
}

TEST(OLE2Parse, BadMagic) {
    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    std::vector<uint8_t> data(1024, 0);
    // Wrong magic
    data[0] = 0xDE; data[1] = 0xAD;
    EXPECT_FALSE(akav_ole2_parse(&ole2, data.data(), data.size()));
    EXPECT_FALSE(ole2.valid);
}

// ── Minimal valid OLE2 ───────────────────────────────────────────

TEST(OLE2Parse, MinimalValid) {
    Ole2Builder builder;
    auto data = builder.build_minimal();

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));
    EXPECT_TRUE(ole2.valid);

    // Check header fields
    EXPECT_EQ(ole2.header.major_version, 0x0003);
    EXPECT_EQ(ole2.header.minor_version, 0x003E);
    EXPECT_EQ(ole2.header.sector_size, 512);
    EXPECT_EQ(ole2.header.mini_sector_size, 64);
    EXPECT_EQ(ole2.header.num_fat_sectors, 1u);
    EXPECT_EQ(ole2.header.dir_start_sector, 1u);
    EXPECT_EQ(ole2.header.mini_stream_cutoff, 0x1000u);

    // Should have at least the root directory entry
    EXPECT_GE(ole2.num_dir_entries, 1u);

    akav_ole2_free(&ole2);
}

// ── Directory entry names ─────────────────────────────────────────

TEST(OLE2Parse, DirectoryEntryNames) {
    Ole2Builder builder;
    const char* test_content = "Hello, OLE2!";
    auto data = builder.build_with_stream(
        "TestStream",
        reinterpret_cast<const uint8_t*>(test_content),
        std::strlen(test_content));

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));
    EXPECT_TRUE(ole2.valid);

    // Should have at least 2 directory entries (Root Entry + TestStream)
    ASSERT_GE(ole2.num_dir_entries, 2u);

    bool found_root = false;
    bool found_test = false;
    for (uint32_t i = 0; i < ole2.num_dir_entries; i++) {
        if (std::strcmp(ole2.dir_entries[i].name, "Root Entry") == 0)
            found_root = true;
        if (std::strcmp(ole2.dir_entries[i].name, "TestStream") == 0)
            found_test = true;
    }
    EXPECT_TRUE(found_root);
    EXPECT_TRUE(found_test);

    akav_ole2_free(&ole2);
}

// ── Stream extraction ─────────────────────────────────────────────

TEST(OLE2Stream, StreamExtraction) {
    Ole2Builder builder;
    const char* test_content = "Hello, OLE2!";
    size_t content_len = std::strlen(test_content);
    auto data = builder.build_with_stream(
        "TestStream",
        reinterpret_cast<const uint8_t*>(test_content),
        content_len);

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));
    ASSERT_TRUE(akav_ole2_extract_streams(&ole2, data.data(), data.size()));

    // Find the TestStream in extracted streams
    bool found = false;
    for (uint32_t i = 0; i < ole2.num_streams; i++) {
        if (std::strcmp(ole2.streams[i].name, "TestStream") == 0) {
            found = true;
            EXPECT_EQ(ole2.streams[i].data_len, content_len);
            if (ole2.streams[i].data && ole2.streams[i].data_len >= content_len) {
                EXPECT_EQ(std::memcmp(ole2.streams[i].data, test_content,
                                       content_len), 0);
            }
            break;
        }
    }
    EXPECT_TRUE(found);

    akav_ole2_free(&ole2);
}

// ── Mini-stream extraction ────────────────────────────────────────

TEST(OLE2Stream, MiniStreamExtraction) {
    Ole2Builder builder;
    // Data smaller than mini_stream_cutoff (4096)
    const char* test_content = "Mini stream data here!";
    size_t content_len = std::strlen(test_content);
    auto data = builder.build_with_mini_stream(
        "MiniStream",
        reinterpret_cast<const uint8_t*>(test_content),
        content_len);

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));
    ASSERT_TRUE(akav_ole2_extract_streams(&ole2, data.data(), data.size()));

    bool found = false;
    for (uint32_t i = 0; i < ole2.num_streams; i++) {
        if (std::strcmp(ole2.streams[i].name, "MiniStream") == 0) {
            found = true;
            EXPECT_EQ(ole2.streams[i].data_len, content_len);
            EXPECT_TRUE(ole2.streams[i].is_mini);
            if (ole2.streams[i].data && ole2.streams[i].data_len >= content_len) {
                EXPECT_EQ(std::memcmp(ole2.streams[i].data, test_content,
                                       content_len), 0);
            }
            break;
        }
    }
    EXPECT_TRUE(found);

    akav_ole2_free(&ole2);
}

// ── Multiple streams ──────────────────────────────────────────────

TEST(OLE2Stream, MultipleStreams) {
    Ole2Builder builder;

    std::vector<Ole2Builder::StreamDef> streams;

    const char* d1 = "Stream One Data";
    const char* d2 = "Second Stream Content!";
    const char* d3 = "Third-and-final-stream";

    Ole2Builder::StreamDef s1;
    s1.name = "StreamOne";
    s1.data.assign(reinterpret_cast<const uint8_t*>(d1),
                   reinterpret_cast<const uint8_t*>(d1) + std::strlen(d1));

    Ole2Builder::StreamDef s2;
    s2.name = "StreamTwo";
    s2.data.assign(reinterpret_cast<const uint8_t*>(d2),
                   reinterpret_cast<const uint8_t*>(d2) + std::strlen(d2));

    Ole2Builder::StreamDef s3;
    s3.name = "StreamThree";
    s3.data.assign(reinterpret_cast<const uint8_t*>(d3),
                   reinterpret_cast<const uint8_t*>(d3) + std::strlen(d3));

    streams.push_back(s1);
    streams.push_back(s2);
    streams.push_back(s3);

    auto data = builder.build_with_streams(streams);

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));
    ASSERT_TRUE(akav_ole2_extract_streams(&ole2, data.data(), data.size()));

    // All three streams should be extracted
    uint32_t found_count = 0;
    for (uint32_t i = 0; i < ole2.num_streams; i++) {
        for (size_t j = 0; j < streams.size(); j++) {
            if (std::strcmp(ole2.streams[i].name, streams[j].name) == 0) {
                EXPECT_EQ(ole2.streams[i].data_len, streams[j].data.size());
                if (ole2.streams[i].data &&
                    ole2.streams[i].data_len == streams[j].data.size()) {
                    EXPECT_EQ(std::memcmp(ole2.streams[i].data,
                                           streams[j].data.data(),
                                           streams[j].data.size()), 0);
                }
                found_count++;
                break;
            }
        }
    }
    EXPECT_EQ(found_count, 3u);

    akav_ole2_free(&ole2);
}

// ── Find entry ────────────────────────────────────────────────────

TEST(OLE2Find, FindEntry) {
    Ole2Builder builder;
    const char* content = "test";
    auto data = builder.build_with_stream(
        "TestStream",
        reinterpret_cast<const uint8_t*>(content), 4);

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));

    // Exact match
    const akav_ole2_dir_entry_t* entry =
        akav_ole2_find_entry(&ole2, "TestStream");
    EXPECT_NE(entry, nullptr);
    if (entry) {
        EXPECT_EQ(entry->obj_type, AKAV_OLE2_OBJTYPE_STREAM);
    }

    // Case-insensitive match
    const akav_ole2_dir_entry_t* entry_ci =
        akav_ole2_find_entry(&ole2, "teststream");
    EXPECT_NE(entry_ci, nullptr);

    // Non-existent name
    const akav_ole2_dir_entry_t* missing =
        akav_ole2_find_entry(&ole2, "NoSuchStream");
    EXPECT_EQ(missing, nullptr);

    akav_ole2_free(&ole2);
}

TEST(OLE2Find, FindEntryNull) {
    // Null ole2
    const akav_ole2_dir_entry_t* entry =
        akav_ole2_find_entry(nullptr, "test");
    EXPECT_EQ(entry, nullptr);

    // Null name
    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    entry = akav_ole2_find_entry(&ole2, nullptr);
    EXPECT_EQ(entry, nullptr);
}

// ── Circular FAT ──────────────────────────────────────────────────

TEST(OLE2Parse, CircularFAT) {
    Ole2Builder builder;
    builder.build_minimal();

    // Modify FAT so sector 2 -> sector 3 -> sector 2 (circular)
    builder.ensure_sector(3);
    builder.write_fat_entry(0, 2, 3);
    builder.write_fat_entry(0, 3, 2);

    // Add a directory entry that uses sector 2 as its start
    // (re-write directory in sector 1)
    builder.write_dir_entry(builder.sector_offset(1), "Root Entry",
                            AKAV_OLE2_OBJTYPE_ROOT,
                            AKAV_OLE2_ENDOFCHAIN, 0, 1);
    builder.write_dir_entry(builder.sector_offset(1) + 128, "BadStream",
                            AKAV_OLE2_OBJTYPE_STREAM,
                            2, 1024);

    auto& data = builder.raw();

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));

    // Parse should succeed (FAT itself is built from DIFAT, not by following chains)
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));

    // Stream extraction should not hang -- the chain follower has a max length
    // It may fail or succeed partially, but must not hang.
    akav_ole2_extract_streams(&ole2, data.data(), data.size());

    akav_ole2_free(&ole2);
}

// ── OVBA decompression tests ──────────────────────────────────────

TEST(OLE2OVBA, DecompressLiteral) {
    // OVBA compressed container: signature byte + uncompressed chunk.
    // Chunk header: 2 bytes, little-endian.
    //   Bits 0-11: chunk size - 3
    //   Bit 12: 0 = uncompressed
    //   Bits 13-15: 0b011 (signature)
    // An uncompressed chunk is 4096 bytes of raw data.

    std::vector<uint8_t> input;
    input.push_back(0x01); // signature byte

    // Build 4096 bytes of test data
    std::vector<uint8_t> raw_data(4096);
    for (size_t i = 0; i < 4096; i++) {
        raw_data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    // Chunk header: size = 4096 - 3 = 4093 = 0x0FFD
    // Flags: uncompressed = bit 12 clear, signature = 0b011 << 13
    // header = 0x0FFD | (0 << 12) | (0x3 << 13) = 0x0FFD | 0x6000 = 0x6FFD
    uint16_t chunk_header = 0x6FFD;
    input.push_back(static_cast<uint8_t>(chunk_header & 0xFF));
    input.push_back(static_cast<uint8_t>((chunk_header >> 8) & 0xFF));

    input.insert(input.end(), raw_data.begin(), raw_data.end());

    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_ole2_ovba_decompress(input.data(), input.size(),
                                           &out, &out_len));
    ASSERT_EQ(out_len, 4096u);
    EXPECT_EQ(std::memcmp(out, raw_data.data(), 4096), 0);
    std::free(out);
}

TEST(OLE2OVBA, DecompressCompressed) {
    // Build a compressed chunk with FlagByte = 0x00 (all 8 tokens are literals).
    // Signature 0x01, then chunk header with compressed flag set.

    std::vector<uint8_t> input;
    input.push_back(0x01); // signature

    // We will create a chunk with 8 literal bytes following a FlagByte of 0x00.
    // Compressed chunk data: FlagByte(0x00) + 8 literal bytes = 9 bytes.
    // Chunk size = 9 bytes. Chunk header size field = 9 - 3 = 6.
    // header = 6 | (0x3 << 12) | (1 << 15) = 0x0006 | 0x3000 | 0x8000 = 0xB006
    uint16_t chunk_header = 0xB006;
    input.push_back(static_cast<uint8_t>(chunk_header & 0xFF));
    input.push_back(static_cast<uint8_t>((chunk_header >> 8) & 0xFF));

    // FlagByte: 0x00 = all literals
    input.push_back(0x00);

    // 8 literal bytes
    const uint8_t literals[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' };
    input.insert(input.end(), literals, literals + 8);

    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_ole2_ovba_decompress(input.data(), input.size(),
                                           &out, &out_len));
    ASSERT_EQ(out_len, 8u);
    EXPECT_EQ(std::memcmp(out, literals, 8), 0);
    std::free(out);
}

TEST(OLE2OVBA, DecompressWithCopyToken) {
    // Build a compressed chunk that copies previously decompressed data.
    // First emit some literal bytes, then use a CopyToken to repeat them.
    //
    // Decompressed output should be: "AAAA" (emit 'A' literal, then copy it 3x).
    //
    // Compressed chunk layout:
    //   FlagByte #1 = 0x00: next 8 tokens are literals
    //     -> emit 'A', 'A', 'A', 'A', (pad 4 more literals, say 'B','B','B','B')
    //
    // Simpler approach: use two FlagByte groups.
    // FlagByte #1 = 0x00: 8 literal tokens -> "ABCDABCD"
    // FlagByte #2 = 0x01: bit0=1 => CopyToken, bits1-7=0 => 7 more literals
    //   CopyToken: offset=5 (back to first 'A'...'D'), length=4
    //
    // Actually, the simplest test: emit 2 literal 'A's via FlagByte=0x00,
    // then a CopyToken that copies from offset 1, length 3.
    //
    // For VBA compression, CopyToken is 2 bytes. The bit packing depends on
    // the current decompressed chunk offset. At offset < 16, the token uses
    // 12 bits for offset and 4 bits for length.
    //
    // CopyToken format (at decompressed offset d):
    //   number of bits for length = max(ceil(log2(d)), 4)
    //   For d in [2..15]: length bits = 4, offset bits = 12
    //   Token = ((offset-1) << 4) | (length - 3)
    //
    // After emitting 2 'A' literals (d=2):
    //   length bits = 4, offset bits = 12
    //   offset = 1 (copy from 1 byte back), length = 3
    //   Token = ((1-1) << 4) | (3-3) = 0x0000
    //
    // So the chunk is:
    //   FlagByte = 0x04 = bit2 set (third token is a CopyToken)
    //     Token 0: literal 'A'
    //     Token 1: literal 'A'
    //     Token 2: CopyToken 0x0000 (2 bytes)
    //   That's 3 tokens out of 8. Remaining 5 need more data or we end the chunk.
    //
    // Total data after FlagByte: 1 + 1 + 2 = 4 bytes.
    // Chunk data size = 1 (FlagByte) + 4 = 5 bytes.
    // Chunk header size = 5 - 3 = 2.
    // header = 2 | (0x3 << 12) | (1 << 15) = 0xB002

    std::vector<uint8_t> input;
    input.push_back(0x01); // signature

    uint16_t chunk_header = 0xB002;
    input.push_back(static_cast<uint8_t>(chunk_header & 0xFF));
    input.push_back(static_cast<uint8_t>((chunk_header >> 8) & 0xFF));

    // FlagByte: bit2 = 1 (CopyToken at position 2), rest = 0 (literals)
    input.push_back(0x04);

    // Token 0: literal 'A'
    input.push_back('A');
    // Token 1: literal 'A'
    input.push_back('A');
    // Token 2: CopyToken = 0x0000 -> offset=1, length=3
    input.push_back(0x00);
    input.push_back(0x00);

    uint8_t* out = nullptr;
    size_t out_len = 0;
    ASSERT_TRUE(akav_ole2_ovba_decompress(input.data(), input.size(),
                                           &out, &out_len));
    // Expected: 'A','A' + copy(offset=1, len=3) = "AAAAA"
    ASSERT_EQ(out_len, 5u);
    for (size_t i = 0; i < out_len; i++) {
        EXPECT_EQ(out[i], 'A');
    }
    std::free(out);
}

TEST(OLE2OVBA, DecompressNull) {
    uint8_t* out = nullptr;
    size_t out_len = 0;

    // Null input
    EXPECT_FALSE(akav_ole2_ovba_decompress(nullptr, 10, &out, &out_len));

    // Zero length
    uint8_t dummy = 0x01;
    EXPECT_FALSE(akav_ole2_ovba_decompress(&dummy, 0, &out, &out_len));

    // Just 1 byte (signature only, no chunks)
    EXPECT_FALSE(akav_ole2_ovba_decompress(&dummy, 1, &out, &out_len));
}

TEST(OLE2OVBA, BadSignature) {
    // Signature byte must be 0x01
    std::vector<uint8_t> input;
    input.push_back(0x02); // bad signature
    // Minimal chunk header
    input.push_back(0x00);
    input.push_back(0x70);
    input.push_back(0x00);
    input.push_back('A');

    uint8_t* out = nullptr;
    size_t out_len = 0;
    EXPECT_FALSE(akav_ole2_ovba_decompress(input.data(), input.size(),
                                            &out, &out_len));
}

// ── VBA extraction ────────────────────────────────────────────────

// Helper: build a simple OVBA-compressed buffer from raw data.
// Uses all-literal encoding for simplicity.
static std::vector<uint8_t> ovba_compress_simple(const uint8_t* raw,
                                                  size_t raw_len) {
    std::vector<uint8_t> result;
    result.push_back(0x01); // signature

    size_t offset = 0;
    while (offset < raw_len) {
        size_t chunk_raw_len = raw_len - offset;
        if (chunk_raw_len > 4096) chunk_raw_len = 4096;

        if (chunk_raw_len == 4096) {
            // Uncompressed chunk
            uint16_t hdr = 0x3FFD; // size=4093, uncompressed, sig=0b011 at bits 12-14
            result.push_back(static_cast<uint8_t>(hdr & 0xFF));
            result.push_back(static_cast<uint8_t>((hdr >> 8) & 0xFF));
            result.insert(result.end(), raw + offset, raw + offset + 4096);
        } else {
            // Compressed chunk with all-literal FlagBytes.
            // Each FlagByte group: 1 FlagByte(0x00) + up to 8 literal bytes.
            std::vector<uint8_t> chunk_data;
            size_t pos = 0;
            while (pos < chunk_raw_len) {
                chunk_data.push_back(0x00); // FlagByte: all literals
                size_t count = chunk_raw_len - pos;
                if (count > 8) count = 8;
                for (size_t i = 0; i < count; i++) {
                    chunk_data.push_back(raw[offset + pos + i]);
                }
                pos += count;
            }

            uint16_t size_field = static_cast<uint16_t>(chunk_data.size() - 3);
            if (chunk_data.size() < 3) size_field = 0;
            // Bits 0-11: size-3, bits 12-14: signature 0b011, bit 15: compressed
            uint16_t hdr = size_field | (0x3u << 12) | (1u << 15);
            result.push_back(static_cast<uint8_t>(hdr & 0xFF));
            result.push_back(static_cast<uint8_t>((hdr >> 8) & 0xFF));
            result.insert(result.end(), chunk_data.begin(), chunk_data.end());
        }
        offset += chunk_raw_len;
    }
    return result;
}

// Helper: build a VBA "dir" stream (uncompressed content) that describes
// one module named module_name with text offset text_offset.
static std::vector<uint8_t> build_vba_dir_raw(const char* module_name,
                                               uint32_t text_offset) {
    std::vector<uint8_t> dir;

    auto put_u16 = [&](uint16_t v) {
        dir.push_back(static_cast<uint8_t>(v & 0xFF));
        dir.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto put_u32 = [&](uint32_t v) {
        dir.push_back(static_cast<uint8_t>(v & 0xFF));
        dir.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        dir.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        dir.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    };

    size_t name_len = std::strlen(module_name);

    // PROJECTSYSKIND record (id=0x0001, size=4, value=0)
    put_u16(0x0001); put_u32(4); put_u32(0);

    // PROJECTLCID (id=0x0002, size=4)
    put_u16(0x0002); put_u32(4); put_u32(0x0409);

    // PROJECTLCIDINVOKE (id=0x0014, size=4)
    put_u16(0x0014); put_u32(4); put_u32(0x0409);

    // PROJECTCODEPAGE (id=0x0003, size=2)
    put_u16(0x0003); put_u32(2); put_u16(1252);

    // PROJECTNAME (id=0x0004)
    put_u16(0x0004); put_u32(7);
    const char* pname = "VBAProj";
    for (size_t i = 0; i < 7; i++)
        dir.push_back(static_cast<uint8_t>(pname[i]));

    // PROJECTDOCSTRING (id=0x0005, size=0)
    put_u16(0x0005); put_u32(0);
    // PROJECTDOCSTRINGUNICODE (id=0x0040, size=0)
    put_u16(0x0040); put_u32(0);

    // PROJECTHELPFILEPATH (id=0x0006, size=0)
    put_u16(0x0006); put_u32(0);
    // PROJECTHELPFILEPATH2 (id=0x003D, size=0)
    put_u16(0x003D); put_u32(0);

    // PROJECTHELPCONTEXT (id=0x0007, size=4)
    put_u16(0x0007); put_u32(4); put_u32(0);

    // PROJECTLIBFLAGS (id=0x0008, size=4)
    put_u16(0x0008); put_u32(4); put_u32(0);

    // PROJECTVERSION (id=0x0009, size=6: major u32 + minor u16)
    put_u16(0x0009); put_u32(6); put_u32(1); put_u16(0);

    // PROJECTCONSTANTS (id=0x000C, size=0)
    put_u16(0x000C); put_u32(0);
    // PROJECTCONSTANTSUNICODE (id=0x003C, size=0)
    put_u16(0x003C); put_u32(0);

    // MODULENAME (id=0x0019)
    put_u16(0x0019);
    put_u32(static_cast<uint32_t>(name_len));
    for (size_t i = 0; i < name_len; i++)
        dir.push_back(static_cast<uint8_t>(module_name[i]));

    // MODULENAMEUNICODE (id=0x0047)
    put_u16(0x0047);
    put_u32(static_cast<uint32_t>(name_len * 2));
    for (size_t i = 0; i < name_len; i++) {
        dir.push_back(static_cast<uint8_t>(module_name[i]));
        dir.push_back(0);
    }

    // MODULESTREAMNAME (id=0x001A)
    put_u16(0x001A);
    put_u32(static_cast<uint32_t>(name_len));
    for (size_t i = 0; i < name_len; i++)
        dir.push_back(static_cast<uint8_t>(module_name[i]));

    // MODULESTREAMNAMEUNICODE (id=0x0032)
    put_u16(0x0032);
    put_u32(static_cast<uint32_t>(name_len * 2));
    for (size_t i = 0; i < name_len; i++) {
        dir.push_back(static_cast<uint8_t>(module_name[i]));
        dir.push_back(0);
    }

    // MODULEDOCSTRING (id=0x001C, size=0)
    put_u16(0x001C); put_u32(0);
    // MODULEDOCSTRINGUNICODE (id=0x0048, size=0)
    put_u16(0x0048); put_u32(0);

    // MODULEOFFSET (id=0x0031, size=4)
    put_u16(0x0031);
    put_u32(4);
    put_u32(text_offset);

    // MODULETYPE procedural (id=0x0021, size=0)
    put_u16(0x0021); put_u32(0);

    // MODULE terminator (id=0x002B, size=0)
    put_u16(0x002B); put_u32(0);

    // PROJECTMODULES count (we already emitted the module above in stream)
    // This is a simplified dir stream; the parser should find the module records.

    return dir;
}

TEST(OLE2VBA, VBAExtraction) {
    // Build a complete OLE2 with VBA storage containing:
    //   Root Entry
    //     VBA (storage)
    //       dir (stream, compressed)
    //       Module1 (stream, compressed VBA source)

    const char* vba_source = "Sub AutoOpen()\nMsgBox \"Hello\"\nEnd Sub\n";
    size_t source_len = std::strlen(vba_source);

    // The module stream contains: [text_offset bytes of garbage] + compressed source
    // We'll use text_offset = 0 for simplicity.
    auto compressed_source = ovba_compress_simple(
        reinterpret_cast<const uint8_t*>(vba_source), source_len);

    // Build the dir stream (raw, then compress it)
    auto dir_raw = build_vba_dir_raw("Module1", 0);
    auto compressed_dir = ovba_compress_simple(dir_raw.data(), dir_raw.size());

    // Now build the OLE2 file.
    // Layout:
    //   Sector 0: FAT
    //   Sector 1: Directory
    //   Sector 2: "dir" stream data
    //   Sector 3: "Module1" stream data
    //   (May need more sectors if data exceeds 512 bytes)

    Ole2Builder builder;

    // Calculate how many sectors we need for each stream
    auto sectors_needed = [](size_t len) -> uint32_t {
        return len == 0 ? 1 : static_cast<uint32_t>((len + 511) / 512);
    };

    uint32_t dir_sectors_count = sectors_needed(compressed_dir.size());
    uint32_t mod_sectors_count = sectors_needed(compressed_source.size());

    // We'll keep it simple: one sector per stream if they fit in 512 bytes.
    // For larger compressed data, chain multiple sectors.
    uint32_t dir_stream_start = 2;
    uint32_t mod_stream_start = dir_stream_start + dir_sectors_count;
    uint32_t total_sectors = mod_stream_start + mod_sectors_count;

    builder.write_header(0x0003, 9, 1, 1);
    builder.set_difat(0, 0);
    // Force mini_stream_cutoff=0 so all streams use regular sectors
    builder.put_u32(56, 0);

    // FAT
    builder.fill_fat_sector(0);
    builder.write_fat_entry(0, 0, AKAV_OLE2_FATSECT);
    builder.write_fat_entry(0, 1, AKAV_OLE2_ENDOFCHAIN); // dir sector

    // Chain for dir stream sectors
    for (uint32_t i = 0; i < dir_sectors_count; i++) {
        uint32_t sid = dir_stream_start + i;
        uint32_t next = (i + 1 < dir_sectors_count)
                        ? (sid + 1) : AKAV_OLE2_ENDOFCHAIN;
        builder.write_fat_entry(0, sid, next);
    }

    // Chain for module stream sectors
    for (uint32_t i = 0; i < mod_sectors_count; i++) {
        uint32_t sid = mod_stream_start + i;
        uint32_t next = (i + 1 < mod_sectors_count)
                        ? (sid + 1) : AKAV_OLE2_ENDOFCHAIN;
        builder.write_fat_entry(0, sid, next);
    }

    // Ensure all sectors exist
    for (uint32_t s = 0; s < total_sectors; s++) {
        builder.ensure_sector(s);
    }

    // Directory sector (sector 1)
    // SID 0: Root Entry, child = 1 (VBA storage)
    builder.write_dir_entry(builder.sector_offset(1), "Root Entry",
                            AKAV_OLE2_OBJTYPE_ROOT,
                            AKAV_OLE2_ENDOFCHAIN, 0,
                            1); // child = VBA storage

    // SID 1: VBA storage, child = 2 (dir stream)
    builder.write_dir_entry(builder.sector_offset(1) + 128, "VBA",
                            AKAV_OLE2_OBJTYPE_STORAGE,
                            AKAV_OLE2_ENDOFCHAIN, 0,
                            2); // child = dir stream

    // SID 2: dir stream, right sibling = 3 (Module1)
    builder.write_dir_entry(builder.sector_offset(1) + 256, "dir",
                            AKAV_OLE2_OBJTYPE_STREAM,
                            dir_stream_start, compressed_dir.size(),
                            0xFFFFFFFFU, 0xFFFFFFFFU,
                            3); // right = Module1

    // SID 3: Module1 stream
    builder.write_dir_entry(builder.sector_offset(1) + 384, "Module1",
                            AKAV_OLE2_OBJTYPE_STREAM,
                            mod_stream_start, compressed_source.size());

    // Write dir stream data
    for (uint32_t i = 0; i < dir_sectors_count; i++) {
        size_t src_off = static_cast<size_t>(i) * 512;
        size_t remain = compressed_dir.size() - src_off;
        size_t copy_len = remain < 512 ? remain : 512;
        builder.write_sector_data(dir_stream_start + i,
                                  compressed_dir.data() + src_off, copy_len);
    }

    // Write module stream data
    for (uint32_t i = 0; i < mod_sectors_count; i++) {
        size_t src_off = static_cast<size_t>(i) * 512;
        size_t remain = compressed_source.size() - src_off;
        size_t copy_len = remain < 512 ? remain : 512;
        builder.write_sector_data(mod_stream_start + i,
                                  compressed_source.data() + src_off, copy_len);
    }

    auto& data = builder.raw();

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));
    ASSERT_TRUE(akav_ole2_extract_streams(&ole2, data.data(), data.size()));
    ASSERT_TRUE(akav_ole2_extract_vba(&ole2, data.data(), data.size()));

    EXPECT_TRUE(ole2.has_vba);
    EXPECT_GE(ole2.num_vba_modules, 1u);

    if (ole2.num_vba_modules >= 1) {
        EXPECT_STREQ(ole2.vba_modules[0].module_name, "Module1");
        if (ole2.vba_modules[0].source && ole2.vba_modules[0].source_len > 0) {
            std::string extracted(
                reinterpret_cast<char*>(ole2.vba_modules[0].source),
                ole2.vba_modules[0].source_len);
            EXPECT_NE(extracted.find("AutoOpen"), std::string::npos);
            EXPECT_NE(extracted.find("MsgBox"), std::string::npos);
        }
    }

    akav_ole2_free(&ole2);
}

// ── Analyze convenience ───────────────────────────────────────────

TEST(OLE2Analyze, AnalyzeConvenience) {
    // Build a minimal OLE2 with VBA storage to trigger has_vba/has_macros.
    Ole2Builder builder;
    builder.build_minimal();

    // Add a VBA storage entry and a dir stream to the directory
    builder.write_dir_entry(builder.sector_offset(1), "Root Entry",
                            AKAV_OLE2_OBJTYPE_ROOT,
                            AKAV_OLE2_ENDOFCHAIN, 0, 1);
    builder.write_dir_entry(builder.sector_offset(1) + 128, "VBA",
                            AKAV_OLE2_OBJTYPE_STORAGE,
                            AKAV_OLE2_ENDOFCHAIN, 0, 2);
    builder.write_dir_entry(builder.sector_offset(1) + 256, "dir",
                            AKAV_OLE2_OBJTYPE_STREAM,
                            AKAV_OLE2_ENDOFCHAIN, 0);

    auto& data = builder.raw();

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    akav_ole2_analyze(&ole2, data.data(), data.size());

    // analyze should parse and detect VBA presence
    EXPECT_TRUE(ole2.has_vba);
    EXPECT_TRUE(ole2.has_macros);

    akav_ole2_free(&ole2);
}

// ── Free safety tests ─────────────────────────────────────────────

TEST(OLE2Free, FreeZeroed) {
    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    akav_ole2_free(&ole2); // should not crash
}

TEST(OLE2Free, FreePartialParse) {
    // Truncated data: valid magic but truncated header area
    std::vector<uint8_t> data(600, 0);
    static const uint8_t magic[] = {
        0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1
    };
    std::memcpy(data.data(), magic, 8);

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    // This may fail (missing FAT/directory), but should not crash
    akav_ole2_parse(&ole2, data.data(), data.size());
    akav_ole2_free(&ole2); // should not crash
}

TEST(OLE2Free, FreeSafety) {
    Ole2Builder builder;
    auto data = builder.build_minimal();

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));
    EXPECT_TRUE(ole2.valid);

    akav_ole2_free(&ole2);

    // After free, struct should be zeroed / safe
    EXPECT_EQ(ole2.fat, nullptr);
    EXPECT_EQ(ole2.minifat, nullptr);
    EXPECT_EQ(ole2.dir_entries, nullptr);
    EXPECT_EQ(ole2.streams, nullptr);
    EXPECT_EQ(ole2.vba_modules, nullptr);
    EXPECT_EQ(ole2.num_fat_entries, 0u);
    EXPECT_EQ(ole2.num_dir_entries, 0u);
    EXPECT_EQ(ole2.num_streams, 0u);
    EXPECT_FALSE(ole2.valid);
}

// ── Edge cases ────────────────────────────────────────────────────

TEST(OLE2Stream, LargeStreamSize) {
    // Stream entry claims a size larger than available data.
    Ole2Builder builder;
    builder.build_minimal();

    // Add a stream entry with size = 1MB but only 1 sector of actual data.
    builder.write_fat_entry(0, 2, AKAV_OLE2_ENDOFCHAIN);
    builder.ensure_sector(2);

    builder.write_dir_entry(builder.sector_offset(1), "Root Entry",
                            AKAV_OLE2_OBJTYPE_ROOT,
                            AKAV_OLE2_ENDOFCHAIN, 0, 1);
    builder.write_dir_entry(builder.sector_offset(1) + 128, "BigStream",
                            AKAV_OLE2_OBJTYPE_STREAM,
                            2, 1048576); // 1 MB

    auto& data = builder.raw();

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));

    // Extraction should handle gracefully (not crash, may extract partial or skip)
    akav_ole2_extract_streams(&ole2, data.data(), data.size());

    akav_ole2_free(&ole2);
}

TEST(OLE2Stream, EmptyStream) {
    Ole2Builder builder;
    // Build with an empty stream (size = 0)
    const uint8_t dummy = 0;
    auto data = builder.build_with_stream("EmptyStream", &dummy, 0);

    // Fix: set the stream size to 0 in the directory entry
    builder.write_dir_entry(builder.sector_offset(1) + 128, "EmptyStream",
                            AKAV_OLE2_OBJTYPE_STREAM,
                            AKAV_OLE2_ENDOFCHAIN, 0);

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    auto& raw = builder.raw();
    ASSERT_TRUE(akav_ole2_parse(&ole2, raw.data(), raw.size()));
    ASSERT_TRUE(akav_ole2_extract_streams(&ole2, raw.data(), raw.size()));

    // Find the empty stream
    bool found = false;
    for (uint32_t i = 0; i < ole2.num_streams; i++) {
        if (std::strcmp(ole2.streams[i].name, "EmptyStream") == 0) {
            found = true;
            EXPECT_EQ(ole2.streams[i].data_len, 0u);
            break;
        }
    }
    EXPECT_TRUE(found);

    akav_ole2_free(&ole2);
}

TEST(OLE2Parse, StorageEntry) {
    // Storage entries (obj_type=1) should be parsed in the directory
    // but NOT extracted as streams.
    Ole2Builder builder;
    builder.build_minimal();

    // Add a storage entry
    builder.write_dir_entry(builder.sector_offset(1), "Root Entry",
                            AKAV_OLE2_OBJTYPE_ROOT,
                            AKAV_OLE2_ENDOFCHAIN, 0, 1);
    builder.write_dir_entry(builder.sector_offset(1) + 128, "MyStorage",
                            AKAV_OLE2_OBJTYPE_STORAGE,
                            AKAV_OLE2_ENDOFCHAIN, 0);

    auto& data = builder.raw();

    akav_ole2_t ole2;
    std::memset(&ole2, 0, sizeof(ole2));
    ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));

    // The storage entry should appear in dir_entries
    bool found_in_dir = false;
    for (uint32_t i = 0; i < ole2.num_dir_entries; i++) {
        if (std::strcmp(ole2.dir_entries[i].name, "MyStorage") == 0) {
            found_in_dir = true;
            EXPECT_EQ(ole2.dir_entries[i].obj_type, AKAV_OLE2_OBJTYPE_STORAGE);
            break;
        }
    }
    EXPECT_TRUE(found_in_dir);

    // But should NOT appear in extracted streams
    akav_ole2_extract_streams(&ole2, data.data(), data.size());
    for (uint32_t i = 0; i < ole2.num_streams; i++) {
        EXPECT_STRNE(ole2.streams[i].name, "MyStorage");
    }

    akav_ole2_free(&ole2);
}

// ── Header versions ───────────────────────────────────────────────

TEST(OLE2Parse, HeaderVersions) {
    // Test v3 (major=0x0003) with 512-byte sectors
    {
        Ole2Builder builder;
        auto data = builder.build_minimal();

        akav_ole2_t ole2;
        std::memset(&ole2, 0, sizeof(ole2));
        ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));
        EXPECT_EQ(ole2.header.major_version, 0x0003);
        EXPECT_EQ(ole2.header.sector_size, 512);
        akav_ole2_free(&ole2);
    }

    // Test v4 (major=0x0004) with 4096-byte sectors
    {
        Ole2Builder builder;
        // v4 header with sector_size_power = 12 (4096)
        builder.write_header(0x0004, 12, 1, 1);
        builder.set_difat(0, 0);

        // FAT sector (4096 bytes)
        builder.fill_fat_sector(0);
        builder.write_fat_entry(0, 0, AKAV_OLE2_FATSECT);
        builder.write_fat_entry(0, 1, AKAV_OLE2_ENDOFCHAIN);

        // Directory sector (4096 bytes, can hold 32 entries)
        builder.ensure_sector(1);
        builder.write_dir_entry(builder.sector_offset(1), "Root Entry",
                                AKAV_OLE2_OBJTYPE_ROOT,
                                AKAV_OLE2_ENDOFCHAIN, 0);

        auto& data = builder.raw();

        akav_ole2_t ole2;
        std::memset(&ole2, 0, sizeof(ole2));
        ASSERT_TRUE(akav_ole2_parse(&ole2, data.data(), data.size()));
        EXPECT_EQ(ole2.header.major_version, 0x0004);
        EXPECT_EQ(ole2.header.sector_size, 4096);
        akav_ole2_free(&ole2);
    }
}
