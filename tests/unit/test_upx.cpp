// test_upx.cpp -- Tests for UPX static unpacker (P6-T2).
//
// Tests:
//   1. Detect UPX by section names (UPX0/UPX1)
//   2. Detect UPX by "UPX!" magic
//   3. Non-UPX PE is not detected
//   4. NRV2B decompression round-trip
//   5. NRV2D decompression round-trip
//   6. NRV2E decompression round-trip
//   7. CT filter reversal
//   8. Full unpack + EICAR detection through pipeline
//   9. Malformed input does not crash
//  10. Non-PE data returns false

#include <gtest/gtest.h>

#include "unpacker/upx.h"
#include "parsers/pe.h"

#include <cstring>
#include <cstdlib>
#include <vector>
#include <cstdint>

// ---- Minimal NRV2B compressor (literal-only, for testing) ----------------
//
// Encodes all data as NRV2B literals (bit 1 + byte) with an end marker.
// Produces valid NRV2B compressed streams that the decompressor can handle.

struct NrvBitWriter {
    std::vector<uint8_t> out;
    uint32_t bb = 0;          // bit buffer
    uint32_t bc = 0;          // bits written in current buffer
    size_t   bb_pos = 0;      // position of current bit buffer in out
    bool     need_buf = true;  // deferred buffer allocation

    void ensure_buffer() {
        if (need_buf) {
            bb_pos = out.size();
            out.push_back(0); out.push_back(0);
            out.push_back(0); out.push_back(0);
            bb = 0;
            bc = 0;
            need_buf = false;
        }
    }

    void flush() {
        out[bb_pos]     = (uint8_t)(bb & 0xFF);
        out[bb_pos + 1] = (uint8_t)((bb >> 8) & 0xFF);
        out[bb_pos + 2] = (uint8_t)((bb >> 16) & 0xFF);
        out[bb_pos + 3] = (uint8_t)((bb >> 24) & 0xFF);
    }

    void writebit(int bit) {
        ensure_buffer();
        bb |= ((uint32_t)(bit & 1) << (31 - bc));
        bc++;
        if (bc == 32) {
            flush();
            need_buf = true;
        }
    }

    void writebyte(uint8_t byte) {
        out.push_back(byte);
    }

    std::vector<uint8_t> finish() {
        if (!need_buf) flush();
        return out;
    }
};

// Encode data as NRV2B literals + end marker
static std::vector<uint8_t> nrv2b_compress_literals(const uint8_t* data, size_t len)
{
    NrvBitWriter bw;

    // Encode each byte as literal: bit 1 + raw byte
    for (size_t i = 0; i < len; i++) {
        bw.writebit(1);
        bw.writebyte(data[i]);
    }

    // End marker: bit 0 (match start), then encode m_off that gives 0xFFFFFFFF
    bw.writebit(0);

    // Encode m_off = 0x01000002 in the Elias-gamma-like code:
    // 24 iterations of (value_bit, check_bit)
    // Iterations 1-22: value=0, check=0
    // Iteration 23: value=1, check=0
    // Iteration 24: value=0, check=1
    for (int i = 0; i < 22; i++) {
        bw.writebit(0);  // value
        bw.writebit(0);  // check
    }
    bw.writebit(1);  // value (iteration 23)
    bw.writebit(0);  // check
    bw.writebit(0);  // value (iteration 24)
    bw.writebit(1);  // check (break)

    bw.writebyte(0xFF);  // end marker byte: (0x01000002 - 3) * 256 + 0xFF = 0xFFFFFFFF

    return bw.finish();
}

// Encode data as NRV2D literals + end marker (same bit pattern as NRV2B)
static std::vector<uint8_t> nrv2d_compress_literals(const uint8_t* data, size_t len)
{
    // NRV2D has the same literal encoding and end marker format as NRV2B
    return nrv2b_compress_literals(data, len);
}

// Encode data as NRV2E literals + end marker
static std::vector<uint8_t> nrv2e_compress_literals(const uint8_t* data, size_t len)
{
    NrvBitWriter bw;

    for (size_t i = 0; i < len; i++) {
        bw.writebit(1);
        bw.writebyte(data[i]);
    }

    bw.writebit(0);  // match start

    // NRV2E end marker: encode m_off = 0x03000002 (26 bits).
    // NRV2E's offset coding reads 2 value bits per non-terminal iteration
    // (3 stream bits: v1, check=0, v2) plus 1 value bit at terminal
    // (2 stream bits: v1, check=1). So total value bits = 2*N + 1,
    // giving m_off with 2*N+2 total bits (including leading 1).
    //
    // 0x01000002 (25 bits) is impossible since 25 is odd.
    // Instead use m_off = 0x03000002 (26 bits = 2*12+2, so N=12).
    // (0x03000002 - 3) * 256 + 0xFF = 0x2FFFFFF * 256 + 0xFF
    //   = 0x2FFFFFF00 + 0xFF = 0xFFFFFFFF (via uint32_t overflow).
    //
    // Bit encoding (MSB first from m_off=1):
    //   NT1:      v1=1, check=0, v2=0   → m_off = 6
    //   NT2-NT11: v1=0, check=0, v2=0   → m_off *= 4 each (×10)
    //   NT12:     v1=0, check=0, v2=1   → m_off = 0x1800001
    //   Terminal: v1=0, check=1          → m_off = 0x3000002

    // NT1
    bw.writebit(1);  // v1
    bw.writebit(0);  // check
    bw.writebit(0);  // v2

    // NT2-NT11 (10 iterations, all zeros)
    for (int i = 0; i < 10; i++) {
        bw.writebit(0);  // v1
        bw.writebit(0);  // check
        bw.writebit(0);  // v2
    }

    // NT12
    bw.writebit(0);  // v1
    bw.writebit(0);  // check
    bw.writebit(1);  // v2

    // Terminal
    bw.writebit(0);  // v1
    bw.writebit(1);  // check (break)

    bw.writebyte(0xFF);  // end marker byte

    return bw.finish();
}

// ---- Minimal PE builder for test fixtures --------------------------------

// Build a minimal valid PE32 with given section names and content
static std::vector<uint8_t> build_test_pe(
    const char* section1_name, uint32_t sec1_vsize, uint32_t sec1_rawsize,
    const char* section2_name, uint32_t sec2_vsize, uint32_t sec2_rawsize,
    const uint8_t* sec2_data,
    uint32_t entry_point_rva = 0x2000,
    const uint8_t* extra_data = nullptr, size_t extra_len = 0)
{
    const uint32_t file_alignment = 0x200;
    const uint32_t section_alignment = 0x1000;

    // DOS header (64 bytes minimum)
    std::vector<uint8_t> pe(64, 0);
    pe[0] = 'M'; pe[1] = 'Z';  // MZ magic
    uint32_t e_lfanew = 64;
    memcpy(pe.data() + 60, &e_lfanew, 4);

    // PE signature
    pe.push_back('P'); pe.push_back('E'); pe.push_back(0); pe.push_back(0);

    // COFF header (20 bytes)
    uint16_t machine = 0x014C;  // i386
    pe.push_back((uint8_t)(machine & 0xFF));
    pe.push_back((uint8_t)(machine >> 8));
    uint16_t num_sections = (section2_name ? 2 : 1);
    if (extra_data && extra_len > 0) num_sections = 3;
    pe.push_back((uint8_t)(num_sections & 0xFF));
    pe.push_back((uint8_t)(num_sections >> 8));
    for (int i = 0; i < 12; i++) pe.push_back(0);  // timestamp, symbols, etc.
    uint16_t opt_header_size = 0xE0;  // standard PE32 optional header
    pe.push_back((uint8_t)(opt_header_size & 0xFF));
    pe.push_back((uint8_t)(opt_header_size >> 8));
    uint16_t characteristics = 0x0102;  // EXECUTABLE_IMAGE | 32BIT_MACHINE
    pe.push_back((uint8_t)(characteristics & 0xFF));
    pe.push_back((uint8_t)(characteristics >> 8));

    // Optional header (PE32, 224 bytes = 0xE0)
    size_t opt_start = pe.size();
    pe.resize(opt_start + 0xE0, 0);
    uint16_t opt_magic = 0x10B;  // PE32
    memcpy(pe.data() + opt_start, &opt_magic, 2);
    // Entry point
    memcpy(pe.data() + opt_start + 16, &entry_point_rva, 4);
    // Base of code
    uint32_t base_of_code = 0x1000;
    memcpy(pe.data() + opt_start + 20, &base_of_code, 4);
    // Image base
    uint32_t image_base = 0x00400000;
    memcpy(pe.data() + opt_start + 28, &image_base, 4);
    // Section alignment
    memcpy(pe.data() + opt_start + 32, &section_alignment, 4);
    // File alignment
    memcpy(pe.data() + opt_start + 36, &file_alignment, 4);
    // Size of image (estimate)
    uint32_t size_of_image = 0x10000;
    memcpy(pe.data() + opt_start + 56, &size_of_image, 4);
    // Size of headers
    uint32_t size_of_headers = 0x400;  // will fix below
    memcpy(pe.data() + opt_start + 60, &size_of_headers, 4);
    // Number of data directories
    uint32_t num_data_dirs = 16;
    memcpy(pe.data() + opt_start + 92, &num_data_dirs, 4);

    // Section table
    size_t sec_table_start = pe.size();

    // Compute headers size (aligned)
    size_t raw_headers_end = sec_table_start + (size_t)num_sections * 40;
    size_of_headers = (uint32_t)((raw_headers_end + file_alignment - 1) &
                                  ~(file_alignment - 1));
    memcpy(pe.data() + opt_start + 60, &size_of_headers, 4);

    // Section 1 (UPX0 - destination)
    uint8_t sec1[40] = {};
    strncpy_s((char*)sec1, 9, section1_name, 8);
    memcpy(sec1 + 8,  &sec1_vsize, 4);                    // VirtualSize
    uint32_t sec1_va = section_alignment;
    memcpy(sec1 + 12, &sec1_va, 4);                        // VirtualAddress
    memcpy(sec1 + 16, &sec1_rawsize, 4);                   // SizeOfRawData
    uint32_t sec1_rawoff = size_of_headers;
    memcpy(sec1 + 20, &sec1_rawoff, 4);                    // PointerToRawData
    uint32_t sec1_chars = 0xE0000080;                      // RWX + UNINIT_DATA
    memcpy(sec1 + 36, &sec1_chars, 4);
    for (int i = 0; i < 40; i++) pe.push_back(sec1[i]);

    // Section 2 (UPX1 - compressed data)
    uint32_t sec2_rawoff = sec1_rawoff + ((sec1_rawsize + file_alignment - 1) &
                                           ~(file_alignment - 1));
    if (sec1_rawsize == 0) sec2_rawoff = sec1_rawoff;

    if (section2_name) {
        uint8_t sec2[40] = {};
        strncpy_s((char*)sec2, 9, section2_name, 8);
        memcpy(sec2 + 8,  &sec2_vsize, 4);
        uint32_t sec2_va = sec1_va + ((sec1_vsize + section_alignment - 1) &
                                       ~(section_alignment - 1));
        memcpy(sec2 + 12, &sec2_va, 4);
        memcpy(sec2 + 16, &sec2_rawsize, 4);
        memcpy(sec2 + 20, &sec2_rawoff, 4);
        uint32_t sec2_chars = 0xE0000060;                  // RWX + CODE + INIT_DATA
        memcpy(sec2 + 36, &sec2_chars, 4);
        for (int i = 0; i < 40; i++) pe.push_back(sec2[i]);
    }

    // Section 3 (resources, if extra_data provided)
    if (extra_data && extra_len > 0) {
        uint32_t sec3_rawoff = sec2_rawoff + ((sec2_rawsize + file_alignment - 1) &
                                               ~(file_alignment - 1));
        uint8_t sec3[40] = {};
        memcpy(sec3, ".rsrc\0\0\0", 8);
        uint32_t sec3_vsize = (uint32_t)extra_len;
        memcpy(sec3 + 8, &sec3_vsize, 4);
        uint32_t sec3_va = 0x4000;
        memcpy(sec3 + 12, &sec3_va, 4);
        uint32_t sec3_rawsize_aligned = (uint32_t)((extra_len + file_alignment - 1) &
                                                     ~(file_alignment - 1));
        memcpy(sec3 + 16, &sec3_rawsize_aligned, 4);
        memcpy(sec3 + 20, &sec3_rawoff, 4);
        uint32_t sec3_chars = 0x40000040;  // READ + INIT_DATA
        memcpy(sec3 + 36, &sec3_chars, 4);
        for (int i = 0; i < 40; i++) pe.push_back(sec3[i]);
    }

    // Pad to size_of_headers
    pe.resize(size_of_headers, 0);

    // Section 1 data (empty for UPX0)
    if (sec1_rawsize > 0) {
        pe.resize(sec1_rawoff + sec1_rawsize, 0);
    }

    // Section 2 data
    if (section2_name && sec2_data && sec2_rawsize > 0) {
        pe.resize(sec2_rawoff + sec2_rawsize, 0);
        memcpy(pe.data() + sec2_rawoff, sec2_data, sec2_rawsize);
    }

    // Section 3 data
    if (extra_data && extra_len > 0) {
        uint32_t sec3_rawoff = sec2_rawoff + ((sec2_rawsize + file_alignment - 1) &
                                               ~(file_alignment - 1));
        uint32_t sec3_rawsize_aligned = (uint32_t)((extra_len + file_alignment - 1) &
                                                     ~(file_alignment - 1));
        pe.resize(sec3_rawoff + sec3_rawsize_aligned, 0);
        memcpy(pe.data() + sec3_rawoff, extra_data, extra_len);
    }

    return pe;
}

// Build a UPX packheader
static std::vector<uint8_t> build_packheader(uint8_t method, uint8_t filter,
                                              uint8_t filter_cto,
                                              uint32_t u_len, uint32_t c_len,
                                              uint32_t u_file_size)
{
    std::vector<uint8_t> hdr_data;

    // "UPX!" magic
    hdr_data.push_back('U'); hdr_data.push_back('P');
    hdr_data.push_back('X'); hdr_data.push_back('!');

    // Packheader fields
    akav_upx_packheader_t hdr = {};
    hdr.version = 0x0D;     // UPX version 3.x format
    hdr.format = 0x09;      // Win32/PE
    hdr.method = method;
    hdr.level = 9;
    hdr.u_adler = 0;        // Not validated in our unpacker
    hdr.c_adler = 0;
    hdr.u_len = u_len;
    hdr.c_len = c_len;
    hdr.u_file_size = u_file_size;
    hdr.filter = filter;
    hdr.filter_cto = filter_cto;
    hdr.n_mru = 0;

    // Compute checksum
    uint8_t cksum = 0;
    const uint8_t* h = (const uint8_t*)&hdr;
    for (size_t i = 0; i < sizeof(hdr) - 1; i++)
        cksum += h[i];
    hdr.header_checksum = cksum;

    const uint8_t* hp = (const uint8_t*)&hdr;
    hdr_data.insert(hdr_data.end(), hp, hp + sizeof(hdr));

    return hdr_data;
}

// ---- Detection tests -----------------------------------------------------

TEST(UPXDetect, DetectBySectionNames)
{
    // Build PE with UPX0 and UPX1 sections
    auto pe = build_test_pe("UPX0", 0x10000, 0, "UPX1", 0x1000, 0x200, nullptr);

    akav_upx_info_t info;
    EXPECT_TRUE(akav_upx_detect(pe.data(), pe.size(), &info));
    EXPECT_TRUE(info.is_upx);
}

TEST(UPXDetect, DetectByMagicInSection)
{
    // Build a PE with non-UPX section names but "UPX!" magic embedded in data.
    // Use UPX0/UPX1 names to ensure PE parses correctly, but the test verifies
    // that detect populates info from the magic/packheader.
    const char EICAR[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    size_t eicar_len = 68;
    auto compressed = nrv2b_compress_literals((const uint8_t*)EICAR, eicar_len);
    auto phdr = build_packheader(AKAV_UPX_METHOD_NRV2B, 0x00, 0x00,
                                  (uint32_t)eicar_len,
                                  (uint32_t)compressed.size(), 4096);
    std::vector<uint8_t> upx1_data;
    upx1_data.insert(upx1_data.end(), compressed.begin(), compressed.end());
    upx1_data.insert(upx1_data.end(), phdr.begin(), phdr.end());

    auto pe = build_test_pe("UPX0", 0x10000, 0, "UPX1",
                             (uint32_t)upx1_data.size(),
                             (uint32_t)upx1_data.size(), upx1_data.data());

    akav_upx_info_t info;
    ASSERT_TRUE(akav_upx_detect(pe.data(), pe.size(), &info));
    EXPECT_TRUE(info.is_upx);
    EXPECT_EQ(info.method, AKAV_UPX_METHOD_NRV2B);
    EXPECT_EQ(info.original_size, (uint32_t)eicar_len);
}

TEST(UPXDetect, NonUPXPENotDetected)
{
    // Build a normal PE without UPX markers
    uint8_t code[] = { 0xCC, 0xCC, 0xCC, 0xCC };  // INT3 padding
    auto pe = build_test_pe(".text", 0x1000, sizeof(code), ".data", 0x1000,
                             sizeof(code), code);

    akav_upx_info_t info;
    EXPECT_FALSE(akav_upx_detect(pe.data(), pe.size(), &info));
    EXPECT_FALSE(info.is_upx);
}

TEST(UPXDetect, NonPEDataReturnsFalse)
{
    uint8_t data[] = "This is not a PE file at all";
    akav_upx_info_t info;
    EXPECT_FALSE(akav_upx_detect(data, sizeof(data), &info));
}

TEST(UPXDetect, NullDataReturnsFalse)
{
    EXPECT_FALSE(akav_upx_detect(nullptr, 0, nullptr));
}

TEST(UPXDetect, SmallDataReturnsFalse)
{
    uint8_t data[64] = {};
    EXPECT_FALSE(akav_upx_detect(data, sizeof(data), nullptr));
}

// ---- NRV decompression tests ---------------------------------------------

TEST(NRV2B, DecompressLiterals)
{
    // Compress "Hello, World!" as all-literal NRV2B
    const char* msg = "Hello, World!";
    size_t msg_len = strlen(msg);

    auto compressed = nrv2b_compress_literals((const uint8_t*)msg, msg_len);
    ASSERT_GT(compressed.size(), 0u);

    // Decompress
    uint8_t out[256];
    size_t out_len = 0;
    bool ok = akav_nrv2b_decompress(compressed.data(), compressed.size(),
                                     out, &out_len, sizeof(out));
    ASSERT_TRUE(ok) << "NRV2B decompression failed";
    ASSERT_EQ(out_len, msg_len);
    EXPECT_EQ(memcmp(out, msg, msg_len), 0);
}

TEST(NRV2B, DecompressMultipleSizes)
{
    // Test several sizes to exercise bit-buffer boundary transitions
    uint32_t sizes[] = { 1, 13, 31, 32, 33, 63, 64, 65, 100 };
    for (uint32_t sz : sizes) {
        std::vector<uint8_t> data(sz);
        uint32_t state = sz * 12345u;
        for (size_t i = 0; i < data.size(); i++) {
            state = state * 1103515245u + 12345u;
            data[i] = (uint8_t)(state >> 16);
        }

        auto compressed = nrv2b_compress_literals(data.data(), data.size());

        std::vector<uint8_t> out(sz + 256);
        size_t out_len = 0;
        bool ok = akav_nrv2b_decompress(compressed.data(), compressed.size(),
                                         out.data(), &out_len, out.size());
        ASSERT_TRUE(ok) << "Failed for size " << sz;
        ASSERT_EQ(out_len, (size_t)sz) << "Wrong output size for " << sz;
        EXPECT_EQ(memcmp(out.data(), data.data(), sz), 0) << "Data mismatch for size " << sz;
    }
}

TEST(NRV2B, EmptyInput)
{
    // Empty compressed data should fail gracefully
    uint8_t out[256];
    size_t out_len = 0;
    EXPECT_FALSE(akav_nrv2b_decompress(nullptr, 0, out, &out_len, sizeof(out)));
}

TEST(NRV2B, TruncatedInput)
{
    const char* msg = "Test";
    auto compressed = nrv2b_compress_literals((const uint8_t*)msg, strlen(msg));

    // Truncate the compressed data
    uint8_t out[256];
    size_t out_len = 0;
    EXPECT_FALSE(akav_nrv2b_decompress(compressed.data(), 4, out, &out_len, sizeof(out)));
}

TEST(NRV2D, DecompressLiterals)
{
    const char* msg = "NRV2D Test Data 123";
    size_t msg_len = strlen(msg);

    auto compressed = nrv2d_compress_literals((const uint8_t*)msg, msg_len);

    uint8_t out[256];
    size_t out_len = 0;
    bool ok = akav_nrv2d_decompress(compressed.data(), compressed.size(),
                                     out, &out_len, sizeof(out));
    ASSERT_TRUE(ok);
    ASSERT_EQ(out_len, msg_len);
    EXPECT_EQ(memcmp(out, msg, msg_len), 0);
}

TEST(NRV2E, DecompressLiterals)
{
    const char* msg = "NRV2E Test Data 456";
    size_t msg_len = strlen(msg);

    auto compressed = nrv2e_compress_literals((const uint8_t*)msg, msg_len);

    uint8_t out[256];
    size_t out_len = 0;
    bool ok = akav_nrv2e_decompress(compressed.data(), compressed.size(),
                                     out, &out_len, sizeof(out));
    ASSERT_TRUE(ok);
    ASSERT_EQ(out_len, msg_len);
    EXPECT_EQ(memcmp(out, msg, msg_len), 0);
}

// ---- CT Filter tests -----------------------------------------------------

TEST(UPXFilter, UnfilterCTReversal)
{
    // Simulate a filtered CALL instruction:
    // Original: E8 <relative_offset>
    // Filtered: E8 <absolute_offset> with cto byte at position +4
    uint8_t cto = 0x00;

    // Build a small code buffer with a filtered E8 at offset 10
    uint8_t buf[32];
    memset(buf, 0x90, sizeof(buf));  // NOP sled

    // Place a filtered CALL at offset 10:
    // The filter converted relative to absolute: addr = relative + offset
    // So absolute = 0x12345678 + 10 = 0x12345682 (conceptually)
    // With cto = 0x00, the high byte of the address must be 0x00
    buf[10] = 0xE8;
    uint32_t absolute_addr = 0x0000000A + 10;  // relative was 0x0A
    memcpy(buf + 11, &absolute_addr, 4);
    buf[14] = cto;  // set the cto byte

    // Now buf[11..14] = absolute address with cto at buf[14]
    // After unfilter, it should become relative again
    akav_upx_unfilter_ct(buf, sizeof(buf), cto);

    uint32_t result_addr;
    memcpy(&result_addr, buf + 11, 4);

    // The unfilter subtracts the position: result = absolute - offset
    EXPECT_EQ(result_addr, 0x0000000Au);
}

TEST(UPXFilter, UnfilterSkipsNonFilteredCalls)
{
    uint8_t cto = 0x00;
    uint8_t buf[16];
    memset(buf, 0x90, sizeof(buf));

    // E8 with a non-cto byte at position +4 should not be modified
    buf[0] = 0xE8;
    buf[1] = 0x11; buf[2] = 0x22; buf[3] = 0x33; buf[4] = 0x44;  // cto != 0x00

    uint8_t expected[16];
    memcpy(expected, buf, sizeof(buf));

    akav_upx_unfilter_ct(buf, sizeof(buf), cto);
    EXPECT_EQ(memcmp(buf, expected, sizeof(buf)), 0);
}

// ---- Full unpack tests ---------------------------------------------------

TEST(UPXUnpack, FullUnpackWithEICAR)
{
    // Build a UPX-packed PE containing the EICAR string in compressed form.
    // Steps:
    //   1. Compress EICAR string + padding as NRV2B literals
    //   2. Build UPX packheader
    //   3. Construct a PE with UPX0/UPX1 sections
    //   4. Call akav_upx_unpack
    //   5. Verify the unpacked PE contains EICAR

    const char EICAR[] =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    size_t eicar_len = 68;

    // Compress EICAR string as NRV2B
    auto compressed = nrv2b_compress_literals((const uint8_t*)EICAR, eicar_len);

    // Build UPX packheader
    auto phdr = build_packheader(AKAV_UPX_METHOD_NRV2B, 0x00, 0x00,
                                  (uint32_t)eicar_len,
                                  (uint32_t)compressed.size(),
                                  4096);

    // Build UPX1 section content: compressed data + packheader at the end
    std::vector<uint8_t> upx1_data;
    upx1_data.insert(upx1_data.end(), compressed.begin(), compressed.end());

    // Add some padding between compressed data and header
    for (int i = 0; i < 64; i++) upx1_data.push_back(0x90);

    // Append packheader
    upx1_data.insert(upx1_data.end(), phdr.begin(), phdr.end());

    // Build the PE: UPX0 (empty destination) + UPX1 (compressed data)
    auto pe = build_test_pe("UPX0", 0x10000, 0,
                             "UPX1", (uint32_t)upx1_data.size(),
                             (uint32_t)upx1_data.size(),
                             upx1_data.data());

    // Detect
    akav_upx_info_t info;
    ASSERT_TRUE(akav_upx_detect(pe.data(), pe.size(), &info));
    EXPECT_EQ(info.method, AKAV_UPX_METHOD_NRV2B);

    // Unpack
    uint8_t* unpacked = nullptr;
    size_t unpacked_len = 0;
    bool ok = akav_upx_unpack(pe.data(), pe.size(),
                               &unpacked, &unpacked_len, &info);
    ASSERT_TRUE(ok) << "Unpack failed: " << info.error;
    ASSERT_NE(unpacked, nullptr);
    ASSERT_GT(unpacked_len, eicar_len);

    // Search for EICAR string in unpacked PE
    bool found_eicar = false;
    for (size_t i = 0; i + eicar_len <= unpacked_len; i++) {
        if (memcmp(unpacked + i, EICAR, eicar_len) == 0) {
            found_eicar = true;
            break;
        }
    }
    EXPECT_TRUE(found_eicar) << "EICAR not found in unpacked output";

    free(unpacked);
}

TEST(UPXUnpack, NonUPXPEFailsGracefully)
{
    uint8_t code[] = { 0xCC, 0xCC, 0xCC, 0xCC };
    auto pe = build_test_pe(".text", 0x1000, sizeof(code),
                             ".data", 0x1000, sizeof(code), code);

    akav_upx_info_t info;
    uint8_t* unpacked = nullptr;
    size_t unpacked_len = 0;
    EXPECT_FALSE(akav_upx_unpack(pe.data(), pe.size(),
                                  &unpacked, &unpacked_len, &info));
    EXPECT_EQ(unpacked, nullptr);
}

TEST(UPXUnpack, MalformedPackheaderHandled)
{
    // Build PE with UPX section names but invalid packheader
    uint8_t garbage[128];
    memset(garbage, 0xAA, sizeof(garbage));
    // Put "UPX!" magic but garbage header after it
    garbage[50] = 'U'; garbage[51] = 'P'; garbage[52] = 'X'; garbage[53] = '!';

    auto pe = build_test_pe("UPX0", 0x10000, 0,
                             "UPX1", 0x1000, sizeof(garbage), garbage);

    akav_upx_info_t info;
    uint8_t* unpacked = nullptr;
    size_t unpacked_len = 0;
    // Should detect but fail to unpack due to bad packheader
    EXPECT_TRUE(akav_upx_detect(pe.data(), pe.size(), &info));
    EXPECT_FALSE(akav_upx_unpack(pe.data(), pe.size(),
                                  &unpacked, &unpacked_len, &info));
}

TEST(UPXUnpack, LZMAMethodReportsUnsupported)
{
    // Build a PE with valid UPX headers but LZMA method
    const char dummy[] = "dummy";
    auto compressed = nrv2b_compress_literals((const uint8_t*)dummy, strlen(dummy));

    auto phdr = build_packheader(AKAV_UPX_METHOD_LZMA, 0x00, 0x00,
                                  (uint32_t)strlen(dummy),
                                  (uint32_t)compressed.size(), 4096);

    std::vector<uint8_t> upx1_data;
    upx1_data.insert(upx1_data.end(), compressed.begin(), compressed.end());
    upx1_data.insert(upx1_data.end(), phdr.begin(), phdr.end());

    auto pe = build_test_pe("UPX0", 0x10000, 0,
                             "UPX1", (uint32_t)upx1_data.size(),
                             (uint32_t)upx1_data.size(), upx1_data.data());

    akav_upx_info_t info;
    uint8_t* unpacked = nullptr;
    size_t unpacked_len = 0;
    EXPECT_FALSE(akav_upx_unpack(pe.data(), pe.size(),
                                  &unpacked, &unpacked_len, &info));
    EXPECT_NE(std::string(info.error).find("LZMA"), std::string::npos);
}
