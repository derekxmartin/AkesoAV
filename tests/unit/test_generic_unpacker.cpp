// test_generic_unpacker.cpp -- Tests for generic emulation-based unpacker (P8-T4).
//
// Acceptance criteria:
//   1. UPX-like PE → unpacked payload matches expected
//   2. Custom XOR PE → recovered
//   3. Non-packed → no unpack, no crash

#include <gtest/gtest.h>
#include "unpacker/generic.h"
#include "emulator/x86_emu.h"
#include "emulator/pe_loader.h"
#include "emulator/winapi_stubs.h"
#include "parsers/pe.h"
#include <cstring>
#include <cstdlib>
#include <vector>

// ── Helper: Build a PE32 that simulates an unpacker ──
//
// The "packed" PE has code that:
//   1. Writes a complete PE (MZ+PE headers + payload) to address 0x402000
//   2. Jumps to 0x402000 (the unpacked code)
//
// This simulates write-then-jump behavior that generic unpackers detect.

static std::vector<uint8_t> build_packed_pe32_with_payload()
{
    // Layout:
    //   0x0000: DOS header (64 bytes, e_lfanew = 0x40)
    //   0x0040: PE signature (4 bytes)
    //   0x0044: COFF header (20 bytes)
    //   0x0058: Optional header PE32 (224 bytes)
    //   0x0138: Section table (1 entry, 40 bytes)
    //   0x0160: padding to 0x200
    //   0x0200: .text section raw data
    //
    // Total file: 0x600 bytes

    std::vector<uint8_t> pe(0x600, 0);

    // ── DOS header ──
    pe[0] = 'M'; pe[1] = 'Z';
    pe[0x3C] = 0x40;

    // ── PE signature ──
    pe[0x40] = 'P'; pe[0x41] = 'E'; pe[0x42] = 0; pe[0x43] = 0;

    // ── COFF header (20 bytes at 0x44) ──
    pe[0x44] = 0x4C; pe[0x45] = 0x01;  // Machine: i386
    pe[0x46] = 0x01; pe[0x47] = 0x00;  // NumberOfSections: 1
    pe[0x54] = 0xE0; pe[0x55] = 0x00;  // SizeOfOptionalHeader: 224
    pe[0x56] = 0x02; pe[0x57] = 0x01;  // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

    // ── Optional header PE32 (224 bytes at 0x58) ──
    pe[0x58] = 0x0B; pe[0x59] = 0x01;  // Magic: PE32

    // AddressOfEntryPoint at opt+16 = 0x68
    pe[0x68] = 0x00; pe[0x69] = 0x10; pe[0x6A] = 0x00; pe[0x6B] = 0x00;  // EP RVA = 0x1000

    // ImageBase at opt+28 = 0x74
    pe[0x74] = 0x00; pe[0x75] = 0x00; pe[0x76] = 0x40; pe[0x77] = 0x00;  // 0x400000

    // SectionAlignment at opt+32 = 0x78
    pe[0x78] = 0x00; pe[0x79] = 0x10; pe[0x7A] = 0x00; pe[0x7B] = 0x00;  // 0x1000

    // FileAlignment at opt+36 = 0x7C
    pe[0x7C] = 0x00; pe[0x7D] = 0x02; pe[0x7E] = 0x00; pe[0x7F] = 0x00;  // 0x200

    // MajorSubsystemVersion at opt+48 = 0x88
    pe[0x88] = 0x04;

    // SizeOfImage at opt+56 = 0x90
    pe[0x90] = 0x00; pe[0x91] = 0x40; pe[0x92] = 0x00; pe[0x93] = 0x00;  // 0x4000

    // SizeOfHeaders at opt+60 = 0x94
    pe[0x94] = 0x00; pe[0x95] = 0x02; pe[0x96] = 0x00; pe[0x97] = 0x00;  // 0x200

    // Subsystem at opt+68 = 0x9C
    pe[0x9C] = 0x03;  // WINDOWS_CUI

    // NumberOfRvaAndSizes at opt+92 = 0xB4
    pe[0xB4] = 0x10;

    // No import directory (packer doesn't need imports for our test)

    // ── Section table (40 bytes at 0x138) ──
    pe[0x138] = '.'; pe[0x139] = 't'; pe[0x13A] = 'e'; pe[0x13B] = 'x';
    pe[0x13C] = 't';
    // VirtualSize = 0x400
    pe[0x140] = 0x00; pe[0x141] = 0x04;
    // VirtualAddress = 0x1000
    pe[0x144] = 0x00; pe[0x145] = 0x10;
    // SizeOfRawData = 0x400
    pe[0x148] = 0x00; pe[0x149] = 0x04;
    // PointerToRawData = 0x200
    pe[0x14C] = 0x00; pe[0x14D] = 0x02;
    // Characteristics: CODE | EXECUTE | READ | WRITE
    pe[0x164] = 0x20; pe[0x165] = 0x00; pe[0x166] = 0x00; pe[0x167] = 0xE0;

    // ── .text section code (at file offset 0x200, RVA 0x1000, VA 0x401000) ──
    //
    // The unpacker stub writes a small PE at VA 0x402000 (RVA 0x2000),
    // then jumps to its entry point.
    //
    // We use REP STOSB to write the PE payload in bulk, which triggers
    // the write tracking. The payload is a minimal DOS+PE header (256 bytes)
    // followed by a code section with INT3.
    //
    // Strategy: Build the payload bytes in the section data, then the stub
    // code copies them with REP MOVSB to 0x402000 and jumps there.

    // Payload to be written at 0x402000 (a minimal PE with INT3 at EP):
    uint8_t payload[256];
    memset(payload, 0, sizeof(payload));
    // DOS header
    payload[0] = 'M'; payload[1] = 'Z';
    payload[0x3C] = 0x40;
    // PE signature
    payload[0x40] = 'P'; payload[0x41] = 'E';
    // COFF header
    payload[0x44] = 0x4C; payload[0x45] = 0x01;  // i386
    payload[0x46] = 0x01;  // 1 section
    payload[0x54] = 0xE0;  // SizeOfOptionalHeader
    payload[0x56] = 0x02; payload[0x57] = 0x01;
    // Optional header
    payload[0x58] = 0x0B; payload[0x59] = 0x01;  // PE32
    payload[0x68] = 0x00; payload[0x69] = 0x10;  // EP = 0x1000
    payload[0x74] = 0x00; payload[0x75] = 0x00; payload[0x76] = 0x40; payload[0x77] = 0x00;
    payload[0x78] = 0x00; payload[0x79] = 0x10;
    payload[0x7C] = 0x00; payload[0x7D] = 0x02;
    payload[0x90] = 0x00; payload[0x91] = 0x20;  // SizeOfImage = 0x2000
    payload[0x94] = 0x00; payload[0x95] = 0x02;
    payload[0x9C] = 0x03;
    payload[0xB4] = 0x10;

    // Payload section table at 0xC0..0xFF is fine (zeros), we just need enough
    // to be recognized as a PE.

    // Store payload at file offset 0x300 (section data offset 0x100)
    memcpy(&pe[0x300], payload, sizeof(payload));

    // Stub code at 0x200 (VA 0x401000):
    int pos = 0;
    uint8_t* code = &pe[0x200];

    // We need to write 4KB+ to trigger the threshold.
    // Use REP STOSB to fill 0x402000 with 4096+256 bytes of 0x90 (NOP),
    // then REP MOVSB to copy the 256-byte payload to 0x402000.

    // Step 1: Fill 4352 bytes at 0x402000 with NOPs (to hit write threshold)
    // mov edi, 0x402000
    code[pos++] = 0xBF;
    code[pos++] = 0x00; code[pos++] = 0x20; code[pos++] = 0x40; code[pos++] = 0x00;
    // mov ecx, 4352 (0x1100)
    code[pos++] = 0xB9;
    code[pos++] = 0x00; code[pos++] = 0x11; code[pos++] = 0x00; code[pos++] = 0x00;
    // mov al, 0x90
    code[pos++] = 0xB0; code[pos++] = 0x90;
    // cld
    code[pos++] = 0xFC;
    // rep stosb
    code[pos++] = 0xF3; code[pos++] = 0xAA;

    // Step 2: Copy 256-byte payload from 0x401100 (section+0x100) to 0x402000
    // mov esi, 0x401100
    code[pos++] = 0xBE;
    code[pos++] = 0x00; code[pos++] = 0x11; code[pos++] = 0x40; code[pos++] = 0x00;
    // mov edi, 0x402000
    code[pos++] = 0xBF;
    code[pos++] = 0x00; code[pos++] = 0x20; code[pos++] = 0x40; code[pos++] = 0x00;
    // mov ecx, 256
    code[pos++] = 0xB9;
    code[pos++] = 0x00; code[pos++] = 0x01; code[pos++] = 0x00; code[pos++] = 0x00;
    // cld
    code[pos++] = 0xFC;
    // rep movsb
    code[pos++] = 0xF3; code[pos++] = 0xA4;

    // Step 3: Jump to 0x402000 (the "unpacked" code)
    // jmp 0x402000  (using mov eax + jmp eax)
    code[pos++] = 0xB8;
    code[pos++] = 0x00; code[pos++] = 0x20; code[pos++] = 0x40; code[pos++] = 0x00;
    // jmp eax
    code[pos++] = 0xFF; code[pos++] = 0xE0;

    return pe;
}

// Build a PE with XOR-encoded payload that self-decrypts and jumps
static std::vector<uint8_t> build_xor_packed_pe32()
{
    // Same layout as above, but the stub XOR-decodes data before jumping
    std::vector<uint8_t> pe(0x600, 0);

    // ── DOS + PE headers (same as above) ──
    pe[0] = 'M'; pe[1] = 'Z';
    pe[0x3C] = 0x40;
    pe[0x40] = 'P'; pe[0x41] = 'E';
    pe[0x44] = 0x4C; pe[0x45] = 0x01;  // i386
    pe[0x46] = 0x01;  // 1 section
    pe[0x54] = 0xE0;
    pe[0x56] = 0x02; pe[0x57] = 0x01;
    pe[0x58] = 0x0B; pe[0x59] = 0x01;  // PE32
    pe[0x68] = 0x00; pe[0x69] = 0x10;  // EP = 0x1000
    pe[0x74] = 0x00; pe[0x75] = 0x00; pe[0x76] = 0x40; pe[0x77] = 0x00;
    pe[0x78] = 0x00; pe[0x79] = 0x10;
    pe[0x7C] = 0x00; pe[0x7D] = 0x02;
    pe[0x90] = 0x00; pe[0x91] = 0x40;  // SizeOfImage = 0x4000
    pe[0x94] = 0x00; pe[0x95] = 0x02;
    pe[0x9C] = 0x03;
    pe[0xB4] = 0x10;

    pe[0x138] = '.'; pe[0x139] = 't'; pe[0x13A] = 'e'; pe[0x13B] = 'x';
    pe[0x13C] = 't';
    pe[0x140] = 0x00; pe[0x141] = 0x04;
    pe[0x144] = 0x00; pe[0x145] = 0x10;
    pe[0x148] = 0x00; pe[0x149] = 0x04;
    pe[0x14C] = 0x00; pe[0x14D] = 0x02;
    pe[0x164] = 0x20; pe[0x165] = 0x00; pe[0x166] = 0x00; pe[0x167] = 0xE0;

    // Build the cleartext payload (same minimal PE as above)
    uint8_t payload[256];
    memset(payload, 0, sizeof(payload));
    payload[0] = 'M'; payload[1] = 'Z';
    payload[0x3C] = 0x40;
    payload[0x40] = 'P'; payload[0x41] = 'E';
    payload[0x44] = 0x4C; payload[0x45] = 0x01;
    payload[0x46] = 0x01;
    payload[0x54] = 0xE0;
    payload[0x56] = 0x02; payload[0x57] = 0x01;
    payload[0x58] = 0x0B; payload[0x59] = 0x01;
    payload[0x68] = 0x00; payload[0x69] = 0x10;
    payload[0x74] = 0x00; payload[0x75] = 0x00; payload[0x76] = 0x40; payload[0x77] = 0x00;
    payload[0x78] = 0x00; payload[0x79] = 0x10;
    payload[0x7C] = 0x00; payload[0x7D] = 0x02;
    payload[0x90] = 0x00; payload[0x91] = 0x20;
    payload[0x94] = 0x00; payload[0x95] = 0x02;
    payload[0x9C] = 0x03;
    payload[0xB4] = 0x10;

    // XOR-encode payload with key 0x55, store at file offset 0x300
    uint8_t xor_key = 0x55;
    for (int i = 0; i < 256; i++) {
        pe[0x300 + i] = payload[i] ^ xor_key;
    }

    // Stub code at 0x200 (VA 0x401000):
    // 1. Copy 4352 NOP bytes to 0x402000 (hit write threshold)
    // 2. Copy XOR'd payload to 0x402000
    // 3. XOR-decode in place
    // 4. Jump to 0x402000
    int pos = 0;
    uint8_t* code = &pe[0x200];

    // Fill 4352 bytes at 0x402000 with NOPs
    code[pos++] = 0xBF;  // mov edi, 0x402000
    code[pos++] = 0x00; code[pos++] = 0x20; code[pos++] = 0x40; code[pos++] = 0x00;
    code[pos++] = 0xB9;  // mov ecx, 4352
    code[pos++] = 0x00; code[pos++] = 0x11; code[pos++] = 0x00; code[pos++] = 0x00;
    code[pos++] = 0xB0; code[pos++] = 0x90;  // mov al, 0x90
    code[pos++] = 0xFC;  // cld
    code[pos++] = 0xF3; code[pos++] = 0xAA;  // rep stosb

    // Copy 256 XOR'd bytes from 0x401100 to 0x402000
    code[pos++] = 0xBE;  // mov esi, 0x401100
    code[pos++] = 0x00; code[pos++] = 0x11; code[pos++] = 0x40; code[pos++] = 0x00;
    code[pos++] = 0xBF;  // mov edi, 0x402000
    code[pos++] = 0x00; code[pos++] = 0x20; code[pos++] = 0x40; code[pos++] = 0x00;
    code[pos++] = 0xB9;  // mov ecx, 256
    code[pos++] = 0x00; code[pos++] = 0x01; code[pos++] = 0x00; code[pos++] = 0x00;
    code[pos++] = 0xFC;  // cld
    code[pos++] = 0xF3; code[pos++] = 0xA4;  // rep movsb

    // XOR-decode 256 bytes at 0x402000:
    //   mov esi, 0x402000
    //   mov ecx, 256
    // .loop:
    //   xor byte [esi], 0x55
    //   inc esi
    //   dec ecx
    //   jnz .loop
    code[pos++] = 0xBE;  // mov esi, 0x402000
    code[pos++] = 0x00; code[pos++] = 0x20; code[pos++] = 0x40; code[pos++] = 0x00;
    code[pos++] = 0xB9;  // mov ecx, 256
    code[pos++] = 0x00; code[pos++] = 0x01; code[pos++] = 0x00; code[pos++] = 0x00;
    // .loop: xor byte [esi], 0x55
    code[pos++] = 0x80; code[pos++] = 0x36; code[pos++] = 0x55;
    // inc esi
    code[pos++] = 0x46;
    // dec ecx
    code[pos++] = 0x49;
    // jnz .loop (-5 bytes back)
    code[pos++] = 0x75; code[pos++] = 0xF9;

    // Jump to 0x402000
    code[pos++] = 0xB8;  // mov eax, 0x402000
    code[pos++] = 0x00; code[pos++] = 0x20; code[pos++] = 0x40; code[pos++] = 0x00;
    code[pos++] = 0xFF; code[pos++] = 0xE0;  // jmp eax

    return pe;
}

// Build a plain non-packed PE (just does INT3)
static std::vector<uint8_t> build_non_packed_pe32()
{
    std::vector<uint8_t> pe(0x400, 0);

    pe[0] = 'M'; pe[1] = 'Z';
    pe[0x3C] = 0x40;
    pe[0x40] = 'P'; pe[0x41] = 'E';
    pe[0x44] = 0x4C; pe[0x45] = 0x01;
    pe[0x46] = 0x01;
    pe[0x54] = 0xE0;
    pe[0x56] = 0x02; pe[0x57] = 0x01;
    pe[0x58] = 0x0B; pe[0x59] = 0x01;
    pe[0x68] = 0x00; pe[0x69] = 0x10;  // EP = 0x1000
    pe[0x74] = 0x00; pe[0x75] = 0x00; pe[0x76] = 0x40; pe[0x77] = 0x00;
    pe[0x78] = 0x00; pe[0x79] = 0x10;
    pe[0x7C] = 0x00; pe[0x7D] = 0x02;
    pe[0x90] = 0x00; pe[0x91] = 0x20;  // SizeOfImage = 0x2000
    pe[0x94] = 0x00; pe[0x95] = 0x02;
    pe[0x9C] = 0x03;
    pe[0xB4] = 0x10;

    pe[0x138] = '.'; pe[0x139] = 't'; pe[0x13A] = 'e'; pe[0x13B] = 'x';
    pe[0x13C] = 't';
    pe[0x140] = 0x00; pe[0x141] = 0x02;
    pe[0x144] = 0x00; pe[0x145] = 0x10;
    pe[0x148] = 0x00; pe[0x149] = 0x02;
    pe[0x14C] = 0x00; pe[0x14D] = 0x02;
    pe[0x164] = 0x20; pe[0x165] = 0x00; pe[0x166] = 0x00; pe[0x167] = 0x60;

    // Code: just RET (no writes, no jump)
    pe[0x200] = 0xC3;

    return pe;
}


// ── Tests ──

TEST(GenericUnpacker, WriteThenJumpDetected)
{
    auto pe = build_packed_pe32_with_payload();

    uint8_t* out = nullptr;
    size_t out_len = 0;
    akav_gunpack_info_t info;

    bool ok = akav_generic_unpack(pe.data(), pe.size(), &out, &out_len, &info);
    ASSERT_TRUE(ok) << "info.error: " << info.error;
    ASSERT_NE(out, nullptr);
    ASSERT_GT(out_len, 64u);

    // Verify the payload starts with MZ
    EXPECT_EQ(out[0], 'M');
    EXPECT_EQ(out[1], 'Z');

    // Verify PE signature
    uint32_t e_lfanew = *(uint32_t*)(out + 0x3C);
    EXPECT_LT(e_lfanew, out_len);
    if (e_lfanew + 4 <= out_len) {
        EXPECT_EQ(out[e_lfanew], 'P');
        EXPECT_EQ(out[e_lfanew + 1], 'E');
    }

    // Info should show the trigger details
    EXPECT_TRUE(info.unpacked);
    EXPECT_GE(info.bytes_written, AKAV_GUNPACK_WRITE_THRESHOLD);
    EXPECT_GT(info.insn_count, 0u);
    EXPECT_EQ(info.oep, 0x402000u);

    free(out);
}

TEST(GenericUnpacker, XorPackedRecovered)
{
    auto pe = build_xor_packed_pe32();

    uint8_t* out = nullptr;
    size_t out_len = 0;
    akav_gunpack_info_t info;

    bool ok = akav_generic_unpack(pe.data(), pe.size(), &out, &out_len, &info);
    ASSERT_TRUE(ok) << "info.error: " << info.error;
    ASSERT_NE(out, nullptr);

    // The XOR-decoded payload should start with MZ
    EXPECT_EQ(out[0], 'M');
    EXPECT_EQ(out[1], 'Z');

    // Check PE signature
    uint32_t e_lfanew = *(uint32_t*)(out + 0x3C);
    if (e_lfanew + 4 <= out_len) {
        EXPECT_EQ(out[e_lfanew], 'P');
        EXPECT_EQ(out[e_lfanew + 1], 'E');
    }

    EXPECT_TRUE(info.unpacked);
    free(out);
}

TEST(GenericUnpacker, NonPackedNoCrash)
{
    auto pe = build_non_packed_pe32();

    uint8_t* out = nullptr;
    size_t out_len = 0;
    akav_gunpack_info_t info;

    bool ok = akav_generic_unpack(pe.data(), pe.size(), &out, &out_len, &info);

    // Should NOT unpack — no write-then-jump
    EXPECT_FALSE(ok);
    EXPECT_EQ(out, nullptr);
    EXPECT_FALSE(info.unpacked);
    EXPECT_EQ(info.bytes_written, 0u);

    // Should not crash, error message should explain why
    EXPECT_NE(strlen(info.error), 0u);
}

TEST(GenericUnpacker, NullParamsSafe)
{
    EXPECT_FALSE(akav_generic_unpack(nullptr, 0, nullptr, nullptr, nullptr));

    uint8_t* out = nullptr;
    size_t out_len = 0;
    EXPECT_FALSE(akav_generic_unpack(nullptr, 100, &out, &out_len, nullptr));

    uint8_t data[10] = {};
    EXPECT_FALSE(akav_generic_unpack(data, 10, &out, &out_len, nullptr));
}

TEST(GenericUnpacker, InfoPopulatedOnFailure)
{
    auto pe = build_non_packed_pe32();

    uint8_t* out = nullptr;
    size_t out_len = 0;
    akav_gunpack_info_t info;
    memset(&info, 0, sizeof(info));

    akav_generic_unpack(pe.data(), pe.size(), &out, &out_len, &info);

    // Info should have instruction count and error
    EXPECT_FALSE(info.unpacked);
    EXPECT_GT(info.insn_count, 0u);
    EXPECT_NE(strlen(info.error), 0u);
}

TEST(GenericUnpacker, IsLikelyPackedDetectsPackerSections)
{
    auto pe = build_packed_pe32_with_payload();

    // Rename the section to "UPX0"
    pe[0x138] = 'U'; pe[0x139] = 'P'; pe[0x13A] = 'X'; pe[0x13B] = '0';
    pe[0x13C] = 0;

    EXPECT_TRUE(akav_generic_is_likely_packed(pe.data(), pe.size()));
}

TEST(GenericUnpacker, IsLikelyPackedRejectsNormal)
{
    // Build a PE with normal section name and many imports
    auto pe = build_non_packed_pe32();
    // .text section name is already normal
    EXPECT_FALSE(akav_generic_is_likely_packed(pe.data(), pe.size()));
}
