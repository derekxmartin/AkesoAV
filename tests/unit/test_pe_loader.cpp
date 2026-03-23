// test_pe_loader.cpp -- Tests for PE loader + API stubs (P8-T3).
//
// Acceptance criteria:
//   1. Load PE → execution through code
//   2. API calls logged with params
//   3. Memory writes tracked
//
// Additional coverage:
//   - Stub table init/add/lookup/install
//   - PE loader init, section mapping, TEB/PEB setup
//   - INT callback dispatch
//   - Write tracking regions
//   - Minimal PE32 loading and execution

#include <gtest/gtest.h>
#include "emulator/x86_emu.h"
#include "emulator/x86_decode.h"
#include "emulator/winapi_stubs.h"
#include "emulator/pe_loader.h"
#include <cstring>
#include <cstdlib>

// ── Stub table tests ──

TEST(StubTable, InitZeroes)
{
    akav_stub_table_t tbl;
    memset(&tbl, 0xFF, sizeof(tbl));
    akav_stub_table_init(&tbl);
    EXPECT_EQ(tbl.count, 0u);
    EXPECT_EQ(tbl.log_count, 0u);
    EXPECT_EQ(tbl.next_addr, AKAV_STUB_REGION_BASE);
}

TEST(StubTable, InitNullSafe)
{
    akav_stub_table_init(nullptr);  // should not crash
}

TEST(StubTable, AddAndLookup)
{
    akav_stub_table_t tbl;
    akav_stub_table_init(&tbl);

    uint32_t addr1 = akav_stub_table_add(&tbl, "kernel32.dll", "VirtualAlloc", 0x800000);
    ASSERT_NE(addr1, 0u);
    EXPECT_EQ(tbl.count, 1u);

    uint32_t addr2 = akav_stub_table_add(&tbl, "kernel32.dll", "VirtualFree", 1);
    ASSERT_NE(addr2, 0u);
    EXPECT_NE(addr1, addr2);
    EXPECT_EQ(tbl.count, 2u);

    // Lookup
    const akav_stub_entry_t* e1 = akav_stub_table_lookup(&tbl, addr1);
    ASSERT_NE(e1, nullptr);
    EXPECT_STREQ(e1->dll_name, "kernel32.dll");
    EXPECT_STREQ(e1->func_name, "VirtualAlloc");
    EXPECT_EQ(e1->default_ret, 0x800000u);

    // Lookup unknown address
    EXPECT_EQ(akav_stub_table_lookup(&tbl, 0x12345678), nullptr);
}

TEST(StubTable, AddNullParams)
{
    akav_stub_table_t tbl;
    akav_stub_table_init(&tbl);
    EXPECT_EQ(akav_stub_table_add(nullptr, "a", "b", 0), 0u);
    EXPECT_EQ(akav_stub_table_add(&tbl, nullptr, "b", 0), 0u);
    EXPECT_EQ(akav_stub_table_add(&tbl, "a", nullptr, 0), 0u);
}

TEST(StubTable, InstallWritesCode)
{
    akav_stub_table_t tbl;
    akav_stub_table_init(&tbl);
    uint32_t addr = akav_stub_table_add(&tbl, "test.dll", "Func", 42);
    ASSERT_NE(addr, 0u);

    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, AKAV_STUB_REGION_BASE + AKAV_STUB_REGION_SIZE + 0x1000));
    ASSERT_TRUE(akav_stub_table_install(&tbl, &emu.mem));

    // Verify stub code: CD 2E C3
    uint8_t b0, b1, b2;
    EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, addr, &b0));
    EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, addr + 1, &b1));
    EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, addr + 2, &b2));
    EXPECT_EQ(b0, 0xCD);
    EXPECT_EQ(b1, 0x2E);
    EXPECT_EQ(b2, 0xC3);

    akav_x86_emu_free(&emu);
}

// ── INT callback dispatch test ──

static bool test_int_callback(akav_x86_emu_t* emu, uint8_t int_num, void* user_data)
{
    akav_stub_table_t* tbl = (akav_stub_table_t*)user_data;
    if (int_num == 0x2E)
        return akav_stub_dispatch(tbl, emu);
    return false;
}

TEST(StubDispatch, APICallLogged)
{
    // Set up emulator with enough memory for stub region
    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, AKAV_STUB_REGION_BASE + AKAV_STUB_REGION_SIZE + 0x1000));

    akav_stub_table_t tbl;
    akav_stub_table_init(&tbl);

    uint32_t stub_addr = akav_stub_table_add(&tbl, "kernel32.dll", "VirtualAlloc", 0x800000);
    ASSERT_NE(stub_addr, 0u);

    // Install stubs
    ASSERT_TRUE(akav_stub_table_install(&tbl, &emu.mem));

    // Set up INT callback
    emu.int_callback = test_int_callback;
    emu.int_callback_data = &tbl;

    // Build code that CALLs the stub with parameters on stack:
    //   push 0x40        (flProtect = PAGE_EXECUTE_READWRITE)
    //   push 0x3000      (flAllocationType = MEM_COMMIT | MEM_RESERVE)
    //   push 0x1000      (dwSize)
    //   push 0            (lpAddress)
    //   call stub_addr   (CALL VirtualAlloc)
    //   ret
    uint32_t code_base = 0x1000;
    uint8_t code[64];
    int pos = 0;

    // push 0x40
    code[pos++] = 0x6A; code[pos++] = 0x40;
    // push 0x3000
    code[pos++] = 0x68; code[pos++] = 0x00; code[pos++] = 0x30;
    code[pos++] = 0x00; code[pos++] = 0x00;
    // push 0x1000
    code[pos++] = 0x68; code[pos++] = 0x00; code[pos++] = 0x10;
    code[pos++] = 0x00; code[pos++] = 0x00;
    // push 0
    code[pos++] = 0x6A; code[pos++] = 0x00;
    // call stub_addr (E8 rel32)
    code[pos++] = 0xE8;
    uint32_t call_eip = code_base + pos + 4;  // EIP after CALL instruction
    int32_t rel = (int32_t)(stub_addr - call_eip);
    code[pos++] = (uint8_t)(rel & 0xFF);
    code[pos++] = (uint8_t)((rel >> 8) & 0xFF);
    code[pos++] = (uint8_t)((rel >> 16) & 0xFF);
    code[pos++] = (uint8_t)((rel >> 24) & 0xFF);
    // add esp, 16 (clean up 4 params — stubs use plain RET, not RET N)
    code[pos++] = 0x83; code[pos++] = 0xC4; code[pos++] = 0x10;
    // ret
    code[pos++] = 0xC3;

    ASSERT_TRUE(akav_x86_emu_load(&emu, code_base, code, (size_t)pos));
    emu.regs.eip = code_base;

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);

    // Verify EAX = default return value (0x800000)
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0x800000u);

    // Verify API call was logged
    uint32_t log_count = 0;
    const akav_api_call_t* log = akav_stub_get_log(&tbl, &log_count);
    ASSERT_GE(log_count, 1u);
    EXPECT_STREQ(log[0].dll_name, "kernel32.dll");
    EXPECT_STREQ(log[0].func_name, "VirtualAlloc");
    EXPECT_EQ(log[0].return_value, 0x800000u);

    // Verify params (stdcall: first param at [ESP+4])
    // After CALL pushes return address, stack has: ret_addr, 0, 0x1000, 0x3000, 0x40
    EXPECT_EQ(log[0].params[0], 0u);       // lpAddress
    EXPECT_EQ(log[0].params[1], 0x1000u);  // dwSize
    EXPECT_EQ(log[0].params[2], 0x3000u);  // flAllocationType
    EXPECT_EQ(log[0].params[3], 0x40u);    // flProtect

    akav_x86_emu_free(&emu);
}

TEST(StubDispatch, UnhandledIntStillHalts)
{
    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, 64 * 1024));

    akav_stub_table_t tbl;
    akav_stub_table_init(&tbl);
    emu.int_callback = test_int_callback;
    emu.int_callback_data = &tbl;

    // INT 0x21 (not 0x2E) — should halt
    uint8_t code[] = { 0xCD, 0x21 };
    ASSERT_TRUE(akav_x86_emu_load(&emu, 0x1000, code, sizeof(code)));
    emu.regs.eip = 0x1000;

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_INT);
    akav_x86_emu_free(&emu);
}

// ── Write tracking tests ──

static void write_tracker_callback(akav_x86_emu_t* /*emu*/,
                                    uint32_t addr, uint32_t size,
                                    void* user_data)
{
    akav_pe_loader_t* loader = (akav_pe_loader_t*)user_data;
    akav_pe_loader_track_write(loader, addr, size);
}

TEST(WriteTracker, TracksMemoryWrites)
{
    akav_pe_loader_t loader;
    akav_pe_loader_init(&loader);

    akav_pe_loader_track_write(&loader, 0x5000, 0x100);
    akav_pe_loader_track_write(&loader, 0x6000, 0x200);

    EXPECT_TRUE(akav_pe_loader_is_written(&loader, 0x5000));
    EXPECT_TRUE(akav_pe_loader_is_written(&loader, 0x50FF));
    EXPECT_FALSE(akav_pe_loader_is_written(&loader, 0x5100));
    EXPECT_TRUE(akav_pe_loader_is_written(&loader, 0x6100));
    EXPECT_FALSE(akav_pe_loader_is_written(&loader, 0x7000));
    EXPECT_EQ(loader.write_tracker.count, 2u);
    EXPECT_EQ(loader.write_tracker.total_bytes_written, 0x300u);
}

TEST(WriteTracker, MergesAdjacentRegions)
{
    akav_pe_loader_t loader;
    akav_pe_loader_init(&loader);

    akav_pe_loader_track_write(&loader, 0x5000, 0x100);
    akav_pe_loader_track_write(&loader, 0x5100, 0x100);  // adjacent

    EXPECT_EQ(loader.write_tracker.count, 1u);
    EXPECT_TRUE(akav_pe_loader_is_written(&loader, 0x5000));
    EXPECT_TRUE(akav_pe_loader_is_written(&loader, 0x51FF));
}

TEST(WriteTracker, EmulatorWriteCallbackIntegration)
{
    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, 64 * 1024));

    akav_pe_loader_t loader;
    akav_pe_loader_init(&loader);

    emu.write_callback = write_tracker_callback;
    emu.write_callback_data = &loader;

    // Code: mov dword [0x5000], 0x12345678; ret
    uint8_t code[] = {
        0xC7, 0x05, 0x00, 0x50, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12,
        0xC3
    };
    ASSERT_TRUE(akav_x86_emu_load(&emu, 0x1000, code, sizeof(code)));
    emu.regs.eip = 0x1000;

    akav_x86_emu_run(&emu);

    EXPECT_TRUE(akav_pe_loader_is_written(&loader, 0x5000));
    EXPECT_GE(loader.write_tracker.total_bytes_written, 4u);

    akav_x86_emu_free(&emu);
}

TEST(WriteTracker, RepStosbTracked)
{
    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, 64 * 1024));

    akav_pe_loader_t loader;
    akav_pe_loader_init(&loader);

    emu.write_callback = write_tracker_callback;
    emu.write_callback_data = &loader;

    // rep stosb: fill 32 bytes at 0x5000 with 0xCC
    uint8_t code[] = {
        0xBF, 0x00, 0x50, 0x00, 0x00,  // mov edi, 0x5000
        0xB9, 0x20, 0x00, 0x00, 0x00,  // mov ecx, 32
        0xB0, 0xCC,                     // mov al, 0xCC
        0xFC,                           // cld
        0xF3, 0xAA,                     // rep stosb
        0xC3                            // ret
    };
    ASSERT_TRUE(akav_x86_emu_load(&emu, 0x1000, code, sizeof(code)));
    emu.regs.eip = 0x1000;

    akav_x86_emu_run(&emu);

    EXPECT_TRUE(akav_pe_loader_is_written(&loader, 0x5000));
    EXPECT_TRUE(akav_pe_loader_is_written(&loader, 0x501F));
    EXPECT_GE(loader.write_tracker.total_bytes_written, 32u);

    akav_x86_emu_free(&emu);
}

// ── TEB/PEB tests ──

TEST(PELoader, InitZeroes)
{
    akav_pe_loader_t loader;
    memset(&loader, 0xFF, sizeof(loader));
    akav_pe_loader_init(&loader);
    EXPECT_EQ(loader.image_base, 0u);
    EXPECT_EQ(loader.entry_point, 0u);
    EXPECT_EQ(loader.write_tracker.count, 0u);
}

// ── Minimal PE32 loading test ──

// Build a tiny valid PE32 (i386) in memory.
// It has:
//   - DOS header + PE signature
//   - COFF header (i386, 1 section)
//   - Optional header (PE32, ImageBase=0x400000, EP=0x1000)
//   - One section: .text at RVA 0x1000, containing code
//   - One import: kernel32.dll!VirtualAlloc
//
// The code at EP just does: push 0; call [IAT_VirtualAlloc]; ret
//
// Note: We build this manually to keep the test self-contained.

static std::vector<uint8_t> build_minimal_pe32(uint32_t image_base = 0x400000)
{
    // Layout:
    //   0x0000: DOS header (64 bytes, e_lfanew = 0x40)
    //   0x0040: PE signature (4 bytes)
    //   0x0044: COFF header (20 bytes)
    //   0x0058: Optional header PE32 (224 bytes)
    //   0x0138: Section table (1 entry, 40 bytes)
    //   0x0160: padding to 0x200
    //   0x0200: .text section raw data (code + IAT area)
    //
    // Total file: 0x400 bytes

    std::vector<uint8_t> pe(0x400, 0);

    // ── DOS header ──
    pe[0] = 'M'; pe[1] = 'Z';
    // e_lfanew at offset 0x3C
    pe[0x3C] = 0x40;

    // ── PE signature ──
    pe[0x40] = 'P'; pe[0x41] = 'E'; pe[0x42] = 0; pe[0x43] = 0;

    // ── COFF header (20 bytes at 0x44) ──
    pe[0x44] = 0x4C; pe[0x45] = 0x01;  // Machine: i386
    pe[0x46] = 0x01; pe[0x47] = 0x00;  // NumberOfSections: 1
    // TimeDateStamp: 0
    // PointerToSymbolTable: 0
    // NumberOfSymbols: 0
    pe[0x54] = 0xE0; pe[0x55] = 0x00;  // SizeOfOptionalHeader: 224
    pe[0x56] = 0x02; pe[0x57] = 0x01;  // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

    // ── Optional header PE32 (224 bytes at 0x58) ──
    pe[0x58] = 0x0B; pe[0x59] = 0x01;  // Magic: PE32

    // AddressOfEntryPoint at offset 0x58+16 = 0x68
    pe[0x68] = 0x00; pe[0x69] = 0x10; pe[0x6A] = 0x00; pe[0x6B] = 0x00;  // EP RVA = 0x1000

    // ImageBase at offset 0x58+28 = 0x74
    pe[0x74] = (uint8_t)(image_base & 0xFF);
    pe[0x75] = (uint8_t)((image_base >> 8) & 0xFF);
    pe[0x76] = (uint8_t)((image_base >> 16) & 0xFF);
    pe[0x77] = (uint8_t)((image_base >> 24) & 0xFF);

    // SectionAlignment at 0x58+32 = 0x78
    pe[0x78] = 0x00; pe[0x79] = 0x10; pe[0x7A] = 0x00; pe[0x7B] = 0x00;  // 0x1000

    // FileAlignment at 0x58+36 = 0x7C
    pe[0x7C] = 0x00; pe[0x7D] = 0x02; pe[0x7E] = 0x00; pe[0x7F] = 0x00;  // 0x200

    // MajorSubsystemVersion at 0x58+48 = 0x88
    pe[0x88] = 0x04; pe[0x89] = 0x00;

    // SizeOfImage at 0x58+56 = 0x90
    pe[0x90] = 0x00; pe[0x91] = 0x30; pe[0x92] = 0x00; pe[0x93] = 0x00;  // 0x3000

    // SizeOfHeaders at 0x58+60 = 0x94
    pe[0x94] = 0x00; pe[0x95] = 0x02; pe[0x96] = 0x00; pe[0x97] = 0x00;  // 0x200

    // Subsystem at 0x58+68 = 0x9C
    pe[0x9C] = 0x03; pe[0x9D] = 0x00;  // WINDOWS_CUI

    // NumberOfRvaAndSizes at opt+92 = 0x58+92 = 0xB4
    pe[0xB4] = 0x10; pe[0xB5] = 0x00;

    // Import Directory at data_dir[1] = opt+96+8 = 0x58+104 = 0xC0
    // RVA = 0x1080 (after code in .text)
    pe[0xC0] = 0x80; pe[0xC1] = 0x10; pe[0xC2] = 0x00; pe[0xC3] = 0x00;
    // Size = 40 (one descriptor + null terminator)
    pe[0xC4] = 0x28; pe[0xC5] = 0x00;

    // ── Section table (40 bytes at 0x138) ──
    // .text section
    pe[0x138] = '.'; pe[0x139] = 't'; pe[0x13A] = 'e'; pe[0x13B] = 'x';
    pe[0x13C] = 't'; pe[0x13D] = 0;   pe[0x13E] = 0;   pe[0x13F] = 0;
    // VirtualSize
    pe[0x140] = 0x00; pe[0x141] = 0x02; pe[0x142] = 0x00; pe[0x143] = 0x00;  // 0x200
    // VirtualAddress
    pe[0x144] = 0x00; pe[0x145] = 0x10; pe[0x146] = 0x00; pe[0x147] = 0x00;  // 0x1000
    // SizeOfRawData
    pe[0x148] = 0x00; pe[0x149] = 0x02; pe[0x14A] = 0x00; pe[0x14B] = 0x00;  // 0x200
    // PointerToRawData
    pe[0x14C] = 0x00; pe[0x14D] = 0x02; pe[0x14E] = 0x00; pe[0x14F] = 0x00;  // 0x200
    // Characteristics: CODE | EXECUTE | READ
    pe[0x164] = 0x20; pe[0x165] = 0x00; pe[0x166] = 0x00; pe[0x167] = 0x60;

    // ── .text section data (at file offset 0x200) ──
    // Code at offset 0 within section (RVA 0x1000):
    //   push 0         ; 6A 00
    //   call [0x10C0]  ; FF 15 C0 10 + image_base  (IAT entry)
    //   ret            ; C3

    uint32_t iat_va = image_base + 0x10C0;
    pe[0x200] = 0x6A; pe[0x201] = 0x00;              // push 0
    pe[0x202] = 0xFF; pe[0x203] = 0x15;              // call dword ptr [...]
    pe[0x204] = (uint8_t)(iat_va & 0xFF);
    pe[0x205] = (uint8_t)((iat_va >> 8) & 0xFF);
    pe[0x206] = (uint8_t)((iat_va >> 16) & 0xFF);
    pe[0x207] = (uint8_t)((iat_va >> 24) & 0xFF);
    pe[0x208] = 0x83; pe[0x209] = 0xC4; pe[0x20A] = 0x04; // add esp, 4
    pe[0x20B] = 0xC3;                                 // ret

    // Import descriptor at file offset 0x280 (RVA 0x1080):
    // IMAGE_IMPORT_DESCRIPTOR (20 bytes):
    //   OriginalFirstThunk RVA = 0x10A0 (INT)
    //   TimeDateStamp = 0
    //   ForwarderChain = 0
    //   Name RVA = 0x10B0 ("kernel32.dll")
    //   FirstThunk RVA = 0x10C0 (IAT)
    pe[0x280] = 0xA0; pe[0x281] = 0x10; pe[0x282] = 0x00; pe[0x283] = 0x00;  // OriginalFirstThunk
    // timestamp, forwarder: 0
    pe[0x28C] = 0xB0; pe[0x28D] = 0x10; pe[0x28E] = 0x00; pe[0x28F] = 0x00;  // Name RVA
    pe[0x290] = 0xC0; pe[0x291] = 0x10; pe[0x292] = 0x00; pe[0x293] = 0x00;  // FirstThunk (IAT)
    // Null terminator descriptor (20 zero bytes already)

    // OriginalFirstThunk / INT at file offset 0x2A0 (RVA 0x10A0):
    // Pointer to IMAGE_IMPORT_BY_NAME at RVA 0x10D0
    pe[0x2A0] = 0xD0; pe[0x2A1] = 0x10; pe[0x2A2] = 0x00; pe[0x2A3] = 0x00;
    // Null terminator
    pe[0x2A4] = 0x00; pe[0x2A5] = 0x00; pe[0x2A6] = 0x00; pe[0x2A7] = 0x00;

    // DLL name at file offset 0x2B0 (RVA 0x10B0):
    const char* dll = "kernel32.dll";
    memcpy(&pe[0x2B0], dll, strlen(dll) + 1);

    // FirstThunk / IAT at file offset 0x2C0 (RVA 0x10C0):
    // Same as INT: pointer to IMAGE_IMPORT_BY_NAME at RVA 0x10D0
    pe[0x2C0] = 0xD0; pe[0x2C1] = 0x10; pe[0x2C2] = 0x00; pe[0x2C3] = 0x00;
    // Null terminator
    pe[0x2C4] = 0x00; pe[0x2C5] = 0x00; pe[0x2C6] = 0x00; pe[0x2C7] = 0x00;

    // IMAGE_IMPORT_BY_NAME at file offset 0x2D0 (RVA 0x10D0):
    // Hint (2 bytes) + Name
    pe[0x2D0] = 0x00; pe[0x2D1] = 0x00;  // Hint
    const char* func = "VirtualAlloc";
    memcpy(&pe[0x2D2], func, strlen(func) + 1);

    return pe;
}

TEST(PELoader, LoadMinimalPE32)
{
    auto pe_data = build_minimal_pe32();

    akav_x86_emu_t emu;
    // Need enough memory for image + stub region + TEB/PEB
    ASSERT_TRUE(akav_x86_emu_init(&emu, AKAV_STUB_REGION_BASE + AKAV_STUB_REGION_SIZE + 0x10000));

    akav_stub_table_t stubs;
    akav_stub_table_init(&stubs);

    akav_pe_loader_t loader;
    bool ok = akav_pe_loader_load(&loader, &emu, &stubs,
                                   pe_data.data(), pe_data.size());
    ASSERT_TRUE(ok);

    // Verify image_base and entry_point
    EXPECT_EQ(loader.image_base, 0x400000u);
    EXPECT_EQ(loader.entry_point, 0x401000u);
    EXPECT_EQ(emu.regs.eip, 0x401000u);

    // Verify TEB/PEB setup
    uint32_t peb_ptr;
    EXPECT_TRUE(akav_x86_mem_read32(&emu.mem, AKAV_TEB_BASE + 0x30, &peb_ptr));
    EXPECT_EQ(peb_ptr, AKAV_PEB_BASE);

    uint32_t peb_image_base;
    EXPECT_TRUE(akav_x86_mem_read32(&emu.mem, AKAV_PEB_BASE + 0x08, &peb_image_base));
    EXPECT_EQ(peb_image_base, 0x400000u);

    // Verify import was resolved (at least one stub registered)
    EXPECT_GE(stubs.count, 1u);

    // Verify IAT was patched with stub address
    uint32_t iat_entry;
    EXPECT_TRUE(akav_x86_mem_read32(&emu.mem, 0x4010C0, &iat_entry));
    EXPECT_EQ(iat_entry, stubs.entries[0].stub_addr);

    akav_x86_emu_free(&emu);
}

TEST(PELoader, ExecuteMinimalPE32WithStubs)
{
    auto pe_data = build_minimal_pe32();

    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, AKAV_STUB_REGION_BASE + AKAV_STUB_REGION_SIZE + 0x10000));

    akav_stub_table_t stubs;
    akav_stub_table_init(&stubs);

    akav_pe_loader_t loader;
    ASSERT_TRUE(akav_pe_loader_load(&loader, &emu, &stubs,
                                     pe_data.data(), pe_data.size()));

    // Install INT callback
    emu.int_callback = test_int_callback;
    emu.int_callback_data = &stubs;

    // Run the PE
    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);

    // Verify API was called
    uint32_t log_count = 0;
    const akav_api_call_t* log = akav_stub_get_log(&stubs, &log_count);
    ASSERT_GE(log_count, 1u);
    EXPECT_STREQ(log[0].func_name, "VirtualAlloc");

    // Verify return value in EAX
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0x800000u);

    akav_x86_emu_free(&emu);
}

TEST(PELoader, RejectsNullParams)
{
    akav_pe_loader_t loader;
    akav_x86_emu_t emu;
    akav_stub_table_t stubs;
    uint8_t data[64] = {};

    EXPECT_FALSE(akav_pe_loader_load(nullptr, &emu, &stubs, data, 64));
    EXPECT_FALSE(akav_pe_loader_load(&loader, nullptr, &stubs, data, 64));
    EXPECT_FALSE(akav_pe_loader_load(&loader, &emu, nullptr, data, 64));
    EXPECT_FALSE(akav_pe_loader_load(&loader, &emu, &stubs, nullptr, 64));
    EXPECT_FALSE(akav_pe_loader_load(&loader, &emu, &stubs, data, 10));
}

TEST(PELoader, RejectsPE32Plus)
{
    // Build a PE32+ (64-bit) header — just change magic and machine
    auto pe_data = build_minimal_pe32();
    pe_data[0x44] = 0x64; pe_data[0x45] = 0x86;  // Machine: AMD64
    pe_data[0x58] = 0x0B; pe_data[0x59] = 0x02;  // Magic: PE32+

    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, AKAV_STUB_REGION_BASE + AKAV_STUB_REGION_SIZE + 0x10000));
    akav_stub_table_t stubs;
    akav_stub_table_init(&stubs);
    akav_pe_loader_t loader;

    EXPECT_FALSE(akav_pe_loader_load(&loader, &emu, &stubs,
                                      pe_data.data(), pe_data.size()));
    akav_x86_emu_free(&emu);
}

// ── Write tracking during PE execution ──

TEST(PELoader, WriteTrackingDuringExecution)
{
    auto pe_data = build_minimal_pe32();

    // Modify the code to also write to memory before calling VirtualAlloc:
    //   mov dword [0x402000], 0xDEADBEEF  ; C7 05 00 20 40 00 EF BE AD DE
    //   push 0
    //   call [IAT]
    //   ret
    uint32_t iat_va = 0x400000 + 0x10C0;
    pe_data[0x200] = 0xC7; pe_data[0x201] = 0x05;
    pe_data[0x202] = 0x00; pe_data[0x203] = 0x20; pe_data[0x204] = 0x40; pe_data[0x205] = 0x00;
    pe_data[0x206] = 0xEF; pe_data[0x207] = 0xBE; pe_data[0x208] = 0xAD; pe_data[0x209] = 0xDE;
    pe_data[0x20A] = 0x6A; pe_data[0x20B] = 0x00;  // push 0
    pe_data[0x20C] = 0xFF; pe_data[0x20D] = 0x15;  // call [IAT]
    pe_data[0x20E] = (uint8_t)(iat_va & 0xFF);
    pe_data[0x20F] = (uint8_t)((iat_va >> 8) & 0xFF);
    pe_data[0x210] = (uint8_t)((iat_va >> 16) & 0xFF);
    pe_data[0x211] = (uint8_t)((iat_va >> 24) & 0xFF);
    pe_data[0x212] = 0x83; pe_data[0x213] = 0xC4; pe_data[0x214] = 0x04;  // add esp, 4
    pe_data[0x215] = 0xC3;  // ret

    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, AKAV_STUB_REGION_BASE + AKAV_STUB_REGION_SIZE + 0x10000));

    akav_stub_table_t stubs;
    akav_stub_table_init(&stubs);

    akav_pe_loader_t loader;
    ASSERT_TRUE(akav_pe_loader_load(&loader, &emu, &stubs,
                                     pe_data.data(), pe_data.size()));

    // Hook callbacks
    emu.int_callback = test_int_callback;
    emu.int_callback_data = &stubs;
    emu.write_callback = write_tracker_callback;
    emu.write_callback_data = &loader;

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);

    // Verify write at 0x402000 was tracked
    EXPECT_TRUE(akav_pe_loader_is_written(&loader, 0x402000));
    EXPECT_GE(loader.write_tracker.total_bytes_written, 4u);

    akav_x86_emu_free(&emu);
}
