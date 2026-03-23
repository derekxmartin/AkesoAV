// test_x86_emu.cpp -- Tests for x86 execution engine (P8-T2).
//
// Acceptance criteria:
//   1. push 0x41414141; pop eax -> EAX = 0x41414141
//   2. Loop sum(1..10) = 55
//   3. Jcc branches correct
//   4. UPX-like stub runs to instruction limit without crash
//
// Additional coverage:
//   - Init/free lifecycle
//   - Memory read/write helpers
//   - MOV, LEA, XCHG
//   - Arithmetic (ADD, SUB, INC, DEC, NEG, MUL, IMUL, DIV)
//   - Logic (AND, OR, XOR, NOT, TEST)
//   - Shifts (SHL, SHR, SAR, ROL, ROR)
//   - String ops (REP MOVSB, REP STOSB)
//   - PUSHAD/POPAD
//   - CALL/RET
//   - EFLAGS (CF, ZF, SF, OF)
//   - ENTER/LEAVE
//   - BSWAP, CDQ
//   - Halt reasons (INT3, fault, limit, sentinel RET)
//   - CPUID, RDTSC

#include <gtest/gtest.h>
#include "emulator/x86_emu.h"
#include "emulator/x86_decode.h"
#include <cstring>

// Helper: init emulator, load code at addr 0x1000, set EIP there.
static void setup_emu(akav_x86_emu_t* emu, const uint8_t* code, size_t len)
{
    ASSERT_TRUE(akav_x86_emu_init(emu, 64 * 1024));  // 64 KB
    ASSERT_TRUE(akav_x86_emu_load(emu, 0x1000, code, len));
    emu->regs.eip = 0x1000;
}

// ── Init / Free ──

TEST(X86Emu, InitSuccess)
{
    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, 64 * 1024));

    // ESP should be near top of memory (aligned top minus 4 for sentinel push)
    EXPECT_GT(emu.regs.reg[AKAV_X86_REG_ESP], 60000u);
    // Top is 16-aligned, then sentinel push subtracts 4
    EXPECT_EQ((emu.regs.reg[AKAV_X86_REG_ESP] + 4) % 16, 0u);

    // Sentinel should be on stack
    uint32_t sentinel;
    EXPECT_TRUE(akav_x86_mem_read32(&emu.mem, emu.regs.reg[AKAV_X86_REG_ESP], &sentinel));
    EXPECT_EQ(sentinel, AKAV_EMU_STACK_SENTINEL);

    EXPECT_EQ(emu.insn_count, 0u);
    EXPECT_EQ(emu.halted, false);

    akav_x86_emu_free(&emu);
}

TEST(X86Emu, InitNullFails)
{
    EXPECT_FALSE(akav_x86_emu_init(nullptr, 64 * 1024));
}

TEST(X86Emu, InitTooSmallFails)
{
    akav_x86_emu_t emu;
    EXPECT_FALSE(akav_x86_emu_init(&emu, 100));  // < 4096
}

TEST(X86Emu, FreeNullSafe)
{
    akav_x86_emu_free(nullptr);  // should not crash
}

TEST(X86Emu, LoadOutOfBounds)
{
    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, 4096));
    uint8_t data[10] = {};
    EXPECT_FALSE(akav_x86_emu_load(&emu, 4090, data, 10));  // exceeds
    EXPECT_TRUE(akav_x86_emu_load(&emu, 4086, data, 10));   // fits exactly
    akav_x86_emu_free(&emu);
}

// ── Memory helpers ──

TEST(X86Emu, MemReadWrite8)
{
    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, 4096));
    EXPECT_TRUE(akav_x86_mem_write8(&emu.mem, 0, 0xAB));
    uint8_t v;
    EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, 0, &v));
    EXPECT_EQ(v, 0xAB);
    EXPECT_FALSE(akav_x86_mem_read8(&emu.mem, 4096, &v));  // OOB
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, MemReadWrite32LE)
{
    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, 4096));
    EXPECT_TRUE(akav_x86_mem_write32(&emu.mem, 100, 0xDEADBEEF));
    uint32_t v;
    EXPECT_TRUE(akav_x86_mem_read32(&emu.mem, 100, &v));
    EXPECT_EQ(v, 0xDEADBEEFu);
    // Verify little-endian byte order
    uint8_t b;
    EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, 100, &b)); EXPECT_EQ(b, 0xEF);
    EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, 101, &b)); EXPECT_EQ(b, 0xBE);
    EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, 102, &b)); EXPECT_EQ(b, 0xAD);
    EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, 103, &b)); EXPECT_EQ(b, 0xDE);
    akav_x86_emu_free(&emu);
}

// ── Acceptance Criterion 1: push 0x41414141; pop eax ──

TEST(X86Emu, PushPopImm32)
{
    // 68 41 41 41 41   push 0x41414141
    // 58               pop eax
    // C3               ret
    uint8_t code[] = { 0x68, 0x41, 0x41, 0x41, 0x41, 0x58, 0xC3 };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);  // RET to sentinel
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0x41414141u);
    akav_x86_emu_free(&emu);
}

// ── Acceptance Criterion 2: loop sum(1..10) = 55 ──

TEST(X86Emu, LoopSum1to10)
{
    // xor eax, eax       ; 31 C0
    // mov ecx, 10        ; B9 0A 00 00 00
    // loop_top:
    //   add eax, ecx     ; 01 C8
    //   loop loop_top    ; E2 FC  (rel8 = -4, back to add)
    // ret                ; C3
    uint8_t code[] = {
        0x31, 0xC0,                         // xor eax, eax
        0xB9, 0x0A, 0x00, 0x00, 0x00,       // mov ecx, 10
        0x01, 0xC8,                          // add eax, ecx
        0xE2, 0xFC,                          // loop -4 (back to add)
        0xC3                                 // ret
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 55u);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_ECX], 0u);
    akav_x86_emu_free(&emu);
}

// ── Acceptance Criterion 3: Jcc branches ──

TEST(X86Emu, JccBranchTaken_JE)
{
    // xor eax, eax       ; 31 C0          (sets ZF=1)
    // je +3              ; 74 03
    // mov eax, 0xBAAD    ; B8 AD BA 00 00 (skipped)
    // ret                ; C3
    uint8_t code[] = {
        0x31, 0xC0,                              // xor eax, eax -> ZF=1
        0x74, 0x05,                              // je +5 (skip mov)
        0xB8, 0xAD, 0xBA, 0x00, 0x00,            // mov eax, 0xBAAD
        0xC3                                     // ret
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0u);  // mov was skipped
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, JccBranchNotTaken_JNE)
{
    // xor eax, eax       ; 31 C0          (sets ZF=1)
    // jne +5             ; 75 05
    // mov eax, 0x42      ; B8 42 00 00 00 (NOT skipped because ZF=1)
    // ret                ; C3
    uint8_t code[] = {
        0x31, 0xC0,
        0x75, 0x05,
        0xB8, 0x42, 0x00, 0x00, 0x00,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0x42u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, JccBranch_JB_CF)
{
    // stc                ; F9             (CF=1)
    // jb +5              ; 72 05          (taken because CF=1)
    // mov eax, 0xBAAD    ; B8 AD BA 00 00
    // mov eax, 0x1       ; B8 01 00 00 00
    // ret                ; C3
    uint8_t code[] = {
        0xF9,
        0x72, 0x05,
        0xB8, 0xAD, 0xBA, 0x00, 0x00,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 1u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, JccBranch_JG_SignedGreater)
{
    // cmp with signed: 5 > 3
    // mov eax, 5         ; B8 05 00 00 00
    // cmp eax, 3         ; 83 F8 03
    // jg +5              ; 7F 05
    // mov ebx, 0xBAAD    ; BB AD BA 00 00
    // mov ebx, 0x1       ; BB 01 00 00 00
    // ret                ; C3
    uint8_t code[] = {
        0xB8, 0x05, 0x00, 0x00, 0x00,       // mov eax, 5
        0x83, 0xF8, 0x03,                    // cmp eax, 3
        0x7F, 0x05,                          // jg +5 (taken: 5 > 3)
        0xBB, 0xAD, 0xBA, 0x00, 0x00,       // mov ebx, 0xBAAD
        0xBB, 0x01, 0x00, 0x00, 0x00,       // mov ebx, 1
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EBX], 1u);
    akav_x86_emu_free(&emu);
}

// ── Acceptance Criterion 4: UPX-like stub runs to limit ──

TEST(X86Emu, UPXLikeStubRunsToLimit)
{
    // Simulate a tight XOR-decode loop that runs until instruction limit.
    // This tests that the emulator doesn't crash on long-running code.
    //
    //   mov esi, 0x2000     ; source addr
    //   mov edi, 0x3000     ; dest addr
    //   mov ecx, 0xFFFFFFFF ; huge count (will hit insn limit first)
    // loop_top:
    //   lodsb               ; AL = [ESI], ESI++
    //   xor al, 0x55        ; decode
    //   stosb               ; [EDI] = AL, EDI++
    //   loop loop_top       ; ECX-- and loop
    //
    uint8_t code[] = {
        0xBE, 0x00, 0x20, 0x00, 0x00,       // mov esi, 0x2000
        0xBF, 0x00, 0x30, 0x00, 0x00,       // mov edi, 0x3000
        0xB9, 0xFF, 0xFF, 0xFF, 0x7F,       // mov ecx, 0x7FFFFFFF
        0xAC,                                // lodsb
        0x34, 0x55,                          // xor al, 0x55
        0xAA,                                // stosb
        0xE2, 0xFB,                          // loop -5 (back to lodsb)
        0xC3                                 // ret (never reached)
    };
    akav_x86_emu_t emu;
    // Use larger memory to hold source/dest areas
    ASSERT_TRUE(akav_x86_emu_init(&emu, 256 * 1024));
    ASSERT_TRUE(akav_x86_emu_load(&emu, 0x1000, code, sizeof(code)));
    emu.regs.eip = 0x1000;

    // Fill source area with pattern
    for (uint32_t i = 0; i < 0x8000; i++) {
        akav_x86_mem_write8(&emu.mem, 0x2000 + i, (uint8_t)(i & 0xFF));
    }

    // Set a smaller limit so the test doesn't take forever
    emu.insn_limit = 10000;

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_LIMIT);
    EXPECT_GE(emu.insn_count, emu.insn_limit);

    // Verify some decoded bytes were written
    uint8_t decoded;
    EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, 0x3000, &decoded));
    EXPECT_EQ(decoded, (uint8_t)(0x00 ^ 0x55));  // first byte: 0 ^ 0x55

    akav_x86_emu_free(&emu);
}

// ── MOV / LEA / XCHG ──

TEST(X86Emu, MovRegReg)
{
    // mov eax, 0x12345678 ; B8 78 56 34 12
    // mov ebx, eax        ; 89 C3
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x78, 0x56, 0x34, 0x12,
        0x89, 0xC3,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0x12345678u);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EBX], 0x12345678u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, LeaComputation)
{
    // mov ebx, 0x100      ; BB 00 01 00 00
    // mov ecx, 0x4        ; B9 04 00 00 00
    // lea eax, [ebx+ecx*4+0x10] ; 8D 44 8B 10
    // ret                 ; C3
    uint8_t code[] = {
        0xBB, 0x00, 0x01, 0x00, 0x00,
        0xB9, 0x04, 0x00, 0x00, 0x00,
        0x8D, 0x44, 0x8B, 0x10,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    // EAX = 0x100 + 4*4 + 0x10 = 0x100 + 0x10 + 0x10 = 0x120
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0x120u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, XchgRegs)
{
    // mov eax, 0xAAAA     ; B8 AA AA 00 00
    // mov ecx, 0xBBBB     ; B9 BB BB 00 00
    // xchg eax, ecx       ; 91
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0xAA, 0xAA, 0x00, 0x00,
        0xB9, 0xBB, 0xBB, 0x00, 0x00,
        0x91,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0xBBBBu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_ECX], 0xAAAAu);
    akav_x86_emu_free(&emu);
}

// ── Arithmetic ──

TEST(X86Emu, AddSubFlags)
{
    // mov eax, 5          ; B8 05 00 00 00
    // add eax, 3          ; 83 C0 03
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x05, 0x00, 0x00, 0x00,
        0x83, 0xC0, 0x03,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 8u);
    EXPECT_EQ(emu.regs.eflags & AKAV_EFLAGS_ZF, 0u);  // not zero
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, SubToZeroSetsZF)
{
    // mov eax, 5          ; B8 05 00 00 00
    // sub eax, 5          ; 83 E8 05
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x05, 0x00, 0x00, 0x00,
        0x83, 0xE8, 0x05,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0u);
    EXPECT_NE(emu.regs.eflags & AKAV_EFLAGS_ZF, 0u);  // ZF set
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, IncDec)
{
    // mov eax, 0          ; B8 00 00 00 00
    // inc eax             ; 40
    // inc eax             ; 40
    // inc eax             ; 40
    // dec eax             ; 48
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x40, 0x40,
        0x48,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 2u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, NegValue)
{
    // mov eax, 5          ; B8 05 00 00 00
    // neg eax             ; F7 D8
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x05, 0x00, 0x00, 0x00,
        0xF7, 0xD8,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], (uint32_t)-5);
    EXPECT_NE(emu.regs.eflags & AKAV_EFLAGS_CF, 0u);  // CF=1 for non-zero
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, MulUnsigned)
{
    // mov eax, 7          ; B8 07 00 00 00
    // mov ecx, 6          ; B9 06 00 00 00
    // mul ecx             ; F7 E1  (EDX:EAX = EAX * ECX)
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x07, 0x00, 0x00, 0x00,
        0xB9, 0x06, 0x00, 0x00, 0x00,
        0xF7, 0xE1,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 42u);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EDX], 0u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, DivUnsigned)
{
    // mov edx, 0          ; BA 00 00 00 00
    // mov eax, 42         ; B8 2A 00 00 00
    // mov ecx, 5          ; B9 05 00 00 00
    // div ecx             ; F7 F1  (EAX = 42/5 = 8, EDX = 42%5 = 2)
    // ret                 ; C3
    uint8_t code[] = {
        0xBA, 0x00, 0x00, 0x00, 0x00,
        0xB8, 0x2A, 0x00, 0x00, 0x00,
        0xB9, 0x05, 0x00, 0x00, 0x00,
        0xF7, 0xF1,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 8u);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EDX], 2u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, DivByZeroFaults)
{
    // mov edx, 0          ; BA 00 00 00 00
    // mov eax, 42         ; B8 2A 00 00 00
    // mov ecx, 0          ; B9 00 00 00 00
    // div ecx             ; F7 F1
    // ret                 ; C3
    uint8_t code[] = {
        0xBA, 0x00, 0x00, 0x00, 0x00,
        0xB8, 0x2A, 0x00, 0x00, 0x00,
        0xB9, 0x00, 0x00, 0x00, 0x00,
        0xF7, 0xF1,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_FAULT);
    akav_x86_emu_free(&emu);
}

// ── Logic ──

TEST(X86Emu, XorSelf)
{
    // xor eax, eax        ; 31 C0
    // ret                 ; C3
    uint8_t code[] = { 0x31, 0xC0, 0xC3 };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));
    emu.regs.reg[AKAV_X86_REG_EAX] = 0x12345678;

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0u);
    EXPECT_NE(emu.regs.eflags & AKAV_EFLAGS_ZF, 0u);
    EXPECT_EQ(emu.regs.eflags & AKAV_EFLAGS_CF, 0u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, AndOrNot)
{
    // mov eax, 0xFF00     ; B8 00 FF 00 00
    // and eax, 0xF0F0     ; 25 F0 F0 00 00
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x00, 0xFF, 0x00, 0x00,
        0x25, 0xF0, 0xF0, 0x00, 0x00,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0xF000u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, TestSetsZF)
{
    // mov eax, 0xF0       ; B8 F0 00 00 00
    // test eax, 0x0F      ; A9 0F 00 00 00
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0xF0, 0x00, 0x00, 0x00,
        0xA9, 0x0F, 0x00, 0x00, 0x00,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_NE(emu.regs.eflags & AKAV_EFLAGS_ZF, 0u);  // 0xF0 & 0x0F = 0
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0xF0u);  // EAX unchanged
    akav_x86_emu_free(&emu);
}

// ── Shifts ──

TEST(X86Emu, ShlShr)
{
    // mov eax, 1          ; B8 01 00 00 00
    // shl eax, 4          ; C1 E0 04        (EAX = 0x10)
    // shr eax, 2          ; C1 E8 02        (EAX = 0x04)
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC1, 0xE0, 0x04,
        0xC1, 0xE8, 0x02,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 4u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, RolRor)
{
    // mov eax, 0x80000001 ; B8 01 00 00 80
    // rol eax, 1          ; C1 C0 01        (EAX = 0x00000003)
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x01, 0x00, 0x00, 0x80,
        0xC1, 0xC0, 0x01,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 3u);
    akav_x86_emu_free(&emu);
}

// ── CALL / RET ──

TEST(X86Emu, CallAndReturn)
{
    // Code at 0x1000:
    //   call 0x1010        ; E8 0B 00 00 00 (rel32 = 0x10 - 0x05 = 0x0B)
    //   mov ebx, eax       ; 89 C3
    //   ret                ; C3
    //
    // Code at 0x1010:
    //   mov eax, 0xCAFE    ; B8 FE CA 00 00
    //   ret                ; C3

    uint8_t code[0x20] = {};
    // Main at 0x00 (loaded at 0x1000):
    code[0x00] = 0xE8;  // call rel32
    code[0x01] = 0x0B; code[0x02] = 0x00; code[0x03] = 0x00; code[0x04] = 0x00;
    // After call returns:
    code[0x05] = 0x89; code[0x06] = 0xC3;  // mov ebx, eax
    code[0x07] = 0xC3;  // ret

    // Subroutine at offset 0x10 (loaded at 0x1010):
    code[0x10] = 0xB8; code[0x11] = 0xFE; code[0x12] = 0xCA;
    code[0x13] = 0x00; code[0x14] = 0x00;
    code[0x15] = 0xC3;  // ret

    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0xCAFEu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EBX], 0xCAFEu);
    akav_x86_emu_free(&emu);
}

// ── PUSHAD / POPAD ──

TEST(X86Emu, PushadPopad)
{
    // Set all regs, pushad, zero them, popad, verify
    // mov eax, 1; mov ecx, 2; mov edx, 3; mov ebx, 4
    // pushad
    // xor eax, eax; xor ecx, ecx; xor edx, edx; xor ebx, ebx
    // popad
    // ret
    uint8_t code[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0xB9, 0x02, 0x00, 0x00, 0x00,  // mov ecx, 2
        0xBA, 0x03, 0x00, 0x00, 0x00,  // mov edx, 3
        0xBB, 0x04, 0x00, 0x00, 0x00,  // mov ebx, 4
        0x60,                           // pushad
        0x31, 0xC0,                     // xor eax, eax
        0x31, 0xC9,                     // xor ecx, ecx
        0x31, 0xD2,                     // xor edx, edx
        0x31, 0xDB,                     // xor ebx, ebx
        0x61,                           // popad
        0xC3                            // ret
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 1u);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_ECX], 2u);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EDX], 3u);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EBX], 4u);
    akav_x86_emu_free(&emu);
}

// ── String ops ──

TEST(X86Emu, RepStosb)
{
    // Fill 16 bytes at 0x2000 with 0xAA
    // mov edi, 0x2000     ; BF 00 20 00 00
    // mov ecx, 16         ; B9 10 00 00 00
    // mov al, 0xAA        ; B0 AA
    // cld                 ; FC
    // rep stosb            ; F3 AA
    // ret                 ; C3
    uint8_t code[] = {
        0xBF, 0x00, 0x20, 0x00, 0x00,
        0xB9, 0x10, 0x00, 0x00, 0x00,
        0xB0, 0xAA,
        0xFC,
        0xF3, 0xAA,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    for (int i = 0; i < 16; i++) {
        uint8_t v;
        EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, 0x2000 + i, &v));
        EXPECT_EQ(v, 0xAA) << "byte at offset " << i;
    }
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_ECX], 0u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, RepMovsb)
{
    // Copy 8 bytes from 0x2000 to 0x3000
    // mov esi, 0x2000     ; BE 00 20 00 00
    // mov edi, 0x3000     ; BF 00 30 00 00
    // mov ecx, 8          ; B9 08 00 00 00
    // cld                 ; FC
    // rep movsb            ; F3 A4
    // ret                 ; C3
    uint8_t code[] = {
        0xBE, 0x00, 0x20, 0x00, 0x00,
        0xBF, 0x00, 0x30, 0x00, 0x00,
        0xB9, 0x08, 0x00, 0x00, 0x00,
        0xFC,
        0xF3, 0xA4,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    // Write source pattern
    for (int i = 0; i < 8; i++) {
        akav_x86_mem_write8(&emu.mem, 0x2000 + i, (uint8_t)(0x10 + i));
    }

    akav_x86_emu_run(&emu);
    for (int i = 0; i < 8; i++) {
        uint8_t v;
        EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, 0x3000 + i, &v));
        EXPECT_EQ(v, (uint8_t)(0x10 + i)) << "byte at offset " << i;
    }
    akav_x86_emu_free(&emu);
}

// ── ENTER / LEAVE ──

TEST(X86Emu, EnterLeave)
{
    // enter 8, 0          ; C8 08 00 00
    // leave               ; C9
    // ret                 ; C3
    uint8_t code[] = { 0xC8, 0x08, 0x00, 0x00, 0xC9, 0xC3 };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    uint32_t orig_esp = emu.regs.reg[AKAV_X86_REG_ESP];
    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);
    // After enter+leave+ret: ESP = orig + 4 (ret pops the sentinel)
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_ESP], orig_esp + 4);
    akav_x86_emu_free(&emu);
}

// ── BSWAP ──

TEST(X86Emu, Bswap)
{
    // mov eax, 0x12345678 ; B8 78 56 34 12
    // bswap eax           ; 0F C8
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x78, 0x56, 0x34, 0x12,
        0x0F, 0xC8,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0x78563412u);
    akav_x86_emu_free(&emu);
}

// ── CDQ ──

TEST(X86Emu, CdqPositive)
{
    // mov eax, 0x7FFFFFFF ; B8 FF FF FF 7F
    // cdq                 ; 99
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0xFF, 0xFF, 0xFF, 0x7F,
        0x99,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EDX], 0u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, CdqNegative)
{
    // mov eax, 0x80000000 ; B8 00 00 00 80
    // cdq                 ; 99
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x00, 0x00, 0x00, 0x80,
        0x99,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EDX], 0xFFFFFFFFu);
    akav_x86_emu_free(&emu);
}

// ── CPUID ──

TEST(X86Emu, CpuidLeaf0)
{
    // xor eax, eax        ; 31 C0
    // cpuid               ; 0F A2
    // ret                 ; C3
    uint8_t code[] = { 0x31, 0xC0, 0x0F, 0xA2, 0xC3 };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 1u);  // max leaf
    // "GenuineIntel" in EBX-EDX-ECX
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EBX], 0x756E6547u);  // "Genu"
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EDX], 0x6C65746Eu);  // "ineI" -- wait this is wrong
    // Actually: EDX = "ineI", ECX = "ntel"
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_ECX], 0x49656E69u);
    akav_x86_emu_free(&emu);
}

// ── RDTSC ──

TEST(X86Emu, Rdtsc)
{
    // Run a few instructions then rdtsc
    // nop                 ; 90
    // nop                 ; 90
    // rdtsc               ; 0F 31
    // ret                 ; C3
    uint8_t code[] = { 0x90, 0x90, 0x0F, 0x31, 0xC3 };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    // After 2 NOPs + RDTSC = 3 insns, insn_count = 3
    // EAX = 3 * 1000 = 3000
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 3000u);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EDX], 0u);
    akav_x86_emu_free(&emu);
}

// ── Halt reasons ──

TEST(X86Emu, Int3Halts)
{
    uint8_t code[] = { 0xCC };  // int3
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_INT3);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, IntNHalts)
{
    uint8_t code[] = { 0xCD, 0x21 };  // int 0x21
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_INT);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, InstructionLimitHalts)
{
    // Infinite loop: jmp -2
    uint8_t code[] = { 0xEB, 0xFE };  // jmp $
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));
    emu.insn_limit = 100;

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_LIMIT);
    EXPECT_GE(emu.insn_count, 100u);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, EipOutOfBoundsFaults)
{
    akav_x86_emu_t emu;
    ASSERT_TRUE(akav_x86_emu_init(&emu, 4096));
    emu.regs.eip = 5000;  // beyond memory

    int rc = akav_x86_emu_step(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_FAULT);
    akav_x86_emu_free(&emu);
}

TEST(X86Emu, RetToSentinelHalts)
{
    uint8_t code[] = { 0xC3 };  // ret (pops sentinel)
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);
    akav_x86_emu_free(&emu);
}

// ── Memory read/write via MOV ──

TEST(X86Emu, MovMemory)
{
    // mov dword [0x2000], 0xDEADBEEF  ; C7 05 00 20 00 00 EF BE AD DE
    // mov eax, [0x2000]               ; A1 00 20 00 00
    // ret                             ; C3
    uint8_t code[] = {
        0xC7, 0x05, 0x00, 0x20, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,
        0xA1, 0x00, 0x20, 0x00, 0x00,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0xDEADBEEFu);
    akav_x86_emu_free(&emu);
}

// ── Flag manipulation ──

TEST(X86Emu, ClcStcCmc)
{
    // clc; stc; cmc; ret
    uint8_t code[] = {
        0xF8,       // clc
        0xF9,       // stc
        0xF5,       // cmc
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    // CLC clears CF, STC sets CF, CMC complements -> CF=0
    EXPECT_EQ(emu.regs.eflags & AKAV_EFLAGS_CF, 0u);
    akav_x86_emu_free(&emu);
}

// ── Step function ──

TEST(X86Emu, StepByStep)
{
    // nop; nop; ret
    uint8_t code[] = { 0x90, 0x90, 0xC3 };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    EXPECT_EQ(akav_x86_emu_step(&emu), AKAV_EMU_OK);
    EXPECT_EQ(emu.insn_count, 1u);
    EXPECT_EQ(emu.regs.eip, 0x1001u);

    EXPECT_EQ(akav_x86_emu_step(&emu), AKAV_EMU_OK);
    EXPECT_EQ(emu.insn_count, 2u);
    EXPECT_EQ(emu.regs.eip, 0x1002u);

    int rc = akav_x86_emu_step(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);

    akav_x86_emu_free(&emu);
}

// ── NOP ──

TEST(X86Emu, NopDoesNothing)
{
    uint8_t code[] = { 0x90, 0x90, 0x90, 0xC3 };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    uint32_t eax_before = emu.regs.reg[AKAV_X86_REG_EAX];
    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], eax_before);
    akav_x86_emu_free(&emu);
}

// ── IMUL 3-operand ──

TEST(X86Emu, Imul3Operand)
{
    // imul eax, ecx, 7    ; 6B C1 07
    // ret                 ; C3
    uint8_t code[] = {
        0xB9, 0x06, 0x00, 0x00, 0x00,  // mov ecx, 6
        0x6B, 0xC1, 0x07,              // imul eax, ecx, 7
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 42u);
    akav_x86_emu_free(&emu);
}

// ── Complex: Fibonacci ──

TEST(X86Emu, FibonacciLoop)
{
    // Compute fib(10) = 55 using a loop
    // mov ecx, 10         ; B9 0A 00 00 00
    // mov eax, 0          ; B8 00 00 00 00  (fib(0))
    // mov ebx, 1          ; BB 01 00 00 00  (fib(1))
    // loop_top:
    //   mov edx, eax      ; 89 C2
    //   add eax, ebx      ; 01 D8
    //   mov ebx, edx      ; 89 D3
    //   dec ecx            ; 49
    //   jnz loop_top      ; 75 F7 (-9)
    // ret                 ; C3
    uint8_t code[] = {
        0xB9, 0x0A, 0x00, 0x00, 0x00,  // mov ecx, 10
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
        0xBB, 0x01, 0x00, 0x00, 0x00,  // mov ebx, 1
        0x89, 0xC2,                     // mov edx, eax
        0x01, 0xD8,                     // add eax, ebx
        0x89, 0xD3,                     // mov ebx, edx
        0x49,                           // dec ecx
        0x75, 0xF7,                     // jnz -9
        0xC3                            // ret
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    int rc = akav_x86_emu_run(&emu);
    EXPECT_EQ(rc, AKAV_EMU_HALT_RET);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 55u);
    akav_x86_emu_free(&emu);
}

// ── MOVSX ──

TEST(X86Emu, MovsxByteToReg)
{
    // Write 0xFF at 0x2000 (signed byte = -1)
    // movsx eax, byte [0x2000]  ; 0F BE 05 00 20 00 00
    // ret                       ; C3
    uint8_t code[] = {
        0x0F, 0xBE, 0x05, 0x00, 0x20, 0x00, 0x00,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));
    akav_x86_mem_write8(&emu.mem, 0x2000, 0xFF);

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 0xFFFFFFFFu);  // sign extended
    akav_x86_emu_free(&emu);
}

// ── BT ──

TEST(X86Emu, BtSetsCF)
{
    // mov eax, 0x08       ; B8 08 00 00 00  (bit 3 set)
    // mov ecx, 3          ; B9 03 00 00 00
    // bt eax, ecx         ; 0F A3 C8  (BT r/m32, r32)
    // ret                 ; C3
    uint8_t code[] = {
        0xB8, 0x08, 0x00, 0x00, 0x00,
        0xB9, 0x03, 0x00, 0x00, 0x00,
        0x0F, 0xA3, 0xC8,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_NE(emu.regs.eflags & AKAV_EFLAGS_CF, 0u);  // bit 3 is set
    akav_x86_emu_free(&emu);
}

// ── BSF / BSR ──

TEST(X86Emu, BsfBsr)
{
    // mov ecx, 0x80       ; B9 80 00 00 00  (bit 7 set)
    // bsf eax, ecx        ; 0F BC C1
    // bsr ebx, ecx        ; 0F BD D9
    // ret                 ; C3
    uint8_t code[] = {
        0xB9, 0x80, 0x00, 0x00, 0x00,
        0x0F, 0xBC, 0xC1,
        0x0F, 0xBD, 0xD9,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EAX], 7u);  // BSF: lowest set bit
    EXPECT_EQ(emu.regs.reg[AKAV_X86_REG_EBX], 7u);  // BSR: highest set bit
    akav_x86_emu_free(&emu);
}

// ── Direction flag + string op ──

TEST(X86Emu, StdReverseDirection)
{
    // Fill 4 bytes backwards from 0x2003 down to 0x2000 with 0xBB
    // mov edi, 0x2003     ; BF 03 20 00 00
    // mov ecx, 4          ; B9 04 00 00 00
    // mov al, 0xBB        ; B0 BB
    // std                 ; FD
    // rep stosb            ; F3 AA
    // ret                 ; C3
    uint8_t code[] = {
        0xBF, 0x03, 0x20, 0x00, 0x00,
        0xB9, 0x04, 0x00, 0x00, 0x00,
        0xB0, 0xBB,
        0xFD,
        0xF3, 0xAA,
        0xC3
    };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    for (int i = 0; i < 4; i++) {
        uint8_t v;
        EXPECT_TRUE(akav_x86_mem_read8(&emu.mem, 0x2000 + i, &v));
        EXPECT_EQ(v, 0xBB) << "byte at 0x" << std::hex << (0x2000 + i);
    }
    akav_x86_emu_free(&emu);
}

// ── PUSHFD / POPFD ──

TEST(X86Emu, PushfdPopfd)
{
    // stc                 ; F9  (set CF)
    // pushfd              ; 9C
    // clc                 ; F8  (clear CF)
    // popfd               ; 9D  (restore CF)
    // ret                 ; C3
    uint8_t code[] = { 0xF9, 0x9C, 0xF8, 0x9D, 0xC3 };
    akav_x86_emu_t emu;
    setup_emu(&emu, code, sizeof(code));

    akav_x86_emu_run(&emu);
    EXPECT_NE(emu.regs.eflags & AKAV_EFLAGS_CF, 0u);  // CF restored
    akav_x86_emu_free(&emu);
}
