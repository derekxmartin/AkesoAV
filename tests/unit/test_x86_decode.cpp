/* test_x86_decode.cpp — Unit tests for x86 instruction decoder. */

#include <gtest/gtest.h>
#include "emulator/x86_decode.h"
#include <cstring>
#include <vector>

/* Helper: decode a single instruction from byte array */
static akav_x86_insn_t decode(const std::vector<uint8_t>& bytes)
{
    akav_x86_insn_t insn;
    memset(&insn, 0, sizeof(insn));
    akav_x86_decode(&insn, bytes.data(), bytes.size());
    return insn;
}

/* ── Basic instruction decode tests ───────────────────────────── */

TEST(X86Decode, Nop)
{
    auto insn = decode({0x90});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 1);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_NOP);
}

TEST(X86Decode, PushEbp)
{
    auto insn = decode({0x55});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 1);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_PUSH);
    EXPECT_EQ(insn.num_operands, 1);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_REG);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EBP);
}

TEST(X86Decode, PopEax)
{
    auto insn = decode({0x58});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_POP);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EAX);
}

TEST(X86Decode, MovEbpEsp)
{
    /* 89 E5 = MOV EBP, ESP (r/m32, r32: mod=3, reg=ESP, rm=EBP) */
    auto insn = decode({0x89, 0xE5});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 2);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOV);
    EXPECT_EQ(insn.num_operands, 2);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_REG);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EBP);
    EXPECT_EQ(insn.operands[1].type, AKAV_X86_OP_REG);
    EXPECT_EQ(insn.operands[1].reg, AKAV_X86_REG_ESP);
}

TEST(X86Decode, MovEaxImm32)
{
    /* B8 41414141 = MOV EAX, 0x41414141 */
    auto insn = decode({0xB8, 0x41, 0x41, 0x41, 0x41});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 5);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOV);
    EXPECT_EQ(insn.num_operands, 2);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EAX);
    EXPECT_EQ(insn.operands[1].type, AKAV_X86_OP_IMM);
    EXPECT_EQ(insn.operands[1].imm, 0x41414141);
}

TEST(X86Decode, PushImm32)
{
    /* 68 78563412 = PUSH 0x12345678 */
    auto insn = decode({0x68, 0x78, 0x56, 0x34, 0x12});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 5);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_PUSH);
    EXPECT_EQ(insn.operands[0].imm, 0x12345678);
}

TEST(X86Decode, PushImm8)
{
    /* 6A 0A = PUSH 0x0A */
    auto insn = decode({0x6A, 0x0A});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 2);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_PUSH);
    EXPECT_EQ(insn.operands[0].imm, 0x0A);
}

TEST(X86Decode, Ret)
{
    auto insn = decode({0xC3});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 1);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_RET);
}

TEST(X86Decode, RetImm16)
{
    /* C2 0800 = RET 8 */
    auto insn = decode({0xC2, 0x08, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 3);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_RETN);
    EXPECT_EQ(insn.operands[0].imm, 8);
}

TEST(X86Decode, CallRel32)
{
    /* E8 00100000 = CALL +0x1000 */
    auto insn = decode({0xE8, 0x00, 0x10, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 5);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_CALL);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_REL);
    EXPECT_EQ(insn.operands[0].imm, 0x1000);
}

TEST(X86Decode, JmpRel8)
{
    /* EB FE = JMP -2 (infinite loop) */
    auto insn = decode({0xEB, 0xFE});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 2);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_JMP);
    EXPECT_EQ(insn.operands[0].imm, -2);
}

TEST(X86Decode, JmpRel32)
{
    /* E9 FBFFFFFF = JMP -5 */
    auto insn = decode({0xE9, 0xFB, 0xFF, 0xFF, 0xFF});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 5);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_JMP);
    EXPECT_EQ(insn.operands[0].imm, -5);
}

TEST(X86Decode, JccRel8)
{
    /* 74 10 = JZ +0x10 */
    auto insn = decode({0x74, 0x10});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 2);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_JCC);
    EXPECT_EQ(insn.operands[0].imm, 0x10);
}

TEST(X86Decode, JccRel32)
{
    /* 0F 85 00020000 = JNZ +0x200 */
    auto insn = decode({0x0F, 0x85, 0x00, 0x02, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 6);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_JCC);
    EXPECT_EQ(insn.operands[0].imm, 0x200);
}

TEST(X86Decode, XorEaxEax)
{
    /* 31 C0 = XOR EAX, EAX */
    auto insn = decode({0x31, 0xC0});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_XOR);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EAX);
    EXPECT_EQ(insn.operands[1].reg, AKAV_X86_REG_EAX);
}

TEST(X86Decode, AddEaxImm32)
{
    /* 05 01000000 = ADD EAX, 1 */
    auto insn = decode({0x05, 0x01, 0x00, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_ADD);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EAX);
    EXPECT_EQ(insn.operands[1].imm, 1);
}

TEST(X86Decode, SubEspImm8)
{
    /* 83 EC 10 = SUB ESP, 0x10 */
    auto insn = decode({0x83, 0xEC, 0x10});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 3);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_SUB);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_REG);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_ESP);
    EXPECT_EQ(insn.operands[1].imm, 0x10);
}

TEST(X86Decode, CmpEaxImm32)
{
    /* 3D 00100000 = CMP EAX, 0x1000 */
    auto insn = decode({0x3D, 0x00, 0x10, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_CMP);
}

TEST(X86Decode, TestAlImm8)
{
    /* A8 01 = TEST AL, 1 */
    auto insn = decode({0xA8, 0x01});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_TEST);
    EXPECT_EQ(insn.operands[0].size, 1);
}

TEST(X86Decode, LeaEaxMem)
{
    /* 8D 44 24 08 = LEA EAX, [ESP+8] */
    auto insn = decode({0x8D, 0x44, 0x24, 0x08});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 4);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_LEA);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_REG);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EAX);
    EXPECT_EQ(insn.operands[1].type, AKAV_X86_OP_MEM);
    EXPECT_TRUE(insn.has_sib);
    EXPECT_EQ(insn.operands[1].disp, 8);
}

TEST(X86Decode, IncEcx)
{
    /* 41 = INC ECX */
    auto insn = decode({0x41});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_INC);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_ECX);
}

TEST(X86Decode, DecEsi)
{
    /* 4E = DEC ESI */
    auto insn = decode({0x4E});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_DEC);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_ESI);
}

TEST(X86Decode, Int3)
{
    auto insn = decode({0xCC});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_INT3);
}

TEST(X86Decode, IntImm8)
{
    /* CD 80 = INT 0x80 */
    auto insn = decode({0xCD, 0x80});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_INT);
    EXPECT_EQ(insn.operands[0].imm, 0x80);
}

TEST(X86Decode, Leave)
{
    auto insn = decode({0xC9});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_LEAVE);
}

TEST(X86Decode, Pushad)
{
    auto insn = decode({0x60});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_PUSHAD);
}

TEST(X86Decode, Popad)
{
    auto insn = decode({0x61});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_POPAD);
}

TEST(X86Decode, Cdq)
{
    auto insn = decode({0x99});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_CDQ);
}

TEST(X86Decode, Clc)
{
    auto insn = decode({0xF8});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_CLC);
}

TEST(X86Decode, Stc)
{
    auto insn = decode({0xF9});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_STC);
}

TEST(X86Decode, Cld)
{
    auto insn = decode({0xFC});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_CLD);
}

TEST(X86Decode, Std)
{
    auto insn = decode({0xFD});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_STD);
}

/* ── String instructions ──────────────────────────────────────── */

TEST(X86Decode, Movsb)
{
    auto insn = decode({0xA4});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOVSB);
}

TEST(X86Decode, Movsd)
{
    auto insn = decode({0xA5});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOVSD);
}

TEST(X86Decode, Stosb)
{
    auto insn = decode({0xAA});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_STOSB);
}

TEST(X86Decode, Stosd)
{
    auto insn = decode({0xAB});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_STOSD);
}

TEST(X86Decode, Lodsb)
{
    auto insn = decode({0xAC});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_LODSB);
}

TEST(X86Decode, Scasb)
{
    auto insn = decode({0xAE});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_SCASB);
}

/* ── Prefix tests ─────────────────────────────────────────────── */

TEST(X86Decode, RepMovsb)
{
    /* F3 A4 = REP MOVSB */
    auto insn = decode({0xF3, 0xA4});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 2);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOVSB);
    EXPECT_TRUE(insn.prefixes & AKAV_X86_PFX_REP);
    EXPECT_EQ(insn.num_prefixes, 1);
}

TEST(X86Decode, RepneScasb)
{
    /* F2 AE = REPNE SCASB */
    auto insn = decode({0xF2, 0xAE});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_SCASB);
    EXPECT_TRUE(insn.prefixes & AKAV_X86_PFX_REPNE);
}

TEST(X86Decode, RepStosd)
{
    /* F3 AB = REP STOSD */
    auto insn = decode({0xF3, 0xAB});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_STOSD);
    EXPECT_TRUE(insn.prefixes & AKAV_X86_PFX_REP);
}

TEST(X86Decode, LockAddMem)
{
    /* F0 01 08 = LOCK ADD [EAX], ECX */
    auto insn = decode({0xF0, 0x01, 0x08});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_ADD);
    EXPECT_TRUE(insn.prefixes & AKAV_X86_PFX_LOCK);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_MEM);
}

TEST(X86Decode, FsSegmentOverride)
{
    /* 64 A1 30000000 = MOV EAX, FS:[0x30] (PEB access) */
    auto insn = decode({0x64, 0xA1, 0x30, 0x00, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 6);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOV);
    EXPECT_TRUE(insn.prefixes & AKAV_X86_PFX_SEG_FS);
}

TEST(X86Decode, OpSizePrefix)
{
    /* 66 50 = PUSH AX (16-bit) */
    auto insn = decode({0x66, 0x50});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 2);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_PUSH);
    EXPECT_TRUE(insn.prefixes & AKAV_X86_PFX_OPSIZE);
    EXPECT_EQ(insn.operands[0].size, 2);  /* 66 prefix: PUSH AX (16-bit) */
}

TEST(X86Decode, OpSizeMovsw)
{
    /* 66 A5 = MOVSW */
    auto insn = decode({0x66, 0xA5});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 2);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOVSW);
}

/* ── ModR/M addressing modes ──────────────────────────────────── */

TEST(X86Decode, MovMemDisp32)
{
    /* 89 05 78563412 = MOV [0x12345678], EAX (mod=0, rm=5: disp32) */
    auto insn = decode({0x89, 0x05, 0x78, 0x56, 0x34, 0x12});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 6);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_MEM);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_NONE);
    EXPECT_EQ(insn.operands[0].disp, 0x12345678);
}

TEST(X86Decode, MovMemBaseDisp8)
{
    /* 89 45 F8 = MOV [EBP-8], EAX (mod=1, rm=5: disp8) */
    auto insn = decode({0x89, 0x45, 0xF8});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 3);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_MEM);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EBP);
    EXPECT_EQ(insn.operands[0].disp, -8);
}

TEST(X86Decode, MovMemBaseDisp32)
{
    /* 89 85 00010000 = MOV [EBP+0x100], EAX (mod=2, rm=5: disp32) */
    auto insn = decode({0x89, 0x85, 0x00, 0x01, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 6);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_MEM);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EBP);
    EXPECT_EQ(insn.operands[0].disp, 0x100);
}

TEST(X86Decode, SibScaleIndexBase)
{
    /* 8B 04 88 = MOV EAX, [EAX+ECX*4] (SIB: scale=2, index=ECX, base=EAX) */
    auto insn = decode({0x8B, 0x04, 0x88});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 3);
    EXPECT_TRUE(insn.has_sib);
    EXPECT_EQ(insn.operands[1].type, AKAV_X86_OP_MEM);
    EXPECT_EQ(insn.operands[1].reg, AKAV_X86_REG_EAX);
    EXPECT_EQ(insn.operands[1].index_reg, AKAV_X86_REG_ECX);
    EXPECT_EQ(insn.operands[1].scale, 4);
}

TEST(X86Decode, SibNoIndex)
{
    /* 8B 04 24 = MOV EAX, [ESP] (SIB with index=4: no index) */
    auto insn = decode({0x8B, 0x04, 0x24});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 3);
    EXPECT_TRUE(insn.has_sib);
    EXPECT_EQ(insn.operands[1].type, AKAV_X86_OP_MEM);
    EXPECT_EQ(insn.operands[1].reg, AKAV_X86_REG_ESP);
    EXPECT_EQ(insn.operands[1].index_reg, AKAV_X86_REG_NONE);
}

TEST(X86Decode, SibBase5Mod0)
{
    /* 8B 04 2D 00100000 = MOV EAX, [EBP*1+0x1000] (SIB: base=5, mod=0: disp32) */
    auto insn = decode({0x8B, 0x04, 0x2D, 0x00, 0x10, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 7);
    EXPECT_EQ(insn.operands[1].type, AKAV_X86_OP_MEM);
    EXPECT_EQ(insn.operands[1].reg, AKAV_X86_REG_NONE);
    EXPECT_EQ(insn.operands[1].index_reg, AKAV_X86_REG_EBP);
    EXPECT_EQ(insn.operands[1].disp, 0x1000);
}

/* ── Group opcode tests ───────────────────────────────────────── */

TEST(X86Decode, Group1AddRmImm8)
{
    /* 83 C0 01 = ADD EAX, 1 (group1, reg_op=0) */
    auto insn = decode({0x83, 0xC0, 0x01});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_ADD);
}

TEST(X86Decode, Group1OrRmImm8)
{
    /* 83 C8 0F = OR EAX, 0x0F (group1, reg_op=1) */
    auto insn = decode({0x83, 0xC8, 0x0F});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_OR);
}

TEST(X86Decode, Group1SubRmImm8)
{
    /* 83 E8 05 = SUB EAX, 5 */
    auto insn = decode({0x83, 0xE8, 0x05});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_SUB);
}

TEST(X86Decode, Group1XorRmImm8)
{
    /* 83 F0 FF = XOR EAX, -1 */
    auto insn = decode({0x83, 0xF0, 0xFF});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_XOR);
}

TEST(X86Decode, Group1CmpRmImm8)
{
    /* 83 F8 00 = CMP EAX, 0 */
    auto insn = decode({0x83, 0xF8, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_CMP);
}

TEST(X86Decode, Group1AndRmImm32)
{
    /* 81 E0 FF000000 = AND EAX, 0xFF */
    auto insn = decode({0x81, 0xE0, 0xFF, 0x00, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_AND);
    EXPECT_EQ(insn.operands[1].imm, 0xFF);
}

TEST(X86Decode, Group2ShlImm8)
{
    /* C1 E0 04 = SHL EAX, 4 */
    auto insn = decode({0xC1, 0xE0, 0x04});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_SHL);
}

TEST(X86Decode, Group2ShrBy1)
{
    /* D1 E8 = SHR EAX, 1 */
    auto insn = decode({0xD1, 0xE8});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_SHR);
    EXPECT_EQ(insn.operands[1].imm, 1);
}

TEST(X86Decode, Group2SarByCl)
{
    /* D3 F8 = SAR EAX, CL */
    auto insn = decode({0xD3, 0xF8});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_SAR);
    EXPECT_EQ(insn.operands[1].type, AKAV_X86_OP_REG);
}

TEST(X86Decode, Group2RolImm8)
{
    /* C0 C0 03 = ROL AL, 3 */
    auto insn = decode({0xC0, 0xC0, 0x03});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_ROL);
}

TEST(X86Decode, Group3NotRm32)
{
    /* F7 D0 = NOT EAX */
    auto insn = decode({0xF7, 0xD0});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_NOT);
}

TEST(X86Decode, Group3NegRm32)
{
    /* F7 D8 = NEG EAX */
    auto insn = decode({0xF7, 0xD8});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_NEG);
}

TEST(X86Decode, Group3MulRm32)
{
    /* F7 E1 = MUL ECX */
    auto insn = decode({0xF7, 0xE1});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MUL);
}

TEST(X86Decode, Group3TestRmImm)
{
    /* F7 C0 01000000 = TEST EAX, 1 */
    auto insn = decode({0xF7, 0xC0, 0x01, 0x00, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 6);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_TEST);
    EXPECT_EQ(insn.operands[1].imm, 1);
}

TEST(X86Decode, Group5CallRm32)
{
    /* FF D0 = CALL EAX */
    auto insn = decode({0xFF, 0xD0});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_CALL);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_REG);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EAX);
}

TEST(X86Decode, Group5JmpRm32)
{
    /* FF E0 = JMP EAX */
    auto insn = decode({0xFF, 0xE0});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_JMP);
}

TEST(X86Decode, Group5PushRm32)
{
    /* FF 35 78563412 = PUSH [0x12345678] */
    auto insn = decode({0xFF, 0x35, 0x78, 0x56, 0x34, 0x12});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 6);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_PUSH);
    EXPECT_EQ(insn.operands[0].type, AKAV_X86_OP_MEM);
}

/* ── 2-byte opcode tests ──────────────────────────────────────── */

TEST(X86Decode, MovzxR32Rm8)
{
    /* 0F B6 C1 = MOVZX EAX, CL */
    auto insn = decode({0x0F, 0xB6, 0xC1});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOVZX);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EAX);
    EXPECT_EQ(insn.operands[1].size, 1);
}

TEST(X86Decode, MovsxR32Rm8)
{
    /* 0F BE C1 = MOVSX EAX, CL */
    auto insn = decode({0x0F, 0xBE, 0xC1});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOVSX);
}

TEST(X86Decode, BswapEax)
{
    /* 0F C8 = BSWAP EAX */
    auto insn = decode({0x0F, 0xC8});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_BSWAP);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_EAX);
}

TEST(X86Decode, Rdtsc)
{
    auto insn = decode({0x0F, 0x31});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_RDTSC);
}

TEST(X86Decode, Cpuid)
{
    auto insn = decode({0x0F, 0xA2});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_CPUID);
}

TEST(X86Decode, SetccRm8)
{
    /* 0F 94 C0 = SETZ AL */
    auto insn = decode({0x0F, 0x94, 0xC0});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_SETCC);
}

TEST(X86Decode, CmovccR32Rm32)
{
    /* 0F 44 C1 = CMOVZ EAX, ECX */
    auto insn = decode({0x0F, 0x44, 0xC1});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_CMOVCC);
}

TEST(X86Decode, ImulR32Rm32)
{
    /* 0F AF C1 = IMUL EAX, ECX */
    auto insn = decode({0x0F, 0xAF, 0xC1});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_IMUL);
}

TEST(X86Decode, Imul3OpImm32)
{
    /* 69 C1 0A000000 = IMUL EAX, ECX, 10 */
    auto insn = decode({0x69, 0xC1, 0x0A, 0x00, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 6);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_IMUL);
    EXPECT_EQ(insn.num_operands, 3);
    EXPECT_EQ(insn.operands[2].imm, 10);
}

TEST(X86Decode, Imul3OpImm8)
{
    /* 6B C1 0A = IMUL EAX, ECX, 10 */
    auto insn = decode({0x6B, 0xC1, 0x0A});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 3);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_IMUL);
    EXPECT_EQ(insn.num_operands, 3);
}

TEST(X86Decode, XaddRm32R32)
{
    /* 0F C1 C8 = XADD EAX, ECX */
    auto insn = decode({0x0F, 0xC1, 0xC8});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_XADD);
}

TEST(X86Decode, MultiByteNop)
{
    /* 0F 1F 44 00 00 = NOP DWORD [EAX+EAX+0x0] (5-byte NOP) */
    auto insn = decode({0x0F, 0x1F, 0x44, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 5);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_NOP);
}

/* ── Misc instruction tests ───────────────────────────────────── */

TEST(X86Decode, MovAlImm8)
{
    /* B0 41 = MOV AL, 0x41 */
    auto insn = decode({0xB0, 0x41});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOV);
    EXPECT_EQ(insn.operands[0].size, 1);
    EXPECT_EQ(insn.operands[1].imm, 0x41);
}

TEST(X86Decode, LoopRel8)
{
    /* E2 FE = LOOP -2 */
    auto insn = decode({0xE2, 0xFE});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_LOOP);
}

TEST(X86Decode, Enter)
{
    /* C8 0800 00 = ENTER 8, 0 */
    auto insn = decode({0xC8, 0x08, 0x00, 0x00});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 4);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_ENTER);
    EXPECT_EQ(insn.operands[0].imm, 8);
    EXPECT_EQ(insn.operands[1].imm, 0);
}

TEST(X86Decode, XchgEaxEcx)
{
    /* 91 = XCHG EAX, ECX */
    auto insn = decode({0x91});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_XCHG);
    EXPECT_EQ(insn.operands[0].reg, AKAV_X86_REG_ECX);
}

TEST(X86Decode, MovMoffsToAl)
{
    /* A0 44332211 = MOV AL, [0x11223344] */
    auto insn = decode({0xA0, 0x44, 0x33, 0x22, 0x11});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.length, 5);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_MOV);
}

TEST(X86Decode, TestRm32R32)
{
    /* 85 C0 = TEST EAX, EAX */
    auto insn = decode({0x85, 0xC0});
    EXPECT_TRUE(insn.valid);
    EXPECT_EQ(insn.mnemonic, AKAV_X86_MN_TEST);
}

/* ── Error handling tests ─────────────────────────────────────── */

TEST(X86Decode, EmptyInput)
{
    akav_x86_insn_t insn;
    memset(&insn, 0, sizeof(insn));
    EXPECT_FALSE(akav_x86_decode(&insn, nullptr, 0));
    EXPECT_FALSE(insn.valid);
}

TEST(X86Decode, TruncatedModrm)
{
    /* 89 without ModR/M */
    auto insn = decode({0x89});
    EXPECT_FALSE(insn.valid);
}

TEST(X86Decode, TruncatedImmediate)
{
    /* B8 41 41 — MOV EAX, imm32 but only 2 imm bytes */
    auto insn = decode({0xB8, 0x41, 0x41});
    EXPECT_FALSE(insn.valid);
}

TEST(X86Decode, Truncated2ByteOpcode)
{
    /* 0F alone */
    auto insn = decode({0x0F});
    EXPECT_FALSE(insn.valid);
}

TEST(X86Decode, InvalidOpcode)
{
    /* 0F FF is not a valid 2-byte opcode */
    auto insn = decode({0x0F, 0xFF});
    EXPECT_FALSE(insn.valid);
}

TEST(X86Decode, NullInsn)
{
    EXPECT_FALSE(akav_x86_decode(nullptr, (const uint8_t*)"\x90", 1));
}

/* ── Stream decoder test ──────────────────────────────────────── */

TEST(X86Decode, StreamDecode)
{
    /* push ebp; mov ebp,esp; sub esp,0x10; xor eax,eax; pop ebp; ret */
    uint8_t code[] = {0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10, 0x31, 0xC0, 0x5D, 0xC3};
    akav_x86_insn_t insns[10];
    memset(insns, 0, sizeof(insns));
    size_t count = akav_x86_decode_stream(insns, 10, code, sizeof(code));
    EXPECT_EQ(count, 6u);
    EXPECT_EQ(insns[0].mnemonic, AKAV_X86_MN_PUSH);   /* push ebp */
    EXPECT_EQ(insns[1].mnemonic, AKAV_X86_MN_MOV);     /* mov ebp, esp */
    EXPECT_EQ(insns[2].mnemonic, AKAV_X86_MN_SUB);     /* sub esp, 0x10 */
    EXPECT_EQ(insns[3].mnemonic, AKAV_X86_MN_XOR);     /* xor eax, eax */
    EXPECT_EQ(insns[4].mnemonic, AKAV_X86_MN_POP);     /* pop ebp */
    EXPECT_EQ(insns[5].mnemonic, AKAV_X86_MN_RET);     /* ret */
}

/* ── Mnemonic name test ───────────────────────────────────────── */

TEST(X86Decode, MnemonicName)
{
    EXPECT_STREQ(akav_x86_mnemonic_name(AKAV_X86_MN_MOV), "mov");
    EXPECT_STREQ(akav_x86_mnemonic_name(AKAV_X86_MN_PUSH), "push");
    EXPECT_STREQ(akav_x86_mnemonic_name(AKAV_X86_MN_CALL), "call");
    EXPECT_STREQ(akav_x86_mnemonic_name(AKAV_X86_MN_RET), "ret");
    EXPECT_STREQ(akav_x86_mnemonic_name(AKAV_X86_MN_NOP), "nop");
    EXPECT_STREQ(akav_x86_mnemonic_name(AKAV_X86_MN_INVALID), "???");
    EXPECT_STREQ(akav_x86_mnemonic_name(9999), "???");
}

/* ── 100-instruction ndisasm comparison test ──────────────────── */
/* Bytes from a typical function prologue + UPX-like decompression stub.
 * Reference lengths/mnemonics verified against ndisasm -b 32.
 */

struct NdisasmRef {
    uint8_t  length;
    uint16_t mnemonic;
};

TEST(X86Decode, Ndisasm100Instructions)
{
    /* A synthetic but realistic 32-bit code sequence covering diverse
     * instruction forms. Each instruction was verified against ndisasm -b 32.
     */
    static const uint8_t code[] = {
        /* 000: push ebp          */ 0x55,
        /* 001: mov ebp, esp      */ 0x89, 0xE5,
        /* 003: sub esp, 0x20     */ 0x83, 0xEC, 0x20,
        /* 006: push ebx          */ 0x53,
        /* 007: push esi          */ 0x56,
        /* 008: push edi          */ 0x57,
        /* 009: xor eax, eax      */ 0x31, 0xC0,
        /* 00B: xor ecx, ecx      */ 0x31, 0xC9,
        /* 00D: mov edi, 0x401000 */ 0xBF, 0x00, 0x10, 0x40, 0x00,
        /* 012: mov esi, 0x402000 */ 0xBE, 0x00, 0x20, 0x40, 0x00,
        /* 017: mov ecx, 0x100    */ 0xB9, 0x00, 0x01, 0x00, 0x00,
        /* 01C: rep movsb          */ 0xF3, 0xA4,
        /* 01E: cld                */ 0xFC,
        /* 01F: mov eax, [ebp+8]  */ 0x8B, 0x45, 0x08,
        /* 022: mov edx, [ebp+12] */ 0x8B, 0x55, 0x0C,
        /* 025: add eax, edx      */ 0x01, 0xD0,
        /* 027: mov [ebp-4], eax  */ 0x89, 0x45, 0xFC,
        /* 02A: cmp eax, 0        */ 0x83, 0xF8, 0x00,
        /* 02D: jz +8             */ 0x74, 0x08,
        /* 02F: sub eax, 1        */ 0x83, 0xE8, 0x01,
        /* 032: jmp +3            */ 0xEB, 0x03,
        /* 034: add eax, 1        */ 0x83, 0xC0, 0x01,
        /* 037: push eax          */ 0x50,
        /* 038: call +0x100       */ 0xE8, 0x00, 0x01, 0x00, 0x00,
        /* 03D: add esp, 4        */ 0x83, 0xC4, 0x04,
        /* 040: test eax, eax     */ 0x85, 0xC0,
        /* 042: jnz +0x20         */ 0x0F, 0x85, 0x20, 0x00, 0x00, 0x00,
        /* 048: lea ecx,[eax+ebx*4] */ 0x8D, 0x0C, 0x98,
        /* 04B: mov al, [esi]     */ 0x8A, 0x06,
        /* 04D: mov [edi], al     */ 0x88, 0x07,
        /* 04F: inc esi           */ 0x46,
        /* 050: inc edi           */ 0x47,
        /* 051: dec ecx           */ 0x49,
        /* 052: jnz -7 (=0x4B)   */ 0x75, 0xF7,
        /* 054: movzx eax, byte [ebx] */ 0x0F, 0xB6, 0x03,
        /* 057: movsx edx, byte [ecx] */ 0x0F, 0xBE, 0x11,
        /* 05A: shl eax, 4        */ 0xC1, 0xE0, 0x04,
        /* 05D: shr edx, 8        */ 0xC1, 0xEA, 0x08,
        /* 060: sar ebx, 1        */ 0xD1, 0xFB,
        /* 062: rol ecx, 3        */ 0xC1, 0xC1, 0x03,
        /* 065: ror edx, cl       */ 0xD3, 0xCA,
        /* 067: not eax           */ 0xF7, 0xD0,
        /* 069: neg ebx           */ 0xF7, 0xDB,
        /* 06B: and eax, 0xFF     */ 0x25, 0xFF, 0x00, 0x00, 0x00,
        /* 070: or eax, 0x80      */ 0x0D, 0x80, 0x00, 0x00, 0x00,
        /* 075: xor eax, 0x1234   */ 0x35, 0x34, 0x12, 0x00, 0x00,
        /* 07A: test al, 1        */ 0xA8, 0x01,
        /* 07C: pushad            */ 0x60,
        /* 07D: popad             */ 0x61,
        /* 07E: pushfd            */ 0x9C,
        /* 07F: popfd             */ 0x9D,
        /* 080: cdq               */ 0x99,
        /* 081: nop               */ 0x90,
        /* 082: xchg eax, ebx     */ 0x93,
        /* 083: bswap eax         */ 0x0F, 0xC8,
        /* 085: rdtsc             */ 0x0F, 0x31,
        /* 087: cpuid             */ 0x0F, 0xA2,
        /* 089: clc               */ 0xF8,
        /* 08A: stc               */ 0xF9,
        /* 08B: cmc               */ 0xF5,
        /* 08C: std               */ 0xFD,
        /* 08D: stosd             */ 0xAB,
        /* 08E: lodsd             */ 0xAD,
        /* 08F: cmpsb             */ 0xA6,
        /* 090: scasb             */ 0xAE,
        /* 091: ret               */ 0xC3,
        /* 092: mov [ebp-8], edx  */ 0x89, 0x55, 0xF8,
        /* 095: lea eax,[esp+8]   */ 0x8D, 0x44, 0x24, 0x08,
        /* 099: push 0x12345678   */ 0x68, 0x78, 0x56, 0x34, 0x12,
        /* 09E: push 0x0A         */ 0x6A, 0x0A,
        /* 0A0: call eax          */ 0xFF, 0xD0,
        /* 0A2: jmp eax           */ 0xFF, 0xE0,
        /* 0A4: int3              */ 0xCC,
        /* 0A5: int 0x80          */ 0xCD, 0x80,
        /* 0A7: leave             */ 0xC9,
        /* 0A8: ret 8             */ 0xC2, 0x08, 0x00,
        /* 0AB: mov cl, 0x41      */ 0xB1, 0x41,
        /* 0AD: or [eax], cl      */ 0x08, 0x08,
        /* 0AF: adc eax, ebx      */ 0x11, 0xD8,
        /* 0B1: sbb eax, 0x10     */ 0x83, 0xD8, 0x10,
        /* 0B4: test eax, 0x1000  */ 0xA9, 0x00, 0x10, 0x00, 0x00,
        /* 0B9: loop -2           */ 0xE2, 0xFE,
        /* 0BB: mul ecx           */ 0xF7, 0xE1,
        /* 0BD: imul eax,ecx,10   */ 0x6B, 0xC1, 0x0A,
        /* 0C0: div edx           */ 0xF7, 0xF2,
        /* 0C2: idiv ebx          */ 0xF7, 0xFB,
        /* 0C4: setcc al (setz)   */ 0x0F, 0x94, 0xC0,
        /* 0C7: cmovz eax, ecx    */ 0x0F, 0x44, 0xC1,
        /* 0CA: bt eax, ecx       */ 0x0F, 0xA3, 0xC8,
        /* 0CD: bsf eax, ecx      */ 0x0F, 0xBC, 0xC1,
        /* 0D0: bsr edx, eax      */ 0x0F, 0xBD, 0xD0,
        /* 0D3: xadd eax, ecx     */ 0x0F, 0xC1, 0xC8,
        /* 0D6: cmpxchg [eax],ecx */ 0x0F, 0xB1, 0x08,
        /* 0D9: imul eax, ecx     */ 0x0F, 0xAF, 0xC1,
        /* 0DC: mov c7:[eax],0x42 */ 0xC6, 0x00, 0x42,
        /* 0DF: movzx eax, word [ebx] */ 0x0F, 0xB7, 0x03,
        /* 0E2: movsx eax, word [ecx] */ 0x0F, 0xBF, 0x01,
        /* 0E5: pop edi           */ 0x5F,
        /* 0E6: pop esi           */ 0x5E,
        /* 0E7: pop ebx           */ 0x5B,
        /* 0E8: mov esp, ebp      */ 0x89, 0xEC,
        /* 0EA: pop ebp           */ 0x5D,
        /* 0EB: ret               */ 0xC3,
    };

    static const NdisasmRef expected[] = {
        { 1, AKAV_X86_MN_PUSH   },  /*  0: push ebp */
        { 2, AKAV_X86_MN_MOV    },  /*  1: mov ebp,esp */
        { 3, AKAV_X86_MN_SUB    },  /*  2: sub esp,0x20 */
        { 1, AKAV_X86_MN_PUSH   },  /*  3: push ebx */
        { 1, AKAV_X86_MN_PUSH   },  /*  4: push esi */
        { 1, AKAV_X86_MN_PUSH   },  /*  5: push edi */
        { 2, AKAV_X86_MN_XOR    },  /*  6: xor eax,eax */
        { 2, AKAV_X86_MN_XOR    },  /*  7: xor ecx,ecx */
        { 5, AKAV_X86_MN_MOV    },  /*  8: mov edi,0x401000 */
        { 5, AKAV_X86_MN_MOV    },  /*  9: mov esi,0x402000 */
        { 5, AKAV_X86_MN_MOV    },  /* 10: mov ecx,0x100 */
        { 2, AKAV_X86_MN_MOVSB  },  /* 11: rep movsb */
        { 1, AKAV_X86_MN_CLD    },  /* 12: cld */
        { 3, AKAV_X86_MN_MOV    },  /* 13: mov eax,[ebp+8] */
        { 3, AKAV_X86_MN_MOV    },  /* 14: mov edx,[ebp+12] */
        { 2, AKAV_X86_MN_ADD    },  /* 15: add eax,edx */
        { 3, AKAV_X86_MN_MOV    },  /* 16: mov [ebp-4],eax */
        { 3, AKAV_X86_MN_CMP    },  /* 17: cmp eax,0 */
        { 2, AKAV_X86_MN_JCC    },  /* 18: jz +8 */
        { 3, AKAV_X86_MN_SUB    },  /* 19: sub eax,1 */
        { 2, AKAV_X86_MN_JMP    },  /* 20: jmp +3 */
        { 3, AKAV_X86_MN_ADD    },  /* 21: add eax,1 */
        { 1, AKAV_X86_MN_PUSH   },  /* 22: push eax */
        { 5, AKAV_X86_MN_CALL   },  /* 23: call +0x100 */
        { 3, AKAV_X86_MN_ADD    },  /* 24: add esp,4 */
        { 2, AKAV_X86_MN_TEST   },  /* 25: test eax,eax */
        { 6, AKAV_X86_MN_JCC    },  /* 26: jnz +0x20 */
        { 3, AKAV_X86_MN_LEA    },  /* 27: lea ecx,[eax+ebx*4] */
        { 2, AKAV_X86_MN_MOV    },  /* 28: mov al,[esi] */
        { 2, AKAV_X86_MN_MOV    },  /* 29: mov [edi],al */
        { 1, AKAV_X86_MN_INC    },  /* 30: inc esi */
        { 1, AKAV_X86_MN_INC    },  /* 31: inc edi */
        { 1, AKAV_X86_MN_DEC    },  /* 32: dec ecx */
        { 2, AKAV_X86_MN_JCC    },  /* 33: jnz -7 */
        { 3, AKAV_X86_MN_MOVZX  },  /* 34: movzx eax,byte [ebx] */
        { 3, AKAV_X86_MN_MOVSX  },  /* 35: movsx edx,byte [ecx] */
        { 3, AKAV_X86_MN_SHL    },  /* 36: shl eax,4 */
        { 3, AKAV_X86_MN_SHR    },  /* 37: shr edx,8 */
        { 2, AKAV_X86_MN_SAR    },  /* 38: sar ebx,1 */
        { 3, AKAV_X86_MN_ROL    },  /* 39: rol ecx,3 */
        { 2, AKAV_X86_MN_ROR    },  /* 40: ror edx,cl */
        { 2, AKAV_X86_MN_NOT    },  /* 41: not eax */
        { 2, AKAV_X86_MN_NEG    },  /* 42: neg ebx */
        { 5, AKAV_X86_MN_AND    },  /* 43: and eax,0xFF */
        { 5, AKAV_X86_MN_OR     },  /* 44: or eax,0x80 */
        { 5, AKAV_X86_MN_XOR    },  /* 45: xor eax,0x1234 */
        { 2, AKAV_X86_MN_TEST   },  /* 46: test al,1 */
        { 1, AKAV_X86_MN_PUSHAD },  /* 47: pushad */
        { 1, AKAV_X86_MN_POPAD  },  /* 48: popad */
        { 1, AKAV_X86_MN_PUSHFD },  /* 49: pushfd */
        { 1, AKAV_X86_MN_POPFD  },  /* 50: popfd */
        { 1, AKAV_X86_MN_CDQ    },  /* 51: cdq */
        { 1, AKAV_X86_MN_NOP    },  /* 52: nop */
        { 1, AKAV_X86_MN_XCHG   },  /* 53: xchg eax,ebx */
        { 2, AKAV_X86_MN_BSWAP  },  /* 54: bswap eax */
        { 2, AKAV_X86_MN_RDTSC  },  /* 55: rdtsc */
        { 2, AKAV_X86_MN_CPUID  },  /* 56: cpuid */
        { 1, AKAV_X86_MN_CLC    },  /* 57: clc */
        { 1, AKAV_X86_MN_STC    },  /* 58: stc */
        { 1, AKAV_X86_MN_CMC    },  /* 59: cmc */
        { 1, AKAV_X86_MN_STD    },  /* 60: std */
        { 1, AKAV_X86_MN_STOSD  },  /* 61: stosd */
        { 1, AKAV_X86_MN_LODSD  },  /* 62: lodsd */
        { 1, AKAV_X86_MN_CMPSB  },  /* 63: cmpsb */
        { 1, AKAV_X86_MN_SCASB  },  /* 64: scasb */
        { 1, AKAV_X86_MN_RET    },  /* 65: ret */
        { 3, AKAV_X86_MN_MOV    },  /* 66: mov [ebp-8],edx */
        { 4, AKAV_X86_MN_LEA    },  /* 67: lea eax,[esp+8] */
        { 5, AKAV_X86_MN_PUSH   },  /* 68: push 0x12345678 */
        { 2, AKAV_X86_MN_PUSH   },  /* 69: push 0x0A */
        { 2, AKAV_X86_MN_CALL   },  /* 70: call eax */
        { 2, AKAV_X86_MN_JMP    },  /* 71: jmp eax */
        { 1, AKAV_X86_MN_INT3   },  /* 72: int3 */
        { 2, AKAV_X86_MN_INT    },  /* 73: int 0x80 */
        { 1, AKAV_X86_MN_LEAVE  },  /* 74: leave */
        { 3, AKAV_X86_MN_RETN   },  /* 75: ret 8 */
        { 2, AKAV_X86_MN_MOV    },  /* 76: mov cl,0x41 */
        { 2, AKAV_X86_MN_OR     },  /* 77: or [eax],cl */
        { 2, AKAV_X86_MN_ADC    },  /* 78: adc eax,ebx */
        { 3, AKAV_X86_MN_SBB    },  /* 79: sbb eax,0x10 */
        { 5, AKAV_X86_MN_TEST   },  /* 80: test eax,0x1000 */
        { 2, AKAV_X86_MN_LOOP   },  /* 81: loop -2 */
        { 2, AKAV_X86_MN_MUL    },  /* 82: mul ecx */
        { 3, AKAV_X86_MN_IMUL   },  /* 83: imul eax,ecx,10 */
        { 2, AKAV_X86_MN_DIV    },  /* 84: div edx */
        { 2, AKAV_X86_MN_IDIV   },  /* 85: idiv ebx */
        { 3, AKAV_X86_MN_SETCC  },  /* 86: setz al */
        { 3, AKAV_X86_MN_CMOVCC },  /* 87: cmovz eax,ecx */
        { 3, AKAV_X86_MN_BT     },  /* 88: bt eax,ecx */
        { 3, AKAV_X86_MN_BSF    },  /* 89: bsf eax,ecx */
        { 3, AKAV_X86_MN_BSR    },  /* 90: bsr edx,eax */
        { 3, AKAV_X86_MN_XADD   },  /* 91: xadd eax,ecx */
        { 3, AKAV_X86_MN_CMPXCHG},  /* 92: cmpxchg [eax],ecx */
        { 3, AKAV_X86_MN_IMUL   },  /* 93: imul eax,ecx */
        { 3, AKAV_X86_MN_MOV    },  /* 94: mov byte [eax],0x42 */
        { 3, AKAV_X86_MN_MOVZX  },  /* 95: movzx eax,word [ebx] */
        { 3, AKAV_X86_MN_MOVSX  },  /* 96: movsx eax,word [ecx] */
        { 1, AKAV_X86_MN_POP    },  /* 97: pop edi */
        { 1, AKAV_X86_MN_POP    },  /* 98: pop esi */
        { 1, AKAV_X86_MN_POP    },  /* 99: pop ebx */
        { 2, AKAV_X86_MN_MOV    },  /* 100: mov esp,ebp */
        { 1, AKAV_X86_MN_POP    },  /* 101: pop ebp */
        { 1, AKAV_X86_MN_RET    },  /* 102: ret */
    };

    size_t num_expected = sizeof(expected) / sizeof(expected[0]);
    ASSERT_GE(num_expected, 100u) << "Need at least 100 instructions";

    akav_x86_insn_t insns[120];
    memset(insns, 0, sizeof(insns));
    size_t count = akav_x86_decode_stream(insns, 120, code, sizeof(code));
    ASSERT_EQ(count, num_expected);

    for (size_t i = 0; i < num_expected; i++) {
        EXPECT_TRUE(insns[i].valid)
            << "Instruction " << i << " should be valid";
        EXPECT_EQ(insns[i].length, expected[i].length)
            << "Instruction " << i << " length mismatch: "
            << akav_x86_mnemonic_name(insns[i].mnemonic);
        EXPECT_EQ(insns[i].mnemonic, expected[i].mnemonic)
            << "Instruction " << i << " mnemonic mismatch: got "
            << akav_x86_mnemonic_name(insns[i].mnemonic) << " expected "
            << akav_x86_mnemonic_name(expected[i].mnemonic);
    }
}
