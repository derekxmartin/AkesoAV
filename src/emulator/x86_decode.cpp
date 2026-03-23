/* x86_decode.cpp — 32-bit x86 instruction decoder for AkesoAV emulator.
 *
 * Decodes prefixes, 1-byte and 2-byte (0F) opcodes, ModR/M, SIB,
 * displacement, and immediate operands. Designed for unpacker analysis.
 */

#include "emulator/x86_decode.h"
#include <cstring>
#include <cstdio>

/* ── Internal encoding types ──────────────────────────────────── */

enum : uint8_t {
    ENC_NONE       = 0,   /* no operands */
    ENC_RM_REG     = 1,   /* r/m, reg (direction=0) */
    ENC_REG_RM     = 2,   /* reg, r/m (direction=1) */
    ENC_RM_IMM     = 3,   /* r/m, imm (group opcodes) */
    ENC_RM_ONLY    = 4,   /* r/m only (INC/DEC/PUSH/CALL/JMP) */
    ENC_AX_IMM     = 5,   /* AL/AX/EAX, imm */
    ENC_REG_OPCODE = 6,   /* register in low 3 bits of opcode */
    ENC_REL8       = 7,   /* rel8 */
    ENC_REL32      = 8,   /* rel32 (or rel16 with 66) */
    ENC_IMM8       = 9,   /* imm8 only */
    ENC_IMM16      = 10,  /* imm16 only */
    ENC_MOFFS      = 11,  /* moffs (MOV AL/EAX, [addr]) */
    ENC_REG_RM_IMM = 12,  /* reg, r/m, imm (IMUL 3-op) */
    ENC_ENTER      = 13,  /* ENTER imm16, imm8 */
    ENC_REG_IMM8   = 14,  /* register in low 3 bits + imm8 */
};

/* ── Internal flags ───────────────────────────────────────────── */

enum : uint8_t {
    F_NONE     = 0x00,
    F_MODRM    = 0x01,  /* has ModR/M byte */
    F_GROUP    = 0x02,  /* reg_op field selects mnemonic */
    F_BYTE     = 0x04,  /* operand size is 1 byte */
    F_IMM8     = 0x08,  /* has imm8 */
    F_IMM_FULL = 0x10,  /* has imm32 (or imm16 with 66 prefix) */
    F_IMM_S8   = 0x20,  /* has sign-extended imm8 to full size */
};

/* ── Opcode table entry ───────────────────────────────────────── */

struct x86_op_entry {
    uint16_t mnemonic;
    uint8_t  encoding;
    uint8_t  flags;
};

/* ── Group tables (indexed by reg_op field 0-7) ───────────────── */

static const uint16_t group1_mn[8] = {
    AKAV_X86_MN_ADD, AKAV_X86_MN_OR,  AKAV_X86_MN_ADC, AKAV_X86_MN_SBB,
    AKAV_X86_MN_AND, AKAV_X86_MN_SUB, AKAV_X86_MN_XOR, AKAV_X86_MN_CMP,
};

static const uint16_t group2_mn[8] = {
    AKAV_X86_MN_ROL, AKAV_X86_MN_ROR, AKAV_X86_MN_RCL, AKAV_X86_MN_RCR,
    AKAV_X86_MN_SHL, AKAV_X86_MN_SHR, AKAV_X86_MN_INVALID, AKAV_X86_MN_SAR,
};

static const uint16_t group3_mn[8] = {
    AKAV_X86_MN_TEST, AKAV_X86_MN_TEST, AKAV_X86_MN_NOT, AKAV_X86_MN_NEG,
    AKAV_X86_MN_MUL,  AKAV_X86_MN_IMUL, AKAV_X86_MN_DIV, AKAV_X86_MN_IDIV,
};

static const uint16_t group4_mn[8] = {
    AKAV_X86_MN_INC, AKAV_X86_MN_DEC, AKAV_X86_MN_INVALID, AKAV_X86_MN_INVALID,
    AKAV_X86_MN_INVALID, AKAV_X86_MN_INVALID, AKAV_X86_MN_INVALID, AKAV_X86_MN_INVALID,
};

static const uint16_t group5_mn[8] = {
    AKAV_X86_MN_INC,  AKAV_X86_MN_DEC,     AKAV_X86_MN_CALL,    AKAV_X86_MN_INVALID,
    AKAV_X86_MN_JMP,  AKAV_X86_MN_INVALID,  AKAV_X86_MN_PUSH,    AKAV_X86_MN_INVALID,
};

/* ── Primary opcode table (1-byte) ────────────────────────────── */

static const x86_op_entry primary_table[256] = {
    /* 00 */ { AKAV_X86_MN_ADD,  ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 01 */ { AKAV_X86_MN_ADD,  ENC_RM_REG,  F_MODRM },
    /* 02 */ { AKAV_X86_MN_ADD,  ENC_REG_RM,  F_MODRM | F_BYTE },
    /* 03 */ { AKAV_X86_MN_ADD,  ENC_REG_RM,  F_MODRM },
    /* 04 */ { AKAV_X86_MN_ADD,  ENC_AX_IMM,  F_BYTE | F_IMM8 },
    /* 05 */ { AKAV_X86_MN_ADD,  ENC_AX_IMM,  F_IMM_FULL },
    /* 06 */ { AKAV_X86_MN_PUSH, ENC_NONE,    F_NONE },  /* PUSH ES */
    /* 07 */ { AKAV_X86_MN_POP,  ENC_NONE,    F_NONE },  /* POP ES */
    /* 08 */ { AKAV_X86_MN_OR,   ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 09 */ { AKAV_X86_MN_OR,   ENC_RM_REG,  F_MODRM },
    /* 0A */ { AKAV_X86_MN_OR,   ENC_REG_RM,  F_MODRM | F_BYTE },
    /* 0B */ { AKAV_X86_MN_OR,   ENC_REG_RM,  F_MODRM },
    /* 0C */ { AKAV_X86_MN_OR,   ENC_AX_IMM,  F_BYTE | F_IMM8 },
    /* 0D */ { AKAV_X86_MN_OR,   ENC_AX_IMM,  F_IMM_FULL },
    /* 0E */ { AKAV_X86_MN_PUSH, ENC_NONE,    F_NONE },  /* PUSH CS */
    /* 0F */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* 2-byte escape */
    /* 10 */ { AKAV_X86_MN_ADC,  ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 11 */ { AKAV_X86_MN_ADC,  ENC_RM_REG,  F_MODRM },
    /* 12 */ { AKAV_X86_MN_ADC,  ENC_REG_RM,  F_MODRM | F_BYTE },
    /* 13 */ { AKAV_X86_MN_ADC,  ENC_REG_RM,  F_MODRM },
    /* 14 */ { AKAV_X86_MN_ADC,  ENC_AX_IMM,  F_BYTE | F_IMM8 },
    /* 15 */ { AKAV_X86_MN_ADC,  ENC_AX_IMM,  F_IMM_FULL },
    /* 16 */ { AKAV_X86_MN_PUSH, ENC_NONE,    F_NONE },  /* PUSH SS */
    /* 17 */ { AKAV_X86_MN_POP,  ENC_NONE,    F_NONE },  /* POP SS */
    /* 18 */ { AKAV_X86_MN_SBB,  ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 19 */ { AKAV_X86_MN_SBB,  ENC_RM_REG,  F_MODRM },
    /* 1A */ { AKAV_X86_MN_SBB,  ENC_REG_RM,  F_MODRM | F_BYTE },
    /* 1B */ { AKAV_X86_MN_SBB,  ENC_REG_RM,  F_MODRM },
    /* 1C */ { AKAV_X86_MN_SBB,  ENC_AX_IMM,  F_BYTE | F_IMM8 },
    /* 1D */ { AKAV_X86_MN_SBB,  ENC_AX_IMM,  F_IMM_FULL },
    /* 1E */ { AKAV_X86_MN_PUSH, ENC_NONE,    F_NONE },  /* PUSH DS */
    /* 1F */ { AKAV_X86_MN_POP,  ENC_NONE,    F_NONE },  /* POP DS */
    /* 20 */ { AKAV_X86_MN_AND,  ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 21 */ { AKAV_X86_MN_AND,  ENC_RM_REG,  F_MODRM },
    /* 22 */ { AKAV_X86_MN_AND,  ENC_REG_RM,  F_MODRM | F_BYTE },
    /* 23 */ { AKAV_X86_MN_AND,  ENC_REG_RM,  F_MODRM },
    /* 24 */ { AKAV_X86_MN_AND,  ENC_AX_IMM,  F_BYTE | F_IMM8 },
    /* 25 */ { AKAV_X86_MN_AND,  ENC_AX_IMM,  F_IMM_FULL },
    /* 26 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* ES: prefix */
    /* 27 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* DAA */
    /* 28 */ { AKAV_X86_MN_SUB,  ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 29 */ { AKAV_X86_MN_SUB,  ENC_RM_REG,  F_MODRM },
    /* 2A */ { AKAV_X86_MN_SUB,  ENC_REG_RM,  F_MODRM | F_BYTE },
    /* 2B */ { AKAV_X86_MN_SUB,  ENC_REG_RM,  F_MODRM },
    /* 2C */ { AKAV_X86_MN_SUB,  ENC_AX_IMM,  F_BYTE | F_IMM8 },
    /* 2D */ { AKAV_X86_MN_SUB,  ENC_AX_IMM,  F_IMM_FULL },
    /* 2E */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* CS: prefix */
    /* 2F */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* DAS */
    /* 30 */ { AKAV_X86_MN_XOR,  ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 31 */ { AKAV_X86_MN_XOR,  ENC_RM_REG,  F_MODRM },
    /* 32 */ { AKAV_X86_MN_XOR,  ENC_REG_RM,  F_MODRM | F_BYTE },
    /* 33 */ { AKAV_X86_MN_XOR,  ENC_REG_RM,  F_MODRM },
    /* 34 */ { AKAV_X86_MN_XOR,  ENC_AX_IMM,  F_BYTE | F_IMM8 },
    /* 35 */ { AKAV_X86_MN_XOR,  ENC_AX_IMM,  F_IMM_FULL },
    /* 36 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* SS: prefix */
    /* 37 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* AAA */
    /* 38 */ { AKAV_X86_MN_CMP,  ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 39 */ { AKAV_X86_MN_CMP,  ENC_RM_REG,  F_MODRM },
    /* 3A */ { AKAV_X86_MN_CMP,  ENC_REG_RM,  F_MODRM | F_BYTE },
    /* 3B */ { AKAV_X86_MN_CMP,  ENC_REG_RM,  F_MODRM },
    /* 3C */ { AKAV_X86_MN_CMP,  ENC_AX_IMM,  F_BYTE | F_IMM8 },
    /* 3D */ { AKAV_X86_MN_CMP,  ENC_AX_IMM,  F_IMM_FULL },
    /* 3E */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* DS: prefix */
    /* 3F */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* AAS */
    /* 40 */ { AKAV_X86_MN_INC,  ENC_REG_OPCODE, F_NONE },
    /* 41 */ { AKAV_X86_MN_INC,  ENC_REG_OPCODE, F_NONE },
    /* 42 */ { AKAV_X86_MN_INC,  ENC_REG_OPCODE, F_NONE },
    /* 43 */ { AKAV_X86_MN_INC,  ENC_REG_OPCODE, F_NONE },
    /* 44 */ { AKAV_X86_MN_INC,  ENC_REG_OPCODE, F_NONE },
    /* 45 */ { AKAV_X86_MN_INC,  ENC_REG_OPCODE, F_NONE },
    /* 46 */ { AKAV_X86_MN_INC,  ENC_REG_OPCODE, F_NONE },
    /* 47 */ { AKAV_X86_MN_INC,  ENC_REG_OPCODE, F_NONE },
    /* 48 */ { AKAV_X86_MN_DEC,  ENC_REG_OPCODE, F_NONE },
    /* 49 */ { AKAV_X86_MN_DEC,  ENC_REG_OPCODE, F_NONE },
    /* 4A */ { AKAV_X86_MN_DEC,  ENC_REG_OPCODE, F_NONE },
    /* 4B */ { AKAV_X86_MN_DEC,  ENC_REG_OPCODE, F_NONE },
    /* 4C */ { AKAV_X86_MN_DEC,  ENC_REG_OPCODE, F_NONE },
    /* 4D */ { AKAV_X86_MN_DEC,  ENC_REG_OPCODE, F_NONE },
    /* 4E */ { AKAV_X86_MN_DEC,  ENC_REG_OPCODE, F_NONE },
    /* 4F */ { AKAV_X86_MN_DEC,  ENC_REG_OPCODE, F_NONE },
    /* 50 */ { AKAV_X86_MN_PUSH, ENC_REG_OPCODE, F_NONE },
    /* 51 */ { AKAV_X86_MN_PUSH, ENC_REG_OPCODE, F_NONE },
    /* 52 */ { AKAV_X86_MN_PUSH, ENC_REG_OPCODE, F_NONE },
    /* 53 */ { AKAV_X86_MN_PUSH, ENC_REG_OPCODE, F_NONE },
    /* 54 */ { AKAV_X86_MN_PUSH, ENC_REG_OPCODE, F_NONE },
    /* 55 */ { AKAV_X86_MN_PUSH, ENC_REG_OPCODE, F_NONE },
    /* 56 */ { AKAV_X86_MN_PUSH, ENC_REG_OPCODE, F_NONE },
    /* 57 */ { AKAV_X86_MN_PUSH, ENC_REG_OPCODE, F_NONE },
    /* 58 */ { AKAV_X86_MN_POP,  ENC_REG_OPCODE, F_NONE },
    /* 59 */ { AKAV_X86_MN_POP,  ENC_REG_OPCODE, F_NONE },
    /* 5A */ { AKAV_X86_MN_POP,  ENC_REG_OPCODE, F_NONE },
    /* 5B */ { AKAV_X86_MN_POP,  ENC_REG_OPCODE, F_NONE },
    /* 5C */ { AKAV_X86_MN_POP,  ENC_REG_OPCODE, F_NONE },
    /* 5D */ { AKAV_X86_MN_POP,  ENC_REG_OPCODE, F_NONE },
    /* 5E */ { AKAV_X86_MN_POP,  ENC_REG_OPCODE, F_NONE },
    /* 5F */ { AKAV_X86_MN_POP,  ENC_REG_OPCODE, F_NONE },
    /* 60 */ { AKAV_X86_MN_PUSHAD, ENC_NONE,  F_NONE },
    /* 61 */ { AKAV_X86_MN_POPAD,  ENC_NONE,  F_NONE },
    /* 62 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* BOUND */
    /* 63 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* ARPL */
    /* 64 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* FS: prefix */
    /* 65 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* GS: prefix */
    /* 66 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* op-size prefix */
    /* 67 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* addr-size prefix */
    /* 68 */ { AKAV_X86_MN_PUSH, ENC_NONE,    F_IMM_FULL },
    /* 69 */ { AKAV_X86_MN_IMUL, ENC_REG_RM_IMM, F_MODRM | F_IMM_FULL },
    /* 6A */ { AKAV_X86_MN_PUSH, ENC_NONE,    F_IMM8 },
    /* 6B */ { AKAV_X86_MN_IMUL, ENC_REG_RM_IMM, F_MODRM | F_IMM8 },
    /* 6C */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* INSB */
    /* 6D */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* INSD */
    /* 6E */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* OUTSB */
    /* 6F */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* OUTSD */
    /* 70 */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 71 */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 72 */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 73 */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 74 */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 75 */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 76 */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 77 */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 78 */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 79 */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 7A */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 7B */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 7C */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 7D */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 7E */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 7F */ { AKAV_X86_MN_JCC,  ENC_REL8,    F_NONE },
    /* 80 */ { AKAV_X86_MN_INVALID, ENC_RM_IMM, F_MODRM | F_GROUP | F_BYTE | F_IMM8 },
    /* 81 */ { AKAV_X86_MN_INVALID, ENC_RM_IMM, F_MODRM | F_GROUP | F_IMM_FULL },
    /* 82 */ { AKAV_X86_MN_INVALID, ENC_RM_IMM, F_MODRM | F_GROUP | F_BYTE | F_IMM8 },  /* alias of 80 */
    /* 83 */ { AKAV_X86_MN_INVALID, ENC_RM_IMM, F_MODRM | F_GROUP | F_IMM_S8 },
    /* 84 */ { AKAV_X86_MN_TEST, ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 85 */ { AKAV_X86_MN_TEST, ENC_RM_REG,  F_MODRM },
    /* 86 */ { AKAV_X86_MN_XCHG, ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 87 */ { AKAV_X86_MN_XCHG, ENC_RM_REG,  F_MODRM },
    /* 88 */ { AKAV_X86_MN_MOV,  ENC_RM_REG,  F_MODRM | F_BYTE },
    /* 89 */ { AKAV_X86_MN_MOV,  ENC_RM_REG,  F_MODRM },
    /* 8A */ { AKAV_X86_MN_MOV,  ENC_REG_RM,  F_MODRM | F_BYTE },
    /* 8B */ { AKAV_X86_MN_MOV,  ENC_REG_RM,  F_MODRM },
    /* 8C */ { AKAV_X86_MN_MOV,  ENC_RM_REG,  F_MODRM },  /* MOV r/m, Sreg */
    /* 8D */ { AKAV_X86_MN_LEA,  ENC_REG_RM,  F_MODRM },
    /* 8E */ { AKAV_X86_MN_MOV,  ENC_REG_RM,  F_MODRM },  /* MOV Sreg, r/m */
    /* 8F */ { AKAV_X86_MN_POP,  ENC_RM_ONLY, F_MODRM },
    /* 90 */ { AKAV_X86_MN_NOP,  ENC_NONE,    F_NONE },
    /* 91 */ { AKAV_X86_MN_XCHG, ENC_REG_OPCODE, F_NONE },
    /* 92 */ { AKAV_X86_MN_XCHG, ENC_REG_OPCODE, F_NONE },
    /* 93 */ { AKAV_X86_MN_XCHG, ENC_REG_OPCODE, F_NONE },
    /* 94 */ { AKAV_X86_MN_XCHG, ENC_REG_OPCODE, F_NONE },
    /* 95 */ { AKAV_X86_MN_XCHG, ENC_REG_OPCODE, F_NONE },
    /* 96 */ { AKAV_X86_MN_XCHG, ENC_REG_OPCODE, F_NONE },
    /* 97 */ { AKAV_X86_MN_XCHG, ENC_REG_OPCODE, F_NONE },
    /* 98 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* CBW/CWDE */
    /* 99 */ { AKAV_X86_MN_CDQ,  ENC_NONE,    F_NONE },
    /* 9A */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* CALLF */
    /* 9B */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* WAIT */
    /* 9C */ { AKAV_X86_MN_PUSHFD, ENC_NONE,  F_NONE },
    /* 9D */ { AKAV_X86_MN_POPFD,  ENC_NONE,  F_NONE },
    /* 9E */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* SAHF */
    /* 9F */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* LAHF */
    /* A0 */ { AKAV_X86_MN_MOV,  ENC_MOFFS,   F_BYTE },
    /* A1 */ { AKAV_X86_MN_MOV,  ENC_MOFFS,   F_NONE },
    /* A2 */ { AKAV_X86_MN_MOV,  ENC_MOFFS,   F_BYTE },
    /* A3 */ { AKAV_X86_MN_MOV,  ENC_MOFFS,   F_NONE },
    /* A4 */ { AKAV_X86_MN_MOVSB, ENC_NONE,   F_NONE },
    /* A5 */ { AKAV_X86_MN_MOVSD, ENC_NONE,   F_NONE },
    /* A6 */ { AKAV_X86_MN_CMPSB, ENC_NONE,   F_NONE },
    /* A7 */ { AKAV_X86_MN_CMPSD, ENC_NONE,   F_NONE },
    /* A8 */ { AKAV_X86_MN_TEST, ENC_AX_IMM,  F_BYTE | F_IMM8 },
    /* A9 */ { AKAV_X86_MN_TEST, ENC_AX_IMM,  F_IMM_FULL },
    /* AA */ { AKAV_X86_MN_STOSB, ENC_NONE,   F_NONE },
    /* AB */ { AKAV_X86_MN_STOSD, ENC_NONE,   F_NONE },
    /* AC */ { AKAV_X86_MN_LODSB, ENC_NONE,   F_NONE },
    /* AD */ { AKAV_X86_MN_LODSD, ENC_NONE,   F_NONE },
    /* AE */ { AKAV_X86_MN_SCASB, ENC_NONE,   F_NONE },
    /* AF */ { AKAV_X86_MN_SCASD, ENC_NONE,   F_NONE },
    /* B0 */ { AKAV_X86_MN_MOV,  ENC_REG_IMM8, F_BYTE },
    /* B1 */ { AKAV_X86_MN_MOV,  ENC_REG_IMM8, F_BYTE },
    /* B2 */ { AKAV_X86_MN_MOV,  ENC_REG_IMM8, F_BYTE },
    /* B3 */ { AKAV_X86_MN_MOV,  ENC_REG_IMM8, F_BYTE },
    /* B4 */ { AKAV_X86_MN_MOV,  ENC_REG_IMM8, F_BYTE },
    /* B5 */ { AKAV_X86_MN_MOV,  ENC_REG_IMM8, F_BYTE },
    /* B6 */ { AKAV_X86_MN_MOV,  ENC_REG_IMM8, F_BYTE },
    /* B7 */ { AKAV_X86_MN_MOV,  ENC_REG_IMM8, F_BYTE },
    /* B8 */ { AKAV_X86_MN_MOV,  ENC_REG_OPCODE, F_IMM_FULL },
    /* B9 */ { AKAV_X86_MN_MOV,  ENC_REG_OPCODE, F_IMM_FULL },
    /* BA */ { AKAV_X86_MN_MOV,  ENC_REG_OPCODE, F_IMM_FULL },
    /* BB */ { AKAV_X86_MN_MOV,  ENC_REG_OPCODE, F_IMM_FULL },
    /* BC */ { AKAV_X86_MN_MOV,  ENC_REG_OPCODE, F_IMM_FULL },
    /* BD */ { AKAV_X86_MN_MOV,  ENC_REG_OPCODE, F_IMM_FULL },
    /* BE */ { AKAV_X86_MN_MOV,  ENC_REG_OPCODE, F_IMM_FULL },
    /* BF */ { AKAV_X86_MN_MOV,  ENC_REG_OPCODE, F_IMM_FULL },
    /* C0 */ { AKAV_X86_MN_INVALID, ENC_RM_IMM, F_MODRM | F_GROUP | F_BYTE | F_IMM8 },
    /* C1 */ { AKAV_X86_MN_INVALID, ENC_RM_IMM, F_MODRM | F_GROUP | F_IMM8 },
    /* C2 */ { AKAV_X86_MN_RETN, ENC_IMM16,   F_NONE },
    /* C3 */ { AKAV_X86_MN_RET,  ENC_NONE,    F_NONE },
    /* C4 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* LES */
    /* C5 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* LDS */
    /* C6 */ { AKAV_X86_MN_MOV,  ENC_RM_IMM,  F_MODRM | F_BYTE | F_IMM8 },
    /* C7 */ { AKAV_X86_MN_MOV,  ENC_RM_IMM,  F_MODRM | F_IMM_FULL },
    /* C8 */ { AKAV_X86_MN_ENTER, ENC_ENTER,  F_NONE },
    /* C9 */ { AKAV_X86_MN_LEAVE, ENC_NONE,   F_NONE },
    /* CA */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* RETF imm16 */
    /* CB */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* RETF */
    /* CC */ { AKAV_X86_MN_INT3, ENC_NONE,    F_NONE },
    /* CD */ { AKAV_X86_MN_INT,  ENC_IMM8,    F_NONE },
    /* CE */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* INTO */
    /* CF */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* IRET */
    /* D0 */ { AKAV_X86_MN_INVALID, ENC_RM_ONLY, F_MODRM | F_GROUP | F_BYTE },
    /* D1 */ { AKAV_X86_MN_INVALID, ENC_RM_ONLY, F_MODRM | F_GROUP },
    /* D2 */ { AKAV_X86_MN_INVALID, ENC_RM_ONLY, F_MODRM | F_GROUP | F_BYTE },
    /* D3 */ { AKAV_X86_MN_INVALID, ENC_RM_ONLY, F_MODRM | F_GROUP },
    /* D4 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* AAM */
    /* D5 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* AAD */
    /* D6 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* SALC */
    /* D7 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* XLAT */
    /* D8-DF: FPU escapes */
    /* D8 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_MODRM },
    /* D9 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_MODRM },
    /* DA */ { AKAV_X86_MN_INVALID, ENC_NONE, F_MODRM },
    /* DB */ { AKAV_X86_MN_INVALID, ENC_NONE, F_MODRM },
    /* DC */ { AKAV_X86_MN_INVALID, ENC_NONE, F_MODRM },
    /* DD */ { AKAV_X86_MN_INVALID, ENC_NONE, F_MODRM },
    /* DE */ { AKAV_X86_MN_INVALID, ENC_NONE, F_MODRM },
    /* DF */ { AKAV_X86_MN_INVALID, ENC_NONE, F_MODRM },
    /* E0 */ { AKAV_X86_MN_LOOPNE, ENC_REL8, F_NONE },
    /* E1 */ { AKAV_X86_MN_LOOPE,  ENC_REL8, F_NONE },
    /* E2 */ { AKAV_X86_MN_LOOP,   ENC_REL8, F_NONE },
    /* E3 */ { AKAV_X86_MN_JCC,    ENC_REL8, F_NONE },  /* JECXZ */
    /* E4 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* IN AL, imm8 */
    /* E5 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* IN EAX, imm8 */
    /* E6 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* OUT imm8, AL */
    /* E7 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* OUT imm8, EAX */
    /* E8 */ { AKAV_X86_MN_CALL, ENC_REL32,   F_NONE },
    /* E9 */ { AKAV_X86_MN_JMP,  ENC_REL32,   F_NONE },
    /* EA */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* JMPF */
    /* EB */ { AKAV_X86_MN_JMP,  ENC_REL8,    F_NONE },
    /* EC */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* IN AL, DX */
    /* ED */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* IN EAX, DX */
    /* EE */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* OUT DX, AL */
    /* EF */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* OUT DX, EAX */
    /* F0 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* LOCK prefix */
    /* F1 */ { AKAV_X86_MN_INT3, ENC_NONE,    F_NONE },  /* INT1/ICEBP */
    /* F2 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* REPNE prefix */
    /* F3 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* REP prefix */
    /* F4 */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* HLT */
    /* F5 */ { AKAV_X86_MN_CMC,  ENC_NONE,    F_NONE },
    /* F6 */ { AKAV_X86_MN_INVALID, ENC_RM_ONLY, F_MODRM | F_GROUP | F_BYTE },
    /* F7 */ { AKAV_X86_MN_INVALID, ENC_RM_ONLY, F_MODRM | F_GROUP },
    /* F8 */ { AKAV_X86_MN_CLC,  ENC_NONE,    F_NONE },
    /* F9 */ { AKAV_X86_MN_STC,  ENC_NONE,    F_NONE },
    /* FA */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* CLI */
    /* FB */ { AKAV_X86_MN_INVALID, ENC_NONE, F_NONE },  /* STI */
    /* FC */ { AKAV_X86_MN_CLD,  ENC_NONE,    F_NONE },
    /* FD */ { AKAV_X86_MN_STD,  ENC_NONE,    F_NONE },
    /* FE */ { AKAV_X86_MN_INVALID, ENC_RM_ONLY, F_MODRM | F_GROUP | F_BYTE },
    /* FF */ { AKAV_X86_MN_INVALID, ENC_RM_ONLY, F_MODRM | F_GROUP },
};

/* ── Secondary opcode table (0F xx) ───────────────────────────── */

static x86_op_entry secondary_table[256];
static bool secondary_table_init = false;

static void init_secondary_table(void)
{
    if (secondary_table_init) return;
    secondary_table_init = true;

    memset(secondary_table, 0, sizeof(secondary_table));

    /* 0F 1F /0 — multi-byte NOP (has ModR/M) */
    secondary_table[0x1F] = { AKAV_X86_MN_NOP, ENC_RM_ONLY, F_MODRM };

    /* 0F 31 — RDTSC */
    secondary_table[0x31] = { AKAV_X86_MN_RDTSC, ENC_NONE, F_NONE };

    /* 0F 40-4F — CMOVcc r32, r/m32 */
    for (int i = 0x40; i <= 0x4F; i++)
        secondary_table[i] = { AKAV_X86_MN_CMOVCC, ENC_REG_RM, F_MODRM };

    /* 0F 80-8F — Jcc rel32 */
    for (int i = 0x80; i <= 0x8F; i++)
        secondary_table[i] = { AKAV_X86_MN_JCC, ENC_REL32, F_NONE };

    /* 0F 90-9F — SETcc r/m8 */
    for (int i = 0x90; i <= 0x9F; i++)
        secondary_table[i] = { AKAV_X86_MN_SETCC, ENC_RM_ONLY, F_MODRM | F_BYTE };

    /* 0F A2 — CPUID */
    secondary_table[0xA2] = { AKAV_X86_MN_CPUID, ENC_NONE, F_NONE };

    /* 0F A3 — BT r/m32, r32 */
    secondary_table[0xA3] = { AKAV_X86_MN_BT, ENC_RM_REG, F_MODRM };

    /* 0F AB — BTS r/m32, r32 */
    secondary_table[0xAB] = { AKAV_X86_MN_BTS, ENC_RM_REG, F_MODRM };

    /* 0F AF — IMUL r32, r/m32 */
    secondary_table[0xAF] = { AKAV_X86_MN_IMUL, ENC_REG_RM, F_MODRM };

    /* 0F B0 — CMPXCHG r/m8, r8 */
    secondary_table[0xB0] = { AKAV_X86_MN_CMPXCHG, ENC_RM_REG, F_MODRM | F_BYTE };

    /* 0F B1 — CMPXCHG r/m32, r32 */
    secondary_table[0xB1] = { AKAV_X86_MN_CMPXCHG, ENC_RM_REG, F_MODRM };

    /* 0F B3 — BTR r/m32, r32 */
    secondary_table[0xB3] = { AKAV_X86_MN_BTR, ENC_RM_REG, F_MODRM };

    /* 0F B6 — MOVZX r32, r/m8 */
    secondary_table[0xB6] = { AKAV_X86_MN_MOVZX, ENC_REG_RM, F_MODRM | F_BYTE };

    /* 0F B7 — MOVZX r32, r/m16 */
    secondary_table[0xB7] = { AKAV_X86_MN_MOVZX, ENC_REG_RM, F_MODRM };

    /* 0F BB — BTC r/m32, r32 */
    secondary_table[0xBB] = { AKAV_X86_MN_BTC, ENC_RM_REG, F_MODRM };

    /* 0F BC — BSF r32, r/m32 */
    secondary_table[0xBC] = { AKAV_X86_MN_BSF, ENC_REG_RM, F_MODRM };

    /* 0F BD — BSR r32, r/m32 */
    secondary_table[0xBD] = { AKAV_X86_MN_BSR, ENC_REG_RM, F_MODRM };

    /* 0F BE — MOVSX r32, r/m8 */
    secondary_table[0xBE] = { AKAV_X86_MN_MOVSX, ENC_REG_RM, F_MODRM | F_BYTE };

    /* 0F BF — MOVSX r32, r/m16 */
    secondary_table[0xBF] = { AKAV_X86_MN_MOVSX, ENC_REG_RM, F_MODRM };

    /* 0F C0 — XADD r/m8, r8 */
    secondary_table[0xC0] = { AKAV_X86_MN_XADD, ENC_RM_REG, F_MODRM | F_BYTE };

    /* 0F C1 — XADD r/m32, r32 */
    secondary_table[0xC1] = { AKAV_X86_MN_XADD, ENC_RM_REG, F_MODRM };

    /* 0F C8-CF — BSWAP r32 */
    for (int i = 0xC8; i <= 0xCF; i++)
        secondary_table[i] = { AKAV_X86_MN_BSWAP, ENC_REG_OPCODE, F_NONE };
}

/* ── Helper: read bytes from code stream ──────────────────────── */

static inline bool read_u8(const uint8_t* code, size_t len, size_t* pos, uint8_t* out)
{
    if (*pos >= len) return false;
    *out = code[(*pos)++];
    return true;
}

static inline bool read_i8(const uint8_t* code, size_t len, size_t* pos, int8_t* out)
{
    if (*pos >= len) return false;
    *out = (int8_t)code[(*pos)++];
    return true;
}

static inline bool read_u16(const uint8_t* code, size_t len, size_t* pos, uint16_t* out)
{
    if (*pos + 2 > len) return false;
    *out = (uint16_t)(code[*pos] | ((uint16_t)code[*pos + 1] << 8));
    *pos += 2;
    return true;
}

static inline bool read_i16(const uint8_t* code, size_t len, size_t* pos, int16_t* out)
{
    uint16_t v;
    if (!read_u16(code, len, pos, &v)) return false;
    *out = (int16_t)v;
    return true;
}

static inline bool read_u32(const uint8_t* code, size_t len, size_t* pos, uint32_t* out)
{
    if (*pos + 4 > len) return false;
    *out = (uint32_t)(code[*pos] | ((uint32_t)code[*pos + 1] << 8) |
           ((uint32_t)code[*pos + 2] << 16) | ((uint32_t)code[*pos + 3] << 24));
    *pos += 4;
    return true;
}

static inline bool read_i32(const uint8_t* code, size_t len, size_t* pos, int32_t* out)
{
    uint32_t v;
    if (!read_u32(code, len, pos, &v)) return false;
    *out = (int32_t)v;
    return true;
}

/* ── Segment override helper ──────────────────────────────────── */

static uint8_t get_seg_override(uint16_t prefixes)
{
    if (prefixes & AKAV_X86_PFX_SEG_CS) return 1;
    if (prefixes & AKAV_X86_PFX_SEG_SS) return 2;
    if (prefixes & AKAV_X86_PFX_SEG_DS) return 3;
    if (prefixes & AKAV_X86_PFX_SEG_ES) return 0;
    if (prefixes & AKAV_X86_PFX_SEG_FS) return 4;
    if (prefixes & AKAV_X86_PFX_SEG_GS) return 5;
    return AKAV_X86_REG_NONE;
}

/* ── ModR/M + SIB decoder ─────────────────────────────────────── */

static bool decode_modrm_operand(akav_x86_insn_t* insn, akav_x86_operand_t* op,
                                  const uint8_t* code, size_t len, size_t* pos,
                                  uint8_t op_size)
{
    if (insn->mod == 3) {
        /* Register direct */
        op->type = AKAV_X86_OP_REG;
        op->size = op_size;
        op->reg  = insn->rm;
        return true;
    }

    /* Memory operand */
    op->type = AKAV_X86_OP_MEM;
    op->size = op_size;
    op->seg  = get_seg_override(insn->prefixes);
    op->index_reg = AKAV_X86_REG_NONE;
    op->scale = 1;

    if (insn->rm == 4) {
        /* SIB byte follows */
        uint8_t sib_byte;
        if (!read_u8(code, len, pos, &sib_byte)) return false;

        insn->has_sib   = true;
        insn->sib       = sib_byte;
        insn->sib_scale = (sib_byte >> 6) & 3;
        insn->sib_index = (sib_byte >> 3) & 7;
        insn->sib_base  = sib_byte & 7;

        op->scale = (uint8_t)(1u << insn->sib_scale);

        if (insn->sib_index != 4) {
            op->index_reg = insn->sib_index;
        }

        if (insn->sib_base == 5 && insn->mod == 0) {
            /* disp32 only, no base */
            op->reg = AKAV_X86_REG_NONE;
            int32_t d;
            if (!read_i32(code, len, pos, &d)) return false;
            op->disp = d;
            op->has_disp = true;
        } else {
            op->reg = insn->sib_base;
        }
    } else if (insn->rm == 5 && insn->mod == 0) {
        /* disp32, no base */
        op->reg = AKAV_X86_REG_NONE;
        int32_t d;
        if (!read_i32(code, len, pos, &d)) return false;
        op->disp = d;
        op->has_disp = true;
        return true;
    } else {
        op->reg = insn->rm;
    }

    /* Read displacement based on mod */
    if (insn->mod == 1) {
        int8_t d;
        if (!read_i8(code, len, pos, &d)) return false;
        op->disp = d;
        op->has_disp = true;
    } else if (insn->mod == 2) {
        int32_t d;
        if (!read_i32(code, len, pos, &d)) return false;
        op->disp = d;
        op->has_disp = true;
    }

    return true;
}

/* ── Main decode function ─────────────────────────────────────── */

bool akav_x86_decode(akav_x86_insn_t* insn, const uint8_t* code, size_t len)
{
    if (!insn || !code || len == 0) {
        if (insn) {
            memset(insn, 0, sizeof(*insn));
            snprintf(insn->error, sizeof(insn->error), "null or empty input");
        }
        return false;
    }

    memset(insn, 0, sizeof(*insn));

    init_secondary_table();

    size_t pos = 0;

    /* ── Step 1: Consume prefixes ────────────────────────────────── */
    bool scanning_prefixes = true;
    while (scanning_prefixes && pos < len && pos < AKAV_X86_MAX_INSN_LEN) {
        uint8_t b = code[pos];
        switch (b) {
        case 0xF0: insn->prefixes |= AKAV_X86_PFX_LOCK;     break;
        case 0xF2: insn->prefixes |= AKAV_X86_PFX_REPNE;    break;
        case 0xF3: insn->prefixes |= AKAV_X86_PFX_REP;      break;
        case 0x2E: insn->prefixes |= AKAV_X86_PFX_SEG_CS;   break;
        case 0x36: insn->prefixes |= AKAV_X86_PFX_SEG_SS;   break;
        case 0x3E: insn->prefixes |= AKAV_X86_PFX_SEG_DS;   break;
        case 0x26: insn->prefixes |= AKAV_X86_PFX_SEG_ES;   break;
        case 0x64: insn->prefixes |= AKAV_X86_PFX_SEG_FS;   break;
        case 0x65: insn->prefixes |= AKAV_X86_PFX_SEG_GS;   break;
        case 0x66: insn->prefixes |= AKAV_X86_PFX_OPSIZE;   break;
        case 0x67: insn->prefixes |= AKAV_X86_PFX_ADDRSIZE; break;
        default:   scanning_prefixes = false; continue;
        }
        insn->num_prefixes++;
        pos++;
    }

    if (pos >= len) {
        snprintf(insn->error, sizeof(insn->error), "only prefixes, no opcode");
        insn->length = (uint8_t)pos;
        memcpy(insn->bytes, code, pos < AKAV_X86_MAX_INSN_LEN ? pos : AKAV_X86_MAX_INSN_LEN);
        return false;
    }

    /* ── Step 2: Read opcode ─────────────────────────────────────── */
    uint8_t op1;
    if (!read_u8(code, len, &pos, &op1)) {
        snprintf(insn->error, sizeof(insn->error), "truncated opcode");
        return false;
    }

    const x86_op_entry* entry;
    bool is_2byte = false;

    if (op1 == 0x0F) {
        is_2byte = true;
        uint8_t op2;
        if (!read_u8(code, len, &pos, &op2)) {
            snprintf(insn->error, sizeof(insn->error), "truncated 2-byte opcode");
            insn->length = (uint8_t)pos;
            memcpy(insn->bytes, code, pos);
            return false;
        }
        insn->opcode[0] = 0x0F;
        insn->opcode[1] = op2;
        insn->opcode_len = 2;
        entry = &secondary_table[op2];
    } else {
        insn->opcode[0] = op1;
        insn->opcode_len = 1;
        entry = &primary_table[op1];
    }

    uint16_t mnemonic = entry->mnemonic;
    uint8_t  encoding = entry->encoding;
    uint8_t  flags    = entry->flags;

    /* Determine operand size */
    bool is_byte = (flags & F_BYTE) != 0;
    uint8_t op_size = is_byte ? 1 : ((insn->prefixes & AKAV_X86_PFX_OPSIZE) ? 2 : 4);

    /* ── Step 3: Read ModR/M if needed ───────────────────────────── */
    if (flags & F_MODRM) {
        uint8_t modrm_byte;
        if (!read_u8(code, len, &pos, &modrm_byte)) {
            snprintf(insn->error, sizeof(insn->error), "truncated modrm");
            insn->length = (uint8_t)pos;
            memcpy(insn->bytes, code, pos);
            return false;
        }

        insn->has_modrm = true;
        insn->modrm  = modrm_byte;
        insn->mod    = (modrm_byte >> 6) & 3;
        insn->reg_op = (modrm_byte >> 3) & 7;
        insn->rm     = modrm_byte & 7;

        /* Resolve group mnemonics */
        if (flags & F_GROUP) {
            uint8_t grp_op = op1;
            if (is_2byte) grp_op = insn->opcode[1];

            switch (grp_op) {
            case 0x80: case 0x81: case 0x82: case 0x83:
                mnemonic = group1_mn[insn->reg_op];
                break;
            case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3:
                mnemonic = group2_mn[insn->reg_op];
                break;
            case 0xF6: case 0xF7:
                mnemonic = group3_mn[insn->reg_op];
                /* TEST in group3 has an immediate */
                if (insn->reg_op == 0 || insn->reg_op == 1) {
                    if (grp_op == 0xF6)
                        flags |= F_IMM8;
                    else
                        flags |= F_IMM_FULL;
                    encoding = ENC_RM_IMM;
                }
                break;
            case 0xFE:
                mnemonic = group4_mn[insn->reg_op];
                break;
            case 0xFF:
                mnemonic = group5_mn[insn->reg_op];
                break;
            }
        }
    }

    /* FPU opcodes: consume ModR/M but mark as invalid */
    if (!is_2byte && op1 >= 0xD8 && op1 <= 0xDF) {
        /* ModR/M already consumed; if mod!=3, consume SIB+disp too */
        if (insn->has_modrm && insn->mod != 3) {
            akav_x86_operand_t dummy;
            memset(&dummy, 0, sizeof(dummy));
            if (!decode_modrm_operand(insn, &dummy, code, len, &pos, 4)) {
                snprintf(insn->error, sizeof(insn->error), "truncated FPU operand");
                insn->length = (uint8_t)(pos < AKAV_X86_MAX_INSN_LEN ? pos : AKAV_X86_MAX_INSN_LEN);
                memcpy(insn->bytes, code, insn->length);
                return false;
            }
        }
        /* FPU instructions decode structurally but are "invalid" for emulation */
        insn->mnemonic = AKAV_X86_MN_INVALID;
        insn->length = (uint8_t)(pos < AKAV_X86_MAX_INSN_LEN ? pos : AKAV_X86_MAX_INSN_LEN);
        memcpy(insn->bytes, code, insn->length);
        insn->valid = true;
        return true;
    }

    if (mnemonic == AKAV_X86_MN_INVALID && !(flags & F_GROUP)) {
        snprintf(insn->error, sizeof(insn->error), "invalid opcode %s%02X",
                 is_2byte ? "0F " : "", is_2byte ? insn->opcode[1] : op1);
        insn->length = (uint8_t)(pos < AKAV_X86_MAX_INSN_LEN ? pos : AKAV_X86_MAX_INSN_LEN);
        memcpy(insn->bytes, code, insn->length);
        return false;
    }

    if (mnemonic == AKAV_X86_MN_INVALID) {
        snprintf(insn->error, sizeof(insn->error), "invalid group opcode");
        insn->length = (uint8_t)(pos < AKAV_X86_MAX_INSN_LEN ? pos : AKAV_X86_MAX_INSN_LEN);
        memcpy(insn->bytes, code, insn->length);
        return false;
    }

    insn->mnemonic = mnemonic;

    /* Handle operand-size prefix for string instructions */
    if (insn->prefixes & AKAV_X86_PFX_OPSIZE) {
        if (mnemonic == AKAV_X86_MN_MOVSD) insn->mnemonic = AKAV_X86_MN_MOVSW;
        else if (mnemonic == AKAV_X86_MN_STOSD) insn->mnemonic = AKAV_X86_MN_STOSW;
        else if (mnemonic == AKAV_X86_MN_LODSD) insn->mnemonic = AKAV_X86_MN_LODSW;
        else if (mnemonic == AKAV_X86_MN_CMPSD) insn->mnemonic = AKAV_X86_MN_CMPSW;
        else if (mnemonic == AKAV_X86_MN_SCASD) insn->mnemonic = AKAV_X86_MN_SCASW;
    }

    /* ── Step 4: Build operands ──────────────────────────────────── */
    switch (encoding) {
    case ENC_NONE:
        /* May still have immediate from flags (PUSH imm32/imm8) */
        if (flags & F_IMM_FULL) {
            akav_x86_operand_t* op = &insn->operands[insn->num_operands++];
            op->type = AKAV_X86_OP_IMM;
            op->size = op_size;
            if (op_size == 2) {
                int16_t v;
                if (!read_i16(code, len, &pos, &v)) goto truncated;
                op->imm = v;
            } else {
                int32_t v;
                if (!read_i32(code, len, &pos, &v)) goto truncated;
                op->imm = v;
            }
        } else if (flags & F_IMM8) {
            akav_x86_operand_t* op = &insn->operands[insn->num_operands++];
            op->type = AKAV_X86_OP_IMM;
            op->size = 1;
            int8_t v;
            if (!read_i8(code, len, &pos, &v)) goto truncated;
            op->imm = v;
        }
        break;

    case ENC_RM_REG: {
        /* operand 0: r/m, operand 1: reg */
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        if (!decode_modrm_operand(insn, op0, code, len, &pos, op_size)) goto truncated;

        akav_x86_operand_t* op_reg = &insn->operands[insn->num_operands++];
        op_reg->type = AKAV_X86_OP_REG;
        op_reg->size = op_size;
        op_reg->reg  = insn->reg_op;
        break;
    }

    case ENC_REG_RM: {
        /* operand 0: reg, operand 1: r/m */
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        op0->type = AKAV_X86_OP_REG;
        op0->size = op_size;
        op0->reg  = insn->reg_op;

        akav_x86_operand_t* op1_rm = &insn->operands[insn->num_operands++];
        /* For MOVZX/MOVSX: source is smaller */
        uint8_t src_size = op_size;
        if ((mnemonic == AKAV_X86_MN_MOVZX || mnemonic == AKAV_X86_MN_MOVSX) && is_2byte) {
            uint8_t op2 = insn->opcode[1];
            if (op2 == 0xB6 || op2 == 0xBE)
                src_size = 1;  /* r/m8 */
            else
                src_size = 2;  /* r/m16 */
            op0->size = op_size;  /* destination is full-size */
        }
        if (!decode_modrm_operand(insn, op1_rm, code, len, &pos, src_size)) goto truncated;
        break;
    }

    case ENC_RM_IMM: {
        /* operand 0: r/m, operand 1: immediate */
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        if (!decode_modrm_operand(insn, op0, code, len, &pos, op_size)) goto truncated;

        akav_x86_operand_t* op1_imm = &insn->operands[insn->num_operands++];
        op1_imm->type = AKAV_X86_OP_IMM;

        if (flags & F_IMM_S8) {
            op1_imm->size = op_size;
            int8_t v;
            if (!read_i8(code, len, &pos, &v)) goto truncated;
            op1_imm->imm = v;  /* sign-extended */
        } else if (flags & F_IMM8) {
            op1_imm->size = 1;
            int8_t v;
            if (!read_i8(code, len, &pos, &v)) goto truncated;
            op1_imm->imm = v;
        } else if (flags & F_IMM_FULL) {
            op1_imm->size = op_size;
            if (op_size == 2) {
                int16_t v;
                if (!read_i16(code, len, &pos, &v)) goto truncated;
                op1_imm->imm = v;
            } else {
                int32_t v;
                if (!read_i32(code, len, &pos, &v)) goto truncated;
                op1_imm->imm = v;
            }
        }
        break;
    }

    case ENC_RM_ONLY: {
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        if (!decode_modrm_operand(insn, op0, code, len, &pos, op_size)) goto truncated;

        /* D0-D3 shifts: second operand is 1 or CL */
        if (!is_2byte && (op1 == 0xD0 || op1 == 0xD1)) {
            akav_x86_operand_t* op1_one = &insn->operands[insn->num_operands++];
            op1_one->type = AKAV_X86_OP_IMM;
            op1_one->size = 1;
            op1_one->imm = 1;
        } else if (!is_2byte && (op1 == 0xD2 || op1 == 0xD3)) {
            akav_x86_operand_t* op1_cl = &insn->operands[insn->num_operands++];
            op1_cl->type = AKAV_X86_OP_REG;
            op1_cl->size = 1;
            op1_cl->reg  = AKAV_X86_REG_ECX;  /* CL */
        }
        break;
    }

    case ENC_AX_IMM: {
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        op0->type = AKAV_X86_OP_REG;
        op0->size = op_size;
        op0->reg  = AKAV_X86_REG_EAX;

        akav_x86_operand_t* op1_imm = &insn->operands[insn->num_operands++];
        op1_imm->type = AKAV_X86_OP_IMM;
        if (flags & F_IMM8) {
            op1_imm->size = 1;
            int8_t v;
            if (!read_i8(code, len, &pos, &v)) goto truncated;
            op1_imm->imm = v;
        } else {
            op1_imm->size = op_size;
            if (op_size == 2) {
                int16_t v;
                if (!read_i16(code, len, &pos, &v)) goto truncated;
                op1_imm->imm = v;
            } else {
                int32_t v;
                if (!read_i32(code, len, &pos, &v)) goto truncated;
                op1_imm->imm = v;
            }
        }
        break;
    }

    case ENC_REG_OPCODE: {
        uint8_t reg_id = (is_2byte ? insn->opcode[1] : op1) & 7;
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        op0->type = AKAV_X86_OP_REG;
        op0->size = op_size;
        op0->reg  = reg_id;

        /* MOV r32, imm32 / MOV r16, imm16 */
        if (flags & F_IMM_FULL) {
            akav_x86_operand_t* op1_imm = &insn->operands[insn->num_operands++];
            op1_imm->type = AKAV_X86_OP_IMM;
            op1_imm->size = op_size;
            if (op_size == 2) {
                int16_t v;
                if (!read_i16(code, len, &pos, &v)) goto truncated;
                op1_imm->imm = v;
            } else {
                int32_t v;
                if (!read_i32(code, len, &pos, &v)) goto truncated;
                op1_imm->imm = v;
            }
        }
        break;
    }

    case ENC_REG_IMM8: {
        /* B0-B7: MOV r8, imm8 */
        uint8_t reg_id = op1 & 7;
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        op0->type = AKAV_X86_OP_REG;
        op0->size = 1;
        op0->reg  = reg_id;

        akav_x86_operand_t* op1_imm = &insn->operands[insn->num_operands++];
        op1_imm->type = AKAV_X86_OP_IMM;
        op1_imm->size = 1;
        int8_t v;
        if (!read_i8(code, len, &pos, &v)) goto truncated;
        op1_imm->imm = (uint8_t)v;  /* zero-extend for MOV r8, imm8 */
        break;
    }

    case ENC_REL8: {
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        op0->type = AKAV_X86_OP_REL;
        op0->size = 1;
        int8_t v;
        if (!read_i8(code, len, &pos, &v)) goto truncated;
        op0->imm = v;
        break;
    }

    case ENC_REL32: {
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        op0->type = AKAV_X86_OP_REL;
        if (insn->prefixes & AKAV_X86_PFX_OPSIZE) {
            op0->size = 2;
            int16_t v;
            if (!read_i16(code, len, &pos, &v)) goto truncated;
            op0->imm = v;
        } else {
            op0->size = 4;
            int32_t v;
            if (!read_i32(code, len, &pos, &v)) goto truncated;
            op0->imm = v;
        }
        break;
    }

    case ENC_IMM8: {
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        op0->type = AKAV_X86_OP_IMM;
        op0->size = 1;
        int8_t v;
        if (!read_i8(code, len, &pos, &v)) goto truncated;
        op0->imm = (uint8_t)v;
        break;
    }

    case ENC_IMM16: {
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        op0->type = AKAV_X86_OP_IMM;
        op0->size = 2;
        uint16_t v;
        if (!read_u16(code, len, &pos, &v)) goto truncated;
        op0->imm = v;
        break;
    }

    case ENC_MOFFS: {
        /* A0-A3: MOV AL/EAX, [moffs] or MOV [moffs], AL/EAX */
        akav_x86_operand_t* op_reg = &insn->operands[insn->num_operands++];
        op_reg->type = AKAV_X86_OP_REG;
        op_reg->size = op_size;
        op_reg->reg  = AKAV_X86_REG_EAX;

        akav_x86_operand_t* op_mem = &insn->operands[insn->num_operands++];
        op_mem->type = AKAV_X86_OP_MEM;
        op_mem->size = op_size;
        op_mem->reg  = AKAV_X86_REG_NONE;
        op_mem->index_reg = AKAV_X86_REG_NONE;
        op_mem->seg  = get_seg_override(insn->prefixes);
        int32_t addr;
        if (!read_i32(code, len, &pos, &addr)) goto truncated;
        op_mem->disp = addr;
        op_mem->has_disp = true;

        /* For A2/A3, swap operand order: [moffs] is destination */
        if (op1 == 0xA2 || op1 == 0xA3) {
            akav_x86_operand_t tmp = insn->operands[0];
            insn->operands[0] = insn->operands[1];
            insn->operands[1] = tmp;
        }
        break;
    }

    case ENC_REG_RM_IMM: {
        /* IMUL r32, r/m32, imm (3-operand) */
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        op0->type = AKAV_X86_OP_REG;
        op0->size = op_size;
        op0->reg  = insn->reg_op;

        akav_x86_operand_t* op1_rm = &insn->operands[insn->num_operands++];
        if (!decode_modrm_operand(insn, op1_rm, code, len, &pos, op_size)) goto truncated;

        akav_x86_operand_t* op2_imm = &insn->operands[insn->num_operands++];
        op2_imm->type = AKAV_X86_OP_IMM;
        if (flags & F_IMM8) {
            op2_imm->size = 1;
            int8_t v;
            if (!read_i8(code, len, &pos, &v)) goto truncated;
            op2_imm->imm = v;
        } else {
            op2_imm->size = op_size;
            if (op_size == 2) {
                int16_t v;
                if (!read_i16(code, len, &pos, &v)) goto truncated;
                op2_imm->imm = v;
            } else {
                int32_t v;
                if (!read_i32(code, len, &pos, &v)) goto truncated;
                op2_imm->imm = v;
            }
        }
        break;
    }

    case ENC_ENTER: {
        /* ENTER imm16, imm8 */
        akav_x86_operand_t* op0 = &insn->operands[insn->num_operands++];
        op0->type = AKAV_X86_OP_IMM;
        op0->size = 2;
        uint16_t v16;
        if (!read_u16(code, len, &pos, &v16)) goto truncated;
        op0->imm = v16;

        akav_x86_operand_t* op1_imm = &insn->operands[insn->num_operands++];
        op1_imm->type = AKAV_X86_OP_IMM;
        op1_imm->size = 1;
        uint8_t v8;
        if (!read_u8(code, len, &pos, &v8)) goto truncated;
        op1_imm->imm = v8;
        break;
    }

    default:
        snprintf(insn->error, sizeof(insn->error), "unhandled encoding %u", encoding);
        insn->length = (uint8_t)(pos < AKAV_X86_MAX_INSN_LEN ? pos : AKAV_X86_MAX_INSN_LEN);
        memcpy(insn->bytes, code, insn->length);
        return false;
    }

    /* ── Finalize ─────────────────────────────────────────────────── */
    if (pos > AKAV_X86_MAX_INSN_LEN) {
        snprintf(insn->error, sizeof(insn->error), "instruction too long (%zu bytes)", pos);
        insn->length = AKAV_X86_MAX_INSN_LEN;
        memcpy(insn->bytes, code, AKAV_X86_MAX_INSN_LEN);
        return false;
    }

    insn->length = (uint8_t)pos;
    memcpy(insn->bytes, code, pos);
    insn->valid = true;
    return true;

truncated:
    snprintf(insn->error, sizeof(insn->error), "truncated instruction");
    insn->length = (uint8_t)(pos < AKAV_X86_MAX_INSN_LEN ? pos : AKAV_X86_MAX_INSN_LEN);
    memcpy(insn->bytes, code, insn->length);
    return false;
}

/* ── Stream decoder ───────────────────────────────────────────── */

size_t akav_x86_decode_stream(akav_x86_insn_t* insns, size_t max_insns,
                               const uint8_t* code, size_t len)
{
    if (!insns || !code) return 0;

    size_t count = 0;
    size_t offset = 0;

    while (count < max_insns && offset < len) {
        akav_x86_insn_t* insn = &insns[count];
        if (akav_x86_decode(insn, code + offset, len - offset)) {
            offset += insn->length;
        } else {
            /* Invalid: consume 1 byte and continue */
            insn->length = 1;
            insn->bytes[0] = code[offset];
            offset++;
        }
        count++;
    }

    return count;
}

/* ── Mnemonic name table ──────────────────────────────────────── */

const char* akav_x86_mnemonic_name(uint16_t mnemonic)
{
    static const char* names[] = {
        /* 0  */ "???",
        /* 1  */ "nop",
        /* 2  */ "mov",
        /* 3  */ "push",
        /* 4  */ "pop",
        /* 5  */ "add",
        /* 6  */ "sub",
        /* 7  */ "and",
        /* 8  */ "or",
        /* 9  */ "xor",
        /* 10 */ "cmp",
        /* 11 */ "test",
        /* 12 */ "jmp",
        /* 13 */ "jcc",
        /* 14 */ "call",
        /* 15 */ "ret",
        /* 16 */ "lea",
        /* 17 */ "xchg",
        /* 18 */ "inc",
        /* 19 */ "dec",
        /* 20 */ "not",
        /* 21 */ "neg",
        /* 22 */ "shl",
        /* 23 */ "shr",
        /* 24 */ "sar",
        /* 25 */ "rol",
        /* 26 */ "ror",
        /* 27 */ "movzx",
        /* 28 */ "movsx",
        /* 29 */ "loop",
        /* 30 */ "loope",
        /* 31 */ "loopne",
        /* 32 */ "movsb",
        /* 33 */ "movsd",
        /* 34 */ "stosb",
        /* 35 */ "stosd",
        /* 36 */ "lodsb",
        /* 37 */ "lodsd",
        /* 38 */ "int",
        /* 39 */ "int3",
        /* 40 */ "mul",
        /* 41 */ "imul",
        /* 42 */ "div",
        /* 43 */ "idiv",
        /* 44 */ "cdq",
        /* 45 */ "leave",
        /* 46 */ "enter",
        /* 47 */ "clc",
        /* 48 */ "stc",
        /* 49 */ "cld",
        /* 50 */ "std",
        /* 51 */ "pushad",
        /* 52 */ "popad",
        /* 53 */ "pushfd",
        /* 54 */ "popfd",
        /* 55 */ "cmc",
        /* 56 */ "cmpsb",
        /* 57 */ "cmpsd",
        /* 58 */ "scasb",
        /* 59 */ "scasd",
        /* 60 */ "setcc",
        /* 61 */ "cmovcc",
        /* 62 */ "bsf",
        /* 63 */ "bsr",
        /* 64 */ "bt",
        /* 65 */ "bts",
        /* 66 */ "btr",
        /* 67 */ "btc",
        /* 68 */ "bswap",
        /* 69 */ "rdtsc",
        /* 70 */ "cpuid",
        /* 71 */ "xadd",
        /* 72 */ "cmpxchg",
        /* 73 */ "sbb",
        /* 74 */ "adc",
        /* 75 */ "rcl",
        /* 76 */ "rcr",
        /* 77 */ "retn",
        /* 78 */ "movsw",
        /* 79 */ "stosw",
        /* 80 */ "lodsw",
        /* 81 */ "cmpsw",
        /* 82 */ "scasw",
    };

    size_t count = sizeof(names) / sizeof(names[0]);
    if (mnemonic < count) return names[mnemonic];
    return "???";
}
