#ifndef AKAV_X86_DECODE_H
#define AKAV_X86_DECODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Maximum instruction length (Intel spec) ───────────────────── */
#define AKAV_X86_MAX_INSN_LEN  15

/* ── Prefix flags (bitfield) ───────────────────────────────────── */
#define AKAV_X86_PFX_LOCK      0x0001
#define AKAV_X86_PFX_REPNE     0x0002  /* F2 */
#define AKAV_X86_PFX_REP       0x0004  /* F3 */
#define AKAV_X86_PFX_SEG_CS    0x0008
#define AKAV_X86_PFX_SEG_SS    0x0010
#define AKAV_X86_PFX_SEG_DS    0x0020
#define AKAV_X86_PFX_SEG_ES    0x0040
#define AKAV_X86_PFX_SEG_FS    0x0080
#define AKAV_X86_PFX_SEG_GS    0x0100
#define AKAV_X86_PFX_OPSIZE    0x0200  /* 66 */
#define AKAV_X86_PFX_ADDRSIZE  0x0400  /* 67 */

/* ── Operand types ─────────────────────────────────────────────── */
#define AKAV_X86_OP_NONE       0
#define AKAV_X86_OP_REG        1
#define AKAV_X86_OP_MEM        2
#define AKAV_X86_OP_IMM        3
#define AKAV_X86_OP_REL        4

/* ── Register IDs ──────────────────────────────────────────────── */
#define AKAV_X86_REG_NONE      0xFF
#define AKAV_X86_REG_EAX       0
#define AKAV_X86_REG_ECX       1
#define AKAV_X86_REG_EDX       2
#define AKAV_X86_REG_EBX       3
#define AKAV_X86_REG_ESP       4
#define AKAV_X86_REG_EBP       5
#define AKAV_X86_REG_ESI       6
#define AKAV_X86_REG_EDI       7

/* ── Mnemonic IDs ──────────────────────────────────────────────── */
#define AKAV_X86_MN_INVALID    0
#define AKAV_X86_MN_NOP        1
#define AKAV_X86_MN_MOV        2
#define AKAV_X86_MN_PUSH       3
#define AKAV_X86_MN_POP        4
#define AKAV_X86_MN_ADD        5
#define AKAV_X86_MN_SUB        6
#define AKAV_X86_MN_AND        7
#define AKAV_X86_MN_OR         8
#define AKAV_X86_MN_XOR        9
#define AKAV_X86_MN_CMP       10
#define AKAV_X86_MN_TEST      11
#define AKAV_X86_MN_JMP       12
#define AKAV_X86_MN_JCC       13
#define AKAV_X86_MN_CALL      14
#define AKAV_X86_MN_RET       15
#define AKAV_X86_MN_LEA       16
#define AKAV_X86_MN_XCHG      17
#define AKAV_X86_MN_INC       18
#define AKAV_X86_MN_DEC       19
#define AKAV_X86_MN_NOT       20
#define AKAV_X86_MN_NEG       21
#define AKAV_X86_MN_SHL       22
#define AKAV_X86_MN_SHR       23
#define AKAV_X86_MN_SAR       24
#define AKAV_X86_MN_ROL       25
#define AKAV_X86_MN_ROR       26
#define AKAV_X86_MN_MOVZX     27
#define AKAV_X86_MN_MOVSX     28
#define AKAV_X86_MN_LOOP      29
#define AKAV_X86_MN_LOOPE     30
#define AKAV_X86_MN_LOOPNE    31
#define AKAV_X86_MN_MOVSB     32
#define AKAV_X86_MN_MOVSD     33
#define AKAV_X86_MN_STOSB     34
#define AKAV_X86_MN_STOSD     35
#define AKAV_X86_MN_LODSB     36
#define AKAV_X86_MN_LODSD     37
#define AKAV_X86_MN_INT       38
#define AKAV_X86_MN_INT3      39
#define AKAV_X86_MN_MUL       40
#define AKAV_X86_MN_IMUL      41
#define AKAV_X86_MN_DIV       42
#define AKAV_X86_MN_IDIV      43
#define AKAV_X86_MN_CDQ       44
#define AKAV_X86_MN_LEAVE     45
#define AKAV_X86_MN_ENTER     46
#define AKAV_X86_MN_CLC       47
#define AKAV_X86_MN_STC       48
#define AKAV_X86_MN_CLD       49
#define AKAV_X86_MN_STD       50
#define AKAV_X86_MN_PUSHAD    51
#define AKAV_X86_MN_POPAD     52
#define AKAV_X86_MN_PUSHFD    53
#define AKAV_X86_MN_POPFD     54
#define AKAV_X86_MN_CMC       55
#define AKAV_X86_MN_CMPSB     56
#define AKAV_X86_MN_CMPSD     57
#define AKAV_X86_MN_SCASB     58
#define AKAV_X86_MN_SCASD     59
#define AKAV_X86_MN_SETCC     60
#define AKAV_X86_MN_CMOVCC    61
#define AKAV_X86_MN_BSF       62
#define AKAV_X86_MN_BSR       63
#define AKAV_X86_MN_BT        64
#define AKAV_X86_MN_BTS       65
#define AKAV_X86_MN_BTR       66
#define AKAV_X86_MN_BTC       67
#define AKAV_X86_MN_BSWAP     68
#define AKAV_X86_MN_RDTSC     69
#define AKAV_X86_MN_CPUID     70
#define AKAV_X86_MN_XADD      71
#define AKAV_X86_MN_CMPXCHG   72
#define AKAV_X86_MN_SBB       73
#define AKAV_X86_MN_ADC       74
#define AKAV_X86_MN_RCL       75
#define AKAV_X86_MN_RCR       76
#define AKAV_X86_MN_RETN      77
#define AKAV_X86_MN_MOVSW     78
#define AKAV_X86_MN_STOSW     79
#define AKAV_X86_MN_LODSW     80
#define AKAV_X86_MN_CMPSW     81
#define AKAV_X86_MN_SCASW     82

/* ── Operand struct ────────────────────────────────────────────── */

typedef struct {
    uint8_t  type;       /* AKAV_X86_OP_* */
    uint8_t  size;       /* operand size in bytes: 1, 2, or 4 */
    uint8_t  reg;        /* register ID (for OP_REG, or base for OP_MEM) */

    /* Memory operand fields (type == OP_MEM) */
    uint8_t  index_reg;  /* SIB index register (REG_NONE if none) */
    uint8_t  scale;      /* SIB scale: 1, 2, 4, or 8 */
    uint8_t  seg;        /* segment override (REG_NONE if default) */
    int32_t  disp;       /* displacement */
    bool     has_disp;

    /* Immediate / relative (type == OP_IMM or OP_REL) */
    int64_t  imm;
} akav_x86_operand_t;

/* ── Decoded instruction ───────────────────────────────────────── */

typedef struct {
    uint8_t  bytes[AKAV_X86_MAX_INSN_LEN];
    uint8_t  length;

    /* Prefixes */
    uint16_t prefixes;   /* AKAV_X86_PFX_* bitfield */
    uint8_t  num_prefixes;

    /* Opcode */
    uint8_t  opcode[3];
    uint8_t  opcode_len;

    /* ModR/M */
    bool     has_modrm;
    uint8_t  modrm;
    uint8_t  mod;
    uint8_t  reg_op;
    uint8_t  rm;

    /* SIB */
    bool     has_sib;
    uint8_t  sib;
    uint8_t  sib_scale;
    uint8_t  sib_index;
    uint8_t  sib_base;

    /* Operands */
    akav_x86_operand_t operands[3];
    uint8_t  num_operands;

    /* Mnemonic */
    uint16_t mnemonic;

    /* Status */
    bool     valid;
    char     error[64];
} akav_x86_insn_t;

/* ── Decode API ────────────────────────────────────────────────── */

/**
 * Decode a single x86 (32-bit mode) instruction.
 * Returns true on success, false on invalid/truncated input.
 */
bool akav_x86_decode(akav_x86_insn_t* insn, const uint8_t* code, size_t len);

/**
 * Decode a stream of instructions. Returns number decoded.
 * Failed decodes consume 1 byte and set insn[i].valid = false.
 */
size_t akav_x86_decode_stream(akav_x86_insn_t* insns, size_t max_insns,
                               const uint8_t* code, size_t len);

/**
 * Return the mnemonic name as a string (e.g., "mov", "push").
 */
const char* akav_x86_mnemonic_name(uint16_t mnemonic);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_X86_DECODE_H */
