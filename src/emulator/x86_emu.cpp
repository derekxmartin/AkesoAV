/* x86_emu.cpp — 32-bit x86 execution engine for AkesoAV emulator.
 *
 * Flat memory model, register file (EAX-EDI, ESP, EBP, EIP, EFLAGS),
 * fetch-decode-execute loop with 2M instruction limit.
 */

#include "emulator/x86_emu.h"
#include "emulator/x86_decode.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

/* ── Memory access ────────────────────────────────────────────── */

bool akav_x86_mem_read8(const akav_x86_mem_t* mem, uint32_t addr, uint8_t* out)
{
    if (addr >= mem->size) return false;
    *out = mem->data[addr];
    return true;
}

bool akav_x86_mem_read16(const akav_x86_mem_t* mem, uint32_t addr, uint16_t* out)
{
    if ((size_t)addr + 2 > mem->size) return false;
    *out = (uint16_t)(mem->data[addr] | ((uint16_t)mem->data[addr + 1] << 8));
    return true;
}

bool akav_x86_mem_read32(const akav_x86_mem_t* mem, uint32_t addr, uint32_t* out)
{
    if ((size_t)addr + 4 > mem->size) return false;
    *out = (uint32_t)(mem->data[addr] | ((uint32_t)mem->data[addr + 1] << 8) |
           ((uint32_t)mem->data[addr + 2] << 16) | ((uint32_t)mem->data[addr + 3] << 24));
    return true;
}

bool akav_x86_mem_write8(akav_x86_mem_t* mem, uint32_t addr, uint8_t val)
{
    if (addr >= mem->size) return false;
    mem->data[addr] = val;
    return true;
}

bool akav_x86_mem_write16(akav_x86_mem_t* mem, uint32_t addr, uint16_t val)
{
    if ((size_t)addr + 2 > mem->size) return false;
    mem->data[addr]     = (uint8_t)(val & 0xFF);
    mem->data[addr + 1] = (uint8_t)(val >> 8);
    return true;
}

bool akav_x86_mem_write32(akav_x86_mem_t* mem, uint32_t addr, uint32_t val)
{
    if ((size_t)addr + 4 > mem->size) return false;
    mem->data[addr]     = (uint8_t)(val & 0xFF);
    mem->data[addr + 1] = (uint8_t)((val >> 8) & 0xFF);
    mem->data[addr + 2] = (uint8_t)((val >> 16) & 0xFF);
    mem->data[addr + 3] = (uint8_t)((val >> 24) & 0xFF);
    return true;
}

/* ── Init / Free ──────────────────────────────────────────────── */

bool akav_x86_emu_init(akav_x86_emu_t* emu, size_t mem_size)
{
    if (!emu || mem_size < 4096) return false;

    memset(emu, 0, sizeof(*emu));

    emu->mem.data = (uint8_t*)calloc(1, mem_size);
    if (!emu->mem.data) return false;
    emu->mem.size = mem_size;

    emu->insn_limit = AKAV_EMU_DEFAULT_INSN_LIMIT;
    emu->regs.eflags = 0x202;  /* reserved bit 1 + IF */

    /* Stack at top of memory, 16-byte aligned */
    emu->regs.reg[4 /* ESP */] = (uint32_t)(mem_size - 16) & ~0xFu;

    /* Push sentinel return address */
    emu->regs.reg[4] -= 4;
    akav_x86_mem_write32(&emu->mem, emu->regs.reg[4], AKAV_EMU_STACK_SENTINEL);

    return true;
}

void akav_x86_emu_free(akav_x86_emu_t* emu)
{
    if (!emu) return;
    free(emu->mem.data);
    emu->mem.data = NULL;
    emu->mem.size = 0;
}

bool akav_x86_emu_load(akav_x86_emu_t* emu, uint32_t addr,
                        const uint8_t* data, size_t len)
{
    if (!emu || !data) return false;
    if ((size_t)addr + len > emu->mem.size) return false;
    memcpy(emu->mem.data + addr, data, len);
    return true;
}

/* ── EFLAGS helpers ───────────────────────────────────────────── */

static inline uint32_t sign_bit(uint8_t size)
{
    if (size == 1) return 0x80u;
    if (size == 2) return 0x8000u;
    return 0x80000000u;
}

static inline uint32_t size_mask(uint8_t size)
{
    if (size == 1) return 0xFFu;
    if (size == 2) return 0xFFFFu;
    return 0xFFFFFFFFu;
}

static void update_flags_zf_sf(akav_x86_regs_t* regs, uint32_t result, uint8_t size)
{
    uint32_t mask = size_mask(size);
    result &= mask;
    regs->eflags &= ~(AKAV_EFLAGS_ZF | AKAV_EFLAGS_SF);
    if (result == 0)
        regs->eflags |= AKAV_EFLAGS_ZF;
    if (result & sign_bit(size))
        regs->eflags |= AKAV_EFLAGS_SF;
}

static void update_flags_add(akav_x86_regs_t* regs, uint32_t a, uint32_t b,
                              uint64_t result64, uint8_t size)
{
    uint32_t mask = size_mask(size);
    uint32_t result = (uint32_t)(result64 & mask);
    uint32_t sb = sign_bit(size);

    regs->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_ZF | AKAV_EFLAGS_SF | AKAV_EFLAGS_OF);

    /* CF: unsigned carry */
    if ((result64 & ((uint64_t)mask + 1)) != 0)
        regs->eflags |= AKAV_EFLAGS_CF;

    /* ZF/SF */
    if (result == 0)
        regs->eflags |= AKAV_EFLAGS_ZF;
    if (result & sb)
        regs->eflags |= AKAV_EFLAGS_SF;

    /* OF: signed overflow */
    if (((~(a ^ b)) & (a ^ result)) & sb)
        regs->eflags |= AKAV_EFLAGS_OF;
}

static void update_flags_sub(akav_x86_regs_t* regs, uint32_t a, uint32_t b,
                              uint32_t result, uint8_t size)
{
    uint32_t mask = size_mask(size);
    uint32_t sb = sign_bit(size);
    a &= mask;
    b &= mask;
    result &= mask;

    regs->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_ZF | AKAV_EFLAGS_SF | AKAV_EFLAGS_OF);

    /* CF: unsigned borrow */
    if (a < b)
        regs->eflags |= AKAV_EFLAGS_CF;

    if (result == 0)
        regs->eflags |= AKAV_EFLAGS_ZF;
    if (result & sb)
        regs->eflags |= AKAV_EFLAGS_SF;

    /* OF: signed overflow */
    if (((a ^ b) & (a ^ result)) & sb)
        regs->eflags |= AKAV_EFLAGS_OF;
}

static void update_flags_logic(akav_x86_regs_t* regs, uint32_t result, uint8_t size)
{
    regs->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_ZF | AKAV_EFLAGS_SF | AKAV_EFLAGS_OF);
    update_flags_zf_sf(regs, result, size);
}

/* ── Condition code evaluation ────────────────────────────────── */

static bool eval_cc(uint8_t cc, uint32_t eflags)
{
    bool cf = (eflags & AKAV_EFLAGS_CF) != 0;
    bool zf = (eflags & AKAV_EFLAGS_ZF) != 0;
    bool sf = (eflags & AKAV_EFLAGS_SF) != 0;
    bool of = (eflags & AKAV_EFLAGS_OF) != 0;

    switch (cc & 0xF) {
    case 0x0: return of;                /* O */
    case 0x1: return !of;               /* NO */
    case 0x2: return cf;                /* B/C */
    case 0x3: return !cf;               /* NB/NC */
    case 0x4: return zf;                /* Z/E */
    case 0x5: return !zf;               /* NZ/NE */
    case 0x6: return cf || zf;          /* BE */
    case 0x7: return !cf && !zf;        /* A/NBE */
    case 0x8: return sf;                /* S */
    case 0x9: return !sf;               /* NS */
    case 0xA: return false;             /* P (stub) */
    case 0xB: return true;              /* NP (stub) */
    case 0xC: return sf != of;          /* L */
    case 0xD: return sf == of;          /* GE/NL */
    case 0xE: return zf || (sf != of);  /* LE */
    case 0xF: return !zf && (sf == of); /* G/NLE */
    default:  return false;
    }
}

/* ── 8-bit register helpers ───────────────────────────────────── */

static uint8_t read_reg8(const akav_x86_regs_t* regs, uint8_t id)
{
    if (id < 4) return (uint8_t)(regs->reg[id] & 0xFF);       /* AL/CL/DL/BL */
    return (uint8_t)((regs->reg[id - 4] >> 8) & 0xFF);        /* AH/CH/DH/BH */
}

static void write_reg8(akav_x86_regs_t* regs, uint8_t id, uint8_t val)
{
    if (id < 4) {
        regs->reg[id] = (regs->reg[id] & 0xFFFFFF00u) | val;
    } else {
        uint8_t base = id - 4;
        regs->reg[base] = (regs->reg[base] & 0xFFFF00FFu) | ((uint32_t)val << 8);
    }
}

/* ── Operand resolution ───────────────────────────────────────── */

static uint32_t compute_ea(const akav_x86_emu_t* emu, const akav_x86_operand_t* op)
{
    uint32_t addr = 0;
    if (op->reg != AKAV_X86_REG_NONE)
        addr += emu->regs.reg[op->reg];
    if (op->index_reg != AKAV_X86_REG_NONE)
        addr += emu->regs.reg[op->index_reg] * op->scale;
    if (op->has_disp)
        addr += (uint32_t)op->disp;

    /* FS segment override: translate to TEB base address.
     * seg==4 is FS (set by decoder from 0x64 prefix).
     * This enables fs:[0x30] → PEB pointer, fs:[0x00] → SEH chain, etc. */
    if (op->seg == 4)
        addr += 0x7FFD0000u; /* AKAV_TEB_BASE */

    return addr;
}

static bool read_operand(akav_x86_emu_t* emu, const akav_x86_operand_t* op, uint32_t* out)
{
    switch (op->type) {
    case AKAV_X86_OP_REG:
        if (op->size == 1) { *out = read_reg8(&emu->regs, op->reg); return true; }
        if (op->size == 2) { *out = emu->regs.reg[op->reg] & 0xFFFF; return true; }
        *out = emu->regs.reg[op->reg];
        return true;
    case AKAV_X86_OP_MEM: {
        uint32_t addr = compute_ea(emu, op);
        if (op->size == 1) { uint8_t v; if (!akav_x86_mem_read8(&emu->mem, addr, &v)) return false; *out = v; return true; }
        if (op->size == 2) { uint16_t v; if (!akav_x86_mem_read16(&emu->mem, addr, &v)) return false; *out = v; return true; }
        return akav_x86_mem_read32(&emu->mem, addr, out);
    }
    case AKAV_X86_OP_IMM:
    case AKAV_X86_OP_REL:
        *out = (uint32_t)op->imm;
        return true;
    default:
        return false;
    }
}

/* ── Write callback helper ────────────────────────────────────── */

static inline void notify_write(akav_x86_emu_t* emu, uint32_t addr, uint32_t sz)
{
    if (emu->write_callback)
        emu->write_callback(emu, addr, sz, emu->write_callback_data);
}

static bool write_operand(akav_x86_emu_t* emu, const akav_x86_operand_t* op, uint32_t val)
{
    switch (op->type) {
    case AKAV_X86_OP_REG:
        if (op->size == 1) { write_reg8(&emu->regs, op->reg, (uint8_t)val); return true; }
        if (op->size == 2) { emu->regs.reg[op->reg] = (emu->regs.reg[op->reg] & 0xFFFF0000u) | (val & 0xFFFF); return true; }
        emu->regs.reg[op->reg] = val;
        return true;
    case AKAV_X86_OP_MEM: {
        uint32_t addr = compute_ea(emu, op);
        bool ok;
        if (op->size == 1) ok = akav_x86_mem_write8(&emu->mem, addr, (uint8_t)val);
        else if (op->size == 2) ok = akav_x86_mem_write16(&emu->mem, addr, (uint16_t)val);
        else ok = akav_x86_mem_write32(&emu->mem, addr, val);
        if (ok) notify_write(emu, addr, op->size);
        return ok;
    }
    default:
        return false;
    }
}

/* ── Push / Pop helpers ───────────────────────────────────────── */

static bool emu_push32(akav_x86_emu_t* emu, uint32_t val)
{
    emu->regs.reg[4] -= 4;  /* ESP */
    return akav_x86_mem_write32(&emu->mem, emu->regs.reg[4], val);
}

static bool emu_pop32(akav_x86_emu_t* emu, uint32_t* val)
{
    if (!akav_x86_mem_read32(&emu->mem, emu->regs.reg[4], val)) return false;
    emu->regs.reg[4] += 4;
    return true;
}

/* ── Fault helper ─────────────────────────────────────────────── */

/* Try to dispatch a fault via the SEH chain in the TEB.
 * Returns true if an SEH handler was found and EIP was redirected. */
static bool try_seh_dispatch(akav_x86_emu_t* emu, uint32_t exception_code)
{
    /* Read SEH chain head from TEB[0] (0x7FFD0000) */
    uint32_t seh_head = 0;
    if (!akav_x86_mem_read32(&emu->mem, 0x7FFD0000u, &seh_head))
        return false;

    /* 0xFFFFFFFF = end of chain (no handler) */
    if (seh_head == 0xFFFFFFFF || seh_head == 0)
        return false;

    /* Read handler address at [seh_head + 4] */
    uint32_t handler = 0;
    if (!akav_x86_mem_read32(&emu->mem, seh_head + 4, &handler))
        return false;
    if (handler == 0 || handler == 0xFFFFFFFF)
        return false;

    /* Push simplified exception record onto stack:
     *   [ESP-4]  = exception code
     *   [ESP-8]  = fault EIP
     *   [ESP-12] = SEH frame pointer */
    uint32_t esp = emu->regs.reg[4]; /* ESP */
    esp -= 4; akav_x86_mem_write32(&emu->mem, esp, exception_code);
    esp -= 4; akav_x86_mem_write32(&emu->mem, esp, emu->regs.eip);
    esp -= 4; akav_x86_mem_write32(&emu->mem, esp, seh_head);
    emu->regs.reg[4] = esp;

    /* Transfer control to handler */
    emu->regs.eip = handler;
    emu->halted = false; /* Clear any halt state */
    return true;
}

static int emu_fault(akav_x86_emu_t* emu, uint8_t reason, const char* msg)
{
    /* For faults (not halts), try SEH dispatch first */
    if (reason == AKAV_EMU_HALT_FAULT) {
        if (try_seh_dispatch(emu, 0xC0000094u /* STATUS_INTEGER_DIVIDE_BY_ZERO */))
            return AKAV_EMU_OK; /* Continue execution at handler */
    }

    emu->halted = true;
    emu->halt_reason = reason;
    snprintf(emu->error, sizeof(emu->error), "%s", msg);
    return reason;
}

/* ── Condition code extraction from decoded instruction ────────── */

static uint8_t extract_cc(const akav_x86_insn_t* insn)
{
    if (insn->opcode_len == 1) {
        /* 0x70-0x7F or 0xE3 (JECXZ) */
        if (insn->opcode[0] == 0xE3) return 0xFF;  /* special: JECXZ */
        return insn->opcode[0] & 0x0F;
    }
    /* 2-byte: 0F 80-8F, 0F 90-9F, 0F 40-4F */
    return insn->opcode[1] & 0x0F;
}

/* ── Execute one instruction ──────────────────────────────────── */

static int execute(akav_x86_emu_t* emu, const akav_x86_insn_t* insn)
{
    akav_x86_regs_t* r = &emu->regs;
    uint32_t a, b, result;
    uint64_t result64;
    uint8_t op_size;

    switch (insn->mnemonic) {

    /* ── Data Movement ────────────────────────────────────────── */

    case AKAV_X86_MN_MOV:
        if (!read_operand(emu, &insn->operands[1], &a)) goto fault;
        if (!write_operand(emu, &insn->operands[0], a)) goto fault;
        break;

    case AKAV_X86_MN_MOVZX:
        if (!read_operand(emu, &insn->operands[1], &a)) goto fault;
        /* Already zero-extended by read_operand */
        if (!write_operand(emu, &insn->operands[0], a)) goto fault;
        break;

    case AKAV_X86_MN_MOVSX: {
        if (!read_operand(emu, &insn->operands[1], &a)) goto fault;
        uint8_t src_size = insn->operands[1].size;
        if (src_size == 1) a = (uint32_t)(int32_t)(int8_t)a;
        else if (src_size == 2) a = (uint32_t)(int32_t)(int16_t)a;
        if (!write_operand(emu, &insn->operands[0], a)) goto fault;
        break;
    }

    case AKAV_X86_MN_LEA:
        a = compute_ea(emu, &insn->operands[1]);
        if (!write_operand(emu, &insn->operands[0], a)) goto fault;
        break;

    case AKAV_X86_MN_XCHG:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        if (!write_operand(emu, &insn->operands[0], b)) goto fault;
        if (!write_operand(emu, &insn->operands[1], a)) goto fault;
        break;

    case AKAV_X86_MN_PUSH:
        if (insn->num_operands > 0) {
            if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        } else {
            a = 0;  /* shouldn't happen */
        }
        if (!emu_push32(emu, a)) goto fault;
        break;

    case AKAV_X86_MN_POP:
        if (!emu_pop32(emu, &a)) goto fault;
        if (!write_operand(emu, &insn->operands[0], a)) goto fault;
        break;

    case AKAV_X86_MN_PUSHAD: {
        uint32_t saved_esp = r->reg[4];
        for (int i = 0; i < 8; i++) {
            uint32_t val = (i == 4) ? saved_esp : r->reg[i];
            if (!emu_push32(emu, val)) goto fault;
        }
        break;
    }

    case AKAV_X86_MN_POPAD:
        for (int i = 7; i >= 0; i--) {
            if (!emu_pop32(emu, &a)) goto fault;
            if (i != 4) r->reg[i] = a;  /* skip ESP */
        }
        break;

    case AKAV_X86_MN_PUSHFD:
        if (!emu_push32(emu, r->eflags)) goto fault;
        break;

    case AKAV_X86_MN_POPFD:
        if (!emu_pop32(emu, &a)) goto fault;
        r->eflags = (a & 0x00000CD5u) | 0x202u;  /* mask writable bits + reserved */
        break;

    case AKAV_X86_MN_CDQ:
        r->reg[2] = (r->reg[0] & 0x80000000u) ? 0xFFFFFFFFu : 0;  /* EDX */
        break;

    case AKAV_X86_MN_BSWAP:
        a = r->reg[insn->operands[0].reg];
        r->reg[insn->operands[0].reg] =
            ((a >> 24) & 0xFF) | ((a >> 8) & 0xFF00) |
            ((a << 8) & 0xFF0000) | ((a << 24) & 0xFF000000u);
        break;

    case AKAV_X86_MN_ENTER:
        if (!emu_push32(emu, r->reg[5])) goto fault;  /* push EBP */
        r->reg[5] = r->reg[4];  /* EBP = ESP */
        r->reg[4] -= (uint32_t)insn->operands[0].imm;  /* ESP -= imm16 */
        break;

    case AKAV_X86_MN_LEAVE:
        r->reg[4] = r->reg[5];  /* ESP = EBP */
        if (!emu_pop32(emu, &r->reg[5])) goto fault;  /* pop EBP */
        break;

    /* ── Arithmetic ───────────────────────────────────────────── */

    case AKAV_X86_MN_ADD:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        result64 = (uint64_t)(a & size_mask(op_size)) + (uint64_t)(b & size_mask(op_size));
        result = (uint32_t)result64;
        update_flags_add(r, a, b, result64, op_size);
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    case AKAV_X86_MN_ADC:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        result64 = (uint64_t)(a & size_mask(op_size)) + (uint64_t)(b & size_mask(op_size))
                   + ((r->eflags & AKAV_EFLAGS_CF) ? 1u : 0u);
        result = (uint32_t)result64;
        update_flags_add(r, a, b, result64, op_size);
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    case AKAV_X86_MN_SUB:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        result = a - b;
        update_flags_sub(r, a, b, result, op_size);
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    case AKAV_X86_MN_SBB:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        b += (r->eflags & AKAV_EFLAGS_CF) ? 1u : 0u;
        result = a - b;
        update_flags_sub(r, a, b, result, op_size);
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    case AKAV_X86_MN_CMP:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        result = a - b;
        update_flags_sub(r, a, b, result, op_size);
        break;

    case AKAV_X86_MN_INC:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        result = a + 1;
        {
            uint32_t saved_cf = r->eflags & AKAV_EFLAGS_CF;
            update_flags_add(r, a, 1, (uint64_t)(a & size_mask(op_size)) + 1, op_size);
            r->eflags = (r->eflags & ~AKAV_EFLAGS_CF) | saved_cf;  /* preserve CF */
        }
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    case AKAV_X86_MN_DEC:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        result = a - 1;
        {
            uint32_t saved_cf = r->eflags & AKAV_EFLAGS_CF;
            update_flags_sub(r, a, 1, result, op_size);
            r->eflags = (r->eflags & ~AKAV_EFLAGS_CF) | saved_cf;
        }
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    case AKAV_X86_MN_NEG:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        result = 0u - a;
        update_flags_sub(r, 0, a, result, op_size);
        if (a != 0) r->eflags |= AKAV_EFLAGS_CF; else r->eflags &= ~AKAV_EFLAGS_CF;
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    case AKAV_X86_MN_MUL:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        op_size = insn->operands[0].size;
        if (op_size == 1) {
            uint16_t res16 = (uint16_t)(r->reg[0] & 0xFF) * (uint16_t)a;
            r->reg[0] = (r->reg[0] & 0xFFFF0000u) | res16;
            r->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_OF);
            if (res16 > 0xFF) r->eflags |= (AKAV_EFLAGS_CF | AKAV_EFLAGS_OF);
        } else if (op_size == 4) {
            result64 = (uint64_t)r->reg[0] * (uint64_t)a;
            r->reg[0] = (uint32_t)result64;
            r->reg[2] = (uint32_t)(result64 >> 32);
            r->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_OF);
            if (r->reg[2] != 0) r->eflags |= (AKAV_EFLAGS_CF | AKAV_EFLAGS_OF);
        }
        break;

    case AKAV_X86_MN_IMUL:
        if (insn->num_operands == 1) {
            /* 1-operand: EDX:EAX = EAX * r/m32 (signed) */
            if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
            int64_t sr = (int64_t)(int32_t)r->reg[0] * (int64_t)(int32_t)a;
            r->reg[0] = (uint32_t)sr;
            r->reg[2] = (uint32_t)((uint64_t)sr >> 32);
            r->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_OF);
            if (sr != (int64_t)(int32_t)r->reg[0])
                r->eflags |= (AKAV_EFLAGS_CF | AKAV_EFLAGS_OF);
        } else if (insn->num_operands == 2) {
            /* 2-operand: reg *= r/m */
            if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
            if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
            int64_t sr = (int64_t)(int32_t)a * (int64_t)(int32_t)b;
            result = (uint32_t)sr;
            r->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_OF);
            if (sr != (int64_t)(int32_t)result)
                r->eflags |= (AKAV_EFLAGS_CF | AKAV_EFLAGS_OF);
            if (!write_operand(emu, &insn->operands[0], result)) goto fault;
        } else {
            /* 3-operand: reg = r/m * imm */
            if (!read_operand(emu, &insn->operands[1], &a)) goto fault;
            if (!read_operand(emu, &insn->operands[2], &b)) goto fault;
            int64_t sr = (int64_t)(int32_t)a * (int64_t)(int32_t)b;
            result = (uint32_t)sr;
            r->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_OF);
            if (sr != (int64_t)(int32_t)result)
                r->eflags |= (AKAV_EFLAGS_CF | AKAV_EFLAGS_OF);
            if (!write_operand(emu, &insn->operands[0], result)) goto fault;
        }
        break;

    case AKAV_X86_MN_DIV:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (a == 0) return emu_fault(emu, AKAV_EMU_HALT_FAULT, "divide by zero");
        result64 = ((uint64_t)r->reg[2] << 32) | r->reg[0];
        r->reg[0] = (uint32_t)(result64 / a);
        r->reg[2] = (uint32_t)(result64 % a);
        break;

    case AKAV_X86_MN_IDIV:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (a == 0) return emu_fault(emu, AKAV_EMU_HALT_FAULT, "divide by zero");
        {
            int64_t dividend = (int64_t)(((uint64_t)r->reg[2] << 32) | r->reg[0]);
            int32_t divisor = (int32_t)a;
            r->reg[0] = (uint32_t)(int32_t)(dividend / divisor);
            r->reg[2] = (uint32_t)(int32_t)(dividend % divisor);
        }
        break;

    case AKAV_X86_MN_XADD:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        op_size = insn->operands[0].size;
        result64 = (uint64_t)(a & size_mask(op_size)) + (uint64_t)(b & size_mask(op_size));
        result = (uint32_t)result64;
        update_flags_add(r, a, b, result64, op_size);
        if (!write_operand(emu, &insn->operands[1], a)) goto fault;  /* src = old dst */
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    /* ── Logical ──────────────────────────────────────────────── */

    case AKAV_X86_MN_AND:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        result = a & b;
        update_flags_logic(r, result, op_size);
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    case AKAV_X86_MN_OR:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        result = a | b;
        update_flags_logic(r, result, op_size);
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    case AKAV_X86_MN_XOR:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        result = a ^ b;
        update_flags_logic(r, result, op_size);
        if (!write_operand(emu, &insn->operands[0], result & size_mask(op_size))) goto fault;
        break;

    case AKAV_X86_MN_NOT:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!write_operand(emu, &insn->operands[0], ~a)) goto fault;
        break;

    case AKAV_X86_MN_TEST:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        result = a & b;
        update_flags_logic(r, result, op_size);
        break;

    /* ── Shifts/Rotates ───────────────────────────────────────── */

    case AKAV_X86_MN_SHL:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        b &= 0x1F;
        if (b == 0) break;
        {
            uint32_t mask = size_mask(op_size);
            a &= mask;
            r->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_ZF | AKAV_EFLAGS_SF | AKAV_EFLAGS_OF);
            if (a & (1u << (op_size * 8 - b))) r->eflags |= AKAV_EFLAGS_CF;
            result = (a << b) & mask;
            update_flags_zf_sf(r, result, op_size);
            if (b == 1) {
                if ((result & sign_bit(op_size)) != ((r->eflags & AKAV_EFLAGS_CF) ? sign_bit(op_size) : 0))
                    r->eflags |= AKAV_EFLAGS_OF;
            }
        }
        if (!write_operand(emu, &insn->operands[0], result)) goto fault;
        break;

    case AKAV_X86_MN_SHR:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        b &= 0x1F;
        if (b == 0) break;
        {
            uint32_t mask = size_mask(op_size);
            a &= mask;
            r->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_ZF | AKAV_EFLAGS_SF | AKAV_EFLAGS_OF);
            if (a & (1u << (b - 1))) r->eflags |= AKAV_EFLAGS_CF;
            result = a >> b;
            update_flags_zf_sf(r, result, op_size);
            if (b == 1 && (a & sign_bit(op_size))) r->eflags |= AKAV_EFLAGS_OF;
        }
        if (!write_operand(emu, &insn->operands[0], result)) goto fault;
        break;

    case AKAV_X86_MN_SAR:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        b &= 0x1F;
        if (b == 0) break;
        {
            uint32_t mask = size_mask(op_size);
            a &= mask;
            r->eflags &= ~(AKAV_EFLAGS_CF | AKAV_EFLAGS_ZF | AKAV_EFLAGS_SF | AKAV_EFLAGS_OF);
            if (a & (1u << (b - 1))) r->eflags |= AKAV_EFLAGS_CF;
            /* Arithmetic shift: sign-extend */
            if (a & sign_bit(op_size)) {
                result = (a >> b) | (mask << (op_size * 8 - b));
                result &= mask;
            } else {
                result = a >> b;
            }
            update_flags_zf_sf(r, result, op_size);
            /* OF = 0 for SAR */
        }
        if (!write_operand(emu, &insn->operands[0], result)) goto fault;
        break;

    case AKAV_X86_MN_ROL:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        b &= 0x1F;
        if (b == 0) break;
        {
            uint32_t bits = op_size * 8;
            uint32_t mask = size_mask(op_size);
            uint32_t count = b % bits;
            a &= mask;
            result = ((a << count) | (a >> (bits - count))) & mask;
            r->eflags &= ~AKAV_EFLAGS_CF;
            if (result & 1) r->eflags |= AKAV_EFLAGS_CF;
        }
        if (!write_operand(emu, &insn->operands[0], result)) goto fault;
        break;

    case AKAV_X86_MN_ROR:
        op_size = insn->operands[0].size;
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        b &= 0x1F;
        if (b == 0) break;
        {
            uint32_t bits = op_size * 8;
            uint32_t mask = size_mask(op_size);
            uint32_t count = b % bits;
            a &= mask;
            result = ((a >> count) | (a << (bits - count))) & mask;
            r->eflags &= ~AKAV_EFLAGS_CF;
            if (result & sign_bit(op_size)) r->eflags |= AKAV_EFLAGS_CF;
        }
        if (!write_operand(emu, &insn->operands[0], result)) goto fault;
        break;

    case AKAV_X86_MN_RCL:
    case AKAV_X86_MN_RCR:
        /* Simplified: handle as NOPs for now if count > 0 */
        /* These are very rare in unpacker stubs */
        break;

    /* ── Bit operations ───────────────────────────────────────── */

    case AKAV_X86_MN_BT:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        r->eflags &= ~AKAV_EFLAGS_CF;
        if (a & (1u << (b & 31))) r->eflags |= AKAV_EFLAGS_CF;
        break;

    case AKAV_X86_MN_BTS:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        r->eflags &= ~AKAV_EFLAGS_CF;
        if (a & (1u << (b & 31))) r->eflags |= AKAV_EFLAGS_CF;
        if (!write_operand(emu, &insn->operands[0], a | (1u << (b & 31)))) goto fault;
        break;

    case AKAV_X86_MN_BTR:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        r->eflags &= ~AKAV_EFLAGS_CF;
        if (a & (1u << (b & 31))) r->eflags |= AKAV_EFLAGS_CF;
        if (!write_operand(emu, &insn->operands[0], a & ~(1u << (b & 31)))) goto fault;
        break;

    case AKAV_X86_MN_BTC:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        r->eflags &= ~AKAV_EFLAGS_CF;
        if (a & (1u << (b & 31))) r->eflags |= AKAV_EFLAGS_CF;
        if (!write_operand(emu, &insn->operands[0], a ^ (1u << (b & 31)))) goto fault;
        break;

    case AKAV_X86_MN_BSF:
        if (!read_operand(emu, &insn->operands[1], &a)) goto fault;
        if (a == 0) {
            r->eflags |= AKAV_EFLAGS_ZF;
        } else {
            r->eflags &= ~AKAV_EFLAGS_ZF;
            uint32_t idx = 0;
            while (!(a & (1u << idx))) idx++;
            if (!write_operand(emu, &insn->operands[0], idx)) goto fault;
        }
        break;

    case AKAV_X86_MN_BSR:
        if (!read_operand(emu, &insn->operands[1], &a)) goto fault;
        if (a == 0) {
            r->eflags |= AKAV_EFLAGS_ZF;
        } else {
            r->eflags &= ~AKAV_EFLAGS_ZF;
            uint32_t idx = 31;
            while (!(a & (1u << idx))) idx--;
            if (!write_operand(emu, &insn->operands[0], idx)) goto fault;
        }
        break;

    case AKAV_X86_MN_CMPXCHG:
        if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
        if (!read_operand(emu, &insn->operands[1], &b)) goto fault;
        if (r->reg[0] == a) {
            r->eflags |= AKAV_EFLAGS_ZF;
            if (!write_operand(emu, &insn->operands[0], b)) goto fault;
        } else {
            r->eflags &= ~AKAV_EFLAGS_ZF;
            r->reg[0] = a;
        }
        break;

    /* ── Control flow ─────────────────────────────────────────── */

    case AKAV_X86_MN_JMP:
        if (insn->operands[0].type == AKAV_X86_OP_REL) {
            r->eip += (uint32_t)insn->operands[0].imm;
        } else {
            if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
            r->eip = a;
        }
        break;

    case AKAV_X86_MN_JCC: {
        uint8_t cc = extract_cc(insn);
        bool taken;
        if (cc == 0xFF) {
            /* JECXZ */
            taken = (r->reg[1] == 0);  /* ECX */
        } else {
            taken = eval_cc(cc, r->eflags);
        }
        if (taken) {
            if (insn->operands[0].type == AKAV_X86_OP_REL) {
                r->eip += (uint32_t)insn->operands[0].imm;
            }
        }
        break;
    }

    case AKAV_X86_MN_CALL:
        if (!emu_push32(emu, r->eip)) goto fault;
        if (insn->operands[0].type == AKAV_X86_OP_REL) {
            r->eip += (uint32_t)insn->operands[0].imm;
        } else {
            if (!read_operand(emu, &insn->operands[0], &a)) goto fault;
            r->eip = a;
        }
        break;

    case AKAV_X86_MN_RET:
        if (!emu_pop32(emu, &a)) goto fault;
        if (a == AKAV_EMU_STACK_SENTINEL)
            return emu_fault(emu, AKAV_EMU_HALT_RET, "returned to sentinel");
        r->eip = a;
        break;

    case AKAV_X86_MN_RETN:
        if (!emu_pop32(emu, &a)) goto fault;
        r->reg[4] += (uint32_t)insn->operands[0].imm;  /* add imm16 to ESP */
        if (a == AKAV_EMU_STACK_SENTINEL)
            return emu_fault(emu, AKAV_EMU_HALT_RET, "returned to sentinel");
        r->eip = a;
        break;

    case AKAV_X86_MN_LOOP:
        r->reg[1]--;  /* ECX-- */
        if (r->reg[1] != 0)
            r->eip += (uint32_t)insn->operands[0].imm;
        break;

    case AKAV_X86_MN_LOOPE:
        r->reg[1]--;
        if (r->reg[1] != 0 && (r->eflags & AKAV_EFLAGS_ZF))
            r->eip += (uint32_t)insn->operands[0].imm;
        break;

    case AKAV_X86_MN_LOOPNE:
        r->reg[1]--;
        if (r->reg[1] != 0 && !(r->eflags & AKAV_EFLAGS_ZF))
            r->eip += (uint32_t)insn->operands[0].imm;
        break;

    case AKAV_X86_MN_SETCC: {
        uint8_t cc = extract_cc(insn);
        uint8_t val = eval_cc(cc, r->eflags) ? 1 : 0;
        if (!write_operand(emu, &insn->operands[0], val)) goto fault;
        break;
    }

    case AKAV_X86_MN_CMOVCC: {
        uint8_t cc = extract_cc(insn);
        if (eval_cc(cc, r->eflags)) {
            if (!read_operand(emu, &insn->operands[1], &a)) goto fault;
            if (!write_operand(emu, &insn->operands[0], a)) goto fault;
        }
        break;
    }

    /* ── String operations ────────────────────────────────────── */

    case AKAV_X86_MN_MOVSB:
    case AKAV_X86_MN_MOVSW:
    case AKAV_X86_MN_MOVSD: {
        uint8_t sz = (insn->mnemonic == AKAV_X86_MN_MOVSB) ? 1 :
                     (insn->mnemonic == AKAV_X86_MN_MOVSW) ? 2 : 4;
        int32_t delta = (r->eflags & AKAV_EFLAGS_DF) ? -(int32_t)sz : (int32_t)sz;
        bool rep = (insn->prefixes & AKAV_X86_PFX_REP) != 0;
        uint32_t count = rep ? r->reg[1] : 1;
        while (count > 0) {
            if (sz == 1) {
                uint8_t v;
                if (!akav_x86_mem_read8(&emu->mem, r->reg[6], &v)) goto fault;
                if (!akav_x86_mem_write8(&emu->mem, r->reg[7], v)) goto fault;
            } else if (sz == 2) {
                uint16_t v;
                if (!akav_x86_mem_read16(&emu->mem, r->reg[6], &v)) goto fault;
                if (!akav_x86_mem_write16(&emu->mem, r->reg[7], v)) goto fault;
            } else {
                uint32_t v;
                if (!akav_x86_mem_read32(&emu->mem, r->reg[6], &v)) goto fault;
                if (!akav_x86_mem_write32(&emu->mem, r->reg[7], v)) goto fault;
            }
            notify_write(emu, r->reg[7], sz);
            r->reg[6] += (uint32_t)delta;  /* ESI */
            r->reg[7] += (uint32_t)delta;  /* EDI */
            count--;
            if (rep) {
                r->reg[1]--;
                emu->insn_count++;
                if (emu->insn_count >= emu->insn_limit)
                    return emu_fault(emu, AKAV_EMU_HALT_LIMIT, "instruction limit");
            }
        }
        break;
    }

    case AKAV_X86_MN_STOSB:
    case AKAV_X86_MN_STOSW:
    case AKAV_X86_MN_STOSD: {
        uint8_t sz = (insn->mnemonic == AKAV_X86_MN_STOSB) ? 1 :
                     (insn->mnemonic == AKAV_X86_MN_STOSW) ? 2 : 4;
        int32_t delta = (r->eflags & AKAV_EFLAGS_DF) ? -(int32_t)sz : (int32_t)sz;
        bool rep = (insn->prefixes & AKAV_X86_PFX_REP) != 0;
        uint32_t count = rep ? r->reg[1] : 1;
        while (count > 0) {
            if (sz == 1) {
                if (!akav_x86_mem_write8(&emu->mem, r->reg[7], (uint8_t)r->reg[0])) goto fault;
            } else if (sz == 2) {
                if (!akav_x86_mem_write16(&emu->mem, r->reg[7], (uint16_t)r->reg[0])) goto fault;
            } else {
                if (!akav_x86_mem_write32(&emu->mem, r->reg[7], r->reg[0])) goto fault;
            }
            notify_write(emu, r->reg[7], sz);
            r->reg[7] += (uint32_t)delta;
            count--;
            if (rep) {
                r->reg[1]--;
                emu->insn_count++;
                if (emu->insn_count >= emu->insn_limit)
                    return emu_fault(emu, AKAV_EMU_HALT_LIMIT, "instruction limit");
            }
        }
        break;
    }

    case AKAV_X86_MN_LODSB:
    case AKAV_X86_MN_LODSW:
    case AKAV_X86_MN_LODSD: {
        uint8_t sz = (insn->mnemonic == AKAV_X86_MN_LODSB) ? 1 :
                     (insn->mnemonic == AKAV_X86_MN_LODSW) ? 2 : 4;
        int32_t delta = (r->eflags & AKAV_EFLAGS_DF) ? -(int32_t)sz : (int32_t)sz;
        if (sz == 1) {
            uint8_t v;
            if (!akav_x86_mem_read8(&emu->mem, r->reg[6], &v)) goto fault;
            r->reg[0] = (r->reg[0] & 0xFFFFFF00u) | v;
        } else if (sz == 2) {
            uint16_t v;
            if (!akav_x86_mem_read16(&emu->mem, r->reg[6], &v)) goto fault;
            r->reg[0] = (r->reg[0] & 0xFFFF0000u) | v;
        } else {
            if (!akav_x86_mem_read32(&emu->mem, r->reg[6], &r->reg[0])) goto fault;
        }
        r->reg[6] += (uint32_t)delta;
        break;
    }

    case AKAV_X86_MN_SCASB:
    case AKAV_X86_MN_SCASW:
    case AKAV_X86_MN_SCASD: {
        uint8_t sz = (insn->mnemonic == AKAV_X86_MN_SCASB) ? 1 :
                     (insn->mnemonic == AKAV_X86_MN_SCASW) ? 2 : 4;
        int32_t delta = (r->eflags & AKAV_EFLAGS_DF) ? -(int32_t)sz : (int32_t)sz;
        bool rep = (insn->prefixes & AKAV_X86_PFX_REP) != 0;
        bool repne = (insn->prefixes & AKAV_X86_PFX_REPNE) != 0;
        uint32_t count = (rep || repne) ? r->reg[1] : 1;
        while (count > 0) {
            uint32_t mem_val = 0;
            if (sz == 1) { uint8_t v; if (!akav_x86_mem_read8(&emu->mem, r->reg[7], &v)) goto fault; mem_val = v; }
            else if (sz == 2) { uint16_t v; if (!akav_x86_mem_read16(&emu->mem, r->reg[7], &v)) goto fault; mem_val = v; }
            else { if (!akav_x86_mem_read32(&emu->mem, r->reg[7], &mem_val)) goto fault; }
            uint32_t ax_val = r->reg[0] & size_mask(sz);
            update_flags_sub(r, ax_val, mem_val, ax_val - mem_val, sz);
            r->reg[7] += (uint32_t)delta;
            count--;
            if (rep || repne) {
                r->reg[1]--;
                emu->insn_count++;
                if (emu->insn_count >= emu->insn_limit)
                    return emu_fault(emu, AKAV_EMU_HALT_LIMIT, "instruction limit");
                if (rep && !(r->eflags & AKAV_EFLAGS_ZF)) break;
                if (repne && (r->eflags & AKAV_EFLAGS_ZF)) break;
            }
        }
        break;
    }

    case AKAV_X86_MN_CMPSB:
    case AKAV_X86_MN_CMPSW:
    case AKAV_X86_MN_CMPSD: {
        uint8_t sz = (insn->mnemonic == AKAV_X86_MN_CMPSB) ? 1 :
                     (insn->mnemonic == AKAV_X86_MN_CMPSW) ? 2 : 4;
        int32_t delta = (r->eflags & AKAV_EFLAGS_DF) ? -(int32_t)sz : (int32_t)sz;
        bool rep = (insn->prefixes & AKAV_X86_PFX_REP) != 0;
        bool repne = (insn->prefixes & AKAV_X86_PFX_REPNE) != 0;
        uint32_t count = (rep || repne) ? r->reg[1] : 1;
        while (count > 0) {
            uint32_t src_val = 0, dst_val = 0;
            if (sz == 1) {
                uint8_t v1, v2;
                if (!akav_x86_mem_read8(&emu->mem, r->reg[6], &v1)) goto fault;
                if (!akav_x86_mem_read8(&emu->mem, r->reg[7], &v2)) goto fault;
                src_val = v1; dst_val = v2;
            } else if (sz == 2) {
                uint16_t v1, v2;
                if (!akav_x86_mem_read16(&emu->mem, r->reg[6], &v1)) goto fault;
                if (!akav_x86_mem_read16(&emu->mem, r->reg[7], &v2)) goto fault;
                src_val = v1; dst_val = v2;
            } else {
                if (!akav_x86_mem_read32(&emu->mem, r->reg[6], &src_val)) goto fault;
                if (!akav_x86_mem_read32(&emu->mem, r->reg[7], &dst_val)) goto fault;
            }
            update_flags_sub(r, src_val, dst_val, src_val - dst_val, sz);
            r->reg[6] += (uint32_t)delta;
            r->reg[7] += (uint32_t)delta;
            count--;
            if (rep || repne) {
                r->reg[1]--;
                emu->insn_count++;
                if (emu->insn_count >= emu->insn_limit)
                    return emu_fault(emu, AKAV_EMU_HALT_LIMIT, "instruction limit");
                if (rep && !(r->eflags & AKAV_EFLAGS_ZF)) break;
                if (repne && (r->eflags & AKAV_EFLAGS_ZF)) break;
            }
        }
        break;
    }

    /* ── Flags ────────────────────────────────────────────────── */

    case AKAV_X86_MN_CLC: r->eflags &= ~AKAV_EFLAGS_CF; break;
    case AKAV_X86_MN_STC: r->eflags |= AKAV_EFLAGS_CF; break;
    case AKAV_X86_MN_CMC: r->eflags ^= AKAV_EFLAGS_CF; break;
    case AKAV_X86_MN_CLD: r->eflags &= ~AKAV_EFLAGS_DF; break;
    case AKAV_X86_MN_STD: r->eflags |= AKAV_EFLAGS_DF; break;

    /* ── Special ──────────────────────────────────────────────── */

    case AKAV_X86_MN_NOP:
        break;

    case AKAV_X86_MN_INT3:
        return emu_fault(emu, AKAV_EMU_HALT_INT3, "int3");

    case AKAV_X86_MN_INT: {
        uint8_t int_num = (uint8_t)insn->operands[0].imm;
        if (emu->int_callback &&
            emu->int_callback(emu, int_num, emu->int_callback_data)) {
            break;  /* callback handled it, continue execution */
        }
        return emu_fault(emu, AKAV_EMU_HALT_INT, "int");
    }

    case AKAV_X86_MN_RDTSC:
        result64 = (uint64_t)emu->insn_count * 1000;
        r->reg[0] = (uint32_t)result64;         /* EAX */
        r->reg[2] = (uint32_t)(result64 >> 32);  /* EDX */
        break;

    case AKAV_X86_MN_CPUID:
        /* Return "GenuineIntel" for leaf 0, basic info for leaf 1 */
        if (r->reg[0] == 0) {
            r->reg[0] = 1;           /* max leaf */
            r->reg[3] = 0x756E6547;  /* EBX: "Genu" */
            r->reg[2] = 0x49656E69;  /* EDX: "ineI" */
            r->reg[1] = 0x6C65746E;  /* ECX: "ntel" */
        } else {
            r->reg[0] = 0x00000F00;  /* family 15 */
            r->reg[3] = 0;
            r->reg[1] = 0;
            r->reg[2] = 0;
        }
        break;

    case AKAV_X86_MN_INVALID:
        /* FPU instructions come through as INVALID but with valid=true */
        break;

    default:
        return emu_fault(emu, AKAV_EMU_HALT_INVALID, "unimplemented instruction");
    }

    return AKAV_EMU_OK;

fault:
    return emu_fault(emu, AKAV_EMU_HALT_FAULT, "memory access fault");
}

/* ── Step / Run ───────────────────────────────────────────────── */

int akav_x86_emu_step(akav_x86_emu_t* emu)
{
    if (!emu || emu->halted) return AKAV_EMU_HALT_INVALID;

    if (emu->regs.eip >= emu->mem.size)
        return emu_fault(emu, AKAV_EMU_HALT_FAULT, "EIP out of bounds");

    akav_x86_insn_t insn;
    memset(&insn, 0, sizeof(insn));

    size_t avail = emu->mem.size - emu->regs.eip;
    if (!akav_x86_decode(&insn, emu->mem.data + emu->regs.eip, avail)) {
        return emu_fault(emu, AKAV_EMU_HALT_INVALID, insn.error);
    }

    /* Advance EIP past instruction before execution */
    emu->regs.eip += insn.length;
    emu->insn_count++;

    int rc = execute(emu, &insn);
    if (rc != AKAV_EMU_OK) return rc;

    if (emu->insn_count >= emu->insn_limit)
        return emu_fault(emu, AKAV_EMU_HALT_LIMIT, "instruction limit");

    return AKAV_EMU_OK;
}

int akav_x86_emu_run(akav_x86_emu_t* emu)
{
    if (!emu) return AKAV_EMU_HALT_INVALID;

    while (!emu->halted) {
        int rc = akav_x86_emu_step(emu);
        if (rc != AKAV_EMU_OK) return rc;
    }

    return emu->halt_reason;
}
