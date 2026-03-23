#ifndef AKAV_X86_EMU_H
#define AKAV_X86_EMU_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────── */

#define AKAV_EMU_DEFAULT_MEM_SIZE  (4 * 1024 * 1024)  /* 4 MB */
#define AKAV_EMU_DEFAULT_INSN_LIMIT  2000000
#define AKAV_EMU_STACK_SENTINEL  0xDEADBEEFu

/* ── EFLAGS bits ───────────────────────────────────────────────── */

#define AKAV_EFLAGS_CF   (1u << 0)
#define AKAV_EFLAGS_PF   (1u << 2)
#define AKAV_EFLAGS_ZF   (1u << 6)
#define AKAV_EFLAGS_SF   (1u << 7)
#define AKAV_EFLAGS_DF   (1u << 10)
#define AKAV_EFLAGS_OF   (1u << 11)

/* ── Halt reasons ──────────────────────────────────────────────── */

#define AKAV_EMU_OK            0
#define AKAV_EMU_HALT_LIMIT    1
#define AKAV_EMU_HALT_INT3     2
#define AKAV_EMU_HALT_RET      3  /* RET to sentinel address */
#define AKAV_EMU_HALT_FAULT    4  /* memory access violation */
#define AKAV_EMU_HALT_INVALID  5  /* unimplemented instruction */
#define AKAV_EMU_HALT_INT      6  /* INT N (not INT3) */

/* ── Memory subsystem ──────────────────────────────────────────── */

typedef struct {
    uint8_t* data;
    size_t   size;
} akav_x86_mem_t;

/* ── Register file ─────────────────────────────────────────────── */

typedef struct {
    uint32_t reg[8];   /* indexed by AKAV_X86_REG_EAX..EDI (0-7) */
    uint32_t eip;
    uint32_t eflags;
} akav_x86_regs_t;

/* ── Callback types ────────────────────────────────────────────── */

typedef struct akav_x86_emu_t akav_x86_emu_t;

/**
 * INT instruction callback. Called when INT N is executed.
 * If callback returns true, execution continues (INT was handled).
 * If false, emulator halts with AKAV_EMU_HALT_INT.
 *   int_num: the interrupt number (e.g. 0x2E)
 */
typedef bool (*akav_emu_int_callback_t)(akav_x86_emu_t* emu,
                                         uint8_t int_num,
                                         void* user_data);

/**
 * Memory write callback. Called after every write to emulator memory.
 * Used for tracking writes for unpacker detection.
 */
typedef void (*akav_emu_write_callback_t)(akav_x86_emu_t* emu,
                                           uint32_t addr,
                                           uint32_t size,
                                           void* user_data);

/* ── Emulator context ──────────────────────────────────────────── */

struct akav_x86_emu_t {
    akav_x86_regs_t  regs;
    akav_x86_mem_t   mem;

    uint32_t  insn_count;
    uint32_t  insn_limit;

    bool      halted;
    uint8_t   halt_reason;
    char      error[128];

    /* Callbacks (P8-T3) */
    akav_emu_int_callback_t   int_callback;
    void*                     int_callback_data;
    akav_emu_write_callback_t write_callback;
    void*                     write_callback_data;
};

/* ── Public API ────────────────────────────────────────────────── */

/**
 * Initialize the emulator with a flat memory buffer.
 * Sets ESP near top of memory, pushes sentinel return address.
 */
bool akav_x86_emu_init(akav_x86_emu_t* emu, size_t mem_size);

/**
 * Free emulator resources.
 */
void akav_x86_emu_free(akav_x86_emu_t* emu);

/**
 * Load code/data into emulator memory at the given address.
 */
bool akav_x86_emu_load(akav_x86_emu_t* emu, uint32_t addr,
                        const uint8_t* data, size_t len);

/**
 * Run the emulator from current EIP until halt.
 * Returns the halt reason code.
 */
int akav_x86_emu_run(akav_x86_emu_t* emu);

/**
 * Execute a single instruction. Returns AKAV_EMU_OK or halt reason.
 */
int akav_x86_emu_step(akav_x86_emu_t* emu);

/* ── Memory access helpers (exposed for P8-T3 PE loader) ──────── */

bool akav_x86_mem_read8(const akav_x86_mem_t* mem, uint32_t addr, uint8_t* out);
bool akav_x86_mem_read16(const akav_x86_mem_t* mem, uint32_t addr, uint16_t* out);
bool akav_x86_mem_read32(const akav_x86_mem_t* mem, uint32_t addr, uint32_t* out);
bool akav_x86_mem_write8(akav_x86_mem_t* mem, uint32_t addr, uint8_t val);
bool akav_x86_mem_write16(akav_x86_mem_t* mem, uint32_t addr, uint16_t val);
bool akav_x86_mem_write32(akav_x86_mem_t* mem, uint32_t addr, uint32_t val);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_X86_EMU_H */
