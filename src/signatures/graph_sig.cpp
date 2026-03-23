/* graph_sig.cpp -- Graph-based (CFG hash) signatures (P9-T2).
 *
 * Decodes x86 instructions from PE .text, builds basic blocks by
 * identifying branch boundaries, hashes the mnemonic sequence per
 * block (ignoring operands and NOPs), and produces a sorted set
 * of block hashes for Jaccard similarity comparison.
 */

#include "signatures/graph_sig.h"
#include "emulator/x86_decode.h"
#include "parsers/pe.h"
#include <stdlib.h>
#include <string.h>

/* ── FNV-1a hash for block mnemonic sequences ────────────────────── */

static uint32_t fnv1a_init(void) { return 0x811C9DC5u; }

static uint32_t fnv1a_update(uint32_t h, uint32_t val)
{
    h ^= val & 0xFF;   h *= 0x01000193u;
    h ^= (val >> 8);   h *= 0x01000193u;
    h ^= (val >> 16);  h *= 0x01000193u;
    h ^= (val >> 24);  h *= 0x01000193u;
    return h;
}

/* ── Helpers ──────────────────────────────────────────────────────── */

static bool is_branch(uint16_t mnemonic)
{
    return mnemonic == AKAV_X86_MN_JMP
        || mnemonic == AKAV_X86_MN_JCC
        || mnemonic == AKAV_X86_MN_CALL
        || mnemonic == AKAV_X86_MN_RET
        || mnemonic == AKAV_X86_MN_RETN
        || mnemonic == AKAV_X86_MN_LOOP
        || mnemonic == AKAV_X86_MN_LOOPE
        || mnemonic == AKAV_X86_MN_LOOPNE
        || mnemonic == AKAV_X86_MN_INT
        || mnemonic == AKAV_X86_MN_INT3;
}

static bool is_nop(uint16_t mnemonic)
{
    return mnemonic == AKAV_X86_MN_NOP;
}

/* Compare for qsort */
static int uint32_cmp(const void* a, const void* b)
{
    uint32_t va = *(const uint32_t*)a;
    uint32_t vb = *(const uint32_t*)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

/* Deduplicate a sorted array in-place. Returns new count. */
static uint32_t dedup_sorted(uint32_t* arr, uint32_t count)
{
    if (count <= 1) return count;
    uint32_t w = 1;
    for (uint32_t r = 1; r < count; r++) {
        if (arr[r] != arr[w - 1])
            arr[w++] = arr[r];
    }
    return w;
}

/* ── Core: build signature from raw code ─────────────────────────── */

bool akav_graph_sig_build_from_code(const uint8_t* code, size_t code_len,
                                     uint32_t base_va,
                                     akav_graph_sig_t* sig)
{
    if (!code || code_len == 0 || !sig)
        return false;

    memset(sig, 0, sizeof(*sig));

    /* ── Pass 1: Decode all instructions and collect branch targets ── */

    /* Track decoded instructions: offset + mnemonic */
    typedef struct { uint32_t offset; uint16_t mnemonic; uint8_t length; } insn_info_t;

    uint32_t max_insns = (uint32_t)code_len;
    if (max_insns > AKAV_GRAPH_MAX_INSNS)
        max_insns = AKAV_GRAPH_MAX_INSNS;

    insn_info_t* insns = (insn_info_t*)malloc(max_insns * sizeof(insn_info_t));
    if (!insns) return false;

    /* Branch target set (offsets relative to code start) */
    uint32_t* targets = (uint32_t*)calloc(max_insns, sizeof(uint32_t));
    if (!targets) { free(insns); return false; }
    uint32_t num_targets = 0;

    uint32_t num_insns = 0;
    size_t offset = 0;

    while (offset < code_len && num_insns < max_insns) {
        akav_x86_insn_t decoded;
        bool ok = akav_x86_decode(&decoded, code + offset, code_len - offset);

        if (!ok || decoded.length == 0) {
            offset++;
            continue;
        }

        insns[num_insns].offset = (uint32_t)offset;
        insns[num_insns].mnemonic = decoded.mnemonic;
        insns[num_insns].length = decoded.length;
        num_insns++;

        /* Collect branch targets for block splitting */
        if (is_branch(decoded.mnemonic)) {
            /* Check for relative operand (JMP/JCC/CALL rel) */
            for (int i = 0; i < decoded.num_operands; i++) {
                if (decoded.operands[i].type == AKAV_X86_OP_REL) {
                    int64_t target_va = (int64_t)base_va + (int64_t)offset
                                       + decoded.length + decoded.operands[i].imm;
                    int64_t target_off = target_va - (int64_t)base_va;
                    if (target_off >= 0 && (size_t)target_off < code_len
                        && num_targets < max_insns) {
                        targets[num_targets++] = (uint32_t)target_off;
                    }
                }
            }
        }

        offset += decoded.length;
    }

    sig->total_insns = num_insns;

    if (num_insns < 2) {
        free(insns);
        free(targets);
        return false;
    }

    /* Sort and dedup branch targets */
    if (num_targets > 0) {
        qsort(targets, num_targets, sizeof(uint32_t), uint32_cmp);
        num_targets = dedup_sorted(targets, num_targets);
    }

    /* ── Pass 2: Split into basic blocks and hash ──────────────────── */

    /* A basic block boundary is:
     *   1. The instruction at a branch target offset
     *   2. The instruction after a branch instruction
     *   3. The first instruction
     */

    uint32_t* block_hashes = (uint32_t*)malloc(AKAV_GRAPH_MAX_BLOCKS * sizeof(uint32_t));
    if (!block_hashes) { free(insns); free(targets); return false; }
    uint32_t num_blocks = 0;

    uint32_t hash = fnv1a_init();
    int block_insn_count = 0;  /* non-NOP instructions in current block */

    for (uint32_t i = 0; i < num_insns && num_blocks < AKAV_GRAPH_MAX_BLOCKS; i++) {
        /* Check if this instruction starts a new block (branch target) */
        if (i > 0) {
            bool is_target = false;
            /* Binary search in sorted targets */
            uint32_t lo = 0, hi = num_targets;
            uint32_t needle = insns[i].offset;
            while (lo < hi) {
                uint32_t mid = lo + (hi - lo) / 2;
                if (targets[mid] < needle) lo = mid + 1;
                else if (targets[mid] > needle) hi = mid;
                else { is_target = true; break; }
            }

            if (is_target) {
                /* Finalize previous block */
                if (block_insn_count >= AKAV_GRAPH_MIN_BLOCK_INSNS) {
                    block_hashes[num_blocks++] = hash;
                }
                hash = fnv1a_init();
                block_insn_count = 0;
            }
        }

        /* Hash mnemonic (skip NOPs) */
        if (!is_nop(insns[i].mnemonic)) {
            hash = fnv1a_update(hash, insns[i].mnemonic);
            block_insn_count++;
        }

        /* If this is a branch, end the block after this instruction */
        if (is_branch(insns[i].mnemonic)) {
            if (block_insn_count >= AKAV_GRAPH_MIN_BLOCK_INSNS) {
                block_hashes[num_blocks++] = hash;
            }
            hash = fnv1a_init();
            block_insn_count = 0;
        }
    }

    /* Finalize last block */
    if (block_insn_count >= AKAV_GRAPH_MIN_BLOCK_INSNS && num_blocks < AKAV_GRAPH_MAX_BLOCKS) {
        block_hashes[num_blocks++] = hash;
    }

    sig->total_blocks = num_blocks;

    free(insns);
    free(targets);

    if (num_blocks == 0) {
        free(block_hashes);
        return false;
    }

    /* Sort and deduplicate block hashes */
    qsort(block_hashes, num_blocks, sizeof(uint32_t), uint32_cmp);
    num_blocks = dedup_sorted(block_hashes, num_blocks);

    /* Shrink allocation */
    uint32_t* final_hashes = (uint32_t*)realloc(block_hashes,
                                                  num_blocks * sizeof(uint32_t));
    sig->block_hashes = final_hashes ? final_hashes : block_hashes;
    sig->num_blocks = num_blocks;

    return true;
}

/* ── Build from PE ───────────────────────────────────────────────── */

bool akav_graph_sig_build(const uint8_t* pe_data, size_t pe_len,
                           akav_graph_sig_t* sig)
{
    if (!pe_data || pe_len == 0 || !sig)
        return false;

    memset(sig, 0, sizeof(*sig));

    /* Parse PE */
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    if (!akav_pe_parse(&pe, pe_data, pe_len)) {
        akav_pe_free(&pe);
        return false;
    }

    /* Find .text section (or first executable section) */
    const akav_pe_section_t* text_sec = akav_pe_find_section(&pe, ".text");
    if (!text_sec) {
        /* Fall back to first section with IMAGE_SCN_MEM_EXECUTE */
        for (uint32_t i = 0; i < pe.num_sections; i++) {
            if (pe.sections[i].characteristics & 0x20000000u) {  /* IMAGE_SCN_MEM_EXECUTE */
                text_sec = &pe.sections[i];
                break;
            }
        }
    }

    if (!text_sec || text_sec->raw_data_size == 0
        || text_sec->raw_data_offset >= pe_len) {
        akav_pe_free(&pe);
        return false;
    }

    size_t code_end = text_sec->raw_data_offset + text_sec->raw_data_size;
    if (code_end > pe_len)
        code_end = pe_len;

    const uint8_t* code = pe_data + text_sec->raw_data_offset;
    size_t code_len = code_end - text_sec->raw_data_offset;
    uint32_t base_va = (uint32_t)pe.image_base + text_sec->virtual_address;

    bool ok = akav_graph_sig_build_from_code(code, code_len, base_va, sig);
    akav_pe_free(&pe);
    return ok;
}

/* ── Jaccard similarity ──────────────────────────────────────────── */

double akav_graph_sig_compare(const akav_graph_sig_t* a,
                               const akav_graph_sig_t* b)
{
    if (!a || !b || !a->block_hashes || !b->block_hashes)
        return 0.0;
    if (a->num_blocks == 0 || b->num_blocks == 0)
        return 0.0;

    /* Merge-based intersection/union count on sorted arrays */
    uint32_t i = 0, j = 0;
    uint32_t intersection = 0;
    uint32_t union_count = 0;

    while (i < a->num_blocks && j < b->num_blocks) {
        if (a->block_hashes[i] == b->block_hashes[j]) {
            intersection++;
            union_count++;
            i++;
            j++;
        } else if (a->block_hashes[i] < b->block_hashes[j]) {
            union_count++;
            i++;
        } else {
            union_count++;
            j++;
        }
    }

    /* Remaining elements */
    union_count += (a->num_blocks - i) + (b->num_blocks - j);

    if (union_count == 0) return 0.0;
    return (double)intersection / (double)union_count;
}

/* ── Free ─────────────────────────────────────────────────────────── */

void akav_graph_sig_free(akav_graph_sig_t* sig)
{
    if (!sig) return;
    free(sig->block_hashes);
    memset(sig, 0, sizeof(*sig));
}
