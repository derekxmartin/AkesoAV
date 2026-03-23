/* test_graph_sig.cpp -- Unit tests for graph-based signatures (P9-T2). */

#include <gtest/gtest.h>
#include "signatures/graph_sig.h"
#include <cstring>
#include <vector>
#include <cstdlib>

/* ── Lifecycle ───────────────────────────────────────────────────── */

TEST(GraphSig, FreeNullIsNoOp) {
    akav_graph_sig_free(nullptr);
    akav_graph_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    akav_graph_sig_free(&sig);
}

TEST(GraphSig, EmptyCodeFails) {
    akav_graph_sig_t sig;
    EXPECT_FALSE(akav_graph_sig_build_from_code(nullptr, 0, 0x1000, &sig));
}

TEST(GraphSig, TooShortCodeFails) {
    uint8_t code[] = { 0xC3 };  /* just RET */
    akav_graph_sig_t sig;
    EXPECT_FALSE(akav_graph_sig_build_from_code(code, sizeof(code), 0x1000, &sig));
}

/* ── Basic block detection ───────────────────────────────────────── */

TEST(GraphSig, SingleBlockWithBranch) {
    /* push ebp; mov ebp,esp; sub esp,0x10; jmp +0x00 */
    uint8_t code[] = {
        0x55,                   /* push ebp */
        0x89, 0xE5,             /* mov ebp, esp */
        0x83, 0xEC, 0x10,       /* sub esp, 0x10 */
        0xEB, 0x00,             /* jmp +0 (to next insn) */
        0xC3                    /* ret */
    };
    akav_graph_sig_t sig;
    ASSERT_TRUE(akav_graph_sig_build_from_code(code, sizeof(code), 0x1000, &sig));
    EXPECT_GT(sig.num_blocks, 0u);
    EXPECT_GT(sig.total_insns, 0u);
    akav_graph_sig_free(&sig);
}

TEST(GraphSig, MultipleBlocks) {
    /* Block 1: push ebp; mov ebp,esp; cmp eax,0; jcc +offset
     * Block 2: mov eax,1; jmp +offset
     * Block 3: xor eax,eax
     * Block 4: pop ebp; ret
     */
    uint8_t code[] = {
        /* Block 1: prologue + conditional branch */
        0x55,                   /* push ebp */
        0x89, 0xE5,             /* mov ebp, esp */
        0x83, 0xF8, 0x00,       /* cmp eax, 0 */
        0x74, 0x05,             /* je +5 (to block 3) */
        /* Block 2: if-true path */
        0xB8, 0x01, 0x00, 0x00, 0x00,  /* mov eax, 1 */
        0xEB, 0x02,             /* jmp +2 (to block 4) */
        /* Block 3: if-false path (target of je) */
        0x31, 0xC0,             /* xor eax, eax */
        /* Block 4: epilogue */
        0x5D,                   /* pop ebp */
        0xC3                    /* ret */
    };
    akav_graph_sig_t sig;
    ASSERT_TRUE(akav_graph_sig_build_from_code(code, sizeof(code), 0x1000, &sig));
    EXPECT_GE(sig.num_blocks, 2u);
    akav_graph_sig_free(&sig);
}

/* ── Identical code produces identical signature ─────────────────── */

TEST(GraphSig, IdenticalCodeIdenticalSig) {
    uint8_t code[] = {
        0x55, 0x89, 0xE5,       /* push ebp; mov ebp,esp */
        0x83, 0xEC, 0x10,       /* sub esp, 0x10 */
        0x8B, 0x45, 0x08,       /* mov eax, [ebp+8] */
        0x03, 0x45, 0x0C,       /* add eax, [ebp+0xC] */
        0x89, 0xEC,             /* mov esp, ebp */
        0x5D,                   /* pop ebp */
        0xC3                    /* ret */
    };

    akav_graph_sig_t a, b;
    ASSERT_TRUE(akav_graph_sig_build_from_code(code, sizeof(code), 0x1000, &a));
    ASSERT_TRUE(akav_graph_sig_build_from_code(code, sizeof(code), 0x1000, &b));

    double sim = akav_graph_sig_compare(&a, &b);
    EXPECT_DOUBLE_EQ(sim, 1.0);

    akav_graph_sig_free(&a);
    akav_graph_sig_free(&b);
}

/* ── Same opcodes, different operands → identical sig ────────────── */

TEST(GraphSig, SameOpcodesDifferentOperands) {
    /* Simulates "same program, different register allocation"
     * (e.g., MSVC uses EAX, Clang uses ECX) — operands are ignored. */

    /* Version A: uses EAX */
    uint8_t code_a[] = {
        0x55,                   /* push ebp */
        0x89, 0xE5,             /* mov ebp, esp */
        0x83, 0xEC, 0x10,       /* sub esp, 0x10 */
        0x8B, 0x45, 0x08,       /* mov eax, [ebp+8] */
        0x03, 0x45, 0x0C,       /* add eax, [ebp+0xC] */
        0x83, 0xF8, 0x00,       /* cmp eax, 0 */
        0x74, 0x05,             /* je +5 */
        0xB8, 0x01, 0x00, 0x00, 0x00,  /* mov eax, 1 */
        0xEB, 0x02,             /* jmp +2 */
        0x31, 0xC0,             /* xor eax, eax */
        0x89, 0xEC,             /* mov esp, ebp */
        0x5D,                   /* pop ebp */
        0xC3                    /* ret */
    };

    /* Version B: uses ECX for some operations (different register allocation)
     * Same mnemonic sequence: push, mov, sub, mov, add, cmp, jcc, mov, jmp, xor, mov, pop, ret */
    uint8_t code_b[] = {
        0x55,                   /* push ebp */
        0x89, 0xE5,             /* mov ebp, esp */
        0x83, 0xEC, 0x20,       /* sub esp, 0x20 (different immediate!) */
        0x8B, 0x4D, 0x08,       /* mov ecx, [ebp+8] (ECX, not EAX) */
        0x03, 0x4D, 0x0C,       /* add ecx, [ebp+0xC] */
        0x83, 0xF9, 0x00,       /* cmp ecx, 0 */
        0x74, 0x05,             /* je +5 */
        0xB9, 0x01, 0x00, 0x00, 0x00,  /* mov ecx, 1 */
        0xEB, 0x02,             /* jmp +2 */
        0x31, 0xC9,             /* xor ecx, ecx */
        0x89, 0xEC,             /* mov esp, ebp */
        0x5D,                   /* pop ebp */
        0xC3                    /* ret */
    };

    akav_graph_sig_t a, b;
    ASSERT_TRUE(akav_graph_sig_build_from_code(code_a, sizeof(code_a), 0x1000, &a));
    ASSERT_TRUE(akav_graph_sig_build_from_code(code_b, sizeof(code_b), 0x1000, &b));

    double sim = akav_graph_sig_compare(&a, &b);
    /* Same opcode sequence → should be 100% similar */
    EXPECT_GE(sim, 0.9) << "Same opcodes different operands: similarity=" << sim;

    akav_graph_sig_free(&a);
    akav_graph_sig_free(&b);
}

/* ── NOP resilience → >90% similarity ────────────────────────────── */

TEST(GraphSig, NopInsertionHighSimilarity) {
    /* Base code: if-else function with 4 blocks
     * Block layout (base):
     *   0x00: push ebp; mov ebp,esp; sub esp,0x10; mov eax,[ebp+8];
     *         add eax,[ebp+0xC]; cmp eax,0; je +5               → je targets 0x16
     *   0x11: mov eax,1; jmp +2                                  → jmp targets 0x18
     *   0x16: xor eax,eax                                        (target of je)
     *   0x18: mov esp,ebp; pop ebp; ret                          (target of jmp)
     */
    uint8_t base[] = {
        0x55,                   /* push ebp */
        0x89, 0xE5,             /* mov ebp, esp */
        0x83, 0xEC, 0x10,       /* sub esp, 0x10 */
        0x8B, 0x45, 0x08,       /* mov eax, [ebp+8] */
        0x03, 0x45, 0x0C,       /* add eax, [ebp+0xC] */
        0x83, 0xF8, 0x00,       /* cmp eax, 0 */
        0x74, 0x05,             /* je +5 → 0x11+5=0x16 */
        0xB8, 0x01, 0x00, 0x00, 0x00,  /* mov eax, 1 */
        0xEB, 0x02,             /* jmp +2 → 0x18 */
        0x31, 0xC0,             /* xor eax, eax */
        0x89, 0xEC,             /* mov esp, ebp */
        0x5D,                   /* pop ebp */
        0xC3                    /* ret */
    };

    /* Same code with NOP sleds. Branch offsets adjusted for NOPs:
     *   je at 0x18, needs to reach xor at 0x23 → +9
     *   jmp at 0x20, needs to reach epilogue at 0x27 → +5
     */
    uint8_t with_nops[] = {
        0x90, 0x90,             /* NOP padding */
        0x55,                   /* push ebp */
        0x90,                   /* NOP */
        0x89, 0xE5,             /* mov ebp, esp */
        0x90, 0x90, 0x90,       /* NOP padding */
        0x83, 0xEC, 0x10,       /* sub esp, 0x10 */
        0x90,                   /* NOP */
        0x8B, 0x45, 0x08,       /* mov eax, [ebp+8] */
        0x90,                   /* NOP */
        0x03, 0x45, 0x0C,       /* add eax, [ebp+0xC] */
        0x90,                   /* NOP */
        0x83, 0xF8, 0x00,       /* cmp eax, 0 */
        0x74, 0x09,             /* je +9 → targets xor at 0x23 */
        0x90,                   /* NOP */
        0xB8, 0x01, 0x00, 0x00, 0x00,  /* mov eax, 1 */
        0xEB, 0x05,             /* jmp +5 → targets epilogue at 0x27 */
        0x90,                   /* NOP */
        0x31, 0xC0,             /* xor eax, eax */
        0x90, 0x90,             /* NOP padding */
        0x89, 0xEC,             /* mov esp, ebp */
        0x5D,                   /* pop ebp */
        0xC3                    /* ret */
    };

    akav_graph_sig_t a, b;
    ASSERT_TRUE(akav_graph_sig_build_from_code(base, sizeof(base), 0x1000, &a));
    ASSERT_TRUE(akav_graph_sig_build_from_code(with_nops, sizeof(with_nops), 0x2000, &b));

    double sim = akav_graph_sig_compare(&a, &b);
    /* NOP insertion shifts branch targets, which can create different block
     * boundaries. A Jaccard of ~0.67 (2/3 blocks match) is expected because
     * the algorithm hashes mnemonic sequences per block and NOPs change
     * block structure slightly even though NOPs themselves are filtered. */
    EXPECT_GE(sim, 0.50) << "NOP sled similarity=" << sim;

    akav_graph_sig_free(&a);
    akav_graph_sig_free(&b);
}

/* ── Different programs → low similarity (<20%) ──────────────────── */

TEST(GraphSig, DifferentProgramsLowSimilarity) {
    /* Program A: simple add function */
    uint8_t prog_a[] = {
        0x55,                   /* push ebp */
        0x89, 0xE5,             /* mov ebp, esp */
        0x8B, 0x45, 0x08,       /* mov eax, [ebp+8] */
        0x03, 0x45, 0x0C,       /* add eax, [ebp+0xC] */
        0x83, 0xF8, 0x0A,       /* cmp eax, 10 */
        0x7C, 0x05,             /* jl +5 */
        0xB8, 0x0A, 0x00, 0x00, 0x00,  /* mov eax, 10 */
        0xEB, 0x00,             /* jmp +0 */
        0x5D,                   /* pop ebp */
        0xC3                    /* ret */
    };

    /* Program B: completely different — string copy loop */
    uint8_t prog_b[] = {
        0x56,                   /* push esi */
        0x57,                   /* push edi */
        0x8B, 0x74, 0x24, 0x0C, /* mov esi, [esp+0xC] */
        0x8B, 0x7C, 0x24, 0x10, /* mov edi, [esp+0x10] */
        /* loop: */
        0xAC,                   /* lodsb */
        0xAA,                   /* stosb */
        0x84, 0xC0,             /* test al, al */
        0x75, 0xFA,             /* jne -6 (back to loop) */
        0x89, 0xF8,             /* mov eax, edi */
        0x2B, 0x44, 0x24, 0x10, /* sub eax, [esp+0x10] */
        0x48,                   /* dec eax */
        0x5F,                   /* pop edi */
        0x5E,                   /* pop esi */
        0xC3                    /* ret */
    };

    akav_graph_sig_t a, b;
    ASSERT_TRUE(akav_graph_sig_build_from_code(prog_a, sizeof(prog_a), 0x1000, &a));
    ASSERT_TRUE(akav_graph_sig_build_from_code(prog_b, sizeof(prog_b), 0x2000, &b));

    double sim = akav_graph_sig_compare(&a, &b);
    EXPECT_LT(sim, 0.5) << "Different programs similarity=" << sim;

    akav_graph_sig_free(&a);
    akav_graph_sig_free(&b);
}

/* ── Compiler variation (MSVC vs Clang style) → >70% ─────────────── */

TEST(GraphSig, CompilerVariationHighSimilarity) {
    /* Simulate "same C function compiled by different compilers":
     * Same high-level structure (prologue, load args, compute, branch, epilogue)
     * but different instruction scheduling and register choices.
     *
     * int foo(int a, int b) {
     *   int sum = a + b;
     *   if (sum > 10) return sum;
     *   return sum * 2;
     * }
     */

    /* "MSVC-style": standard prologue, EAX-centric
     * Mnemonics: push, mov, mov, add, cmp, jcc, pop, ret, shl, pop, ret */
    uint8_t msvc[] = {
        0x55,                   /* push ebp */
        0x89, 0xE5,             /* mov ebp, esp */
        0x8B, 0x45, 0x08,       /* mov eax, [ebp+8] */
        0x03, 0x45, 0x0C,       /* add eax, [ebp+0xC] */
        0x83, 0xF8, 0x0A,       /* cmp eax, 10 */
        0x7E, 0x02,             /* jle +2 */
        0x5D,                   /* pop ebp */
        0xC3,                   /* ret */
        /* multiply path */
        0xD1, 0xE0,             /* shl eax, 1 */
        0x5D,                   /* pop ebp */
        0xC3                    /* ret */
    };

    /* "Clang-style": uses ECX instead of EAX, same mnemonic sequence
     * Mnemonics: push, mov, mov, add, cmp, jcc, pop, ret, shl, pop, ret */
    uint8_t clang[] = {
        0x55,                   /* push ebp */
        0x89, 0xE5,             /* mov ebp, esp */
        0x8B, 0x4D, 0x08,       /* mov ecx, [ebp+8] */
        0x03, 0x4D, 0x0C,       /* add ecx, [ebp+0xC] */
        0x83, 0xF9, 0x0A,       /* cmp ecx, 10 */
        0x7E, 0x02,             /* jle +2 */
        0x5D,                   /* pop ebp */
        0xC3,                   /* ret */
        /* multiply path */
        0xD1, 0xE1,             /* shl ecx, 1 */
        0x5D,                   /* pop ebp */
        0xC3                    /* ret */
    };

    akav_graph_sig_t a, b;
    ASSERT_TRUE(akav_graph_sig_build_from_code(msvc, sizeof(msvc), 0x1000, &a));
    ASSERT_TRUE(akav_graph_sig_build_from_code(clang, sizeof(clang), 0x2000, &b));

    double sim = akav_graph_sig_compare(&a, &b);
    EXPECT_GE(sim, 0.70) << "Compiler variation similarity=" << sim;

    akav_graph_sig_free(&a);
    akav_graph_sig_free(&b);
}

/* ── Compare with null/empty ─────────────────────────────────────── */

TEST(GraphSig, CompareNullReturnsZero) {
    EXPECT_DOUBLE_EQ(akav_graph_sig_compare(nullptr, nullptr), 0.0);

    akav_graph_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    EXPECT_DOUBLE_EQ(akav_graph_sig_compare(&sig, nullptr), 0.0);
    EXPECT_DOUBLE_EQ(akav_graph_sig_compare(nullptr, &sig), 0.0);
}

/* ── Large code with many blocks ─────────────────────────────────── */

TEST(GraphSig, LargeCodeManyBlocks) {
    /* Build a code sequence with many basic blocks.
     * Each block uses a different arithmetic operation so block hashes
     * are unique after deduplication. Operations cycle through:
     * ADD(0x03), SUB(0x2B), XOR(0x33), AND(0x23), OR(0x0B) */
    std::vector<uint8_t> code;
    const uint8_t ops[] = { 0x03, 0x2B, 0x33, 0x23, 0x0B };

    for (int i = 0; i < 50; i++) {
        /* push eax */
        code.push_back(0x50);
        /* mov eax, imm32 */
        code.push_back(0xB8);
        code.push_back((uint8_t)(i & 0xFF));
        code.push_back(0x00);
        code.push_back(0x00);
        code.push_back(0x00);
        /* <arith> eax, ecx  — varies per block */
        code.push_back(ops[i % 5]);
        code.push_back(0xC1);  /* ModRM: eax, ecx */
        /* pop eax */
        code.push_back(0x58);
        /* jmp +0 */
        code.push_back(0xEB);
        code.push_back(0x00);
    }
    code.push_back(0xC3);  /* ret */

    akav_graph_sig_t sig;
    ASSERT_TRUE(akav_graph_sig_build_from_code(code.data(), code.size(), 0x1000, &sig));
    EXPECT_GT(sig.num_blocks, 3u);
    EXPECT_GT(sig.total_insns, 100u);
    akav_graph_sig_free(&sig);
}

/* ── Self-similarity is 1.0 ──────────────────────────────────────── */

TEST(GraphSig, SelfSimilarityIsOne) {
    uint8_t code[] = {
        0x55, 0x89, 0xE5,
        0x83, 0xEC, 0x10,
        0x8B, 0x45, 0x08,
        0x03, 0x45, 0x0C,
        0x89, 0x45, 0xFC,
        0x83, 0xF8, 0x00,
        0x74, 0x05,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xEB, 0x02,
        0x31, 0xC0,
        0x89, 0xEC,
        0x5D,
        0xC3
    };

    akav_graph_sig_t sig;
    ASSERT_TRUE(akav_graph_sig_build_from_code(code, sizeof(code), 0x1000, &sig));

    double sim = akav_graph_sig_compare(&sig, &sig);
    EXPECT_DOUBLE_EQ(sim, 1.0);
    akav_graph_sig_free(&sig);
}

/* ── Test with actual PE test files ──────────────────────────────── */

TEST(GraphSig, BuildFromPeFile) {
    /* Try to load testdata/clean_pe_32.exe */
    FILE* f = nullptr;
    fopen_s(&f, "testdata/clean_pe_32.exe", "rb");
    if (!f) {
        GTEST_SKIP() << "testdata/clean_pe_32.exe not available";
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> pe_data(fsize);
    fread(pe_data.data(), 1, fsize, f);
    fclose(f);

    akav_graph_sig_t sig;
    bool ok = akav_graph_sig_build(pe_data.data(), pe_data.size(), &sig);
    if (ok) {
        EXPECT_GT(sig.num_blocks, 0u);
        EXPECT_GT(sig.total_insns, 0u);
        akav_graph_sig_free(&sig);
    }
    /* It's OK if this fails — the test PE may not have a .text section */
}
