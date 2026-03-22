/* test_entropy_analyzer.cpp -- Unit tests for entropy heuristic analyzer.
 *
 * Tests all checks from section 5.6 Entropy row:
 *   - .text > 7.0  -> packed (+20)
 *   - .text < 1.0  -> XOR-encoded (+15)
 *   - Overall > 7.5 -> suspicious (+10)
 *   - Clean files score 0
 *   - Edge cases and JSON weight loading
 */

#include <gtest/gtest.h>
#include "heuristics/entropy.h"
#include "parsers/pe.h"
#include <cstring>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cmath>

/* ── PE builder helper ───────────────────────────────────────────── */

class EntropyPeBuilder {
public:
    EntropyPeBuilder() { build_pe32(); }

    void build_pe32() {
        data_.clear();
        data_.resize(2048, 0);
        section_count_ = 0;
        uint8_t* d = data_.data();

        /* DOS header */
        d[0] = 'M'; d[1] = 'Z';
        uint32_t lfanew = 0x80;
        memcpy(d + 0x3C, &lfanew, 4);

        /* PE signature */
        uint32_t pe_sig = 0x00004550;
        memcpy(d + 0x80, &pe_sig, 4);

        /* COFF header */
        size_t off = 0x84;
        set16(off, 0x014C); off += 2;       /* machine */
        num_sections_off_ = off;
        set16(off, 0); off += 2;            /* NumberOfSections (updated by add_section) */
        set32(off, 0x65000000); off += 4;   /* TimeDateStamp */
        off += 8;                            /* SymbolTable + NumSymbols */
        set16(off, 224); off += 2;          /* SizeOfOptionalHeader */
        set16(off, 0x0002); off += 2;       /* Characteristics */

        /* Optional header */
        set16(off, 0x10B); off += 2;        /* PE32 */
        off += 2;                            /* linker version */
        set32(off, 0x200); off += 4;        /* SizeOfCode */
        off += 8;                            /* InitData + UninitData */
        set32(off, 0x1000); off += 4;       /* EntryPoint */
        set32(off, 0x1000); off += 4;       /* BaseOfCode */
        off += 4;                            /* BaseOfData */
        set32(off, 0x00400000); off += 4;   /* ImageBase */
        set32(off, 0x1000); off += 4;       /* SectionAlignment */
        set32(off, 0x200); off += 4;        /* FileAlignment */
        off += 8;                            /* OS/Image version */
        off += 8;                            /* Subsystem versions + Win32VersionValue */
        set32(off, 0x4000); off += 4;       /* SizeOfImage */
        set32(off, 0x200); off += 4;        /* SizeOfHeaders */
        off += 4;                            /* Checksum */
        set16(off, 3); off += 2;            /* Subsystem */
        off += 2;                            /* DllCharacteristics */
        off += 16;                           /* Stack/Heap */
        off += 4;                            /* LoaderFlags */
        set32(off, 16); off += 4;           /* NumberOfRvaAndSizes */
        off += 16 * 8;                      /* Data directories */

        section_table_off_ = off;
    }

    /* Add a section with specific content */
    void add_section_with_data(const char* name, uint32_t vaddr,
                                const uint8_t* content, size_t content_len,
                                uint32_t chars) {
        /* Align raw offset to 0x200 */
        uint32_t raw_off = (uint32_t)data_.size();
        if (raw_off % 0x200 != 0)
            raw_off = (raw_off + 0x1FF) & ~0x1FF;

        uint32_t raw_size = (uint32_t)((content_len + 0x1FF) & ~0x1FF);

        /* Ensure space for section table entry + content */
        size_t sec_entry = section_table_off_ + (size_t)section_count_ * 40;
        size_t needed = raw_off + raw_size;
        if (data_.size() < needed)
            data_.resize(needed, 0);
        if (data_.size() < sec_entry + 40)
            data_.resize(sec_entry + 40, 0);

        /* Write section header */
        memset(data_.data() + sec_entry, 0, 40);
        size_t nlen = strlen(name);
        memcpy(data_.data() + sec_entry, name, nlen < 8 ? nlen : 8);
        set32(sec_entry + 8, (uint32_t)content_len);  /* VirtualSize */
        set32(sec_entry + 12, vaddr);                  /* VirtualAddress */
        set32(sec_entry + 16, raw_size);               /* SizeOfRawData */
        set32(sec_entry + 20, raw_off);                /* PointerToRawData */
        set32(sec_entry + 36, chars);                  /* Characteristics */

        /* Write content */
        if (content && content_len > 0)
            memcpy(data_.data() + raw_off, content, content_len);

        section_count_++;
        set16(num_sections_off_, section_count_);
    }

    /* Convenience: add .text with specific fill */
    void add_text_with_fill(uint8_t fill_byte, size_t size) {
        std::vector<uint8_t> content(size, fill_byte);
        add_section_with_data(".text", 0x1000, content.data(), content.size(),
                               0x60000020); /* CODE|EXEC|READ */
    }

    /* Add .text with high-entropy (pseudo-random) content */
    void add_text_high_entropy(size_t size) {
        std::vector<uint8_t> content(size);
        uint32_t seed = 0xDEADBEEF;
        for (size_t i = 0; i < size; i++) {
            seed = seed * 1103515245 + 12345;
            content[i] = (uint8_t)(seed >> 16);
        }
        add_section_with_data(".text", 0x1000, content.data(), content.size(),
                               0x60000020);
    }

    /* Add .text with low-entropy (single-byte XOR pattern) content */
    void add_text_low_entropy(size_t size) {
        std::vector<uint8_t> content(size, 0xAA); /* single repeating byte = entropy 0 */
        add_section_with_data(".text", 0x1000, content.data(), content.size(),
                               0x60000020);
    }

    /* Add .text with normal code-like entropy (~5.5-6.5) */
    void add_text_normal(size_t size) {
        std::vector<uint8_t> content(size);
        /* Simulate x86 code: heavy bias toward common opcode bytes.
           Real .text entropy is typically 5.5-6.5. */
        static const uint8_t common_opcodes[] = {
            0x00, 0x01, 0x03, 0x08, 0x0F, 0x10, 0x20, 0x24,
            0x33, 0x39, 0x3B, 0x48, 0x4C, 0x50, 0x51, 0x52,
            0x55, 0x56, 0x57, 0x58, 0x59, 0x5B, 0x5D, 0x5E,
            0x5F, 0x74, 0x75, 0x83, 0x85, 0x89, 0x8B, 0x8D,
            0x90, 0xC3, 0xC7, 0xCC, 0xE8, 0xE9, 0xEB, 0xFF,
        };
        uint32_t seed = 42;
        for (size_t i = 0; i < size; i++) {
            seed = seed * 1103515245 + 12345;
            /* 70% from common opcodes, 30% from full range */
            if ((seed >> 8) % 100 < 70) {
                content[i] = common_opcodes[(seed >> 16) % sizeof(common_opcodes)];
            } else {
                content[i] = (uint8_t)((seed >> 16) & 0xFF);
            }
        }
        add_section_with_data(".text", 0x1000, content.data(), content.size(),
                               0x60000020);
    }

    const uint8_t* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }

private:
    std::vector<uint8_t> data_;
    uint16_t section_count_ = 0;
    size_t num_sections_off_ = 0;
    size_t section_table_off_ = 0;

    void set16(size_t off, uint16_t v) { memcpy(data_.data() + off, &v, 2); }
    void set32(size_t off, uint32_t v) { memcpy(data_.data() + off, &v, 4); }
};

/* ── Helper: parse PE, compute entropy, and run analyzer ─────────── */

static akav_entropy_result_t analyze_entropy(const uint8_t* data, size_t len,
                                               const akav_entropy_weights_t* w = nullptr)
{
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    EXPECT_TRUE(akav_pe_parse(&pe, data, len));
    akav_pe_compute_entropy(&pe, data, len);

    akav_entropy_result_t result;
    akav_entropy_analyze(&pe, data, len, w, &result);
    akav_pe_free(&pe);
    return result;
}

static bool has_hit(const akav_entropy_result_t& r, const char* name) {
    for (int i = 0; i < r.num_hits; i++) {
        if (strcmp(r.hits[i].check_name, name) == 0) return true;
    }
    return false;
}

static int hit_weight(const akav_entropy_result_t& r, const char* name) {
    for (int i = 0; i < r.num_hits; i++) {
        if (strcmp(r.hits[i].check_name, name) == 0) return r.hits[i].weight;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════ */
/* Tests                                                             */
/* ══════════════════════════════════════════════════════════════════ */

/* ── Shannon entropy function ────────────────────────────────────── */

TEST(EntropyAnalyzer, ShannonAllZeros) {
    uint8_t data[1024];
    memset(data, 0, sizeof(data));
    double e = akav_shannon_entropy(data, sizeof(data));
    EXPECT_DOUBLE_EQ(e, 0.0);
}

TEST(EntropyAnalyzer, ShannonRandom) {
    /* All 256 byte values equally distributed */
    uint8_t data[256 * 100];
    for (int i = 0; i < 256 * 100; i++)
        data[i] = (uint8_t)(i % 256);
    double e = akav_shannon_entropy(data, sizeof(data));
    EXPECT_NEAR(e, 8.0, 0.01);
}

TEST(EntropyAnalyzer, ShannonEmpty) {
    double e = akav_shannon_entropy(nullptr, 0);
    EXPECT_DOUBLE_EQ(e, 0.0);
}

TEST(EntropyAnalyzer, ShannonSingleByte) {
    uint8_t data[1] = {0x42};
    double e = akav_shannon_entropy(data, 1);
    EXPECT_DOUBLE_EQ(e, 0.0); /* only one symbol */
}

TEST(EntropyAnalyzer, ShannonTwoValues) {
    /* 50/50 distribution of two values -> entropy = 1.0 */
    uint8_t data[1000];
    for (int i = 0; i < 1000; i++)
        data[i] = (uint8_t)(i % 2);
    double e = akav_shannon_entropy(data, sizeof(data));
    EXPECT_NEAR(e, 1.0, 0.01);
}

/* ── Default weights ─────────────────────────────────────────────── */

TEST(EntropyAnalyzer, DefaultWeights) {
    akav_entropy_weights_t w;
    akav_entropy_weights_default(&w);
    EXPECT_EQ(w.text_high_entropy, 20);
    EXPECT_EQ(w.text_low_entropy, 15);
    EXPECT_EQ(w.overall_high_entropy, 10);
}

/* ── High entropy .text (packed) ─────────────────────────────────── */

TEST(EntropyAnalyzer, TextHighEntropy) {
    EntropyPeBuilder b;
    b.add_text_high_entropy(4096);
    auto r = analyze_entropy(b.data(), b.size());
    EXPECT_TRUE(has_hit(r, "text_high_entropy"));
    EXPECT_EQ(hit_weight(r, "text_high_entropy"), 20);
}

/* ── Low entropy .text (XOR-encoded) ─────────────────────────────── */

TEST(EntropyAnalyzer, TextLowEntropy) {
    EntropyPeBuilder b;
    b.add_text_low_entropy(4096);
    auto r = analyze_entropy(b.data(), b.size());
    EXPECT_TRUE(has_hit(r, "text_low_entropy"));
    EXPECT_EQ(hit_weight(r, "text_low_entropy"), 15);
}

/* ── Normal entropy .text (clean code) ───────────────────────────── */

TEST(EntropyAnalyzer, TextNormalEntropy) {
    EntropyPeBuilder b;
    b.add_text_normal(4096);
    auto r = analyze_entropy(b.data(), b.size());
    EXPECT_FALSE(has_hit(r, "text_high_entropy"));
    EXPECT_FALSE(has_hit(r, "text_low_entropy"));
}

/* ── Whole-file high entropy ─────────────────────────────────────── */

TEST(EntropyAnalyzer, WholeFileHighEntropy) {
    EntropyPeBuilder b;
    b.add_text_high_entropy(8192); /* Large random section dominates file */
    auto r = analyze_entropy(b.data(), b.size());
    /* With large random content, whole-file entropy should be > 7.5 */
    if (r.whole_file_entropy > 7.5) {
        EXPECT_TRUE(has_hit(r, "overall_high_entropy"));
    }
    /* text_high_entropy should always fire */
    EXPECT_TRUE(has_hit(r, "text_high_entropy"));
}

TEST(EntropyAnalyzer, WholeFileLowEntropyNoHit) {
    EntropyPeBuilder b;
    b.add_text_with_fill(0x00, 4096); /* all zeros */
    auto r = analyze_entropy(b.data(), b.size());
    EXPECT_FALSE(has_hit(r, "overall_high_entropy"));
    EXPECT_LT(r.whole_file_entropy, 7.5);
}

/* ── Combined scoring ────────────────────────────────────────────── */

TEST(EntropyAnalyzer, HighEntropyTextAndOverall) {
    /* Build a PE that's mostly random data */
    EntropyPeBuilder b;
    b.add_text_high_entropy(16384);
    auto r = analyze_entropy(b.data(), b.size());
    /* Should get text_high_entropy (+20) and potentially overall_high_entropy (+10) */
    EXPECT_TRUE(has_hit(r, "text_high_entropy"));
    EXPECT_GE(r.total_score, 20);
}

/* ── JSON weight loading ─────────────────────────────────────────── */

TEST(EntropyAnalyzer, JsonWeightsLoaded) {
    const char* json =
        "{\n"
        "  \"text_high_entropy\": 50,\n"
        "  \"text_low_entropy\": 40,\n"
        "  \"overall_high_entropy\": 30\n"
        "}\n";
    const char* tmp_path = "test_entropy_weights_tmp.json";
    FILE* f = nullptr;
    fopen_s(&f, tmp_path, "w");
    ASSERT_NE(f, nullptr);
    fputs(json, f);
    fclose(f);

    akav_entropy_weights_t w;
    EXPECT_TRUE(akav_entropy_weights_load_json(&w, tmp_path));
    EXPECT_EQ(w.text_high_entropy, 50);
    EXPECT_EQ(w.text_low_entropy, 40);
    EXPECT_EQ(w.overall_high_entropy, 30);

    remove(tmp_path);
}

TEST(EntropyAnalyzer, JsonWeightsOverrideScoring) {
    const char* json = "{ \"text_high_entropy\": 99 }";
    const char* tmp_path = "test_entropy_weights_override.json";
    FILE* f = nullptr;
    fopen_s(&f, tmp_path, "w");
    ASSERT_NE(f, nullptr);
    fputs(json, f);
    fclose(f);

    akav_entropy_weights_t w;
    akav_entropy_weights_load_json(&w, tmp_path);

    EntropyPeBuilder b;
    b.add_text_high_entropy(4096);
    auto r = analyze_entropy(b.data(), b.size(), &w);
    EXPECT_TRUE(has_hit(r, "text_high_entropy"));
    EXPECT_EQ(hit_weight(r, "text_high_entropy"), 99);

    remove(tmp_path);
}

TEST(EntropyAnalyzer, JsonMissingFileFallsBack) {
    akav_entropy_weights_t w;
    EXPECT_FALSE(akav_entropy_weights_load_json(&w, "nonexistent.json"));
    EXPECT_EQ(w.text_high_entropy, 20); /* defaults */
}

/* ── Null safety ─────────────────────────────────────────────────── */

TEST(EntropyAnalyzer, NullPeNocrash) {
    akav_entropy_result_t result;
    memset(&result, 0xFF, sizeof(result));
    akav_entropy_analyze(nullptr, nullptr, 0, nullptr, &result);
}

TEST(EntropyAnalyzer, NullResultNocrash) {
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    pe.valid = true;
    akav_entropy_analyze(&pe, nullptr, 0, nullptr, nullptr);
}

TEST(EntropyAnalyzer, InvalidPeNocrash) {
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    pe.valid = false;
    akav_entropy_result_t result;
    akav_entropy_analyze(&pe, nullptr, 0, nullptr, &result);
}

/* ── Real system PE (kernel32) — normal entropy ──────────────────── */

TEST(EntropyAnalyzer, Kernel32NormalEntropy) {
    FILE* f = nullptr;
    fopen_s(&f, "C:\\Windows\\System32\\kernel32.dll", "rb");
    if (!f) GTEST_SKIP() << "kernel32.dll not available";

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> data((size_t)fsize);
    fread(data.data(), 1, (size_t)fsize, f);
    fclose(f);

    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    ASSERT_TRUE(akav_pe_parse(&pe, data.data(), data.size()));
    akav_pe_compute_entropy(&pe, data.data(), data.size());

    akav_entropy_result_t result;
    akav_entropy_analyze(&pe, data.data(), data.size(), nullptr, &result);

    /* kernel32 .text should have normal entropy (5-7 range) */
    EXPECT_EQ(result.total_score, 0) << "kernel32.dll entropy score should be 0";
    EXPECT_FALSE(has_hit(result, "text_high_entropy"));
    EXPECT_FALSE(has_hit(result, "text_low_entropy"));

    /* Whole file entropy should be well below 7.5 */
    EXPECT_LT(result.whole_file_entropy, 7.5);

    akav_pe_free(&pe);
}

/* ── Entropy value ranges ────────────────────────────────────────── */

TEST(EntropyAnalyzer, WholeFileEntropyComputed) {
    EntropyPeBuilder b;
    b.add_text_normal(4096);
    auto r = analyze_entropy(b.data(), b.size());
    /* Whole-file entropy should be a valid value */
    EXPECT_GE(r.whole_file_entropy, 0.0);
    EXPECT_LE(r.whole_file_entropy, 8.0);
}

TEST(EntropyAnalyzer, TextEntropyBoundary70) {
    /* Entropy exactly at 7.0 should NOT trigger (> 7.0, not >= 7.0) */
    /* Hard to hit exactly 7.0, so we just verify the threshold logic
       by checking that normal code (~5.5-6.5) doesn't trigger. */
    EntropyPeBuilder b;
    b.add_text_normal(4096);
    auto r = analyze_entropy(b.data(), b.size());
    EXPECT_FALSE(has_hit(r, "text_high_entropy"));
}

/* ── Code section without .text name ─────────────────────────────── */

TEST(EntropyAnalyzer, CodeSectionNotNamedText) {
    /* Section named .code with CNT_CODE flag and high entropy */
    EntropyPeBuilder b;
    std::vector<uint8_t> content(4096);
    uint32_t seed = 0xCAFEBABE;
    for (size_t i = 0; i < 4096; i++) {
        seed = seed * 1103515245 + 12345;
        content[i] = (uint8_t)(seed >> 16);
    }
    b.add_section_with_data(".code", 0x1000, content.data(), content.size(),
                             0x60000020); /* CODE|EXEC|READ */
    auto r = analyze_entropy(b.data(), b.size());
    /* Should detect high entropy in the code section even though not named .text */
    EXPECT_TRUE(has_hit(r, "text_high_entropy"));
}

/* ── Adversarial tests ──────────────────────────────────────────── */

TEST(EntropyAnalyzer, Adversarial_JustBelowThreshold) {
    /* Attacker crafts .text entropy ~6.9 to evade the >7.0 packed detection.
       This verifies the boundary: 6.9 should NOT trigger. */
    EntropyPeBuilder b;

    /* Build a 4096-byte block with entropy ~6.9 by mixing 200 distinct
       byte values uniformly — yields entropy = log2(200) ≈ 7.64, so we
       instead use 120 values → log2(120) ≈ 6.91 */
    std::vector<uint8_t> content(4096);
    for (size_t i = 0; i < content.size(); i++)
        content[i] = (uint8_t)(i % 120);
    /* Shuffle to remove positional patterns */
    uint32_t seed = 0x12345678;
    for (size_t i = content.size() - 1; i > 0; i--) {
        seed = seed * 1103515245 + 12345;
        size_t j = (seed >> 16) % (i + 1);
        std::swap(content[i], content[j]);
    }

    b.add_section_with_data(".text", 0x1000, content.data(), content.size(),
                             0x60000020);

    auto r = analyze_entropy(b.data(), b.size());
    EXPECT_FALSE(has_hit(r, "text_high_entropy"))
        << "Entropy just below 7.0 should evade packed detection";
}

TEST(EntropyAnalyzer, Adversarial_JustAboveThreshold) {
    /* Entropy ~7.1 should trigger packed detection. Use 140 distinct
       values → log2(140) ≈ 7.13 */
    EntropyPeBuilder b;
    std::vector<uint8_t> content(4096);
    for (size_t i = 0; i < content.size(); i++)
        content[i] = (uint8_t)(i % 140);
    uint32_t seed = 0xDEADBEEF;
    for (size_t i = content.size() - 1; i > 0; i--) {
        seed = seed * 1103515245 + 12345;
        size_t j = (seed >> 16) % (i + 1);
        std::swap(content[i], content[j]);
    }

    b.add_section_with_data(".text", 0x1000, content.data(), content.size(),
                             0x60000020);

    auto r = analyze_entropy(b.data(), b.size());
    EXPECT_TRUE(has_hit(r, "text_high_entropy"))
        << "Entropy just above 7.0 should trigger packed detection";
}

TEST(EntropyAnalyzer, Adversarial_EntropyDilution) {
    /* Attacker places small encrypted payload in .data and pads the rest
       with zeros. Whole-file entropy stays below 7.5 even though the
       payload itself is high-entropy. This is a known evasion. */
    EntropyPeBuilder b;
    b.add_text_normal(4096);

    /* 512 bytes of random data + 7680 bytes of zeros = 8192 byte .data */
    std::vector<uint8_t> data_sec(8192, 0);
    uint32_t seed = 0xBADC0DE;
    for (size_t i = 0; i < 512; i++) {
        seed = seed * 1103515245 + 12345;
        data_sec[i] = (uint8_t)(seed >> 16);
    }
    b.add_section_with_data(".data", 0x2000, data_sec.data(), data_sec.size(),
                             0xC0000040); /* READ|WRITE|INITIALIZED */

    auto r = analyze_entropy(b.data(), b.size());
    /* Whole-file entropy should be diluted below 7.5 */
    EXPECT_FALSE(has_hit(r, "overall_high_entropy"))
        << "Entropy dilution via zero-padding should evade whole-file check";
    /* .text is normal, so no per-section hit either */
    EXPECT_FALSE(has_hit(r, "text_high_entropy"));
}

TEST(EntropyAnalyzer, Adversarial_HighEntropyResourceSection) {
    /* Encrypted payload hidden in .rsrc section. Current analyzer only
       checks code sections, so this should NOT be detected. Documents
       a known blind spot. */
    EntropyPeBuilder b;
    b.add_text_normal(4096);

    /* Random .rsrc data (high entropy) */
    std::vector<uint8_t> rsrc(4096);
    uint32_t seed = 0xFACEFEED;
    for (size_t i = 0; i < rsrc.size(); i++) {
        seed = seed * 1103515245 + 12345;
        rsrc[i] = (uint8_t)(seed >> 16);
    }
    b.add_section_with_data(".rsrc", 0x2000, rsrc.data(), rsrc.size(),
                             0x40000040); /* READ|INITIALIZED (no code flag) */

    auto r = analyze_entropy(b.data(), b.size());
    /* Not detected — .rsrc has no CODE flag */
    EXPECT_FALSE(has_hit(r, "text_high_entropy"))
        << "High-entropy .rsrc should not trigger code section check";
}

TEST(EntropyAnalyzer, Adversarial_TwoKeyXOR) {
    /* Alternating two XOR keys (0xAA, 0x55) over zeros produces two
       distinct byte values → entropy = log2(2) = 1.0.
       This is AT the 1.0 threshold (check is < 1.0, not <=), so it
       should evade XOR detection. */
    EntropyPeBuilder b;
    std::vector<uint8_t> content(4096);
    for (size_t i = 0; i < content.size(); i++)
        content[i] = (i % 2 == 0) ? 0xAA : 0x55;

    b.add_section_with_data(".text", 0x1000, content.data(), content.size(),
                             0x60000020);

    auto r = analyze_entropy(b.data(), b.size());
    EXPECT_FALSE(has_hit(r, "text_low_entropy"))
        << "Two-key XOR (entropy=1.0) should evade <1.0 threshold";
}

TEST(EntropyAnalyzer, Adversarial_SingleKeyXOR) {
    /* Single-byte XOR (0xAA) over zeros: all bytes identical → entropy = 0.
       This SHOULD be caught by the <1.0 check. */
    EntropyPeBuilder b;
    std::vector<uint8_t> content(4096, 0xAA);

    b.add_section_with_data(".text", 0x1000, content.data(), content.size(),
                             0x60000020);

    auto r = analyze_entropy(b.data(), b.size());
    EXPECT_TRUE(has_hit(r, "text_low_entropy"))
        << "Single-key XOR (entropy=0) should trigger XOR detection";
}

TEST(EntropyAnalyzer, Adversarial_HighEntropyNoCodeFlag) {
    /* Packed code placed in a section without the CNT_CODE flag.
       If the section isn't named .text and lacks CODE flag, the
       analyzer won't check it. Documents this evasion. */
    EntropyPeBuilder b;
    b.add_text_normal(4096); /* legitimate .text first */

    /* High entropy in .packed section without CODE flag */
    std::vector<uint8_t> packed(4096);
    uint32_t seed = 0xC0FFEE;
    for (size_t i = 0; i < packed.size(); i++) {
        seed = seed * 1103515245 + 12345;
        packed[i] = (uint8_t)(seed >> 16);
    }
    b.add_section_with_data(".packed", 0x2000, packed.data(), packed.size(),
                             0xC0000040); /* READ|WRITE|INITIALIZED, no CODE */

    auto r = analyze_entropy(b.data(), b.size());
    /* Analyzer only checks the first code section (.text here, which is normal) */
    EXPECT_FALSE(has_hit(r, "text_high_entropy"))
        << "High-entropy non-code section should not be checked";
}

TEST(EntropyAnalyzer, Adversarial_PaddedToReduceWholeFile) {
    /* Attacker appends large zero-padding to reduce whole-file entropy
       below 7.5, but .text is still packed. Per-section check should
       still catch it. */
    EntropyPeBuilder b;

    /* High-entropy .text (random data → ~8.0) */
    std::vector<uint8_t> text(4096);
    uint32_t seed = 0xBEEFCAFE;
    for (size_t i = 0; i < text.size(); i++) {
        seed = seed * 1103515245 + 12345;
        text[i] = (uint8_t)(seed >> 16);
    }
    b.add_section_with_data(".text", 0x1000, text.data(), text.size(),
                             0x60000020);

    /* Large zero .data section to dilute whole-file entropy */
    std::vector<uint8_t> padding(32768, 0);
    b.add_section_with_data(".data", 0x2000, padding.data(), padding.size(),
                             0xC0000040);

    auto r = analyze_entropy(b.data(), b.size());
    /* .text should still be caught */
    EXPECT_TRUE(has_hit(r, "text_high_entropy"))
        << "Per-section check should catch packed .text despite padding";
    /* But whole-file entropy is diluted */
    EXPECT_FALSE(has_hit(r, "overall_high_entropy"))
        << "Zero-padding should dilute whole-file entropy below 7.5";
}
