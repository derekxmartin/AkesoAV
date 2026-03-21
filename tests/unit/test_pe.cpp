#include <gtest/gtest.h>
#include "parsers/pe.h"
#include <cstring>
#include <vector>

/* ── Helper: Build a minimal valid PE32 binary ───────────────────── */

class PeBuilder {
public:
    PeBuilder() { reset_pe32(); }

    /* Reset to a default PE32 (i386) with 1 .text section */
    void reset_pe32() {
        data_.clear();
        data_.resize(1024, 0);
        is_pe32plus_ = false;
        build();
    }

    /* Reset to a default PE32+ (AMD64) with 1 .text section */
    void reset_pe32plus() {
        data_.clear();
        data_.resize(1024, 0);
        is_pe32plus_ = true;
        build();
    }

    const uint8_t* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }
    std::vector<uint8_t>& raw() { return data_; }

    /* Set specific fields after build */
    void set_u16(size_t off, uint16_t v) { memcpy(data_.data() + off, &v, 2); }
    void set_u32(size_t off, uint32_t v) { memcpy(data_.data() + off, &v, 4); }

private:
    std::vector<uint8_t> data_;
    bool is_pe32plus_ = false;

    void build() {
        uint8_t* d = data_.data();

        /* DOS header */
        d[0] = 'M'; d[1] = 'Z';    /* e_magic */
        uint32_t lfanew = 0x80;
        memcpy(d + 0x3C, &lfanew, 4); /* e_lfanew */

        /* PE signature at 0x80 */
        uint32_t pe_sig = 0x00004550;
        memcpy(d + 0x80, &pe_sig, 4);

        /* COFF header at 0x84 */
        uint16_t machine = is_pe32plus_ ? 0x8664 : 0x014C;
        uint16_t num_sections = 1;
        uint32_t timestamp = 0x60000000;
        uint16_t opt_size = is_pe32plus_ ? 240 : 224;
        uint16_t chars = 0x0002; /* EXECUTABLE */

        size_t off = 0x84;
        memcpy(d + off, &machine, 2); off += 2;
        memcpy(d + off, &num_sections, 2); off += 2;
        memcpy(d + off, &timestamp, 4); off += 4;
        off += 4; /* symbol_table_offset = 0 */
        off += 4; /* num_symbols = 0 */
        memcpy(d + off, &opt_size, 2); off += 2;
        memcpy(d + off, &chars, 2); off += 2;

        /* Optional header at 0x98 */
        size_t opt_start = off;
        uint16_t opt_magic = is_pe32plus_ ? 0x20B : 0x10B;
        memcpy(d + off, &opt_magic, 2); off += 2;

        d[off++] = 14; /* major_linker */
        d[off++] = 0;  /* minor_linker */

        uint32_t size_of_code = 0x1000;
        memcpy(d + off, &size_of_code, 4); off += 4; /* SizeOfCode */
        off += 4; /* SizeOfInitData */
        off += 4; /* SizeOfUninitData */
        uint32_t entry_rva = 0x1000;
        memcpy(d + off, &entry_rva, 4); off += 4; /* EntryPoint */
        uint32_t base_of_code = 0x1000;
        memcpy(d + off, &base_of_code, 4); off += 4; /* BaseOfCode */

        if (!is_pe32plus_) {
            /* PE32: BaseOfData + ImageBase (4 each) */
            off += 4; /* BaseOfData */
            uint32_t ib32 = 0x00400000;
            memcpy(d + off, &ib32, 4); off += 4;
        } else {
            /* PE32+: ImageBase (8 bytes) */
            uint64_t ib64 = 0x0000000140000000ULL;
            memcpy(d + off, &ib64, 8); off += 8;
        }

        uint32_t sec_align = 0x1000;
        uint32_t file_align = 0x200;
        memcpy(d + off, &sec_align, 4); off += 4;
        memcpy(d + off, &file_align, 4); off += 4;

        /* OS/Image/Subsystem versions */
        uint16_t v6 = 6;
        memcpy(d + off, &v6, 2); off += 2; /* MajorOS */
        off += 2; /* MinorOS */
        off += 2; /* MajorImage */
        off += 2; /* MinorImage */
        memcpy(d + off, &v6, 2); off += 2; /* MajorSubsystem */
        off += 2; /* MinorSubsystem */
        off += 4; /* Win32VersionValue */

        uint32_t size_of_image = 0x3000;
        memcpy(d + off, &size_of_image, 4); off += 4;
        uint32_t size_of_headers = 0x200;
        memcpy(d + off, &size_of_headers, 4); off += 4;
        off += 4; /* Checksum */
        uint16_t subsystem = 3; /* CONSOLE */
        memcpy(d + off, &subsystem, 2); off += 2;
        uint16_t dll_chars = 0x8160; /* ASLR+DEP+NX */
        memcpy(d + off, &dll_chars, 2); off += 2;

        if (!is_pe32plus_) {
            off += 16; /* 4x uint32: stack/heap reserve/commit */
        } else {
            off += 32; /* 4x uint64 */
        }

        off += 4; /* LoaderFlags */
        uint32_t num_dd = 16;
        memcpy(d + off, &num_dd, 4); off += 4;

        /* 16 data directories (8 bytes each) */
        off += 16 * 8;

        /* Verify optional header size consumed */
        size_t opt_consumed = off - opt_start;
        (void)opt_consumed;

        /* Section table (40 bytes per section) */
        /* .text section */
        memcpy(d + off, ".text\0\0\0", 8); off += 8;
        uint32_t virt_size = 0x100;
        memcpy(d + off, &virt_size, 4); off += 4;   /* VirtualSize */
        uint32_t virt_addr = 0x1000;
        memcpy(d + off, &virt_addr, 4); off += 4;   /* VirtualAddress */
        uint32_t raw_size = 0x200;
        memcpy(d + off, &raw_size, 4); off += 4;    /* SizeOfRawData */
        uint32_t raw_off = 0x200;
        memcpy(d + off, &raw_off, 4); off += 4;     /* PointerToRawData */
        off += 12; /* relocations, linenumbers */
        uint32_t scn_chars = 0x60000020; /* CODE|EXEC|READ */
        memcpy(d + off, &scn_chars, 4); off += 4;
    }
};

/* ══════════════════════════════════════════════════════════════════ */
/* Tests                                                             */
/* ══════════════════════════════════════════════════════════════════ */

/* ── PE32 (32-bit) parsing ───────────────────────────────────────── */

TEST(PeParser, ParseValidPE32) {
    PeBuilder b;
    b.reset_pe32();

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, b.data(), b.size()));
    EXPECT_TRUE(pe.valid);

    EXPECT_EQ(pe.dos_magic, 0x5A4D);
    EXPECT_EQ(pe.e_lfanew, 0x80u);
    EXPECT_EQ(pe.machine, AKAV_PE_MACHINE_I386);
    EXPECT_EQ(pe.num_sections, 1);
    EXPECT_FALSE(pe.is_pe32plus);
    EXPECT_EQ(pe.opt_magic, 0x10B);
    EXPECT_EQ(pe.image_base, 0x00400000u);
    EXPECT_EQ(pe.entry_point, 0x1000u);
    EXPECT_EQ(pe.section_alignment, 0x1000u);
    EXPECT_EQ(pe.file_alignment, 0x200u);
    EXPECT_EQ(pe.subsystem, 3); /* CONSOLE */
    EXPECT_STREQ(akav_pe_machine_name(pe.machine), "i386");
}

/* ── PE32+ (64-bit) parsing ──────────────────────────────────────── */

TEST(PeParser, ParseValidPE32Plus) {
    PeBuilder b;
    b.reset_pe32plus();

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, b.data(), b.size()));
    EXPECT_TRUE(pe.valid);

    EXPECT_EQ(pe.machine, AKAV_PE_MACHINE_AMD64);
    EXPECT_TRUE(pe.is_pe32plus);
    EXPECT_EQ(pe.opt_magic, 0x20B);
    EXPECT_EQ(pe.image_base, 0x0000000140000000ULL);
    EXPECT_STREQ(akav_pe_machine_name(pe.machine), "AMD64");
}

/* ── Section table parsed ────────────────────────────────────────── */

TEST(PeParser, SectionTableParsed) {
    PeBuilder b;
    b.reset_pe32();

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, b.data(), b.size()));

    ASSERT_EQ(pe.num_sections, 1);
    EXPECT_STREQ(pe.sections[0].name, ".text");
    EXPECT_EQ(pe.sections[0].virtual_size, 0x100u);
    EXPECT_EQ(pe.sections[0].virtual_address, 0x1000u);
    EXPECT_EQ(pe.sections[0].raw_data_size, 0x200u);
    EXPECT_EQ(pe.sections[0].raw_data_offset, 0x200u);
    EXPECT_EQ(pe.sections[0].characteristics, 0x60000020u);
}

/* ── Find section by name ────────────────────────────────────────── */

TEST(PeParser, FindSection) {
    PeBuilder b;
    b.reset_pe32();

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, b.data(), b.size()));

    const akav_pe_section_t* text = akav_pe_find_section(&pe, ".text");
    ASSERT_NE(text, nullptr);
    EXPECT_STREQ(text->name, ".text");

    EXPECT_EQ(akav_pe_find_section(&pe, ".data"), nullptr);
}

/* ── RVA to offset conversion ────────────────────────────────────── */

TEST(PeParser, RvaToOffset) {
    PeBuilder b;
    b.reset_pe32();

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, b.data(), b.size()));

    /* .text: VA=0x1000, raw_offset=0x200 */
    EXPECT_EQ(akav_pe_rva_to_offset(&pe, 0x1000), 0x200u);
    EXPECT_EQ(akav_pe_rva_to_offset(&pe, 0x1050), 0x250u);
    EXPECT_EQ(akav_pe_rva_to_offset(&pe, 0x2000), 0u); /* outside any section */
}

/* ── Data directories parsed ─────────────────────────────────────── */

TEST(PeParser, DataDirectories) {
    PeBuilder b;
    b.reset_pe32();

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, b.data(), b.size()));

    EXPECT_EQ(pe.num_data_dirs, 16u);
    /* All zeroed in our synthetic PE */
    for (uint32_t i = 0; i < pe.num_data_dirs; i++) {
        EXPECT_EQ(pe.data_dirs[i].virtual_address, 0u);
        EXPECT_EQ(pe.data_dirs[i].size, 0u);
    }
}

/* ── Truncation: too small for DOS header ────────────────────────── */

TEST(PeParser, TruncatedDosHeader) {
    uint8_t tiny[] = {'M', 'Z'};
    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, tiny, sizeof(tiny)));
    EXPECT_FALSE(pe.valid);
    EXPECT_NE(strlen(pe.error), 0u);
}

/* ── Truncation: truncated at COFF header ────────────────────────── */

TEST(PeParser, TruncatedCoffHeader) {
    PeBuilder b;
    b.reset_pe32();

    /* Truncate right after PE signature */
    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, b.data(), 0x86));
    EXPECT_FALSE(pe.valid);
}

/* ── Truncation: truncated in optional header ────────────────────── */

TEST(PeParser, TruncatedOptionalHeader) {
    PeBuilder b;
    b.reset_pe32();

    /* Truncate in the middle of the optional header */
    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, b.data(), 0xB0));
    EXPECT_FALSE(pe.valid);
}

/* ── Truncation: truncated in section table ──────────────────────── */

TEST(PeParser, TruncatedSectionTable) {
    PeBuilder b;
    b.reset_pe32();

    /* The section table starts after optional header. Truncate mid-section. */
    size_t sec_table_start = 0x80 + 4 + 20 + 224; /* lfanew + sig + coff + opt */
    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, b.data(), sec_table_start + 10));
    EXPECT_FALSE(pe.valid);
}

/* ── Zero sections → error ───────────────────────────────────────── */

TEST(PeParser, ZeroSectionsError) {
    PeBuilder b;
    b.reset_pe32();

    /* Patch num_sections to 0 at offset 0x86 */
    b.set_u16(0x86, 0);

    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, b.data(), b.size()));
    EXPECT_FALSE(pe.valid);
    EXPECT_NE(strstr(pe.error, "Zero sections"), nullptr);
}

/* ── Invalid DOS magic ───────────────────────────────────────────── */

TEST(PeParser, InvalidDosMagic) {
    uint8_t bad[256] = {};
    bad[0] = 'P'; bad[1] = 'E';  /* not MZ */

    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, bad, sizeof(bad)));
    EXPECT_NE(strstr(pe.error, "DOS magic"), nullptr);
}

/* ── Invalid PE signature ────────────────────────────────────────── */

TEST(PeParser, InvalidPeSignature) {
    PeBuilder b;
    b.reset_pe32();

    /* Corrupt PE signature */
    b.set_u32(0x80, 0xDEADBEEF);

    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, b.data(), b.size()));
    EXPECT_NE(strstr(pe.error, "PE signature"), nullptr);
}

/* ── Invalid optional header magic ───────────────────────────────── */

TEST(PeParser, InvalidOptMagic) {
    PeBuilder b;
    b.reset_pe32();

    /* Corrupt optional header magic at 0x98 */
    b.set_u16(0x98, 0xBEEF);

    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, b.data(), b.size()));
    EXPECT_NE(strstr(pe.error, "optional header magic"), nullptr);
}

/* ── e_lfanew too large ──────────────────────────────────────────── */

TEST(PeParser, ElfanewTooLarge) {
    PeBuilder b;
    b.reset_pe32();

    /* Set e_lfanew to > 64K */
    b.set_u32(0x3C, 0x20000);

    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, b.data(), b.size()));
    EXPECT_NE(strstr(pe.error, "e_lfanew too large"), nullptr);
}

/* ── Too many sections ───────────────────────────────────────────── */

TEST(PeParser, TooManySections) {
    PeBuilder b;
    b.reset_pe32();

    b.set_u16(0x86, 200); /* > AKAV_PE_MAX_SECTIONS */

    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, b.data(), b.size()));
    EXPECT_NE(strstr(pe.error, "maximum"), nullptr);
}

/* ── Null buffer ─────────────────────────────────────────────────── */

TEST(PeParser, NullBuffer) {
    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, nullptr, 0));
    EXPECT_FALSE(pe.valid);
}

/* ── Empty buffer ────────────────────────────────────────────────── */

TEST(PeParser, EmptyBuffer) {
    akav_pe_t pe;
    EXPECT_FALSE(akav_pe_parse(&pe, (const uint8_t*)"", 0));
    EXPECT_FALSE(pe.valid);
}

/* ── Machine name helper ─────────────────────────────────────────── */

TEST(PeParser, MachineNames) {
    EXPECT_STREQ(akav_pe_machine_name(0x014C), "i386");
    EXPECT_STREQ(akav_pe_machine_name(0x8664), "AMD64");
    EXPECT_STREQ(akav_pe_machine_name(0x01C0), "ARM");
    EXPECT_STREQ(akav_pe_machine_name(0xAA64), "ARM64");
    EXPECT_STREQ(akav_pe_machine_name(0x9999), "Unknown");
}

/* ── DLL characteristics flag ────────────────────────────────────── */

TEST(PeParser, DLLFlagParsed) {
    PeBuilder b;
    b.reset_pe32();

    /* Set characteristics to include DLL flag */
    b.set_u16(0x96, 0x2002); /* EXECUTABLE | DLL */

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, b.data(), b.size()));
    EXPECT_TRUE(pe.characteristics & AKAV_PE_CHAR_DLL);
    EXPECT_TRUE(pe.characteristics & AKAV_PE_CHAR_EXECUTABLE);
}

/* ── Real-world: parse actual system DLL ─────────────────────────── */

/* ── Helper: load a PE file from disk ────────────────────────────── */

static std::vector<uint8_t> load_file(const char* path) {
    std::vector<uint8_t> buf;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return buf;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf.resize((size_t)fsize);
    fread(buf.data(), 1, buf.size(), f);
    fclose(f);
    return buf;
}

TEST(PeParser, ParseKernel32) {
    auto buf = load_file("C:\\Windows\\System32\\kernel32.dll");
    if (buf.empty()) GTEST_SKIP() << "kernel32.dll not accessible";

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, buf.data(), buf.size()));
    EXPECT_TRUE(pe.valid);
    EXPECT_EQ(pe.machine, AKAV_PE_MACHINE_AMD64);
    EXPECT_TRUE(pe.is_pe32plus);
    EXPECT_TRUE(pe.characteristics & AKAV_PE_CHAR_DLL);
    EXPECT_NE(akav_pe_find_section(&pe, ".text"), nullptr);
    akav_pe_free(&pe);
}

TEST(PeParser, ParseSysWOW64DLL) {
    auto buf = load_file("C:\\Windows\\SysWOW64\\kernel32.dll");
    if (buf.empty()) GTEST_SKIP() << "SysWOW64 kernel32.dll not accessible";

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, buf.data(), buf.size()));
    EXPECT_TRUE(pe.valid);
    EXPECT_EQ(pe.machine, AKAV_PE_MACHINE_I386);
    EXPECT_FALSE(pe.is_pe32plus);
    akav_pe_free(&pe);
}

/* ══════════════════════════════════════════════════════════════════ */
/* Import / Export tests                                             */
/* ══════════════════════════════════════════════════════════════════ */

/* ── kernel32.dll exports: known functions ───────────────────────── */

TEST(PeImports, Kernel32Exports) {
    auto buf = load_file("C:\\Windows\\System32\\kernel32.dll");
    if (buf.empty()) GTEST_SKIP() << "kernel32.dll not accessible";

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, buf.data(), buf.size()));
    ASSERT_TRUE(akav_pe_parse_exports(&pe, buf.data(), buf.size()));

    /* kernel32 should export many functions */
    EXPECT_GT(pe.num_export_funcs, 100u);
    EXPECT_GT(pe.export_dir.num_names, 100u);

    /* Check for well-known exports */
    bool found_create_file = false;
    bool found_virtual_alloc = false;
    bool found_get_proc = false;
    for (uint32_t i = 0; i < pe.num_export_funcs; i++) {
        if (strcmp(pe.export_funcs[i].name, "CreateFileW") == 0)
            found_create_file = true;
        if (strcmp(pe.export_funcs[i].name, "VirtualAlloc") == 0)
            found_virtual_alloc = true;
        if (strcmp(pe.export_funcs[i].name, "GetProcAddress") == 0)
            found_get_proc = true;
    }
    EXPECT_TRUE(found_create_file);
    EXPECT_TRUE(found_virtual_alloc);
    EXPECT_TRUE(found_get_proc);

    /* DLL name should be set */
    EXPECT_NE(strlen(pe.export_dir.dll_name), 0u);

    akav_pe_free(&pe);
}

/* ── kernel32.dll imports: known DLLs ────────────────────────────── */

TEST(PeImports, Kernel32Imports) {
    auto buf = load_file("C:\\Windows\\System32\\kernel32.dll");
    if (buf.empty()) GTEST_SKIP() << "kernel32.dll not accessible";

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, buf.data(), buf.size()));
    ASSERT_TRUE(akav_pe_parse_imports(&pe, buf.data(), buf.size()));

    EXPECT_GT(pe.num_import_dlls, 0u);
    EXPECT_GT(pe.num_import_funcs, 0u);

    /* kernel32 should import from ntdll.dll (or api-ms-win shims) */
    bool found_ntdll = false;
    for (uint32_t i = 0; i < pe.num_import_dlls; i++) {
        /* Case-insensitive check */
        if (_stricmp(pe.import_dlls[i].dll_name, "ntdll.dll") == 0 ||
            _stricmp(pe.import_dlls[i].dll_name, "NTDLL.dll") == 0) {
            found_ntdll = true;
        }
    }
    /* On modern Windows, kernel32 may import from api-ms shims instead */
    EXPECT_GT(pe.num_import_dlls, 0u);

    akav_pe_free(&pe);
}

/* ── 32-bit kernel32 imports ─────────────────────────────────────── */

TEST(PeImports, SysWOW64Imports) {
    auto buf = load_file("C:\\Windows\\SysWOW64\\kernel32.dll");
    if (buf.empty()) GTEST_SKIP() << "SysWOW64 not accessible";

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, buf.data(), buf.size()));
    ASSERT_TRUE(akav_pe_parse_imports(&pe, buf.data(), buf.size()));

    EXPECT_GT(pe.num_import_dlls, 0u);
    EXPECT_GT(pe.num_import_funcs, 0u);

    /* 32-bit PE should parse without crash */
    EXPECT_FALSE(pe.is_pe32plus);
    akav_pe_free(&pe);
}

/* ── 32-bit kernel32 exports ─────────────────────────────────────── */

TEST(PeImports, SysWOW64Exports) {
    auto buf = load_file("C:\\Windows\\SysWOW64\\kernel32.dll");
    if (buf.empty()) GTEST_SKIP() << "SysWOW64 not accessible";

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, buf.data(), buf.size()));
    ASSERT_TRUE(akav_pe_parse_exports(&pe, buf.data(), buf.size()));

    EXPECT_GT(pe.num_export_funcs, 100u);
    akav_pe_free(&pe);
}

/* ── No import directory → returns false, no crash ───────────────── */

TEST(PeImports, NoImportDirReturnsFalse) {
    PeBuilder b;
    b.reset_pe32();

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, b.data(), b.size()));

    /* Synthetic PE has no import dir (data dirs all zero) */
    EXPECT_FALSE(akav_pe_parse_imports(&pe, b.data(), b.size()));
    EXPECT_EQ(pe.num_import_dlls, 0u);
    akav_pe_free(&pe);
}

/* ── No export directory → returns false, no crash ───────────────── */

TEST(PeImports, NoExportDirReturnsFalse) {
    PeBuilder b;
    b.reset_pe32();

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, b.data(), b.size()));

    EXPECT_FALSE(akav_pe_parse_exports(&pe, b.data(), b.size()));
    EXPECT_EQ(pe.num_export_funcs, 0u);
    akav_pe_free(&pe);
}

/* ── Invalid RVA in import dir → skip, don't crash ───────────────── */

TEST(PeImports, InvalidImportRva) {
    PeBuilder b;
    b.reset_pe32();

    /* Point import dir to a nonsense RVA */
    /* Data dir[1] (import) is at opt_header_start + fixed_offset */
    /* In our builder, data dirs start at 0x98 + 2 + 2 + ... */
    /* Import dir (index 1) = 8 bytes at data_dir_start + 8 */
    /* opt_start = 0x98, fixed fields before data dirs for PE32 = 96 bytes,
       so data dirs at 0x98 + 96 = 0xF8 */
    size_t dd_start = 0x98 + 96;
    b.set_u32((uint32_t)(dd_start + 8), 0xDEAD0000);  /* import dir RVA */
    b.set_u32((uint32_t)(dd_start + 12), 0x100);       /* import dir size */

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, b.data(), b.size()));

    /* Should return false gracefully, not crash */
    EXPECT_FALSE(akav_pe_parse_imports(&pe, b.data(), b.size()));
    akav_pe_free(&pe);
}

/* ── pe_free is safe on zeroed struct ────────────────────────────── */

TEST(PeImports, FreeZeroedStruct) {
    akav_pe_t pe;
    memset(&pe, 0, sizeof(pe));
    akav_pe_free(&pe); /* should not crash */
}

/* ── pe_free is safe to call twice ───────────────────────────────── */

TEST(PeImports, DoubleFree) {
    auto buf = load_file("C:\\Windows\\System32\\kernel32.dll");
    if (buf.empty()) GTEST_SKIP() << "kernel32.dll not accessible";

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, buf.data(), buf.size()));
    akav_pe_parse_imports(&pe, buf.data(), buf.size());
    akav_pe_parse_exports(&pe, buf.data(), buf.size());

    akav_pe_free(&pe);
    akav_pe_free(&pe); /* second free should be safe */
}

/* ── Import function names are readable ──────────────────────────── */

TEST(PeImports, ImportFuncNamesReadable) {
    auto buf = load_file("C:\\Windows\\System32\\kernel32.dll");
    if (buf.empty()) GTEST_SKIP() << "kernel32.dll not accessible";

    akav_pe_t pe;
    ASSERT_TRUE(akav_pe_parse(&pe, buf.data(), buf.size()));
    ASSERT_TRUE(akav_pe_parse_imports(&pe, buf.data(), buf.size()));

    /* All non-ordinal import names should be printable ASCII */
    for (uint32_t i = 0; i < pe.num_import_funcs; i++) {
        if (!pe.import_funcs[i].is_ordinal && pe.import_funcs[i].name[0]) {
            for (size_t c = 0; pe.import_funcs[i].name[c]; c++) {
                EXPECT_GE((unsigned char)pe.import_funcs[i].name[c], 0x20)
                    << "Non-printable char in import name: " << pe.import_funcs[i].name;
            }
        }
    }
    akav_pe_free(&pe);
}
