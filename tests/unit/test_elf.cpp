// test_elf.cpp -- Tests for ELF parser (P7-T1).
//
// Tests cover:
//   - ELF32 LE/BE header parsing
//   - ELF64 LE/BE header parsing
//   - Section header parsing and name resolution
//   - Program header parsing
//   - .symtab / .dynsym symbol tables
//   - .dynamic section and DT_NEEDED resolution
//   - .note sections and build-id extraction
//   - PT_INTERP interpreter string
//   - Truncated/malformed input graceful error handling
//   - Non-ELF data returns false

#include <gtest/gtest.h>
#include "parsers/elf.h"
#include "parsers/safe_reader.h"

#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>

// ── Minimal ELF builder ───────────────────────────────────────────

struct ElfBuilder {
    bool is_64;
    bool big_endian;
    std::vector<uint8_t> buf;

    // Track section header entries and their raw data
    struct SectionDef {
        uint32_t sh_name;       // offset into shstrtab
        uint32_t sh_type;
        uint64_t sh_flags;
        uint64_t sh_addr;
        uint64_t sh_offset;     // filled in during build
        uint64_t sh_size;       // filled in during build
        uint32_t sh_link;
        uint32_t sh_info;
        uint64_t sh_addralign;
        uint64_t sh_entsize;
        std::vector<uint8_t> data;
    };

    struct PhdrDef {
        uint32_t p_type;
        uint32_t p_flags;
        uint64_t p_offset;      // filled in during build
        uint64_t p_vaddr;
        uint64_t p_paddr;
        uint64_t p_filesz;      // filled in during build
        uint64_t p_memsz;
        uint64_t p_align;
        std::vector<uint8_t> data; // if non-empty, maps to segment data
    };

    std::vector<SectionDef> sections;
    std::vector<PhdrDef> phdrs;
    std::string shstrtab_content;
    uint16_t e_type = 2;        // ET_EXEC
    uint16_t e_machine = 62;    // EM_X86_64
    uint64_t e_entry = 0x401000;

    ElfBuilder(bool is64, bool be) : is_64(is64), big_endian(be) {
        // Section 0 is always SHN_UNDEF (null)
        shstrtab_content.push_back('\0'); // index 0 = empty string
        SectionDef null_sec = {};
        null_sec.sh_name = 0;
        sections.push_back(null_sec);
    }

    uint32_t add_string(const char* s) {
        uint32_t off = (uint32_t)shstrtab_content.size();
        shstrtab_content.append(s);
        shstrtab_content.push_back('\0');
        return off;
    }

    size_t add_section(const char* name, uint32_t type, uint64_t flags,
                       const std::vector<uint8_t>& data,
                       uint32_t link = 0, uint32_t info = 0,
                       uint64_t entsize = 0) {
        SectionDef sec = {};
        sec.sh_name = add_string(name);
        sec.sh_type = type;
        sec.sh_flags = flags;
        sec.sh_link = link;
        sec.sh_info = info;
        sec.sh_addralign = 1;
        sec.sh_entsize = entsize;
        sec.data = data;
        sections.push_back(sec);
        return sections.size() - 1;
    }

    size_t add_phdr(uint32_t type, uint32_t flags, uint64_t vaddr,
                    uint64_t memsz, uint64_t align,
                    const std::vector<uint8_t>& data = {}) {
        PhdrDef ph = {};
        ph.p_type = type;
        ph.p_flags = flags;
        ph.p_vaddr = vaddr;
        ph.p_paddr = vaddr;
        ph.p_memsz = memsz;
        ph.p_align = align;
        ph.data = data;
        phdrs.push_back(ph);
        return phdrs.size() - 1;
    }

    void put16(uint16_t v) {
        if (big_endian) {
            buf.push_back((uint8_t)(v >> 8));
            buf.push_back((uint8_t)(v & 0xFF));
        } else {
            buf.push_back((uint8_t)(v & 0xFF));
            buf.push_back((uint8_t)(v >> 8));
        }
    }

    void put32(uint32_t v) {
        if (big_endian) {
            buf.push_back((uint8_t)(v >> 24));
            buf.push_back((uint8_t)((v >> 16) & 0xFF));
            buf.push_back((uint8_t)((v >> 8) & 0xFF));
            buf.push_back((uint8_t)(v & 0xFF));
        } else {
            buf.push_back((uint8_t)(v & 0xFF));
            buf.push_back((uint8_t)((v >> 8) & 0xFF));
            buf.push_back((uint8_t)((v >> 16) & 0xFF));
            buf.push_back((uint8_t)(v >> 24));
        }
    }

    void put64(uint64_t v) {
        if (big_endian) {
            for (int i = 7; i >= 0; i--)
                buf.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
        } else {
            for (int i = 0; i < 8; i++)
                buf.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
        }
    }

    void put_addr(uint64_t v) {
        if (is_64) put64(v); else put32((uint32_t)v);
    }

    void pad_to(size_t target) {
        while (buf.size() < target) buf.push_back(0);
    }

    std::vector<uint8_t> build() {
        buf.clear();

        // Finalize shstrtab
        uint32_t shstrtab_name = add_string(".shstrtab");
        SectionDef shstrtab_sec = {};
        shstrtab_sec.sh_name = shstrtab_name;
        shstrtab_sec.sh_type = 3; // SHT_STRTAB
        shstrtab_sec.sh_flags = 0;
        shstrtab_sec.data.assign(shstrtab_content.begin(), shstrtab_content.end());
        shstrtab_sec.sh_addralign = 1;
        sections.push_back(shstrtab_sec);
        uint16_t shstrndx = (uint16_t)(sections.size() - 1);

        // Layout:
        //   ELF header
        //   Program headers (immediately after)
        //   Section data (each section's raw data)
        //   Section header table

        uint64_t ehdr_size = is_64 ? 64u : 52u;
        uint64_t phent_size = is_64 ? 56u : 32u;
        uint64_t shent_size = is_64 ? 64u : 40u;

        uint64_t phoff = (phdrs.empty()) ? 0 : ehdr_size;
        uint64_t data_start = ehdr_size + (uint64_t)phdrs.size() * phent_size;

        // Assign offsets to phdr segment data first
        uint64_t cursor = data_start;
        for (auto& ph : phdrs) {
            if (!ph.data.empty()) {
                // Align to 4
                cursor = (cursor + 3) & ~3ull;
                ph.p_offset = cursor;
                ph.p_filesz = ph.data.size();
                cursor += ph.data.size();
            }
        }

        // Assign offsets to section data
        for (size_t i = 1; i < sections.size(); i++) {
            cursor = (cursor + 3) & ~3ull;
            sections[i].sh_offset = cursor;
            sections[i].sh_size = sections[i].data.size();
            cursor += sections[i].data.size();
        }

        uint64_t shoff = (cursor + 7) & ~7ull; // align shdr table

        // ── Write ELF header ──
        // e_ident
        buf.push_back(0x7F); buf.push_back('E'); buf.push_back('L'); buf.push_back('F');
        buf.push_back(is_64 ? 2 : 1);           // EI_CLASS
        buf.push_back(big_endian ? 2 : 1);       // EI_DATA
        buf.push_back(1);                         // EI_VERSION
        buf.push_back(0);                         // EI_OSABI
        for (int i = 0; i < 8; i++) buf.push_back(0); // padding

        put16(e_type);
        put16(e_machine);
        put32(1);                                 // e_version
        put_addr(e_entry);
        put_addr(phdrs.empty() ? 0 : phoff);     // e_phoff
        put_addr(shoff);                          // e_shoff
        put32(0);                                 // e_flags
        put16((uint16_t)ehdr_size);               // e_ehsize
        put16((uint16_t)phent_size);              // e_phentsize
        put16((uint16_t)phdrs.size());            // e_phnum
        put16((uint16_t)shent_size);              // e_shentsize
        put16((uint16_t)sections.size());         // e_shnum
        put16(shstrndx);                          // e_shstrndx

        // ── Write program headers ──
        for (auto& ph : phdrs) {
            put32(ph.p_type);
            if (is_64) {
                put32(ph.p_flags);
                put64(ph.p_offset);
                put64(ph.p_vaddr);
                put64(ph.p_paddr);
                put64(ph.p_filesz);
                put64(ph.p_memsz);
                put64(ph.p_align);
            } else {
                put32((uint32_t)ph.p_offset);
                put32((uint32_t)ph.p_vaddr);
                put32((uint32_t)ph.p_paddr);
                put32((uint32_t)ph.p_filesz);
                put32((uint32_t)ph.p_memsz);
                put32(ph.p_flags);
                put32((uint32_t)ph.p_align);
            }
        }

        // ── Write phdr segment data ──
        for (auto& ph : phdrs) {
            if (!ph.data.empty()) {
                pad_to((size_t)ph.p_offset);
                buf.insert(buf.end(), ph.data.begin(), ph.data.end());
            }
        }

        // ── Write section data ──
        for (size_t i = 1; i < sections.size(); i++) {
            pad_to((size_t)sections[i].sh_offset);
            buf.insert(buf.end(), sections[i].data.begin(), sections[i].data.end());
        }

        // ── Write section header table ──
        pad_to((size_t)shoff);
        for (size_t i = 0; i < sections.size(); i++) {
            auto& sec = sections[i];
            put32(sec.sh_name);
            put32(sec.sh_type);
            put_addr(sec.sh_flags);
            put_addr(sec.sh_addr);
            put_addr(sec.sh_offset);
            put_addr(sec.sh_size);
            put32(sec.sh_link);
            put32(sec.sh_info);
            put_addr(sec.sh_addralign);
            put_addr(sec.sh_entsize);
        }

        return buf;
    }
};

// Helper to build a note entry
static std::vector<uint8_t> build_note(const char* name, uint32_t type,
                                        const uint8_t* desc, uint32_t descsz,
                                        bool big_endian)
{
    std::vector<uint8_t> out;
    uint32_t namesz = (uint32_t)strlen(name) + 1; // include null
    uint32_t namesz_aligned = (namesz + 3) & ~3u;
    uint32_t descsz_aligned = (descsz + 3) & ~3u;

    auto put32 = [&](uint32_t v) {
        if (big_endian) {
            out.push_back((uint8_t)(v >> 24));
            out.push_back((uint8_t)((v >> 16) & 0xFF));
            out.push_back((uint8_t)((v >> 8) & 0xFF));
            out.push_back((uint8_t)(v & 0xFF));
        } else {
            out.push_back((uint8_t)(v & 0xFF));
            out.push_back((uint8_t)((v >> 8) & 0xFF));
            out.push_back((uint8_t)((v >> 16) & 0xFF));
            out.push_back((uint8_t)(v >> 24));
        }
    };

    put32(namesz);
    put32(descsz);
    put32(type);

    // Name + padding
    for (uint32_t i = 0; i < namesz; i++)
        out.push_back((uint8_t)name[i]);
    for (uint32_t i = namesz; i < namesz_aligned; i++)
        out.push_back(0);

    // Desc + padding
    for (uint32_t i = 0; i < descsz; i++)
        out.push_back(desc[i]);
    for (uint32_t i = descsz; i < descsz_aligned; i++)
        out.push_back(0);

    return out;
}

// Helper to build ELF32/64 symbol entry
static std::vector<uint8_t> build_symbol(uint32_t st_name, uint64_t st_value,
                                          uint64_t st_size, uint8_t st_info,
                                          uint8_t st_other, uint16_t st_shndx,
                                          bool is_64, bool big_endian)
{
    std::vector<uint8_t> out;
    auto put16 = [&](uint16_t v) {
        if (big_endian) { out.push_back((uint8_t)(v >> 8)); out.push_back((uint8_t)(v & 0xFF)); }
        else { out.push_back((uint8_t)(v & 0xFF)); out.push_back((uint8_t)(v >> 8)); }
    };
    auto put32 = [&](uint32_t v) {
        if (big_endian) {
            out.push_back((uint8_t)(v >> 24)); out.push_back((uint8_t)((v >> 16) & 0xFF));
            out.push_back((uint8_t)((v >> 8) & 0xFF)); out.push_back((uint8_t)(v & 0xFF));
        } else {
            out.push_back((uint8_t)(v & 0xFF)); out.push_back((uint8_t)((v >> 8) & 0xFF));
            out.push_back((uint8_t)((v >> 16) & 0xFF)); out.push_back((uint8_t)(v >> 24));
        }
    };
    auto put64 = [&](uint64_t v) {
        if (big_endian) { for (int i = 7; i >= 0; i--) out.push_back((uint8_t)((v >> (i*8)) & 0xFF)); }
        else { for (int i = 0; i < 8; i++) out.push_back((uint8_t)((v >> (i*8)) & 0xFF)); }
    };

    if (is_64) {
        // ELF64: st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8) = 24
        put32(st_name);
        out.push_back(st_info);
        out.push_back(st_other);
        put16(st_shndx);
        put64(st_value);
        put64(st_size);
    } else {
        // ELF32: st_name(4), st_value(4), st_size(4), st_info(1), st_other(1), st_shndx(2) = 16
        put32(st_name);
        put32((uint32_t)st_value);
        put32((uint32_t)st_size);
        out.push_back(st_info);
        out.push_back(st_other);
        put16(st_shndx);
    }

    return out;
}

// Helper to build a dynamic entry
static std::vector<uint8_t> build_dynamic_entry(int64_t tag, uint64_t val,
                                                  bool is_64, bool big_endian)
{
    std::vector<uint8_t> out;
    auto put32 = [&](uint32_t v) {
        if (big_endian) {
            out.push_back((uint8_t)(v >> 24)); out.push_back((uint8_t)((v >> 16) & 0xFF));
            out.push_back((uint8_t)((v >> 8) & 0xFF)); out.push_back((uint8_t)(v & 0xFF));
        } else {
            out.push_back((uint8_t)(v & 0xFF)); out.push_back((uint8_t)((v >> 8) & 0xFF));
            out.push_back((uint8_t)((v >> 16) & 0xFF)); out.push_back((uint8_t)(v >> 24));
        }
    };
    auto put64 = [&](uint64_t v) {
        if (big_endian) { for (int i = 7; i >= 0; i--) out.push_back((uint8_t)((v >> (i*8)) & 0xFF)); }
        else { for (int i = 0; i < 8; i++) out.push_back((uint8_t)((v >> (i*8)) & 0xFF)); }
    };

    if (is_64) {
        put64((uint64_t)tag);
        put64(val);
    } else {
        put32((uint32_t)(int32_t)tag);
        put32((uint32_t)val);
    }
    return out;
}

// ── ELF header parsing tests ──────────────────────────────────────

TEST(ELFParse, ELF64LittleEndian)
{
    ElfBuilder eb(true, false);
    eb.e_type = 2;    // ET_EXEC
    eb.e_machine = 62; // EM_X86_64
    eb.e_entry = 0x401000;

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    EXPECT_TRUE(elf.valid);
    EXPECT_TRUE(elf.is_64);
    EXPECT_FALSE(elf.is_big_endian);
    EXPECT_EQ(elf.e_type, 2);
    EXPECT_EQ(elf.e_machine, 62);
    EXPECT_EQ(elf.e_entry, 0x401000u);
    EXPECT_EQ(elf.ei_data, AKAV_ELF_DATA_LSB);

    akav_elf_free(&elf);
}

TEST(ELFParse, ELF32LittleEndian)
{
    ElfBuilder eb(false, false);
    eb.e_type = 3;    // ET_DYN
    eb.e_machine = 3; // EM_386

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    EXPECT_TRUE(elf.valid);
    EXPECT_FALSE(elf.is_64);
    EXPECT_FALSE(elf.is_big_endian);
    EXPECT_EQ(elf.e_type, 3);
    EXPECT_EQ(elf.e_machine, 3);

    akav_elf_free(&elf);
}

TEST(ELFParse, ELF64BigEndian)
{
    ElfBuilder eb(true, true);
    eb.e_type = 2;
    eb.e_machine = 21;  // EM_PPC64
    eb.e_entry = 0x10000000;

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    EXPECT_TRUE(elf.valid);
    EXPECT_TRUE(elf.is_64);
    EXPECT_TRUE(elf.is_big_endian);
    EXPECT_EQ(elf.e_machine, 21);
    EXPECT_EQ(elf.e_entry, 0x10000000u);

    akav_elf_free(&elf);
}

TEST(ELFParse, ELF32BigEndian)
{
    ElfBuilder eb(false, true);
    eb.e_type = 2;
    eb.e_machine = 8;  // EM_MIPS

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    EXPECT_TRUE(elf.valid);
    EXPECT_FALSE(elf.is_64);
    EXPECT_TRUE(elf.is_big_endian);
    EXPECT_EQ(elf.e_machine, 8);

    akav_elf_free(&elf);
}

// ── Section tests ─────────────────────────────────────────────────

TEST(ELFSections, SectionNamesResolved)
{
    ElfBuilder eb(true, false);

    std::vector<uint8_t> code(64, 0xCC);
    eb.add_section(".text", 1, 6, code);   // SHT_PROGBITS, AX

    std::vector<uint8_t> bss_data;
    eb.add_section(".bss", 8, 3, bss_data); // SHT_NOBITS, WA

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    EXPECT_TRUE(elf.valid);

    // Section 0 is SHN_UNDEF, section 1 is .text, section 2 is .bss,
    // last is .shstrtab
    ASSERT_GE(elf.num_sections, 4);

    EXPECT_STREQ(elf.sections[1].name, ".text");
    EXPECT_EQ(elf.sections[1].sh_type, 1u);
    EXPECT_EQ(elf.sections[1].sh_size, 64u);

    EXPECT_STREQ(elf.sections[2].name, ".bss");
    EXPECT_EQ(elf.sections[2].sh_type, 8u);

    // Find by name
    const akav_elf_section_t* text = akav_elf_find_section(&elf, ".text");
    ASSERT_NE(text, nullptr);
    EXPECT_EQ(text->sh_size, 64u);

    EXPECT_EQ(akav_elf_find_section(&elf, ".nonexistent"), nullptr);

    akav_elf_free(&elf);
}

// ── Program header tests ──────────────────────────────────────────

TEST(ELFPhdrs, ProgramHeadersParsed)
{
    ElfBuilder eb(true, false);
    eb.add_phdr(1, 5, 0x400000, 0x1000, 0x1000);  // PT_LOAD, PF_R|PF_X
    eb.add_phdr(1, 6, 0x600000, 0x2000, 0x1000);  // PT_LOAD, PF_R|PF_W

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    EXPECT_TRUE(elf.valid);
    ASSERT_EQ(elf.num_phdrs, 2);
    EXPECT_EQ(elf.phdrs[0].p_type, 1u);
    EXPECT_EQ(elf.phdrs[0].p_vaddr, 0x400000u);
    EXPECT_EQ(elf.phdrs[1].p_vaddr, 0x600000u);

    akav_elf_free(&elf);
}

TEST(ELFPhdrs, ELF32ProgramHeaders)
{
    ElfBuilder eb(false, false);
    eb.add_phdr(1, 5, 0x08048000, 0x1000, 0x1000);

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    ASSERT_EQ(elf.num_phdrs, 1);
    EXPECT_EQ(elf.phdrs[0].p_vaddr, 0x08048000u);

    akav_elf_free(&elf);
}

// ── Symbol table tests ────────────────────────────────────────────

TEST(ELFSymtab, SymbolsParsed)
{
    ElfBuilder eb(true, false);

    // Build a string table for symbol names
    std::string strtab_str;
    strtab_str.push_back('\0');       // index 0
    uint32_t main_off = (uint32_t)strtab_str.size();
    strtab_str.append("main");
    strtab_str.push_back('\0');
    uint32_t printf_off = (uint32_t)strtab_str.size();
    strtab_str.append("printf");
    strtab_str.push_back('\0');

    std::vector<uint8_t> strtab_data(strtab_str.begin(), strtab_str.end());
    size_t strtab_idx = eb.add_section(".strtab", 3, 0, strtab_data); // SHT_STRTAB

    // Build symbol entries
    std::vector<uint8_t> symtab_data;
    // Sym 0: null symbol
    auto null_sym = build_symbol(0, 0, 0, 0, 0, 0, true, false);
    symtab_data.insert(symtab_data.end(), null_sym.begin(), null_sym.end());
    // Sym 1: main (STB_GLOBAL | STT_FUNC)
    auto main_sym = build_symbol(main_off, 0x401000, 128, (1 << 4) | 2, 0, 1, true, false);
    symtab_data.insert(symtab_data.end(), main_sym.begin(), main_sym.end());
    // Sym 2: printf (STB_GLOBAL | STT_FUNC)
    auto printf_sym = build_symbol(printf_off, 0, 0, (1 << 4) | 2, 0, 0, true, false);
    symtab_data.insert(symtab_data.end(), printf_sym.begin(), printf_sym.end());

    eb.add_section(".symtab", 2, 0, symtab_data,
                   (uint32_t)strtab_idx, 1, 24); // SHT_SYMTAB, link=strtab, entsize=24

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    ASSERT_TRUE(akav_elf_parse_symtab(&elf, data.data(), data.size()));

    ASSERT_GE(elf.num_symtab, 3u);
    EXPECT_STREQ(elf.symtab[1].name, "main");
    EXPECT_EQ(elf.symtab[1].st_value, 0x401000u);
    EXPECT_EQ(elf.symtab[1].binding, 1);  // STB_GLOBAL
    EXPECT_EQ(elf.symtab[1].type, 2);     // STT_FUNC

    EXPECT_STREQ(elf.symtab[2].name, "printf");

    akav_elf_free(&elf);
}

// ── Dynamic section tests ─────────────────────────────────────────

TEST(ELFDynamic, NeededLibraries)
{
    ElfBuilder eb(true, false);

    // Build .dynstr
    std::string dynstr;
    dynstr.push_back('\0');
    uint32_t libc_off = (uint32_t)dynstr.size();
    dynstr.append("libc.so.6");
    dynstr.push_back('\0');
    uint32_t libm_off = (uint32_t)dynstr.size();
    dynstr.append("libm.so.6");
    dynstr.push_back('\0');
    uint32_t soname_off = (uint32_t)dynstr.size();
    dynstr.append("mylib.so.1");
    dynstr.push_back('\0');

    std::vector<uint8_t> dynstr_data(dynstr.begin(), dynstr.end());
    size_t dynstr_idx = eb.add_section(".dynstr", 3, 0, dynstr_data);

    // Build .dynamic entries
    std::vector<uint8_t> dyn_data;
    auto e1 = build_dynamic_entry(1, libc_off, true, false);   // DT_NEEDED
    dyn_data.insert(dyn_data.end(), e1.begin(), e1.end());
    auto e2 = build_dynamic_entry(1, libm_off, true, false);   // DT_NEEDED
    dyn_data.insert(dyn_data.end(), e2.begin(), e2.end());
    auto e3 = build_dynamic_entry(14, soname_off, true, false); // DT_SONAME
    dyn_data.insert(dyn_data.end(), e3.begin(), e3.end());
    auto e4 = build_dynamic_entry(0, 0, true, false);           // DT_NULL
    dyn_data.insert(dyn_data.end(), e4.begin(), e4.end());

    eb.add_section(".dynamic", 6, 0, dyn_data,
                   (uint32_t)dynstr_idx, 0, 16); // SHT_DYNAMIC, link=dynstr

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    ASSERT_TRUE(akav_elf_parse_dynamic(&elf, data.data(), data.size()));

    ASSERT_EQ(elf.num_needed, 2u);
    EXPECT_STREQ(elf.needed[0], "libc.so.6");
    EXPECT_STREQ(elf.needed[1], "libm.so.6");
    EXPECT_STREQ(elf.soname, "mylib.so.1");

    akav_elf_free(&elf);
}

// ── Note tests ────────────────────────────────────────────────────

TEST(ELFNotes, BuildIdExtracted)
{
    ElfBuilder eb(true, false);

    uint8_t build_id_hash[] = {
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xde, 0xad, 0xbe, 0xef
    };

    auto note_data = build_note("GNU", 3, build_id_hash, 20, false); // NT_GNU_BUILD_ID = 3
    eb.add_section(".note.gnu.build-id", 7, 2, note_data); // SHT_NOTE, ALLOC

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    ASSERT_TRUE(akav_elf_parse_notes(&elf, data.data(), data.size()));

    EXPECT_TRUE(elf.has_build_id);
    EXPECT_EQ(elf.build_id_len, 20u);
    EXPECT_EQ(memcmp(elf.build_id, build_id_hash, 20), 0);
    ASSERT_GE(elf.num_notes, 1u);
    EXPECT_EQ(elf.notes[0].type, 3u);
    EXPECT_STREQ(elf.notes[0].name, "GNU");

    akav_elf_free(&elf);
}

// ── Interpreter tests ─────────────────────────────────────────────

TEST(ELFInterp, InterpreterParsed)
{
    ElfBuilder eb(true, false);

    const char* interp_path = "/lib64/ld-linux-x86-64.so.2";
    std::vector<uint8_t> interp_data(interp_path, interp_path + strlen(interp_path) + 1);
    eb.add_phdr(3, 4, 0, 0, 1, interp_data); // PT_INTERP, PF_R

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    ASSERT_TRUE(akav_elf_parse_interp(&elf, data.data(), data.size()));

    EXPECT_STREQ(elf.interp, "/lib64/ld-linux-x86-64.so.2");

    akav_elf_free(&elf);
}

// ── Convenience analyze test ──────────────────────────────────────

TEST(ELFAnalyze, FullAnalysis)
{
    ElfBuilder eb(true, false);
    eb.e_type = 3; // ET_DYN (shared object / PIE)

    // Add a .text section
    std::vector<uint8_t> code(128, 0x90); // NOP sled
    eb.add_section(".text", 1, 6, code);

    // Add interpreter
    const char* interp_path = "/lib64/ld-linux-x86-64.so.2";
    std::vector<uint8_t> interp_data(interp_path, interp_path + strlen(interp_path) + 1);
    eb.add_phdr(3, 4, 0, 0, 1, interp_data);

    // Add a note
    uint8_t bid[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    auto note_data = build_note("GNU", 3, bid, 4, false);
    eb.add_section(".note.gnu.build-id", 7, 2, note_data);

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));

    akav_elf_analyze(&elf, data.data(), data.size());

    EXPECT_STREQ(elf.interp, "/lib64/ld-linux-x86-64.so.2");
    EXPECT_TRUE(elf.has_build_id);
    EXPECT_EQ(elf.build_id_len, 4u);

    akav_elf_free(&elf);
}

// ── Error handling tests ──────────────────────────────────────────

TEST(ELFParse, NullInput)
{
    akav_elf_t elf;
    EXPECT_FALSE(akav_elf_parse(&elf, nullptr, 0));
    EXPECT_FALSE(elf.valid);
}

TEST(ELFParse, NullElfStruct)
{
    uint8_t data[64] = {};
    EXPECT_FALSE(akav_elf_parse(nullptr, data, sizeof(data)));
}

TEST(ELFParse, TooSmall)
{
    uint8_t data[8] = { 0x7F, 'E', 'L', 'F', 2, 1, 1, 0 };
    akav_elf_t elf;
    EXPECT_FALSE(akav_elf_parse(&elf, data, sizeof(data)));
}

TEST(ELFParse, BadMagic)
{
    uint8_t data[64] = {};
    data[0] = 'M'; data[1] = 'Z'; // PE magic, not ELF
    akav_elf_t elf;
    EXPECT_FALSE(akav_elf_parse(&elf, data, sizeof(data)));
    EXPECT_FALSE(elf.valid);
}

TEST(ELFParse, TruncatedHeader)
{
    // Valid ELF ident but not enough data for full header
    uint8_t data[20] = {};
    data[0] = 0x7F; data[1] = 'E'; data[2] = 'L'; data[3] = 'F';
    data[4] = 2;  // ELFCLASS64
    data[5] = 1;  // ELFDATA2LSB
    data[6] = 1;  // EV_CURRENT
    // Rest is zeros, but buffer too small for full ELF64 header (64 bytes)

    akav_elf_t elf;
    EXPECT_FALSE(akav_elf_parse(&elf, data, sizeof(data)));
}

TEST(ELFParse, BadClass)
{
    uint8_t data[64] = {};
    data[0] = 0x7F; data[1] = 'E'; data[2] = 'L'; data[3] = 'F';
    data[4] = 99;  // invalid class
    data[5] = 1;

    akav_elf_t elf;
    EXPECT_FALSE(akav_elf_parse(&elf, data, sizeof(data)));
}

TEST(ELFParse, BadEndian)
{
    uint8_t data[64] = {};
    data[0] = 0x7F; data[1] = 'E'; data[2] = 'L'; data[3] = 'F';
    data[4] = 1;   // ELFCLASS32
    data[5] = 99;  // invalid data encoding

    akav_elf_t elf;
    EXPECT_FALSE(akav_elf_parse(&elf, data, sizeof(data)));
}

// ── Machine name tests ────────────────────────────────────────────

TEST(ELFNames, MachineNames)
{
    EXPECT_STREQ(akav_elf_machine_name(62), "AMD x86-64");
    EXPECT_STREQ(akav_elf_machine_name(3), "Intel 80386");
    EXPECT_STREQ(akav_elf_machine_name(183), "AArch64");
    EXPECT_STREQ(akav_elf_machine_name(40), "ARM");
    EXPECT_STREQ(akav_elf_machine_name(0xFFFF), "Unknown");
}

TEST(ELFNames, TypeNames)
{
    EXPECT_STREQ(akav_elf_type_name(2), "EXEC (Executable)");
    EXPECT_STREQ(akav_elf_type_name(3), "DYN (Shared object)");
    EXPECT_STREQ(akav_elf_type_name(99), "Unknown");
}

// ── Free safety tests ─────────────────────────────────────────────

TEST(ELFFree, NullSafe)
{
    akav_elf_free(nullptr);  // should not crash
}

TEST(ELFFree, DoubleFree)
{
    akav_elf_t elf;
    memset(&elf, 0, sizeof(elf));
    akav_elf_free(&elf);
    akav_elf_free(&elf);  // should not crash
}

// ── Dynsym test ───────────────────────────────────────────────────

TEST(ELFDynsym, DynSymbolsParsed)
{
    ElfBuilder eb(true, false);

    // Build .dynstr
    std::string dynstr;
    dynstr.push_back('\0');
    uint32_t puts_off = (uint32_t)dynstr.size();
    dynstr.append("puts");
    dynstr.push_back('\0');

    std::vector<uint8_t> dynstr_data(dynstr.begin(), dynstr.end());
    size_t dynstr_idx = eb.add_section(".dynstr", 3, 2, dynstr_data);

    // Build .dynsym
    std::vector<uint8_t> dynsym_data;
    auto null_sym = build_symbol(0, 0, 0, 0, 0, 0, true, false);
    dynsym_data.insert(dynsym_data.end(), null_sym.begin(), null_sym.end());
    auto puts_sym = build_symbol(puts_off, 0, 0, (1 << 4) | 2, 0, 0, true, false);
    dynsym_data.insert(dynsym_data.end(), puts_sym.begin(), puts_sym.end());

    eb.add_section(".dynsym", 11, 2, dynsym_data,
                   (uint32_t)dynstr_idx, 1, 24);

    auto data = eb.build();

    akav_elf_t elf;
    ASSERT_TRUE(akav_elf_parse(&elf, data.data(), data.size()));
    ASSERT_TRUE(akav_elf_parse_dynsym(&elf, data.data(), data.size()));

    ASSERT_GE(elf.num_dynsym, 2u);
    EXPECT_STREQ(elf.dynsym[1].name, "puts");
    EXPECT_EQ(elf.dynsym[1].binding, 1);
    EXPECT_EQ(elf.dynsym[1].type, 2);

    akav_elf_free(&elf);
}

// ── Big-endian reader tests ───────────────────────────────────────

TEST(SafeReaderBE, ReadU16BE)
{
    uint8_t data[] = { 0x12, 0x34 };
    akav_safe_reader_t r;
    akav_reader_init(&r, data, sizeof(data));
    uint16_t v;
    ASSERT_TRUE(akav_reader_read_u16_be(&r, &v));
    EXPECT_EQ(v, 0x1234);
}

TEST(SafeReaderBE, ReadU32BE)
{
    uint8_t data[] = { 0x12, 0x34, 0x56, 0x78 };
    akav_safe_reader_t r;
    akav_reader_init(&r, data, sizeof(data));
    uint32_t v;
    ASSERT_TRUE(akav_reader_read_u32_be(&r, &v));
    EXPECT_EQ(v, 0x12345678u);
}

TEST(SafeReaderBE, ReadU64BE)
{
    uint8_t data[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    akav_safe_reader_t r;
    akav_reader_init(&r, data, sizeof(data));
    uint64_t v;
    ASSERT_TRUE(akav_reader_read_u64_be(&r, &v));
    EXPECT_EQ(v, 0x0123456789ABCDEFull);
}
