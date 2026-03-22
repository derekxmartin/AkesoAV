/* create_test_db.cpp -- Standalone utility to create a test .akavdb file
 * with EICAR detection signatures (MD5 + Aho-Corasick).
 *
 * Build: cl /EHsc /std:c++20 /I..\include /I..\src create_test_db.cpp /Fe:create_test_db.exe
 * Usage: create_test_db.exe [output_path]
 *        Default output: testdata\test.akavdb
 *
 * This is a standalone tool -- does NOT link against the engine.
 * It manually constructs the binary .akavdb format.
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

/* EICAR test string */
static const char EICAR[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
static const size_t EICAR_LEN = 68;

/* ── Minimal MD5 (matches BCrypt output) ────────────────────────── */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

static bool compute_md5(const uint8_t* data, size_t len, uint8_t out[16])
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
            if (BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0) == 0) {
                if (BCryptFinishHash(hash, out, 16, 0) == 0) {
                    ok = true;
                }
            }
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return ok;
}

/* ── .akavdb format helpers ─────────────────────────────────────── */

static void push_u16(std::vector<uint8_t>& v, uint16_t val) {
    v.push_back((uint8_t)(val & 0xFF));
    v.push_back((uint8_t)((val >> 8) & 0xFF));
}

static void push_u32(std::vector<uint8_t>& v, uint32_t val) {
    v.push_back((uint8_t)(val & 0xFF));
    v.push_back((uint8_t)((val >> 8) & 0xFF));
    v.push_back((uint8_t)((val >> 16) & 0xFF));
    v.push_back((uint8_t)((val >> 24) & 0xFF));
}

static void push_bytes(std::vector<uint8_t>& v, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    v.insert(v.end(), p, p + len);
}

/* Section type constants */
enum {
    SECTION_MD5          = 1,
    SECTION_AHO_CORASICK = 4,
    SECTION_STRING_TABLE = 0xFF
};

/* ── Build .akavdb with EICAR signatures ────────────────────────── */

static std::vector<uint8_t> build_eicar_db()
{
    /* String table: "EICAR-Test-File\0" */
    const std::string name = "EICAR-Test-File";
    std::vector<uint8_t> strtab(name.begin(), name.end());
    strtab.push_back(0);

    /* MD5 of EICAR */
    uint8_t eicar_md5[16];
    compute_md5((const uint8_t*)EICAR, EICAR_LEN, eicar_md5);

    /* MD5 entry: 16 bytes hash + 4 bytes name_index */
    std::vector<uint8_t> md5_section;
    push_bytes(md5_section, eicar_md5, 16);
    push_u32(md5_section, 0); /* name_index = 0 */

    /* Aho-Corasick section: minimal single-pattern automaton
     * Format: uint32 pattern_count, then for each pattern:
     *   uint32 pattern_len, bytes[pattern_len], uint32 pattern_id (=name_index)
     * Then: uint32 state_count (=0 for flat scan fallback) */
    std::vector<uint8_t> ac_section;
    push_u32(ac_section, 1); /* pattern_count */
    push_u32(ac_section, (uint32_t)EICAR_LEN);
    push_bytes(ac_section, EICAR, EICAR_LEN);
    push_u32(ac_section, 0); /* pattern_id = name_index 0 */
    push_u32(ac_section, 0); /* state_count = 0 (use build-from-patterns mode) */

    /* File header:
     * magic[8] = "AKAVDB\x01\x00"
     * version: uint16 = 1
     * section_count: uint16
     * total_signatures: uint32
     * timestamp: uint32
     * reserved: uint32
     *
     * Then section_count section entries:
     *   type: uint8
     *   offset: uint32
     *   size: uint32
     *   entry_count: uint32
     */
    const uint16_t section_count = 3; /* MD5, AC, string table */
    const uint32_t header_size = 8 + 2 + 2 + 4 + 4 + 4; /* 24 bytes */
    const uint32_t entry_size = 1 + 4 + 4 + 4; /* 13 bytes per section entry */
    const uint32_t entries_size = section_count * entry_size;

    uint32_t data_offset = header_size + entries_size;
    uint32_t md5_offset = data_offset;
    uint32_t ac_offset = md5_offset + (uint32_t)md5_section.size();
    uint32_t strtab_offset = ac_offset + (uint32_t)ac_section.size();

    std::vector<uint8_t> db;

    /* Header */
    push_bytes(db, "AKAVDB\x01\x00", 8);
    push_u16(db, 1); /* version */
    push_u16(db, section_count);
    push_u32(db, 2); /* total_signatures (1 MD5 + 1 AC pattern) */
    push_u32(db, 0); /* timestamp */
    push_u32(db, 0); /* reserved */

    /* Section entries */
    /* MD5 */
    db.push_back(SECTION_MD5);
    push_u32(db, md5_offset);
    push_u32(db, (uint32_t)md5_section.size());
    push_u32(db, 1); /* entry_count */

    /* Aho-Corasick */
    db.push_back(SECTION_AHO_CORASICK);
    push_u32(db, ac_offset);
    push_u32(db, (uint32_t)ac_section.size());
    push_u32(db, 1);

    /* String table */
    db.push_back(SECTION_STRING_TABLE);
    push_u32(db, strtab_offset);
    push_u32(db, (uint32_t)strtab.size());
    push_u32(db, 1);

    /* Section data */
    push_bytes(db, md5_section.data(), md5_section.size());
    push_bytes(db, ac_section.data(), ac_section.size());
    push_bytes(db, strtab.data(), strtab.size());

    return db;
}

/* ── Main ───────────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    const char* output = "testdata\\test.akavdb";
    if (argc > 1) output = argv[1];

    auto db = build_eicar_db();

    FILE* f = nullptr;
    if (fopen_s(&f, output, "wb") != 0 || !f) {
        fprintf(stderr, "Failed to open: %s\n", output);
        return 1;
    }

    fwrite(db.data(), 1, db.size(), f);
    fclose(f);

    printf("Created %s (%zu bytes, EICAR MD5 + AC signatures)\n",
           output, db.size());
    return 0;
}
