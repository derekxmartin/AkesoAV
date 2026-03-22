/* create_test_db.cpp -- Standalone utility to create a test .akavdb file
 * with EICAR detection signatures (MD5 + Aho-Corasick).
 *
 * Build: part of CMake build (target: create_test_db)
 * Usage: create_test_db.exe [output_path]
 *        Default output: testdata\test.akavdb
 *
 * Links against akesoav_core to use the real AC serializer and BCrypt MD5.
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

/* Engine headers for real formats */
#include "database/sigdb.h"
#include "signatures/hash_matcher.h"
#include "signatures/aho_corasick.h"

/* EICAR test string (standard 68-byte form) */
static const char EICAR[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
static const size_t EICAR_LEN = 68;

/* ── MD5 via BCrypt ──────────────────────────────────────────────── */

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

/* ── Helpers ─────────────────────────────────────────────────────── */

static void push_u32(std::vector<uint8_t>& v, uint32_t val) {
    v.push_back((uint8_t)(val & 0xFF));
    v.push_back((uint8_t)((val >> 8) & 0xFF));
    v.push_back((uint8_t)((val >> 16) & 0xFF));
    v.push_back((uint8_t)((val >> 24) & 0xFF));
}

static void push_i64(std::vector<uint8_t>& v, int64_t val) {
    for (int i = 0; i < 8; i++)
        v.push_back((uint8_t)((val >> (i * 8)) & 0xFF));
}

static void push_bytes(std::vector<uint8_t>& v, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    v.insert(v.end(), p, p + len);
}

static void push_zeros(std::vector<uint8_t>& v, size_t count) {
    for (size_t i = 0; i < count; i++)
        v.push_back(0);
}

/* ── Build .akavdb ───────────────────────────────────────────────── */

static std::vector<uint8_t> build_eicar_db()
{
    /* 1. String table: "EICAR-Test-File\0" */
    const std::string name = "EICAR-Test-File";
    std::vector<uint8_t> strtab(name.begin(), name.end());
    strtab.push_back(0);

    /* 2. MD5 of EICAR -> akav_md5_entry_t: 16 bytes hash + 4 bytes name_index */
    uint8_t eicar_md5[16];
    if (!compute_md5((const uint8_t*)EICAR, EICAR_LEN, eicar_md5)) {
        fprintf(stderr, "Failed to compute MD5\n");
        return {};
    }

    std::vector<uint8_t> md5_section;
    push_bytes(md5_section, eicar_md5, 16);  /* hash[16] */
    push_u32(md5_section, 0);                /* name_index = 0 */

    /* 3. Aho-Corasick: build automaton with real API, then serialize */
    akav_ac_t* ac = akav_ac_create();
    if (!ac) {
        fprintf(stderr, "Failed to create AC automaton\n");
        return {};
    }

    /* pattern_id = 0 (name_index into string table) */
    if (!akav_ac_add_pattern(ac, (const uint8_t*)EICAR, (uint32_t)EICAR_LEN, 0)) {
        fprintf(stderr, "Failed to add EICAR pattern\n");
        akav_ac_destroy(ac);
        return {};
    }

    if (!akav_ac_finalize(ac)) {
        fprintf(stderr, "Failed to finalize AC automaton\n");
        akav_ac_destroy(ac);
        return {};
    }

    /* Get serialization size, then serialize */
    size_t ac_size = akav_ac_serialize(ac, nullptr, 0);
    std::vector<uint8_t> ac_section(ac_size);
    akav_ac_serialize(ac, ac_section.data(), ac_section.size());
    akav_ac_destroy(ac);

    /* 4. Build the file
     *
     * Layout:
     *   [280 bytes]  akav_db_header_t (magic, version, sig_count, created_at,
     *                                   section_count, rsa_signature[256])
     *   [N * 16]     section offset table (akav_db_section_entry_t per section)
     *   [...]        section data (MD5, AC, string table)
     */
    const uint32_t section_count = 3;  /* MD5, AC, string table */
    const uint32_t section_table_size = section_count * 16;
    const uint32_t data_start = AKAV_DB_HEADER_SIZE + section_table_size;

    uint32_t md5_offset    = data_start;
    uint32_t ac_offset     = md5_offset + (uint32_t)md5_section.size();
    uint32_t strtab_offset = ac_offset  + (uint32_t)ac_section.size();

    std::vector<uint8_t> db;

    /* ── Header (280 bytes) ── */
    push_u32(db, AKAV_DB_MAGIC);                  /* magic */
    push_u32(db, AKAV_DB_VERSION);                /* version */
    push_u32(db, 2);                              /* signature_count (1 MD5 + 1 AC) */
    push_i64(db, (int64_t)time(nullptr));         /* created_at */
    push_u32(db, section_count);                  /* section_count */
    push_zeros(db, AKAV_DB_RSA_SIG_SIZE);         /* rsa_signature (zeros = unsigned) */

    /* Verify header size matches constant */
    if (db.size() != AKAV_DB_HEADER_SIZE) {
        fprintf(stderr, "BUG: header size %zu != expected %u\n",
                db.size(), AKAV_DB_HEADER_SIZE);
        return {};
    }

    /* ── Section offset table ── */
    /* Entry 0: MD5 */
    push_u32(db, AKAV_SECTION_MD5);
    push_u32(db, md5_offset);
    push_u32(db, (uint32_t)md5_section.size());
    push_u32(db, 1);  /* entry_count */

    /* Entry 1: Aho-Corasick */
    push_u32(db, AKAV_SECTION_AHO_CORASICK);
    push_u32(db, ac_offset);
    push_u32(db, (uint32_t)ac_section.size());
    push_u32(db, 1);

    /* Entry 2: String table */
    push_u32(db, AKAV_SECTION_STRING_TABLE);
    push_u32(db, strtab_offset);
    push_u32(db, (uint32_t)strtab.size());
    push_u32(db, 1);

    /* ── Section data ── */
    push_bytes(db, md5_section.data(), md5_section.size());
    push_bytes(db, ac_section.data(), ac_section.size());
    push_bytes(db, strtab.data(), strtab.size());

    return db;
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    const char* output = "testdata\\test.akavdb";
    if (argc > 1) output = argv[1];

    auto db = build_eicar_db();
    if (db.empty()) {
        fprintf(stderr, "Failed to build database\n");
        return 1;
    }

    FILE* f = nullptr;
    if (fopen_s(&f, output, "wb") != 0 || !f) {
        fprintf(stderr, "Failed to open: %s\n", output);
        return 1;
    }

    fwrite(db.data(), 1, db.size(), f);
    fclose(f);

    printf("Created %s (%zu bytes, EICAR MD5 + AC signatures)\n",
           output, db.size());

    /* Print MD5 for verification */
    uint8_t md5[16];
    compute_md5((const uint8_t*)EICAR, EICAR_LEN, md5);
    printf("EICAR MD5: ");
    for (int i = 0; i < 16; i++) printf("%02x", md5[i]);
    printf("\n");

    return 0;
}
