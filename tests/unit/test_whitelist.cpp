/* test_whitelist.cpp -- Unit tests for whitelist/exclusion mechanism (P5-T2).
 *
 * Tests:
 *   1. Hash whitelist: add, lookup, duplicate, not-found
 *   2. Path exclusions: prefix match, case insensitive, slash normalization
 *   3. Signer trust: MS-signed calc.exe, unsigned file
 *   4. Clear: resets all lists
 *   5. Stats: correct counts
 *   6. Engine integration: path excluded -> not scanned, hash whitelisted -> skip,
 *      signer trusted -> in_whitelist=1, whitelist disabled -> normal scan,
 *      clear -> no longer whitelisted
 *   7. Thread safety: concurrent add/check
 */

#include <gtest/gtest.h>

#include "whitelist.h"
#include "engine_internal.h"
#include "signatures/hash_matcher.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstring>
#include <thread>
#include <vector>
#include <cstdio>

/* ── Whitelist unit tests ──────────────────────────────────────── */

class WhitelistTest : public ::testing::Test {
protected:
    akav::Whitelist wl;
};

TEST_F(WhitelistTest, HashAddAndLookup)
{
    uint8_t hash[32];
    memset(hash, 0xAA, 32);

    EXPECT_FALSE(wl.is_hash_whitelisted(hash));
    wl.add_hash(hash);
    EXPECT_TRUE(wl.is_hash_whitelisted(hash));
}

TEST_F(WhitelistTest, HashNotFound)
{
    uint8_t hash1[32], hash2[32];
    memset(hash1, 0xAA, 32);
    memset(hash2, 0xBB, 32);

    wl.add_hash(hash1);
    EXPECT_FALSE(wl.is_hash_whitelisted(hash2));
}

TEST_F(WhitelistTest, HashDuplicateAdd)
{
    uint8_t hash[32];
    memset(hash, 0xCC, 32);

    wl.add_hash(hash);
    wl.add_hash(hash);  /* Duplicate — should not crash or double-insert */

    uint32_t hc = 0, pc = 0, sc = 0;
    wl.stats(&hc, &pc, &sc);
    EXPECT_EQ(hc, 1u);
    EXPECT_TRUE(wl.is_hash_whitelisted(hash));
}

TEST_F(WhitelistTest, HashMultipleSorted)
{
    /* Insert in reverse order to test sorted insertion */
    uint8_t h1[32], h2[32], h3[32];
    memset(h1, 0xFF, 32);
    memset(h2, 0x80, 32);
    memset(h3, 0x00, 32);

    wl.add_hash(h1);
    wl.add_hash(h2);
    wl.add_hash(h3);

    EXPECT_TRUE(wl.is_hash_whitelisted(h1));
    EXPECT_TRUE(wl.is_hash_whitelisted(h2));
    EXPECT_TRUE(wl.is_hash_whitelisted(h3));

    uint8_t h_miss[32];
    memset(h_miss, 0x40, 32);
    EXPECT_FALSE(wl.is_hash_whitelisted(h_miss));
}

TEST_F(WhitelistTest, HashNullSafety)
{
    EXPECT_FALSE(wl.is_hash_whitelisted(nullptr));
    wl.add_hash(nullptr);  /* Should not crash */
}

TEST_F(WhitelistTest, PathExclusionBasic)
{
    wl.add_path("C:\\Windows\\Temp");
    EXPECT_TRUE(wl.is_path_excluded("C:\\Windows\\Temp\\malware.exe"));
    EXPECT_TRUE(wl.is_path_excluded("C:\\Windows\\Temp"));
    EXPECT_FALSE(wl.is_path_excluded("C:\\Windows\\System32\\cmd.exe"));
}

TEST_F(WhitelistTest, PathExclusionCaseInsensitive)
{
    wl.add_path("C:\\WINDOWS\\TEMP");
    EXPECT_TRUE(wl.is_path_excluded("c:\\windows\\temp\\file.txt"));
    EXPECT_TRUE(wl.is_path_excluded("C:\\Windows\\Temp\\file.txt"));
}

TEST_F(WhitelistTest, PathExclusionSlashNormalization)
{
    wl.add_path("C:/Program Files/AkesoAV");
    EXPECT_TRUE(wl.is_path_excluded("C:\\Program Files\\AkesoAV\\akesoav.dll"));
}

TEST_F(WhitelistTest, PathExclusionMultiple)
{
    wl.add_path("C:\\Excluded1");
    wl.add_path("C:\\Excluded2");

    EXPECT_TRUE(wl.is_path_excluded("C:\\Excluded1\\file.txt"));
    EXPECT_TRUE(wl.is_path_excluded("C:\\Excluded2\\file.txt"));
    EXPECT_FALSE(wl.is_path_excluded("C:\\Excluded3\\file.txt"));
}

TEST_F(WhitelistTest, PathExclusionDuplicate)
{
    wl.add_path("C:\\Test");
    wl.add_path("C:\\Test");

    uint32_t hc = 0, pc = 0, sc = 0;
    wl.stats(&hc, &pc, &sc);
    EXPECT_EQ(pc, 1u);
}

TEST_F(WhitelistTest, PathExclusionNullSafety)
{
    EXPECT_FALSE(wl.is_path_excluded(nullptr));
    EXPECT_FALSE(wl.is_path_excluded(""));
    wl.add_path(nullptr);  /* Should not crash */
    wl.add_path("");        /* Should not add */

    uint32_t hc = 0, pc = 0, sc = 0;
    wl.stats(&hc, &pc, &sc);
    EXPECT_EQ(pc, 0u);
}

TEST_F(WhitelistTest, SignerAddAndList)
{
    wl.add_signer("Test Publisher");

    uint32_t hc = 0, pc = 0, sc = 0;
    wl.stats(&hc, &pc, &sc);
    EXPECT_EQ(sc, 1u);
}

TEST_F(WhitelistTest, SignerDuplicate)
{
    wl.add_signer("Microsoft Corporation");
    wl.add_signer("microsoft corporation");  /* Case-insensitive duplicate */

    uint32_t hc = 0, pc = 0, sc = 0;
    wl.stats(&hc, &pc, &sc);
    EXPECT_EQ(sc, 1u);
}

TEST_F(WhitelistTest, SignerNullSafety)
{
    EXPECT_FALSE(wl.is_signer_trusted(nullptr));
    wl.add_signer(nullptr);  /* Should not crash */

    uint32_t hc = 0, pc = 0, sc = 0;
    wl.stats(&hc, &pc, &sc);
    EXPECT_EQ(sc, 0u);
}

TEST_F(WhitelistTest, SignerNoSignersConfigured)
{
    /* With no signers, should return false without calling WinVerifyTrust */
    EXPECT_FALSE(wl.is_signer_trusted("C:\\Windows\\System32\\calc.exe"));
}

TEST_F(WhitelistTest, ClearResetsAll)
{
    uint8_t hash[32];
    memset(hash, 0xDD, 32);
    wl.add_hash(hash);
    wl.add_path("C:\\Test");
    wl.add_signer("Test");

    wl.clear();

    uint32_t hc = 0, pc = 0, sc = 0;
    wl.stats(&hc, &pc, &sc);
    EXPECT_EQ(hc, 0u);
    EXPECT_EQ(pc, 0u);
    EXPECT_EQ(sc, 0u);

    EXPECT_FALSE(wl.is_hash_whitelisted(hash));
    EXPECT_FALSE(wl.is_path_excluded("C:\\Test\\file.txt"));
}

TEST_F(WhitelistTest, StatsAccurate)
{
    uint8_t h1[32], h2[32];
    memset(h1, 0x11, 32);
    memset(h2, 0x22, 32);

    wl.add_hash(h1);
    wl.add_hash(h2);
    wl.add_path("C:\\Path1");
    wl.add_path("C:\\Path2");
    wl.add_path("C:\\Path3");
    wl.add_signer("Signer1");

    uint32_t hc = 0, pc = 0, sc = 0;
    wl.stats(&hc, &pc, &sc);
    EXPECT_EQ(hc, 2u);
    EXPECT_EQ(pc, 3u);
    EXPECT_EQ(sc, 1u);
}

/* ── Signer trust with real files ──────────────────────────────── */

TEST_F(WhitelistTest, SignerTrustMicrosoftSigned)
{
    /* Add both common Microsoft signer names */
    wl.add_signer("Microsoft Windows");
    wl.add_signer("Microsoft Corporation");
    wl.add_signer("Microsoft Windows Publisher");

    /* Try notepad.exe first (always present), fall back to calc.exe */
    const char* candidates[] = {
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\calc.exe",
        "C:\\Windows\\notepad.exe",
    };

    bool found_signed = false;
    for (const char* path : candidates) {
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
            /* Debug: check if WinVerifyTrust sees a valid signature */
            if (wl.is_signer_trusted(path)) {
                found_signed = true;
                printf("  [info] %s is MS-signed and trusted\n", path);
                break;
            } else {
                printf("  [info] %s exists but not trusted (signer mismatch or unsigned)\n", path);
            }
        }
    }

    EXPECT_TRUE(found_signed) << "Expected at least one MS-signed system binary";
}

TEST_F(WhitelistTest, SignerTrustUnsignedFile)
{
    wl.add_signer("Microsoft Corporation");

    /* Create a temp file — it won't be Authenticode signed */
    char temp_path[MAX_PATH];
    char temp_dir[MAX_PATH];
    GetTempPathA(sizeof(temp_dir), temp_dir);
    GetTempFileNameA(temp_dir, "akav", 0, temp_path);

    /* Write some content */
    HANDLE hf = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ASSERT_NE(hf, INVALID_HANDLE_VALUE);
    const char* data = "not a signed binary";
    DWORD written = 0;
    WriteFile(hf, data, (DWORD)strlen(data), &written, NULL);
    CloseHandle(hf);

    EXPECT_FALSE(wl.is_signer_trusted(temp_path));

    DeleteFileA(temp_path);
}

TEST_F(WhitelistTest, SignerTrustNonexistentFile)
{
    wl.add_signer("Microsoft Corporation");
    EXPECT_FALSE(wl.is_signer_trusted("C:\\nonexistent_file_akav_test.exe"));
}

TEST_F(WhitelistTest, SignerTrustWrongSigner)
{
    /* Only trust a signer that doesn't match any real binary */
    wl.add_signer("FakeCorp Nonexistent Publisher");

    const char* path = "C:\\Windows\\System32\\notepad.exe";
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
        EXPECT_FALSE(wl.is_signer_trusted(path));
    }
}

/* ── Thread safety ─────────────────────────────────────────────── */

TEST_F(WhitelistTest, ConcurrentHashAddAndCheck)
{
    const int NUM_THREADS = 4;
    const int HASHES_PER_THREAD = 100;

    std::vector<std::thread> threads;

    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([this, t]() {
            for (int i = 0; i < HASHES_PER_THREAD; ++i) {
                uint8_t hash[32];
                memset(hash, 0, 32);
                hash[0] = (uint8_t)t;
                hash[1] = (uint8_t)i;
                wl.add_hash(hash);
            }
        });
    }

    for (auto& th : threads) th.join();

    /* Verify all hashes are findable */
    for (int t = 0; t < NUM_THREADS; ++t) {
        for (int i = 0; i < HASHES_PER_THREAD; ++i) {
            uint8_t hash[32];
            memset(hash, 0, 32);
            hash[0] = (uint8_t)t;
            hash[1] = (uint8_t)i;
            EXPECT_TRUE(wl.is_hash_whitelisted(hash))
                << "Missing hash t=" << t << " i=" << i;
        }
    }
}

/* ── Engine integration tests ──────────────────────────────────── */

class WhitelistEngineTest : public ::testing::Test {
protected:
    akav_engine_t* engine = nullptr;

    void SetUp() override {
        ASSERT_EQ(akav_engine_create(&engine), AKAV_OK);
        ASSERT_EQ(akav_engine_init(engine, nullptr), AKAV_OK);
    }

    void TearDown() override {
        if (engine) akav_engine_destroy(engine);
    }

    /* Create a temp file with given content, return path */
    std::string create_temp_file(const char* content, size_t len) {
        char temp_dir[MAX_PATH];
        char temp_path[MAX_PATH];
        GetTempPathA(sizeof(temp_dir), temp_dir);
        GetTempFileNameA(temp_dir, "akwl", 0, temp_path);

        HANDLE hf = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(hf, content, (DWORD)len, &written, NULL);
            CloseHandle(hf);
        }
        return temp_path;
    }

    void delete_file(const std::string& path) {
        DeleteFileA(path.c_str());
    }
};

TEST_F(WhitelistEngineTest, PathExcludedSkipsScan)
{
    /* Add a path exclusion */
    char temp_dir[MAX_PATH];
    GetTempPathA(sizeof(temp_dir), temp_dir);
    akav_whitelist_add_path(engine, temp_dir);

    /* Create a temp file in the excluded directory */
    const char* content = "test content";
    std::string path = create_temp_file(content, strlen(content));

    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_whitelist = 1;

    akav_scan_result_t result;
    EXPECT_EQ(akav_scan_file(engine, path.c_str(), &opts, &result), AKAV_OK);
    EXPECT_EQ(result.in_whitelist, 1);
    EXPECT_EQ(result.found, 0);

    delete_file(path);
}

TEST_F(WhitelistEngineTest, PathExclusionDisabledScansNormally)
{
    char temp_dir[MAX_PATH];
    GetTempPathA(sizeof(temp_dir), temp_dir);
    akav_whitelist_add_path(engine, temp_dir);

    const char* content = "test content for normal scan";
    std::string path = create_temp_file(content, strlen(content));

    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_whitelist = 0;  /* Whitelist disabled */

    akav_scan_result_t result;
    EXPECT_EQ(akav_scan_file(engine, path.c_str(), &opts, &result), AKAV_OK);
    EXPECT_EQ(result.in_whitelist, 0);  /* Not whitelisted because disabled */

    delete_file(path);
}

TEST_F(WhitelistEngineTest, HashWhitelistSkipsScan)
{
    /* Create a temp file */
    const char* content = "known clean file content for hash test";
    std::string path = create_temp_file(content, strlen(content));

    /* Compute its SHA-256 */
    uint8_t sha[32];
    ASSERT_TRUE(akav_hash_sha256((const uint8_t*)content, strlen(content), sha));

    /* Add hash to whitelist */
    akav_whitelist_add_hash(engine, sha);

    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_whitelist = 1;

    akav_scan_result_t result;
    EXPECT_EQ(akav_scan_file(engine, path.c_str(), &opts, &result), AKAV_OK);
    EXPECT_EQ(result.in_whitelist, 1);
    EXPECT_EQ(result.found, 0);

    delete_file(path);
}

TEST_F(WhitelistEngineTest, HashNotWhitelistedScansNormally)
{
    const char* content = "this file's hash is not whitelisted";
    std::string path = create_temp_file(content, strlen(content));

    /* Add a different hash */
    uint8_t fake_hash[32];
    memset(fake_hash, 0xDE, 32);
    akav_whitelist_add_hash(engine, fake_hash);

    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_whitelist = 1;

    akav_scan_result_t result;
    EXPECT_EQ(akav_scan_file(engine, path.c_str(), &opts, &result), AKAV_OK);
    EXPECT_EQ(result.in_whitelist, 0);

    delete_file(path);
}

TEST_F(WhitelistEngineTest, SignerTrustedCalcExe)
{
    /* Engine constructor adds "Microsoft Corporation" and "Microsoft Windows"
     * by default. Scan a known MS-signed binary. */
    const char* candidates[] = {
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\calc.exe",
        "C:\\Windows\\notepad.exe",
    };

    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_whitelist = 1;

    bool found_whitelisted = false;
    for (const char* path : candidates) {
        if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
            continue;

        akav_scan_result_t result;
        akav_error_t err = akav_scan_file(engine, path, &opts, &result);
        if (err == AKAV_OK && result.in_whitelist == 1) {
            found_whitelisted = true;
            printf("  [info] %s -> in_whitelist=1 (MS signer trusted)\n", path);
            EXPECT_EQ(result.found, 0);
            break;
        }
    }

    EXPECT_TRUE(found_whitelisted)
        << "Expected at least one MS-signed binary to be whitelisted";
}

TEST_F(WhitelistEngineTest, WhitelistClearRemovesAll)
{
    /* Add exclusions */
    uint8_t hash[32];
    memset(hash, 0xAB, 32);
    akav_whitelist_add_hash(engine, hash);
    akav_whitelist_add_path(engine, "C:\\TestExclude");
    akav_whitelist_add_signer(engine, "Test Publisher");

    /* Clear */
    akav_whitelist_clear(engine);

    /* Path should no longer be excluded.
     * We can't directly test hash/signer through public API without scanning,
     * but clear should have emptied all three lists. */
    const char* content = "test";
    std::string path = create_temp_file(content, strlen(content));

    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_whitelist = 1;

    akav_scan_result_t result;
    EXPECT_EQ(akav_scan_file(engine, path.c_str(), &opts, &result), AKAV_OK);
    /* After clear, no whitelist entries -> should not be whitelisted
     * (unless default signers were re-added, but clear removes those too) */
    EXPECT_EQ(result.in_whitelist, 0);

    delete_file(path);
}

TEST_F(WhitelistEngineTest, NonWhitelistedFileScansNormally)
{
    /* A file that isn't path-excluded, hash-whitelisted, or signer-trusted
     * should proceed through the normal scan pipeline (in_whitelist=0). */
    const char* content = "just a regular file that should be scanned normally";
    std::string path = create_temp_file(content, strlen(content));

    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    opts.use_whitelist = 1;

    akav_scan_result_t result;
    EXPECT_EQ(akav_scan_file(engine, path.c_str(), &opts, &result), AKAV_OK);
    EXPECT_EQ(result.in_whitelist, 0);
    /* Without signatures loaded, found=0, which is fine — we're testing
     * that the whitelist pipeline doesn't short-circuit this file. */
    EXPECT_EQ(result.found, 0);

    delete_file(path);
}
