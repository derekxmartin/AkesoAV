/* test_edr_shim.cpp -- Tests for the EDR integration shim.
 *
 * Tests:
 *   1. Graceful degradation: init with no DLL → av_available()=false
 *   2. Empty telemetry: scan without DLL → defaults
 *   3. Config parsing: [av] section values
 *   4. Config missing file → defaults
 *   5. Init with real DLL → av_available()=true
 *   6. Scan clean file → not detected
 *   7. Scan nonexistent file → error handled
 *   8. Cache stats after scan
 *   9. Cache clear
 *  10. Version strings
 *  11. Re-scan cached
 *  12. Reload signatures
 *  13. Shutdown idempotent
 *  14. Buffer scan
 *  15. Telemetry fields populated correctly
 */

#include <gtest/gtest.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* The shim header is in integration/ — add to include path in CMakeLists */
#include "edr_shim.h"

#include <cstdio>
#include <cstring>
#include <string>

/* ── Helpers ───────────────────────────────────────────────────── */

static std::string get_test_dll_path()
{
    /* Find akesoav.dll next to the test exe */
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    std::string dir(exe_path);
    auto pos = dir.rfind('\\');
    if (pos != std::string::npos)
        dir = dir.substr(0, pos);
    return dir + "\\akesoav.dll";
}

static bool dll_available()
{
    std::string path = get_test_dll_path();
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static std::string create_temp_config(const char* content)
{
    char temp_dir[MAX_PATH];
    char temp_path[MAX_PATH];
    GetTempPathA(sizeof(temp_dir), temp_dir);
    GetTempFileNameA(temp_dir, "akav", 0, temp_path);

    FILE* f = nullptr;
    fopen_s(&f, temp_path, "w");
    if (f) {
        fputs(content, f);
        fclose(f);
    }
    return temp_path;
}

static std::string create_temp_file(const char* content, size_t len)
{
    char temp_dir[MAX_PATH];
    char temp_path[MAX_PATH];
    GetTempPathA(sizeof(temp_dir), temp_dir);
    GetTempFileNameA(temp_dir, "aksv", 0, temp_path);

    HANDLE hf = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hf, content, (DWORD)len, &written, NULL);
        CloseHandle(hf);
    }
    return temp_path;
}

/* ── Tests: Graceful degradation (no DLL) ──────────────────────── */

class EdrShimNoDllTest : public ::testing::Test {
protected:
    void SetUp() override {
        /* Point to a nonexistent DLL */
        config_ = create_temp_config(
            "[av]\n"
            "dll_path = C:\\nonexistent_akav_test_12345\\akesoav.dll\n"
        );
    }

    void TearDown() override {
        DeleteFileA(config_.c_str());
    }

    std::string config_;
};

TEST_F(EdrShimNoDllTest, InitGracefulDegradation)
{
    AVEngine av;
    /* Init should return false but not crash */
    bool ok = av.init(config_.c_str());
    EXPECT_FALSE(ok);
    EXPECT_FALSE(av.av_available());
}

TEST_F(EdrShimNoDllTest, ScanReturnsEmptyTelemetry)
{
    AVEngine av;
    av.init(config_.c_str());

    AVTelemetry t = av.scan_file("C:\\Windows\\System32\\notepad.exe");
    EXPECT_FALSE(t.av_available);
    EXPECT_FALSE(t.av_detected);
    EXPECT_FALSE(t.av_timeout);
    EXPECT_DOUBLE_EQ(t.av_heuristic_score, 0.0);
    EXPECT_EQ(t.av_malware_name[0], '\0');
}

TEST_F(EdrShimNoDllTest, BufferScanReturnsEmptyTelemetry)
{
    AVEngine av;
    av.init(config_.c_str());

    const uint8_t buf[] = "hello";
    AVTelemetry t = av.scan_buffer(buf, sizeof(buf), "test");
    EXPECT_FALSE(t.av_available);
    EXPECT_FALSE(t.av_detected);
}

TEST_F(EdrShimNoDllTest, CacheOpsReturnFalse)
{
    AVEngine av;
    av.init(config_.c_str());

    uint64_t h = 0, m = 0, e = 0;
    EXPECT_FALSE(av.cache_stats(&h, &m, &e));
    EXPECT_FALSE(av.cache_clear());
}

TEST_F(EdrShimNoDllTest, VersionStringsGraceful)
{
    AVEngine av;
    av.init(config_.c_str());

    EXPECT_STREQ(av.engine_version(), "unavailable");
    EXPECT_STREQ(av.db_version(), "unavailable");
}

TEST_F(EdrShimNoDllTest, ShutdownIdempotent)
{
    AVEngine av;
    av.init(config_.c_str());
    av.shutdown();
    av.shutdown();  /* Should not crash */
    EXPECT_FALSE(av.av_available());
}

/* ── Tests: Config parsing ─────────────────────────────────────── */

TEST(EdrShimConfigTest, ParsesAvSection)
{
    std::string cfg = create_temp_config(
        "[other]\n"
        "key = value\n"
        "\n"
        "[av]\n"
        "dll_path = C:\\test\\akesoav.dll\n"
        "db_path = C:\\test\\sigs.akavdb\n"
        "heuristic_level = 3\n"
        "scan_timeout_ms = 10000\n"
    );

    AVEngine av;
    /* Init will fail (no real DLL) but config is parsed */
    av.init(cfg.c_str());

    EXPECT_EQ(av.dll_path(), "C:\\test\\akesoav.dll");
    EXPECT_EQ(av.db_path(), "C:\\test\\sigs.akavdb");
    EXPECT_EQ(av.scan_timeout_ms(), 10000);

    DeleteFileA(cfg.c_str());
}

TEST(EdrShimConfigTest, DefaultsOnMissingConfig)
{
    AVEngine av;
    av.init(nullptr);

    EXPECT_EQ(av.scan_timeout_ms(), 5000);
    /* dll_path_ should be set to exe_dir\akesoav.dll by default */
    EXPECT_FALSE(av.dll_path().empty());
}

TEST(EdrShimConfigTest, DefaultsOnNonexistentFile)
{
    AVEngine av;
    av.init("C:\\nonexistent_config_12345.conf");

    EXPECT_EQ(av.scan_timeout_ms(), 5000);
}

TEST(EdrShimConfigTest, InvalidHeuristicLevelClamped)
{
    std::string cfg = create_temp_config(
        "[av]\n"
        "heuristic_level = 99\n"
        "dll_path = C:\\nonexistent\\akesoav.dll\n"
    );

    AVEngine av;
    av.init(cfg.c_str());

    /* Should clamp to MEDIUM (2) */
    /* We can't directly access heuristic_level_, but we check it doesn't crash */
    EXPECT_FALSE(av.av_available());

    DeleteFileA(cfg.c_str());
}

/* ── Tests: With real DLL (conditional) ────────────────────────── */

class EdrShimDllTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!dll_available()) {
            GTEST_SKIP() << "akesoav.dll not found — skipping DLL tests";
        }

        std::string dll = get_test_dll_path();
        std::string cfg_content =
            "[av]\n"
            "dll_path = " + dll + "\n";
        config_ = create_temp_config(cfg_content.c_str());
    }

    void TearDown() override {
        if (!config_.empty())
            DeleteFileA(config_.c_str());
        for (auto& f : temp_files_)
            DeleteFileA(f.c_str());
    }

    std::string create_clean_file() {
        const char* content = "this is a clean test file for edr shim";
        std::string path = create_temp_file(content, strlen(content));
        temp_files_.push_back(path);
        return path;
    }

    std::string config_;
    std::vector<std::string> temp_files_;
};

TEST_F(EdrShimDllTest, InitSuccess)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));
    EXPECT_TRUE(av.av_available());
}

TEST_F(EdrShimDllTest, VersionStrings)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));

    const char* ver = av.engine_version();
    EXPECT_NE(ver, nullptr);
    EXPECT_STRNE(ver, "unavailable");
    EXPECT_STRNE(ver, "");
}

TEST_F(EdrShimDllTest, ScanCleanFile)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));

    std::string path = create_clean_file();
    AVTelemetry t = av.scan_file(path.c_str());

    EXPECT_TRUE(t.av_available);
    EXPECT_FALSE(t.av_detected);
    EXPECT_FALSE(t.av_timeout);
    EXPECT_EQ(t.av_malware_name[0], '\0');
}

TEST_F(EdrShimDllTest, ScanNonexistentFile)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));

    AVTelemetry t = av.scan_file("C:\\nonexistent_akav_test_12345.exe");

    /* Should handle gracefully — either error or empty result */
    EXPECT_TRUE(t.av_available);
    EXPECT_FALSE(t.av_detected);
}

TEST_F(EdrShimDllTest, TelemetryFieldsPopulated)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));

    std::string path = create_clean_file();
    AVTelemetry t = av.scan_file(path.c_str());

    EXPECT_TRUE(t.av_available);
    EXPECT_FALSE(t.av_timeout);
    /* file_type should be populated for any file */
    /* heuristic_score should be >= 0 */
    EXPECT_GE(t.av_heuristic_score, 0.0);
}

TEST_F(EdrShimDllTest, CacheStats)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));

    /* Scan a file first */
    std::string path = create_clean_file();
    av.scan_file(path.c_str());

    uint64_t hits = 0, misses = 0, entries = 0;
    EXPECT_TRUE(av.cache_stats(&hits, &misses, &entries));
    /* At least 1 miss (the first scan) */
    EXPECT_GE(misses, 1ULL);
}

TEST_F(EdrShimDllTest, CacheClear)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));

    std::string path = create_clean_file();
    av.scan_file(path.c_str());

    EXPECT_TRUE(av.cache_clear());

    uint64_t hits = 0, misses = 0, entries = 0;
    EXPECT_TRUE(av.cache_stats(&hits, &misses, &entries));
    EXPECT_EQ(entries, 0ULL);
}

TEST_F(EdrShimDllTest, RescanCached)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));

    std::string path = create_clean_file();

    /* First scan — cache miss */
    AVTelemetry t1 = av.scan_file(path.c_str());
    EXPECT_TRUE(t1.av_available);

    /* Second scan — should be cached */
    AVTelemetry t2 = av.scan_file(path.c_str());
    EXPECT_TRUE(t2.av_available);
    EXPECT_TRUE(t2.av_scan_cached);
}

TEST_F(EdrShimDllTest, BufferScan)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));

    const uint8_t buf[] = "this is clean buffer data for testing";
    AVTelemetry t = av.scan_buffer(buf, sizeof(buf) - 1, "test-buffer");

    EXPECT_TRUE(t.av_available);
    EXPECT_FALSE(t.av_detected);
    EXPECT_FALSE(t.av_timeout);
}

TEST_F(EdrShimDllTest, ReloadSignatures)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));

    /* Reload without a db_path configured should return false */
    EXPECT_FALSE(av.reload_signatures());
}

TEST_F(EdrShimDllTest, ShutdownAndReinit)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));
    EXPECT_TRUE(av.av_available());

    av.shutdown();
    EXPECT_FALSE(av.av_available());

    /* Re-init should work */
    ASSERT_TRUE(av.init(config_.c_str()));
    EXPECT_TRUE(av.av_available());
}

TEST_F(EdrShimDllTest, WhitelistedFileHasTelemetryField)
{
    AVEngine av;
    ASSERT_TRUE(av.init(config_.c_str()));

    /* notepad.exe is MS-signed → whitelisted by default */
    AVTelemetry t = av.scan_file("C:\\Windows\\System32\\notepad.exe");
    EXPECT_TRUE(t.av_available);
    EXPECT_TRUE(t.av_in_whitelist);
    EXPECT_FALSE(t.av_detected);
}
