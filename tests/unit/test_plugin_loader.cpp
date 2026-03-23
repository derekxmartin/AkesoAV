// test_plugin_loader.cpp -- Tests for dynamic plugin loading (P6-T3).
//
// Tests:
//   1. PluginManager init zeroes state
//   2. Load valid scanner plugin DLL
//   3. Plugin detects "PLUGINTEST" string
//   4. Plugin does not detect clean buffer
//   5. Bad API version is rejected
//   6. Missing DLL returns error gracefully
//   7. NULL params return error
//   8. Load directory with mixed plugins
//   9. Clean shutdown (no crash)
//  10. Engine integration: plugins run in scan pipeline

#include <gtest/gtest.h>

#include "plugin/plugin_loader.h"
#include "engine_internal.h"

#include <cstring>
#include <cstdlib>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// ── Helper: locate test plugin DLLs relative to the test executable ──
//
// The test plugin DLLs are built to the same output directory as the test
// executable (e.g., build/Release/).  We find them by getting the path
// of the current module.

static std::string get_exe_dir()
{
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (len == 0) return ".";

    // Strip filename to get directory
    for (DWORD i = len; i > 0; i--) {
        if (path[i - 1] == '\\' || path[i - 1] == '/') {
            path[i] = '\0';
            return std::string(path);
        }
    }
    return ".";
}

static std::string plugin_path(const char* dll_name)
{
    return get_exe_dir() + dll_name;
}

// ── PluginManager basic tests ──

TEST(PluginManager, InitZeroesState)
{
    akav_plugin_manager_t mgr;
    memset(&mgr, 0xFF, sizeof(mgr));  // Fill with garbage
    akav_plugin_manager_init(&mgr);
    EXPECT_EQ(mgr.count, 0);
    for (int i = 0; i < AKAV_MAX_PLUGINS; i++) {
        EXPECT_EQ(mgr.plugins[i].active, 0);
        EXPECT_EQ(mgr.plugins[i].dll_handle, nullptr);
    }
}

TEST(PluginManager, InitNullSafe)
{
    // Should not crash
    akav_plugin_manager_init(nullptr);
}

TEST(PluginManager, LoadNullParams)
{
    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);

    EXPECT_EQ(akav_plugin_manager_load(nullptr, "foo.dll"), AKAV_ERROR_INVALID);
    EXPECT_EQ(akav_plugin_manager_load(&mgr, nullptr), AKAV_ERROR_INVALID);
    EXPECT_EQ(mgr.count, 0);
}

TEST(PluginManager, LoadMissingDLL)
{
    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);

    akav_error_t err = akav_plugin_manager_load(&mgr, "nonexistent_plugin_abc123.dll");
    EXPECT_EQ(err, AKAV_ERROR_IO);
    EXPECT_EQ(mgr.count, 0);
}

TEST(PluginManager, LoadValidScannerPlugin)
{
    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);

    std::string path = plugin_path("test_plugin_scanner.dll");
    akav_error_t err = akav_plugin_manager_load(&mgr, path.c_str());
    ASSERT_EQ(err, AKAV_OK) << "Failed to load " << path;

    EXPECT_EQ(mgr.count, 1);
    EXPECT_EQ(mgr.plugins[0].active, 1);
    EXPECT_NE(mgr.plugins[0].dll_handle, nullptr);
    EXPECT_STREQ(mgr.plugins[0].info->name, "Test Plugin Scanner");
    EXPECT_STREQ(mgr.plugins[0].info->version, "1.0.0");
    EXPECT_EQ(mgr.plugins[0].info->type, (uint32_t)AKAV_PLUGIN_TYPE_SCANNER);

    akav_plugin_manager_destroy(&mgr);
}

TEST(PluginManager, BadAPIVersionRejected)
{
    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);

    std::string path = plugin_path("test_plugin_bad_version.dll");
    akav_error_t err = akav_plugin_manager_load(&mgr, path.c_str());
    EXPECT_EQ(err, AKAV_ERROR_INVALID);
    EXPECT_EQ(mgr.count, 0);  // Not loaded

    akav_plugin_manager_destroy(&mgr);
}

// ── Plugin scan tests ──

TEST(PluginScan, DetectsPLUGINTEST)
{
    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);

    std::string path = plugin_path("test_plugin_scanner.dll");
    ASSERT_EQ(akav_plugin_manager_load(&mgr, path.c_str()), AKAV_OK);

    // Buffer containing the target string
    const char data[] = "some prefix PLUGINTEST some suffix";
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    akav_scan_result_t result;
    memset(&result, 0, sizeof(result));

    akav_plugin_manager_scan(&mgr, (const uint8_t*)data, strlen(data), &opts, &result);

    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.malware_name, "Test.Plugin.Detection");
    EXPECT_STREQ(result.scanner_id, "test_plugin");
    EXPECT_STREQ(result.signature_id, "plugin-test-1");

    akav_plugin_manager_destroy(&mgr);
}

TEST(PluginScan, NoDetectCleanBuffer)
{
    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);

    std::string path = plugin_path("test_plugin_scanner.dll");
    ASSERT_EQ(akav_plugin_manager_load(&mgr, path.c_str()), AKAV_OK);

    const char data[] = "This is a clean buffer with nothing suspicious.";
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    akav_scan_result_t result;
    memset(&result, 0, sizeof(result));

    akav_plugin_manager_scan(&mgr, (const uint8_t*)data, strlen(data), &opts, &result);

    EXPECT_EQ(result.found, 0);

    akav_plugin_manager_destroy(&mgr);
}

TEST(PluginScan, NullParamsSafe)
{
    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);

    // Should not crash with any NULL params
    akav_plugin_manager_scan(nullptr, nullptr, 0, nullptr, nullptr);
    akav_plugin_manager_scan(&mgr, nullptr, 0, nullptr, nullptr);

    akav_plugin_manager_destroy(&mgr);
}

// ── Directory loading tests ──

TEST(PluginLoadDir, LoadsMultiplePlugins)
{
    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);

    // The exe directory has both test_plugin_scanner.dll and test_plugin_bad_version.dll.
    // Only the valid one should load (bad version is rejected).
    std::string dir = get_exe_dir();
    // Remove trailing backslash for load_dir
    if (!dir.empty() && (dir.back() == '\\' || dir.back() == '/'))
        dir.pop_back();

    int loaded = akav_plugin_manager_load_dir(&mgr, dir.c_str());

    // At minimum test_plugin_scanner.dll should load.
    // test_plugin_bad_version.dll should be rejected.
    // Other DLLs in the directory (gtest, etc.) will fail at GetProcAddress and be skipped.
    EXPECT_GE(loaded, 1);
    EXPECT_GE(mgr.count, 1);

    // Verify the scanner plugin is among them
    bool found_scanner = false;
    for (int i = 0; i < mgr.count; i++) {
        if (mgr.plugins[i].info &&
            strcmp(mgr.plugins[i].info->name, "Test Plugin Scanner") == 0) {
            found_scanner = true;
            break;
        }
    }
    EXPECT_TRUE(found_scanner);

    akav_plugin_manager_destroy(&mgr);
}

TEST(PluginLoadDir, EmptyDirReturnsZero)
{
    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);

    int loaded = akav_plugin_manager_load_dir(&mgr, "C:\\nonexistent_dir_xyz123");
    EXPECT_EQ(loaded, 0);
    EXPECT_EQ(mgr.count, 0);

    akav_plugin_manager_destroy(&mgr);
}

TEST(PluginLoadDir, NullParamsSafe)
{
    EXPECT_EQ(akav_plugin_manager_load_dir(nullptr, "foo"), 0);

    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);
    EXPECT_EQ(akav_plugin_manager_load_dir(&mgr, nullptr), 0);

    akav_plugin_manager_destroy(&mgr);
}

// ── Shutdown tests ──

TEST(PluginManager, DestroyNullSafe)
{
    // Should not crash
    akav_plugin_manager_destroy(nullptr);
}

TEST(PluginManager, DoubleDestroySafe)
{
    akav_plugin_manager_t mgr;
    akav_plugin_manager_init(&mgr);

    std::string path = plugin_path("test_plugin_scanner.dll");
    ASSERT_EQ(akav_plugin_manager_load(&mgr, path.c_str()), AKAV_OK);

    akav_plugin_manager_destroy(&mgr);
    // Second destroy should be safe (count is zeroed)
    akav_plugin_manager_destroy(&mgr);
}

// ── Engine integration tests ──

TEST(PluginEngine, PluginAbsentEngineNormal)
{
    // Engine works normally without any plugins loaded
    akav::Engine engine;
    ASSERT_EQ(engine.init(nullptr), AKAV_OK);

    const char data[] = "Hello, World!";
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    akav_scan_result_t result;

    akav_error_t err = engine.scan_buffer(
        (const uint8_t*)data, strlen(data), "test.txt", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 0);
}

TEST(PluginEngine, PluginDetectionInPipeline)
{
    akav::Engine engine;
    ASSERT_EQ(engine.init(nullptr), AKAV_OK);

    // Load the test plugin
    std::string dir = get_exe_dir();
    if (!dir.empty() && (dir.back() == '\\' || dir.back() == '/'))
        dir.pop_back();
    engine.load_plugins(dir.c_str());

    // Scan a buffer containing PLUGINTEST
    const char data[] = "This contains PLUGINTEST marker";
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    akav_scan_result_t result;

    akav_error_t err = engine.scan_buffer(
        (const uint8_t*)data, strlen(data), "test.bin", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 1);
    EXPECT_STREQ(result.malware_name, "Test.Plugin.Detection");
    EXPECT_STREQ(result.scanner_id, "test_plugin");
}

TEST(PluginEngine, CleanBufferNotDetectedByPlugin)
{
    akav::Engine engine;
    ASSERT_EQ(engine.init(nullptr), AKAV_OK);

    std::string dir = get_exe_dir();
    if (!dir.empty() && (dir.back() == '\\' || dir.back() == '/'))
        dir.pop_back();
    engine.load_plugins(dir.c_str());

    const char data[] = "Perfectly normal file content";
    akav_scan_options_t opts;
    akav_scan_options_default(&opts);
    akav_scan_result_t result;

    akav_error_t err = engine.scan_buffer(
        (const uint8_t*)data, strlen(data), "clean.txt", &opts, &result);
    EXPECT_EQ(err, AKAV_OK);
    EXPECT_EQ(result.found, 0);
}
