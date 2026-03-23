/*
 * Unit tests for self-protection module (P10-T2).
 *
 * Tests:
 *   1. DACL hardening
 *   2. Authenticode verification (WinVerifyTrust)
 *   3. DLL verification (signed/unsigned/invalid)
 *   4. Integrity monitor lifecycle
 *   5. Integrity monitor add/check
 *   6. Integrity monitor detects modification
 *   7. Integrity monitor detects deletion
 *   8. Integrity monitor directory scan
 */

#include <gtest/gtest.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "protection/self_protect.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

/* ── Helper: create a temp file with known content ──────────────── */

static std::string create_temp_file(const char* prefix, const char* content)
{
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);

    char temp_path[MAX_PATH];
    GetTempFileNameA(temp_dir, prefix, 0, temp_path);

    std::ofstream f(temp_path, std::ios::binary);
    f.write(content, strlen(content));
    f.close();

    return std::string(temp_path);
}

static std::string create_temp_file_in(const char* dir, const char* name,
                                        const char* content)
{
    std::string path = std::string(dir) + "\\" + name;
    std::ofstream f(path, std::ios::binary);
    f.write(content, strlen(content));
    f.close();
    return path;
}

/* ── 1. DACL Hardening ──────────────────────────────────────────── */

TEST(SelfProtect, HardenProcess)
{
    /* akav_self_protect_harden_process() modifies the current process DACL.
     * This may fail in non-elevated test environments, so we accept both
     * success and graceful failure. */
    bool result = akav_self_protect_harden_process();

    /* If running elevated (CI, service), should succeed.
     * If not elevated, may fail — that's acceptable. */
    if (result) {
        /* Verify we can still call basic APIs on ourselves */
        HANDLE self = GetCurrentProcess();
        DWORD exitCode = 0;
        EXPECT_TRUE(GetExitCodeProcess(self, &exitCode));
    }
    /* Either way, the test should not crash */
}

TEST(SelfProtect, HardenProcessDoesNotCrash)
{
    /* Calling twice should be safe */
    akav_self_protect_harden_process();
    akav_self_protect_harden_process();
    /* No crash = pass */
}

/* ── 2. Authenticode Verification ───────────────────────────────── */

TEST(SelfProtect, VerifyAuthenticodeSignedSystem)
{
    /* System DLLs should have valid Authenticode signatures */
    akav_verify_result_t result =
        akav_self_protect_verify_authenticode("C:\\Windows\\System32\\kernel32.dll");

    /* Should be OK (signed by Microsoft) */
    EXPECT_EQ(AKAV_VERIFY_OK, result);
}

TEST(SelfProtect, VerifyAuthenticodeUnsignedFile)
{
    /* Create a small temp file — it won't be signed */
    std::string path = create_temp_file("unsig", "not a PE file");

    akav_verify_result_t result = akav_self_protect_verify_authenticode(path.c_str());
    EXPECT_EQ(AKAV_VERIFY_NO_SIGNATURE, result);

    DeleteFileA(path.c_str());
}

TEST(SelfProtect, VerifyAuthenticodeNullPath)
{
    EXPECT_EQ(AKAV_VERIFY_ERROR, akav_self_protect_verify_authenticode(NULL));
    EXPECT_EQ(AKAV_VERIFY_ERROR, akav_self_protect_verify_authenticode(""));
}

TEST(SelfProtect, VerifyAuthenticodeNonexistent)
{
    akav_verify_result_t result =
        akav_self_protect_verify_authenticode("C:\\nonexistent_file_12345.dll");
    /* WinVerifyTrust on nonexistent file returns NO_SIGNATURE or ERROR */
    EXPECT_NE(AKAV_VERIFY_OK, result);
}

/* ── 3. DLL Verification ────────────────────────────────────────── */

TEST(SelfProtect, VerifyDllSignedSystem)
{
    /* Signed system DLL should pass in both modes */
    EXPECT_TRUE(akav_self_protect_verify_dll(
        "C:\\Windows\\System32\\kernel32.dll", true));
    EXPECT_TRUE(akav_self_protect_verify_dll(
        "C:\\Windows\\System32\\kernel32.dll", false));
}

TEST(SelfProtect, VerifyDllUnsignedDevMode)
{
    /* Unsigned file in dev mode (require_signed=false) → allowed */
    std::string path = create_temp_file("devdl", "fake dll content");

    EXPECT_TRUE(akav_self_protect_verify_dll(path.c_str(), false));

    DeleteFileA(path.c_str());
}

TEST(SelfProtect, VerifyDllUnsignedProductionMode)
{
    /* Unsigned file in production mode (require_signed=true) → blocked */
    std::string path = create_temp_file("proddl", "fake dll content");

    EXPECT_FALSE(akav_self_protect_verify_dll(path.c_str(), true));

    DeleteFileA(path.c_str());
}

TEST(SelfProtect, VerifyDllNull)
{
    EXPECT_FALSE(akav_self_protect_verify_dll(NULL, false));
    EXPECT_FALSE(akav_self_protect_verify_dll(NULL, true));
}

/* ── 4. Integrity Monitor Lifecycle ─────────────────────────────── */

TEST(IntegrityMonitor, InitDestroy)
{
    akav_integrity_monitor_t mon;
    akav_integrity_monitor_init(&mon, 60);

    EXPECT_TRUE(mon.initialized);
    EXPECT_EQ(60u, mon.check_interval_sec);
    EXPECT_EQ(0, mon.file_count);

    akav_integrity_monitor_destroy(&mon);
    EXPECT_FALSE(mon.initialized);
}

TEST(IntegrityMonitor, InitDefaultInterval)
{
    akav_integrity_monitor_t mon;
    akav_integrity_monitor_init(&mon, 0);  /* 0 → default 60 */
    EXPECT_EQ(60u, mon.check_interval_sec);
    akav_integrity_monitor_destroy(&mon);
}

TEST(IntegrityMonitor, InitNull)
{
    /* Should not crash */
    akav_integrity_monitor_init(NULL, 60);
    akav_integrity_monitor_destroy(NULL);
}

/* ── 5. Integrity Monitor Add + Check ───────────────────────────── */

TEST(IntegrityMonitor, AddFileAndCheck)
{
    std::string path = create_temp_file("integ", "hello integrity check");

    akav_integrity_monitor_t mon;
    akav_integrity_monitor_init(&mon, 60);

    EXPECT_TRUE(akav_integrity_monitor_add(&mon, path.c_str()));
    EXPECT_EQ(1, mon.file_count);

    /* Check — file unchanged → all OK */
    akav_integrity_result_t result = akav_integrity_monitor_check(&mon);
    EXPECT_EQ(1, result.files_checked);
    EXPECT_EQ(1, result.files_ok);
    EXPECT_EQ(0, result.files_modified);
    EXPECT_EQ(0, result.files_missing);

    akav_integrity_monitor_destroy(&mon);
    DeleteFileA(path.c_str());
}

TEST(IntegrityMonitor, AddNonexistentFile)
{
    akav_integrity_monitor_t mon;
    akav_integrity_monitor_init(&mon, 60);

    EXPECT_FALSE(akav_integrity_monitor_add(&mon, "C:\\nonexistent_12345.txt"));
    EXPECT_EQ(0, mon.file_count);

    akav_integrity_monitor_destroy(&mon);
}

TEST(IntegrityMonitor, AddWithoutInit)
{
    akav_integrity_monitor_t mon;
    memset(&mon, 0, sizeof(mon));  /* Not initialized */

    EXPECT_FALSE(akav_integrity_monitor_add(&mon, "C:\\Windows\\System32\\kernel32.dll"));
}

/* ── 6. Detects Modification ────────────────────────────────────── */

TEST(IntegrityMonitor, DetectsModification)
{
    std::string path = create_temp_file("modi", "original content here");

    akav_integrity_monitor_t mon;
    akav_integrity_monitor_init(&mon, 60);
    ASSERT_TRUE(akav_integrity_monitor_add(&mon, path.c_str()));

    /* Verify baseline is OK */
    akav_integrity_result_t result = akav_integrity_monitor_check(&mon);
    ASSERT_EQ(1, result.files_ok);

    /* Modify the file */
    {
        std::ofstream f(path, std::ios::binary);
        f << "MODIFIED content!!!";
        f.close();
    }

    /* Check again — should detect modification */
    result = akav_integrity_monitor_check(&mon);
    EXPECT_EQ(1, result.files_checked);
    EXPECT_EQ(0, result.files_ok);
    EXPECT_EQ(1, result.files_modified);
    EXPECT_EQ(0, result.files_missing);

    /* modified_paths should contain the path */
    EXPECT_STREQ(path.c_str(), result.modified_paths[0]);

    akav_integrity_monitor_destroy(&mon);
    DeleteFileA(path.c_str());
}

/* ── 7. Detects Deletion ────────────────────────────────────────── */

TEST(IntegrityMonitor, DetectsDeletion)
{
    std::string path = create_temp_file("dele", "file to be deleted");

    akav_integrity_monitor_t mon;
    akav_integrity_monitor_init(&mon, 60);
    ASSERT_TRUE(akav_integrity_monitor_add(&mon, path.c_str()));

    /* Delete the file */
    DeleteFileA(path.c_str());

    /* Check — should detect missing file */
    akav_integrity_result_t result = akav_integrity_monitor_check(&mon);
    EXPECT_EQ(1, result.files_checked);
    EXPECT_EQ(0, result.files_ok);
    EXPECT_EQ(0, result.files_modified);
    EXPECT_EQ(1, result.files_missing);

    akav_integrity_monitor_destroy(&mon);
}

/* ── 8. Directory Scan ──────────────────────────────────────────── */

TEST(IntegrityMonitor, AddDirectory)
{
    /* Create a temp directory with some .dll and .exe files */
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);

    char test_dir[MAX_PATH];
    snprintf(test_dir, sizeof(test_dir), "%sakav_integ_test_%lu",
             temp_dir, GetCurrentProcessId());
    CreateDirectoryA(test_dir, NULL);

    /* Create some files */
    std::string f1 = create_temp_file_in(test_dir, "engine.dll", "dll content 1");
    std::string f2 = create_temp_file_in(test_dir, "scanner.dll", "dll content 2");
    std::string f3 = create_temp_file_in(test_dir, "service.exe", "exe content");
    std::string f4 = create_temp_file_in(test_dir, "config.json", "not monitored");

    akav_integrity_monitor_t mon;
    akav_integrity_monitor_init(&mon, 60);

    int added = akav_integrity_monitor_add_dir(&mon, test_dir);
    EXPECT_EQ(3, added);  /* .dll × 2 + .exe × 1, .json excluded */
    EXPECT_EQ(3, mon.file_count);

    /* Check — all should be OK */
    akav_integrity_result_t result = akav_integrity_monitor_check(&mon);
    EXPECT_EQ(3, result.files_checked);
    EXPECT_EQ(3, result.files_ok);

    akav_integrity_monitor_destroy(&mon);

    /* Cleanup */
    DeleteFileA(f1.c_str());
    DeleteFileA(f2.c_str());
    DeleteFileA(f3.c_str());
    DeleteFileA(f4.c_str());
    RemoveDirectoryA(test_dir);
}

TEST(IntegrityMonitor, AddDirectoryNull)
{
    akav_integrity_monitor_t mon;
    akav_integrity_monitor_init(&mon, 60);

    EXPECT_EQ(0, akav_integrity_monitor_add_dir(&mon, NULL));
    EXPECT_EQ(0, akav_integrity_monitor_add_dir(NULL, "C:\\"));

    akav_integrity_monitor_destroy(&mon);
}

/* ── 9. Monitor capacity ────────────────────────────────────────── */

TEST(IntegrityMonitor, MaxFilesLimit)
{
    akav_integrity_monitor_t mon;
    akav_integrity_monitor_init(&mon, 60);

    /* Use a real system file — we'll add the same file many times
     * by exploiting the fact that add doesn't check for duplicates */
    const char* sys_file = "C:\\Windows\\System32\\kernel32.dll";

    for (int i = 0; i < AKAV_SELF_PROTECT_MAX_FILES; i++) {
        EXPECT_TRUE(akav_integrity_monitor_add(&mon, sys_file));
    }

    /* Next one should fail — at capacity */
    EXPECT_FALSE(akav_integrity_monitor_add(&mon, sys_file));

    akav_integrity_monitor_destroy(&mon);
}

/* ── 10. Check on uninitialized monitor ─────────────────────────── */

TEST(IntegrityMonitor, CheckUninitialized)
{
    akav_integrity_monitor_t mon;
    memset(&mon, 0, sizeof(mon));

    akav_integrity_result_t result = akav_integrity_monitor_check(&mon);
    EXPECT_EQ(0, result.files_checked);
}

/* ── 11. Multiple modifications tracked ─────────────────────────── */

TEST(IntegrityMonitor, MultipleModifications)
{
    std::string path1 = create_temp_file("mm1", "content one");
    std::string path2 = create_temp_file("mm2", "content two");
    std::string path3 = create_temp_file("mm3", "content three");

    akav_integrity_monitor_t mon;
    akav_integrity_monitor_init(&mon, 60);
    ASSERT_TRUE(akav_integrity_monitor_add(&mon, path1.c_str()));
    ASSERT_TRUE(akav_integrity_monitor_add(&mon, path2.c_str()));
    ASSERT_TRUE(akav_integrity_monitor_add(&mon, path3.c_str()));

    /* Modify two files */
    { std::ofstream f(path1, std::ios::binary); f << "CHANGED"; }
    { std::ofstream f(path3, std::ios::binary); f << "CHANGED"; }

    akav_integrity_result_t result = akav_integrity_monitor_check(&mon);
    EXPECT_EQ(3, result.files_checked);
    EXPECT_EQ(1, result.files_ok);
    EXPECT_EQ(2, result.files_modified);

    akav_integrity_monitor_destroy(&mon);
    DeleteFileA(path1.c_str());
    DeleteFileA(path2.c_str());
    DeleteFileA(path3.c_str());
}
