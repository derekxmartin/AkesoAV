/* test_quarantine.cpp -- Tests for the quarantine vault.
 *
 * Tests:
 *   1. Init creates vault directory and DB
 *   2. Quarantine file → .sqz exists + index row
 *   3. Restore file → decrypted matches original SHA-256
 *   4. Restore to custom path
 *   5. List entries
 *   6. Delete entry removes .sqz + index row
 *   7. Purge removes old entries
 *   8. Count
 *   9. Key persistence (shutdown + re-init decrypts with same key)
 *  10. Original file deleted after quarantine
 *  11. Quarantine nonexistent file fails gracefully
 *  12. Restore nonexistent entry fails gracefully
 *  13. Double shutdown safe
 *  14. Entry metadata correct
 *  15. Multiple files
 */

#include <gtest/gtest.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "quarantine/quarantine.h"
#include "signatures/hash_matcher.h"  /* akav_hash_sha256 */

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

/* ── Helpers ───────────────────────────────────────────────────── */

static std::string make_temp_dir(const char* prefix)
{
    char temp_base[MAX_PATH];
    GetTempPathA(sizeof(temp_base), temp_base);

    /* Append a unique subdirectory */
    char dir[MAX_PATH];
    snprintf(dir, sizeof(dir), "%sakav_%s_%u",
             temp_base, prefix, GetTickCount());
    CreateDirectoryA(dir, NULL);
    return dir;
}

static std::string create_test_file(const char* dir, const char* name,
                                     const char* content, size_t len)
{
    std::string path = std::string(dir) + "\\" + name;
    HANDLE hf = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hf, content, (DWORD)len, &written, NULL);
        CloseHandle(hf);
    }
    return path;
}

static std::vector<uint8_t> read_file_bytes(const char* path)
{
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return {};

    LARGE_INTEGER size;
    GetFileSizeEx(hf, &size);
    std::vector<uint8_t> data((size_t)size.QuadPart);
    DWORD read_count = 0;
    if (size.QuadPart > 0)
        ReadFile(hf, data.data(), (DWORD)size.QuadPart, &read_count, NULL);
    CloseHandle(hf);
    return data;
}

static std::string sha256_hex(const uint8_t* data, size_t len)
{
    uint8_t hash[32];
    if (!akav_hash_sha256(data, len, hash))
        return "";
    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    hex[64] = '\0';
    return hex;
}

static bool file_exists(const char* path)
{
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static void remove_dir_recursive(const char* dir)
{
    std::string pattern = std::string(dir) + "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            std::string path = std::string(dir) + "\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                remove_dir_recursive(path.c_str());
            else
                DeleteFileA(path.c_str());
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    RemoveDirectoryA(dir);
}

/* ── Test fixture ──────────────────────────────────────────────── */

class QuarantineTest : public ::testing::Test {
protected:
    void SetUp() override {
        vault_dir_ = make_temp_dir("qtest");
        test_dir_ = make_temp_dir("qfiles");
    }

    void TearDown() override {
        q_.shutdown();
        remove_dir_recursive(vault_dir_.c_str());
        remove_dir_recursive(test_dir_.c_str());
    }

    std::string create_file(const char* name, const char* content) {
        return create_test_file(test_dir_.c_str(), name,
                                content, strlen(content));
    }

    Quarantine q_;
    std::string vault_dir_;
    std::string test_dir_;
};

/* ── Tests ──────────────────────────────────────────────────────── */

TEST_F(QuarantineTest, InitCreatesDirectoryAndDB)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    /* vault/ subdirectory should exist */
    std::string vault_subdir = vault_dir_ + "\\vault";
    EXPECT_TRUE(file_exists(vault_subdir.c_str()));

    /* quarantine.db should exist */
    std::string db_path = vault_dir_ + "\\quarantine.db";
    EXPECT_TRUE(file_exists(db_path.c_str()));

    /* key.dpapi should exist */
    std::string key_path = vault_dir_ + "\\key.dpapi";
    EXPECT_TRUE(file_exists(key_path.c_str()));
}

TEST_F(QuarantineTest, QuarantineFileCreatesSqzAndIndex)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    std::string path = create_file("malware.exe", "evil payload data here");

    std::string vid = q_.quarantine_file(path.c_str(),
                                          "Win32.Test.Malware", "sig-001");
    ASSERT_FALSE(vid.empty()) << "quarantine_file returned empty vault_id";
    EXPECT_TRUE(vid.find("q-") == 0) << "vault_id format: " << vid;

    /* .sqz should exist */
    std::string sqz = vault_dir_ + "\\vault\\" + vid + ".sqz";
    EXPECT_TRUE(file_exists(sqz.c_str())) << "Missing: " << sqz;

    /* Index should have 1 entry */
    EXPECT_EQ(q_.count(), 1);

    auto entries = q_.list();
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_STREQ(entries[0].id, vid.c_str());
    EXPECT_STREQ(entries[0].malware_name, "Win32.Test.Malware");
    EXPECT_STREQ(entries[0].signature_id, "sig-001");
}

TEST_F(QuarantineTest, RestoreMatchesOriginalSHA256)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    const char* content = "this is the original file content for sha256 verification";
    std::string path = create_file("test.dat", content);

    /* Compute original hash */
    auto original_data = read_file_bytes(path.c_str());
    std::string original_hash = sha256_hex(original_data.data(), original_data.size());
    ASSERT_FALSE(original_hash.empty());

    /* Quarantine */
    std::string vid = q_.quarantine_file(path.c_str(), "TestMalware", "sig-t1");
    ASSERT_FALSE(vid.empty());

    /* Original should be deleted */
    EXPECT_FALSE(file_exists(path.c_str()));

    /* Restore to a new location */
    std::string restore = test_dir_ + "\\restored.dat";
    ASSERT_TRUE(q_.restore_file(vid.c_str(), restore.c_str()));

    /* Verify SHA-256 matches */
    auto restored_data = read_file_bytes(restore.c_str());
    std::string restored_hash = sha256_hex(restored_data.data(), restored_data.size());
    EXPECT_EQ(original_hash, restored_hash);

    /* Index entry should be removed */
    EXPECT_EQ(q_.count(), 0);
}

TEST_F(QuarantineTest, RestoreToOriginalPath)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    const char* content = "restore to original path test";
    std::string path = create_file("original.bin", content);

    auto original_data = read_file_bytes(path.c_str());
    std::string original_hash = sha256_hex(original_data.data(), original_data.size());

    std::string vid = q_.quarantine_file(path.c_str(), "Malware", "sig");
    ASSERT_FALSE(vid.empty());
    EXPECT_FALSE(file_exists(path.c_str()));

    /* Restore without specifying path → goes to original_path */
    ASSERT_TRUE(q_.restore_file(vid.c_str()));
    EXPECT_TRUE(file_exists(path.c_str()));

    auto restored_data = read_file_bytes(path.c_str());
    std::string restored_hash = sha256_hex(restored_data.data(), restored_data.size());
    EXPECT_EQ(original_hash, restored_hash);
}

TEST_F(QuarantineTest, ListEntries)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    std::string p1 = create_file("file1.exe", "content 1");
    std::string p2 = create_file("file2.exe", "content 2");
    std::string p3 = create_file("file3.exe", "content 3");

    q_.quarantine_file(p1.c_str(), "Malware.A", "sig-a");
    q_.quarantine_file(p2.c_str(), "Malware.B", "sig-b");
    q_.quarantine_file(p3.c_str(), "Malware.C", "sig-c");

    auto entries = q_.list();
    EXPECT_EQ(entries.size(), 3u);
    EXPECT_EQ(q_.count(), 3);
}

TEST_F(QuarantineTest, DeleteEntry)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    std::string path = create_file("todelete.exe", "delete me");
    std::string vid = q_.quarantine_file(path.c_str(), "Malware", "sig");
    ASSERT_FALSE(vid.empty());

    EXPECT_EQ(q_.count(), 1);

    /* Delete */
    ASSERT_TRUE(q_.delete_entry(vid.c_str()));

    EXPECT_EQ(q_.count(), 0);

    /* .sqz should be gone */
    std::string sqz = vault_dir_ + "\\vault\\" + vid + ".sqz";
    EXPECT_FALSE(file_exists(sqz.c_str()));
}

TEST_F(QuarantineTest, PurgeOldEntries)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    /* Create and quarantine a file */
    std::string path = create_file("old.exe", "old content");
    std::string vid = q_.quarantine_file(path.c_str(), "OldMalware", "sig-old");
    ASSERT_FALSE(vid.empty());
    EXPECT_EQ(q_.count(), 1);

    /* Wait 2 seconds so the entry is at least 1 second old,
     * then purge entries older than 0 days (cutoff = now, entry < now). */
    Sleep(2000);
    int purged = q_.purge(0);
    EXPECT_EQ(purged, 1);
    EXPECT_EQ(q_.count(), 0);
}

TEST_F(QuarantineTest, PurgeKeepsRecentEntries)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    std::string path = create_file("recent.exe", "recent content");
    q_.quarantine_file(path.c_str(), "RecentMalware", "sig-r");
    EXPECT_EQ(q_.count(), 1);

    /* Purge entries older than 30 days — recent entry should survive */
    int purged = q_.purge(30);
    EXPECT_EQ(purged, 0);
    EXPECT_EQ(q_.count(), 1);
}

TEST_F(QuarantineTest, KeyPersistenceAcrossRestart)
{
    const char* content = "key persistence test data - encrypt then decrypt after restart";
    std::string path = create_file("persist.dat", content);
    auto original_data = read_file_bytes(path.c_str());
    std::string original_hash = sha256_hex(original_data.data(), original_data.size());

    /* First init: quarantine */
    {
        Quarantine q1;
        ASSERT_TRUE(q1.init(vault_dir_.c_str()));
        std::string vid = q1.quarantine_file(path.c_str(), "Test", "sig");
        ASSERT_FALSE(vid.empty());
        q1.shutdown();

        /* Second init: restore with same key from DPAPI */
        Quarantine q2;
        ASSERT_TRUE(q2.init(vault_dir_.c_str()));

        std::string restore = test_dir_ + "\\persist_restored.dat";
        ASSERT_TRUE(q2.restore_file(vid.c_str(), restore.c_str()));

        auto restored_data = read_file_bytes(restore.c_str());
        std::string restored_hash = sha256_hex(restored_data.data(), restored_data.size());
        EXPECT_EQ(original_hash, restored_hash);
    }
}

TEST_F(QuarantineTest, OriginalFileDeletedAfterQuarantine)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    std::string path = create_file("willbedeleted.exe", "content");
    EXPECT_TRUE(file_exists(path.c_str()));

    std::string vid = q_.quarantine_file(path.c_str(), "Malware", "sig");
    ASSERT_FALSE(vid.empty());

    /* Original should be deleted */
    EXPECT_FALSE(file_exists(path.c_str()));
}

TEST_F(QuarantineTest, QuarantineNonexistentFileFails)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    std::string vid = q_.quarantine_file(
        "C:\\nonexistent_akav_quarantine_test_12345.exe", "Malware", "sig");
    EXPECT_TRUE(vid.empty());
    EXPECT_EQ(q_.count(), 0);
}

TEST_F(QuarantineTest, RestoreNonexistentEntryFails)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));
    EXPECT_FALSE(q_.restore_file("q-nonexistent-0000"));
}

TEST_F(QuarantineTest, DoubleShutdownSafe)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));
    q_.shutdown();
    q_.shutdown();  /* Should not crash */
}

TEST_F(QuarantineTest, EntryMetadataCorrect)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    const char* content = "metadata test content";
    std::string path = create_file("meta.exe", content);

    /* Compute expected SHA-256 */
    auto data = read_file_bytes(path.c_str());
    std::string expected_hash = sha256_hex(data.data(), data.size());

    std::string vid = q_.quarantine_file(path.c_str(),
                                          "Win32.Trojan.Test", "bytestream-42");

    auto entries = q_.list();
    ASSERT_EQ(entries.size(), 1u);

    EXPECT_STREQ(entries[0].id, vid.c_str());
    EXPECT_STREQ(entries[0].malware_name, "Win32.Trojan.Test");
    EXPECT_STREQ(entries[0].signature_id, "bytestream-42");
    EXPECT_EQ(entries[0].file_size, (int64_t)strlen(content));
    EXPECT_STREQ(entries[0].sha256, expected_hash.c_str());
    EXPECT_GT(entries[0].timestamp, 0LL);
    EXPECT_TRUE(strlen(entries[0].user_sid) > 0);
    EXPECT_TRUE(entries[0].original_path[0] != '\0');
}

TEST_F(QuarantineTest, MultipleFilesQuarantineAndRestore)
{
    ASSERT_TRUE(q_.init(vault_dir_.c_str()));

    /* Quarantine 3 files */
    std::vector<std::string> paths;
    std::vector<std::string> hashes;
    std::vector<std::string> vids;

    for (int i = 0; i < 3; i++) {
        char name[32], content[64];
        snprintf(name, sizeof(name), "multi_%d.exe", i);
        snprintf(content, sizeof(content), "multi file content %d - unique data", i);

        std::string p = create_file(name, content);
        auto data = read_file_bytes(p.c_str());
        hashes.push_back(sha256_hex(data.data(), data.size()));

        std::string vid = q_.quarantine_file(p.c_str(), "MultiMalware", "sig-m");
        ASSERT_FALSE(vid.empty());
        paths.push_back(p);
        vids.push_back(vid);
    }

    EXPECT_EQ(q_.count(), 3);

    /* Restore all and verify hashes */
    for (int i = 0; i < 3; i++) {
        char restore_name[64];
        snprintf(restore_name, sizeof(restore_name), "restored_%d.dat", i);
        std::string restore = test_dir_ + "\\" + restore_name;

        ASSERT_TRUE(q_.restore_file(vids[i].c_str(), restore.c_str()));

        auto restored_data = read_file_bytes(restore.c_str());
        std::string restored_hash = sha256_hex(restored_data.data(), restored_data.size());
        EXPECT_EQ(hashes[i], restored_hash) << "Hash mismatch for file " << i;
    }

    EXPECT_EQ(q_.count(), 0);
}
