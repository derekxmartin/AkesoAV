/* test_update_client.cpp -- Unit tests for update client (P10-T1). */

#include <gtest/gtest.h>
#include "update/update_client.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

/* ── Helpers ─────────────────────────────────────────────────────── */

static void write_file(const char* path, const void* data, size_t len)
{
    FILE* f = nullptr;
    ASSERT_EQ(fopen_s(&f, path, "wb"), 0);
    ASSERT_NE(f, nullptr);
    fwrite(data, 1, len, f);
    fclose(f);
}

static std::vector<uint8_t> read_file(const char* path)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return {};
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> data((size_t)sz);
    fread(data.data(), 1, data.size(), f);
    fclose(f);
    return data;
}

/* ── Hex decode tests ───────────────────────────────────────────── */

TEST(UpdateClient, HexDecodeValid) {
    const char* hex = "48656c6c6f";  /* "Hello" */
    uint8_t out[16];
    size_t n = akav_hex_decode(hex, strlen(hex), out, sizeof(out));
    EXPECT_EQ(n, 5u);
    EXPECT_EQ(memcmp(out, "Hello", 5), 0);
}

TEST(UpdateClient, HexDecodeUpperCase) {
    const char* hex = "DEADBEEF";
    uint8_t out[4];
    size_t n = akav_hex_decode(hex, strlen(hex), out, sizeof(out));
    EXPECT_EQ(n, 4u);
    EXPECT_EQ(out[0], 0xDE);
    EXPECT_EQ(out[1], 0xAD);
    EXPECT_EQ(out[2], 0xBE);
    EXPECT_EQ(out[3], 0xEF);
}

TEST(UpdateClient, HexDecodeOddLength) {
    uint8_t out[4];
    EXPECT_EQ(akav_hex_decode("ABC", 3, out, sizeof(out)), 0u);
}

TEST(UpdateClient, HexDecodeInvalidChar) {
    uint8_t out[4];
    EXPECT_EQ(akav_hex_decode("ZZZZ", 4, out, sizeof(out)), 0u);
}

/* ── Base64 decode tests ────────────────────────────────────────── */

TEST(UpdateClient, Base64DecodeBasic) {
    const char* b64 = "SGVsbG8=";  /* "Hello" */
    uint8_t out[16];
    size_t n = akav_base64_decode(b64, strlen(b64), out, sizeof(out));
    EXPECT_EQ(n, 5u);
    EXPECT_EQ(memcmp(out, "Hello", 5), 0);
}

TEST(UpdateClient, Base64DecodeNoPadding) {
    const char* b64 = "TWE=";  /* "Ma" */
    uint8_t out[16];
    size_t n = akav_base64_decode(b64, strlen(b64), out, sizeof(out));
    EXPECT_EQ(n, 2u);
    EXPECT_EQ(out[0], 'M');
    EXPECT_EQ(out[1], 'a');
}

TEST(UpdateClient, Base64DecodeEmpty) {
    uint8_t out[16];
    EXPECT_EQ(akav_base64_decode("", 0, out, sizeof(out)), 0u);
}

/* ── Manifest parsing tests ─────────────────────────────────────── */

static const char SIMPLE_MANIFEST[] = R"({
    "version": 42,
    "published_at": "2026-03-15T10:30:00Z",
    "minimum_engine_version": 1,
    "files": [
        {
            "name": "signatures.akavdb",
            "url": "https://update.example.com/v42/signatures.akavdb",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "rsa_signature": "AAAA",
            "size": 102400,
            "type": "full"
        }
    ],
    "manifest_signature": "BBBB"
})";

TEST(UpdateClient, ParseManifestBasic) {
    akav_update_manifest_t m;
    ASSERT_TRUE(akav_update_parse_manifest(SIMPLE_MANIFEST,
                                            strlen(SIMPLE_MANIFEST), &m));

    EXPECT_EQ(m.version, 42u);
    EXPECT_STREQ(m.published_at, "2026-03-15T10:30:00Z");
    EXPECT_EQ(m.minimum_engine_version, 1u);
    EXPECT_EQ(m.num_files, 1u);

    EXPECT_STREQ(m.files[0].name, "signatures.akavdb");
    EXPECT_STREQ(m.files[0].url,
                 "https://update.example.com/v42/signatures.akavdb");
    EXPECT_EQ(m.files[0].size, 102400u);
    EXPECT_STREQ(m.files[0].type, "full");

    /* SHA-256 should be decoded from hex */
    EXPECT_EQ(m.files[0].sha256[0], 0xe3);
    EXPECT_EQ(m.files[0].sha256[1], 0xb0);
    EXPECT_EQ(m.files[0].sha256[31], 0x55);

    EXPECT_TRUE(m.has_manifest_signature);
}

TEST(UpdateClient, ParseManifestMultipleFiles) {
    const char* json = R"({
        "version": 10,
        "published_at": "2026-01-01T00:00:00Z",
        "minimum_engine_version": 1,
        "files": [
            { "name": "a.akavdb", "url": "https://x/a", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "rsa_signature": "", "size": 100, "type": "full" },
            { "name": "b.yar", "url": "https://x/b", "sha256": "0000000000000000000000000000000000000000000000000000000000000001", "rsa_signature": "", "size": 200, "type": "delta" }
        ]
    })";
    akav_update_manifest_t m;
    ASSERT_TRUE(akav_update_parse_manifest(json, strlen(json), &m));
    EXPECT_EQ(m.num_files, 2u);
    EXPECT_STREQ(m.files[0].name, "a.akavdb");
    EXPECT_STREQ(m.files[1].name, "b.yar");
    EXPECT_STREQ(m.files[1].type, "delta");
}

TEST(UpdateClient, ParseManifestNoFiles) {
    const char* json = R"({ "version": 5, "files": [] })";
    akav_update_manifest_t m;
    ASSERT_TRUE(akav_update_parse_manifest(json, strlen(json), &m));
    EXPECT_EQ(m.version, 5u);
    EXPECT_EQ(m.num_files, 0u);
}

TEST(UpdateClient, ParseManifestInvalid) {
    akav_update_manifest_t m;
    EXPECT_FALSE(akav_update_parse_manifest("not json", 8, &m));
    EXPECT_FALSE(akav_update_parse_manifest(nullptr, 0, &m));
    EXPECT_FALSE(akav_update_parse_manifest("{}", 2, &m));  /* version=0 → invalid */
}

/* ── SHA-256 buffer tests ───────────────────────────────────────── */

TEST(UpdateClient, SHA256Buffer) {
    /* SHA-256 of empty string = e3b0c44298fc1c14... */
    uint8_t hash[32];
    ASSERT_TRUE(akav_update_sha256_buffer((const uint8_t*)"", 0, hash));
    EXPECT_EQ(hash[0], 0xe3);
    EXPECT_EQ(hash[1], 0xb0);
    EXPECT_EQ(hash[2], 0xc4);
}

TEST(UpdateClient, SHA256BufferKnown) {
    /* SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 */
    uint8_t hash[32];
    ASSERT_TRUE(akav_update_sha256_buffer((const uint8_t*)"hello", 5, hash));
    EXPECT_EQ(hash[0], 0x2c);
    EXPECT_EQ(hash[1], 0xf2);
    EXPECT_EQ(hash[31], 0x24);
}

/* ── SHA-256 file tests ─────────────────────────────────────────── */

TEST(UpdateClient, SHA256File) {
    const char* path = "test_update_sha256_tmp.bin";
    const char* data = "hello";
    write_file(path, data, 5);

    uint8_t hash[32];
    ASSERT_TRUE(akav_update_sha256_file(path, hash));
    EXPECT_EQ(hash[0], 0x2c);
    EXPECT_EQ(hash[1], 0xf2);

    remove(path);
}

TEST(UpdateClient, SHA256FileMissing) {
    uint8_t hash[32];
    EXPECT_FALSE(akav_update_sha256_file("nonexistent_file.bin", hash));
}

/* ── RSA-2048 sign + verify tests ───────────────────────────────── */

/* Helper: generate a test RSA-2048 key pair using CNG */
struct TestKeyPair {
    std::vector<uint8_t> pub_blob;
    BCRYPT_KEY_HANDLE priv_key;
    BCRYPT_ALG_HANDLE alg;

    TestKeyPair() : priv_key(NULL), alg(NULL) {}
    ~TestKeyPair() {
        if (priv_key) BCryptDestroyKey(priv_key);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    }
};

static bool generate_test_keypair(TestKeyPair& kp)
{
    NTSTATUS status = BCryptOpenAlgorithmProvider(&kp.alg, BCRYPT_RSA_ALGORITHM,
                                                   NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptGenerateKeyPair(kp.alg, &kp.priv_key, 2048, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptFinalizeKeyPair(kp.priv_key, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    /* Export public key blob */
    ULONG blob_len = 0;
    status = BCryptExportKey(kp.priv_key, NULL, BCRYPT_RSAPUBLIC_BLOB,
                              NULL, 0, &blob_len, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    kp.pub_blob.resize(blob_len);
    status = BCryptExportKey(kp.priv_key, NULL, BCRYPT_RSAPUBLIC_BLOB,
                              kp.pub_blob.data(), blob_len, &blob_len, 0);
    return BCRYPT_SUCCESS(status);
}

static bool test_rsa_sign(BCRYPT_KEY_HANDLE key, const uint8_t* data,
                          size_t data_len, std::vector<uint8_t>& signature)
{
    /* Hash data first */
    uint8_t hash[32];
    if (!akav_update_sha256_buffer(data, data_len, hash))
        return false;

    BCRYPT_PKCS1_PADDING_INFO padding;
    padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    ULONG sig_len = 0;
    NTSTATUS status = BCryptSignHash(key, &padding, hash, sizeof(hash),
                                      NULL, 0, &sig_len, BCRYPT_PAD_PKCS1);
    if (!BCRYPT_SUCCESS(status)) return false;

    signature.resize(sig_len);
    status = BCryptSignHash(key, &padding, hash, sizeof(hash),
                             signature.data(), sig_len, &sig_len,
                             BCRYPT_PAD_PKCS1);
    return BCRYPT_SUCCESS(status);
}

TEST(UpdateClient, RSAVerifyValid) {
    TestKeyPair kp;
    ASSERT_TRUE(generate_test_keypair(kp));

    const char* message = "This is a test message for RSA signing";
    std::vector<uint8_t> sig;
    ASSERT_TRUE(test_rsa_sign(kp.priv_key, (const uint8_t*)message,
                               strlen(message), sig));

    EXPECT_TRUE(akav_update_rsa_verify((const uint8_t*)message, strlen(message),
                                        sig.data(), sig.size(),
                                        kp.pub_blob.data(), kp.pub_blob.size()));
}

TEST(UpdateClient, RSAVerifyTamperedData) {
    TestKeyPair kp;
    ASSERT_TRUE(generate_test_keypair(kp));

    const char* message = "Original message";
    std::vector<uint8_t> sig;
    ASSERT_TRUE(test_rsa_sign(kp.priv_key, (const uint8_t*)message,
                               strlen(message), sig));

    /* Tamper with the message */
    const char* tampered = "Tampered message";
    EXPECT_FALSE(akav_update_rsa_verify((const uint8_t*)tampered, strlen(tampered),
                                         sig.data(), sig.size(),
                                         kp.pub_blob.data(), kp.pub_blob.size()));
}

TEST(UpdateClient, RSAVerifyTamperedSignature) {
    TestKeyPair kp;
    ASSERT_TRUE(generate_test_keypair(kp));

    const char* message = "Test message";
    std::vector<uint8_t> sig;
    ASSERT_TRUE(test_rsa_sign(kp.priv_key, (const uint8_t*)message,
                               strlen(message), sig));

    /* Flip a bit in the signature */
    sig[0] ^= 0x01;
    EXPECT_FALSE(akav_update_rsa_verify((const uint8_t*)message, strlen(message),
                                         sig.data(), sig.size(),
                                         kp.pub_blob.data(), kp.pub_blob.size()));
}

TEST(UpdateClient, RSAVerifyWrongKey) {
    TestKeyPair kp1, kp2;
    ASSERT_TRUE(generate_test_keypair(kp1));
    ASSERT_TRUE(generate_test_keypair(kp2));

    const char* message = "Test message";
    std::vector<uint8_t> sig;
    ASSERT_TRUE(test_rsa_sign(kp1.priv_key, (const uint8_t*)message,
                               strlen(message), sig));

    /* Verify with wrong key */
    EXPECT_FALSE(akav_update_rsa_verify((const uint8_t*)message, strlen(message),
                                         sig.data(), sig.size(),
                                         kp2.pub_blob.data(), kp2.pub_blob.size()));
}

TEST(UpdateClient, RSAVerifyNullParams) {
    EXPECT_FALSE(akav_update_rsa_verify(nullptr, 0, nullptr, 0, nullptr, 0));
}

/* ── Atomic install tests ───────────────────────────────────────── */

TEST(UpdateClient, AtomicInstallNewDB) {
    const char* current = "test_update_current.akavdb";
    const char* new_file = "test_update_current.akavdb.new";

    /* Create "current" DB */
    write_file(current, "OLD_DATA", 8);

    /* Create "new" DB */
    write_file(new_file, "NEW_DATA", 8);

    char error[256] = {0};
    ASSERT_TRUE(akav_update_install_db(new_file, current, error, sizeof(error)))
        << error;

    /* Current should now contain NEW_DATA */
    auto data = read_file(current);
    ASSERT_EQ(data.size(), 8u);
    EXPECT_EQ(memcmp(data.data(), "NEW_DATA", 8), 0);

    /* .prev should contain OLD_DATA */
    char prev[MAX_PATH];
    snprintf(prev, sizeof(prev), "%s.prev", current);
    auto prev_data = read_file(prev);
    ASSERT_EQ(prev_data.size(), 8u);
    EXPECT_EQ(memcmp(prev_data.data(), "OLD_DATA", 8), 0);

    /* .new should be gone (moved) */
    EXPECT_EQ(GetFileAttributesA(new_file), INVALID_FILE_ATTRIBUTES);

    remove(current);
    remove(prev);
}

TEST(UpdateClient, AtomicInstallNoCurrent) {
    const char* current = "test_update_nocurrent.akavdb";
    const char* new_file = "test_update_nocurrent.akavdb.new";

    /* Ensure current doesn't exist */
    DeleteFileA(current);

    /* Create new file */
    write_file(new_file, "FRESH", 5);

    char error[256] = {0};
    ASSERT_TRUE(akav_update_install_db(new_file, current, error, sizeof(error)))
        << error;

    auto data = read_file(current);
    ASSERT_EQ(data.size(), 5u);
    EXPECT_EQ(memcmp(data.data(), "FRESH", 5), 0);

    remove(current);
}

/* ── Rollback tests ─────────────────────────────────────────────── */

TEST(UpdateClient, RollbackRestoresPrev) {
    const char* current = "test_update_rollback.akavdb";
    char prev[MAX_PATH];
    snprintf(prev, sizeof(prev), "%s.prev", current);

    /* Create current (bad) and .prev (good) */
    write_file(current, "BAD_DATA", 8);
    write_file(prev, "GOOD_DATA", 9);

    char error[256] = {0};
    ASSERT_TRUE(akav_update_rollback(current, error, sizeof(error)))
        << error;

    /* Current should now be GOOD_DATA */
    auto data = read_file(current);
    ASSERT_EQ(data.size(), 9u);
    EXPECT_EQ(memcmp(data.data(), "GOOD_DATA", 9), 0);

    /* .prev should be gone */
    EXPECT_EQ(GetFileAttributesA(prev), INVALID_FILE_ATTRIBUTES);

    remove(current);
}

TEST(UpdateClient, RollbackNoPrevFails) {
    const char* current = "test_update_no_prev.akavdb";
    char prev[MAX_PATH];
    snprintf(prev, sizeof(prev), "%s.prev", current);
    DeleteFileA(prev);

    char error[256] = {0};
    EXPECT_FALSE(akav_update_rollback(current, error, sizeof(error)));
    EXPECT_STRNE(error, "");
}

/* ── Version comparison (via manifest parsing) ──────────────────── */

TEST(UpdateClient, VersionComparison) {
    /* Build a manifest with version 10 */
    const char* json = R"({
        "version": 10,
        "published_at": "2026-01-01",
        "files": []
    })";
    akav_update_manifest_t m;
    ASSERT_TRUE(akav_update_parse_manifest(json, strlen(json), &m));
    EXPECT_EQ(m.version, 10u);

    /* Simulating: current_version=10, manifest_version=10 → no update */
    EXPECT_FALSE(m.version > 10u);  /* same version → skip */

    /* current_version=5, manifest_version=10 → update available */
    EXPECT_TRUE(m.version > 5u);

    /* current_version=15, manifest_version=10 → downgrade, skip */
    EXPECT_FALSE(m.version > 15u);
}

/* ── Integrated RSA manifest verification ───────────────────────── */

TEST(UpdateClient, ManifestRSAVerification) {
    /* Generate key pair */
    TestKeyPair kp;
    ASSERT_TRUE(generate_test_keypair(kp));

    /* Create a manifest body (the content to be signed) */
    const char* manifest_body = R"({
        "version": 42,
        "published_at": "2026-03-15T10:30:00Z",
        "minimum_engine_version": 1,
        "files": [
            {
                "name": "test.akavdb",
                "url": "https://x/test.akavdb",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "rsa_signature": "",
                "size": 1024,
                "type": "full"
            }
        ]
    })";

    /* Sign the manifest body */
    std::vector<uint8_t> sig;
    ASSERT_TRUE(test_rsa_sign(kp.priv_key,
                               (const uint8_t*)manifest_body,
                               strlen(manifest_body), sig));

    /* Verify the signature using our function */
    EXPECT_TRUE(akav_update_rsa_verify(
        (const uint8_t*)manifest_body, strlen(manifest_body),
        sig.data(), sig.size(),
        kp.pub_blob.data(), kp.pub_blob.size()));

    /* Tamper with manifest body → verification fails */
    std::string tampered(manifest_body);
    tampered[10] = 'X';
    EXPECT_FALSE(akav_update_rsa_verify(
        (const uint8_t*)tampered.c_str(), tampered.size(),
        sig.data(), sig.size(),
        kp.pub_blob.data(), kp.pub_blob.size()));
}

/* ── SHA-256 file verification (simulates download verify) ──────── */

TEST(UpdateClient, FileHashVerification) {
    const char* path = "test_update_verify.bin";
    const char* content = "signature database content";
    write_file(path, content, strlen(content));

    /* Compute expected hash */
    uint8_t expected[32];
    ASSERT_TRUE(akav_update_sha256_buffer((const uint8_t*)content,
                                           strlen(content), expected));

    /* Verify file matches */
    uint8_t file_hash[32];
    ASSERT_TRUE(akav_update_sha256_file(path, file_hash));
    EXPECT_EQ(memcmp(file_hash, expected, 32), 0);

    /* Tamper: write different content */
    write_file(path, "tampered content!!!", 19);
    ASSERT_TRUE(akav_update_sha256_file(path, file_hash));
    EXPECT_NE(memcmp(file_hash, expected, 32), 0);

    remove(path);
}

/* ── Full install + rollback cycle ──────────────────────────────── */

TEST(UpdateClient, FullInstallRollbackCycle) {
    const char* db = "test_update_cycle.akavdb";
    const char* db_new = "test_update_cycle.akavdb.new";
    char db_prev[MAX_PATH];
    snprintf(db_prev, sizeof(db_prev), "%s.prev", db);

    /* Start with v1 */
    write_file(db, "V1_CONTENT", 10);

    /* "Download" v2 */
    write_file(db_new, "V2_CONTENT", 10);

    /* Install v2 */
    char error[256] = {0};
    ASSERT_TRUE(akav_update_install_db(db_new, db, error, sizeof(error)));

    /* Verify v2 is current, v1 is .prev */
    auto current = read_file(db);
    EXPECT_EQ(memcmp(current.data(), "V2_CONTENT", 10), 0);
    auto prev = read_file(db_prev);
    EXPECT_EQ(memcmp(prev.data(), "V1_CONTENT", 10), 0);

    /* Simulate bad DB — rollback to v1 */
    ASSERT_TRUE(akav_update_rollback(db, error, sizeof(error)));
    current = read_file(db);
    EXPECT_EQ(memcmp(current.data(), "V1_CONTENT", 10), 0);

    remove(db);
    DeleteFileA(db_prev);
}
