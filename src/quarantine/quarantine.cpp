/* quarantine.cpp -- AkesoAV quarantine vault implementation.
 *
 * Implements §5.12:
 *   - AES-256-GCM encryption via CNG (BCryptEncrypt/BCryptDecrypt)
 *   - DPAPI key management (CryptProtectData/CryptUnprotectData)
 *   - SQLite index for quarantine metadata
 *   - ACLs: vault directory restricted to SYSTEM + Administrators
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <sddl.h>    /* ConvertSidToStringSid, ConvertStringSecurityDescriptorToSecurityDescriptor */
#include <aclapi.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#include "quarantine.h"
#include "signatures/hash_matcher.h"  /* akav_hash_sha256 */

#include <sqlite3.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <cstdlib>

/* ── Constants ──────────────────────────────────────────────────── */

static const size_t AES_KEY_LEN = 32;   /* AES-256 */
static const size_t GCM_IV_LEN  = 12;   /* NIST recommended for GCM */
static const size_t GCM_TAG_LEN = 16;   /* 128-bit auth tag */

/* ── Logging ────────────────────────────────────────────────────── */

static void q_log(const char* level, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[quarantine][%s] ", level);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* ── Quarantine ─────────────────────────────────────────────────── */

Quarantine::Quarantine()
    : db_(nullptr)
    , key_loaded_(false)
    , alg_(NULL)
{
    SecureZeroMemory(aes_key_, sizeof(aes_key_));
}

Quarantine::~Quarantine()
{
    shutdown();
}

/* ── Init / Shutdown ───────────────────────────────────────────── */

bool Quarantine::init(const char* vault_dir)
{
    if (!vault_dir || !vault_dir[0]) {
        q_log("error", "Empty vault directory");
        return false;
    }

    vault_dir_ = vault_dir;

    /* Normalize trailing backslash */
    if (vault_dir_.back() != '\\' && vault_dir_.back() != '/')
        vault_dir_ += '\\';

    vault_path_ = vault_dir_ + "vault\\";
    db_path_ = vault_dir_ + "quarantine.db";
    key_path_ = vault_dir_ + "key.dpapi";

    /* Create directories */
    CreateDirectoryA(vault_dir_.c_str(), NULL);
    CreateDirectoryA(vault_path_.c_str(), NULL);

    /* Open CNG AES algorithm provider */
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &alg_, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        q_log("error", "BCryptOpenAlgorithmProvider failed: 0x%08lx", status);
        return false;
    }

    /* Set chaining mode to GCM */
    status = BCryptSetProperty(
        alg_, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        q_log("error", "BCryptSetProperty (GCM mode) failed: 0x%08lx", status);
        BCryptCloseAlgorithmProvider(alg_, 0);
        alg_ = NULL;
        return false;
    }

    /* Load or generate encryption key */
    if (GetFileAttributesA(key_path_.c_str()) != INVALID_FILE_ATTRIBUTES) {
        if (!load_key_dpapi()) {
            q_log("error", "Failed to load DPAPI key — generating new one");
            if (!generate_key() || !save_key_dpapi())
                return false;
        }
    } else {
        if (!generate_key() || !save_key_dpapi())
            return false;
    }

    /* Open SQLite database */
    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        q_log("error", "sqlite3_open('%s') failed: %s",
              db_path_.c_str(), sqlite3_errmsg(db_));
        db_ = nullptr;
        return false;
    }

    /* Enable WAL mode for better concurrent read performance */
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    if (!create_tables()) {
        q_log("error", "Failed to create quarantine tables");
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }

    /* Set restrictive ACL on vault directory (SYSTEM + Admins only).
     * Done last so initialization can complete even without admin rights.
     * If this fails (non-admin), vault still works but without ACL hardening. */
    set_vault_acl();

    q_log("info", "Quarantine initialized: vault=%s", vault_dir_.c_str());
    return true;
}

void Quarantine::shutdown()
{
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }

    if (alg_) {
        BCryptCloseAlgorithmProvider(alg_, 0);
        alg_ = NULL;
    }

    /* Securely zero key material */
    SecureZeroMemory(aes_key_, sizeof(aes_key_));
    key_loaded_ = false;
}

/* ── Key management ────────────────────────────────────────────── */

bool Quarantine::generate_key()
{
    NTSTATUS status = BCryptGenRandom(
        NULL, aes_key_, AES_KEY_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        q_log("error", "BCryptGenRandom failed: 0x%08lx", status);
        return false;
    }
    key_loaded_ = true;
    q_log("info", "Generated new AES-256 key");
    return true;
}

bool Quarantine::save_key_dpapi()
{
    if (!key_loaded_) return false;

    DATA_BLOB input;
    input.pbData = aes_key_;
    input.cbData = AES_KEY_LEN;

    DATA_BLOB output{};

    /* CRYPTPROTECT_LOCAL_MACHINE: machine-scope protection (any admin can decrypt) */
    if (!CryptProtectData(&input, L"AkesoAV Quarantine Key",
                          NULL, NULL, NULL,
                          CRYPTPROTECT_LOCAL_MACHINE, &output)) {
        q_log("error", "CryptProtectData failed: %lu", GetLastError());
        return false;
    }

    /* Write protected blob to file */
    HANDLE hf = CreateFileA(key_path_.c_str(), GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        q_log("error", "Cannot create key file '%s': %lu",
              key_path_.c_str(), GetLastError());
        LocalFree(output.pbData);
        return false;
    }

    DWORD written = 0;
    WriteFile(hf, output.pbData, output.cbData, &written, NULL);
    CloseHandle(hf);
    LocalFree(output.pbData);

    q_log("info", "Saved DPAPI-protected key to '%s'", key_path_.c_str());
    return written == output.cbData;
}

bool Quarantine::load_key_dpapi()
{
    /* Read protected blob from file */
    HANDLE hf = CreateFileA(key_path_.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        q_log("error", "Cannot open key file '%s': %lu",
              key_path_.c_str(), GetLastError());
        return false;
    }

    DWORD file_size = GetFileSize(hf, NULL);
    if (file_size == 0 || file_size > 65536) {
        q_log("error", "Key file size invalid: %lu", file_size);
        CloseHandle(hf);
        return false;
    }

    std::vector<uint8_t> blob(file_size);
    DWORD read_count = 0;
    ReadFile(hf, blob.data(), file_size, &read_count, NULL);
    CloseHandle(hf);

    if (read_count != file_size) {
        q_log("error", "Key file read incomplete");
        return false;
    }

    DATA_BLOB input;
    input.pbData = blob.data();
    input.cbData = (DWORD)blob.size();

    DATA_BLOB output{};

    if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        q_log("error", "CryptUnprotectData failed: %lu", GetLastError());
        return false;
    }

    if (output.cbData != AES_KEY_LEN) {
        q_log("error", "Decrypted key wrong size: %lu (expected %zu)",
              output.cbData, AES_KEY_LEN);
        LocalFree(output.pbData);
        return false;
    }

    memcpy(aes_key_, output.pbData, AES_KEY_LEN);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);

    key_loaded_ = true;
    q_log("info", "Loaded DPAPI-protected key from '%s'", key_path_.c_str());
    return true;
}

/* ── AES-256-GCM ───────────────────────────────────────────────── */

bool Quarantine::aes_gcm_encrypt(const uint8_t* plaintext, size_t plain_len,
                                  const uint8_t* iv, size_t iv_len,
                                  uint8_t* ciphertext,
                                  uint8_t* tag, size_t tag_len)
{
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = BCryptGenerateSymmetricKey(
        alg_, &hKey, NULL, 0, aes_key_, AES_KEY_LEN, 0);
    if (!BCRYPT_SUCCESS(status)) {
        q_log("error", "BCryptGenerateSymmetricKey failed: 0x%08lx", status);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = (ULONG)iv_len;
    authInfo.pbTag = tag;
    authInfo.cbTag = (ULONG)tag_len;

    ULONG out_len = 0;
    status = BCryptEncrypt(
        hKey,
        (PUCHAR)plaintext, (ULONG)plain_len,
        &authInfo,
        NULL, 0,  /* No separate IV for GCM — nonce is in authInfo */
        ciphertext, (ULONG)plain_len,
        &out_len, 0);

    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status)) {
        q_log("error", "BCryptEncrypt (GCM) failed: 0x%08lx", status);
        return false;
    }

    return true;
}

bool Quarantine::aes_gcm_decrypt(const uint8_t* ciphertext, size_t cipher_len,
                                  const uint8_t* iv, size_t iv_len,
                                  const uint8_t* tag, size_t tag_len,
                                  uint8_t* plaintext)
{
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = BCryptGenerateSymmetricKey(
        alg_, &hKey, NULL, 0, aes_key_, AES_KEY_LEN, 0);
    if (!BCRYPT_SUCCESS(status)) {
        q_log("error", "BCryptGenerateSymmetricKey failed: 0x%08lx", status);
        return false;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = (ULONG)iv_len;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = (ULONG)tag_len;

    ULONG out_len = 0;
    status = BCryptDecrypt(
        hKey,
        (PUCHAR)ciphertext, (ULONG)cipher_len,
        &authInfo,
        NULL, 0,
        plaintext, (ULONG)cipher_len,
        &out_len, 0);

    BCryptDestroyKey(hKey);

    if (!BCRYPT_SUCCESS(status)) {
        q_log("error", "BCryptDecrypt (GCM) failed: 0x%08lx", status);
        return false;
    }

    return true;
}

/* ── File encryption / decryption ──────────────────────────────── */

bool Quarantine::encrypt_file(const char* src_path, const char* dst_path)
{
    /* Read source file */
    HANDLE hf = CreateFileA(src_path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        q_log("error", "Cannot open source file '%s': %lu",
              src_path, GetLastError());
        return false;
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hf, &file_size) || file_size.QuadPart > (1LL << 30)) {
        q_log("error", "File too large or size error: %s", src_path);
        CloseHandle(hf);
        return false;
    }

    size_t data_len = (size_t)file_size.QuadPart;
    std::vector<uint8_t> plaintext(data_len);

    DWORD read_count = 0;
    if (data_len > 0) {
        ReadFile(hf, plaintext.data(), (DWORD)data_len, &read_count, NULL);
    }
    CloseHandle(hf);

    if (read_count != (DWORD)data_len) {
        q_log("error", "Read incomplete for '%s'", src_path);
        return false;
    }

    /* Generate random IV */
    uint8_t iv[GCM_IV_LEN];
    BCryptGenRandom(NULL, iv, (ULONG)GCM_IV_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    /* Encrypt */
    std::vector<uint8_t> ciphertext(data_len);
    uint8_t tag[GCM_TAG_LEN];

    if (data_len > 0) {
        if (!aes_gcm_encrypt(plaintext.data(), data_len, iv, GCM_IV_LEN,
                             ciphertext.data(), tag, GCM_TAG_LEN))
            return false;
    } else {
        /* Empty file — just store IV + tag + no ciphertext */
        memset(tag, 0, GCM_TAG_LEN);
        /* For empty plaintext, generate tag with empty encrypt */
        if (!aes_gcm_encrypt(nullptr, 0, iv, GCM_IV_LEN,
                             nullptr, tag, GCM_TAG_LEN)) {
            /* Fallback: zero tag is fine for empty file */
        }
    }

    /* Write .sqz: [IV 12] [TAG 16] [ciphertext...] */
    HANDLE out = CreateFileA(dst_path, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) {
        q_log("error", "Cannot create .sqz file '%s': %lu",
              dst_path, GetLastError());
        return false;
    }

    DWORD written = 0;
    WriteFile(out, iv, GCM_IV_LEN, &written, NULL);
    WriteFile(out, tag, GCM_TAG_LEN, &written, NULL);
    if (data_len > 0)
        WriteFile(out, ciphertext.data(), (DWORD)data_len, &written, NULL);
    CloseHandle(out);

    /* Securely zero plaintext */
    SecureZeroMemory(plaintext.data(), plaintext.size());

    return true;
}

bool Quarantine::decrypt_file(const char* src_path, const char* dst_path)
{
    /* Read .sqz file */
    HANDLE hf = CreateFileA(src_path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        q_log("error", "Cannot open .sqz file '%s': %lu",
              src_path, GetLastError());
        return false;
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hf, &file_size)) {
        CloseHandle(hf);
        return false;
    }

    size_t total = (size_t)file_size.QuadPart;
    size_t header = GCM_IV_LEN + GCM_TAG_LEN;
    if (total < header) {
        q_log("error", ".sqz file too small: %zu bytes", total);
        CloseHandle(hf);
        return false;
    }

    std::vector<uint8_t> sqz_data(total);
    DWORD read_count = 0;
    ReadFile(hf, sqz_data.data(), (DWORD)total, &read_count, NULL);
    CloseHandle(hf);

    if (read_count != (DWORD)total) {
        q_log("error", "Read incomplete for .sqz '%s'", src_path);
        return false;
    }

    /* Parse: [IV 12] [TAG 16] [ciphertext...] */
    const uint8_t* iv = sqz_data.data();
    const uint8_t* tag = sqz_data.data() + GCM_IV_LEN;
    const uint8_t* ciphertext = sqz_data.data() + header;
    size_t cipher_len = total - header;

    std::vector<uint8_t> plaintext(cipher_len);

    if (cipher_len > 0) {
        if (!aes_gcm_decrypt(ciphertext, cipher_len, iv, GCM_IV_LEN,
                             tag, GCM_TAG_LEN, plaintext.data()))
            return false;
    }

    /* Write decrypted file */
    HANDLE out = CreateFileA(dst_path, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) {
        q_log("error", "Cannot create restored file '%s': %lu",
              dst_path, GetLastError());
        return false;
    }

    DWORD written = 0;
    if (cipher_len > 0)
        WriteFile(out, plaintext.data(), (DWORD)cipher_len, &written, NULL);
    CloseHandle(out);

    return true;
}

/* ── SQLite helpers ────────────────────────────────────────────── */

bool Quarantine::create_tables()
{
    const char* sql =
        "CREATE TABLE IF NOT EXISTS quarantine ("
        "  id TEXT PRIMARY KEY,"
        "  original_path TEXT NOT NULL,"
        "  malware_name TEXT NOT NULL,"
        "  signature_id TEXT,"
        "  timestamp INTEGER NOT NULL,"
        "  sha256 TEXT NOT NULL,"
        "  file_size INTEGER NOT NULL,"
        "  user_sid TEXT"
        ");";

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        q_log("error", "CREATE TABLE failed: %s", err_msg);
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}

bool Quarantine::insert_entry(const QuarantineEntry& entry)
{
    const char* sql =
        "INSERT INTO quarantine (id, original_path, malware_name, signature_id,"
        " timestamp, sha256, file_size, user_sid)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        q_log("error", "prepare insert failed: %s", sqlite3_errmsg(db_));
        return false;
    }

    sqlite3_bind_text(stmt, 1, entry.id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry.original_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry.malware_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry.signature_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, entry.timestamp);
    sqlite3_bind_text(stmt, 6, entry.sha256, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, entry.file_size);
    sqlite3_bind_text(stmt, 8, entry.user_sid, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        q_log("error", "insert failed: %s", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

bool Quarantine::remove_entry(const char* vault_id)
{
    const char* sql = "DELETE FROM quarantine WHERE id = ?;";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, vault_id, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

/* ── Vault ID generation ───────────────────────────────────────── */

std::string Quarantine::generate_vault_id()
{
    /* Format: q-YYYYMMDDHHMMSS-XXXX where XXXX is random hex */
    time_t now = time(nullptr);
    struct tm local_tm;
    localtime_s(&local_tm, &now);

    uint16_t rnd = 0;
    BCryptGenRandom(NULL, (PUCHAR)&rnd, sizeof(rnd),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    char buf[64];
    snprintf(buf, sizeof(buf), "q-%04d%02d%02d%02d%02d%02d-%04x",
             local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday,
             local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec,
             rnd);
    return buf;
}

/* ── SHA-256 hex ───────────────────────────────────────────────── */

std::string Quarantine::compute_sha256_hex(const uint8_t* data, size_t len)
{
    uint8_t hash[32];
    if (!akav_hash_sha256(data, len, hash))
        return std::string(64, '0');

    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", hash[i]);
    hex[64] = '\0';
    return hex;
}

/* ── Current user SID ──────────────────────────────────────────── */

std::string Quarantine::get_current_user_sid()
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return "S-1-0-0";

    DWORD len = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &len);

    std::vector<uint8_t> buf(len);
    if (!GetTokenInformation(token, TokenUser, buf.data(), len, &len)) {
        CloseHandle(token);
        return "S-1-0-0";
    }
    CloseHandle(token);

    TOKEN_USER* user = (TOKEN_USER*)buf.data();
    LPSTR sid_str = NULL;
    if (!ConvertSidToStringSidA(user->User.Sid, &sid_str))
        return "S-1-0-0";

    std::string result(sid_str);
    LocalFree(sid_str);
    return result;
}

/* ── ACL ───────────────────────────────────────────────────────── */

bool Quarantine::set_vault_acl()
{
    /* Check if running elevated — only apply restrictive ACL if so.
     * Under UAC, non-elevated admin processes don't have the Administrators
     * group enabled, so a DACL restricted to BA would lock us out. */
    BOOL is_elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation{};
        DWORD len = 0;
        if (GetTokenInformation(token, TokenElevation, &elevation,
                                sizeof(elevation), &len)) {
            is_elevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }

    if (!is_elevated) {
        q_log("info", "Not elevated — skipping restrictive ACL (dev/test mode)");
        return true;
    }

    /* SDDL: D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)
     *   D:P   = DACL, protected (no inheritance)
     *   A     = Allow
     *   OICI  = Object inherit + Container inherit
     *   FA    = Full access
     *   SY    = SYSTEM
     *   BA    = Builtin Administrators */
    const char* sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl, SDDL_REVISION_1, &sd, NULL)) {
        q_log("warn", "ConvertStringSecurityDescriptor failed: %lu", GetLastError());
        return false;
    }

    /* Extract DACL from the security descriptor */
    PACL dacl = NULL;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    GetSecurityDescriptorDacl(sd, &dacl_present, &dacl, &dacl_defaulted);

    DWORD err = SetNamedSecurityInfoA(
        (LPSTR)vault_dir_.c_str(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, dacl, NULL);

    LocalFree(sd);

    if (err != ERROR_SUCCESS) {
        q_log("warn", "SetNamedSecurityInfo failed: %lu (may need admin)", err);
        return false;
    }

    /* Also apply to vault subdirectory */
    err = SetNamedSecurityInfoA(
        (LPSTR)vault_path_.c_str(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, dacl, NULL);

    q_log("info", "ACL set: SYSTEM + Administrators only");
    return true;
}

/* ── .sqz path helper ──────────────────────────────────────────── */

std::string Quarantine::sqz_path(const char* vault_id) const
{
    return vault_path_ + vault_id + ".sqz";
}

/* ── Quarantine operations ─────────────────────────────────────── */

std::string Quarantine::quarantine_file(const char* file_path,
                                         const char* malware_name,
                                         const char* signature_id)
{
    if (!db_ || !key_loaded_) {
        q_log("error", "Quarantine not initialized");
        return "";
    }

    /* Read original file to compute SHA-256 */
    HANDLE hf = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        q_log("error", "Cannot open '%s' for quarantine: %lu",
              file_path, GetLastError());
        return "";
    }

    LARGE_INTEGER file_size;
    GetFileSizeEx(hf, &file_size);

    std::vector<uint8_t> file_data((size_t)file_size.QuadPart);
    DWORD read_count = 0;
    if (file_size.QuadPart > 0)
        ReadFile(hf, file_data.data(), (DWORD)file_size.QuadPart, &read_count, NULL);
    CloseHandle(hf);

    std::string sha256_hex = compute_sha256_hex(file_data.data(), file_data.size());

    /* Generate vault ID and encrypt */
    std::string vid = generate_vault_id();
    std::string sqz = sqz_path(vid.c_str());

    if (!encrypt_file(file_path, sqz.c_str())) {
        q_log("error", "Encryption failed for '%s'", file_path);
        return "";
    }

    /* Build index entry */
    QuarantineEntry entry{};
    strncpy_s(entry.id, sizeof(entry.id), vid.c_str(), _TRUNCATE);
    strncpy_s(entry.original_path, sizeof(entry.original_path),
              file_path, _TRUNCATE);
    strncpy_s(entry.malware_name, sizeof(entry.malware_name),
              malware_name ? malware_name : "", _TRUNCATE);
    strncpy_s(entry.signature_id, sizeof(entry.signature_id),
              signature_id ? signature_id : "", _TRUNCATE);
    entry.timestamp = (int64_t)time(nullptr);
    strncpy_s(entry.sha256, sizeof(entry.sha256),
              sha256_hex.c_str(), _TRUNCATE);
    entry.file_size = file_size.QuadPart;

    std::string sid = get_current_user_sid();
    strncpy_s(entry.user_sid, sizeof(entry.user_sid),
              sid.c_str(), _TRUNCATE);

    if (!insert_entry(entry)) {
        /* Remove .sqz on index failure */
        DeleteFileA(sqz.c_str());
        return "";
    }

    /* Delete original file */
    if (!DeleteFileA(file_path)) {
        q_log("warn", "Could not delete original '%s': %lu",
              file_path, GetLastError());
        /* Not fatal — file is quarantined even if original remains */
    }

    q_log("info", "Quarantined '%s' → %s.sqz (%s)",
          file_path, vid.c_str(), malware_name ? malware_name : "");

    return vid;
}

bool Quarantine::restore_file(const char* vault_id, const char* restore_path)
{
    if (!db_ || !key_loaded_) return false;

    /* Look up the entry to get original_path if no restore_path specified */
    std::string target;
    if (restore_path && restore_path[0]) {
        target = restore_path;
    } else {
        /* Query original_path from index */
        const char* sql = "SELECT original_path FROM quarantine WHERE id = ?;";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) return false;

        sqlite3_bind_text(stmt, 1, vault_id, -1, SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            target = (const char*)sqlite3_column_text(stmt, 0);
        }
        sqlite3_finalize(stmt);

        if (target.empty()) {
            q_log("error", "Entry '%s' not found in index", vault_id);
            return false;
        }
    }

    /* Decrypt */
    std::string sqz = sqz_path(vault_id);
    if (!decrypt_file(sqz.c_str(), target.c_str())) {
        q_log("error", "Decryption failed for '%s'", vault_id);
        return false;
    }

    /* Remove .sqz and index entry */
    DeleteFileA(sqz.c_str());
    remove_entry(vault_id);

    q_log("info", "Restored '%s' → '%s'", vault_id, target.c_str());
    return true;
}

std::vector<QuarantineEntry> Quarantine::list()
{
    std::vector<QuarantineEntry> entries;
    if (!db_) return entries;

    const char* sql =
        "SELECT id, original_path, malware_name, signature_id,"
        " timestamp, sha256, file_size, user_sid"
        " FROM quarantine ORDER BY timestamp DESC;";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return entries;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        QuarantineEntry e{};
        strncpy_s(e.id, sizeof(e.id),
                  (const char*)sqlite3_column_text(stmt, 0), _TRUNCATE);
        strncpy_s(e.original_path, sizeof(e.original_path),
                  (const char*)sqlite3_column_text(stmt, 1), _TRUNCATE);
        strncpy_s(e.malware_name, sizeof(e.malware_name),
                  (const char*)sqlite3_column_text(stmt, 2), _TRUNCATE);
        const char* sig = (const char*)sqlite3_column_text(stmt, 3);
        strncpy_s(e.signature_id, sizeof(e.signature_id),
                  sig ? sig : "", _TRUNCATE);
        e.timestamp = sqlite3_column_int64(stmt, 4);
        strncpy_s(e.sha256, sizeof(e.sha256),
                  (const char*)sqlite3_column_text(stmt, 5), _TRUNCATE);
        e.file_size = sqlite3_column_int64(stmt, 6);
        const char* sid = (const char*)sqlite3_column_text(stmt, 7);
        strncpy_s(e.user_sid, sizeof(e.user_sid),
                  sid ? sid : "", _TRUNCATE);
        entries.push_back(e);
    }

    sqlite3_finalize(stmt);
    return entries;
}

bool Quarantine::delete_entry(const char* vault_id)
{
    if (!db_) return false;

    /* Remove .sqz file */
    std::string sqz = sqz_path(vault_id);
    DeleteFileA(sqz.c_str());

    /* Remove index entry */
    return remove_entry(vault_id);
}

int Quarantine::purge(int days)
{
    if (!db_) return 0;

    int64_t cutoff = (int64_t)time(nullptr) - (int64_t)days * 86400;

    /* First, get the IDs to delete so we can remove .sqz files */
    const char* select_sql = "SELECT id FROM quarantine WHERE timestamp < ?;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, cutoff);

    std::vector<std::string> ids;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ids.push_back((const char*)sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);

    /* Delete .sqz files */
    for (auto& id : ids) {
        std::string sqz = sqz_path(id.c_str());
        DeleteFileA(sqz.c_str());
    }

    /* Delete index entries */
    const char* delete_sql = "DELETE FROM quarantine WHERE timestamp < ?;";
    rc = sqlite3_prepare_v2(db_, delete_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    sqlite3_bind_int64(stmt, 1, cutoff);
    sqlite3_step(stmt);
    int deleted = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (deleted > 0)
        q_log("info", "Purged %d entries older than %d days", deleted, days);

    return deleted;
}

int Quarantine::count()
{
    if (!db_) return 0;

    const char* sql = "SELECT COUNT(*) FROM quarantine;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    int cnt = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        cnt = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return cnt;
}
