/* whitelist.cpp -- Hash/path/signer exclusion mechanism.
 *
 * Implements section 5.4:
 *   - SHA-256 hash whitelist (sorted vector + binary search)
 *   - Path prefix exclusions (case-insensitive)
 *   - Authenticode signer trust (WinVerifyTrust + CertGetNameString)
 *
 * Thread safety: SRWLOCK reader-writer on all mutable state.
 */

#include "whitelist.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#include <algorithm>
#include <cstring>
#include <cctype>

namespace akav {

/* ── Helpers ────────────────────────────────────────────────────── */

static std::string to_lower(const char* s)
{
    std::string result;
    if (!s) return result;
    result.reserve(strlen(s));
    for (const char* p = s; *p; ++p)
        result.push_back((char)std::tolower((unsigned char)*p));
    return result;
}

static int compare_hash(const std::vector<uint8_t>& a,
                         const std::vector<uint8_t>& b)
{
    return memcmp(a.data(), b.data(), 32);
}

/* ── Whitelist implementation ──────────────────────────────────── */

Whitelist::Whitelist()
{
    InitializeSRWLock(&lock_);
}

Whitelist::~Whitelist()
{
    /* SRWLOCK does not need explicit destruction */
}

/* ── Hash whitelist ────────────────────────────────────────────── */

void Whitelist::add_hash(const uint8_t sha256[32])
{
    if (!sha256) return;

    std::vector<uint8_t> hash(sha256, sha256 + 32);

    AcquireSRWLockExclusive(&lock_);

    /* Insert in sorted order (binary search for position) */
    auto it = std::lower_bound(hashes_.begin(), hashes_.end(), hash,
        [](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
            return compare_hash(a, b) < 0;
        });

    /* Don't insert duplicates */
    if (it == hashes_.end() || compare_hash(*it, hash) != 0) {
        hashes_.insert(it, std::move(hash));
    }

    ReleaseSRWLockExclusive(&lock_);
}

bool Whitelist::is_hash_whitelisted(const uint8_t sha256[32]) const
{
    if (!sha256) return false;

    std::vector<uint8_t> hash(sha256, sha256 + 32);

    AcquireSRWLockShared(&lock_);

    bool found = std::binary_search(hashes_.begin(), hashes_.end(), hash,
        [](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
            return compare_hash(a, b) < 0;
        });

    ReleaseSRWLockShared(&lock_);
    return found;
}

/* ── Path exclusions ───────────────────────────────────────────── */

void Whitelist::add_path(const char* path_prefix)
{
    if (!path_prefix || !path_prefix[0]) return;

    std::string lower = to_lower(path_prefix);

    /* Normalize backslashes to forward slashes for consistent matching */
    for (char& c : lower) {
        if (c == '/') c = '\\';
    }

    AcquireSRWLockExclusive(&lock_);

    /* Don't insert duplicates */
    auto it = std::find(path_prefixes_.begin(), path_prefixes_.end(), lower);
    if (it == path_prefixes_.end()) {
        path_prefixes_.push_back(std::move(lower));
    }

    ReleaseSRWLockExclusive(&lock_);
}

bool Whitelist::is_path_excluded(const char* path) const
{
    if (!path || !path[0]) return false;

    std::string lower_path = to_lower(path);
    /* Normalize forward slashes */
    for (char& c : lower_path) {
        if (c == '/') c = '\\';
    }

    AcquireSRWLockShared(&lock_);

    for (const auto& prefix : path_prefixes_) {
        if (lower_path.size() >= prefix.size() &&
            lower_path.compare(0, prefix.size(), prefix) == 0)
        {
            ReleaseSRWLockShared(&lock_);
            return true;
        }
    }

    ReleaseSRWLockShared(&lock_);
    return false;
}

/* ── Signer trust ──────────────────────────────────────────────── */

void Whitelist::add_signer(const char* signer_name)
{
    if (!signer_name || !signer_name[0]) return;

    std::string lower = to_lower(signer_name);

    AcquireSRWLockExclusive(&lock_);

    auto it = std::find(signers_.begin(), signers_.end(), lower);
    if (it == signers_.end()) {
        signers_.push_back(std::move(lower));
    }

    ReleaseSRWLockExclusive(&lock_);
}

/**
 * Helper: extract signer name from WinVerifyTrust state and check against
 * our trusted signer list. Returns true if a match is found.
 */
bool Whitelist::check_signer_from_state(HANDLE state_data) const
{
    if (!state_data) return false;

    CRYPT_PROVIDER_DATA* prov_data = WTHelperProvDataFromStateData(state_data);
    if (!prov_data) return false;

    CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(
        prov_data, 0, FALSE, 0);
    if (!signer || !signer->pasCertChain || signer->csCertChain == 0)
        return false;

    PCCERT_CONTEXT cert = signer->pasCertChain[0].pCert;
    if (!cert) return false;

    char name_buf[256]{};
    DWORD name_len = CertGetNameStringA(
        cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL,
        name_buf, sizeof(name_buf));

    if (name_len <= 1) return false;  /* CertGetNameString returns 1 for empty */

    std::string signer_lower = to_lower(name_buf);

    bool trusted = false;
    AcquireSRWLockShared(&lock_);
    for (const auto& s : signers_) {
        if (signer_lower == s) {
            trusted = true;
            break;
        }
    }
    ReleaseSRWLockShared(&lock_);

    return trusted;
}

bool Whitelist::is_signer_trusted(const char* file_path) const
{
    if (!file_path || !file_path[0]) return false;

    /* Quick check: if no trusted signers configured, skip WinVerifyTrust */
    AcquireSRWLockShared(&lock_);
    bool have_signers = !signers_.empty();
    ReleaseSRWLockShared(&lock_);
    if (!have_signers) return false;

    /* Convert path to wide string for WinVerifyTrust */
    int wide_len = MultiByteToWideChar(CP_ACP, 0, file_path, -1, NULL, 0);
    if (wide_len <= 0) return false;

    std::vector<wchar_t> wide_path((size_t)wide_len);
    MultiByteToWideChar(CP_ACP, 0, file_path, -1, wide_path.data(), wide_len);

    /* ── Attempt 1: Embedded Authenticode signature ─────────────── */
    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wide_path.data();

    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(NULL, &policy_guid, &trust_data);

    if (status == ERROR_SUCCESS) {
        bool trusted = check_signer_from_state(trust_data.hWVTStateData);
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policy_guid, &trust_data);
        return trusted;
    }

    /* Close embedded attempt */
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy_guid, &trust_data);

    /* ── Attempt 2: Catalog-based signature (Windows system files) ─ */
    HCATADMIN cat_admin = NULL;
    if (!CryptCATAdminAcquireContext(&cat_admin, NULL, 0))
        return false;

    /* Open the file and compute its catalog hash */
    HANDLE hFile = CreateFileW(wide_path.data(), GENERIC_READ,
                                FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CryptCATAdminReleaseContext(cat_admin, 0);
        return false;
    }

    DWORD hash_len = 0;
    CryptCATAdminCalcHashFromFileHandle(hFile, &hash_len, NULL, 0);
    if (hash_len == 0) {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(cat_admin, 0);
        return false;
    }

    std::vector<BYTE> cat_hash(hash_len);
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hash_len,
                                              cat_hash.data(), 0)) {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(cat_admin, 0);
        return false;
    }
    CloseHandle(hFile);

    /* Find the catalog that contains this hash */
    HCATINFO cat_info = CryptCATAdminEnumCatalogFromHash(
        cat_admin, cat_hash.data(), hash_len, 0, NULL);

    bool trusted = false;
    if (cat_info) {
        /* Get catalog file path */
        CATALOG_INFO ci{};
        ci.cbStruct = sizeof(ci);
        if (CryptCATCatalogInfoFromContext(cat_info, &ci, 0)) {
            /* Verify the catalog file's signature via WinVerifyTrust */
            WINTRUST_CATALOG_INFO wci{};
            wci.cbStruct = sizeof(wci);
            wci.pcwszCatalogFilePath = ci.wszCatalogFile;
            wci.pcwszMemberFilePath = wide_path.data();
            wci.pcwszMemberTag = wide_path.data();
            wci.cbCalculatedFileHash = hash_len;
            wci.pbCalculatedFileHash = cat_hash.data();

            WINTRUST_DATA cat_trust{};
            cat_trust.cbStruct = sizeof(cat_trust);
            cat_trust.dwUIChoice = WTD_UI_NONE;
            cat_trust.fdwRevocationChecks = WTD_REVOKE_NONE;
            cat_trust.dwUnionChoice = WTD_CHOICE_CATALOG;
            cat_trust.pCatalog = &wci;
            cat_trust.dwStateAction = WTD_STATEACTION_VERIFY;
            cat_trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

            LONG cat_status = WinVerifyTrust(NULL, &policy_guid, &cat_trust);

            if (cat_status == ERROR_SUCCESS) {
                trusted = check_signer_from_state(cat_trust.hWVTStateData);
            }

            cat_trust.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &policy_guid, &cat_trust);
        }

        CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
    }

    CryptCATAdminReleaseContext(cat_admin, 0);
    return trusted;
}

/* ── Bulk operations ───────────────────────────────────────────── */

void Whitelist::clear()
{
    AcquireSRWLockExclusive(&lock_);
    hashes_.clear();
    path_prefixes_.clear();
    signers_.clear();
    ReleaseSRWLockExclusive(&lock_);
}

void Whitelist::stats(uint32_t* hash_count, uint32_t* path_count,
                       uint32_t* signer_count) const
{
    AcquireSRWLockShared(&lock_);
    if (hash_count)   *hash_count   = (uint32_t)hashes_.size();
    if (path_count)   *path_count   = (uint32_t)path_prefixes_.size();
    if (signer_count) *signer_count = (uint32_t)signers_.size();
    ReleaseSRWLockShared(&lock_);
}

} /* namespace akav */
