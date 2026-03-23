/* update_client.cpp -- Secure signature update client (P10-T1).
 *
 * Implements §5.10: WinHTTP HTTPS + cert pinning, JSON manifest parsing,
 * CNG SHA-256 + RSA-2048 verification, atomic MoveFileEx swap, rollback.
 */

#include "update/update_client.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>  /* for CertGetCertificateContextProperty */

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#include <cstdio>
#include <cstring>
#include <cstdlib>

/* ── Placeholder RSA public key (test key, replaced for production) ── */

/* This is a minimal BCRYPT_RSAPUBLIC_BLOB for testing.  Production builds
 * must replace this with the real signing key embedded at compile time. */

static const uint8_t s_placeholder_pubkey[] = {
    /* BCRYPT_RSAPUBLIC_BLOB header:
     * Magic  = BCRYPT_RSAPUBLIC_MAGIC (0x31415352 = "RSA1")
     * BitLen = 2048
     * cbPub  = 3 (exponent bytes)
     * cbMod  = 256 (modulus bytes)
     * Followed by: exponent (3 bytes) + modulus (256 bytes)
     *
     * This is a DUMMY key for compilation only.  Tests generate real keys. */
    0x52, 0x53, 0x41, 0x31,  /* Magic "RSA1" */
    0x00, 0x08, 0x00, 0x00,  /* BitLength = 2048 */
    0x03, 0x00, 0x00, 0x00,  /* cbPublicExp = 3 */
    0x00, 0x01, 0x00, 0x00,  /* cbModulus = 256 */
    0x01, 0x00, 0x01,        /* Public exponent = 65537 */
    /* 256 bytes of modulus follow -- all zeros = INVALID, test-only */
};

const uint8_t  AKAV_UPDATE_RSA_PUBKEY[]  = { 0 };
const size_t   AKAV_UPDATE_RSA_PUBKEY_LEN = 0;

/* ── Hex decode ─────────────────────────────────────────────────────── */

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

size_t akav_hex_decode(const char* hex, size_t hex_len,
                       uint8_t* out, size_t out_max)
{
    if (!hex || hex_len % 2 != 0) return 0;
    size_t byte_count = hex_len / 2;
    if (byte_count > out_max) return 0;

    for (size_t i = 0; i < byte_count; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return byte_count;
}

/* ── Base64 decode ──────────────────────────────────────────────────── */

static uint8_t b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return (uint8_t)(c - 'A');
    if (c >= 'a' && c <= 'z') return (uint8_t)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 0;
}

static bool is_b64_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/';
}

size_t akav_base64_decode(const char* b64, size_t b64_len,
                          uint8_t* out, size_t out_max)
{
    if (!b64 || !out) return 0;

    /* Strip whitespace, count valid chars */
    size_t valid = 0;
    for (size_t i = 0; i < b64_len; i++) {
        if (is_b64_char(b64[i]) || b64[i] == '=') valid++;
    }
    if (valid == 0) return 0;

    size_t out_len = (valid / 4) * 3;
    if (b64_len >= 1 && b64[b64_len - 1] == '=') out_len--;
    if (b64_len >= 2 && b64[b64_len - 2] == '=') out_len--;
    if (out_len > out_max) return 0;

    size_t oi = 0;
    uint32_t accum = 0;
    int bits = 0;
    for (size_t i = 0; i < b64_len && oi < out_len; i++) {
        char c = b64[i];
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        if (!is_b64_char(c)) return 0;
        accum = (accum << 6) | b64_val(c);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[oi++] = (uint8_t)(accum >> bits);
            accum &= (1u << bits) - 1;
        }
    }
    return oi;
}

/* ── JSON manifest parser ───────────────────────────────────────────── */

static const char* skip_ws(const char* p, const char* end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
        p++;
    return p;
}

/* Extract a JSON string value after "key": — returns pointer past closing quote.
 * Writes value (unescaped) to out. */
static const char* json_extract_string(const char* p, const char* end,
                                       char* out, size_t out_max)
{
    p = skip_ws(p, end);
    if (p >= end || *p != '"') return nullptr;
    p++; /* skip opening quote */

    size_t oi = 0;
    while (p < end && *p != '"') {
        if (*p == '\\' && p + 1 < end) {
            p++;
            char c = *p;
            if (c == '"' || c == '\\' || c == '/') {
                if (oi < out_max - 1) out[oi++] = c;
            } else if (c == 'n') {
                if (oi < out_max - 1) out[oi++] = '\n';
            }
            /* skip other escapes */
        } else {
            if (oi < out_max - 1) out[oi++] = *p;
        }
        p++;
    }
    if (oi < out_max) out[oi] = '\0';
    if (p < end) p++; /* skip closing quote */
    return p;
}

/* Find "key" in JSON, return pointer to the value (after the colon) */
static const char* json_find_key(const char* json, size_t json_len,
                                 const char* key)
{
    char search[256];
    int n = snprintf(search, sizeof(search), "\"%s\"", key);
    if (n <= 0) return nullptr;

    const char* p = json;
    const char* end = json + json_len;
    while (p < end) {
        const char* found = strstr(p, search);
        if (!found || found >= end) return nullptr;
        p = found + strlen(search);
        p = skip_ws(p, end);
        if (p < end && *p == ':') {
            p++;
            return skip_ws(p, end);
        }
    }
    return nullptr;
}

static bool json_read_uint32(const char* json, size_t len,
                             const char* key, uint32_t* out)
{
    const char* v = json_find_key(json, len, key);
    if (!v) return false;
    *out = (uint32_t)strtoul(v, nullptr, 10);
    return true;
}

static bool json_read_uint64(const char* json, size_t len,
                             const char* key, uint64_t* out)
{
    const char* v = json_find_key(json, len, key);
    if (!v) return false;
    *out = (uint64_t)strtoull(v, nullptr, 10);
    return true;
}

static bool json_read_string(const char* json, size_t len,
                             const char* key, char* out, size_t out_max)
{
    const char* v = json_find_key(json, len, key);
    if (!v) return false;
    return json_extract_string(v, json + len, out, out_max) != nullptr;
}

/* Parse the "files" array from the manifest */
static bool parse_files_array(const char* json, size_t json_len,
                              akav_update_manifest_t* manifest)
{
    const char* v = json_find_key(json, json_len, "files");
    if (!v) return false;
    if (*v != '[') return false;

    const char* p = v + 1;
    const char* end = json + json_len;
    manifest->num_files = 0;

    while (p < end && manifest->num_files < AKAV_UPDATE_MAX_FILES) {
        p = skip_ws(p, end);
        if (p >= end) break;
        if (*p == ']') break;
        if (*p == ',') { p++; continue; }
        if (*p != '{') break;

        /* Find matching closing brace for this object */
        int depth = 1;
        const char* obj_start = p;
        p++;
        while (p < end && depth > 0) {
            if (*p == '{') depth++;
            else if (*p == '}') depth--;
            else if (*p == '"') {
                p++;
                while (p < end && *p != '"') {
                    if (*p == '\\') p++;
                    p++;
                }
            }
            p++;
        }
        const char* obj_end = p;
        size_t obj_len = (size_t)(obj_end - obj_start);

        akav_update_file_t* f = &manifest->files[manifest->num_files];
        memset(f, 0, sizeof(*f));

        json_read_string(obj_start, obj_len, "name", f->name, sizeof(f->name));
        json_read_string(obj_start, obj_len, "url", f->url, sizeof(f->url));
        json_read_string(obj_start, obj_len, "type", f->type, sizeof(f->type));
        json_read_uint64(obj_start, obj_len, "size", &f->size);

        /* SHA-256 as hex string */
        char sha_hex[128] = {0};
        if (json_read_string(obj_start, obj_len, "sha256", sha_hex, sizeof(sha_hex))) {
            akav_hex_decode(sha_hex, strlen(sha_hex), f->sha256, sizeof(f->sha256));
        }

        /* RSA signature as base64 */
        char sig_b64[512] = {0};
        if (json_read_string(obj_start, obj_len, "rsa_signature", sig_b64, sizeof(sig_b64))) {
            akav_base64_decode(sig_b64, strlen(sig_b64),
                              f->rsa_signature, sizeof(f->rsa_signature));
        }

        manifest->num_files++;
    }
    return true;
}

bool akav_update_parse_manifest(const char* json, size_t json_len,
                                akav_update_manifest_t* manifest)
{
    if (!json || !manifest || json_len == 0) return false;
    memset(manifest, 0, sizeof(*manifest));

    json_read_uint32(json, json_len, "version", &manifest->version);
    json_read_string(json, json_len, "published_at",
                     manifest->published_at, sizeof(manifest->published_at));
    json_read_uint32(json, json_len, "minimum_engine_version",
                     &manifest->minimum_engine_version);

    parse_files_array(json, json_len, manifest);

    /* Manifest signature (base64) */
    char sig_b64[512] = {0};
    if (json_read_string(json, json_len, "manifest_signature",
                         sig_b64, sizeof(sig_b64))) {
        size_t decoded = akav_base64_decode(sig_b64, strlen(sig_b64),
                                            manifest->manifest_signature,
                                            sizeof(manifest->manifest_signature));
        manifest->has_manifest_signature = (decoded > 0);
    }

    /* Store raw body for signature verification.
     * The signer signs the JSON with manifest_signature set to "".
     * We must reconstruct that same JSON by replacing the real
     * signature value with an empty string. */
    if (json_len < sizeof(manifest->raw_body)) {
        memcpy(manifest->raw_body, json, json_len);
        manifest->raw_body_len = json_len;

        /* Find "manifest_signature": "..." and replace the value with "" */
        const char* key = "\"manifest_signature\"";
        char* pos = strstr(manifest->raw_body, key);
        if (pos) {
            /* Skip key and colon+whitespace to find the opening quote */
            char* p = pos + strlen(key);
            while (*p == ' ' || *p == ':') p++;
            if (*p == '"') {
                char* val_start = p;  /* Points to opening quote */
                p++;  /* Skip opening quote */
                /* Find closing quote (handle escaped quotes) */
                while (*p && !(*p == '"' && *(p - 1) != '\\')) p++;
                if (*p == '"') {
                    char* val_end = p + 1;  /* Points past closing quote */
                    /* Replace "base64sig..." with "" */
                    size_t tail_len = (manifest->raw_body + manifest->raw_body_len) - val_end;
                    memmove(val_start + 2, val_end, tail_len + 1); /* +1 for null */
                    val_start[0] = '"';
                    val_start[1] = '"';
                    manifest->raw_body_len -= (size_t)(val_end - (val_start + 2));
                }
            }
        }
    }

    return manifest->version > 0;
}

/* ── CNG SHA-256 ────────────────────────────────────────────────────── */

bool akav_update_sha256_buffer(const uint8_t* data, size_t len,
                               uint8_t out_hash[AKAV_UPDATE_SHA256_LEN])
{
    if (!data || !out_hash) return false;

    BCRYPT_ALG_HANDLE alg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                                  NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptHash(alg, NULL, 0,
                        (PUCHAR)data, (ULONG)len,
                        out_hash, AKAV_UPDATE_SHA256_LEN);

    BCryptCloseAlgorithmProvider(alg, 0);
    return BCRYPT_SUCCESS(status);
}

bool akav_update_sha256_file(const char* path,
                             uint8_t out_hash[AKAV_UPDATE_SHA256_LEN])
{
    if (!path || !out_hash) return false;

    FILE* f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) return false;

    /* Streaming hash for potentially large files */
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    bool ok = false;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                                  NULL, 0);
    if (!BCRYPT_SUCCESS(status)) { fclose(f); return false; }

    DWORD hash_obj_len = 0;
    DWORD cb = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash_obj_len,
                      sizeof(hash_obj_len), &cb, 0);

    uint8_t* hash_obj = (uint8_t*)malloc(hash_obj_len);
    if (!hash_obj) goto cleanup;

    status = BCryptCreateHash(alg, &hash, hash_obj, hash_obj_len,
                              NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    {
        uint8_t buf[8192];
        size_t rd;
        while ((rd = fread(buf, 1, sizeof(buf), f)) > 0) {
            status = BCryptHashData(hash, buf, (ULONG)rd, 0);
            if (!BCRYPT_SUCCESS(status)) goto cleanup;
        }
    }

    status = BCryptFinishHash(hash, out_hash, AKAV_UPDATE_SHA256_LEN, 0);
    ok = BCRYPT_SUCCESS(status);

cleanup:
    if (hash) BCryptDestroyHash(hash);
    free(hash_obj);
    BCryptCloseAlgorithmProvider(alg, 0);
    fclose(f);
    return ok;
}

/* ── CNG RSA-2048 signature verification ────────────────────────────── */

bool akav_update_rsa_verify(const uint8_t* data, size_t data_len,
                            const uint8_t* signature, size_t sig_len,
                            const uint8_t* pub_key, size_t key_len)
{
    if (!data || !signature || !pub_key || sig_len == 0 || key_len == 0)
        return false;

    /* 1. Hash the data with SHA-256 */
    uint8_t hash[32];
    if (!akav_update_sha256_buffer(data, data_len, hash))
        return false;

    /* 2. Import the RSA public key */
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    bool ok = false;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM,
                                                  NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptImportKeyPair(alg, NULL, BCRYPT_RSAPUBLIC_BLOB,
                                 &key, (PUCHAR)pub_key, (ULONG)key_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    /* 3. Verify the PKCS#1 v1.5 signature */
    BCRYPT_PKCS1_PADDING_INFO padding;
    padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    status = BCryptVerifySignature(key, &padding,
                                   hash, sizeof(hash),
                                   (PUCHAR)signature, (ULONG)sig_len,
                                   BCRYPT_PAD_PKCS1);

    ok = BCRYPT_SUCCESS(status);

    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

/* ── WinHTTP HTTPS fetch with cert pinning ──────────────────────────── */

/* Context passed to the WinHTTP status callback for cert pinning */
struct CertPinContext {
    const uint8_t* pinned_sha256;   /* 32-byte fingerprint to match */
    bool           cert_valid;       /* set to true if cert matches */
    bool           cert_checked;     /* set to true once check is done */
};

static void CALLBACK winhttp_status_callback(
    HINTERNET   hInternet,
    DWORD_PTR   dwContext,
    DWORD       dwInternetStatus,
    LPVOID      lpvStatusInformation,
    DWORD       dwStatusInformationLength)
{
    (void)lpvStatusInformation;
    (void)dwStatusInformationLength;

    if (dwInternetStatus != WINHTTP_CALLBACK_STATUS_SENDING_REQUEST)
        return;

    CertPinContext* ctx = (CertPinContext*)dwContext;
    if (!ctx || !ctx->pinned_sha256) return;

    /* Retrieve the server certificate */
    WINHTTP_CERTIFICATE_INFO certInfo;
    DWORD certInfoSize = sizeof(certInfo);
    memset(&certInfo, 0, sizeof(certInfo));

    if (!WinHttpQueryOption(hInternet, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT,
                            &certInfo, &certInfoSize)) {
        ctx->cert_valid = false;
        ctx->cert_checked = true;
        return;
    }

    /* Get the raw certificate bytes for hashing.
     * We use WINHTTP_OPTION_SERVER_CERT_CONTEXT to get the CERT_CONTEXT. */
    PCCERT_CONTEXT pCertCtx = NULL;
    DWORD certCtxSize = sizeof(pCertCtx);
    if (!WinHttpQueryOption(hInternet, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                            &pCertCtx, &certCtxSize) || !pCertCtx) {
        /* Free any strings allocated by WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT */
        if (certInfo.lpszSubjectInfo) LocalFree(certInfo.lpszSubjectInfo);
        if (certInfo.lpszIssuerInfo) LocalFree(certInfo.lpszIssuerInfo);
        ctx->cert_valid = false;
        ctx->cert_checked = true;
        return;
    }

    /* Hash the DER-encoded certificate with SHA-256 */
    uint8_t cert_hash[32];
    bool hashed = akav_update_sha256_buffer(pCertCtx->pbCertEncoded,
                                            pCertCtx->cbCertEncoded,
                                            cert_hash);

    ctx->cert_valid = hashed &&
                      (memcmp(cert_hash, ctx->pinned_sha256, 32) == 0);
    ctx->cert_checked = true;

    CertFreeCertificateContext(pCertCtx);
    if (certInfo.lpszSubjectInfo) LocalFree(certInfo.lpszSubjectInfo);
    if (certInfo.lpszIssuerInfo) LocalFree(certInfo.lpszIssuerInfo);
}

bool akav_update_https_fetch(const char* url,
                             const uint8_t* pinned_cert_sha256,
                             bool skip_tls_verify,
                             uint8_t** out_data, size_t* out_len,
                             char* error, size_t error_len)
{
    if (!url || !out_data || !out_len) {
        if (error) snprintf(error, error_len, "Invalid parameters");
        return false;
    }
    *out_data = NULL;
    *out_len = 0;

    /* Convert URL to wide string */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, url, -1, NULL, 0);
    if (wlen <= 0) {
        if (error) snprintf(error, error_len, "URL conversion failed");
        return false;
    }
    wchar_t* wurl = (wchar_t*)malloc((size_t)wlen * sizeof(wchar_t));
    if (!wurl) {
        if (error) snprintf(error, error_len, "Out of memory");
        return false;
    }
    MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, wlen);

    /* Crack URL */
    URL_COMPONENTS uc;
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {0};
    wchar_t path[2048] = {0};
    uc.lpszHostName = host;
    uc.dwHostNameLength = _countof(host);
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        free(wurl);
        if (error) snprintf(error, error_len, "URL parse failed");
        return false;
    }
    free(wurl);

    bool is_https = (uc.nScheme == INTERNET_SCHEME_HTTPS);

    /* Open session */
    HINTERNET session = WinHttpOpen(L"AkesoAV-Update/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        if (error) snprintf(error, error_len, "WinHttpOpen failed: %lu", GetLastError());
        return false;
    }

    /* Set timeouts: 5s connect, 10s send/receive */
    WinHttpSetTimeouts(session, 5000, 5000, 10000, 10000);

    /* Connect */
    HINTERNET conn = WinHttpConnect(session, host, uc.nPort, 0);
    if (!conn) {
        if (error) snprintf(error, error_len, "WinHttpConnect failed: %lu", GetLastError());
        WinHttpCloseHandle(session);
        return false;
    }

    /* Open request */
    DWORD flags = is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(conn, L"GET", path, NULL,
                                            WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            flags);
    if (!request) {
        if (error) snprintf(error, error_len, "WinHttpOpenRequest failed: %lu", GetLastError());
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return false;
    }

    /* Skip TLS certificate validation if requested (test-only) */
    if (skip_tls_verify && is_https) {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS,
                         &sec_flags, sizeof(sec_flags));
    }

    /* Set up cert pinning callback if requested */
    CertPinContext pinCtx = {0};
    pinCtx.pinned_sha256 = pinned_cert_sha256;
    pinCtx.cert_valid = false;
    pinCtx.cert_checked = false;

    if (pinned_cert_sha256 && is_https) {
        WinHttpSetStatusCallback(request, winhttp_status_callback,
                                  WINHTTP_CALLBACK_STATUS_SENDING_REQUEST, 0);
    }

    /* Send request */
    BOOL sent = WinHttpSendRequest(request,
                                    WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    WINHTTP_NO_REQUEST_DATA, 0, 0,
                                    (DWORD_PTR)&pinCtx);
    if (!sent) {
        DWORD err_code = GetLastError();
        if (error) snprintf(error, error_len, "WinHttpSendRequest failed: %lu", err_code);
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return false;
    }

    /* Check cert pinning result */
    if (pinned_cert_sha256 && is_https && pinCtx.cert_checked && !pinCtx.cert_valid) {
        if (error) snprintf(error, error_len, "Certificate pinning failed");
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return false;
    }

    /* Receive response */
    if (!WinHttpReceiveResponse(request, NULL)) {
        if (error) snprintf(error, error_len, "WinHttpReceiveResponse failed: %lu", GetLastError());
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return false;
    }

    /* Check status code */
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(request,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &status_code, &status_size, WINHTTP_NO_HEADER_INDEX);

    if (status_code < 200 || status_code >= 300) {
        if (error) snprintf(error, error_len, "HTTP %lu", status_code);
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return false;
    }

    /* Read response body */
    uint8_t* body = NULL;
    size_t body_len = 0;
    size_t body_cap = 0;

    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(request, &avail) && avail > 0) {
        if (body_len + avail > body_cap) {
            size_t new_cap = body_cap == 0 ? 4096 : body_cap * 2;
            while (new_cap < body_len + avail) new_cap *= 2;
            /* Limit to 256MB */
            if (new_cap > 256 * 1024 * 1024) {
                free(body);
                if (error) snprintf(error, error_len, "Response too large");
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(conn);
                WinHttpCloseHandle(session);
                return false;
            }
            uint8_t* tmp = (uint8_t*)realloc(body, new_cap);
            if (!tmp) {
                free(body);
                if (error) snprintf(error, error_len, "Out of memory");
                WinHttpCloseHandle(request);
                WinHttpCloseHandle(conn);
                WinHttpCloseHandle(session);
                return false;
            }
            body = tmp;
            body_cap = new_cap;
        }

        DWORD rd = 0;
        if (!WinHttpReadData(request, body + body_len, avail, &rd)) break;
        body_len += rd;
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);

    *out_data = body;
    *out_len = body_len;
    return true;
}

/* ── Atomic install + rollback ──────────────────────────────────────── */

bool akav_update_install_db(const char* new_file_path,
                            const char* current_db_path,
                            char* error, size_t error_len)
{
    if (!new_file_path || !current_db_path) {
        if (error) snprintf(error, error_len, "Invalid parameters");
        return false;
    }

    /* Build .prev path */
    char prev_path[MAX_PATH];
    snprintf(prev_path, sizeof(prev_path), "%s.prev", current_db_path);

    /* Step 1: Backup current → .prev (if current exists) */
    DWORD attrs = GetFileAttributesA(current_db_path);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        /* Delete old .prev if it exists */
        DeleteFileA(prev_path);
        if (!MoveFileA(current_db_path, prev_path)) {
            if (error) snprintf(error, error_len,
                               "Backup to .prev failed: %lu", GetLastError());
            return false;
        }
    }

    /* Step 2: Atomic swap new → current */
    if (!MoveFileExA(new_file_path, current_db_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        if (error) snprintf(error, error_len,
                           "Atomic swap failed: %lu", GetLastError());
        /* Try to restore from .prev */
        MoveFileA(prev_path, current_db_path);
        return false;
    }

    return true;
}

bool akav_update_rollback(const char* db_path,
                          char* error, size_t error_len)
{
    if (!db_path) {
        if (error) snprintf(error, error_len, "Invalid parameters");
        return false;
    }

    char prev_path[MAX_PATH];
    snprintf(prev_path, sizeof(prev_path), "%s.prev", db_path);

    /* Check .prev exists */
    if (GetFileAttributesA(prev_path) == INVALID_FILE_ATTRIBUTES) {
        if (error) snprintf(error, error_len, "No .prev file found for rollback");
        return false;
    }

    /* Replace current with .prev */
    if (!MoveFileExA(prev_path, db_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        if (error) snprintf(error, error_len,
                           "Rollback MoveFileEx failed: %lu", GetLastError());
        return false;
    }

    return true;
}

/* ── High-level update check ────────────────────────────────────────── */

bool akav_update_check(const akav_update_config_t* config,
                       akav_update_result_t* result)
{
    if (!config || !result) return false;
    memset(result, 0, sizeof(*result));
    result->old_version = config->current_version;

    /* 1. Fetch manifest */
    uint8_t* manifest_data = NULL;
    size_t manifest_len = 0;
    if (!akav_update_https_fetch(config->update_url,
                                  config->pinned_cert_sha256,
                                  false, /* skip_tls_verify */
                                  &manifest_data, &manifest_len,
                                  result->error, sizeof(result->error))) {
        return false;
    }

    /* 2. Parse manifest */
    akav_update_manifest_t manifest;
    if (!akav_update_parse_manifest((const char*)manifest_data, manifest_len,
                                     &manifest)) {
        free(manifest_data);
        snprintf(result->error, sizeof(result->error), "Invalid manifest JSON");
        return false;
    }

    /* 3. Verify manifest RSA signature */
    if (config->rsa_public_key && config->rsa_public_key_len > 0) {
        if (manifest.has_manifest_signature) {
            if (!akav_update_rsa_verify(
                    (const uint8_t*)manifest.raw_body, manifest.raw_body_len,
                    manifest.manifest_signature, AKAV_UPDATE_RSA_SIG_LEN,
                    config->rsa_public_key, config->rsa_public_key_len)) {
                free(manifest_data);
                snprintf(result->error, sizeof(result->error),
                         "Manifest RSA signature verification failed");
                return false;
            }
        } else {
            free(manifest_data);
            snprintf(result->error, sizeof(result->error),
                     "Manifest missing RSA signature");
            return false;
        }
    }
    free(manifest_data);

    /* 4. Compare version — skip if already up-to-date or downgrade */
    if (manifest.version <= config->current_version) {
        result->new_version = config->current_version;
        return true;  /* Already up-to-date, not an error */
    }

    /* 5. Download each file */
    for (uint32_t i = 0; i < manifest.num_files; i++) {
        const akav_update_file_t* file = &manifest.files[i];

        /* Download file */
        uint8_t* file_data = NULL;
        size_t file_len = 0;
        if (!akav_update_https_fetch(file->url,
                                      config->pinned_cert_sha256,
                                      false, /* skip_tls_verify */
                                      &file_data, &file_len,
                                      result->error, sizeof(result->error))) {
            return false;
        }

        /* 6. Verify SHA-256 */
        uint8_t file_hash[32];
        if (!akav_update_sha256_buffer(file_data, file_len, file_hash) ||
            memcmp(file_hash, file->sha256, 32) != 0) {
            free(file_data);
            snprintf(result->error, sizeof(result->error),
                     "SHA-256 verification failed for %s", file->name);
            return false;
        }

        /* 7. Verify RSA signature on file */
        if (config->rsa_public_key && config->rsa_public_key_len > 0) {
            if (!akav_update_rsa_verify(file_data, file_len,
                                         file->rsa_signature,
                                         AKAV_UPDATE_RSA_SIG_LEN,
                                         config->rsa_public_key,
                                         config->rsa_public_key_len)) {
                free(file_data);
                snprintf(result->error, sizeof(result->error),
                         "RSA signature verification failed for %s", file->name);
                return false;
            }
        }

        /* 8. Write to .new file */
        char new_path[MAX_PATH];
        snprintf(new_path, sizeof(new_path), "%s.new", config->db_path);

        FILE* f = NULL;
        if (fopen_s(&f, new_path, "wb") != 0 || !f) {
            free(file_data);
            snprintf(result->error, sizeof(result->error),
                     "Failed to write %s", new_path);
            return false;
        }
        fwrite(file_data, 1, file_len, f);
        fclose(f);
        free(file_data);

        /* 9. Atomic install */
        if (!akav_update_install_db(new_path, config->db_path,
                                     result->error, sizeof(result->error))) {
            /* Clean up .new */
            DeleteFileA(new_path);
            return false;
        }
    }

    result->updated = true;
    result->new_version = manifest.version;
    return true;
}
