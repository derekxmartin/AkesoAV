/* update_client.h -- Secure signature update client (P10-T1).
 *
 * WinHTTP HTTPS with cert pinning, CNG SHA-256 + RSA-2048 verification,
 * atomic file swap, and rollback support per §5.10.
 */

#ifndef AKAV_UPDATE_CLIENT_H
#define AKAV_UPDATE_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ──────────────────────────────────────────────────────── */

#define AKAV_UPDATE_MAX_FILES       16
#define AKAV_UPDATE_SHA256_LEN      32
#define AKAV_UPDATE_RSA_SIG_LEN    256   /* RSA-2048 = 256 bytes */
#define AKAV_UPDATE_ERROR_LEN      256

/* ── Embedded RSA public key (DER-encoded PKCS#1, replaced at build) ─ */

/* Placeholder test key -- production builds replace this with the real
 * signing key.  The key is in BCRYPT_RSAPUBLIC_BLOB format for direct
 * import via BCryptImportKeyPair. */

extern const uint8_t  AKAV_UPDATE_RSA_PUBKEY[];
extern const size_t   AKAV_UPDATE_RSA_PUBKEY_LEN;

/* ── Manifest types ─────────────────────────────────────────────────── */

typedef struct {
    char     name[256];
    char     url[1024];
    uint8_t  sha256[AKAV_UPDATE_SHA256_LEN];
    uint8_t  rsa_signature[AKAV_UPDATE_RSA_SIG_LEN];
    uint64_t size;
    char     type[32];              /* "full" or "delta" */
} akav_update_file_t;

typedef struct {
    uint32_t            version;
    char                published_at[64];
    uint32_t            minimum_engine_version;
    akav_update_file_t  files[AKAV_UPDATE_MAX_FILES];
    uint32_t            num_files;
    uint8_t             manifest_signature[AKAV_UPDATE_RSA_SIG_LEN];
    bool                has_manifest_signature;
    /* Raw JSON body (excluding manifest_signature) for RSA verification */
    char                raw_body[8192];
    size_t              raw_body_len;
} akav_update_manifest_t;

/* ── Configuration ──────────────────────────────────────────────────── */

typedef struct {
    const char*    update_url;             /* Base URL for manifest.json */
    const char*    db_path;                /* Current .akavdb file path */
    uint32_t       current_version;        /* Current DB version number */
    const uint8_t* pinned_cert_sha256;     /* SHA-256 of pinned server cert (32 bytes), NULL to skip */
    const uint8_t* rsa_public_key;         /* RSA public key blob */
    size_t         rsa_public_key_len;     /* Length of RSA public key */
} akav_update_config_t;

/* ── Result ─────────────────────────────────────────────────────────── */

typedef struct {
    bool     updated;
    uint32_t old_version;
    uint32_t new_version;
    char     error[AKAV_UPDATE_ERROR_LEN];
} akav_update_result_t;

/* ── High-level API ─────────────────────────────────────────────────── */

/**
 * Check for updates and install if available.
 *
 * Flow: fetch manifest → verify signature → compare version → download
 *       → SHA-256 verify → RSA verify → atomic swap → RELOAD.
 *
 * Returns true on success (updated or already up-to-date).
 * Returns false on error (result->error populated).
 */
bool akav_update_check(const akav_update_config_t* config,
                       akav_update_result_t* result);

/* ── Lower-level functions (exposed for unit testing) ───────────────── */

/**
 * Parse a JSON manifest string into the manifest struct.
 */
bool akav_update_parse_manifest(const char* json, size_t json_len,
                                akav_update_manifest_t* manifest);

/**
 * Fetch data from a URL via WinHTTP HTTPS.
 * If pinned_cert_sha256 is non-NULL, certificate pinning is enforced.
 * Caller must free *out_data with free().
 */
bool akav_update_https_fetch(const char* url,
                             const uint8_t* pinned_cert_sha256,
                             uint8_t** out_data, size_t* out_len,
                             char* error, size_t error_len);

/**
 * Compute SHA-256 of a file on disk.
 */
bool akav_update_sha256_file(const char* path,
                             uint8_t out_hash[AKAV_UPDATE_SHA256_LEN]);

/**
 * Compute SHA-256 of a memory buffer.
 */
bool akav_update_sha256_buffer(const uint8_t* data, size_t len,
                               uint8_t out_hash[AKAV_UPDATE_SHA256_LEN]);

/**
 * Verify an RSA-2048 PKCS#1 v1.5 signature over a SHA-256 hash.
 * pub_key is in BCRYPT_RSAPUBLIC_BLOB format.
 */
bool akav_update_rsa_verify(const uint8_t* data, size_t data_len,
                            const uint8_t* signature, size_t sig_len,
                            const uint8_t* pub_key, size_t key_len);

/**
 * Atomic install: write new DB to .akavdb.new, backup current to .akavdb.prev,
 * then MoveFileEx atomic swap.
 */
bool akav_update_install_db(const char* new_file_path,
                            const char* current_db_path,
                            char* error, size_t error_len);

/**
 * Rollback: restore .akavdb.prev to .akavdb.
 */
bool akav_update_rollback(const char* db_path,
                          char* error, size_t error_len);

/* ── Utility ────────────────────────────────────────────────────────── */

/**
 * Decode a hex string to bytes. Returns number of bytes written,
 * or 0 on error.
 */
size_t akav_hex_decode(const char* hex, size_t hex_len,
                       uint8_t* out, size_t out_max);

/**
 * Decode a base64 string to bytes. Returns number of bytes written,
 * or 0 on error.
 */
size_t akav_base64_decode(const char* b64, size_t b64_len,
                          uint8_t* out, size_t out_max);

#ifdef __cplusplus
}
#endif

#endif /* AKAV_UPDATE_CLIENT_H */
