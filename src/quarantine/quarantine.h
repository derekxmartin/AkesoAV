/* quarantine.h -- AkesoAV quarantine vault.
 *
 * Implements §5.12: AES-256-GCM encryption (CNG), DPAPI key management,
 * SQLite index, and all quarantine operations.
 *
 * .sqz file format:
 *   [12 bytes IV/nonce] [16 bytes GCM auth tag] [encrypted data...]
 *
 * Key management:
 *   - 32-byte AES key generated via BCryptGenRandom on first use
 *   - Protected at rest with DPAPI (CryptProtectData, machine scope)
 *   - Stored in vault_dir/key.dpapi
 *
 * Thread safety: NOT thread-safe. Caller must serialize access.
 */

#ifndef AKESOAV_QUARANTINE_H
#define AKESOAV_QUARANTINE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <string>
#include <vector>

/* Forward-declare sqlite3 to avoid including the header here */
struct sqlite3;

/* ── Quarantine index entry ────────────────────────────────────── */

struct QuarantineEntry {
    char     id[64];                /* Vault ID: "q-YYYYMMDDHHMMSS-XXXX" */
    char     original_path[MAX_PATH];
    char     malware_name[256];
    char     signature_id[64];
    int64_t  timestamp;             /* Unix epoch seconds */
    char     sha256[65];            /* Hex string */
    int64_t  file_size;
    char     user_sid[128];
};

/* ── Quarantine class ──────────────────────────────────────────── */

class Quarantine {
public:
    Quarantine();
    ~Quarantine();

    /* Non-copyable */
    Quarantine(const Quarantine&) = delete;
    Quarantine& operator=(const Quarantine&) = delete;

    /* Initialize: create vault directory, open/create SQLite DB,
     * load or generate DPAPI-protected AES key.
     * vault_dir: e.g., "C:\ProgramData\Akeso\Quarantine" */
    bool init(const char* vault_dir);

    /* Shutdown: close DB, zero key material. */
    void shutdown();

    /* Quarantine a file: encrypt → .sqz, add index row.
     * Returns the vault_id on success, empty string on failure. */
    std::string quarantine_file(const char* file_path,
                                const char* malware_name,
                                const char* signature_id);

    /* Restore a quarantined file.
     * If restore_path is null, restores to original_path.
     * Removes the index entry and .sqz file on success. */
    bool restore_file(const char* vault_id, const char* restore_path = nullptr);

    /* List all quarantine entries. */
    std::vector<QuarantineEntry> list();

    /* Delete a single quarantine entry (remove .sqz + index row). */
    bool delete_entry(const char* vault_id);

    /* Purge entries older than N days. Returns number deleted. */
    int purge(int days);

    /* Get count of entries. */
    int count();

    /* Get vault directory path. */
    const std::string& vault_dir() const { return vault_dir_; }

private:
    std::string vault_dir_;
    std::string vault_path_;  /* vault_dir/vault/ */
    std::string db_path_;     /* vault_dir/quarantine.db */
    std::string key_path_;    /* vault_dir/key.dpapi */

    sqlite3* db_;

    /* AES-256 key (32 bytes), zeroed on shutdown */
    uint8_t aes_key_[32];
    bool    key_loaded_;

    BCRYPT_ALG_HANDLE alg_;

    /* Key management */
    bool generate_key();
    bool save_key_dpapi();
    bool load_key_dpapi();

    /* Encryption/decryption */
    bool encrypt_file(const char* src_path, const char* dst_path);
    bool decrypt_file(const char* src_path, const char* dst_path);

    /* AES-256-GCM primitives */
    bool aes_gcm_encrypt(const uint8_t* plaintext, size_t plain_len,
                         const uint8_t* iv, size_t iv_len,
                         uint8_t* ciphertext,
                         uint8_t* tag, size_t tag_len);
    bool aes_gcm_decrypt(const uint8_t* ciphertext, size_t cipher_len,
                         const uint8_t* iv, size_t iv_len,
                         const uint8_t* tag, size_t tag_len,
                         uint8_t* plaintext);

    /* SQLite helpers */
    bool create_tables();
    bool insert_entry(const QuarantineEntry& entry);
    bool remove_entry(const char* vault_id);

    /* Generate a unique vault ID */
    static std::string generate_vault_id();

    /* Compute SHA-256 hex of file contents */
    static std::string compute_sha256_hex(const uint8_t* data, size_t len);

    /* Get current user SID as string */
    static std::string get_current_user_sid();

    /* Set vault directory ACL (SYSTEM + Admins only) */
    bool set_vault_acl();

    /* Build the .sqz path from vault_id */
    std::string sqz_path(const char* vault_id) const;
};

#endif /* AKESOAV_QUARANTINE_H */
