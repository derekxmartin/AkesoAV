#ifndef AKAV_WHITELIST_H
#define AKAV_WHITELIST_H

/* whitelist.h -- Hash/path/signer exclusion mechanism.
 *
 * Per section 5.4:
 *   - Hash whitelist: SHA-256 of known-clean files (sorted, binary search)
 *   - Path exclusions: prefix-based, checked before any file I/O
 *   - Signer trust: Authenticode via WinVerifyTrust
 *
 * Thread safety: SRWLOCK reader-writer pattern.
 *   - Checks acquire shared (read) lock
 *   - Adds/clears acquire exclusive (write) lock
 *
 * Pipeline position (scan_file):
 *   1. Path exclusion (before file read)
 *   2. Hash whitelist (after SHA-256 computation)
 *   3. Signer trust (WinVerifyTrust if Authenticode present)
 *   Any match -> short-circuit as clean (in_whitelist=1)
 */

#ifdef __cplusplus

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>
#include <cstdint>

namespace akav {

class Whitelist {
public:
    Whitelist();
    ~Whitelist();

    Whitelist(const Whitelist&) = delete;
    Whitelist& operator=(const Whitelist&) = delete;

    /* ── Hash whitelist ─────────────────────────────────────────── */

    /**
     * Add a SHA-256 hash to the runtime whitelist.
     * Thread-safe (exclusive lock).
     */
    void add_hash(const uint8_t sha256[32]);

    /**
     * Check if a SHA-256 hash is whitelisted.
     * Thread-safe (shared lock).
     */
    bool is_hash_whitelisted(const uint8_t sha256[32]) const;

    /* ── Path exclusions ────────────────────────────────────────── */

    /**
     * Add a path prefix exclusion (case-insensitive on Windows).
     * Thread-safe (exclusive lock).
     */
    void add_path(const char* path_prefix);

    /**
     * Check if a file path matches any exclusion prefix.
     * Thread-safe (shared lock). Case-insensitive.
     */
    bool is_path_excluded(const char* path) const;

    /* ── Signer trust ───────────────────────────────────────────── */

    /**
     * Add a trusted Authenticode signer name.
     * Thread-safe (exclusive lock).
     */
    void add_signer(const char* signer_name);

    /**
     * Check if a file has a valid Authenticode signature from a trusted signer.
     * Uses WinVerifyTrust + CertGetNameString.
     * Thread-safe (shared lock for signer list; WinVerifyTrust is thread-safe).
     */
    bool is_signer_trusted(const char* file_path) const;

    /* ── Bulk operations ────────────────────────────────────────── */

    /**
     * Clear all hashes, paths, and signers.
     * Thread-safe (exclusive lock).
     */
    void clear();

    /**
     * Get counts for diagnostics.
     */
    void stats(uint32_t* hash_count, uint32_t* path_count,
               uint32_t* signer_count) const;

private:
    /**
     * Helper: check signer name from WinVerifyTrust state data against
     * our trusted signer list. Called under shared or no lock on signers_.
     */
    bool check_signer_from_state(HANDLE state_data) const;

    /* Sorted vector of 32-byte SHA-256 hashes for binary search */
    std::vector<std::vector<uint8_t>> hashes_;

    /* Lowercased path prefixes for case-insensitive matching */
    std::vector<std::string> path_prefixes_;

    /* Lowercased trusted signer names */
    std::vector<std::string> signers_;

    mutable SRWLOCK lock_;
};

} /* namespace akav */

#endif /* __cplusplus */

#endif /* AKAV_WHITELIST_H */
